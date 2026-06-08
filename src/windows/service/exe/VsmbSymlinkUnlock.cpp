/*++

Copyright (c) Microsoft. All rights reserved.

Module Name:

    VsmbSymlinkUnlock.cpp

Abstract:

    This file contains the implementation for unlocking symbolic-link creation
    through VirtualSmb (VSMB) DrvFs shares by flipping the host VSMB server's
    per-session IsAdmin flag.

--*/

#include "precomp.h"
#include "VsmbSymlinkUnlock.h"
#include "WslSecurity.h"
#include "WslTelemetry.h"
#include <tlhelp32.h>
#include <algorithm>
#include <string>
#include <vector>

namespace {

//
// vmusrv.dll session-table layout.
//
// These offsets were derived by reverse-engineering the VSMB server's SMB2 session
// table (verified on Windows 11, vmusrv 10.0.26100.x). They may drift across major
// vmusrv updates; a drift is caught by the structural sanity checks in
// FlipAdminSessions (which then performs no write) rather than corrupting memory.
//
// The session table is reachable from `vmusrv_base + c_sessionTableRva`, a pointer to
// an "RFS" table. The RFS table holds a pointer to the session array plus a high-water
// mark and capacity; each array entry points to a session whose IsAdmin byte gates
// symlink creation.
//
constexpr DWORD64 c_sessionTableRva = 0xa5db0;
constexpr DWORD c_rfsArrayOffset = 0x08;
constexpr DWORD c_rfsHighWaterOffset = 0x7c;
constexpr DWORD c_rfsCapacityOffset = 0x80;
constexpr DWORD c_sessionStateOffset = 0x10;
constexpr DWORD c_sessionIsAdminOffset = 0x68;
constexpr DWORD c_sessionStructSize = 0x70;
constexpr DWORD c_sessionStateInit = 0xdb;
constexpr DWORD c_sessionStateClosed = 0xdd;

// A session pointer must lie in user-mode heap range and not inside the module image.
constexpr DWORD64 c_minUserAddress = 0x10000;
constexpr DWORD64 c_maxUserAddress = 0x00007fffffffffff;
constexpr DWORD64 c_imageRangeLow = 0x00007ff000000000;
constexpr DWORD64 c_imageRangeHigh = 0x00007fffffffffff;

// Upper bound on the number of sessions, guarding against a garbage high-water/capacity.
constexpr DWORD c_maxSessions = 0x10000;

// Timing. vmwp.exe exists almost immediately; vmusrv.dll and the SMB2 session only
// appear once the guest boots and mounts a VSMB share, which can take a while.
constexpr DWORD c_findWorkerTimeoutMs = 30 * 1000;
constexpr DWORD c_sessionTimeoutMs = 180 * 1000;
constexpr DWORD c_pollIntervalMs = 500;

bool ReadMemory(HANDLE Process, DWORD64 Address, _Out_writes_bytes_(Size) void* Buffer, SIZE_T Size) noexcept
{
    SIZE_T read = 0;
    return ReadProcessMemory(Process, reinterpret_cast<LPCVOID>(Address), Buffer, Size, &read) && read == Size;
}

//
// Reads the command line of a target process by walking its PEB. Used to match a
// vmwp.exe instance to a VM by the RuntimeId it was launched with.
//
std::wstring ReadCommandLine(HANDLE Process) noexcept
{
    PROCESS_BASIC_INFORMATION basicInfo{};
    if (!NT_SUCCESS(NtQueryInformationProcess(Process, ProcessBasicInformation, &basicInfo, sizeof(basicInfo), nullptr)) ||
        basicInfo.PebBaseAddress == nullptr)
    {
        return {};
    }

    PEB peb{};
    if (!ReadMemory(Process, reinterpret_cast<DWORD64>(basicInfo.PebBaseAddress), &peb, sizeof(peb)) || peb.ProcessParameters == nullptr)
    {
        return {};
    }

    RTL_USER_PROCESS_PARAMETERS parameters{};
    if (!ReadMemory(Process, reinterpret_cast<DWORD64>(peb.ProcessParameters), &parameters, sizeof(parameters)))
    {
        return {};
    }

    const USHORT length = parameters.CommandLine.Length;
    if (parameters.CommandLine.Buffer == nullptr || length == 0)
    {
        return {};
    }

    std::wstring commandLine(length / sizeof(wchar_t), L'\0');
    if (!ReadMemory(Process, reinterpret_cast<DWORD64>(parameters.CommandLine.Buffer), commandLine.data(), length))
    {
        return {};
    }

    return commandLine;
}

//
// Finds the vmwp.exe process hosting the VM with the given RuntimeId by matching the
// GUID in each vmwp.exe command line. Requires SeDebugPrivilege to open the worker
// (owned by a virtual-machine SID).
//
DWORD FindWorkerProcess(const GUID& RuntimeId) noexcept
{
    wchar_t guidString[40] = {};
    if (StringFromGUID2(RuntimeId, guidString, ARRAYSIZE(guidString)) == 0)
    {
        return 0;
    }

    // Strip the surrounding braces and lower-case the bare 36-char core so the match is
    // insensitive to brace/case differences in how vmwp's command line spells the GUID.
    std::wstring needle(guidString);
    if (needle.size() >= 2 && needle.front() == L'{' && needle.back() == L'}')
    {
        needle = needle.substr(1, needle.size() - 2);
    }
    std::transform(needle.begin(), needle.end(), needle.begin(), ::towlower);

    wil::unique_handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (!snapshot)
    {
        return 0;
    }

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    for (BOOL more = Process32FirstW(snapshot.get(), &entry); more; more = Process32NextW(snapshot.get(), &entry))
    {
        if (_wcsicmp(entry.szExeFile, L"vmwp.exe") != 0)
        {
            continue;
        }

        wil::unique_handle process(OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, entry.th32ProcessID));
        if (!process)
        {
            continue;
        }

        std::wstring commandLine = ReadCommandLine(process.get());
        std::transform(commandLine.begin(), commandLine.end(), commandLine.begin(), ::towlower);
        if (commandLine.find(needle) != std::wstring::npos)
        {
            return entry.th32ProcessID;
        }
    }

    return 0;
}

//
// Returns the load base of the named module in the target process, or 0 if not loaded.
//
DWORD64 FindModuleBase(DWORD ProcessId, PCWSTR ModuleName) noexcept
{
    wil::unique_handle snapshot;
    for (int attempt = 0; attempt < 8; ++attempt)
    {
        snapshot.reset(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, ProcessId));
        if (snapshot)
        {
            break;
        }

        // The module list can be momentarily inconsistent while the target loads.
        if (GetLastError() != ERROR_BAD_LENGTH)
        {
            return 0;
        }
    }

    if (!snapshot)
    {
        return 0;
    }

    MODULEENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    for (BOOL more = Module32FirstW(snapshot.get(), &entry); more; more = Module32NextW(snapshot.get(), &entry))
    {
        if (_wcsicmp(entry.szModule, ModuleName) == 0)
        {
            return reinterpret_cast<DWORD64>(entry.modBaseAddr);
        }
    }

    return 0;
}

//
// Walks the VSMB server's session table and flips IsAdmin to 1 on any session that has
// it cleared. Returns the number of sessions flipped, or -1 if the table could not be
// read. Every step is range/shape-checked; on any mismatch the function bails without
// writing.
//
int FlipAdminSessions(HANDLE Process, DWORD64 VmusrvBase) noexcept
{
    DWORD64 table = 0;
    if (!ReadMemory(Process, VmusrvBase + c_sessionTableRva, &table, sizeof(table)))
    {
        return -1;
    }
    if (table == 0)
    {
        return 0; // No sessions yet.
    }

    // Read the RFS header (array pointer + high-water + capacity) in one shot.
    BYTE header[0x80] = {};
    if (!ReadMemory(Process, table + c_rfsArrayOffset, header, sizeof(header)))
    {
        return -1;
    }

    DWORD64 array = 0;
    DWORD highWater = 0;
    DWORD capacity = 0;
    memcpy(&array, header + (c_rfsArrayOffset - c_rfsArrayOffset), sizeof(array));
    memcpy(&highWater, header + (c_rfsHighWaterOffset - c_rfsArrayOffset), sizeof(highWater));
    memcpy(&capacity, header + (c_rfsCapacityOffset - c_rfsArrayOffset), sizeof(capacity));

    const DWORD bound = capacity ? std::min(highWater, capacity) : highWater;
    if (array == 0 || bound == 0 || bound > c_maxSessions)
    {
        return 0; // Empty or implausible table shape -- treat as nothing to do.
    }

    std::vector<DWORD64> sessions(bound);
    if (!ReadMemory(Process, array, sessions.data(), static_cast<SIZE_T>(bound) * sizeof(DWORD64)))
    {
        return -1;
    }

    int flipped = 0;
    for (DWORD i = 0; i < bound; ++i)
    {
        const DWORD64 sessionAddress = sessions[i];
        if (sessionAddress < c_minUserAddress || sessionAddress > c_maxUserAddress)
        {
            continue;
        }
        if (sessionAddress >= c_imageRangeLow && sessionAddress <= c_imageRangeHigh)
        {
            continue; // Module image range -- never a heap session pointer.
        }

        BYTE session[c_sessionStructSize] = {};
        if (!ReadMemory(Process, sessionAddress, session, sizeof(session)))
        {
            continue;
        }

        DWORD state = 0;
        memcpy(&state, session + c_sessionStateOffset, sizeof(state));
        if (state != c_sessionStateInit && state != c_sessionStateClosed)
        {
            continue;
        }

        const BYTE isAdmin = session[c_sessionIsAdminOffset];
        if (isAdmin != 0 && isAdmin != 1)
        {
            continue; // Not a plausible boolean -- offset likely no longer valid.
        }
        if (isAdmin != 0)
        {
            continue; // Already admin.
        }

        const BYTE one = 1;
        SIZE_T written = 0;
        if (WriteProcessMemory(Process, reinterpret_cast<LPVOID>(sessionAddress + c_sessionIsAdminOffset), &one, 1, &written) &&
            written == 1)
        {
            // Confirm the write landed before counting it.
            BYTE check = 0;
            if (ReadMemory(Process, sessionAddress + c_sessionIsAdminOffset, &check, 1) && check == 1)
            {
                ++flipped;
            }
        }
    }

    return flipped;
}

// Sleeps up to Milliseconds. Returns true to continue, false if the terminating event
// was signaled (the caller should return).
bool WaitOrCancel(HANDLE TerminatingEvent, DWORD Milliseconds) noexcept
{
    return WaitForSingleObject(TerminatingEvent, Milliseconds) == WAIT_TIMEOUT;
}

} // namespace

namespace wsl::windows::service {

void UnlockVirtualSmbSymlinks(const GUID& RuntimeId, HANDLE TerminatingEvent) noexcept
try
{
    ::SetThreadDescription(GetCurrentThread(), L"VirtualSmb - SymlinkUnlock");

    // SeDebugPrivilege is required to open the vmwp.exe worker (owned by a VM SID) and
    // to snapshot its modules. It is released once the worker handle is open and
    // vmusrv.dll is located; Read/WriteProcessMemory then rely on the handle's access.
    auto privilege = wsl::windows::common::security::AcquirePrivilege(SE_DEBUG_NAME);

    // Locate the VM's worker process.
    const ULONGLONG workerDeadline = GetTickCount64() + c_findWorkerTimeoutMs;
    DWORD workerPid = 0;
    while ((workerPid = FindWorkerProcess(RuntimeId)) == 0)
    {
        if (GetTickCount64() >= workerDeadline || !WaitOrCancel(TerminatingEvent, c_pollIntervalMs))
        {
            WSL_LOG("VsmbSymlinkUnlockNoWorker", TraceLoggingValue(RuntimeId, "vmId"));
            return;
        }
    }

    wil::unique_handle worker(
        OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION, FALSE, workerPid));
    if (!worker)
    {
        LOG_LAST_ERROR_MSG("OpenProcess(vmwp.exe pid=%lu) failed", workerPid);
        return;
    }

    // Wait for vmusrv.dll, which is mapped only once the guest begins a VSMB session.
    const ULONGLONG sessionDeadline = GetTickCount64() + c_sessionTimeoutMs;
    DWORD64 vmusrvBase = 0;
    while ((vmusrvBase = FindModuleBase(workerPid, L"vmusrv.dll")) == 0)
    {
        if (GetTickCount64() >= sessionDeadline || !WaitOrCancel(TerminatingEvent, c_pollIntervalMs))
        {
            WSL_LOG("VsmbSymlinkUnlockNoServer", TraceLoggingValue(workerPid, "pid"));
            return;
        }
    }

    // The open handle already carries the access needed for the flip loop.
    privilege.reset();

    // hv_vmsmb keeps a single long-lived SMB2 session, so one successful flip is enough.
    // The session may take a moment to fully establish after vmusrv.dll loads, so poll
    // until at least one session is flipped, then stop.
    for (;;)
    {
        const int flipped = FlipAdminSessions(worker.get(), vmusrvBase);
        if (flipped > 0)
        {
            WSL_LOG("VsmbSymlinkUnlockDone", TraceLoggingValue(workerPid, "pid"), TraceLoggingValue(flipped, "flipped"));
            return;
        }

        if (GetTickCount64() >= sessionDeadline || !WaitOrCancel(TerminatingEvent, c_pollIntervalMs))
        {
            WSL_LOG("VsmbSymlinkUnlockTimeout", TraceLoggingValue(workerPid, "pid"));
            return;
        }
    }
}
CATCH_LOG()

} // namespace wsl::windows::service
