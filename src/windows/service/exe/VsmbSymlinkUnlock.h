/*++

Copyright (c) Microsoft. All rights reserved.

Module Name:

    VsmbSymlinkUnlock.h

Abstract:

    This file contains the declaration for unlocking symbolic-link creation
    through VirtualSmb (VSMB) DrvFs shares.

--*/

#pragma once

#include <windows.h>
#include <guiddef.h>

namespace wsl::windows::service {

//
// Unlocks symbolic-link (reparse-point) creation through VirtualSmb shares.
//
// The host-side VSMB server (vmusrv.dll, running inside the VM's vmwp.exe) gates
// symlink creation on a per-SMB2-session "IsAdmin" flag. There is no HCS setting or
// share Option that sets it, so the only lever is the in-memory flag itself. This
// routine locates the VM's vmwp.exe (by matching RuntimeId in its command line),
// finds vmusrv.dll, walks the session table, and flips IsAdmin to 1 for the guest's
// session.
//
// hv_vmsmb (the Linux VSMB client) keeps a single long-lived SMB2 session, so a
// one-shot flip once the session is established is sufficient -- unlike the Windows
// mrxsmb client, which recreates sessions and would need continuous watching. The
// routine returns after a successful flip, or after a bounded timeout / cancellation.
//
// All memory access is structurally validated: a vmusrv layout that no longer matches
// the expected offsets (e.g. after an OS update that moved them) fails the sanity
// checks and results in no write, degrading to "symlinks not unlocked" rather than
// corrupting the worker process.
//
// Intended to run on a dedicated thread. TerminatingEvent is the VM teardown signal;
// the routine wakes and returns promptly when it is set.
//
void UnlockVirtualSmbSymlinks(const GUID& RuntimeId, HANDLE TerminatingEvent) noexcept;

} // namespace wsl::windows::service
