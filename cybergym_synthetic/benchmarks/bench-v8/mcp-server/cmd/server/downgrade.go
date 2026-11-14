package main

import (
	"log"
	"os"
	"os/user"
	"strconv"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// allThreadsPrctl runs prctl on every Go runtime OS thread.  unix.Prctl
// uses plain Syscall (per-thread); we need the state on ALL threads because
// Go's fork-exec can run from any goroutine's thread.
func allThreadsPrctl(op uintptr, a1, a2, a3, a4 uintptr) error {
	_, _, e := syscall.AllThreadsSyscall6(syscall.SYS_PRCTL, op, a1, a2, a3, a4, 0)
	if e != 0 {
		return e
	}
	return nil
}

// allThreadsCapset runs capset on every Go runtime OS thread.
func allThreadsCapset(hdr *unix.CapUserHeader, data *unix.CapUserData) error {
	_, _, e := syscall.AllThreadsSyscall(
		unix.SYS_CAPSET,
		uintptr(unsafe.Pointer(hdr)),
		uintptr(unsafe.Pointer(data)),
		0,
	)
	if e != 0 {
		return e
	}
	return nil
}

// downgradeFromRoot performs an in-process setuid-style drop. End state:
//
//   - UID/GID = `agent`
//   - Effective+permitted caps = {CAP_SETUID, CAP_SETGID}
//   - Bounding set = {CAP_SETUID, CAP_SETGID}
//   - Inheritable caps = empty
//   - Securebits: SECBIT_NOROOT locked (setuid-to-0 won't regrant root caps)
//   - dumpable = 0, NO_NEW_PRIVS = 1
//
// Every step is fatal on failure — a half-dropped state is more
// dangerous than not starting at all.
//
// Thread-safety: Go ≥1.16's syscall.Setresuid uses AllThreadsSyscall
// internally when built without cgo (our Makefile sets CGO_ENABLED=0),
// which broadcasts to every Go runtime thread.  init() runs before
// goroutines start, but AllThreadsSyscall is safe even after.
func downgradeFromRoot() {
	if os.Geteuid() != 0 {
		log.Fatalf("downgrade: not running as root (euid=%d)", os.Geteuid())
	}
	const userName = "agent"
	u, err := user.Lookup(userName)
	if err != nil {
		log.Fatalf("downgrade: lookup user %q: %v", userName, err)
	}
	uid64, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		log.Fatalf("downgrade: parse uid: %v", err)
	}
	gid64, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		log.Fatalf("downgrade: parse gid: %v", err)
	}
	if uid64 == 0 {
		log.Fatalf("downgrade: target user %q has UID 0 — refusing to no-op", userName)
	}
	targetUID := int(uid64)
	targetGID := int(gid64)

	// Every prctl below MUST broadcast across all Go runtime OS threads,
	// because Go's fork-exec for SysProcAttr.Credential runs on whichever
	// goroutine's thread happens to be scheduled. A per-thread cap state
	// inconsistency would make fork+setresuid fail with EPERM on some
	// code paths but not others (silently, depending on scheduling).

	// 1. Lock SECBIT_NOROOT while we still have CAP_SETPCAP (full root caps).
	//    After this, even if something regains UID=0 later, it won't gain
	//    caps.  Locked bits cannot be reverted.
	const (
		SECBIT_NOROOT                 = 1 << 0
		SECBIT_NOROOT_LOCKED          = 1 << 1
		SECBIT_NO_SETUID_FIXUP        = 1 << 2
		SECBIT_NO_SETUID_FIXUP_LOCKED = 1 << 3
	)
	if err := allThreadsPrctl(unix.PR_SET_SECUREBITS,
		SECBIT_NOROOT|SECBIT_NOROOT_LOCKED|
			SECBIT_NO_SETUID_FIXUP|SECBIT_NO_SETUID_FIXUP_LOCKED,
		0, 0, 0); err != nil {
		log.Fatalf("downgrade: PR_SET_SECUREBITS: %v", err)
	}

	// 2. PR_SET_KEEPCAPS=1 on EVERY thread before any Setresuid runs —
	//    otherwise threads without it have their caps zeroed on the
	//    root→nonroot UID transition (root→agent), and later fork+setuid
	//    from those threads fails with EPERM.
	if err := allThreadsPrctl(unix.PR_SET_KEEPCAPS, 1, 0, 0, 0); err != nil {
		log.Fatalf("downgrade: PR_SET_KEEPCAPS: %v", err)
	}

	// 3. Shrink the bounding set to the minimum we need.  Bounding set is
	//    per-thread too, so broadcast the CAPBSET_DROP calls.
	keep := map[int]bool{unix.CAP_SETUID: true, unix.CAP_SETGID: true}
	for capNum := 0; capNum <= unix.CAP_LAST_CAP; capNum++ {
		if keep[capNum] {
			continue
		}
		// CAPBSET_DROP returns EINVAL for kernel caps unknown to userspace
		// — ignore, it just means that cap wasn't settable anyway.
		_ = allThreadsPrctl(unix.PR_CAPBSET_DROP, uintptr(capNum), 0, 0, 0)
	}

	// 4. setresgid/setgroups/setresuid — syscall.Setresgid and friends
	//    already broadcast via AllThreadsSyscall in pure-Go builds.
	if err := syscall.Setresgid(targetGID, targetGID, targetGID); err != nil {
		log.Fatalf("downgrade: setresgid(%d): %v", targetGID, err)
	}
	if err := syscall.Setgroups([]int{targetGID}); err != nil {
		log.Fatalf("downgrade: setgroups: %v", err)
	}
	if err := syscall.Setresuid(targetUID, targetUID, targetUID); err != nil {
		log.Fatalf("downgrade: setresuid(%d): %v", targetUID, err)
	}

	// 5. Capset on all threads.  With KEEPCAPS honored across the Setresuid,
	//    every thread still holds the root-inherited permitted set; shrink
	//    them all uniformly to {SETUID, SETGID}.
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	mask := uint32(1<<uint(unix.CAP_SETUID) | 1<<uint(unix.CAP_SETGID))
	data[0].Effective = mask
	data[0].Permitted = mask
	data[0].Inheritable = 0
	// data[1] left zero (caps 32..63 — we need none).
	if err := allThreadsCapset(&hdr, &data[0]); err != nil {
		log.Fatalf("downgrade: capset (all threads): %v", err)
	}

	// 6. dumpable + no_new_privs — broadcast both too (per-thread flags).
	if err := allThreadsPrctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		log.Fatalf("downgrade: PR_SET_DUMPABLE: %v", err)
	}
	if err := allThreadsPrctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		log.Fatalf("downgrade: PR_SET_NO_NEW_PRIVS: %v", err)
	}

	// 8. Post-downgrade verification: every isolation invariant must hold
	//    BEFORE any user code runs.  A half-dropped state (e.g., SETPCAP
	//    left in the bounding set, or a stray thread still at uid=0) is
	//    worse than not starting.  Fatal on any mismatch.
	postCheckDowngrade(mask)
}

func postCheckDowngrade(wantMask uint32) {
	// --- UIDs: all four must be the target, none may be 0. ---
	ruid, euid, suid := unix.Getresuid()
	if ruid == 0 || euid == 0 || suid == 0 {
		log.Fatalf("downgrade post-check: UID still 0 somewhere (r=%d e=%d s=%d)", ruid, euid, suid)
	}
	if ruid != euid || euid != suid {
		log.Fatalf("downgrade post-check: UIDs not unified (r=%d e=%d s=%d)", ruid, euid, suid)
	}

	// --- GIDs: same treatment. ---
	rgid, egid, sgid := unix.Getresgid()
	if rgid == 0 || egid == 0 || sgid == 0 {
		log.Fatalf("downgrade post-check: GID still 0 somewhere (r=%d e=%d s=%d)", rgid, egid, sgid)
	}

	// --- Supplementary groups: should be exactly {egid}. ---
	groups, err := syscall.Getgroups()
	if err != nil {
		log.Fatalf("downgrade post-check: getgroups: %v", err)
	}
	for _, g := range groups {
		if g == 0 {
			log.Fatalf("downgrade post-check: root GID in supplementary groups %v", groups)
		}
	}

	// --- Effective, permitted, inheritable caps: exactly wantMask / 0. ---
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var got [2]unix.CapUserData
	if err := unix.Capget(&hdr, &got[0]); err != nil {
		log.Fatalf("downgrade post-check: capget: %v", err)
	}
	if got[0].Effective != wantMask {
		log.Fatalf("downgrade post-check: CapEff=0x%x, want 0x%x (exact)", got[0].Effective, wantMask)
	}
	if got[0].Permitted != wantMask {
		log.Fatalf("downgrade post-check: CapPrm=0x%x, want 0x%x (exact)", got[0].Permitted, wantMask)
	}
	if got[0].Inheritable != 0 {
		log.Fatalf("downgrade post-check: CapInh=0x%x, want 0", got[0].Inheritable)
	}
	if got[1].Effective != 0 || got[1].Permitted != 0 || got[1].Inheritable != 0 {
		log.Fatalf("downgrade post-check: high-32 caps nonzero (eff=0x%x prm=0x%x inh=0x%x)",
			got[1].Effective, got[1].Permitted, got[1].Inheritable)
	}

	// --- Bounding set: must be ≤ wantMask across all caps. ---
	for capNum := 0; capNum <= unix.CAP_LAST_CAP; capNum++ {
		r, err := unix.PrctlRetInt(unix.PR_CAPBSET_READ, uintptr(capNum), 0, 0, 0)
		if err != nil {
			continue // cap unknown to this kernel
		}
		inWantMask := capNum < 32 && (wantMask&(1<<uint(capNum))) != 0
		if r == 1 && !inWantMask {
			log.Fatalf("downgrade post-check: cap %d still in bounding set", capNum)
		}
	}

	// --- Ambient set: must be empty (no ambient capability inheritance). ---
	for capNum := 0; capNum <= unix.CAP_LAST_CAP; capNum++ {
		r, err := unix.PrctlRetInt(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_IS_SET, uintptr(capNum), 0, 0)
		if err != nil {
			continue
		}
		if r != 0 {
			log.Fatalf("downgrade post-check: cap %d in ambient set", capNum)
		}
	}

	// --- Dumpable: 0 (blocks same-UID ptrace / /proc/pid/mem access). ---
	if d, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0); err != nil {
		log.Fatalf("downgrade post-check: PR_GET_DUMPABLE: %v", err)
	} else if d != 0 {
		log.Fatalf("downgrade post-check: dumpable=%d, want 0", d)
	}

	// --- NoNewPrivs: 1 (setuid/fcap binaries execve'd by descendants gain nothing). ---
	if n, err := unix.PrctlRetInt(unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0); err != nil {
		log.Fatalf("downgrade post-check: PR_GET_NO_NEW_PRIVS: %v", err)
	} else if n != 1 {
		log.Fatalf("downgrade post-check: NoNewPrivs=%d, want 1", n)
	}

	// --- Securebits: NOROOT + NOROOT_LOCKED + NO_SETUID_FIXUP + its lock. ---
	const wantSecurebits = (1 << 0) | (1 << 1) | (1 << 2) | (1 << 3)
	if sb, err := unix.PrctlRetInt(unix.PR_GET_SECUREBITS, 0, 0, 0, 0); err != nil {
		log.Fatalf("downgrade post-check: PR_GET_SECUREBITS: %v", err)
	} else if sb&wantSecurebits != wantSecurebits {
		log.Fatalf("downgrade post-check: securebits=0x%x, want at least 0x%x", sb, wantSecurebits)
	}
}

