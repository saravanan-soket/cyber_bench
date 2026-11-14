package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/exploitbench/bench-v8/mcp-server/tools"
	"golang.org/x/sys/unix"
)

// Linux capability bit positions — see capabilities(7).
const (
	capSetgid = 6
	capSetuid = 7
)

// preflight verifies every runtime invariant the isolation design relies on.
// Any failure is fatal: a misconfigured container would silently downgrade
// security without this check, which is worse than not running at all.
func preflight(cfg tools.Config) error {
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return fmt.Errorf("read /proc/self/status: %w", err)
	}
	s := string(status)

	// 1. Must NOT run as root.  Either the self-downgrade in init() never
	//    happened, or the container was launched with --user=root AND a
	//    non-root agent user wasn't provisioned.  Either way we refuse.
	if os.Geteuid() == 0 {
		return fmt.Errorf("refusing to run as root; check downgradeFromRoot logs in init()")
	}

	// 2. Agent shell and MCP server share a UID by design; the ONLY thing
	//    protecting MCP memory from agent ptrace is dumpable=0.  Set
	//    explicitly by downgradeFromRoot (and usually by the kernel's
	//    suid_dumpable default on root→nonzero transition).
	if d, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return fmt.Errorf("PR_GET_DUMPABLE: %w", err)
	} else if d != 0 {
		return fmt.Errorf("dumpable=%d (want 0) — prctl failed in downgradeFromRoot", d)
	}

	// 3. NO_NEW_PRIVS must be set so setuid/fcap binaries the agent may
	//    exec via the `exec` tool don't grant them elevation.
	if n, err := unix.PrctlRetInt(unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0); err != nil {
		return fmt.Errorf("PR_GET_NO_NEW_PRIVS: %w", err)
	} else if n != 1 {
		return fmt.Errorf("NoNewPrivs=%d (want 1) — prctl(PR_SET_NO_NEW_PRIVS) failed", n)
	}

	// 4. CAP_SETUID + CAP_SETGID must be in the effective set — needed
	//    to spawn graded children via SysProcAttr.Credential{Uid: grader}.
	capEff, err := parseCapLine(s, "CapEff:")
	if err != nil {
		return fmt.Errorf("parse CapEff: %w", err)
	}
	required := uint64(1<<capSetuid | 1<<capSetgid)
	if capEff&required != required {
		return fmt.Errorf("missing CAP_SETUID/CAP_SETGID in effective set (CapEff=0x%x, want at least 0x%x); "+
			"downgradeFromRoot's capset call may have failed — check logs", capEff, required)
	}

	// 5. grader UID must be disjoint from MCP's UID — same-UID would
	//    collapse the ptrace / /proc access boundary entirely.
	if cfg.GraderUID == uint32(os.Geteuid()) {
		return fmt.Errorf("grader UID (%d) == MCP UID (%d); must be disjoint", cfg.GraderUID, os.Geteuid())
	}
	if cfg.GraderUID == 0 {
		return fmt.Errorf("grader user not found")
	}

	// 6. /rlenv/grader-run/ must exist, be grader-owned, and mode 0700.
	//    If it's readable by agent, daemons can harvest ASAN logs and
	//    coverage profraw — the whole point of Fix 2 isolation goes away.
	//    (The ACE proof no longer lives on disk — it's a per-round prctl
	//    nonce passed via env — but the dir still holds per-round
	//    grader-only state.)
	if err := checkGraderDir(cfg.GraderRunDir, cfg.GraderUID); err != nil {
		return err
	}

	// 7. grader-diff must exist and be disjoint from both grader and MCP.
	//    DiffGrader's fixed d8 runs there; same-UID-as-grader would let
	//    fixed d8 forge vuln's ASAN log and trivially grant CapASAN.
	if cfg.GraderDiffUID == 0 {
		return fmt.Errorf("grader-diff user not found; image predates the grader-diff split — rebuild")
	}
	if cfg.GraderDiffUID == cfg.GraderUID {
		return fmt.Errorf("grader-diff UID (%d) == grader UID (%d); must be disjoint", cfg.GraderDiffUID, cfg.GraderUID)
	}
	if cfg.GraderDiffUID == uint32(os.Geteuid()) {
		return fmt.Errorf("grader-diff UID (%d) == MCP UID (%d); must be disjoint", cfg.GraderDiffUID, os.Geteuid())
	}
	if err := checkGraderDir(cfg.DiffGraderRunDir, cfg.GraderDiffUID); err != nil {
		return err
	}

	// 8. Sanity: expected vuln d8 binary exists and is executable.  A
	//    missing binary produces unhelpful errors deep inside the grader.
	vulnD8 := cfg.BinariesDir + "/vuln/release/d8"
	if fi, err := os.Stat(vulnD8); err != nil {
		return fmt.Errorf("stat %s: %w", vulnD8, err)
	} else if fi.Mode()&0o111 == 0 {
		return fmt.Errorf("%s is not executable", vulnD8)
	}

	return nil
}

// checkGraderDir asserts that dir exists, is owned by wantUID, and is mode 0700.
// Same invariant applies to every per-cred scratch dir: leakage through a loose
// parent is what lets same-UID-as-MCP agent daemons harvest grader state.
func checkGraderDir(dir string, wantUID uint32) error {
	st, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("stat %s: %w", dir, err)
	}
	sst, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%s: cannot stat on this platform", dir)
	}
	if sst.Uid != wantUID {
		return fmt.Errorf("%s owner UID %d != expected UID %d", dir, sst.Uid, wantUID)
	}
	if st.Mode().Perm() != 0o700 {
		return fmt.Errorf("%s mode is %04o, want 0700", dir, st.Mode().Perm())
	}
	return nil
}

// parseCapLine parses a "CapXxx:\t<hex>" row from /proc/self/status.
func parseCapLine(status, key string) (uint64, error) {
	for _, line := range strings.Split(status, "\n") {
		if strings.HasPrefix(line, key) {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				return 0, fmt.Errorf("malformed %s line: %q", key, line)
			}
			return strconv.ParseUint(fields[1], 16, 64)
		}
	}
	return 0, fmt.Errorf("%s not found in /proc/self/status", key)
}
