//go:build isolation

// Slow regression test for the grader's per-d8 SIGKILL path.
//
// The grader spawns d8 under SysProcAttr.Credential (grader UID).  MCP
// itself runs as `agent` with caps {SETUID, SETGID} and no CAP_KILL, so
// the default cmd.Process.Kill() called when ctx expires returns EPERM
// against the grader-UID child and leaves it running indefinitely.  We
// route the kill through a same-UID helper (killPgidAsGrader) — this
// test exercises that path end-to-end via grade() on an infinite-loop
// PoC and asserts no orphan d8 remains.
//
// Wall-time budget: sub-graders run in parallel (CompositeGrader), so
// total = max(DiffGrader, PrimitiveGrader, CoverageGrader).  The longest
// is DiffGrader: 6 sequential rounds (3 release-asan + 3 release) ×
// ~30.05s per round = ~180s normal, ~210s pessimistic if WaitDelay (5s)
// fires every kill.  Plus session setup + tool-call roundtrips → 240s.

package test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestIsolation_GraderKillsInfiniteLoopPoC(t *testing.T) {
	image := requireImage(t)
	s := newMCPSession(t, image)

	// PoC that never returns. d8 will spin in JS; every grader round must
	// hit its per-d8 30s timeout and SIGKILL the child.
	poc := `while (true) {}` + "\n"
	s.callTool(t, "write_file", map[string]string{
		"path":     "/rlenv/workspace/poc-infloop.js",
		"contents": poc,
	})

	// Send grade() and wait with a generous deadline. The default
	// callTool deadline (120s) is shorter than the grade's worst case
	// even when the kill mechanism works correctly, so we read the
	// response inline with our own deadline.
	id := s.nextID
	s.nextID++
	s.sendRaw(t, jsonRPCRequest(id, "tools/call", map[string]any{
		"name":      "grade",
		"arguments": map[string]string{"path": "/rlenv/workspace/poc-infloop.js"},
	}))

	const gradeDeadline = 4 * time.Minute
	start := time.Now()
	done := make(chan map[string]any, 1)
	errCh := make(chan error, 1)
	go func() {
		for {
			if !s.stdout.Scan() {
				errCh <- fmt.Errorf("stdout closed: %v", s.stdout.Err())
				return
			}
			var resp map[string]any
			if err := json.Unmarshal(s.stdout.Bytes(), &resp); err != nil {
				errCh <- fmt.Errorf("parse: %v\nraw: %s", err, s.stdout.Text())
				return
			}
			if rid, ok := resp["id"]; ok {
				if int(rid.(float64)) == id {
					done <- resp
					return
				}
			}
		}
	}()

	var resp map[string]any
	select {
	case resp = <-done:
	case err := <-errCh:
		t.Fatalf("read response: %v", err)
	case <-time.After(gradeDeadline):
		t.Fatalf("grade() did not return within %v — d8 SIGKILL leak regression",
			gradeDeadline)
	}
	t.Logf("grade() returned in %v", time.Since(start).Truncate(time.Second))

	if errObj, ok := resp["error"]; ok {
		t.Fatalf("grade returned error: %v", errObj)
	}

	// Grade returned; verify no leaked d8 children. `pgrep -x d8` from
	// inside the container would catch any process spawned with our cred.
	check := s.callTool(t, "exec", map[string]string{
		"cmd": `pgrep -x d8 2>/dev/null || true`,
	})
	sc := extractStructured(check)
	out := strings.TrimSpace(sc["stdout"].(string))
	if out != "" {
		t.Errorf("orphan d8 processes after grade returned:\n%s", out)
	}
}
