//go:build functional

package test

import (
	"strings"
	"testing"
	"time"
)

func (s *mcpSession) exec(t *testing.T, cmd string) (string, string, float64) {
	t.Helper()
	r := s.callTool(t, "exec", map[string]any{"cmd": cmd, "timeout": 30.0})
	sc := extractStructured(r)
	out, _ := sc["stdout"].(string)
	errOut, _ := sc["stderr"].(string)
	exit, _ := sc["exitcode"].(float64)
	return strings.TrimSpace(out), strings.TrimSpace(errOut), exit
}

// A backgrounded grandchild that sets PR_SET_DUMPABLE=0 (root-owned /proc dir)
// and forges a "Uid:" line in its comm must still be killed on exec return.
// Cleanup relies on kernel signal permission, not /proc ownership or status
// contents, so neither trick lets it survive.
func TestFunctional_ExecEvasionDumpableForgedComm(t *testing.T) {
	t.Parallel()
	s := newMCPSession(t, requireImage(t))

	const marker = "/rlenv/workspace/survived_evasion"
	s.exec(t, "rm -f "+marker)
	py := "python3 -c '" +
		"import ctypes,os,time;" +
		"l=ctypes.CDLL(None);" +
		"os._exit(0) if os.fork() else None;" + // foreground parent exits at once
		"os.setsid();" +
		"l.prctl(4,0,0,0,0);" + // PR_SET_DUMPABLE=0 -> root-owned /proc dir
		"l.prctl(15,b\"\\nUid:\\t0\\t0\\t0\\t0\",0,0,0);" + // forge comm Uid line
		"os.close(0);os.close(1);os.close(2);" +
		"time.sleep(2);" +
		"open(\"" + marker + "\",\"w\").close()'"
	if _, _, exit := s.exec(t, py); exit != 0 {
		t.Fatalf("launch exited %v", exit)
	}

	time.Sleep(3 * time.Second)
	out, _, _ := s.exec(t, "test -e "+marker+" && echo SURVIVED || echo gone")
	t.Logf("evasion marker: %q", out)
	if out == "SURVIVED" {
		t.Errorf("dumpable=0 + forged-comm child evaded cleanup")
	}
}
