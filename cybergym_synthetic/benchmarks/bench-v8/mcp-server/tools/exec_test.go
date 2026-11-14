package tools

import (
	"context"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestMain stubs cleanupStraggler: killAtSelfUID would SIGKILL every process
// at our UID, which on a dev host is the whole session. On the host the probe
// finds no CAP_SYS_ADMIN, so these exercise the fallback path; the foreground
// is still bounded by Go's own WaitDelay kill.
func TestMain(m *testing.M) {
	cleanupStraggler = func() {}
	os.Exit(m.Run())
}

func TestRunExecCommandReturnsWhenForegroundExits(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("exec tool is Linux-only")
	}
	start := time.Now()
	out, err := runExecCommand(context.Background(), "sleep 2 & echo LAUNCHED", 5*time.Second)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("runExecCommand: %v", err)
	}
	if out.ExitCode != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%q", out.ExitCode, out.Stderr)
	}
	if strings.TrimSpace(out.Stdout) != "LAUNCHED" {
		t.Fatalf("stdout = %q, want LAUNCHED", out.Stdout)
	}
	if elapsed >= time.Second {
		t.Fatalf("waited %s for a backgrounded child after the foreground exited", elapsed)
	}
}

func TestRunExecCommandPreservesTimeout(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("exec tool is Linux-only")
	}
	start := time.Now()
	out, err := runExecCommand(context.Background(), "sleep 2; echo NEVER", 100*time.Millisecond)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("runExecCommand: %v", err)
	}
	if out.ExitCode != 137 {
		t.Fatalf("exit code = %d, want 137", out.ExitCode)
	}
	if out.Stdout != "" {
		t.Fatalf("stdout = %q, want empty after timeout", out.Stdout)
	}
	if elapsed >= time.Second {
		t.Fatalf("timeout took %s, want bounded well under the child sleep", elapsed)
	}
}

func TestRunExecCommandReturnsExitCodeAndOutput(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("exec tool is Linux-only")
	}
	out, err := runExecCommand(context.Background(), "echo OUT; echo ERR >&2; exit 7", 5*time.Second)
	if err != nil {
		t.Fatalf("runExecCommand: %v", err)
	}
	if out.ExitCode != 7 {
		t.Fatalf("exit code = %d, want 7", out.ExitCode)
	}
	if strings.TrimSpace(out.Stdout) != "OUT" {
		t.Fatalf("stdout = %q, want OUT", out.Stdout)
	}
	if strings.TrimSpace(out.Stderr) != "ERR" {
		t.Fatalf("stderr = %q, want ERR", out.Stderr)
	}
}
