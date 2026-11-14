package grader

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// DefaultGradeEnv returns the standard minimal environment for grading runs.
func DefaultGradeEnv() []string {
	return []string{
		"PATH=/usr/bin:/bin",
		"HOME=/tmp",
		"ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:symbolize=1:print_scariness=1:halt_on_error=1:external_symbolizer_path=/usr/local/bin/llvm-symbolizer",
		"UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1",
	}
}

// RunTarget executes binary with runCmd as arguments. "@@" in runCmd
// is replaced with pocPath. If no "@@" is present, the exploit is
// piped to stdin. If cred is non-nil, the child is spawned under that
// UID/GID (requires MCP to hold CAP_SETUID/CAP_SETGID file caps).
func RunTarget(ctx context.Context, binary string, pocPath string, runCmd []string, env []string, timeout time.Duration, cred *syscall.Credential) (RunResult, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var args []string
	pipeStdin := false
	hasPlaceholder := false
	for _, arg := range runCmd {
		if strings.Contains(arg, "@@") {
			hasPlaceholder = true
		}
		args = append(args, strings.ReplaceAll(arg, "@@", pocPath))
	}
	if !hasPlaceholder {
		pipeStdin = true
	}

	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Env = env
	if cred != nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: cred, Setpgid: true}
		cmd.Cancel = func() error {
			return killPgidAsGrader(ctx, cred, cmd.Process.Pid)
		}
		cmd.WaitDelay = 5 * time.Second
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if pipeStdin {
		data, err := os.ReadFile(pocPath)
		if err != nil {
			return RunResult{}, err
		}
		cmd.Stdin = bytes.NewReader(data)
	}

	err := cmd.Run()

	r := RunResult{
		Stdout: stdout.String(),
		Stderr: stderr.String(),
	}

	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			r.TimedOut = true
			r.ExitCode = 137
		} else if exitErr, ok := err.(*exec.ExitError); ok {
			r.ExitCode = exitErr.ExitCode()
			if r.ExitCode == -1 {
				if ws, ok := exitErr.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
					r.ExitCode = -int(ws.Signal())
				}
			}
		}
	}

	ca := CrashAnalyzer{}
	if sig, hasSig := ca.ParseSignal(r.ExitCode); hasSig {
		r.Signal = ca.SignalName(sig)
	}

	return r, nil
}
