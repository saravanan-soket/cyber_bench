package tools

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const defaultExecTimeout = 60 * time.Second
const maxOutputBytes = 128 * 1024 // 128 KB per stream (~32K tokens)

// postExitPipeDrain bounds cmd.Run()'s wait for stdout/stderr to reach EOF
// after the foreground shell exits. A child backgrounded without redirecting
// its fds inherits the pipe and would otherwise block the call for its whole
// lifetime. Short so a backgrounded launch returns promptly.
const postExitPipeDrain = 100 * time.Millisecond

// execMu serializes exec invocations: killAtSelfUID is sound only when one
// exec subtree is alive at our UID.
var execMu sync.Mutex

// cleanupStraggler reaps UID-owned stragglers the command left behind.
// Indirected so tests can stub it; killAtSelfUID is safe only in-container (on
// a dev host it would SIGKILL the whole session).
var cleanupStraggler = killAtSelfUID

type ExecInput struct {
	Cmd     string  `json:"cmd" jsonschema:"Shell command to execute"`
	Timeout float64 `json:"timeout,omitempty" jsonschema:"Optional timeout in seconds. Defaults to 60s. Values larger than 60s are silently capped to 60s; values <= 0 fall back to the default."`
}

type ExecOutput struct {
	ExitCode int    `json:"exitcode"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
}

func RegisterExec(server *mcp.Server) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "exec",
		Description: "Run a shell command. Use for git, grep, gdb, build tools, etc. stdout and stderr are each truncated to 128 KB; use head/tail/grep to narrow large outputs.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, input ExecInput) (*mcp.CallToolResult, ExecOutput, error) {
		timeout := defaultExecTimeout
		if input.Timeout > 0 {
			if requested := time.Duration(input.Timeout * float64(time.Second)); requested < timeout {
				timeout = requested
			}
		}
		out, err := runExecCommand(ctx, input.Cmd, timeout)
		return nil, out, err
	})
}

// runExecCommand runs `sh -c shellCmd` with a wall-clock timeout and bounded
// output. Cleanup kills the foreground process group then sweeps UID-owned
// stragglers (see reapExecTree). WaitDelay bounds the post-exit pipe drain.
func runExecCommand(ctx context.Context, shellCmd string, timeout time.Duration) (ExecOutput, error) {
	execMu.Lock()
	defer execMu.Unlock()

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "sh", "-c", shellCmd)
	// Own process group so the whole foreground subtree can be SIGKILLed at once.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		reapExecTree(cmd)
		return nil
	}
	cmd.WaitDelay = postExitPipeDrain
	// Runs on every return, including the prompt happy path where Cancel never
	// fires, so a backgrounded child cannot outlive the call.
	defer reapExecTree(cmd)

	// Re-add depot_tools to the agent shell's PATH (MCP's own PATH excludes it)
	// and pin HOME so depot_tools telemetry init doesn't EACCES post-downgrade.
	env := slices.DeleteFunc(os.Environ(), func(e string) bool {
		return strings.HasPrefix(e, "PATH=") || strings.HasPrefix(e, "HOME=")
	})
	cmd.Env = append(env,
		"PATH=/rlenv/source/depot_tools:"+os.Getenv("PATH"),
		"HOME=/home/agent",
	)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	// Timeout first: a signal-killed process reports ExitCode -1, which would
	// otherwise mask it. 137 (128 + SIGKILL) is the shell convention.
	exitCode := 0
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		exitCode = 137
	} else if cmd.ProcessState != nil {
		exitCode = cmd.ProcessState.ExitCode()
	}
	if err != nil {
		// Non-zero exit, bounded pipe drain, and timeout are all expected and
		// already in exitCode; anything else is a real spawn/wait failure.
		_, isExit := err.(*exec.ExitError)
		if !isExit && !errors.Is(err, exec.ErrWaitDelay) && !errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return ExecOutput{}, fmt.Errorf("exec failed: %w", err)
		}
	}

	return ExecOutput{
		ExitCode: exitCode,
		Stdout:   truncateBytes(stdout.String(), maxOutputBytes),
		Stderr:   truncateBytes(stderr.String(), maxOutputBytes),
	}, nil
}

// reapExecTree kills the command's process group, then sweeps UID-owned
// stragglers. The group kill clears the common case (the command and its `&`
// jobs share the group) in one syscall; killAtSelfUID then catches children
// that escaped the group via setsid/double-fork.
func reapExecTree(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cleanupStraggler()
}

// killAtSelfUID SIGKILLs every process whose real UID is ours, except
// ourselves. The real UID comes from /proc/<pid>/status (world-readable even
// for a PR_SET_DUMPABLE=0 child, whose /proc dir owner flips to root), and we
// hold no CAP_KILL so the kernel signal-permission check is the hard bound on
// what is actually delivered. Caller must hold execMu.
func killAtSelfUID() {
	selfPid := os.Getpid()
	selfUID := uint32(os.Getuid())
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return
	}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == selfPid {
			continue
		}
		status, err := os.ReadFile("/proc/" + e.Name() + "/status")
		if err != nil {
			continue
		}
		uid, ok := realUIDFromStatus(status)
		if !ok || uid != selfUID {
			continue
		}
		_ = syscall.Kill(pid, syscall.SIGKILL)
	}
}

// realUIDFromStatus parses the real UID (first value of the "Uid:" line) from
// /proc/<pid>/status. Kernel format: "Uid:\t<real>\t<euid>\t<suid>\t<fsuid>".
// Scanned from the end: the only caller-controlled field is comm (the Name
// line, always first), so a "Uid:" line forged via a comm newline can only sit
// above the real one. Returns false if no well-formed Uid line is present.
func realUIDFromStatus(status []byte) (uint32, bool) {
	lines := strings.Split(string(status), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		rest, ok := strings.CutPrefix(lines[i], "Uid:")
		if !ok {
			continue
		}
		fields := strings.Fields(rest) // real, euid, suid, fsuid
		if len(fields) < 1 {
			return 0, false
		}
		uid, err := strconv.ParseUint(fields[0], 10, 32)
		if err != nil {
			return 0, false
		}
		return uint32(uid), true
	}
	return 0, false
}
