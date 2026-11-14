package grader

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

// File operations performed as the grader UID via fork+execve of /bin/sh.
// MCP runs as `agent` with CAP_SETUID file caps; to touch files inside
// /rlenv/grader-run/ (which is root:grader 0700) it forks a helper that
// drops to grader before running.  Keeping grader-state files unreachable
// to same-UID agent daemons is the whole point of Fix 2 isolation — these
// helpers are how MCP talks to that isolated space.
//
// If cred is nil (test/dev path), operations run as the current UID.  In
// production cred is always &syscall.Credential{Uid: graderUID, Gid: graderGID}.

// mkGraderTempDir creates a fresh subdir under baseDir as cred's UID. The
// dir is mode 0700 owned by cred, so same-UID-as-MCP agent daemons cannot
// enumerate or read it. baseDir must already exist and be writable by cred
// (set up in the Dockerfile — /rlenv/grader-run, /rlenv/grader-diff-run).
func mkGraderTempDir(ctx context.Context, cred *syscall.Credential, baseDir, prefix string) (string, error) {
	if cred == nil {
		return os.MkdirTemp("", prefix+"-*")
	}
	// mktemp -d does atomic name selection; run via `sh -c` so baseDir is
	// quoted as $1 and not exposed to shell parsing.
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c",
		`mktemp -d "$1/$2-XXXXXXXX"`, "sh", baseDir, prefix)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: cred}
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("mktemp -d %s/%s-XXXXXXXX as cred: %w", baseDir, prefix, err)
	}
	return strings.TrimSpace(string(out)), nil
}

// readFileAsGrader reads a file as the grader UID and returns its contents.
func readFileAsGrader(ctx context.Context, cred *syscall.Credential, path string) ([]byte, error) {
	if cred == nil {
		return os.ReadFile(path)
	}
	cmd := exec.CommandContext(ctx, "cat", path)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: cred}
	return cmd.Output()
}

// listDirAsGrader returns the filenames (basenames) in a dir, as grader.
// Empty slice if the dir is empty or missing.
func listDirAsGrader(ctx context.Context, cred *syscall.Credential, dir string) ([]string, error) {
	if cred == nil {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return nil, err
		}
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		return names, nil
	}
	// ls -1A: one-per-line, include dotfiles (except . and ..).
	cmd := exec.CommandContext(ctx, "ls", "-1A", "--", dir)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: cred}
	out, _ := cmd.Output()
	raw := strings.TrimSpace(string(out))
	if raw == "" {
		return nil, nil
	}
	return strings.Split(raw, "\n"), nil
}

// killPgidAsGrader SIGKILLs the pgrp led by pid, running as cred so the
// signal is permitted (same UID as the d8 children). MCP holds no
// CAP_KILL, so a direct syscall.Kill across UIDs returns EPERM.
//
// pid must come from a child started with Setpgid:true (pgid==pid).
func killPgidAsGrader(ctx context.Context, cred *syscall.Credential, pid int) error {
	if pid <= 0 {
		return fmt.Errorf("killPgidAsGrader: invalid pid %d", pid)
	}
	if cred == nil {
		return syscall.Kill(-pid, syscall.SIGKILL)
	}
	cmd := exec.Command("/bin/kill", "-KILL", "--", fmt.Sprintf("-%d", pid))
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: cred}
	return cmd.Run()
}

// removeAllAsGrader recursively removes a path as grader. Errors are logged
// but not surfaced — cleanup failure is not fatal.
func removeAllAsGrader(ctx context.Context, cred *syscall.Credential, path string) {
	if cred == nil {
		_ = os.RemoveAll(path)
		return
	}
	// Safety: only allow removal inside known grader scratch dirs.
	if path == "" || !(strings.HasPrefix(path, "/rlenv/grader-run/") ||
		strings.HasPrefix(path, "/rlenv/grader-diff-run/")) {
		return
	}
	cmd := exec.CommandContext(ctx, "rm", "-rf", path)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: cred}
	_ = cmd.Run()
}

