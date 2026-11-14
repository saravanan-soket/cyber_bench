package tools

import (
	"os"
	"os/user"
	"strconv"
)

// Config holds runtime paths read from environment or defaults.
type Config struct {
	ProblemDir       string
	BinariesDir      string
	SourceDir        string
	WorkspaceDir     string
	GraderRunDir     string
	DiffGraderRunDir string
	GraderUID        uint32
	GraderGID        uint32
	GraderDiffUID    uint32
	GraderDiffGID    uint32
}

// ConfigFromEnv reads configuration from RLENV_* environment variables,
// falling back to default container paths. Also looks up the `grader` user's
// UID/GID — required for privilege-dropped grader subprocess spawns.
func ConfigFromEnv() Config {
	c := Config{
		ProblemDir:       "/rlenv/problem",
		BinariesDir:      "/rlenv/binaries",
		SourceDir:        "/rlenv/source",
		WorkspaceDir:     "/rlenv/workspace",
		GraderRunDir:     "/rlenv/grader-run",
		DiffGraderRunDir: "/rlenv/grader-diff-run",
	}
	if v := os.Getenv("RLENV_PROBLEM_DIR"); v != "" {
		c.ProblemDir = v
	}
	if v := os.Getenv("RLENV_BINARIES_DIR"); v != "" {
		c.BinariesDir = v
	}
	if v := os.Getenv("RLENV_SOURCE_DIR"); v != "" {
		c.SourceDir = v
	}
	if v := os.Getenv("RLENV_WORKSPACE_DIR"); v != "" {
		c.WorkspaceDir = v
	}

	// Resolve grader users. Missing users leave UID fields at 0; preflight
	// turns that into a fatal error.
	if u, err := user.Lookup("grader"); err == nil {
		uid, _ := strconv.ParseUint(u.Uid, 10, 32)
		gid, _ := strconv.ParseUint(u.Gid, 10, 32)
		c.GraderUID = uint32(uid)
		c.GraderGID = uint32(gid)
	}
	if u, err := user.Lookup("grader-diff"); err == nil {
		uid, _ := strconv.ParseUint(u.Uid, 10, 32)
		gid, _ := strconv.ParseUint(u.Gid, 10, 32)
		c.GraderDiffUID = uint32(uid)
		c.GraderDiffGID = uint32(gid)
	}
	return c
}
