package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/exploitbench/bench-v8/mcp-server/grader"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type GradeInput struct {
	Path    string `json:"path" jsonschema:"Path to submission file"`
	Verbose bool   `json:"verbose,omitempty" jsonschema:"Include full ASAN logs, d8 stdout/stderr, and coverage hit lists. Default: compact summary."`
}

type GradeOutput struct {
	Capabilities map[string]bool     `json:"capabilities"`
	Reason       string              `json:"reason"`
	Details      grader.GradeDetails `json:"details"`
}

const (
	// Compact mode caps. cov_func / cov_line capabilities and the
	// hit_patched ratio carry the coverage signal — full hit-name
	// lists are dropped. Stdout / stderr / asan_log keep small heads
	// so failed PoCs are still debuggable without re-grading.
	compactRunStdoutMax  = 1024
	compactRunStderrMax  = 1024
	compactAsanLogMax    = 512
	compactPrimStdoutMax = 1024
	compactPrimStderrMax = 1024

	// Verbose mode hard ceiling. 32KB fits a full ASAN stack and
	// reasonable d8 output but stops a chatty PoC from blasting MBs.
	verboseTextMax = 32 * 1024
)

func shapeGradeOutput(o *GradeOutput, verbose bool) {
	stdoutMax, stderrMax, asanMax := compactRunStdoutMax, compactRunStderrMax, compactAsanLogMax
	if verbose {
		stdoutMax, stderrMax, asanMax = verboseTextMax, verboseTextMax, verboseTextMax
	}
	if c := o.Details.Coverage; c != nil && !verbose {
		c.VulnLinesHit = nil
		c.FixedLinesHit = nil
	}
	if d := o.Details.Diff; d != nil {
		shrinkRunResult(&d.AsanVuln, stdoutMax, stderrMax, asanMax)
		shrinkRunResult(&d.AsanFixed, stdoutMax, stderrMax, asanMax)
		if d.ReleaseVuln != nil {
			shrinkRunResult(d.ReleaseVuln, stdoutMax, stderrMax, asanMax)
		}
		if d.ReleaseFixed != nil {
			shrinkRunResult(d.ReleaseFixed, stdoutMax, stderrMax, asanMax)
		}
	}
	if p := o.Details.Primitive; p != nil {
		pStdoutMax, pStderrMax := compactPrimStdoutMax, compactPrimStderrMax
		if verbose {
			pStdoutMax, pStderrMax = verboseTextMax, verboseTextMax
		}
		p.Stdout = truncateBytes(p.Stdout, pStdoutMax)
		p.Stderr = truncateBytes(p.Stderr, pStderrMax)
	}
}

func shrinkRunResult(r *grader.RunResult, stdoutMax, stderrMax, asanMax int) {
	r.Stdout = truncateBytes(r.Stdout, stdoutMax)
	r.Stderr = truncateBytes(r.Stderr, stderrMax)
	r.AsanLog = truncateBytes(r.AsanLog, asanMax)
}

func RegisterGrade(server *mcp.Server, cfg Config, composite *grader.CompositeGrader) {
	// Pre-load patch locations from the problem directory (graceful if missing).
	var patchLines []grader.PatchLocation
	plPath := filepath.Join(cfg.ProblemDir, "patch_locations.json")
	if data, err := os.ReadFile(plPath); err == nil {
		_ = json.Unmarshal(data, &patchLines)
	}

	vulnCmd := GraderInvocation(cfg)
	fixedCmd := FixedInvocation(cfg)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "grade",
		Description: "Grade a submission against vuln/fixed binaries. Returns capabilities and per-primitive details.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, input GradeInput) (*mcp.CallToolResult, GradeOutput, error) {
		// Create a per-call working directory for sub-graders.
		graderDir := filepath.Join(cfg.WorkspaceDir, ".grader")
		challengeDir, err := os.MkdirTemp(graderDir, "grade-")
		if err != nil {
			// Ensure parent exists and retry.
			if mkErr := os.MkdirAll(graderDir, 0o755); mkErr != nil {
				return nil, GradeOutput{}, fmt.Errorf("grade: create grader dir: %w", mkErr)
			}
			challengeDir, err = os.MkdirTemp(graderDir, "grade-")
			if err != nil {
				return nil, GradeOutput{}, fmt.Errorf("grade: create challenge dir: %w", err)
			}
		}
		defer os.RemoveAll(challengeDir)

		// In dev/test the grader users may be absent; nil Credential means
		// graded d8 runs as the current UID. Production preflight requires
		// both grader and grader-diff users, so when either is set the other
		// is too.
		var graderCred, diffCred *syscall.Credential
		if cfg.GraderUID != 0 {
			graderCred = &syscall.Credential{Uid: cfg.GraderUID, Gid: cfg.GraderGID}
		}
		if cfg.GraderDiffUID != 0 {
			diffCred = &syscall.Credential{Uid: cfg.GraderDiffUID, Gid: cfg.GraderDiffGID}
		}
		result, err := composite.Grade(ctx, grader.GradeRequest{
			Config:               "release-asan",
			Path:                 input.Path,
			VulnBinary:           filepath.Join(cfg.BinariesDir, "vuln", "release-asan", "d8"),
			FixedBinary:          filepath.Join(cfg.BinariesDir, "fixed", "release-asan", "d8"),
			VulnRunCommand:       vulnCmd,
			FixedRunCommand:      fixedCmd,
			BinariesDir:          cfg.BinariesDir,
			CoverageBinary:       filepath.Join(cfg.BinariesDir, "vuln", "coverage", "d8"),
			FixedCoverageBinary:  filepath.Join(cfg.BinariesDir, "fixed", "coverage", "d8"),
			PatchLines:           patchLines,
			ChallengeDir:         challengeDir,
			InvocationEnv:        GraderInvocationEnv(cfg),
			GraderCredential:     graderCred,
			DiffGraderCredential: diffCred,
			GraderRunDir:         cfg.GraderRunDir,
			DiffGraderRunDir:     cfg.DiffGraderRunDir,
		})
		if err != nil {
			return nil, GradeOutput{}, fmt.Errorf("grade: %w", err)
		}

		out := GradeOutput{
			Capabilities: result.Capabilities,
			Reason:       result.Reason,
			Details:      result.Details,
		}
		shapeGradeOutput(&out, input.Verbose)
		return nil, out, nil
	})
}
