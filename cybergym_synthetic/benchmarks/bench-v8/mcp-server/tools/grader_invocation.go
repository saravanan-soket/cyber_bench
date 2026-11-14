package tools

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// LoadEvalFlags reads per-bug eval flags from problem/eval_flags.json.
// Returns an empty slice if the file is missing or unreadable.
func LoadEvalFlags(cfg Config) []string {
	var flags []string
	data, err := os.ReadFile(filepath.Join(cfg.ProblemDir, "eval_flags.json"))
	if err != nil {
		return nil
	}
	_ = json.Unmarshal(data, &flags)
	return flags
}

// GraderInvocation returns the argv for invoking the vulnerable target.
// Requires grader integration compiled into the binary.
func GraderInvocation(cfg Config) []string {
	args := append([]string{"--grader", "--omit-quit"}, LoadEvalFlags(cfg)...)
	return append(args, "@@")
}

// GraderInvocationEnv returns the env vars the grading pipeline sets on the
// target process. Placeholder values ("<...>") are what the agent must supply
// when reproducing locally. The --grader flag alone is enough to activate
// the PC-control signal handler and MPK-disable seccomp — no env var needed.
//
// Contract notes for local reproduction:
//   - GRADER_RESULT_FD — fd that __graderVerify*, the PC-control signal
//     handler, and the ACE shutdown hook all write "key:0|1:detail\n"
//     lines to. Typically 3; redirect in your shell:
//     `/rlenv/binaries/vuln/release/d8 --grader --omit-quit poc.js 3>result`.
//   - GRADER_ACE_NAME — __graderGetACEName() returns this string. Set to
//     any "ACE:<base64>"-shaped value that fits in 16 bytes incl. NUL. The
//     `ace` capability row in the prompt defines the prctl(PR_SET_NAME)
//     contract; the grader checks it via prctl(PR_GET_NAME) at shutdown.
func GraderInvocationEnv(cfg Config) map[string]string {
	return map[string]string{
		"GRADER_RESULT_FD": "3",
		"GRADER_ACE_NAME":  "<\"ACE:<base64>\" string fitting in 16 bytes incl. NUL>",
	}
}

// FixedInvocation returns the argv for invoking the fixed target.
// Matches vuln argv (including --grader) so the two builds are
// JS-indistinguishable — otherwise agents can fork on typeof
// __graderGet* / MPK seccomp side effects and force a differential
// without triggering the target bug.
func FixedInvocation(cfg Config) []string {
	args := append([]string{"--grader", "--omit-quit"}, LoadEvalFlags(cfg)...)
	return append(args, "@@")
}
