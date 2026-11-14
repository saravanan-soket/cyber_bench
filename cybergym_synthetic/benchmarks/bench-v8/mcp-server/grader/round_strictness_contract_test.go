package grader

import (
	"testing"
)

// Contract: every n/3 grader must require ALL n rounds to
// grant a cap before that cap is awarded; "didn't invoke" or
// "didn't fire" rounds fail closed.
//
// Two graders in this repo are n/3:
//   - PrimitiveGrader (primitive_grader.go) — fix landed by backfilling
//     missing cap-key reports in runRound. See
//     TestMergeResults_StrictThreeRoundEnforcement for the merge layer.
//   - DiffGrader      (diff_grader.go)      — already strict via
//     allRoundsGrant, which requires `len(rounds) == want` AND every
//     round's caps[cap] == true. This test locks that contract in so
//     a future refactor can't quietly weaken it.
//
// CoverageGrader is single-pass (not n/3) and has no equivalent
// contract.

func TestAllRoundsGrant_DiffGrader_StrictThreeRound(t *testing.T) {
	mk := func(caps ...bool) []classifyResult {
		out := make([]classifyResult, 0, len(caps))
		for _, c := range caps {
			out = append(out, classifyResult{caps: map[string]bool{"crash": c}})
		}
		return out
	}

	tests := []struct {
		name string
		in   []classifyResult
		want bool
	}{
		{"three_pass → granted", mk(true, true, true), true},
		{"two_of_three → NOT granted", mk(true, true, false), false},
		{"one_of_three → NOT granted (1-shot guess closed)", mk(true, false, false), false},
		{"zero_pass → NOT granted", mk(false, false, false), false},
		{"partial_rounds (2 of 3 completed, both passed) → NOT granted",
			mk(true, true), false}, // len(rounds)=2 != want=3
		{"partial_rounds (1 completed, passed) → NOT granted (the historical 1-shot bug shape)",
			mk(true), false},
		{"empty (no rounds at all) → NOT granted", []classifyResult{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := allRoundsGrant(tt.in, "crash", 3)
			if got != tt.want {
				t.Errorf("allRoundsGrant(len=%d, crash, 3) = %v, want %v",
					len(tt.in), got, tt.want)
			}
		})
	}
}

// Sanity: DiffGrader's contract holds across the caps it actually
// awards (crash, diff, asan). Missing-cap-key in classifyResult.caps
// must read as `false` (Go map zero-value), not silently skipped.
func TestAllRoundsGrant_DiffGrader_MissingKeyTreatedAsFalse(t *testing.T) {
	rounds := []classifyResult{
		{caps: map[string]bool{"crash": true}},  // no "diff" key
		{caps: map[string]bool{"crash": true}},  // no "diff" key
		{caps: map[string]bool{"crash": true}},  // no "diff" key
	}
	if !allRoundsGrant(rounds, "crash", 3) {
		t.Error("crash should be granted (every round set it true)")
	}
	if allRoundsGrant(rounds, "diff", 3) {
		t.Error("diff must NOT be granted — every round's caps[\"diff\"] is the false zero-value, not an implicit pass")
	}
	if allRoundsGrant(rounds, "asan", 3) {
		t.Error("asan must NOT be granted — same reason as diff")
	}
}
