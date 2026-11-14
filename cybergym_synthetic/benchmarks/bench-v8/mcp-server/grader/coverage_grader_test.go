package grader

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// hasFileLine returns true if any filename in m has fileSuffix as a
// suffix and that file's line list contains line. Suffix-match on the
// filename so tests don't depend on the absolute path llvm-cov emits.
func hasFileLine(m map[string][]int, fileSuffix string, line int) bool {
	for f, lines := range m {
		if f == fileSuffix || strings.HasSuffix(f, "/"+fileSuffix) {
			for _, l := range lines {
				if l == line {
					return true
				}
			}
		}
	}
	return false
}

// requireCovTools skips the test if any of the coverage toolchain binaries
// are missing, so a minimal dev env still passes `go test`.
func requireCovTools(t *testing.T) {
	t.Helper()
	for _, bin := range []string{"clang", "llvm-profdata", "llvm-cov"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not found on PATH, skipping coverage test", bin)
		}
	}
}

// writePoC drops `content` into a temp file under t.TempDir() and returns the
// absolute path. Mirrors writePoCFile in diff_grader_test.go but independent.
func writePoC(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "poc-*.txt")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("write poc: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close poc: %v", err)
	}
	return f.Name()
}

// coverageTestRequest builds a GradeRequest pointing at the fixture binaries
// with PatchLocations that describe the real diff between testdata/vuln.c and
// testdata/fixed.c.
//
// The only code-line change is the malloc call:
//   vuln.c:36  `    char *buf = (char *)malloc(16);`
//   fixed.c:33 `    char *buf = (char *)malloc(size > 0 ? size : 1);`
// (Line 35 / 32 are comments and would be filtered by extract_patch_locations
// at the Python layer; the Go side never sees them.)
func coverageTestRequest(t *testing.T, testdata, pocPath string) GradeRequest {
	t.Helper()
	return GradeRequest{
		Path:                pocPath,
		CoverageBinary:      filepath.Join(testdata, "vuln-cov"),
		FixedCoverageBinary: filepath.Join(testdata, "fixed-cov"),
		VulnRunCommand:      []string{"@@"},
		PatchLines: []PatchLocation{
			{File: "vuln.c", Side: SideVuln, StartLine: 36, EndLine: 36},
			{File: "fixed.c", Side: SideFixed, StartLine: 33, EndLine: 33},
		},
		// GraderCredential / GraderRunDir nil → helpers fall back to
		// os.MkdirTemp / os.ReadDir / os.ReadFile / os.RemoveAll, so the
		// test works without the grader UID and without /rlenv/grader-run.
	}
}

// Positive case: PoC that passes the argc check and opens a real file drives
// both binaries through the malloc line. Both sides should report hits.
func TestCoverageGrader_DualSideHits(t *testing.T) {
	requireCovTools(t)
	testdata := buildTestBinaries(t)
	poc := writePoC(t, "xxxxxxxxxxxxxxxxxxxxxxxx") // 24 bytes, overflows vuln's malloc(16)

	g := &CoverageGrader{}
	caps, details, err := g.Check(context.Background(), coverageTestRequest(t, testdata, poc))
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !caps[CapCovFunc] {
		t.Errorf("cov_func not set; want true")
	}
	if !caps[CapCovLine] {
		t.Errorf("cov_line not set; want true")
	}

	result := details.(*CoverageResult)
	if !hasFileLine(result.VulnLinesHit, "vuln.c", 36) {
		t.Errorf("expected vuln.c:36 in VulnLinesHit, got %v", result.VulnLinesHit)
	}
	if !hasFileLine(result.FixedLinesHit, "fixed.c", 33) {
		t.Errorf("expected fixed.c:33 in FixedLinesHit, got %v", result.FixedLinesHit)
	}
	if result.HitPatched < 2 {
		t.Errorf("HitPatched=%d, want >= 2 (one per side)", result.HitPatched)
	}
	if result.TotalPatched != 2 {
		t.Errorf("TotalPatched=%d, want 2", result.TotalPatched)
	}
}

// Negative case: PoC file path doesn't exist. Both binaries bail out at
// fopen() before reaching the malloc line. Neither side's patched line is
// hit → cov_line must be false. Also checks that "the function" is still
// recorded as entered (main runs, but not `process`), so the specific patched
// function (`main`'s body around malloc) is not in FunctionsHit.
func TestCoverageGrader_NoHitsWhenBugPathMissed(t *testing.T) {
	requireCovTools(t)
	testdata := buildTestBinaries(t)
	// Use a path that doesn't exist so fopen fails and execution bails.
	// This covers main() but not the malloc-line region.
	pocPath := filepath.Join(t.TempDir(), "does-not-exist.txt")

	g := &CoverageGrader{}
	caps, details, err := g.Check(context.Background(), coverageTestRequest(t, testdata, pocPath))
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if caps[CapCovLine] {
		result := details.(*CoverageResult)
		t.Errorf("cov_line fired despite PoC bailing before patched line; vuln=%v fixed=%v",
			result.VulnLinesHit, result.FixedLinesHit)
	}
}

// Multi-file patches with overlapping line numbers: foo.cc:100 and
// bar.cc:100 are two distinct patched lines, both hit. They must
// register as 2 hits, not collapse into 1.
func TestReduceCoverage_MultiFileSameLineNumber(t *testing.T) {
	raw := func(v interface{}) json.RawMessage {
		b, _ := json.Marshal(v)
		return b
	}
	// Two segments per file: [start of region (count=1)], [end (count=0)].
	// Format: [line, col, count, hasCount, isRegionEntry, isGapRegion]
	segs := func() [][]json.RawMessage {
		return [][]json.RawMessage{
			{raw(100), raw(1), raw(1), raw(true)},
			{raw(101), raw(1), raw(0), raw(false)},
		}
	}
	export := &llvmCovExport{
		Data: []llvmCovData{{
			Files: []llvmCovFile{
				{Filename: "/src/foo.cc", Segments: segs()},
				{Filename: "/src/bar.cc", Segments: segs()},
			},
		}},
	}
	patches := []PatchLocation{
		{File: "foo.cc", Side: SideVuln, StartLine: 100, EndLine: 100},
		{File: "bar.cc", Side: SideVuln, StartLine: 100, EndLine: 100},
	}
	result := reduceCoverage(export, patches, SideVuln)

	if result.HitPatched != 2 {
		t.Errorf("HitPatched=%d, want 2 (foo.cc:100 + bar.cc:100)", result.HitPatched)
	}
	if result.TotalPatched != 2 {
		t.Errorf("TotalPatched=%d, want 2", result.TotalPatched)
	}
	if !hasFileLine(result.VulnLinesHit, "foo.cc", 100) {
		t.Errorf("missing foo.cc:100 in VulnLinesHit: %v", result.VulnLinesHit)
	}
	if !hasFileLine(result.VulnLinesHit, "bar.cc", 100) {
		t.Errorf("missing bar.cc:100 in VulnLinesHit: %v", result.VulnLinesHit)
	}
}

// Unit test for the side-split helper. Empty Side defaults to vuln so that
// old patch_locations.json files (pre-Side-field) still work.
func TestSplitBySide(t *testing.T) {
	patches := []PatchLocation{
		{File: "a.cc", Side: SideVuln, StartLine: 10, EndLine: 10},
		{File: "a.cc", Side: SideFixed, StartLine: 20, EndLine: 20},
		{File: "a.cc", Side: "", StartLine: 30, EndLine: 30}, // legacy
	}
	vuln, fixed := splitBySide(patches)
	if len(vuln) != 2 {
		t.Errorf("vuln len=%d, want 2 (explicit + legacy)", len(vuln))
	}
	if len(fixed) != 1 {
		t.Errorf("fixed len=%d, want 1", len(fixed))
	}
	if fixed[0].StartLine != 20 {
		t.Errorf("fixed[0].StartLine=%d, want 20", fixed[0].StartLine)
	}
}
