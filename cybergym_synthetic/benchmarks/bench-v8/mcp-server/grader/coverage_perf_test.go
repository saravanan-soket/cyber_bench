package grader

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

// Regression cover for the functionOverlapsPatches O(F×R×N×P) blowup.
// Without the loop-invariant hoist, this dataset wedges at ~10s+; the fix
// moves the file-match check out of the per-region loop, making it sub-ms.
//
// Synthesizes a llvmCovExport that mirrors V8-shape: many hit functions,
// each with many regions, against a non-trivial patch list.
func TestReduceCoverage_HotPathBounded(t *testing.T) {
	const (
		numFunctions     = 1000
		regionsPerFn     = 100
		numPatches       = 100
		hardLimit        = 500 * time.Millisecond
	)

	patches := make([]PatchLocation, numPatches)
	for i := range patches {
		patches[i] = PatchLocation{
			File:      fmt.Sprintf("src/foo/bar%d.cc", i),
			StartLine: 1,
			EndLine:   100,
		}
	}

	fns := make([]llvmCovFunction, numFunctions)
	for i := range fns {
		regions := make([][]json.RawMessage, regionsPerFn)
		for r := 0; r < regionsPerFn; r++ {
			regions[r] = []json.RawMessage{
				json.RawMessage(fmt.Sprintf("%d", r*10+1)),
				json.RawMessage("1"),
				json.RawMessage(fmt.Sprintf("%d", r*10+9)),
				json.RawMessage("1"),
				json.RawMessage("1"),
			}
		}
		fns[i] = llvmCovFunction{
			Name:      fmt.Sprintf("Fn_%d", i),
			Count:     1,
			Filenames: []string{fmt.Sprintf("../../src/no/match%d.cc", i)},
			Regions:   regions,
		}
	}

	export := &llvmCovExport{
		Data: []llvmCovData{{Functions: fns}},
	}

	start := time.Now()
	_ = reduceCoverage(export, patches, "vuln")
	elapsed := time.Since(start)

	if elapsed > hardLimit {
		t.Fatalf("reduceCoverage took %v (limit %v); functionOverlapsPatches "+
			"loop-invariant hoist regressed", elapsed, hardLimit)
	}
}

// Stresses the hit-line collection path with V8-shape workload: many
// segments per file, many lines per segment, multi-file patches that
// each match. Guards against accidental quadratic regressions in the
// hitLines / collectHitLines structure when this code is touched.
func TestReduceCoverage_LineCollectionBounded(t *testing.T) {
	const (
		numFiles        = 5
		segmentsPerFile = 2000
		linesPerSegment = 50
		hardLimit       = 200 * time.Millisecond
	)

	patches := make([]PatchLocation, numFiles)
	for i := range patches {
		patches[i] = PatchLocation{
			File:      fmt.Sprintf("src/foo/bar%d.cc", i),
			Side:      SideVuln,
			StartLine: 1,
			EndLine:   segmentsPerFile * linesPerSegment,
		}
	}

	files := make([]llvmCovFile, numFiles)
	for f := range files {
		segs := make([][]json.RawMessage, segmentsPerFile)
		for s := 0; s < segmentsPerFile; s++ {
			segs[s] = []json.RawMessage{
				json.RawMessage(fmt.Sprintf("%d", s*linesPerSegment+1)),
				json.RawMessage("1"),
				json.RawMessage("1"),
				json.RawMessage("true"),
			}
		}
		files[f] = llvmCovFile{
			Filename: fmt.Sprintf("../../src/foo/bar%d.cc", f),
			Segments: segs,
		}
	}
	export := &llvmCovExport{Data: []llvmCovData{{Files: files}}}

	start := time.Now()
	r := reduceCoverage(export, patches, SideVuln)
	elapsed := time.Since(start)

	if elapsed > hardLimit {
		t.Fatalf("reduceCoverage took %v (limit %v) on %d files × %d segments",
			elapsed, hardLimit, numFiles, segmentsPerFile)
	}
	// Sanity: per-file dedup must keep them distinct.
	if len(r.VulnLinesHit) != numFiles {
		t.Errorf("expected %d files in VulnLinesHit, got %d (per-file dedup wrong)",
			numFiles, len(r.VulnLinesHit))
	}
}

// Sanity: the optimized functionOverlapsPatches must still return true when
// a function's filename matches a patch and one of its regions overlaps.
func TestFunctionOverlapsPatches_StillCorrect(t *testing.T) {
	patches := []PatchLocation{
		{File: "src/foo/patched.cc", StartLine: 1388, EndLine: 1393},
		{File: "src/other/unrelated.cc", StartLine: 10, EndLine: 20},
	}
	fn := llvmCovFunction{
		Name:      "PatchedFn",
		Count:     1,
		Filenames: []string{"../../src/foo/patched.cc"},
		Regions: [][]json.RawMessage{
			{
				json.RawMessage("1390"), json.RawMessage("1"),
				json.RawMessage("1391"), json.RawMessage("1"),
				json.RawMessage("1"),
			},
		},
	}
	if !functionOverlapsPatches(fn, patches) {
		t.Errorf("expected overlap (region 1390-1391 ⊂ patch 1388-1393)")
	}

	// And it must NOT return true when filename doesn't match any patch.
	fn.Filenames = []string{"../../src/totally/different.cc"}
	if functionOverlapsPatches(fn, patches) {
		t.Errorf("unexpected overlap when no filename matches")
	}
}
