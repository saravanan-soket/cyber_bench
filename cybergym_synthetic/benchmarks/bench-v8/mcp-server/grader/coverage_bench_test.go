package grader

import (
	"encoding/json"
	"os"
	"testing"
)

// Run with:
//   BENCH_COV_JSON=/tmp/full.json BENCH_PATCHES=/tmp/patch_locations.json \
//   go test -bench=Coverage -benchmem -run=^$ ./grader/ -benchtime=3x
//
// Skips if env not set so unit-test runs aren't blocked.

func loadCovJSON(b *testing.B) []byte {
	b.Helper()
	p := os.Getenv("BENCH_COV_JSON")
	if p == "" {
		b.Skip("BENCH_COV_JSON not set")
	}
	d, err := os.ReadFile(p)
	if err != nil {
		b.Fatalf("read %s: %v", p, err)
	}
	return d
}

func loadPatches(b *testing.B) []PatchLocation {
	b.Helper()
	p := os.Getenv("BENCH_PATCHES")
	if p == "" {
		b.Skip("BENCH_PATCHES not set")
	}
	d, err := os.ReadFile(p)
	if err != nil {
		b.Fatalf("read %s: %v", p, err)
	}
	var locs []PatchLocation
	if err := json.Unmarshal(d, &locs); err != nil {
		b.Fatalf("unmarshal patches: %v", err)
	}
	return locs
}

// (a) cost of json.Unmarshal alone
func BenchmarkCoverage_Unmarshal(b *testing.B) {
	covJSON := loadCovJSON(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var export llvmCovExport
		if err := json.Unmarshal(covJSON, &export); err != nil {
			b.Fatal(err)
		}
	}
}

// (b) cost of reduceCoverage given an already-parsed export
func BenchmarkCoverage_Reduce(b *testing.B) {
	covJSON := loadCovJSON(b)
	patches := loadPatches(b)
	var export llvmCovExport
	if err := json.Unmarshal(covJSON, &export); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = reduceCoverage(&export, patches, "vuln")
	}
}

// (c) full pipeline: Unmarshal + Reduce, what production pays per-side
func BenchmarkCoverage_Pipeline(b *testing.B) {
	covJSON := loadCovJSON(b)
	patches := loadPatches(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var export llvmCovExport
		if err := json.Unmarshal(covJSON, &export); err != nil {
			b.Fatal(err)
		}
		_ = reduceCoverage(&export, patches, "vuln")
	}
}

// (d) parseSegNum cost in isolation; regression guard for the
// strconv.ParseInt fast path.
func BenchmarkCoverage_ParseSegNum(b *testing.B) {
	raw := json.RawMessage("12345")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = parseSegNum(raw)
	}
}
