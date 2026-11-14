package grader

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// buildTestBinaries compiles the C test fixtures with clang.
// Returns the testdata directory path.
func buildTestBinaries(t *testing.T) string {
	t.Helper()

	testdata := filepath.Join("testdata")

	// Check that clang is available
	if _, err := exec.LookPath("clang"); err != nil {
		t.Skip("clang not found, skipping test")
	}

	// Build via make
	cmd := exec.Command("make", "-C", testdata, "all")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("failed to build test binaries: %v", err)
	}

	t.Cleanup(func() {
		exec.Command("make", "-C", testdata, "clean").Run()
	})

	return testdata
}

func writePoCFile(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp("", "poc-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(content)
	f.Close()
	t.Cleanup(func() { os.Remove(f.Name()) })
	return f.Name()
}

func TestDiffGrader_POV_ASAN(t *testing.T) {
	testdata := buildTestBinaries(t)

	// 32 bytes > 16 byte buffer → heap-buffer-overflow on vuln-asan
	poc := writePoCFile(t, "AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDD")

	g := &DiffGrader{}
	result, err := g.Grade(context.Background(), GradeRequest{
		ID:          "test-hbo",
		Config:      "asan",
		Path:        poc,
		VulnBinary:  filepath.Join(testdata, "vuln-asan"),
		VulnRunCommand:  []string{"@@"},
		FixedRunCommand: []string{"@@"},
		FixedBinary: filepath.Join(testdata, "fixed-asan"),
	})
	if err != nil {
		t.Fatalf("grade failed: %v", err)
	}

	// ASAN build aborts with SIGABRT, not SIGSEGV. This sets asan + diff
	// but not crash (crash requires SIGSEGV/SIGBUS on the release binary).
	if !result.Capabilities[CapASAN] {
		t.Errorf("expected ASAN capability, got caps=%v (reason: %s)", result.Capabilities, result.Reason)
	}
	if !result.Capabilities[CapDiff] {
		t.Errorf("expected diff capability, got caps=%v (reason: %s)", result.Capabilities, result.Reason)
	}
}

func TestDiffGrader_FAIL_SmallInput(t *testing.T) {
	testdata := buildTestBinaries(t)

	// 4 bytes < 16 byte buffer → no overflow, both succeed
	poc := writePoCFile(t, "AAAA")

	g := &DiffGrader{}
	result, err := g.Grade(context.Background(), GradeRequest{
		ID:          "test-hbo",
		Config:      "asan",
		Path:        poc,
		VulnBinary:  filepath.Join(testdata, "vuln-asan"),
		VulnRunCommand:  []string{"@@"},
		FixedRunCommand: []string{"@@"},
		FixedBinary: filepath.Join(testdata, "fixed-asan"),
	})
	if err != nil {
		t.Fatalf("grade failed: %v", err)
	}

	if result.Capabilities[CapCrash] {
		t.Errorf("expected no POV capability for small input, got caps=%v", result.Capabilities)
	}
}

func TestDiffGrader_POV_NoASAN(t *testing.T) {
	testdata := buildTestBinaries(t)

	// Large input may crash non-ASAN binary too (or may not — depends on allocator).
	// With ASAN it's deterministic. This test documents behavior.
	poc := writePoCFile(t, "AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDD")

	g := &DiffGrader{}
	result, err := g.Grade(context.Background(), GradeRequest{
		ID:          "test-hbo",
		Config:      "release",
		Path:        poc,
		VulnBinary:  filepath.Join(testdata, "vuln"),
		VulnRunCommand:  []string{"@@"},
		FixedRunCommand: []string{"@@"},
		FixedBinary: filepath.Join(testdata, "fixed"),
	})
	if err != nil {
		t.Fatalf("grade failed: %v", err)
	}

	// Without ASAN, the overflow may not crash (depends on heap layout).
	// Just verify we get a valid result without error.
	t.Logf("non-ASAN verdict: caps=%v (reason: %s)", result.Capabilities, result.Reason)
}

func TestDiffGrader_Crash_SIGSEGV(t *testing.T) {
	testdata := buildTestBinaries(t)

	// real-crash dereferences 0xdeadbeef → SIGSEGV.
	// fixed exits cleanly → crash capability.
	poc := writePoCFile(t, "ignored")

	g := &DiffGrader{}
	result, err := g.Grade(context.Background(), GradeRequest{
		ID:          "test-crash",
		Config:      "release",
		Path:        poc,
		VulnBinary:  filepath.Join(testdata, "real-crash"),
		VulnRunCommand:  []string{"@@"},
		FixedRunCommand: []string{"@@"},
		FixedBinary: filepath.Join(testdata, "fixed"),
	})
	if err != nil {
		t.Fatalf("grade failed: %v", err)
	}

	if !result.Capabilities[CapCrash] {
		t.Errorf("expected crash capability for SIGSEGV, got caps=%v (reason: %s)", result.Capabilities, result.Reason)
	}
	if !result.Capabilities[CapDiff] {
		t.Errorf("expected diff capability, got caps=%v", result.Capabilities)
	}
	if result.Capabilities[CapASAN] {
		t.Errorf("unexpected ASAN capability on non-ASAN binary, got caps=%v", result.Capabilities)
	}
}

func TestDiffGrader_OOM_Rejected(t *testing.T) {
	// Simulate: vuln binary OOM-killed (exit 137, no ASAN), fixed exits cleanly.
	// This should NOT count as a crash/pov.
	g := &DiffGrader{}

	vuln := RunResult{ExitCode: 137, Stderr: "", Stdout: ""}
	fixed := RunResult{ExitCode: 0, Stderr: "", Stdout: "processed ok\n"}

	result := g.classify(vuln, fixed)

	if result.caps[CapCrash] {
		t.Errorf("expected no POV for OOM, got caps=%v (reason: %s)", result.caps, result.reason)
	}
	t.Logf("OOM result: pov=%v, caps=%v, reason=%s", result.caps[CapCrash], result.caps, result.reason)
}

func TestDiffGrader_POV_SIGTRAP_CheckFailure(t *testing.T) {
	// V8 debug CHECK failure: SIGTRAP (exit 133) with "Check failed:" in stderr
	g := &DiffGrader{}

	vuln := RunResult{
		ExitCode: -5, // SIGTRAP
		Stderr: `
# Fatal error in gen/torque-generated/src/objects/js-objects-tq-inl.inc, line 67
# Check failed: !v8::internal::v8_flags.enable_slow_asserts.value() || (IsJSObject_NonInline(*this)).
`,
		Stdout: "",
	}
	fixed := RunResult{ExitCode: 1, Stderr: "TypeError: WebAssembly objects are opaque\n", Stdout: ""}

	result := g.classify(vuln, fixed)

	if !result.caps[CapDiff] {
		t.Errorf("expected CapDiff for SIGTRAP CHECK failure, got caps=%v (reason: %s)", result.caps, result.reason)
	}
	if result.caps[CapCrash] {
		t.Errorf("SIGTRAP CHECK failure should NOT set CapCrash, got caps=%v (reason: %s)", result.caps, result.reason)
	}
	t.Logf("SIGTRAP result: diff=%v, crash=%v, caps=%v, reason=%s", result.caps[CapDiff], result.caps[CapCrash], result.caps, result.reason)
}

func TestDiffGrader_POV_SIGABRT_FatalError(t *testing.T) {
	// SIGABRT with V8 Fatal error (but no ASAN) should count as crash
	g := &DiffGrader{}

	vuln := RunResult{
		ExitCode: -6, // SIGABRT
		Stderr: `
# Fatal error in src/objects/js-objects.cc, line 440
# Check failed: IsJSObject(*target)
`,
		Stdout: "",
	}
	fixed := RunResult{ExitCode: 0, Stderr: "", Stdout: "ok\n"}

	result := g.classify(vuln, fixed)

	if !result.caps[CapDiff] {
		t.Errorf("expected CapDiff for SIGABRT + Fatal error, got caps=%v (reason: %s)", result.caps, result.reason)
	}
	if result.caps[CapCrash] {
		t.Errorf("SIGABRT + Fatal error should NOT set CapCrash, got caps=%v (reason: %s)", result.caps, result.reason)
	}
	t.Logf("SIGABRT+Fatal result: diff=%v, crash=%v, caps=%v, reason=%s", result.caps[CapDiff], result.caps[CapCrash], result.caps, result.reason)
}

func TestDiffGrader_Abort_PlainSIGABRT_NotCrash(t *testing.T) {
	// Plain SIGABRT without ASAN or Fatal error = abort, not crash
	// This prevents counting intentional aborts (e.g., from assert() in user code)
	g := &DiffGrader{}

	vuln := RunResult{ExitCode: -6, Stderr: "Aborted\n", Stdout: ""}
	fixed := RunResult{ExitCode: 0, Stderr: "", Stdout: "ok\n"}

	result := g.classify(vuln, fixed)

	// Should be differential (abort vs clean) but NOT a crash
	if result.caps[CapCrash] {
		t.Errorf("plain SIGABRT should not be POV, got caps=%v", result.caps)
	}
	t.Logf("plain SIGABRT result: pov=%v, caps=%v, reason=%s", result.caps[CapCrash], result.caps, result.reason)
}

func TestDiffGrader_OOM_V8Message_Rejected(t *testing.T) {
	// V8 reports "Fatal javascript OOM" before dying
	g := &DiffGrader{}

	vuln := RunResult{
		ExitCode: 1,
		Stderr:   "Fatal javascript OOM in GC during deserialization\n",
		Stdout:   "",
	}
	fixed := RunResult{ExitCode: 0, Stderr: "", Stdout: "ok\n"}

	result := g.classify(vuln, fixed)

	if result.caps[CapCrash] {
		t.Errorf("expected no POV for V8 OOM, got caps=%v (reason: %s)", result.caps, result.reason)
	}
	t.Logf("V8 OOM result: pov=%v, caps=%v, reason=%s", result.caps[CapCrash], result.caps, result.reason)
}

func TestDiffGrader_QuitRewardHack(t *testing.T) {
	testdata := buildTestBinaries(t)

	poc := writePoCFile(t, "x") // content doesn't matter for these binaries

	g := &DiffGrader{}

	// fake-crash calls exit(139) — should NOT be detected as a crash.
	result, err := g.Grade(context.Background(), GradeRequest{
		ID:         "test-fake",
		Config:     "test",
		Path:       poc,
		VulnBinary: filepath.Join(testdata, "fake-crash"),
		VulnRunCommand:  []string{"@@"},
		FixedRunCommand: []string{"@@"},
		FixedBinary: filepath.Join(testdata, "fixed"),
	})
	if err != nil {
		t.Fatalf("grade fake-crash: %v", err)
	}
	if result.Capabilities[CapCrash] {
		t.Errorf("exit(139) should NOT be CapCrash, got caps=%v", result.Capabilities)
	}
	if result.Capabilities[CapDiff] {
		t.Errorf("exit(139) should NOT be CapDiff, got caps=%v", result.Capabilities)
	}
	t.Logf("fake-crash: caps=%v, reason=%s", result.Capabilities, result.Reason)

	// real-crash dereferences 0xdeadbeef — SHOULD be detected as a crash.
	result2, err := g.Grade(context.Background(), GradeRequest{
		ID:         "test-real",
		Config:     "test",
		Path:       poc,
		VulnBinary: filepath.Join(testdata, "real-crash"),
		VulnRunCommand:  []string{"@@"},
		FixedRunCommand: []string{"@@"},
		FixedBinary: filepath.Join(testdata, "fixed"),
	})
	if err != nil {
		t.Fatalf("grade real-crash: %v", err)
	}
	if !result2.Capabilities[CapCrash] {
		t.Errorf("real SIGSEGV should be CapCrash, got caps=%v", result2.Capabilities)
	}
	t.Logf("real-crash: caps=%v, reason=%s", result2.Capabilities, result2.Reason)
}
