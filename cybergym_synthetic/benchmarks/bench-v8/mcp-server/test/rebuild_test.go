//go:build functional

// Verify the agent can actually rebuild d8 inside the container — the
// path the prompt-template explicitly tells the model to use.
//
// Two things broke this in the past, both detectable here:
//   - chromium update.py >=2025 clobbers third_party/llvm-build/Release+Asserts/
//     when invoked with --package=coverage_tools, removing libclang_rt
//     and cr_build_revision. Build then fails at gn-regen or link.
//   - HOME defaults to /root post-downgrade, so depot_tools' telemetry
//     init hits EACCES on /root/.config/depot_tools and autoninja aborts.

package test

import (
	"strings"
	"testing"
)

// TestFunctional_RebuildToolchainPresent asserts that every file the agent's
// d8-rebuild path depends on actually exists in the image. Pinpoints which
// piece is missing if a Dockerfile change drops something.
func TestFunctional_RebuildToolchainPresent(t *testing.T) {
	t.Parallel()
	image := requireImage(t)
	s := newMCPSession(t, image)

	// path → human-readable label for the failure message; wantOwner is
	// the expected owner ("" = unchecked).
	required := []struct{ path, label, wantOwner string }{
		// Agent-side runtime helpers — root-owned so an agent compromise
		// can't tamper with the binaries the grader's ASAN runs invoke.
		{"/usr/local/bin/llvm-symbolizer", "llvm-symbolizer (ASAN stack symbolication)", "root"},
		{"/usr/local/bin/llvm-cov", "llvm-cov (coverage post-processing)", "root"},
		{"/usr/local/bin/llvm-profdata", "llvm-profdata (coverage post-processing)", "root"},

		// gn-regen prerequisites (chromium clang toolchain markers).
		// Missing => "rebuild manifest failed: cr_build_revision: Could not read file".
		{"/rlenv/source/v8/third_party/llvm-build/Release+Asserts/cr_build_revision", "cr_build_revision (chromium toolchain stamp; gn regen reads it)", ""},

		// Build-time tooling on PATH for the agent shell.
		{"/rlenv/source/depot_tools/autoninja", "autoninja (build wrapper, prompt-documented entrypoint)", ""},
		{"/rlenv/source/depot_tools/gclient", "gclient (chromium dep manager)", ""},
		{"/rlenv/source/v8/buildtools/linux64/gn", "gn (build-graph generator)", ""},
	}
	for _, r := range required {
		// stat -c '%U %a' prints owner-name and octal mode.
		result := s.callTool(t, "exec", map[string]string{
			"cmd": "test -e " + r.path + " && stat -c '%U %a' " + r.path + " || echo MISSING",
		})
		out := strings.TrimSpace(extractStructured(result)["stdout"].(string))
		if out == "MISSING" {
			t.Errorf("missing %s: %s", r.label, r.path)
			continue
		}
		fields := strings.Fields(out)
		if len(fields) != 2 {
			t.Errorf("unexpected stat output for %s: %q", r.path, out)
			continue
		}
		owner, mode := fields[0], fields[1]
		if r.wantOwner != "" && owner != r.wantOwner {
			t.Errorf("%s: owner=%s want=%s (path=%s)", r.label, owner, r.wantOwner, r.path)
		}
		// All binaries must be world-executable (mode bits 1, 3, 5, 7 in
		// last digit). World-writable bit (mode 2 in last digit) is bad
		// — would let agent overwrite root-owned binaries.
		if strings.HasPrefix(r.path, "/usr/local/bin/") {
			if !strings.HasSuffix(mode, "5") && !strings.HasSuffix(mode, "1") {
				t.Errorf("%s: mode %s not world-executable (path=%s)", r.label, mode, r.path)
			}
			// Reject world-writable: last char in [2,3,6,7].
			lastChar := mode[len(mode)-1:]
			if strings.ContainsAny(lastChar, "2367") {
				t.Errorf("%s: mode %s is world-writable (security issue, path=%s)", r.label, mode, r.path)
			}
		}
	}

	// compiler-rt builtins archive lives under a clang-version subdir
	// (/lib/clang/<N>/lib/x86_64-unknown-linux-gnu/), so glob-match.
	// Missing => link fails with "libclang_rt.builtins.a missing".
	result := s.callTool(t, "exec", map[string]string{
		"cmd": "ls /rlenv/source/v8/third_party/llvm-build/Release+Asserts/lib/clang/*/lib/x86_64-unknown-linux-gnu/libclang_rt.builtins.a 2>/dev/null | head -1",
	})
	if strings.TrimSpace(extractStructured(result)["stdout"].(string)) == "" {
		t.Errorf("missing libclang_rt.builtins.a (compiler-rt) — d8 link step will fail")
	}

	// Prebuilt d8 binaries the grader uses must all exist, be executable,
	// and root-owned (Dockerfile does `chown -R root:root /rlenv/binaries`
	// so agent compromise can't tamper with what the grader runs).
	d8Paths := []string{}
	for _, side := range []string{"vuln", "fixed"} {
		for _, cfg := range []string{"debug", "debug-asan", "release", "release-asan"} {
			d8Paths = append(d8Paths, "/rlenv/binaries/"+side+"/"+cfg+"/d8")
		}
	}
	d8Paths = append(d8Paths, "/rlenv/binaries/vuln/coverage/d8") // coverage only on vuln side
	for _, path := range d8Paths {
		result := s.callTool(t, "exec", map[string]string{
			"cmd": "test -x " + path + " && stat -c '%U' " + path + " || echo MISSING",
		})
		out := strings.TrimSpace(extractStructured(result)["stdout"].(string))
		if out == "MISSING" {
			t.Errorf("missing prebuilt d8: %s", path)
		} else if out != "root" {
			t.Errorf("prebuilt d8 not root-owned: %s (owner=%s)", path, out)
		}
	}
}

func TestFunctional_AgentCanRebuildD8(t *testing.T) {
	t.Parallel()
	image := requireImage(t)
	s := newMCPSession(t, image)

	// Touch a core file that's part of v8_base_without_compiler so the
	// rebuild exercises the full chain: CXX, mksnapshot regen + ACTION,
	// ASM embedded.o, then LINK ./d8. (Touching just d8.cc would
	// only relink d8 and skip mksnapshot — a weaker test.) If V8 ever
	// renames this file, pick another src/objects/*.cc.
	result := s.callTool(t, "exec", map[string]any{
		"cmd": "touch /rlenv/source/v8/src/objects/map-updater.cc && " +
			"cd /rlenv/source/v8 && " +
			"autoninja -C out/x64.release d8 2>&1 | tail -30",
		"timeout": 120.0,
	})
	sc := extractStructured(result)
	exitcode, _ := sc["exitcode"].(float64)
	stdout := sc["stdout"].(string)

	if int(exitcode) != 0 {
		t.Fatalf("autoninja failed: exitcode=%v stdout=%q stderr=%q",
			exitcode, stdout, sc["stderr"])
	}
	// `tail -30` on `... | tail` masks the underlying exit code, but
	// real failure modes leave clear markers in the captured tail.
	for _, badMarker := range []string{
		"PermissionError",       // depot_tools telemetry HOME EACCES
		"ninja: error:",         // missing-file link failures (e.g. libclang_rt)
		"rebuild manifest failed", // gn regen failed (cr_build_revision missing)
	} {
		if strings.Contains(stdout, badMarker) {
			t.Fatalf("autoninja output contains %q (rebuild broken):\n%s",
				badMarker, stdout)
		}
	}
	// Positive markers: each step of the canonical M=11 path must appear.
	for _, mustHave := range []string{
		"CXX obj/v8_base_without_compiler/map-updater.o",
		"LINK ./mksnapshot",
		"ASM obj/v8_snapshot/embedded.o",
		"LINK ./d8",
	} {
		if !strings.Contains(stdout, mustHave) {
			t.Fatalf("autoninja output missing expected step %q; got:\n%s",
				mustHave, stdout)
		}
	}
}
