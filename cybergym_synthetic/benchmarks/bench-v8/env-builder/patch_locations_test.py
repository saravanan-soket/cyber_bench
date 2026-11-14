"""Tests for patch_locations.extract_patch_locations.

Run: python3 -m unittest patch_locations_test
"""

import unittest

from patch_locations import extract_patch_locations


class TestExtractPatchLocations(unittest.TestCase):

    def test_removal(self):
        """Pure removal: `-` only, no `+`. Two removed code lines → two vuln entries."""
        diff = """\
--- a/src/foo.cc
+++ b/src/foo.cc
@@ -1,6 +1,4 @@
 int main() {
   int x = 1;
-  int y = 2;
-  int z = 3;
   return x;
 }
"""
        self.assertEqual(extract_patch_locations(diff), [
            {"file": "src/foo.cc", "side": "vuln", "start_line": 3, "end_line": 3},
            {"file": "src/foo.cc", "side": "vuln", "start_line": 4, "end_line": 4},
        ])

    def test_change(self):
        """Change: `-` and `+` both present. One entry per side at the changed line."""
        diff = """\
--- a/src/foo.cc
+++ b/src/foo.cc
@@ -1,5 +1,5 @@
 int main() {
   int x = 1;
-  int y = unsafe_mul(x, 2);
+  int y = checked_mul(x, 2);
   return y;
 }
"""
        self.assertEqual(extract_patch_locations(diff), [
            {"file": "src/foo.cc", "side": "vuln", "start_line": 3, "end_line": 3},
            {"file": "src/foo.cc", "side": "fixed", "start_line": 3, "end_line": 3},
        ])

    def test_additive_with_block_header_dropped(self):
        """Pure additive whose first `+` line is `if (x < 0) {` — block-header
        first line is dropped so the emitted lines are only the body."""
        diff = """\
--- a/src/foo.cc
+++ b/src/foo.cc
@@ -1,4 +1,7 @@
 int main() {
   int x = 1;
+  if (x < 0) {
+    return -1;
+  }
   return x;
 }
"""
        self.assertEqual(extract_patch_locations(diff), [
            {"file": "src/foo.cc", "side": "fixed", "start_line": 4, "end_line": 4},
            {"file": "src/foo.cc", "side": "fixed", "start_line": 5, "end_line": 5},
        ])

    def test_cve_2023_6702_pattern(self):
        """CVE-2023-6702 shape: `-` is a comment-typo fix, `+` block contains
        a defensive `if (NativeContext) return;` check. Comment-only `-` is
        filtered; `+` block's `if (...) {` header is dropped; comment `+`
        lines are filtered; body (`return;`, `}`) remains."""
        # Built line-by-line so blank context lines carry their leading space.
        diff = "\n".join([
            "--- a/src/execution/isolate.cc",
            "+++ b/src/execution/isolate.cc",
            "@@ -1042,7 +1042,13 @@",
            "       builder->AppendPromiseCombinatorFrame(function, combinator);",
            " ",
            "-      // Now peak into the Promise.all() resolve element context to",
            "+      if (IsNativeContext(*context)) {",
            "+        // NativeContext is used as a marker that the closure was already",
            "+        // called. We can't access the reject element context any more.",
            "+        return;",
            "+      }",
            "+",
            "+      // Now peek into the Promise.all() resolve element context to",
            "       // find the promise capability that's being resolved when all",
            "       // the concurrent promises resolve.",
            "       int const index =",
            "",
        ])
        self.assertEqual(extract_patch_locations(diff), [
            {"file": "src/execution/isolate.cc", "side": "fixed", "start_line": 1047, "end_line": 1047},
            {"file": "src/execution/isolate.cc", "side": "fixed", "start_line": 1048, "end_line": 1048},
        ])

    def test_multifile(self):
        """Multiple hunks across multiple files; line counters reset per file."""
        diff = """\
--- a/src/a.cc
+++ b/src/a.cc
@@ -10,3 +10,3 @@
 foo();
-bar();
+baz();
 qux();
--- a/src/b.cc
+++ b/src/b.cc
@@ -50,2 +50,3 @@
 hello();
+extra();
 world();
"""
        self.assertEqual(extract_patch_locations(diff), [
            {"file": "src/a.cc", "side": "vuln",  "start_line": 11, "end_line": 11},
            {"file": "src/a.cc", "side": "fixed", "start_line": 11, "end_line": 11},
            {"file": "src/b.cc", "side": "fixed", "start_line": 51, "end_line": 51},
        ])

    def test_no_newline_marker(self):
        """`\\ No newline at end of file` markers must not advance line counters."""
        diff = """\
--- a/src/foo.cc
+++ b/src/foo.cc
@@ -1,2 +1,2 @@
 line1
-old_last
\\ No newline at end of file
+new_last
\\ No newline at end of file
"""
        self.assertEqual(extract_patch_locations(diff), [
            {"file": "src/foo.cc", "side": "vuln",  "start_line": 2, "end_line": 2},
            {"file": "src/foo.cc", "side": "fixed", "start_line": 2, "end_line": 2},
        ])

    def test_blank_line_removal(self):
        """Removing a blank line emits nothing (blank is filtered)."""
        diff = """\
--- a/src/foo.cc
+++ b/src/foo.cc
@@ -1,4 +1,3 @@
 int main() {
   int x = 1;
-
   return x;
 }
"""
        self.assertEqual(extract_patch_locations(diff), [])

    def test_single_line_add_kept(self):
        """Single-line `+` blocks keep their only line even if it ends with `{`
        (otherwise `+CHECK(x);`-style patches would have zero signal)."""
        diff = """\
--- a/src/foo.cc
+++ b/src/foo.cc
@@ -1,3 +1,4 @@
 int main() {
+  CHECK(x);
   return 0;
 }
"""
        self.assertEqual(extract_patch_locations(diff), [
            {"file": "src/foo.cc", "side": "fixed", "start_line": 2, "end_line": 2},
        ])

    def test_multi_line_add_nonheader_kept(self):
        """Multi-line `+` whose first line isn't a block header — all lines kept."""
        diff = """\
--- a/src/foo.cc
+++ b/src/foo.cc
@@ -1,2 +1,4 @@
 int main() {
+  int y = add(x, 1);
+  if_err_return(y);
   return 0;
"""
        self.assertEqual(extract_patch_locations(diff), [
            {"file": "src/foo.cc", "side": "fixed", "start_line": 2, "end_line": 2},
            {"file": "src/foo.cc", "side": "fixed", "start_line": 3, "end_line": 3},
        ])

    def test_removal_block_drops_header(self):
        """Removal of a conditional block: `-` side symmetric to `+`. First
        `-` line (`if (...) {`) is dropped; body remains."""
        diff = """\
--- a/src/foo.cc
+++ b/src/foo.cc
@@ -1,5 +1,2 @@
 int main() {
-  if (unsafe) {
-    bad();
-  }
   return 0;
"""
        self.assertEqual(extract_patch_locations(diff), [
            {"file": "src/foo.cc", "side": "vuln", "start_line": 3, "end_line": 3},
            {"file": "src/foo.cc", "side": "vuln", "start_line": 4, "end_line": 4},
        ])


if __name__ == "__main__":
    unittest.main()