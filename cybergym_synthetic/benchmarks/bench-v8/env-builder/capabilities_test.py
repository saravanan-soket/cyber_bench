"""Tests for the capabilities module.

Run: python3 -m unittest capabilities_test
"""

import unittest

import capabilities


class TestDefaultAvailable(unittest.TestCase):

    def test_v8_has_all_capabilities(self):
        avail = capabilities.default_available("v8")
        all_caps = {c.name for c in capabilities.CAPABILITIES}
        self.assertEqual(avail, all_caps)

    def test_unknown_target_returns_all(self):
        # Conservative: unknown targets get the full set rather than an empty one.
        self.assertEqual(capabilities.default_available("unknown"),
                         {c.name for c in capabilities.CAPABILITIES})


class TestPruneByPatch(unittest.TestCase):

    def test_empty_patch_locations_drops_coverage(self):
        avail = capabilities.default_available("v8")
        pruned = capabilities.prune_by_patch(avail, [])
        self.assertNotIn("cov_func", pruned)
        self.assertNotIn("cov_line", pruned)
        # Non-coverage caps are unaffected.
        self.assertIn("diff", pruned)
        self.assertIn("ace", pruned)

    def test_non_empty_patch_locations_keeps_coverage(self):
        avail = capabilities.default_available("v8")
        patches = [{"file": "x.cc", "side": "vuln", "start_line": 1, "end_line": 1}]
        pruned = capabilities.prune_by_patch(avail, patches)
        self.assertEqual(pruned, avail)


class TestRenderSection(unittest.TestCase):

    def test_contains_sections_for_full_cap_set(self):
        md = capabilities.render_section(capabilities.default_available("v8"))
        for section in ("**Coverage**", "**Bug reproduction**",
                        "**V8 exploit primitives**",
                        "**General exploit primitives**",
                        "**Full exploit**"):
            self.assertIn(section, md)

    def test_omits_section_when_all_caps_absent(self):
        # With coverage pruned, the Coverage section should disappear entirely —
        # we don't tell the agent about caps that can't fire.
        pruned = capabilities.prune_by_patch(
            capabilities.default_available("v8"), []
        )
        md = capabilities.render_section(pruned)
        self.assertNotIn("**Coverage**", md)
        self.assertNotIn("`cov_func`", md)
        self.assertIn("**Bug reproduction**", md)  # other sections intact

    def test_builtin_column_appears_only_for_builtin_sections(self):
        md = capabilities.render_section(capabilities.default_available("v8"))
        # Coverage + Bug-reproduction use 2-column tables (no Builtin).
        # Primitives + Full-exploit use 3-column tables (with Builtin).
        self.assertIn("| Capability | Description |", md)
        self.assertIn("| Capability | Builtin | Description |", md)


class TestProblemTypes(unittest.TestCase):

    def test_prefix_applied(self):
        pt = capabilities.problem_types(capabilities.default_available("v8"), "1day")
        self.assertTrue(all(p.startswith("1day_") for p in pt))

    def test_custom_prefix(self):
        pt = capabilities.problem_types(capabilities.default_available("v8"), "0day")
        self.assertTrue(all(p.startswith("0day_") for p in pt))

    def test_canonical_order_preserved(self):
        pt = capabilities.problem_types(capabilities.default_available("v8"), "1day")
        self.assertEqual(pt[0], "1day_cov_func")
        self.assertEqual(pt[-1], "1day_ace")

    def test_filters_to_available(self):
        avail = {"diff", "crash"}
        pt = capabilities.problem_types(avail, "1day")
        self.assertEqual(set(pt), {"1day_diff", "1day_crash"})


if __name__ == "__main__":
    unittest.main()
