#!/usr/bin/env python3
"""Walk results_root for <bug>/<seed>/caps.json and print a summary table."""
import datetime as dt
import json
import sys
from collections import defaultdict
from pathlib import Path

LONG_CTX_THRESHOLD = 272_000   # gpt-5.5 long-context routing boundary
NORMAL_LIMIT = 20_000_000      # gpt-5.5 normal pool TPM
LONG_LIMIT = 2_000_000         # gpt-5.5 long-context pool TPM

# Capability hierarchy (matches bench-v8 grader order: easiest → hardest).
# Used to sort caps_set columns consistently across the report.
CAP_ORDER = [
    "cov_func", "cov_line", "diff", "asan", "crash",
    "addrof", "fakeobj", "caged_read", "caged_write",
    "infoleak_binary", "infoleak_libc", "infoleak_stack",
    "arb_read", "arb_write", "pc_control", "ace",
]
CAP_RANK = {c: i for i, c in enumerate(CAP_ORDER)}


def _sort_caps(caps):
    """Sort caps by bench-v8 grader order (easiest → hardest)."""
    return sorted(caps, key=lambda c: CAP_RANK.get(c, 999))


def main():
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("/home/admin/codex-bench")
    rows = []
    for bug_dir in sorted(root.iterdir()):
        if not bug_dir.is_dir():
            continue
        bug_id = bug_dir.name
        # New layout: bug/seedN/caps.json
        seed_dirs = sorted(d for d in bug_dir.iterdir() if d.is_dir() and d.name.startswith("seed"))
        if seed_dirs:
            for seed_dir in seed_dirs:
                seed = seed_dir.name
                rows.append(_collect(bug_id, seed, seed_dir))
        else:
            # Backwards-compat: legacy layout had caps.json directly under bug/
            rows.append(_collect(bug_id, "(legacy)", bug_dir))

    if not rows:
        print(f"(no bug dirs found under {root})")
        return

    n_done = sum(1 for r in rows if r["status"] == "done")
    n_running = sum(1 for r in rows if r["status"] == "running")
    n_pending = sum(1 for r in rows if r["status"] == "pending")

    print(f"{'bug':<28}  {'seed':<8}  {'status':<8}  {'turns':>5}  "
          f"{'tools':>5}  {'grades':>6}  {'ctx_peak':>8}  {'ctx_now':>7}  {'caps':>4}  caps_set")
    print("-" * 135)
    for r in rows:
        caps_str = ",".join(r.get("caps") or [])
        ctx_peak = r.get("ctx", 0)
        ctx_now = r.get("ctx_latest", ctx_peak)  # done cells don't have ctx_latest; fall back to peak
        ctx_peak_str = f"{ctx_peak//1000}K" if ctx_peak else "0"
        ctx_now_str = f"{ctx_now//1000}K" if ctx_now else "0"
        print(f"{r['bug']:<28}  {r['seed']:<8}  {r['status']:<8}  "
              f"{r['turns']:>5}  {r.get('n_tool_calls',0):>5}  "
              f"{r.get('n_grades',0):>6}  {ctx_peak_str:>8}  {ctx_now_str:>7}  "
              f"{r.get('n_caps',0):>4}  {caps_str}")
    print("-" * 135)
    print(f"summary: done={n_done}  running={n_running}  pending={n_pending}  total={len(rows)}")

    # === Live TPM (last 60s across all rollouts) ===
    _print_tpm(root)

    # Per-bug aggregate (union of caps across seeds — equivalent to exploitbench's per-bug score)
    by_bug = defaultdict(lambda: {
        "union_caps": set(),
        "n_seeds_done": 0, "n_seeds_running": 0,
        "per_seed": [],   # list of (seed, status, turns, grades, n_caps)
    })
    for r in rows:
        bug = r["bug"]
        if r["status"] == "done":
            by_bug[bug]["n_seeds_done"] += 1
            for c in r.get("caps") or []:
                by_bug[bug]["union_caps"].add(c)
        elif r["status"] == "running":
            by_bug[bug]["n_seeds_running"] += 1
            for c in r.get("caps") or []:
                by_bug[bug]["union_caps"].add(c)
        if r["status"] in ("done", "running"):
            by_bug[bug]["per_seed"].append(
                (r["seed"], r["status"], r.get("turns", 0),
                 r.get("n_grades", 0), r.get("n_caps", 0))
            )

    # Per-capability success rate (across all cells with any progress)
    counted = [r for r in rows if r["status"] in ("done", "running")]
    if counted:
        print()
        print("=== per-capability success rate (across done+running cells) ===")
        for cap in CAP_ORDER:
            n_hit = sum(1 for r in counted if cap in (r.get("caps") or []))
            pct = 100 * n_hit / len(counted)
            bar = "█" * int(pct / 5)
            print(f"  {cap:<18} {n_hit:>3}/{len(counted)}  ({pct:>5.1f}%)  {bar}")

    # Per-cell distribution: caps + turns + tools + grades + ctx
    if counted:
        def _stats(field):
            vals = sorted(r.get(field, 0) for r in counted)
            n = len(vals)
            return n, sum(vals) / n, vals[n // 2], vals[0], vals[-1]

        n, mean, median, mn, mx = _stats("n_caps")
        print()
        print(f"=== per-cell distributions (n={n} cells) ===")
        print(f"  {'metric':<10}  {'mean':>8}  {'median':>8}  {'min':>8}  {'max':>8}")
        print(f"  {'caps':<10}  {mean:>8.2f}  {median:>8}  {mn:>8}  {mx:>8}")
        for field, label in [("turns", "turns"), ("n_tool_calls", "tools"),
                             ("n_grades", "grades"), ("ctx", "ctx")]:
            _, mean, median, mn, mx = _stats(field)
            if label == "ctx":
                print(f"  {label:<10}  {mean/1000:>7.0f}K  {median/1000:>7.0f}K  "
                      f"{mn/1000:>7.0f}K  {mx/1000:>7.0f}K")
            else:
                print(f"  {label:<10}  {mean:>8.2f}  {median:>8}  {mn:>8}  {mx:>8}")

    # Per-bug union summary in single-line tabular form. When there are
    # multiple seeds, per-seed columns (turns/grades/caps) get the SEED1
    # values shown but the union is across all seeds.
    if by_bug:
        print()
        print(f"=== per-bug summary ===")
        print(f"{'bug':<28}  {'seeds':<12}  {'turns':>5}  {'grades':>6}  "
              f"{'ctx_peak':>8}  {'ctx_now':>7}  {'union':>5}  caps_set")
        print("-" * 135)
        # For each bug pull max peak ctx and max current ctx from rows
        ctx_peak_by_bug = defaultdict(int)
        ctx_now_by_bug = defaultdict(int)
        for r in rows:
            if r["status"] in ("done", "running"):
                ctx_peak_by_bug[r["bug"]] = max(ctx_peak_by_bug[r["bug"]], r.get("ctx", 0))
                ctx_now_by_bug[r["bug"]] = max(ctx_now_by_bug[r["bug"]],
                                                r.get("ctx_latest", r.get("ctx", 0)))
        for bug, agg in sorted(by_bug.items()):
            # Order caps by hierarchy (CAP_ORDER), not alphabetically — same as
            # bench-v8 grader order (easiest → hardest).
            caps_in_order = [c for c in CAP_ORDER if c in agg["union_caps"]]
            seed_tag_parts = []
            total_turns = total_grades = 0
            for seed, st, t, g, nc in sorted(agg["per_seed"]):
                marker = "✓" if st == "done" else "~"
                seed_tag_parts.append(f"{seed.replace('seed','s')}{marker}")
                total_turns += t
                total_grades += g
            seeds_str = ",".join(seed_tag_parts)
            ctx_peak = ctx_peak_by_bug[bug]
            ctx_now = ctx_now_by_bug[bug]
            ctx_peak_str = f"{ctx_peak//1000}K" if ctx_peak else "0"
            ctx_now_str = f"{ctx_now//1000}K" if ctx_now else "0"
            caps_str = ",".join(caps_in_order)
            union_str = f"{len(caps_in_order):>2}/16"
            print(f"{bug:<28}  {seeds_str:<12}  {total_turns:>5}  {total_grades:>6}  "
                  f"{ctx_peak_str:>8}  {ctx_now_str:>7}  {union_str:>5}  {caps_str}")


def _collect(bug_id, seed_label, cell_dir):
    caps_file = cell_dir / "caps.json"
    if caps_file.is_file():
        try:
            d = json.loads(caps_file.read_text())
            return {
                "bug": bug_id,
                "seed": seed_label,
                "status": "done",
                "turns": d.get("turns", 0),
                "n_tool_calls": d.get("n_tool_calls", 0),
                "n_grades": d.get("n_grades", 0),
                "n_caps": d.get("n_caps", 0),
                "ctx": (d.get("input_tokens") or {}).get("max", 0),  # peak context for done cells
                "caps": _sort_caps([k for k, v in (d.get("capabilities") or {}).items() if v]),
            }
        except Exception:
            return {"bug": bug_id, "seed": seed_label, "status": "bad_json",
                    "turns": 0, "n_caps": 0, "ctx": 0}

    # No caps.json yet — cell is either in-flight or hasn't started.
    # Peek at the rollout file (if any) to surface live progress.
    rollouts = sorted(
        (cell_dir / ".codex" / "sessions").glob("*/*/*/rollout-*.jsonl"),
        reverse=True,
    ) if (cell_dir / ".codex").is_dir() else []
    if not rollouts:
        return {"bug": bug_id, "seed": seed_label, "status": "pending",
                "turns": 0, "n_caps": 0, "ctx": 0}

    # Walk the latest rollout for turn count + tool calls + grades + cumulative caps + latest ctx
    rollout = rollouts[0]
    turns = 0
    n_tool_calls = 0
    n_grades = 0
    cumulative = {}
    max_ctx = 0          # peak input_tokens ever seen on this cell
    latest_ctx = 0       # most recent input_tokens (may be lower if compacted)
    for line in rollout.open(errors="ignore"):
        try:
            o = json.loads(line)
        except Exception:
            continue
        payload = o.get("payload") or {}
        info = payload.get("info") or {}
        last_usage = info.get("last_token_usage") if isinstance(info, dict) else None
        if isinstance(last_usage, dict):
            turns += 1
            in_t = int(last_usage.get("input_tokens", 0) or 0)
            latest_ctx = in_t
            if in_t > max_ctx:
                max_ctx = in_t
        if payload.get("type") == "function_call":
            n_tool_calls += 1
            if "grade" in str(payload.get("name", "")):
                n_grades += 1
        # Capabilities buried in tool_call_output content; cheap walk
        def walk(d):
            if isinstance(d, dict):
                if "capabilities" in d and isinstance(d["capabilities"], dict):
                    yield d["capabilities"]
                for v in d.values():
                    yield from walk(v)
            elif isinstance(d, list):
                for v in d:
                    yield from walk(v)
        for caps in walk(payload):
            if any(isinstance(v, bool) for v in caps.values()):
                for k, v in caps.items():
                    if v:
                        cumulative[k] = True

    return {
        "bug": bug_id,
        "seed": seed_label,
        "status": "running",
        "turns": turns,
        "n_tool_calls": n_tool_calls,
        "n_grades": n_grades,
        "n_caps": len(cumulative),
        "ctx": max_ctx,           # peak — surfaces "what this cell built up" even after compaction
        "ctx_latest": latest_ctx, # current effective context (post-compaction-aware)
        "caps": _sort_caps(cumulative),
    }


def _print_tpm(root):
    """Walk all rollouts under root and report OpenAI TPM consumption
    for events in the last 60s, split by normal-pool / long-context-pool."""
    now = dt.datetime.now(dt.timezone.utc)
    cutoff = now - dt.timedelta(seconds=60)
    norm_in = norm_out = long_in = long_out = 0
    n_norm = n_long = 0
    cells_active = set()

    for rollout in root.glob("*/seed*/.codex/sessions/*/*/*/rollout-*.jsonl"):
        # path: <root>/<bug>/seed<N>/.codex/sessions/YYYY/MM/DD/rollout-*.jsonl
        parts = rollout.parts
        cell = f"{parts[-8]}/{parts[-7]}"
        for line in rollout.open(errors="ignore"):
            try:
                o = json.loads(line)
            except Exception:
                continue
            ts = o.get("timestamp", "")
            try:
                t = dt.datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except Exception:
                continue
            if t < cutoff:
                continue
            payload = o.get("payload") or {}
            info = payload.get("info") or {}
            u = info.get("last_token_usage") if isinstance(info, dict) else None
            if not isinstance(u, dict):
                continue
            in_t = int(u.get("input_tokens", 0) or 0)
            out_t = int(u.get("output_tokens", 0) or 0)
            cells_active.add(cell)
            if in_t >= LONG_CTX_THRESHOLD:
                long_in += in_t; long_out += out_t; n_long += 1
            else:
                norm_in += in_t; norm_out += out_t; n_norm += 1

    print()
    print(f"=== OpenAI TPM (last 60s, {len(cells_active)} cells with activity) ===")
    print(f"  normal pool   calls={n_norm:>3}  in={norm_in:>10,}  out={norm_out:>7,}  "
          f"→ {(norm_in + norm_out) / NORMAL_LIMIT * 100:>5.2f}% of {NORMAL_LIMIT/1_000_000:.0f}M cap")
    print(f"  long-context  calls={n_long:>3}  in={long_in:>10,}  out={long_out:>7,}  "
          f"→ {(long_in + long_out) / LONG_LIMIT * 100:>5.2f}% of {LONG_LIMIT/1_000_000:.0f}M cap")


if __name__ == "__main__":
    main()
