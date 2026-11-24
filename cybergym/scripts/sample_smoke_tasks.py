#!/usr/bin/env python3
"""Sample N CyberGym task ids for the 10% smoke benchmark.

Picks the upstream-curated subset first (so TIER=easy/hard still has
meaning) then fills the remainder with a deterministic random sample
from `cybergym_data/tasks.json`.

Usage:
    python3 cybergym/scripts/sample_smoke_tasks.py \
        --tasks-json cybergym_data/tasks.json \
        --count 151 --seed 10 \
        --out loop_runners/smoke_tasks_10pct.txt
"""
from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path


# The 10 tasks CyberGym upstream calls the "subset" — 5 easy + 5 hard.
CURATED: list[str] = [
    "arvo:47101", "arvo:3938", "arvo:24993", "arvo:1065", "arvo:10400",
    "arvo:368",
    "oss-fuzz:42535201", "oss-fuzz:42535468",
    "oss-fuzz:370689421", "oss-fuzz:385167047",
]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tasks-json", type=Path, required=True,
                    help="Path to cybergym_data/tasks.json")
    ap.add_argument("--count", type=int, default=151,
                    help="Total number of tasks to sample (default: 151, about 10 percent of 1,507)")
    ap.add_argument("--seed", type=int, default=10,
                    help="RNG seed for reproducible sampling")
    ap.add_argument("--out", type=Path, default=None,
                    help="Write ids to this file (one per line) instead of stdout")
    args = ap.parse_args()

    if not args.tasks_json.is_file():
        print(f"tasks.json not found at {args.tasks_json}", file=sys.stderr)
        return 2

    all_ids = list(json.load(open(args.tasks_json)))
    if not all_ids:
        print("tasks.json is empty", file=sys.stderr); return 2

    picked = [t for t in CURATED if t in set(all_ids)]
    remaining = [t for t in all_ids if t not in set(picked)]
    random.Random(args.seed).shuffle(remaining)
    picked.extend(remaining[: max(0, args.count - len(picked))])

    text = "\n".join(picked) + "\n"
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text)
        print(f"wrote {len(picked)} task ids to {args.out}", file=sys.stderr)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
