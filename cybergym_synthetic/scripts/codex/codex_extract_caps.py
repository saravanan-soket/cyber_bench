#!/usr/bin/env python3
"""Parse a Codex rollout jsonl + the JSON event log and emit a caps.json
summary for a single bug run.

Output schema (printed to stdout as JSON):
  {
    "rollout":          "/abs/path/rollout-*.jsonl",
    "log":              "/abs/path/codex.log",
    "turns":            <int>,        # model API calls
    "n_tool_calls":     <int>,
    "n_grades":         <int>,
    "capabilities":     {"cov_func": true, ...},   # cumulative
    "n_caps":           <int>,
    "tools_per_turn":   {1: <count>, 2: <count>, ...},  # distribution
    "reasoning_tokens": {"sum": ..., "mean": ..., "median": ..., "nonzero_rate": ...},
    "input_tokens":     {"sum": ..., "max": ..., "mean": ...},
    "output_tokens":    {"sum": ..., "mean": ...},
    "first_event_ts":   "ISO-8601",
    "last_event_ts":    "ISO-8601",
  }
"""
import json
import sys
from collections import Counter
from pathlib import Path


def parse_rollout(rollout):
    rt = []
    in_t = []
    out_t = []
    first_ts = None
    last_ts = None
    for line in Path(rollout).open(errors="ignore"):
        try:
            o = json.loads(line)
        except Exception:
            continue
        ts = o.get("timestamp")
        if ts:
            if first_ts is None:
                first_ts = ts
            last_ts = ts
        payload = o.get("payload") or {}
        info = payload.get("info") or {}
        last = info.get("last_token_usage")
        if isinstance(last, dict) and "reasoning_output_tokens" in last:
            rt.append(int(last.get("reasoning_output_tokens", 0) or 0))
            in_t.append(int(last.get("input_tokens", 0) or 0))
            out_t.append(int(last.get("output_tokens", 0) or 0))
    return rt, in_t, out_t, first_ts, last_ts


def parse_event_log(log):
    """Walk the --json event log; count tool calls and harvest grade()
    response capabilities (cumulative)."""
    tools_per_turn = Counter()
    cumulative_caps = {}
    n_grades = 0
    n_tool_calls = 0

    if not Path(log).is_file():
        return tools_per_turn, cumulative_caps, n_grades, n_tool_calls

    # We don't have a clean "turn" boundary in --json events; tool_calls
    # are emitted as separate items. Count item.completed of mcp_tool_call.
    # For caps, walk every payload looking for a capabilities dict.
    def walk_for_caps(d):
        if isinstance(d, dict):
            if "capabilities" in d and isinstance(d["capabilities"], dict):
                yield d["capabilities"]
            for v in d.values():
                yield from walk_for_caps(v)
        elif isinstance(d, list):
            for v in d:
                yield from walk_for_caps(v)

    for line in Path(log).open(errors="ignore"):
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            o = json.loads(line)
        except Exception:
            continue
        item = o.get("item") or {}
        item_type = item.get("type", "")
        if o.get("type") == "item.completed":
            if item_type in ("mcp_tool_call", "tool_call", "function_call"):
                n_tool_calls += 1
                if (item.get("tool") or item.get("name") or "") == "grade":
                    n_grades += 1
        # Look for capabilities in any object (grade results buried in stream)
        for caps in walk_for_caps(o):
            if any(isinstance(v, bool) for v in caps.values()):
                for k, v in caps.items():
                    if v:
                        cumulative_caps[k] = True

    return tools_per_turn, cumulative_caps, n_grades, n_tool_calls


def stats(arr):
    if not arr:
        return {"n": 0}
    s = sorted(arr)
    n = len(s)
    return {
        "n": n,
        "sum": sum(s),
        "mean": sum(s) / n,
        "median": s[n // 2],
        "max": s[-1],
        "nonzero": sum(1 for x in arr if x > 0),
        "nonzero_rate": sum(1 for x in arr if x > 0) / n,
    }


def main():
    rollout = sys.argv[1]
    log = sys.argv[2]

    rt, in_t, out_t, first_ts, last_ts = parse_rollout(rollout)
    _, caps, n_grades, n_tool_calls = parse_event_log(log)

    out = {
        "rollout": rollout,
        "log": log,
        "turns": len(rt),
        "n_tool_calls": n_tool_calls,
        "n_grades": n_grades,
        "capabilities": caps,
        "n_caps": sum(1 for v in caps.values() if v),
        "reasoning_tokens": stats(rt),
        "input_tokens": stats(in_t),
        "output_tokens": stats(out_t),
        "first_event_ts": first_ts,
        "last_event_ts": last_ts,
    }
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
