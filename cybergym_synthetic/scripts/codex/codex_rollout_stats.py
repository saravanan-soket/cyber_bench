#!/usr/bin/env python3
"""Parse a Codex rollout jsonl file and emit summary stats.

Usage:
  codex_rollout_stats.py <rollout.jsonl>

Output (one key=value per line):
  turns=<int>           # number of model API calls
  last_grade_turn=<int> # turn index of most recent grade() call (0 = never)
  last_tool_call=<name> # name of the last tool call, or "(none)"
  has_pending_tool=<bool>  # true if last assistant turn emitted a tool call without result
"""
import json
import sys
from pathlib import Path


def main(path):
    turns = 0
    last_grade_turn = 0
    last_tool_call = "(none)"
    last_call_pending = False
    last_call_id = None

    pending_call_ids = set()

    for raw in Path(path).open(errors="ignore"):
        try:
            o = json.loads(raw)
        except Exception:
            continue
        payload = o.get("payload") or {}
        info = payload.get("info") or {}
        # Each per-API-call usage record marks one model turn
        if isinstance(info, dict) and info.get("last_token_usage"):
            turns += 1
        ptype = payload.get("type", "")
        # function_call: model emitting a tool call
        if ptype == "function_call":
            name = payload.get("name") or ""
            call_id = payload.get("call_id") or payload.get("id") or ""
            last_tool_call = name
            last_call_id = call_id
            if "grade" in name:
                last_grade_turn = turns
            pending_call_ids.add(call_id)
        # function_call_output: tool result returned
        elif ptype == "function_call_output":
            call_id = payload.get("call_id") or payload.get("id") or ""
            pending_call_ids.discard(call_id)

    last_call_pending = bool(pending_call_ids)

    print(f"turns={turns}")
    print(f"last_grade_turn={last_grade_turn}")
    print(f"last_tool_call={last_tool_call}")
    print(f"has_pending_tool={'true' if last_call_pending else 'false'}")


if __name__ == "__main__":
    main(sys.argv[1])
