"""Verify all per-cell data + transcript artifacts are being collected correctly."""
import json
import sys
from pathlib import Path

root = Path(sys.argv[1] if len(sys.argv) > 1 else "/home/admin/codex-bench")

problems = []
cells = []

for bug_dir in sorted(root.iterdir()):
    if not bug_dir.is_dir():
        continue
    for seed_dir in sorted(bug_dir.iterdir()):
        if not seed_dir.is_dir() or not seed_dir.name.startswith("seed"):
            continue
        cells.append((bug_dir.name, seed_dir.name, seed_dir))

print(f"=== verifying {len(cells)} cells ===\n")

def check(cond, msg, cell):
    if not cond:
        problems.append((cell, msg))
        return False
    return True

for bug, seed, sd in cells:
    cell_id = f"{bug}/{seed}"

    # Required artifacts
    log_path = sd / "codex.log"
    cwd_path = sd / "cwd"
    codex_home = sd / ".codex"
    config_path = codex_home / "config.toml"
    auth_path = codex_home / "auth.json"
    rollouts = list(codex_home.glob("sessions/*/*/*/rollout-*.jsonl")) if codex_home.exists() else []
    caps_path = sd / "caps.json"

    # Basic presence checks
    has_log = log_path.is_file()
    has_codex_home = codex_home.is_dir()
    has_config = config_path.is_file()
    has_auth = auth_path.is_file()
    has_cwd = cwd_path.is_dir()
    has_rollout = len(rollouts) > 0
    has_caps = caps_path.is_file()

    # Status
    if has_caps:
        status = "DONE"
    elif has_rollout and has_log:
        status = "RUNNING"
    else:
        status = "STARTING"

    # Log sanity
    log_size = log_path.stat().st_size if has_log else 0
    rollout_size = rollouts[0].stat().st_size if has_rollout else 0

    # Quick content check on log
    log_has_init = False
    log_has_events = False
    log_unique_event_types = set()
    if has_log:
        try:
            for line in log_path.open(errors="ignore"):
                if line.startswith("[run_bug] launching codex"):
                    log_has_init = True
                if line.startswith("{"):
                    try:
                        o = json.loads(line)
                        log_unique_event_types.add(o.get("type", "?"))
                        log_has_events = True
                    except Exception:
                        pass
        except Exception as e:
            problems.append((cell_id, f"log read error: {e}"))

    # Rollout sanity
    n_turns = 0
    if has_rollout:
        try:
            for line in rollouts[0].open(errors="ignore"):
                try:
                    o = json.loads(line)
                except Exception:
                    continue
                info = (o.get("payload") or {}).get("info") or {}
                if isinstance(info, dict) and info.get("last_token_usage"):
                    n_turns += 1
        except Exception as e:
            problems.append((cell_id, f"rollout read error: {e}"))

    # If DONE, caps.json should parse and match expected shape
    caps_valid = None
    if has_caps:
        try:
            d = json.loads(caps_path.read_text())
            required = {"turns", "n_tool_calls", "n_grades", "n_caps", "capabilities",
                        "reasoning_tokens", "input_tokens", "output_tokens",
                        "first_event_ts", "last_event_ts"}
            missing = required - set(d.keys())
            if missing:
                problems.append((cell_id, f"caps.json missing fields: {missing}"))
                caps_valid = False
            else:
                caps_valid = True
        except Exception as e:
            problems.append((cell_id, f"caps.json parse error: {e}"))
            caps_valid = False

    # Required checks: log + codex_home + config + rollout (every cell needs these)
    check(has_log, "missing codex.log", cell_id)
    check(has_codex_home, "missing .codex/", cell_id)
    check(has_config, "missing .codex/config.toml", cell_id)
    check(has_auth, "missing .codex/auth.json (auth.json not seeded)", cell_id)
    check(has_cwd, "missing cwd/ (throwaway workspace)", cell_id)
    check(has_rollout, "missing .codex/sessions/.../rollout-*.jsonl", cell_id)
    check(log_has_init, "log missing [run_bug] launching line", cell_id)
    check(log_has_events, "log has no JSON events", cell_id)

    print(f"  {cell_id:<36}  status={status:<8}  "
          f"log={log_size:>9,}b  rollout={rollout_size:>9,}b  turns={n_turns:>3}  "
          f"caps={'yes' if has_caps else '-':<3}  "
          f"event_types={len(log_unique_event_types)}")

print()
if problems:
    print(f"⚠ {len(problems)} problem(s) found:")
    for cell, msg in problems:
        print(f"  {cell}: {msg}")
else:
    print("✓ all cells have expected data artifacts")
