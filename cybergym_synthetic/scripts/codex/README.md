# Codex CLI benchmark — V8 bug sweep

Run the OpenAI Codex CLI (patched fork from
[exploitbench/codex#1](https://github.com/exploitbench/codex/pull/1)) as a
"vendor-supplied agent" baseline against bench-v8 bugs. Compares against
our own minimal-agent exploitbench runs on the same model + bugs.

## What it tests

Same model (`gpt-5.5`), same `reasoning_effort=xhigh`, same bench-v8 MCP
tools, same one-sentence init prompt as exploitbench's
`default_init_prompt()`. Codex's natural behavior — including stateful
Responses API + `previous_response_id` chaining + `phase` preservation +
auto-compaction when triggered — is what we want to measure, vs. our
stateless chat-completions setup.

## Prerequisites (one-time, on the box)

1. Patched codex binary built from
   `https://github.com/exploitbench/codex` (PR #1 adds `--max-turns`).
   Built at `~/codex-fork/codex-rs/target/release/codex`. Requires
   rustc ≥ 1.91 (install via `apt -t trixie-backports install rustc cargo`).
2. `codex login --api-key $OPENAI_API_KEY` to seed `~/.codex/auth.json`.
3. bench-v8 docker images pulled (`docker images | grep exploitbench:`).
   All 41 already present on the box.

## Scripts

| script | purpose |
| --- | --- |
| `config_template.toml` | Source-of-truth config. `__MODEL__` / `__EFFORT__` / `__IMAGE__` placeholders substituted at runtime by the per-bug runner. |
| `codex_run_bug.sh <bug_id> [seed] [results_root]` | Per-bug runner. Creates isolated `CODEX_HOME`, renders config from template, runs `codex exec --max-turns 300`, extracts `caps.json`. |
| `codex_extract_caps.py <rollout> <log>` | Parses rollout + JSON log → caps.json summary (turns, tool calls, grades, capabilities, rt density). |
| `codex_benchmark_all.sh [yaml] [results_root] [concurrency] [seeds]` | Coordinator — schedules bugs × seeds with concurrency cap, tmux session per (bug,seed). |
| `codex_aggregate.py [results_root]` | Walks results dir → per-cell + per-bug summary table, per-cap success rate, TPM, distributions. |
| `codex_rollout_stats.py <rollout>` | Quick stats for a single rollout (turns / last_grade / last_tool). |
| `codex_tpm.py [results_root]` | Live TPM consumption (last 60s) split by normal-pool vs long-context-pool. |
| `verify_data_collection.py [results_root]` | Audits every cell for expected artifacts (codex.log, config.toml, auth.json, rollout, cwd, caps.json). |
| `codex_force_300.sh` | Legacy nudge-resume wrapper, superseded by `--max-turns`. |

## Output layout (per cell)

```
<results_root>/<bug_id>/seed<N>/
  codex.log                              # --json event stream (~190KB+ per 10-turn run)
  caps.json                              # extracted summary
  cwd/                                   # throwaway working dir (isolates apply_patch)
  .codex/
    auth.json                            # copy of host auth (per-cell isolation)
    config.toml                          # EXPERIMENT CONFIG snapshot (rendered)
    sessions/YYYY/MM/DD/rollout-*.jsonl  # full per-turn rollout (canonical truth)
    ...
```

Seed isolation is critical for parallel runs — each cell has its own `CODEX_HOME` so rollouts don't conflict.

## Per-bug config.toml (the "experiment config snapshot")

See `scripts/codex/config_template.toml` for the verbatim source; the
sections of interest:

```toml
sandbox_mode = "danger-full-access"  # required to spawn docker for the MCP server
approval_policy = "never"
web_search = "disabled"

[features]
shell_tool = false

[shell_environment_policy]
inherit = "none"
include_only = ["PATH"]              # don't leak OPENAI_API_KEY into MCP subprocess

[history]
persistence = "none"                 # all session data isolated under CODEX_HOME

[mcp_servers.bench_v8]
command = "docker"
args = ["run", "--network", "none", "-i", "--rm", "<per-bug image>"]
tool_timeout_sec = 300
startup_timeout_sec = 60
```

## Host-safety posture

The bench-v8 MCP server (over docker `--network none`) is the only
path the model can affect anything outside its own context.

- **`CODEX_DISABLE_APPLY_PATCH=1`** — env var exported by
  `codex_run_bug.sh` to every codex invocation. The forked codex
  refuses every `apply_patch` at the `apply_patch::apply_patch`
  entry point in `codex-rs/apply-patch/src/lib.rs`, regardless of
  which registration path put the tool into the model's schema.
  The `[features] apply_patch_freeform = false` config option only
  gates one registration path; the custom-tool-call path used by
  gpt-5.5 admits the tool even when the freeform feature is off,
  so the env-var kill switch is the only fully-suppressive control.
  See `exploitbench/codex` fork branch `feature/disable-apply-patch-env`.
- **`sandbox_mode = "danger-full-access"`** — required for codex to
  spawn the bench_v8 MCP server's docker subprocess. Tighter sandbox
  modes pre-flight-cancel the docker invocation. Host writes are
  blocked by the apply_patch kill switch above, not by the sandbox.
- **`[features] shell_tool = false`** — codex's host shell off.
- **`web_search = "disabled"`** plus container's `--network none`
  blocks all egress. exec-side curl/wget/urllib calls from inside
  the container fail because the container has no network.
- **env inheritance disabled** — `OPENAI_API_KEY` not visible to the
  MCP subprocess (codex itself reads it from
  `<cell>/.codex/auth.json`).

## Key methodology differences from exploitbench (intentional)

These are part of what the comparison measures, not artifacts to suppress:

- **API path**: codex uses native Responses API (stateful,
  `previous_response_id`, phase preservation). Exploitbench uses chat-
  completions via litellm bridge (stateless full-history each turn).
- **Auto-compaction**: codex compacts at high context. Exploitbench
  doesn't compact; just grows context until model OOM.
- **System prompt**: codex injects its own "You are Codex, a coding
  agent based on GPT-5..." plus skills metadata. Exploitbench sends no
  system prompt.
- **Built-in tools**: codex still has `apply_patch` (and `update_plan`
  in default config). Exploitbench exposes only bench_v8 MCP tools.

## Same as exploitbench (apples-to-apples on these dimensions)

- Model: `gpt-5.5`
- Reasoning effort: `xhigh`
- Init / user prompt: byte-identical to `default_init_prompt()`
- bench_v8 MCP tool surface (setup / exec / grade / write_file /
  read_file / list_directory)
- Turn budget: 300 (via `--max-turns 300` on codex side)
- Bug context: only via bench-v8 `setup()` tool

## Cost & wallclock expectations

At gpt-5.5 + xhigh + 300-turn cap (codex stops earlier on most bugs):

- **Per cell**: ~$20-50 (mean ~$30; varies by how deep codex iterates)
- **1-seed sweep (41 cells)**: ~$800-2000
- **3-seed sweep (123 cells)**: ~$2400-6000

Wallclock by concurrency:

```
par     1-seed         3-seed
─────────────────────────────────
2       ~24-40h        ~72-120h
6       ~8-12h         ~24-36h
12      ~4-6h          ~12-18h
20      ~3h            ~8h        ← recommended for 3-seed
```

## Empirical findings (running record)

### Codex's auto-compaction prevents long-context tier entirely

Codex's `model_auto_compact_token_limit` default for gpt-5.5 fires at
**~243-244K input_tokens** — comfortably below OpenAI's 272K long-
context routing threshold. Confirmed across multiple cells:

```
cve-2024-2887:  peak 243,065 → 0 (compact at turn 95)
cve-2024-12053: peak 244,753 → 0 (compact at turn 85)
```

Implication: all codex traffic stays on the **20M normal pool**. The
tighter 2M long-context pool is never hit. par=12-20 is well within
TPM cap.

### Compaction does NOT degrade reasoning

Empirical pre/post-compaction comparison on 2 cells:

```
cve-2024-2887:  pre-compact 68% nonzero rt, mean=303
                post-compact 75% nonzero rt, mean=362  (slight improvement)

cve-2024-12053: pre-compact 67% nonzero rt, mean=235
                post-compact 82% nonzero rt, mean=372  (improvement)
```

Cells continue grading and unlocking new caps after compaction.

### Per-cell TPM rate at par=12

~270K TPM per cell (avg). At par=20: ~5.4M TPM = 27% of 20M cap.
At par=37: would hit ~50% (failsafe limit).

### Per-cell wall time

Mean ~75-90 min. Fast-stop cells finish in 30-50 min; deep cells
that grind to 300-turn cap take 2.5-3.5h.

### TPM rate limits (verified empirically)

```
gpt-5.5 normal pool (input < 272K):    20,000,000 TPM
gpt-5.5 long-context pool (>= 272K):    2,000,000 TPM   (we don't hit this)
gpt-5.5 RPM cap:                           15,000 RPM
```

## Launch commands

### Smoke test (one bug, low turn cap)

```bash
ssh -i ~/.ssh/vr-agent-ec2 admin@32.196.124.61 \
  'MAX_TURNS=10 ~/codex-experiment/codex_run_bug.sh v8-cve-2024-1939 1 /tmp/codex-smoke'
```

### Full sweep — 41 bugs × 3 seeds (recommended: par=20)

```bash
ssh -i ~/.ssh/vr-agent-ec2 admin@32.196.124.61 \
  "tmux new -d -s codex-sweep '~/codex-experiment/codex_benchmark_all.sh \
    /home/admin/exploitbench/benchmarks/v8.yaml \
    /home/admin/codex-bench \
    20 \
    \"1,2,3\" \
    2>&1 | tee -a /home/admin/codex-bench/sweep.log'"
```

Arguments are positional: `<yaml> <results_root> <concurrency> <seeds>`.

### Single-seed sweep (41 cells, par=12)

```bash
ssh -i ~/.ssh/vr-agent-ec2 admin@32.196.124.61 \
  "tmux new -d -s codex-sweep '~/codex-experiment/codex_benchmark_all.sh \
    /home/admin/exploitbench/benchmarks/v8.yaml /home/admin/codex-bench 12 1 \
    2>&1 | tee /home/admin/codex-bench/sweep.log'"
```

### Add seeds 2,3 after seed=1 completes (resumes, skips done cells)

```bash
ssh -i ~/.ssh/vr-agent-ec2 admin@32.196.124.61 \
  "tmux new -d -s codex-sweep-23 '~/codex-experiment/codex_benchmark_all.sh \
    /home/admin/exploitbench/benchmarks/v8.yaml /home/admin/codex-bench 20 \"2,3\" \
    2>&1 | tee /home/admin/codex-bench/sweep-23.log'"
```

### Bump concurrency mid-run (kill+restart, preserves all state)

```bash
ssh -i ~/.ssh/vr-agent-ec2 admin@32.196.124.61 'tmux kill-session -t codex-sweep 2>/dev/null'
# then relaunch with new <concurrency> arg — already-running cells continue,
# already-done cells get skipped (caps.json existence check)
```

### Filter to a subset (e.g. just 2024 CVEs)

```bash
ssh -i ~/.ssh/vr-agent-ec2 admin@32.196.124.61 \
  "FILTER='cve-2024-' tmux new -d -s codex-sweep-2024 \
    '~/codex-experiment/codex_benchmark_all.sh \
    /home/admin/exploitbench/benchmarks/v8.yaml /home/admin/codex-bench 12 1 \
    2>&1 | tee /home/admin/codex-bench/sweep-2024.log'"
```

## Monitoring commands

### Count of in-flight cells

```bash
ssh -i ~/.ssh/vr-agent-ec2 admin@32.196.124.61 \
  'tmux ls 2>/dev/null | grep -c codex-bench-'
```

### Coordinator's launch/skip events

```bash
ssh -i ~/.ssh/vr-agent-ec2 admin@32.196.124.61 \
  'tail -30 /home/admin/codex-bench/sweep.log'
```

### Per-cell summary table (caps achieved + turns + ctx + TPM + distributions)

```bash
ssh -i ~/.ssh/vr-agent-ec2 admin@32.196.124.61 \
  'python3 ~/codex-experiment/codex_aggregate.py /home/admin/codex-bench'
```

Output includes:
- Per-cell table (turns / tools / grades / ctx_peak / ctx_now / caps)
- summary line (done / running / pending / total)
- **OpenAI TPM** (last 60s, split by normal-pool / long-context-pool)
- per-capability success rate (with bar chart)
- per-cell distributions (mean / median / min / max for each metric)
- per-bug summary (per-seed turns/grades + union of caps across seeds)

### TPM-only check (cheap, fast)

```bash
ssh -i ~/.ssh/vr-agent-ec2 admin@32.196.124.61 \
  'python3 ~/codex-experiment/codex_tpm.py /home/admin/codex-bench'
```

### Data-collection integrity check

```bash
ssh -i ~/.ssh/vr-agent-ec2 admin@32.196.124.61 \
  'python3 ~/codex-experiment/verify_data_collection.py /home/admin/codex-bench'
```

Verifies every cell has expected artifacts (codex.log, config.toml,
auth.json, rollout, cwd, caps.json for done cells). Run after any
significant config / script change to confirm pipeline integrity.

### Live turn counts on active cells

```bash
ssh -i ~/.ssh/vr-agent-ec2 admin@32.196.124.61 'for b in $(tmux ls 2>/dev/null | grep -oE "codex-bench-v8-[^:]+-s[0-9]+" | sed -E "s/codex-bench-(v8-.+)-s([0-9]+)/\1 \2/"); do
  bug=$(echo $b | cut -d" " -f1); seed=$(echo $b | cut -d" " -f2)
  [ -z "$bug" ] && continue
  ROLLOUT=$(ls -t /home/admin/codex-bench/$bug/seed$seed/.codex/sessions/*/*/*/rollout-*.jsonl 2>/dev/null | head -1)
  [ -n "$ROLLOUT" ] && python3 ~/codex-experiment/codex_rollout_stats.py "$ROLLOUT" 2>/dev/null | awk -v b=$bug -v s=$seed "{print \"  \" b \"/seed\" s \": \" \$0}" | tr \"\\n\" \" \"; echo
done'
```

### Watch a specific bug's live JSON stream

```bash
ssh -i ~/.ssh/vr-agent-ec2 admin@32.196.124.61 \
  'tail -f /home/admin/codex-bench/v8-cve-2024-XXXX/seed1/codex.log'
```

### Continuous status (poll every 30s)

`watch` needs a TTY which `ssh` doesn't allocate by default, so use a
manual loop:

```bash
ssh -i ~/.ssh/vr-agent-ec2 admin@32.196.124.61 \
  'while true; do
     printf "\033[2J\033[H"        # clear screen without needing $TERM
     date -u +%FT%TZ
     echo "=== tmux active ==="
     tmux ls 2>/dev/null | grep codex-bench- || echo "(none)"
     echo "=== aggregate ==="
     python3 ~/codex-experiment/codex_aggregate.py /home/admin/codex-bench | tail -15
     sleep 30
   done'
```

(`clear` and `watch` require a TTY which `ssh` doesn't allocate by default
— the `\033[2J\033[H` ANSI escape is the portable equivalent. Use
`ssh -tt` if you want full TTY allocation so `clear` / `watch -n N "..."`
work normally.)

### Per-cell duration / cost diagnosis after completion

```bash
ssh -i ~/.ssh/vr-agent-ec2 admin@32.196.124.61 \
  'for d in /home/admin/codex-bench/*/seed1/; do
     bug=$(basename $(dirname $d))
     [ -f "$d/caps.json" ] || continue
     python3 -c "
import json
d=json.load(open(\"$d/caps.json\"))
print(f\"$bug t={d[\\\"turns\\\"]} caps={d[\\\"n_caps\\\"]} grades={d[\\\"n_grades\\\"]} \"
      f\"in_sum={d[\\\"input_tokens\\\"][\\\"sum\\\"]:,} \"
      f\"out_sum={d[\\\"output_tokens\\\"][\\\"sum\\\"]:,} \"
      f\"start={d[\\\"first_event_ts\\\"][:19]} end={d[\\\"last_event_ts\\\"][:19]}\")
"
   done'
```

## Stopping / cleanup

### Stop the sweep gracefully (let active cells finish)

```bash
# Kill only the coordinator; active per-bug runners continue to completion
ssh -i ~/.ssh/vr-agent-ec2 admin@32.196.124.61 'tmux kill-session -t codex-sweep'
```

### Stop everything immediately

```bash
ssh -i ~/.ssh/vr-agent-ec2 admin@32.196.124.61 \
  'tmux ls 2>/dev/null | grep -oE "^codex-(sweep|bench-[^:]+)" | xargs -I{} tmux kill-session -t {}'
```

### Clean reset (delete all results, start over)

```bash
ssh -i ~/.ssh/vr-agent-ec2 admin@32.196.124.61 \
  'tmux ls 2>/dev/null | grep -oE "^codex-(sweep|bench-[^:]+)" | xargs -I{} tmux kill-session -t {} ;
   rm -rf /home/admin/codex-bench'
```
