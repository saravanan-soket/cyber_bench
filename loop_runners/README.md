# loop_runners

Benchmark drivers that use [**loop**](https://github.com/soketlabs/loop) (Soket AI's
open-source Rust agent harness) as the agent for two benchmarks that live in
this repo:

- `cybergym_loop.py` — drives CyberGym tasks (one PoC per task, graded by the
  CyberGym server).
- `sec_bench_pro/eval_loop.py` — drop-in sibling of SEC-bench Pro's existing
  `eval_claude.py` / `eval_codex.py` / `eval_opencode.py`, running the `loop`
  agent inside each benchmark container.

Both runners invoke the installed `loop` binary (`~/.loop/bin/loop` or
`~/.local/bin/loop`) with `--print`, so each task is one non-interactive agent
turn. Provider and model come from CLI flags; set the matching API-key env var
(`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `SOKET_API_KEY`, …) for the provider
you pick.

Prerequisites:

- `loop` on `PATH` (`curl -fsSL https://loop.soket.ai/install | bash`).
- Docker running (SEC-bench Pro). CyberGym grading needs the CyberGym server
  reachable at `--server`; pass `--no-grade` to skip it.

## CyberGym

```
python3 loop_runners/cybergym_loop.py \
    --tasks-dir path/to/cybergym/tasks \
    --out-dir   runs/cybergym-loop \
    --provider  openai --model gpt-5.5 \
    --server    http://cybergym.local:8666 \
    --concurrency 4
```

Per task, the runner:

1. Prepares a per-task workspace (`<out>/<task>/workspace/`) and extracts
   `repo-vul.tar.gz` into it, alongside `description.txt`, `README.md`, and the
   task's `submit.sh`.
2. Runs `loop --cwd <workspace> --provider ... --model ... --print "<prompt>"`,
   where the prompt is the CyberGym README text plus a reminder to write the
   PoC as `poc` in the workspace and call `bash submit.sh ./poc`.
3. Reads loop's stdout (final agent message) plus the resulting `poc` file.
4. Grades the submission via `submit.sh` (unless `--no-grade`) and writes
   `result.json`, `transcript.txt`, and `poc` into `<out>/<task>/`.

## SEC-bench Pro

```
python3 sec_bench_pro/harness/eval_loop.py \
    sec_bench_pro/harness/configs/loop/v8/config.example.toml
```

Same shape as the other `eval_*.py` scripts in `sec_bench_pro/harness/`. See
`sec_bench_pro/harness/configs/loop/v8/config.example.toml` for a config
template; it installs `loop` inside the container on first use, runs
`loop --cwd <work_dir> --print "<prompt>"`, and the existing harness collects
the `audit/` directory back.
