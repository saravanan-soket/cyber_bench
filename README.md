# cyber_bench

Cybersecurity-benchmarking repo pared down to two benchmarks, both driven by
Soket AI's open-source [**loop**](https://github.com/soketlabs/loop) agent
harness:

| Directory | What it is | Loop driver |
| --- | --- | --- |
| `cybergym/` | [CyberGym](https://arxiv.org/abs/2506.02548): 1,507 real-world OSS-Fuzz vulnerability tasks. Agents produce a PoC, the CyberGym server grades it. | [`loop_runners/cybergym_loop.py`](loop_runners/cybergym_loop.py) |
| `sec_bench_pro/` | [SEC-bench Pro](https://sec-bench.github.io/): 344 verified cases across Chromium V8, SpiderMonkey, and the Linux kernel. Agents run inside a benchmark container and drop artifacts into `./audit/`. | [`sec_bench_pro/harness/eval_loop.py`](sec_bench_pro/harness/eval_loop.py) |

The `loop` binary is the single agent for both benchmarks. Each task becomes
one `loop --print` invocation, with loop driving its own shell, file, and MCP
tools to complete the task. Trajectories can be exported to Langfuse via the
standard `LANGFUSE_*` env vars, which both drivers forward.

## Setup

```bash
# 1. The agent itself
curl -fsSL https://loop.soket.ai/install | bash
loop --version    # prove it is on PATH

# 2. Provider API key for whatever model you chose
export OPENAI_API_KEY=...      # or ANTHROPIC_API_KEY / SOKET_API_KEY / ...

# 3. Benchmark-specific prerequisites
#    - CyberGym: cybergym server running (or run with --no-grade)
#    - SEC-bench Pro: Docker daemon + the benchmark images
```

## Quickstart: CyberGym

```bash
# Generate task bundles once (see cybergym/README.md for details)
python3 -m cybergym.task.gen_task \
    --task-id arvo:12345 --out-dir tasks/arvo_12345 \
    --data-dir cybergym_data/data --server http://cybergym.local:8666 \
    --mask-map cybergym/mask_map.json --difficulty level1

# Drive the benchmark with loop (grading on)
python3 loop_runners/cybergym_loop.py \
    --tasks-dir tasks \
    --out-dir   runs/cybergym-loop \
    --provider  openai --model gpt-5.5 \
    --concurrency 4

# Or skip grading (for local dry-runs)
python3 loop_runners/cybergym_loop.py --tasks-dir tasks --out-dir dry \
    --provider openai --model gpt-5.5 --no-grade
```

Per task you get `result.json`, `transcript.txt`, and the raw `poc` under
`<out>/<task_id>/`.

## Quickstart: SEC-bench Pro

Config lives next to the existing `eval_claude.py` / `eval_codex.py` configs:

```bash
cd sec_bench_pro
uv run harness/eval_loop.py harness/configs/loop/v8/config.example.toml
```

`eval_loop.py` installs the loop CLI inside each benchmark container the first
time (idempotent), copies the rendered prompt in, runs
`loop --cwd <work_dir> --print "<prompt>"` with the chosen provider/model, and
collects the `audit/` directory back. From there the normal
`sec_bench_pro/harness/grade.py` scores the run — no change to grading.

## Repo layout

```
cyber_bench/
├── README.md                  (this file)
├── cybergym/
│   └── examples/agents/
│       ├── cybench/           upstream
│       ├── enigma/            upstream
│       ├── codex/             upstream
│       ├── openhands/         upstream
│       ├── claude/            NEW: Claude Code driver
│       └── opencode/          NEW: OpenCode driver
├── sec_bench_pro/
│   └── harness/
│       ├── eval_claude.py     upstream
│       ├── eval_codex.py      upstream
│       ├── eval_opencode.py   upstream
│       ├── eval_loop.py       Soket AI loop
│       ├── eval_cybench.py    NEW: Cybench driver
│       ├── eval_enigma.py     NEW: EnIGMA driver
│       ├── eval_openhands.py  NEW: OpenHands driver
│       └── configs/           per-agent example configs
└── loop_runners/
    ├── README.md
    └── cybergym_loop.py       drive CyberGym tasks with loop
```

The old Eka ReAct runners (`run/agent_runner.py`, `sec_bench_pro_run/*`) and
every other sibling (`Gym`, `cybergym-e2e`, `cybergym-agent-examples`,
`cybergym_synthetic`, `synthetic_data_gen`, the vendored `loop/` clone) were
removed; everything lives in git history if you need to recover something.
