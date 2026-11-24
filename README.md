# cyber_bench

Two real-world cybersecurity benchmarks wired up to run with Soket AI's
[**loop**](https://github.com/soketlabs/loop) agent harness and a set of
peer harnesses (`pi`, `dsh`, Claude Code, Codex, OpenCode, OpenHands,
Cybench, EnIGMA).

| Benchmark | What it is | Tasks |
| --- | --- | ---: |
| [CyberGym](https://arxiv.org/abs/2506.02548) (`cybergym/`) | Real OSS-Fuzz / ARVO vulnerabilities. Agent produces a PoC bytes file; a grading server runs it against the pre-patch and post-patch builds. | 1,507 |
| [SEC-bench Pro](https://sec-bench.github.io/) (`sec_bench_pro/`) | Long-horizon V8 / SpiderMonkey security cases. Agent works inside a per-case Docker container and writes findings into `./audit/`. | 183 (103 V8 + 80 SM) |

This README is the single step-by-step for **running the 10% smoke set
on a fresh VM** — 151 CyberGym tasks + 18 SEC-bench Pro cases, across
three agents (`loop`, `pi`, `deepseek` / `dsh`). The per-benchmark
READMEs under `cybergym/README.md` and `sec_bench_pro/README.md` have
more detail on each benchmark's internals.

---

## 1. What the "10% smoke" is and why

Full benchmarks are expensive (CyberGym's server data goes up to 10 TB;
SEC-bench Pro's 183 cases run ~16 compute-hours per agent). The 10%
smoke set picks a representative slice so you can validate the full
pipeline — image pulls, agent install, grading, result collection — in
one working day. The cases below are checked in; nothing has to be
hand-selected at run time.

### CyberGym 10% — 151 tasks

The first 10 are the upstream-curated subset (5 solvable + 5 hard), so
pass/fail on them is diagnostic. The remaining 141 are a
deterministic random sample of the other 1,497 tasks, drawn by
[cybergym/scripts/sample_smoke_tasks.py](cybergym/scripts/sample_smoke_tasks.py)
with a fixed seed so every run of this README picks the same set.

The curated 10 ([loop_runners/smoke_tasks.txt](loop_runners/smoke_tasks.txt)):

| Tier | Task id |
| --- | --- |
| easy | `arvo:47101`, `arvo:3938`, `arvo:24993`, `arvo:1065`, `arvo:10400` |
| hard | `arvo:368`, `oss-fuzz:42535201`, `oss-fuzz:42535468`, `oss-fuzz:370689421`, `oss-fuzz:385167047` |

Why this mix: the 5 easy tasks must pass end-to-end for the harness to
be considered working; the 5 hard tasks exercise non-trivial agent
reasoning (long stack traces, cross-file analysis); the 141 random
tasks give enough breadth for a real success-rate number.

### SEC-bench Pro 10% — 18 cases

Checked in as `smoke.toml` under every agent's config tree
([`sec_bench_pro/harness/configs/<agent>/{v8,sm}/smoke.toml`](sec_bench_pro/harness/configs/)):

**V8 — 10 cases (one per failure mode, filled to 10 by vuln class):**

| Case id | error_type | Vulnerability type |
| --- | --- | --- |
| `324596281` | DCHECK | Type confusion |
| `324747822` | DCHECK | Debug assertion failure |
| `325866363` | RUNTIME_CRASH | Out-of-bounds write |
| `325893559` | DCHECK | Out-of-bounds read |
| `327740539` | RUNTIME_CRASH | Type confusion |
| `329130358` | RUNTIME_CRASH | Use-after-free |
| `334120897` | SANDBOX_VIOLATION | Sandbox bypass |
| `336009921` | SANDBOX_VIOLATION | Type confusion |
| `340221135` | DCHECK | Incorrect JIT optimization |
| `343748812` | DCHECK | Incorrect code generation |

**SpiderMonkey — 8 cases (SM is almost entirely ASAN_CRASH; variety is in bug class):**

| Case id | Vulnerability type |
| --- | --- |
| `1791520` | Use-after-free |
| `1810711` | Cross-compartment violation |
| `1814899` | Incorrect code generation |
| `1821959` | Invalid free |
| `1827073` | Out-of-bounds write |
| `1834711` | Debug assertion failure |
| `1842617` | Type confusion |
| `1862473` | Stack corruption |

Why this mix: V8 has four `error_type` values (DCHECK, RUNTIME_CRASH,
SANDBOX_VIOLATION, ASAN_CRASH) — the set picks each one, then fills by
vulnerability-class variety so each grading path and each bug class is
exercised at least once.

---

## 2. Provisioning the VM

**Recommended:** `n2d-standard-32` (32 vCPU, 128 GB RAM) with a 1 TB
`pd-ssd` boot disk.

```bash
gcloud compute instances create cyber-bench \
    --machine-type=n2d-standard-32 \
    --zone=us-central1-a \
    --image-family=ubuntu-2404-lts \
    --image-project=ubuntu-os-cloud \
    --boot-disk-size=1000GB \
    --boot-disk-type=pd-ssd \
    --metadata=enable-oslogin=TRUE
```

Why `n2d-standard-32`:

- **128 GB RAM** caps SEC-bench Pro concurrency at ~8 containers (each
  V8 build needs ~14 GB). A larger machine wouldn't run more cases in
  parallel.
- **32 vCPU** matches the LLM-rate-limited CyberGym ceiling (~16
  concurrent tasks) with headroom for the host and grading server.
- **1 TB pd-ssd** covers the ~630 GB working set and gives IOPS burst
  for concurrent `docker pull` + log writes.

### Disk budget (why 1 TB)

| Component | Size |
| --- | ---: |
| OS + Docker + Python + agent CLIs | ~40 GB |
| CyberGym metadata + binary-only server data | ~135 GB |
| CyberGym generated task bundles (151 × ~300 MB) | ~45 GB |
| CyberGym grading images | ~30 GB |
| SEC-bench Pro V8 images (10 × ~12 GB) | ~120 GB |
| SEC-bench Pro SM images (8 × ~6 GB) | ~50 GB |
| Agent trajectories + audit (3 agents × 169 runs) | ~90 GB |
| Docker overlay FS + buffer | ~120 GB |
| **Total working set** | **~630 GB** |

---

## 3. One-time setup on the VM

```bash
# 3.1 SSH in
gcloud compute ssh cyber-bench --zone=us-central1-a

# 3.2 System packages + Docker
sudo apt-get update
sudo apt-get install -y git curl build-essential git-lfs \
                        python3 python3-pip p7zip-full
curl -fsSL https://get.docker.com | sudo bash
sudo usermod -aG docker "$USER"
newgrp docker        # pick up the group in this shell

# 3.3 uv (fast Python package manager used by SEC-bench Pro)
curl -LsSf https://astral.sh/uv/install.sh | sh
source "$HOME/.local/bin/env"

# 3.4 loop CLI on the host (used by CyberGym runs)
curl -fsSL https://loop.soket.ai/install | bash
loop --version    # sanity check

# 3.5 Clone this repo
git clone https://github.com/saravanan-soket/cyber_bench.git
cd cyber_bench
git lfs install

# 3.6 Python deps for the SEC-bench Pro harness
cd sec_bench_pro && uv sync && cd ..

# 3.7 Install CyberGym itself (for gen_task + server)
cd cybergym && pip install -e '.[dev,server]' && cd ..

# 3.8 Provider API key(s)
export OPENAI_API_KEY=sk-...
# or ANTHROPIC_API_KEY, SOKET_API_KEY, DEEPSEEK_API_KEY, ...
```

Verify Docker is healthy:

```bash
docker run --rm hello-world
```

---

## 4. CyberGym 10% — step by step

### 4.1 Download data

```bash
cd ~/cyber_bench

# Task metadata (~5 GB over LFS)
git clone https://huggingface.co/datasets/sunblaze-ucb/cybergym cybergym_data

# Binary-only server runners (~130 GB on disk)
python3 cybergym/scripts/server_data/download_binary_only_runners.py
wget https://huggingface.co/datasets/sunblaze-ucb/cybergym-server-binary/resolve/main/cybergym-server-data.7z
7z x cybergym-server-data.7z
```

### 4.2 Pick the 151 task ids (deterministic)

```bash
python3 cybergym/scripts/sample_smoke_tasks.py \
    --tasks-json cybergym_data/tasks.json \
    --count 151 --seed 10 \
    --out loop_runners/smoke_tasks_10pct.txt
# Produces 151 ids; the first 10 are the curated subset.
```

### 4.3 Start the CyberGym grading server (bind to the Docker network gateway, not 0.0.0.0)

```bash
docker network create --driver bridge cybergym-internal
HOST=$(docker network inspect cybergym-internal -f '{{(index .IPAM.Config 0).Gateway}}')
export CYBERGYM_API_KEY="$(openssl rand -hex 32)"

# Run the server in the background (tmux / nohup / systemd — your call)
nohup python3 -m cybergym.server --host "$HOST" --port 8666 \
    > server.log 2>&1 &
export CYBERGYM_SERVER="http://$HOST:8666"
```

See [cybergym/FAQ.md](cybergym/FAQ.md) (Q4) for why `0.0.0.0` is wrong.

### 4.4 Generate the 151 task bundles

```bash
mkdir -p tasks
while read -r task_id; do
  [ -z "$task_id" ] && continue
  slug="${task_id/:/_}"
  python3 -m cybergym.task.gen_task \
      --task-id "$task_id" \
      --out-dir "tasks/$slug" \
      --data-dir cybergym_data/data \
      --server  "$CYBERGYM_SERVER" \
      --mask-map cybergym/mask_map.json \
      --difficulty level1
done < loop_runners/smoke_tasks_10pct.txt
```

### 4.5 Run each agent

**loop** (batched driver):

```bash
python3 loop_runners/cybergym_loop.py \
    --tasks-dir tasks \
    --out-dir   runs/cybergym-loop \
    --provider  openai --model gpt-5.5 \
    --concurrency 16 --task-deadline 1800
```

**pi** and **deepseek** (per-task, so loop in shell):

```bash
for agent in pi deepseek; do
  mkdir -p "runs/cybergym-$agent/logs" "runs/cybergym-$agent/tmp"
  while read -r task_id; do
    [ -z "$task_id" ] && continue
    python3 "cybergym/examples/agents/$agent/run.py" \
        --model gpt-5.5 \
        --log_dir "runs/cybergym-$agent/logs" \
        --tmp_dir "runs/cybergym-$agent/tmp" \
        --task_id "$task_id" \
        --data_dir cybergym_data/data \
        --server  "$CYBERGYM_SERVER" \
        --difficulty level1 || echo "FAIL $task_id" >> "runs/cybergym-$agent/failures.log"
  done < loop_runners/smoke_tasks_10pct.txt
done
```

Each task produces `result.json`, `transcript.txt`, `poc`, and
`submit_output.txt` under its per-task directory.

---

## 5. SEC-bench Pro 10% — step by step

### 5.1 Pre-pull the 18 benchmark images

Pulled from Docker Hub; each image is 6–15 GB. Total ~170 GB, 30–45 min
on a typical GCP network.

```bash
cd ~/cyber_bench/sec_bench_pro

# v8 and sm image names are stored in each case's meta.json
python3 - <<'PY'
import json, pathlib, subprocess, tomllib
for proj in ("v8", "sm"):
    cfg = tomllib.load(open(f"harness/configs/loop/{proj}/smoke.toml", "rb"))
    for inst in cfg["instances"]:
        meta = json.load(open(f"projects/{proj}/{inst}/meta.json"))
        img = meta["image_name"]
        print(f"docker pull {img}")
        subprocess.run(["docker", "pull", img], check=False)
PY
```

### 5.2 Run each agent on V8 and SM

```bash
cd ~/cyber_bench/sec_bench_pro

for agent in loop pi deepseek; do
  for proj in v8 sm; do
    uv run "harness/eval_${agent}.py" \
        "harness/configs/${agent}/${proj}/smoke.toml" \
        --no-tui
  done
done
```

Each run writes under
`sec_bench_pro/output/<proj>/<agent>/smoke/<timestamp>/<instance>/`:
- `prompt.txt` — the rendered task prompt
- `agent_stdout.txt` — full agent output
- `audit/` — files the agent produced (PoC, notes, trajectories)

### 5.3 Grade

```bash
for run in output/v8/{loop,pi,deepseek}/smoke/*/ \
           output/sm/{loop,pi,deepseek}/smoke/*/; do
    uv run harness/grade.py --run-dir "$run"
done
```

`grade.py` runs each agent's PoC against the vulnerable image, confirms
the `error_type` matches `meta.json`, and scores source-review overlap
against `target_source_files`.

---

## 6. Fast path (sanity check, not 10%)

If you want a quick 10-minute smoke rather than the full 10%:

```bash
# CyberGym — curated 10 tasks only (TIER=easy|hard|all)
TIER=easy PROVIDER=openai MODEL=gpt-5.5 \
    TASKS_DIR=tasks OUT_DIR=runs/cybergym-quick \
    bash loop_runners/run_smoke.sh

# SEC-bench Pro — any single smoke config
uv run harness/eval_loop.py harness/configs/loop/v8/smoke.toml --no-tui
```

---

## 7. Expected wallclock and cost (10% full smoke)

On `n2d-standard-32`, three agents back-to-back (image cache reused):

| Phase | Per agent | Three agents |
| --- | ---: | ---: |
| Image pulls (one-time) | — | ~45 min |
| CyberGym 151 tasks (conc=16) | ~3.5 h | ~10.5 h |
| SEC-bench V8 10 cases (conc=8) | ~1.5 h | ~4.5 h |
| SEC-bench SM 8 cases (conc=8) | ~1 h | ~3 h |
| **Total** | **~6.5 h** | **~18 h wallclock** |

LLM cost at GPT-5.5-class pricing lands roughly **$1.5k–$3k for the
full 10% across all three agents**. Confirm your API budget before
starting.

---

## 8. Repo layout

```
cyber_bench/
├── README.md                  (this file)
├── cybergym/
│   ├── README.md              upstream docs
│   ├── examples/agents/
│   │   ├── cybench/           upstream
│   │   ├── enigma/            upstream
│   │   ├── codex/             upstream
│   │   ├── openhands/         upstream
│   │   ├── claude/            Claude Code driver
│   │   ├── opencode/          OpenCode driver
│   │   ├── pi/                pi (Earendil) driver
│   │   └── deepseek/          DeepSeek Harness (dsh) driver
│   └── scripts/
│       ├── sample_smoke_tasks.py   deterministic 151-task sampler
│       └── server_data/            upstream server-data helpers
├── sec_bench_pro/
│   └── harness/
│       ├── eval_{claude,codex,opencode,loop,cybench,enigma,
│       │          openhands,pi,deepseek}.py
│       ├── grade.py
│       └── configs/<agent>/<proj>/{config.example.toml, smoke.toml}
└── loop_runners/
    ├── cybergym_loop.py       CyberGym task driver using loop
    ├── run_smoke.sh           curated-10 subset runner
    └── smoke_tasks.txt        curated 10-task list
```

---

## 9. Troubleshooting

- **`docker: permission denied`** — run `newgrp docker` or log out/in
  after `usermod -aG docker`.
- **CyberGym grading hangs** — the server must be reachable from the
  agent containers. Verify with `docker run --rm --network cybergym-internal
  curlimages/curl -s "$CYBERGYM_SERVER/health"`. If not reachable you
  bound the server to `0.0.0.0` or `127.0.0.1` instead of the Docker
  gateway (see [cybergym/FAQ.md](cybergym/FAQ.md), Q4).
- **SEC-bench container OOM on V8 cases** — RAM ceiling. Drop
  concurrency in the config (`concurrency = 4`) or move to
  `n2d-standard-32`+.
- **Disk fills during image pulls** — `docker system prune -a --volumes`
  between benchmarks; CyberGym and SEC-bench use disjoint image sets.
- **LLM rate-limit (HTTP 429)** — lower concurrency or use a higher-tier
  API key. The harness retries on 429 but each retry eats wallclock.
