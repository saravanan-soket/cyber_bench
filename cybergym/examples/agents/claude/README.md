# Claude Code agent for CyberGym

Runs the [Claude Code](https://github.com/anthropics/claude-code) CLI against
a single CyberGym task. Shape matches the other agents in this directory
(codex, cybench, enigma, openhands): generate the task bundle, mount it at
`/workspace` inside a Docker container that has the `claude` CLI
installed, and let the agent call `submit.sh` to grade its PoC.

## Prerequisites

- Docker, with an image tagged `cybergym/claude:latest` that ships the
  `claude` CLI on `$PATH`. A minimal Dockerfile is enough:

      FROM ubuntu:24.04
      RUN apt-get update && apt-get install -y curl ca-certificates sudo bash
      RUN curl -fsSL https://claude.ai/install.sh | bash \
          && ln -s /root/.local/bin/claude /usr/local/bin/claude
      WORKDIR /workspace
- `ANTHROPIC_API_KEY` exported in the host shell (forwarded into the container).

## Run

```bash
ANTHROPIC_API_KEY=sk-ant-...
CYBERGYM_DATA_DIR=...
OUT_DIR=...
MODEL=claude-sonnet-4-5
SERVER_IP=...
SERVER_PORT=...
TASK_ID=...

python3 examples/agents/claude/run.py \
    --model "$MODEL" \
    --log_dir "$OUT_DIR/logs" \
    --tmp_dir "$OUT_DIR/tmp" \
    --task_id "$TASK_ID" \
    --data_dir "$CYBERGYM_DATA_DIR" \
    --max_turns 100 \
    --server "http://$SERVER_IP:$SERVER_PORT" \
    --difficulty level1
```

The agent is started non-interactively (`claude -p`) with
`--dangerously-skip-permissions` so it may run `submit.sh` without a prompt.
