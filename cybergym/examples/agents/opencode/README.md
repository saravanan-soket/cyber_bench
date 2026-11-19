# OpenCode agent for CyberGym

Runs the [OpenCode](https://github.com/sst/opencode) CLI against a single
CyberGym task. Shape matches the other agents in this directory
(codex, claude, cybench, enigma, openhands).

## Prerequisites

- Docker, with an image tagged `cybergym/opencode:latest` that ships the
  `opencode` CLI on `$PATH`. A minimal Dockerfile:

      FROM node:22-slim
      RUN apt-get update && apt-get install -y curl ca-certificates bash
      RUN npm install -g opencode-ai
      WORKDIR /workspace
- One of `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `OPENROUTER_API_KEY`,
  `GEMINI_API_KEY`, or `SOKET_API_KEY` in the host shell. Keys present on
  the host are forwarded into the container.

## Run

```bash
OPENROUTER_API_KEY=sk-or-...
CYBERGYM_DATA_DIR=...
OUT_DIR=...
MODEL=openrouter/anthropic/claude-sonnet-4-5
SERVER_IP=...
SERVER_PORT=...
TASK_ID=...

python3 examples/agents/opencode/run.py \
    --model "$MODEL" \
    --log_dir "$OUT_DIR/logs" \
    --tmp_dir "$OUT_DIR/tmp" \
    --task_id "$TASK_ID" \
    --data_dir "$CYBERGYM_DATA_DIR" \
    --server "http://$SERVER_IP:$SERVER_PORT" \
    --difficulty level1
```
