# DeepSeek Harness agent for CyberGym

Runs [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness)
(`@deepseek-ai/dsh`, by DeepSeek AI) against one CyberGym task in its one-shot
headless mode: `dsh --profile headless --json "<task>"`. The task bundle is
mounted at `/workspace` and the agent grades its PoC with `submit.sh`.

## Build the image

```bash
docker build -t cybergym/deepseek:latest examples/agents/deepseek
# pin a different release (needs Node >= 24.9, which the node:24 base provides):
docker build --build-arg DSH_VERSION=0.2.2-rc.5 -t cybergym/deepseek:latest examples/agents/deepseek
```

## Run

```bash
# Native DeepSeek route
export DEEPSEEK_API_KEY=sk-...
python3 examples/agents/deepseek/run.py \
    --provider deepseek-official --model deepseek-v4-pro \
    --log_dir "$OUT_DIR/logs" --tmp_dir "$OUT_DIR/tmp" \
    --task_id "$TASK_ID" --data_dir "$CYBERGYM_DATA_DIR" \
    --server "http://$SERVER_IP:$SERVER_PORT" --difficulty level1

# Same model as the other harnesses (routed through dsh's bundled pi-ai adapter)
export OPENAI_API_KEY=sk-...
python3 examples/agents/deepseek/run.py --provider openai --model gpt-5.5 ...
```

How the run is configured:

- A profile overlay (`<log_dir>/.../dsh_home/overlay.yml`) selects the model.
  For providers other than `deepseek-official`, it also declares the provider
  route on the pi-ai adapter, which ships with none.
- Web search and fetch are **disabled** so the agent cannot look up published
  fixes. Pass `--allow_web true` to keep them.
- `--permission-mode danger-full-access --approval-policy never`: dsh's own
  sandbox and approval prompts are off. The container is the sandbox, as with
  the other agents.
- `DSH_HOME` is mounted from `<log_dir>/.../dsh_home`, so dsh's session log
  (`sessions/**/session.v4.jsonl.zstd`) is kept. `console.log` holds the
  `--json` event stream, ending in a `final` event.
