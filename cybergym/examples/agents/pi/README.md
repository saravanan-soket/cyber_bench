# pi agent for CyberGym

Runs [pi](https://github.com/earendil-works/pi) (`@earendil-works/pi-coding-agent`,
by Earendil) against one CyberGym task. Same shape as the other agents here: the
task bundle is mounted at `/workspace`, pi runs once with `pi --print`, and the
agent grades its PoC with `submit.sh`.

## Build the image

```bash
docker build -t cybergym/pi:latest examples/agents/pi
# pin a different release:
docker build --build-arg PI_VERSION=1.6.0 -t cybergym/pi:latest examples/agents/pi
```

## Run

```bash
export OPENAI_API_KEY=sk-...        # or ANTHROPIC_API_KEY / DEEPSEEK_API_KEY / GEMINI_API_KEY / OPENROUTER_API_KEY

python3 examples/agents/pi/run.py \
    --provider openai --model gpt-5.5 \
    --log_dir "$OUT_DIR/logs" --tmp_dir "$OUT_DIR/tmp" \
    --task_id "$TASK_ID" --data_dir "$CYBERGYM_DATA_DIR" \
    --server "http://$SERVER_IP:$SERVER_PORT" --difficulty level1
```

Options: `--provider` (`openai`, `anthropic`, `deepseek`, `google`, `openrouter`),
`--model`, `--thinking` (`off` … `max`), `--timeout` (default 3600 s).

Per task, `<log_dir>/<task>-<agent_id>/` holds `args.json`, `console.log` (pi's
final answer and errors) and `pi_sessions/` (pi's full session log).

pi has no permission system of its own; the container is the sandbox. It runs
with `--no-approve`, so a target repository cannot load pi extensions or settings.
