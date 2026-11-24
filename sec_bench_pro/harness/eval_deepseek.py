"""Evaluation harness that drives SEC-bench Pro instances with
[DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) (`dsh`).

Usage::

    uv run harness/eval_deepseek.py harness/configs/deepseek/v8/config.example.toml
    python3 harness/eval_deepseek.py harness/configs/deepseek/sm/config.example.toml --no-tui

For each instance: start the benchmark container, `npm install -g` the pinned
`@deepseek-ai/dsh` (needs Node >= 24.9; the images ship Node 24), write a
profile overlay that selects the model and disables web search/fetch, run
`dsh --profile headless --json` once with the task on stdin, copy dsh's
session logs to the run output, and collect `audit/` for `grade.py`.

Config keys beyond the common ones:

    model              model id, e.g. "deepseek-v4-pro" or "gpt-5.5"
    provider           "deepseek-official" (native DeepSeek route) or a pi-ai
                       provider id: openai | anthropic | google | openrouter | ...
    api_key_env        env var forwarded into the container (default: per provider)
    reasoning_effort   optional effort level stored on the default model
    allow_web          true keeps dsh's web search/fetch tool (default false)
    dsh_version        npm version to install (default: _DEFAULT_DSH_VERSION)
"""
from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import sys
from datetime import datetime
from pathlib import Path

import common
from common import (
    SCRIPT_DIR,
    BOLD,
    CYAN,
    DIM,
    NC,
    YELLOW,
    build_env_args,
    collect_audit_artifacts,
    docker_copy_from,
    docker_copy_to,
    docker_exec,
    docker_exec_streaming,
    docker_pipe_stdin,
    docker_preflight,
    error,
    info,
    is_timeout_exit_code,
    load_config,
    resolve_instances,
    resolve_path,
    run_eval_loop,
    setup_linux_evaluation_container,
    step_err,
    step_ok,
    step_run,
    write_timeout_marker,
)


_DEFAULT_DSH_VERSION = "0.2.2-rc.5"
_DSH_PACKAGE = "@deepseek-ai/dsh"
_DSH_NATIVE_PROVIDER = "deepseek-official"
_DSH_HOME = "/root/.dsh"
_BENCH_DIR = "/root/.dsh-bench"

_PROVIDER_API_KEY_ENV: dict[str, str] = {
    _DSH_NATIVE_PROVIDER: "DEEPSEEK_API_KEY",
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "google": "GEMINI_API_KEY",
    "openrouter": "OPENROUTER_API_KEY",
}

_NODE_24_9_CHECK = (
    "node -e 'const [a,b]=process.versions.node.split(\".\").map(Number);"
    "process.exit(a>24||(a===24&&b>=9)?0:1)'"
)


def build_overlay(*, provider: str, model: str, api_key_env: str,
                  reasoning_effort: str | None, allow_web: bool) -> str:
    """Return the dsh profile patch; JSON scalars are valid YAML."""
    q = json.dumps
    lines = [
        "- id: agent-default-model",
        "  config:",
        f"    provider: {q(provider)}",
        f"    model: {q(model)}",
    ]
    if reasoning_effort:
        lines.append(f"    reasoningEffort: {q(reasoning_effort)}")
    # Non-native providers route through the pi-ai adapter, which ships with no routes.
    if provider != _DSH_NATIVE_PROVIDER:
        lines += [
            "- id: llm-pi-ai",
            "  config:",
            "    providers:",
            f"      {q(provider)}:",
            f"        apiKeyEnv: {q(api_key_env)}",
        ]
    if not allow_web:
        lines += ["- id: tool-web", "  disabled: true"]
    return "\n".join(lines) + "\n"


def build_dsh_command(*, work_dir: str, prompt_path: str, overlay_path: str) -> str:
    return (
        f"cd {shlex.quote(work_dir)} && "
        f"DSH_HOME={_DSH_HOME} dsh --profile headless "
        f"--patch {shlex.quote(overlay_path)} "
        "--permission-mode danger-full-access --approval-policy never "
        f"--json - < {shlex.quote(prompt_path)}"
    )


def _install_dsh(container_id: str, version: str) -> int:
    step_run("Install DeepSeek Harness CLI")
    pkg = shlex.quote(f"{_DSH_PACKAGE}@{version}")
    cmd = (
        "set -e; "
        "command -v node >/dev/null 2>&1 || { echo 'node not found in image' >&2; exit 2; }; "
        f"{_NODE_24_9_CHECK} || {{ echo \"dsh needs Node >= 24.9, image has $(node --version)\" >&2; exit 2; }}; "
        f"npm install -g --ignore-scripts --no-audit --no-fund {pkg} >/dev/null"
    )
    rc, _out, stderr = docker_exec(container_id, cmd, 900)
    if rc != 0:
        detail = (stderr or "").strip().splitlines()[-1:] or [""]
        step_err(f"Install DeepSeek Harness CLI  {DIM}{detail[0][:160]}{NC}")
        return rc
    step_ok(f"Install DeepSeek Harness CLI  {DIM}{version}{NC}")
    return 0


def _write_agents_md(container_id: str, work_dir: str,
                     agents_md_content: str | None) -> None:
    if not agents_md_content:
        return
    rc, _, _ = docker_exec(
        container_id,
        (
            f"cat > {shlex.quote(work_dir)}/AGENTS.md <<'_DSH_AGENTS_MD_EOF'\n"
            f"{agents_md_content}\n"
            "_DSH_AGENTS_MD_EOF"
        ),
        30,
    )
    if rc == 0:
        step_ok("Stage AGENTS.md")


def run_instance(
    *,
    instance_id: str,
    image_name: str,
    work_dir: str,
    instance_outdir: Path,
    prompt: str,
    config: dict,
    agents_md_content: str | None,
    linux_secb_config_content: str | None,
    linux_instance_dir: Path | None,
) -> int:
    model: str = config["model"]
    provider: str = config.get("provider", _DSH_NATIVE_PROVIDER)
    version: str = str(config.get("dsh_version", _DEFAULT_DSH_VERSION))
    timeout_secs: int = int(config.get("timeout", 5400))
    privileged: bool = bool(config.get("privileged", False))
    api_key_env: str = config.get(
        "api_key_env", _PROVIDER_API_KEY_ENV.get(provider, "")
    )
    if not api_key_env:
        error(f"No API-key env var known for provider {provider!r}; set api_key_env")
        return 1

    container_name = f"dsh-eval-{instance_id}-{int(datetime.now().timestamp())}"
    common._emit(f"\n{CYAN}{BOLD}>>> Instance: {instance_id} <<<{NC}")
    info(f"Image: {image_name}")
    info(f"Work dir: {work_dir}")
    info(f"Agent: deepseek-harness {version} (provider={provider}, model={model})")

    if subprocess.run(["docker", "image", "inspect", image_name],
                      capture_output=True).returncode != 0:
        info(f"Pulling Docker image: {image_name}")
        subprocess.run(["docker", "pull", image_name], check=True)

    docker_run_cmd = ["docker", "run", "--detach", "--name", container_name]
    if privileged:
        docker_run_cmd.append("--privileged")
    docker_run_cmd += [*build_env_args((api_key_env,)), image_name,
                       "bash", "-c", "sleep infinity"]
    run_rc = subprocess.run(docker_run_cmd, capture_output=True, text=True)
    if run_rc.returncode != 0:
        error(f"docker run failed: {run_rc.stderr.strip()}")
        return 1
    container_id = run_rc.stdout.strip()

    try:
        if linux_secb_config_content is not None:
            setup_linux_evaluation_container(
                container_id,
                secb_config_content=linux_secb_config_content,
                instance_dir=linux_instance_dir,
            )

        if _install_dsh(container_id, version) != 0:
            return 1

        overlay = build_overlay(
            provider=provider, model=model, api_key_env=api_key_env,
            reasoning_effort=config.get("reasoning_effort"),
            allow_web=bool(config.get("allow_web", False)),
        )
        (instance_outdir / "dsh_overlay.yml").write_text(overlay, encoding="utf-8")
        prompt_host = instance_outdir / "prompt.txt"
        if not prompt_host.exists():
            prompt_host.write_text(prompt, encoding="utf-8")

        overlay_path = f"{_BENCH_DIR}/overlay.yml"
        prompt_path = f"{_BENCH_DIR}/prompt.txt"
        docker_exec(container_id, f"mkdir -p {_BENCH_DIR} {shlex.quote(work_dir)}", 15)
        if not docker_pipe_stdin(container_id, overlay, overlay_path):
            step_err("Write dsh overlay")
            return 1
        docker_copy_to(container_id, str(prompt_host), prompt_path)
        _write_agents_md(container_id, work_dir, agents_md_content)

        dsh_cmd = build_dsh_command(
            work_dir=work_dir, prompt_path=prompt_path, overlay_path=overlay_path,
        )
        common._emit(
            f"  {YELLOW}◉{NC} Run DeepSeek Harness agent  "
            f"{DIM}(timeout={timeout_secs}s, model={provider}/{model}){NC}"
        )
        info("Agent output:")
        common._emit(f"{DIM}{'─' * 64}{NC}")
        agent_exit = docker_exec_streaming(
            container_id, dsh_cmd, timeout_secs,
            instance_outdir / "agent_stdout.txt", agent_type="deepseek",
        )
        common._emit(f"{DIM}{'─' * 64}{NC}")

        if agent_exit == 0:
            step_ok(f"Run DeepSeek Harness agent  {DIM}exit 0{NC}")
        else:
            step_err(f"Run DeepSeek Harness agent  {DIM}exit {agent_exit}{NC}")
            if is_timeout_exit_code(agent_exit):
                write_timeout_marker(instance_outdir, timeout_secs, agent_exit)

        sessions_dest = instance_outdir / "dsh_sessions"
        sessions_dest.mkdir(parents=True, exist_ok=True)
        docker_copy_from(container_id, f"{_DSH_HOME}/sessions/.", str(sessions_dest) + "/")

        collect_audit_artifacts(container_id, work_dir, instance_outdir)
        return 0 if agent_exit == 0 else 1
    finally:
        subprocess.run(["docker", "rm", "-f", container_name], capture_output=True)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run SEC-bench Pro with DeepSeek Harness (dsh)."
    )
    parser.add_argument("config", type=Path, help="TOML configuration file")
    parser.add_argument("--no-tui", action="store_true")
    args = parser.parse_args()

    if not args.config.is_file():
        error(f"Config not found: {args.config}")
        return 2
    try:
        config = load_config(args.config)
    except Exception as exc:
        error(f"Invalid config: {exc}")
        return 2
    if "model" not in config:
        error("config missing required field: model")
        return 2
    config.setdefault("provider", _DSH_NATIVE_PROVIDER)
    config.setdefault("timeout", 5400)

    try:
        docker_preflight()
    except Exception as exc:
        error(f"Docker preflight failed: {exc}")
        return 1

    images_dir = resolve_path(SCRIPT_DIR, str(config.get("images_dir", "../projects")))
    if not images_dir.is_dir():
        error(f"images_dir not found: {images_dir}")
        return 2
    try:
        instances = resolve_instances(config, images_dir)
    except ValueError as exc:
        error(str(exc))
        return 2
    if not instances:
        error("No instances resolved from config")
        return 2

    outdir = resolve_path(SCRIPT_DIR, str(config.get("outdir", "output/deepseek")))
    run_outdir = outdir / datetime.now().strftime("%Y-%m-%dT%H-%M-%S")
    run_outdir.mkdir(parents=True, exist_ok=True)

    prompt_template_path = resolve_path(SCRIPT_DIR, str(config["prompt_template"]))
    if not prompt_template_path.is_file():
        error(f"prompt_template not found: {prompt_template_path}")
        return 2
    agents_md = None
    if "agents_md" in config:
        agents_md = resolve_path(SCRIPT_DIR, str(config["agents_md"]))
        if not agents_md.is_file():
            error(f"agents_md not found: {agents_md}")
            return 2

    info(f"Harness: deepseek/{config['model']}")
    info(f"Output:  {run_outdir}")
    info(f"Instances: {' '.join(instances)}")

    return run_eval_loop(
        instances=instances,
        images_dir=images_dir,
        run_outdir=run_outdir,
        prompt_template_path=prompt_template_path,
        config=config,
        agent_label=f"deepseek/{config['model']}",
        run_instance_fn=run_instance,
        use_tui=not args.no_tui,
        agents_md=agents_md,
    )


if __name__ == "__main__":
    sys.exit(main())
