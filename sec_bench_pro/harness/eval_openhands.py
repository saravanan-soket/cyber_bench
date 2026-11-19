"""Evaluation harness for the OpenHands agent inside Docker containers.

Mirrors eval_claude / eval_codex / eval_opencode / eval_loop. For each
instance we:

1.  Start the SEC-bench container for that instance.
2.  Install the OpenHands CLI inside the container (pip install).
3.  Write the rendered task prompt into the workdir.
4.  Run OpenHands in "single task" mode (`openhands --task-file ...`), so
    the agent patches `./audit/` and exits.
5.  Collect `./audit/` via the same helper the other drivers use so
    `grade.py` can read the result.

Usage::

    uv run harness/eval_openhands.py harness/configs/openhands/v8/config.example.toml
    python3 harness/eval_openhands.py harness/configs/openhands/sm/config.example.toml --no-tui
"""
from __future__ import annotations

import argparse
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
    docker_copy_to,
    docker_exec,
    docker_exec_streaming,
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


# Default API-key env var per LLM provider id used by OpenHands.
_PROVIDER_API_KEY_ENV: dict[str, str] = {
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "openrouter": "OPENROUTER_API_KEY",
    "gemini": "GEMINI_API_KEY",
}


def _install_openhands(container_id: str, version: str | None) -> int:
    step_run("Install OpenHands CLI")

    pkg = "openhands-ai"
    if version:
        pkg = f"openhands-ai=={version}"
    pkg = shlex.quote(pkg)

    cmd = (
        "set -e; "
        "if ! command -v pip >/dev/null 2>&1 && ! command -v pip3 >/dev/null 2>&1; then "
        "  apt-get update -qq && apt-get install -y -qq python3-pip >/dev/null; "
        "fi; "
        f"python3 -m pip install --quiet --upgrade --no-cache-dir {pkg}"
    )
    rc, _out, stderr = docker_exec(container_id, cmd, 600)
    if rc != 0:
        detail = (stderr or "").strip().splitlines()[-1:] or [""]
        step_err(f"Install OpenHands CLI  {DIM}{detail[0][:160]}{NC}")
        return rc

    v_rc, v_out, _ = docker_exec(container_id, "openhands --version 2>&1 | head -1", 30)
    if v_rc == 0:
        step_ok(f"Install OpenHands CLI  {DIM}{v_out.strip()}{NC}")
    else:
        step_ok("Install OpenHands CLI")
    return 0


def _write_prompt(container_id: str, work_dir: str, prompt: str,
                  instance_outdir: Path) -> str:
    prompt_host = instance_outdir / "prompt.txt"
    if not prompt_host.exists():
        prompt_host.write_text(prompt, encoding="utf-8")
    prompt_container = f"{work_dir.rstrip('/')}/.openhands_task.txt"
    docker_exec(container_id, f"mkdir -p {shlex.quote(work_dir)}", 15)
    docker_copy_to(container_id, str(prompt_host), prompt_container)
    return prompt_container


def _write_agents_md(container_id: str, work_dir: str,
                     agents_md_content: str | None) -> None:
    if not agents_md_content:
        return
    rc, _, _ = docker_exec(
        container_id,
        (
            f"cat > {shlex.quote(work_dir)}/AGENTS.md <<'_OH_AGENTS_MD_EOF'\n"
            f"{agents_md_content}\n"
            "_OH_AGENTS_MD_EOF"
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
    provider: str = config.get("provider", "openai")
    openhands_version: str | None = config.get("openhands_version")
    timeout_secs: int = int(config.get("timeout", 5400))
    max_iterations: int = int(config.get("max_iterations", 100))
    privileged: bool = bool(
        config.get("privileged", common.is_linux_project(config.get("project", "")))
    )

    api_key_env: str = config.get(
        "api_key_env",
        _PROVIDER_API_KEY_ENV.get(provider, "OPENAI_API_KEY"),
    )

    # LLM_MODEL / LLM_API_KEY / LLM_BASE_URL are the standard OpenHands envs.
    forwarded_env_vars: tuple[str, ...] = tuple(
        v for v in {api_key_env, "LLM_API_KEY", "LLM_BASE_URL"} if v
    )

    container_name = (
        f"openhands-eval-{instance_id}-{int(datetime.now().timestamp())}"
    )
    common._emit(f"\n{CYAN}{BOLD}>>> Instance: {instance_id} <<<{NC}")
    info(f"Image: {image_name}")
    info(f"Work dir: {work_dir}")
    info(f"Agent: openhands (provider={provider}, model={model})")

    rc = subprocess.run(
        ["docker", "image", "inspect", image_name], capture_output=True
    ).returncode
    if rc != 0:
        info(f"Pulling Docker image: {image_name}")
        subprocess.run(["docker", "pull", image_name], check=True)
    else:
        info(f"Docker image found locally: {image_name}")

    env_args = build_env_args(forwarded_env_vars)
    docker_run_cmd = [
        "docker", "run", "--detach", "--name", container_name,
    ]
    if privileged:
        docker_run_cmd.append("--privileged")
    docker_run_cmd.extend([*env_args, image_name, "bash", "-c", "sleep infinity"])

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

        if _install_openhands(container_id, openhands_version) != 0:
            return 1

        prompt_container_path = _write_prompt(
            container_id, work_dir, prompt, instance_outdir
        )
        _write_agents_md(container_id, work_dir, agents_md_content)

        # OpenHands CLI runs one headless task per invocation.
        openhands_cmd = (
            f"cd {shlex.quote(work_dir)} && "
            f"export LLM_MODEL={shlex.quote(f'{provider}/{model}' if provider else model)} && "
            f"export LLM_API_KEY=\"${{{api_key_env}:-${{LLM_API_KEY:-}}}}\" && "
            "openhands "
            f"--task-file {shlex.quote(prompt_container_path)} "
            f"--max-iterations {max_iterations} "
            "--no-interactive"
        )

        common._emit(
            f"  {YELLOW}◉{NC} Run OpenHands agent  "
            f"{DIM}(timeout={timeout_secs}s, model={provider}/{model}){NC}"
        )
        info("Agent output:")
        common._emit(f"{DIM}{'─' * 64}{NC}")

        agent_stdout_file = instance_outdir / "agent_stdout.txt"
        agent_exit = docker_exec_streaming(
            container_id,
            openhands_cmd,
            timeout_secs,
            agent_stdout_file,
            agent_type="openhands",
        )
        common._emit(f"{DIM}{'─' * 64}{NC}")

        if agent_exit == 0:
            step_ok(f"Run OpenHands agent  {DIM}exit 0{NC}")
        else:
            step_err(f"Run OpenHands agent  {DIM}exit {agent_exit}{NC}")
            if is_timeout_exit_code(agent_exit):
                write_timeout_marker(instance_outdir, timeout_secs, agent_exit)

        # Snapshot OpenHands trajectories if present.
        docker_exec(
            container_id,
            "cp -r /root/.openhands/trajectories ./audit/openhands_trajectories 2>/dev/null || true",
            30,
        )

        collect_audit_artifacts(container_id, work_dir, instance_outdir)
        return 0 if agent_exit == 0 else 1
    finally:
        subprocess.run(["docker", "rm", "-f", container_name], capture_output=True)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run SEC-bench Pro with the OpenHands agent."
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
    config.setdefault("provider", "openai")
    config.setdefault("timeout", 5400)

    try:
        docker_preflight()
    except Exception as exc:
        error(f"Docker preflight failed: {exc}")
        return 1

    images_dir = resolve_path(
        SCRIPT_DIR, str(config.get("images_dir", "../projects")),
    )
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

    outdir = resolve_path(
        SCRIPT_DIR, str(config.get("outdir", "output/openhands")),
    )
    run_outdir = outdir / datetime.now().strftime("%Y-%m-%dT%H-%M-%S")
    run_outdir.mkdir(parents=True, exist_ok=True)

    prompt_template_path = resolve_path(
        SCRIPT_DIR, str(config["prompt_template"]),
    )
    if not prompt_template_path.is_file():
        error(f"prompt_template not found: {prompt_template_path}")
        return 2

    agents_md = None
    if "agents_md" in config:
        agents_md = resolve_path(SCRIPT_DIR, str(config["agents_md"]))
        if not agents_md.is_file():
            error(f"agents_md not found: {agents_md}")
            return 2

    info(f"Harness: openhands/{config['model']}")
    info(f"Output:  {run_outdir}")
    info(f"Instances: {' '.join(instances)}")

    return run_eval_loop(
        instances=instances,
        images_dir=images_dir,
        run_outdir=run_outdir,
        prompt_template_path=prompt_template_path,
        config=config,
        agent_label=f"openhands/{config['model']}",
        run_instance_fn=run_instance,
        use_tui=not args.no_tui,
        agents_md=agents_md,
    )


if __name__ == "__main__":
    sys.exit(main())
