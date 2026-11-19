"""Evaluation harness for the EnIGMA agent inside Docker containers.

EnIGMA is built on top of SWE-agent; the entrypoint lives at
``sweagent run`` (single-task mode) in recent releases. This driver
clones the EnIGMA fork of SWE-agent into the SEC-bench container, runs
one task per instance against the workdir, and collects `./audit/`.

Usage::

    uv run harness/eval_enigma.py harness/configs/enigma/v8/config.example.toml
    python3 harness/eval_enigma.py harness/configs/enigma/sm/config.example.toml --no-tui
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


_PROVIDER_API_KEY_ENV: dict[str, str] = {
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "openrouter": "OPENROUTER_API_KEY",
    "gemini": "GEMINI_API_KEY",
}

_ENIGMA_REPO_DEFAULT = "https://github.com/princeton-nlp/SWE-agent.git"
_ENIGMA_INSTALL_DIR = "/opt/enigma"


def _install_enigma(container_id: str, repo_url: str, commit: str | None) -> int:
    step_run("Install EnIGMA harness")

    checkout = f"&& git checkout {shlex.quote(commit)}" if commit else ""
    cmd = (
        "set -e; "
        "if ! command -v git >/dev/null 2>&1 || ! command -v pip3 >/dev/null 2>&1; then "
        "  apt-get update -qq && apt-get install -y -qq git python3-pip >/dev/null; "
        "fi; "
        f"if [ ! -d {_ENIGMA_INSTALL_DIR} ]; then "
        f"  git clone --depth 1 {shlex.quote(repo_url)} {_ENIGMA_INSTALL_DIR}; "
        "fi; "
        f"cd {_ENIGMA_INSTALL_DIR} {checkout} && "
        "python3 -m pip install --quiet --no-cache-dir -e . || true"
    )
    rc, _out, stderr = docker_exec(container_id, cmd, 900)
    if rc != 0:
        detail = (stderr or "").strip().splitlines()[-1:] or [""]
        step_err(f"Install EnIGMA  {DIM}{detail[0][:160]}{NC}")
        return rc
    step_ok("Install EnIGMA harness")
    return 0


def _write_prompt(container_id: str, work_dir: str, prompt: str,
                  instance_outdir: Path) -> str:
    prompt_host = instance_outdir / "prompt.txt"
    if not prompt_host.exists():
        prompt_host.write_text(prompt, encoding="utf-8")
    prompt_container = f"{work_dir.rstrip('/')}/.enigma_task.md"
    docker_exec(container_id, f"mkdir -p {shlex.quote(work_dir)}", 15)
    docker_copy_to(container_id, str(prompt_host), prompt_container)
    return prompt_container


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
    repo_url: str = config.get("enigma_repo", _ENIGMA_REPO_DEFAULT)
    commit: str | None = config.get("enigma_commit")
    timeout_secs: int = int(config.get("timeout", 5400))
    cost_limit: float = float(config.get("cost_limit", 3.0))
    privileged: bool = bool(
        config.get("privileged", common.is_linux_project(config.get("project", "")))
    )

    api_key_env: str = config.get(
        "api_key_env",
        _PROVIDER_API_KEY_ENV.get(provider, "OPENAI_API_KEY"),
    )

    forwarded_env_vars: tuple[str, ...] = tuple(v for v in {api_key_env} if v)

    container_name = (
        f"enigma-eval-{instance_id}-{int(datetime.now().timestamp())}"
    )
    common._emit(f"\n{CYAN}{BOLD}>>> Instance: {instance_id} <<<{NC}")
    info(f"Image: {image_name}")
    info(f"Work dir: {work_dir}")
    info(f"Agent: enigma (provider={provider}, model={model})")

    rc = subprocess.run(
        ["docker", "image", "inspect", image_name], capture_output=True
    ).returncode
    if rc != 0:
        info(f"Pulling Docker image: {image_name}")
        subprocess.run(["docker", "pull", image_name], check=True)

    env_args = build_env_args(forwarded_env_vars)
    docker_run_cmd = ["docker", "run", "--detach", "--name", container_name]
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

        if _install_enigma(container_id, repo_url, commit) != 0:
            return 1

        prompt_container_path = _write_prompt(
            container_id, work_dir, prompt, instance_outdir
        )

        # SWE-agent / EnIGMA single-task invocation.
        model_name = f"{provider}/{model}" if provider else model
        agent_cmd = (
            f"cd {shlex.quote(work_dir)} && "
            "sweagent run "
            f"--agent.model.name={shlex.quote(model_name)} "
            f"--agent.model.per_instance_cost_limit={cost_limit} "
            f"--env.repo.path={shlex.quote(work_dir)} "
            f"--problem_statement.path={shlex.quote(prompt_container_path)}"
        )

        common._emit(
            f"  {YELLOW}◉{NC} Run EnIGMA agent  "
            f"{DIM}(timeout={timeout_secs}s, model={provider}/{model}){NC}"
        )
        info("Agent output:")
        common._emit(f"{DIM}{'─' * 64}{NC}")

        agent_stdout_file = instance_outdir / "agent_stdout.txt"
        agent_exit = docker_exec_streaming(
            container_id,
            agent_cmd,
            timeout_secs,
            agent_stdout_file,
            agent_type="enigma",
        )
        common._emit(f"{DIM}{'─' * 64}{NC}")

        if agent_exit == 0:
            step_ok(f"Run EnIGMA agent  {DIM}exit 0{NC}")
        else:
            step_err(f"Run EnIGMA agent  {DIM}exit {agent_exit}{NC}")
            if is_timeout_exit_code(agent_exit):
                write_timeout_marker(instance_outdir, timeout_secs, agent_exit)

        # Collect EnIGMA/SWE-agent trajectories if present.
        docker_exec(
            container_id,
            "cp -r trajectories ./audit/enigma_trajectories 2>/dev/null || true",
            30,
        )

        collect_audit_artifacts(container_id, work_dir, instance_outdir)
        return 0 if agent_exit == 0 else 1
    finally:
        subprocess.run(["docker", "rm", "-f", container_name], capture_output=True)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run SEC-bench Pro with the EnIGMA agent."
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
        SCRIPT_DIR, str(config.get("outdir", "output/enigma")),
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

    info(f"Harness: enigma/{config['model']}")
    info(f"Output:  {run_outdir}")
    info(f"Instances: {' '.join(instances)}")

    return run_eval_loop(
        instances=instances,
        images_dir=images_dir,
        run_outdir=run_outdir,
        prompt_template_path=prompt_template_path,
        config=config,
        agent_label=f"enigma/{config['model']}",
        run_instance_fn=run_instance,
        use_tui=not args.no_tui,
        agents_md=agents_md,
    )


if __name__ == "__main__":
    sys.exit(main())
