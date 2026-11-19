"""Evaluation harness that drives SEC-bench Pro instances with the
[loop](https://github.com/soketlabs/loop) agent (Soket AI).

Usage::

    uv run harness/eval_loop.py harness/configs/loop/v8/config.example.toml
    python3 harness/eval_loop.py harness/configs/loop/v8/config.example.toml --no-tui

Shape:

1. Load a TOML config (same style as eval_codex / eval_opencode).
2. For each selected instance: start the benchmark container, install the
   `loop` CLI into the container (one-shot installer from loop.soket.ai),
   write the rendered prompt into the container, run
   `loop --cwd <work_dir> --provider <p> --model <m> --print "<prompt>"`,
   collect the `audit/` directory back, and tear the container down.
3. The existing grader (`harness/grade.py`) reads the collected audit
   directory per instance, same as any other agent runner.

Only a few config keys matter to this script beyond what common.py already
handles:

    model              loop model id, e.g. "gpt-5.5"
    provider           loop provider id, e.g. "openai" | "anthropic" | "soket"
    api_key_env        env var that holds the provider API key; forwarded
                       into the container (default: provider-dependent, see
                       _PROVIDER_API_KEY_ENV)
    loop_version       optional pinned version for the installer
    timeout            per-instance wallclock limit (seconds, default 5400)
    prompt_template    jinja2 path (relative to harness/)
    agents_md          jinja2 path for AGENTS.md (optional)
    images_dir         dir with <instance_id>/meta.json (default harness/../projects)
    instances          list of instance ids OR a selector string

Nothing else from this script is loop-specific; the rest matches the
common.py contract so `grade.py`, resume logic, and the TUI keep working.
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
    run_step,
    setup_linux_evaluation_container,
    step_err,
    step_ok,
    step_run,
    write_timeout_marker,
)


# Default API-key env var per provider id. Only the chosen provider's var is
# forwarded into the container; the others are ignored.
_PROVIDER_API_KEY_ENV: dict[str, str] = {
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "soket": "SOKET_API_KEY",
    "gemini": "GEMINI_API_KEY",
    "openrouter": "OPENROUTER_API_KEY",
}


_LOOP_INSTALLER_URL = "https://loop.soket.ai/install"


def _install_loop_in_container(
    container_id: str, loop_version: str | None
) -> int:
    """Run the official loop installer inside the container. Idempotent:
    the installer skips the download if the binary is already current.
    """
    step_run("Install loop CLI")

    args_env = ""
    if loop_version:
        args_env = f" -s -- --version {shlex.quote(loop_version)}"

    # Try curl first (installer is a shell script). Fall back to wget.
    install_cmd = (
        "set -e; "
        "if command -v curl >/dev/null 2>&1; then "
        f"  curl -fsSL {_LOOP_INSTALLER_URL} | bash{args_env}; "
        "elif command -v wget >/dev/null 2>&1; then "
        f"  wget -qO- {_LOOP_INSTALLER_URL} | bash{args_env}; "
        "else "
        "  echo 'need curl or wget to install loop' >&2; exit 2; "
        "fi"
    )
    rc, _out, stderr = docker_exec(container_id, install_cmd, 300)
    if rc != 0:
        detail = (stderr or "").strip().splitlines()[-1:] or [""]
        step_err(f"Install loop CLI  {DIM}{detail[0][:160]}{NC}")
        return rc

    # Sanity: ensure PATH picks up ~/.loop/bin
    docker_exec(container_id, 'echo "export PATH=\\"$HOME/.loop/bin:$PATH\\"" >> /root/.bashrc', 15)
    version_rc, version_stdout, _ = docker_exec(
        container_id,
        'export PATH="$HOME/.loop/bin:$PATH"; loop --version',
        30,
    )
    if version_rc == 0:
        step_ok(f"Install loop CLI  {DIM}{version_stdout.strip()}{NC}")
    else:
        step_ok("Install loop CLI")
    return 0


def _write_prompt(container_id: str, work_dir: str, prompt: str,
                  instance_outdir: Path) -> str:
    """Write `prompt.txt` into the container's work_dir; return its path."""
    prompt_host = instance_outdir / "prompt.txt"
    # prompt was already saved by run_eval_loop; this is a belt-and-braces write.
    if not prompt_host.exists():
        prompt_host.write_text(prompt, encoding="utf-8")
    prompt_container = f"{work_dir.rstrip('/')}/.loop_prompt.txt"
    docker_exec(container_id, f"mkdir -p {shlex.quote(work_dir)}", 15)
    docker_copy_to(container_id, str(prompt_host), prompt_container)
    return prompt_container


def _write_agents_md(container_id: str, work_dir: str,
                     agents_md_content: str | None) -> None:
    if not agents_md_content:
        return
    # We stage AGENTS.md into the container so loop auto-loads it. Loop reads
    # AGENTS.md from the cwd on startup unless -c is passed.
    rc, _, _ = docker_exec(
        container_id,
        (
            f"cat > {shlex.quote(work_dir)}/AGENTS.md <<'_LOOP_AGENTS_MD_EOF'\n"
            f"{agents_md_content}\n"
            "_LOOP_AGENTS_MD_EOF"
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
    loop_version: str | None = config.get("loop_version")
    timeout_secs: int = int(config.get("timeout", 5400))
    privileged: bool = bool(
        config.get("privileged", common.is_linux_project(config.get("project", "")))
    )

    api_key_env: str = config.get(
        "api_key_env",
        _PROVIDER_API_KEY_ENV.get(provider, ""),
    )
    forwarded_env_vars: tuple[str, ...] = tuple(
        v for v in {api_key_env, "SOKET_API_KEY"} if v
    )
    # Also forward common tracing envs so operators can wire Langfuse.
    forwarded_env_vars = forwarded_env_vars + (
        "LANGFUSE_HOST",
        "LANGFUSE_PUBLIC_KEY",
        "LANGFUSE_SECRET_KEY",
    )

    container_name = (
        f"loop-eval-{instance_id}-{int(datetime.now().timestamp())}"
    )
    common._emit(f"\n{CYAN}{BOLD}>>> Instance: {instance_id} <<<{NC}")
    info(f"Image: {image_name}")
    info(f"Work dir: {work_dir}")
    info(f"Agent: loop (provider={provider}, model={model})")

    # Pull if needed
    rc = subprocess.run(
        ["docker", "image", "inspect", image_name],
        capture_output=True,
    ).returncode
    if rc != 0:
        info(f"Pulling Docker image: {image_name}")
        subprocess.run(["docker", "pull", image_name], check=True)
    else:
        info(f"Docker image found locally: {image_name}")

    env_args = build_env_args(forwarded_env_vars)
    docker_run_cmd = [
        "docker",
        "run",
        "--detach",
        "--name",
        container_name,
    ]
    if privileged:
        docker_run_cmd.append("--privileged")
    docker_run_cmd.extend(
        [
            *env_args,
            image_name,
            "bash",
            "-c",
            "sleep infinity",
        ]
    )

    run_rc = subprocess.run(
        docker_run_cmd, capture_output=True, text=True
    )
    if run_rc.returncode != 0:
        error(f"docker run failed: {run_rc.stderr.strip()}")
        return 1
    container_id = run_rc.stdout.strip()

    try:
        # Per-project container setup is the same as the other eval_*.py.
        if linux_secb_config_content is not None:
            setup_linux_evaluation_container(
                container_id,
                secb_config_content=linux_secb_config_content,
                instance_dir=linux_instance_dir,
            )

        if _install_loop_in_container(container_id, loop_version) != 0:
            return 1

        prompt_container_path = _write_prompt(
            container_id, work_dir, prompt, instance_outdir
        )
        _write_agents_md(container_id, work_dir, agents_md_content)

        # Build the agent command. Use heredoc so the prompt text is
        # passed as a single argument without shell quoting hazards.
        loop_cmd = (
            'export PATH="$HOME/.loop/bin:$PATH" && '
            f"cd {shlex.quote(work_dir)} && "
            "prompt=\"$(cat "
            f"{shlex.quote(prompt_container_path)})\" && "
            "loop "
            f"--cwd {shlex.quote(work_dir)} "
            f"--provider {shlex.quote(provider)} "
            f"--model {shlex.quote(model)} "
            '--print "$prompt"'
        )

        common._emit(
            f"  {YELLOW}\u25c9{NC} Run loop agent  "
            f"{DIM}(timeout={timeout_secs}s, model={provider}/{model}){NC}"
        )
        info("Agent output:")
        common._emit(f"{DIM}{'─' * 64}{NC}")

        agent_stdout_file = instance_outdir / "agent_stdout.txt"
        agent_exit = docker_exec_streaming(
            container_id,
            loop_cmd,
            timeout_secs,
            agent_stdout_file,
            agent_type="loop",
        )
        common._emit(f"{DIM}{'─' * 64}{NC}")

        if agent_exit == 0:
            step_ok(f"Run loop agent  {DIM}exit 0{NC}")
        else:
            step_err(f"Run loop agent  {DIM}exit {agent_exit}{NC}")
            if is_timeout_exit_code(agent_exit):
                write_timeout_marker(
                    instance_outdir,
                    timeout_secs,
                    agent_exit,
                )

        # Save session logs loop writes to target/debug/logs/ when --debug is set
        # (they survive inside the container; collect best-effort).
        docker_exec(
            container_id,
            "cp -r target/debug/logs ./audit/loop_debug_logs 2>/dev/null || true",
            30,
        )

        # Grade-side artifact collection (same helper as other agents)
        collect_audit_artifacts(container_id, work_dir, instance_outdir)

        return 0 if agent_exit == 0 else 1
    finally:
        subprocess.run(
            ["docker", "rm", "-f", container_name],
            capture_output=True,
        )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run SEC-bench Pro with the loop agent.",
    )
    parser.add_argument("config", type=Path, help="TOML configuration file")
    parser.add_argument(
        "--no-tui", action="store_true",
        help="Disable the ratatui-style progress display",
    )
    args = parser.parse_args()

    if not args.config.is_file():
        error(f"Config not found: {args.config}")
        return 2

    try:
        config = load_config(args.config)
    except Exception as exc:
        error(f"Invalid config: {exc}")
        return 2

    # Required
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
        SCRIPT_DIR, str(config.get("outdir", "output/loop")),
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

    info(f"Harness: loop/{config['model']}")
    info(f"Output:  {run_outdir}")
    info(f"Instances: {' '.join(instances)}")

    return run_eval_loop(
        instances=instances,
        images_dir=images_dir,
        run_outdir=run_outdir,
        prompt_template_path=prompt_template_path,
        config=config,
        agent_label=f"loop/{config['model']}",
        run_instance_fn=run_instance,
        use_tui=not args.no_tui,
        agents_md=agents_md,
    )


if __name__ == "__main__":
    sys.exit(main())
