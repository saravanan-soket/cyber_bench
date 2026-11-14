#!/usr/bin/env python3
"""build_bugs.py — build a single bug's Docker image from bugs/<id>/.

Default (artifact mode): two-stage build (base + agent), SOURCE_DATE_EPOCH
pinned for reproducibility, exports image to db/<bug>.tar.zst.
--dev: single-stage non-reproducible build, tag <bug>-dev, no export.

For external parallelization:
  parallel -j 4 --linebuffer --tag ./build_bugs.py {} :::: bugs.txt
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BUGS = ROOT / "bugs"
DB = ROOT / "db"
LOG_DIR = ROOT / "build-logs"
GITCOOKIES = Path.home() / ".gitcookies"


def find_bug_dir(bug_id: str) -> Path:
    """Resolve bug id to a directory under bugs/, case-insensitive."""
    direct = BUGS / bug_id
    if direct.is_dir():
        return direct
    target = bug_id.lower()
    for entry in BUGS.iterdir():
        if entry.is_dir() and entry.name.lower() == target:
            return entry
    raise SystemExit(f"error: bugs/{bug_id} (or any case variant) not found")


def read_sde(bug_dir: Path) -> str:
    """Read source_date_epoch from task.json. Refuse if missing/null."""
    task_path = bug_dir / "task.json"
    if not task_path.is_file():
        raise SystemExit(f"error: {task_path} not found")
    sde = json.loads(task_path.read_text()).get("source_date_epoch")
    if sde is None or sde == "":
        raise SystemExit(
            f"error: source_date_epoch missing in {task_path}; refuse to build "
            "non-reproducibly. Re-run dataset-bootstrap.py for this bug."
        )
    return str(sde)


def human_gb(b: int) -> str:
    return f"{b / 1024**3:.1f}GB"


def image_size(tag: str) -> int:
    try:
        out = subprocess.run(
            ["docker", "image", "inspect", tag, "--format", "{{.Size}}"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
        return int(out)
    except (subprocess.CalledProcessError, ValueError):
        return 0


def run_build(cmd: list[str], log_path: Path) -> int:
    """Run docker build, teeing output to log_path AND stderr. Returns rc."""
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("wb") as logf:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0)
        assert proc.stdout is not None
        for chunk in iter(lambda: proc.stdout.read(4096), b""):
            sys.stderr.buffer.write(chunk)
            sys.stderr.buffer.flush()
            logf.write(chunk)
        return proc.wait()


def fail_with_tail(stage: str, image_tag: str, log_path: Path, lines: int = 50) -> None:
    print(f"FAIL {image_tag} stage={stage}", file=sys.stderr)
    if log_path.is_file():
        tail = log_path.read_bytes().splitlines()[-lines:]
        sys.stderr.buffer.write(f"--- last {lines} lines of {log_path} ---\n".encode())
        for ln in tail:
            sys.stderr.buffer.write(ln + b"\n")


def export_image(tag: str, dest: Path) -> bool:
    """docker save <tag> | zstd -T0 > dest."""
    if shutil.which("zstd") is None:
        print("error: zstd not found in PATH; cannot export. Install zstd or use --no-export.",
              file=sys.stderr)
        return False
    dest.parent.mkdir(parents=True, exist_ok=True)
    save = subprocess.Popen(["docker", "save", tag], stdout=subprocess.PIPE)
    with dest.open("wb") as out:
        zstd = subprocess.Popen(["zstd", "-T0", "-q"], stdin=save.stdout, stdout=out)
        assert save.stdout is not None
        save.stdout.close()
        zstd.wait()
    save.wait()
    return save.returncode == 0 and zstd.returncode == 0


def common_build_args(no_cache: bool, sde: str | None) -> list[str]:
    args: list[str] = []
    if sde is not None:
        args += ["--build-arg", f"SOURCE_DATE_EPOCH={sde}"]
    if no_cache:
        args.append("--no-cache")
    if GITCOOKIES.is_file():
        args += ["--secret", f"id=gitcookies,src={GITCOOKIES}"]
    return args


def build_artifact(bug_dir: Path, image_tag: str, sde: str, no_cache: bool, no_export: bool) -> int:
    base_tag = f"{image_tag}-base"
    base_log = LOG_DIR / f"build-{image_tag}-base.log"
    agent_log = LOG_DIR / f"build-{image_tag}.log"
    args = common_build_args(no_cache, sde)
    t0 = time.monotonic()

    print(f"[build_bug] {image_tag}: stage 1/2 (base) -> {base_tag}", file=sys.stderr)
    rc = run_build(["docker", "build", *args, "--target=base", "-t", base_tag, str(bug_dir)], base_log)
    if rc != 0:
        fail_with_tail("base", image_tag, base_log)
        return 1

    # --build-context substitutes the `FROM ... AS base` stage with the
    # just-built image, dropping the base RUN ops out of the build graph
    # entirely. --cache-from would still re-evaluate them and a cache-key
    # mismatch could force a 60-minute rebuild.
    print(f"[build_bug] {image_tag}: stage 2/2 (agent) -> {image_tag}", file=sys.stderr)
    rc = run_build([
        "docker", "build", *args,
        "--build-context", f"base=docker-image://{base_tag}",
        "-t", image_tag, str(bug_dir),
    ], agent_log)
    if rc != 0:
        fail_with_tail("agent", image_tag, agent_log)
        return 1

    elapsed = int(time.monotonic() - t0)
    base_gb = human_gb(image_size(base_tag))
    agent_gb = human_gb(image_size(image_tag))

    if not no_export:
        export_path = DB / f"{image_tag}.tar.zst"
        print(f"[build_bug] {image_tag}: exporting to {export_path}", file=sys.stderr)
        if not export_image(image_tag, export_path):
            print(f"FAIL {image_tag} stage=export", file=sys.stderr)
            return 1

    print(f"PASS {image_tag} ({elapsed}s, base={base_gb} agent={agent_gb})")
    return 0


def build_dev(bug_dir: Path, image_tag: str, no_cache: bool) -> int:
    dev_tag = f"{image_tag}-dev"
    dev_log = LOG_DIR / f"build-{dev_tag}.log"
    args = common_build_args(no_cache, sde=None)
    t0 = time.monotonic()

    print(f"[build_bug] {image_tag}: dev build -> {dev_tag}", file=sys.stderr)
    rc = run_build(["docker", "build", *args, "-t", dev_tag, str(bug_dir)], dev_log)
    if rc != 0:
        fail_with_tail("dev", image_tag, dev_log)
        return 1

    elapsed = int(time.monotonic() - t0)
    dev_gb = human_gb(image_size(dev_tag))
    print(f"PASS {dev_tag} ({elapsed}s, {dev_gb})")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(
        description="Build a single bug's Docker image. Reads bugs/<BUG_ID>/Dockerfile + task.json.",
    )
    p.add_argument("bug_id", metavar="BUG_ID", help="Bug directory name under bugs/ (case-insensitive).")
    p.add_argument("--dev", action="store_true",
                   help="Single-stage non-reproducible build for fast iteration. Tag <bug>-dev. No export.")
    p.add_argument("--no-export", action="store_true",
                   help="Skip writing db/<bug>.tar.zst (artifact mode only).")
    p.add_argument("--no-cache", action="store_true",
                   help="Pass --no-cache to docker build.")
    args = p.parse_args()

    bug_dir = find_bug_dir(args.bug_id)
    image_tag = bug_dir.name.lower()

    if args.dev:
        return build_dev(bug_dir, image_tag, args.no_cache)
    return build_artifact(bug_dir, image_tag, read_sde(bug_dir), args.no_cache, args.no_export)


if __name__ == "__main__":
    sys.exit(main())
