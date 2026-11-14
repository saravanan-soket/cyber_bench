#!/usr/bin/env python3
"""dataset-bootstrap.py — one-shot init for bugs/<id>/ contexts.

Runs env-builder/bootstrap_v8.py for every target in TARGETS with pinned
commits / depot_tools / eval flags. Parallel, per-bug logs, aggregate report
at end, nonzero exit iff any failed.

Fast-fails if bugs/ already exists and is non-empty (unless --only is set,
which only touches one bug's directory). To re-bootstrap the full dataset,
explicitly:  rm -rf bugs/ && ./dataset-bootstrap.py

Env (still respected as fallback):
    CONCURRENCY   parallel bootstrap workers (default 4); -j/--jobs overrides
    LOG_DIR       per-bug log directory (default: mktemp); --log-dir overrides
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
import json
import os
import subprocess
import sys
import tempfile
import time


@dataclass(frozen=True)
class Target:
    bug_id: str         # bugs/<bug_id>/ directory name
    crbug: str          # Chromium Issue Tracker ID
    cve: str            # "CVE-YYYY-ZZZZ" or "CVE-UNKNOWN"
    last_patch: str     # full SHA for --commit
    depot_tools: str    # full SHA for --depot-tools-commit
    eval_flags: tuple[str, ...]


DEPOT_TOOLS_COMMIT = "364ccfdd5f1346dc973b66ab5f088a4ec88ca8c6"

# Pinned knobs for every bug in the dataset.
TARGETS: tuple[Target, ...] = (
    # V8 Exploit Tracker, excluding non-x64 bugs or embedder-dependent bugs
    Target("CVE-2023-6702", "1501326",   "CVE-2023-6702",  "bde3d360097607f36cd1d17cbe8412b84eae0a7f", DEPOT_TOOLS_COMMIT, ()),
    Target("CVE-2024-0517", "1515930",   "CVE-2024-0517",  "78dd4b31847ab1f5b06ef3d8742a9f3835fb6919", DEPOT_TOOLS_COMMIT, ()),
    Target("CVE-2024-0519", "1517354",   "CVE-2024-0519",  "389ea9be7d68bb189e16da79f6414edbd4f7594f", DEPOT_TOOLS_COMMIT, ()),
    Target("CVE-2024-10230","371565065", "CVE-2024-10230", "eb7b54834daeda95e4c3f11b3fdea027c6e8d4ae", DEPOT_TOOLS_COMMIT, ()),
    Target("CVE-2024-10231","372269618", "CVE-2024-10231", "160612a75397f9048e3824d5177ed702742f22ff", DEPOT_TOOLS_COMMIT, ("--turboshaft-wasm",)),
    Target("CVE-2024-12053","379009132", "CVE-2024-12053", "20d9a7f760c018183c836283017a321638b66810", DEPOT_TOOLS_COMMIT, ()),
    Target("CVE-2024-1939", "323694592", "CVE-2024-1939",  "fbd00f2178c1a437fd1362dab39c0144ea6b1b08", DEPOT_TOOLS_COMMIT, ()),
    Target("CVE-2024-2887", "330575498", "CVE-2024-2887",  "7058e46284d281e18725ece23fe8d94e8ec8bec7", DEPOT_TOOLS_COMMIT, ()),
    Target("CVE-2024-3159", "330760873", "CVE-2024-3159",  "807cf7d0b7d96212c98ed2119e07f9b2c6a23f61", DEPOT_TOOLS_COMMIT, ()),
    Target("CVE-2024-4761", "339458194", "CVE-2024-4761",  "f320600cd1f48ba6bb57c0395823fe0c5e5ec52e", DEPOT_TOOLS_COMMIT, ()),
    Target("CVE-2024-4947", "340221135", "CVE-2024-4947",  "b3c01ac1e60afc9addad9942f7a9a6c5e8a4a6da", DEPOT_TOOLS_COMMIT, ()),
    Target("CVE-2024-5274", "341663589", "CVE-2024-5274",  "3e037e195e508dea045f5626862412e8f64fc919", DEPOT_TOOLS_COMMIT, ()),
    Target("CVE-2024-6100", "344608204", "CVE-2024-6100",  "422cdc5eddcadb53b8eafb099722fb211a35739e", DEPOT_TOOLS_COMMIT, ()),
    Target("CVE-2024-7965", "356196918", "CVE-2024-7965",  "780d5608bb8ab63a3cd4b5c4846a3ec41e21c1a8", DEPOT_TOOLS_COMMIT, ()),
    Target("CVE-2024-7971", "360700873", "CVE-2024-7971",  "97975764885482e92e53f65352446b5c4ea68f20", DEPOT_TOOLS_COMMIT, ()),
    Target("CVE-2024-8194", "360533914", "CVE-2024-8194",  "79f3f1276efa17a6172a0923dd13436ad8337a86", DEPOT_TOOLS_COMMIT, ()),
    Target("CVE-2024-9122", "365802567", "CVE-2024-9122",  "f612d9a40b194cc7fc1d9cffdd295a78fa2f10c9", DEPOT_TOOLS_COMMIT, ()),
    Target("CVE-2024-9602", "368241697", "CVE-2024-9602",  "9542895cdd3dbd97da3d9032ddb36fd4feb612e4", DEPOT_TOOLS_COMMIT, ("--wasm-test-streaming", "--wasm_max_module_size=1500000000")),
    Target("CVE-2024-9859", "346197738", "CVE-2024-9859",  "89dc6eab605cde2ffaa92dd9acf461caa63478de", DEPOT_TOOLS_COMMIT, ()),
    Target("CVE-2025-0291", "383356864", "CVE-2025-0291",  "c84e01e92bfd61d29541c59e378b9a15ba6fc891", DEPOT_TOOLS_COMMIT, ()),
    Target("CVE-2025-0995", "391907159", "CVE-2025-0995",  "33ca4f51e5dbba9817eba16fd3249e66a880cf33", DEPOT_TOOLS_COMMIT, ()),
    # Target("CVE-2025-10585","445380761", "CVE-2025-10585", "4fce2e4c38d7e358c4cd6f947b4d080d215d6cab", DEPOT_TOOLS_COMMIT, ()),
    Target("CVE-2025-10891","443765373", "CVE-2025-10891", "a5f18bb86c3b97b9bfc8f95a0926812a1282ad7c", DEPOT_TOOLS_COMMIT, ()),
    Target("CVE-2025-12727","454485895", "CVE-2025-12727", "af7644b2de8ca3ccc4069b637b550d076caf4b38", DEPOT_TOOLS_COMMIT, ()),
    Target("CVE-2025-13223","460017370", "CVE-2025-13223", "4cf9311810b0561ee8b532a694526c7904e18367", DEPOT_TOOLS_COMMIT, ()),
    Target("CVE-2025-13226","446113732", "CVE-2025-13226", "48c3551179299151b044b2c161566465497c0407", DEPOT_TOOLS_COMMIT, ("--experimental-wasm-custom-descriptors",)),
    Target("CVE-2025-1920", "398065918", "CVE-2025-1920",  "7c3ccfc4429cb9fefe586a5359a12ebcbb101dd7", DEPOT_TOOLS_COMMIT, ()),
    Target("CVE-2025-2135", "400052777", "CVE-2025-2135",  "8b490a9690b859346a68a3d2a7008b4e1852c3ea", DEPOT_TOOLS_COMMIT, ()),
    Target("CVE-2025-5419", "420636529", "CVE-2025-5419",  "7bc0a67ebfbf44e7adab47fc2bbbe308660e27f4", DEPOT_TOOLS_COMMIT, ()),
    Target("CVE-2025-5959", "422313191", "CVE-2025-5959",  "a970eed8995bb1b2cd083c3c79cdefc79e84f8b7", DEPOT_TOOLS_COMMIT, ()),
    Target("CVE-2025-6554", "427663123", "CVE-2025-6554",  "c17ee553a8b9c096351810ac43920a22c72c7df9", DEPOT_TOOLS_COMMIT, ()),
    Target("CVE-2025-8010", "430344952", "CVE-2025-8010",  "328f6c467b940f322544567740c9c871064d045c", DEPOT_TOOLS_COMMIT, ()),
    Target("CVE-2025-9132", "436181695", "CVE-2025-9132",  "848d7f4122826f4d26ee09404fe57ac9b9295b00", DEPOT_TOOLS_COMMIT, ()),
    Target("CVE-2026-2649", "481074858", "CVE-2026-2649",  "04d57e1a869ae90d812cc66eb5946b42069558e8", DEPOT_TOOLS_COMMIT, ()),
    Target("CVE-2026-3910", "491410818", "CVE-2026-3910",  "acf4c8ead045710baa3528efe7a261b1ba77edbb", DEPOT_TOOLS_COMMIT, ()),
    Target("CVE-2026-4447", "486657483", "CVE-2026-4447",  "bf136adcbb927aeec4548865c600d5498932e979", DEPOT_TOOLS_COMMIT, ()),
    Target("crbug-1509576", "1509576",   "CVE-UNKNOWN",    "4a664b390577de3d3572010da0dc1138d78ab2c4", DEPOT_TOOLS_COMMIT, ()),
    Target("crbug-339064932", "339064932", "CVE-UNKNOWN",    "11f8ae2875307189937a1a67b419cda1d69c272a", DEPOT_TOOLS_COMMIT, ()),
    Target("crbug-339736513", "339736513", "CVE-UNKNOWN",    "8a69c7880844ab00ee2f32079579a040a87eedca", DEPOT_TOOLS_COMMIT, ()),
    Target("crbug-378779897", "378779897", "CVE-UNKNOWN",    "57a017e611a5abfb0e4b59f6de028bc4070a3615", DEPOT_TOOLS_COMMIT, ()),
    Target("crbug-386565144", "386565144", "CVE-UNKNOWN",    "816e71cc160c897ed18548a4584a306f054a9a38", DEPOT_TOOLS_COMMIT, ()),
    Target("crbug-403364367", "403364367", "CVE-UNKNOWN",    "22ac8acf3508ff99e17323383a1b0182d21a8ce7", DEPOT_TOOLS_COMMIT, ()),
)


ROOT = Path(__file__).resolve().parent
BUGS = ROOT / "bugs"
REPRO = ROOT / "repro"
BOOTSTRAP = ROOT / "env-builder" / "bootstrap_v8.py"


def build_argv(t: Target) -> list[str]:
    # Absolute path so we can pin cwd=env-builder/ — v8bug needs that for
    # its CWD-relative fs reads (chrome-cve-db.json.lock).
    argv = [sys.executable, str(BOOTSTRAP),
            "--force", "--log-level", "INFO",
            "--depot-tools-commit", t.depot_tools]
    for f in t.eval_flags:
        # `=`-form binds the value even when it starts with `--`, avoiding
        # argparse mis-parsing (e.g. --eval-flag --turboshaft-wasm).
        argv += [f"--eval-flag={f}"]
    # Always pass --pair, including the literal "CVE-UNKNOWN" sentinel —
    # bootstrap_v8.py recognizes it and skips crbug2cve (NVD pagination)
    # and cve2desc (MITRE lookup), which are pure waste when we already
    # know there is no CVE.
    argv += ["bug", f"b/{t.crbug}", "--commit", t.last_patch, "--pair", t.cve]
    return argv


def bootstrap_one(t: Target, log_dir: Path, max_retries: int, backoff_base: float) -> tuple[Target, int, Path]:
    log = log_dir / f"{t.bug_id}.log"
    argv = build_argv(t)
    rc = 0
    with log.open("w") as lf:
        lf.write(f"[+] {t.bug_id}: {' '.join(argv)}\n")
        for attempt in range(1, max_retries + 2):  # initial try + max_retries retries
            lf.write(f"[+] attempt {attempt}/{max_retries + 1} started {time.strftime('%Y-%m-%dT%H:%M:%S%z')}\n")
            lf.flush()
            rc = subprocess.call(argv, stdout=lf, stderr=subprocess.STDOUT, cwd=BOOTSTRAP.parent)
            lf.write(f"[+] attempt {attempt} finished rc={rc} at {time.strftime('%Y-%m-%dT%H:%M:%S%z')}\n")
            if rc == 0 or attempt > max_retries:
                break
            delay = backoff_base * (2 ** (attempt - 1))
            lf.write(f"[+] retrying in {delay:.1f}s\n")
            lf.flush()
            print(f"[RETRY] {t.bug_id} attempt {attempt}/{max_retries + 1} failed rc={rc}, "
                  f"sleeping {delay:.1f}s before attempt {attempt + 1}",
                  file=sys.stderr, flush=True)
            time.sleep(delay)
    return t, rc, log


def repro_crosscheck() -> None:
    if not REPRO.is_dir():
        print("repro/: not present; skipping cross-check")
        return

    repro = set(os.listdir(REPRO))
    skip_crbugs: set[str] = set()
    for r in repro:
        parts = r.split("-")
        if parts[-1] == "skip":
            for p in parts[:-1]:
                if p.isdigit():
                    skip_crbugs.add(p)

    bugs_crbugs: dict[str, str] = {}
    for d in sorted(os.listdir(BUGS)):
        tj = BUGS / d / "task.json"
        if tj.is_file():
            bugs_crbugs[d] = json.loads(tj.read_text())["crbug"]

    leaked = [(b, c) for b, c in bugs_crbugs.items() if c in skip_crbugs]
    if leaked:
        print("WARN: bugs/ contains entries whose crbug is tagged -skip in repro/:")
        for b, c in leaked:
            print(f"    {b} (crbug {c})")

    def match(crbug: str) -> str | None:
        for r in repro:
            parts = r.split("-")
            if parts[-1] == "skip":
                continue
            if crbug in parts:
                return r
        return None

    unmatched = [(b, c) for b, c in bugs_crbugs.items() if match(c) is None]
    matched = len(bugs_crbugs) - len(unmatched)
    print(f"repro/: {matched}/{len(bugs_crbugs)} bugs have a matching repro/ dir")
    if unmatched:
        print("  no repro/ match for:")
        for b, c in unmatched:
            print(f"    {b} (crbug {c})")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Bootstrap bug Dockerfiles. Default: all targets in parallel. "
                    "Use --only <BUG_ID> to bootstrap a single bug (for external parallelization).",
    )
    p.add_argument(
        "--only", metavar="BUG_ID",
        help="Bootstrap only this bug (case-insensitive match against TARGETS). "
             "Skips the bugs/-non-empty guard and the repro/ cross-check.",
    )
    p.add_argument(
        "-j", "--jobs", type=int, default=None,
        help=f"Parallel bootstrap workers (default: $CONCURRENCY env or 4). Ignored with --only.",
    )
    p.add_argument(
        "--log-dir", type=Path, default=None,
        help="Per-bug log directory (default: $LOG_DIR env or mktemp).",
    )
    p.add_argument(
        "--max-retries", type=int, default=3,
        help="Retries on bootstrap failure, with exponential backoff (default: 3).",
    )
    p.add_argument(
        "--backoff-base", type=float, default=5.0,
        help="Initial backoff delay in seconds; doubles each retry (default: 5).",
    )
    return p.parse_args()


def filter_targets(only: str | None) -> tuple[Target, ...]:
    if only is None:
        return TARGETS
    needle = only.lower()
    matches = tuple(t for t in TARGETS if t.bug_id.lower() == needle)
    if not matches:
        valid = ", ".join(t.bug_id for t in TARGETS)
        print(f"error: --only {only!r} not in TARGETS. Known: {valid}", file=sys.stderr)
        sys.exit(2)
    return matches


def preflight() -> None:
    """Surface common setup errors before forking 41 subprocesses that all
    fail identically. Without this, the user waits ~35s through the retry
    loop and then has to dig into a /tmp log to find out what went wrong.
    """
    errors: list[str] = []

    missing = []
    for mod in ("aiofiles", "aiohttp"):
        try:
            __import__(mod)
        except ImportError:
            missing.append(mod)
    if missing:
        errors.append(
            f"missing python deps: {', '.join(missing)}\n"
            f"  install with:  pip install -r requirements.txt"
        )

    mcp_server = ROOT / "mcp-server" / "server"
    if not mcp_server.is_file():
        errors.append(
            f"mcp-server binary not found at {mcp_server}\n"
            f"  build it with:  cd mcp-server && make build"
        )

    if errors:
        for e in errors:
            print(f"error: {e}", file=sys.stderr)
        sys.exit(2)


def main() -> int:
    args = parse_args()
    preflight()
    targets = filter_targets(args.only)

    if args.only is None and BUGS.exists() and any(BUGS.iterdir()):
        print(f"error: {BUGS} exists and is non-empty. Refusing to overwrite.", file=sys.stderr)
        print(f"       To re-bootstrap, explicitly:  rm -rf {BUGS} && {sys.argv[0]}", file=sys.stderr)
        print(f"       To bootstrap a single bug:   {sys.argv[0]} --only <BUG_ID>", file=sys.stderr)
        return 1
    if not BOOTSTRAP.is_file():
        print(f"error: {BOOTSTRAP} not found", file=sys.stderr)
        return 1
    BUGS.mkdir(exist_ok=True)

    log_dir = args.log_dir or Path(os.environ.get("LOG_DIR") or tempfile.mkdtemp(prefix="bench-v8-bootstrap-"))
    log_dir.mkdir(parents=True, exist_ok=True)
    concurrency = args.jobs if args.jobs is not None else int(os.environ.get("CONCURRENCY", "4"))
    if args.only is not None:
        concurrency = 1  # external parallelism drives multiple --only invocations
    print(f"logs: {log_dir}")
    print(f"concurrency: {concurrency}")
    print(f"targets: {len(targets)}" + (f" (--only {args.only})" if args.only else ""))

    results: list[tuple[Target, int, Path]] = []
    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        futures = {ex.submit(bootstrap_one, t, log_dir, args.max_retries, args.backoff_base): t for t in targets}
        for fut in as_completed(futures):
            t, rc, log = fut.result()
            tag = "PASS" if rc == 0 else "FAIL"
            print(f"[{tag}] {t.bug_id}" + (f"  rc={rc}  log={log}" if rc else ""),
                  file=sys.stderr if rc else sys.stdout)
            results.append((t, rc, log))

    (log_dir / "results.txt").write_text(
        "".join(f"{'PASS' if rc == 0 else 'FAIL'} {t.bug_id} rc={rc} log={log}\n"
                for t, rc, log in results)
    )

    passed = sum(1 for _, rc, _ in results if rc == 0)
    failed = sum(1 for _, rc, _ in results if rc != 0)
    print()
    print(f"summary: {passed} passed, {failed} failed, {len(targets)} total")
    if failed:
        print("failed bugs:")
        for t, rc, log in results:
            if rc:
                print(f"  {t.bug_id}  rc={rc}  {log}")
                # Surface the last few log lines so the user sees the actual
                # error without having to open the log file separately.
                try:
                    tail = log.read_text().splitlines()[-15:]
                    for line in tail:
                        print(f"    | {line}")
                except OSError:
                    pass

    if args.only is None:
        print()
        repro_crosscheck()

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
