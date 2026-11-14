#!/usr/bin/env python3

from datetime import datetime, timezone
from pathlib import Path
from string import Template
import argparse
import asyncio
import hashlib
import itertools
import json
import logging
import shutil
import tempfile
import zipfile
import v8bug
import capabilities
from patch_locations import extract_patch_locations

# TODO: properly package stuff into structured module
import sys
# directory where this python file resides in
THIS_DIR = Path(__file__).absolute().parent
sys.path.append(str(THIS_DIR.parent))

BENCH_V8_VERSION = '0.1.0'
UNKNOWN_CVE_ID = 'CVE-UNKNOWN'

# Default pwndbg release URL
PWNDBG_URL = 'https://github.com/pwndbg/pwndbg/releases/download/2024.08.29/pwndbg_2024.08.29_amd64.deb'

# Path to pre-built MCP server binary (relative to repo root)
MCP_SERVER_BIN = THIS_DIR.parent / 'mcp-server' / 'server'

# V8 grader builtins (patch + source files)
V8_GRADER_BUILTINS_DIR = THIS_DIR / 'v8_grader_builtins'

# Prompt template directory
PROMPT_TEMPLATE_DIR = THIS_DIR.parent / 'prompt-template'


def setup_custom_logger(name, loglevel=logging.INFO):
    logger = logging.getLogger(name)
    logger.setLevel(loglevel)

    formatter = logging.Formatter(
        fmt="[%(name)s] %(asctime)s %(levelname)-8s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S %Z",
    )

    screen_handler = logging.StreamHandler(stream=sys.stdout)
    screen_handler.setFormatter(formatter)
    logger.addHandler(screen_handler)

    return logger


def get_log_level(level_str):
    level_map = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR,
        "CRITICAL": logging.CRITICAL,
    }
    return level_map[level_str.upper()]


log = setup_custom_logger("v8/bootstrap")


def render_template(template_path: Path, variables: dict[str, str]) -> str:
    """Render a Dockerfile template by replacing ${VARIABLE} placeholders.

    Uses simple string replacement to avoid conflicts with Docker's own
    $VARIABLE syntax (which uses no braces or different variable names).
    """
    content = template_path.read_text()
    for key, value in variables.items():
        content = content.replace(f'${{{key}}}', str(value))
    return content


def render_prompt(target: str, bug_id: str, bug_desc: str, patch_diff: str, available_caps: set[str]) -> str:
    """Render the prompt for a target, including only the `available_caps`
    in the capability tables. Caps that can't be graded for this bug (e.g.
    coverage when patch_locations is empty) are simply absent from the
    prompt — the agent is never told about a capability it can't achieve.
    """
    template_path = PROMPT_TEMPLATE_DIR / f'{target}.template'
    template = template_path.read_text()
    return template.format(
        bug_id=bug_id,
        bug_desc=bug_desc,
        patch_diff=patch_diff,
        capabilities_section=capabilities.render_section(available_caps),
    )


def generate_problem_dir(task_path: Path, bug_id: str, target: str, bug_desc: str, patch_diff: str, eval_flags: list[str], patch_locations: list[dict], available_caps: set[str], task_prefix: str):
    """Generate the problem/ directory with id, prompt, types, and patch
    locations files. `available_caps` is the pre-computed per-bug cap set
    used for both prompt rendering and problem_types emission.
    `task_prefix` is "1day" or "0day" — prepended to each cap name in
    problem/types."""
    problem_dir = task_path / 'problem'
    problem_dir.mkdir(parents=True, exist_ok=True)
    (problem_dir / 'id').write_text(bug_id)
    (problem_dir / 'prompt').write_text(render_prompt(target, bug_id, bug_desc, patch_diff, available_caps))
    (problem_dir / 'types').write_text(json.dumps(capabilities.problem_types(available_caps, task_prefix)))
    (problem_dir / 'eval_flags.json').write_text(json.dumps(eval_flags))
    (problem_dir / 'patch_locations.json').write_text(json.dumps(patch_locations, indent=2))


def copy_mcp_server(task_path: Path):
    """Copy the pre-built MCP server binary into the bug directory."""
    if not MCP_SERVER_BIN.is_file():
        raise FileNotFoundError(
            f'MCP server binary not found at {MCP_SERVER_BIN}. '
            f'Build it first: cd mcp-server && make build'
        )
    dst = task_path / 'mcp-server'
    shutil.copy2(MCP_SERVER_BIN, dst)
    dst.chmod(0o755)


def copy_grader_builtins(task_path: Path):
    """Copy V8 grader builtins into the bug directory.

    Only copies the three files the Dockerfile actually consumes — the
    rest of env-builder/v8_grader_builtins/ (README.md, etc.) is
    maintainer documentation and shouldn't be duplicated into per-bug
    build contexts.
    """
    if not V8_GRADER_BUILTINS_DIR.is_dir():
        log.warning(f'v8_grader_builtins not found at {V8_GRADER_BUILTINS_DIR}, skipping.')
        return
    dst = task_path / 'v8_grader_builtins'
    if dst.exists():
        shutil.rmtree(dst)
    dst.mkdir(parents=True)
    for name in ('d8-grader.h', 'd8-grader.cc', 'apply_grader_integration.py'):
        shutil.copy2(V8_GRADER_BUILTINS_DIR / name, dst / name)


async def resolve_depot_tools_commit() -> str:
    """Get the current HEAD commit of depot_tools."""
    import aiohttp
    url = 'https://chromium.googlesource.com/chromium/tools/depot_tools/+/refs/heads/main?format=JSON'
    async with v8bug.make_session() as session:
        async with session.get(url) as res:
            text = await res.text()
            data = json.loads(text[5:])  # skip XSSI prefix
            return data['commit']


async def bootstrap_bug(cve_id: str, crbug_id: str, force: bool, depot_tools_commit: str | None = None, eval_flags: list[str] | None = None, commit_sha: str | None = None, out_dir = THIS_DIR / '../bugs'):
    eval_flags = list(eval_flags or [])
    log.debug(f'[*] bootstrap_bug({cve_id}, b/{crbug_id})')
    cve_desc = (await v8bug.cve2desc(cve_id)) if cve_id != UNKNOWN_CVE_ID else 'N/A'
    commits = await v8bug.crbug2commits(crbug_id)
    # Upstream commits occasionally miss their `Bug:` footer, so Gerrit's
    # bug:<id> search returns nothing. Tolerate that when the caller pinned
    # --commit: trust it as the sole patch commit and skip the search.
    if not commits and commit_sha is not None:
        log.warning(f'[*] crbug2commits(b/{crbug_id}) returned empty; '
                    f'treating --commit {commit_sha} as the sole patch commit')
        commits = [commit_sha]
    patches, crevs = await asyncio.gather(
        asyncio.gather(*map(v8bug.commit2patch, commits)),
        asyncio.gather(*map(v8bug.commit2crev, commits))
    )
    cpcs = list(zip(commits, patches, crevs))
    if commit_sha is not None:
        matches = [i for i, c in enumerate(commits) if c == commit_sha]
        if not matches:
            raise ValueError(f'--commit {commit_sha} not found in crbug2commits(b/{crbug_id}); got {commits}')
        idx = matches[0]
    elif len(commits) > 1:
        print(f'[!] Multiple commits found for b/{crbug_id} ({cve_id}). Select the index for the last patch commit. Commits are in ascending order.')
        for i, (commit, patch, crev) in enumerate(cpcs):
            print(f'[{i}] {commit} (@{crev}): {patch.splitlines()[3]}')
        idx = int(input('> '))
    else:
        idx = 0
    commit, patch, crev = cpcs[idx]

    log.debug(f'[*] Using last patch {commit} (@{crev}): {patch.splitlines()[3]}')

    tgt_commit = await v8bug.commit2parent(commits[0])  # parent of first patch commit
    tgt_crev = crevs[0] - 1     # revision just before first patch commit, matches tgt_commit
    assert tgt_crev == await v8bug.commit2crev(tgt_commit), f'Revision invariant failure: target commit {tgt_commit} does not match expected revision {tgt_crev}'
    fix_crev = crev             # revision at last patch commit
    assert tgt_crev < fix_crev, f'Revision invariant failure: target revision {tgt_crev} is not smaller than fixed revision {fix_crev}'

    target = 'v8'
    variants = ('debug', 'debug-asan', 'release', 'release-asan', 'coverage')

    # Get fix commit date and depot_tools commit for reproducibility
    async def _depot_tools():
        return depot_tools_commit or await resolve_depot_tools_commit()

    fix_date_epoch, depot_tools_commit = await asyncio.gather(
        v8bug.commit2date(commit),
        _depot_tools(),
    )
    fix_date_str = datetime.fromtimestamp(fix_date_epoch, tz=timezone.utc).isoformat()

    log.debug(f'[*] Fix commit date: {fix_date_str} (epoch {fix_date_epoch})')
    log.debug(f'[*] depot_tools commit: {depot_tools_commit}')

    # Build template variables. Both vuln and fixed are source-built.
    template_vars = {
        'BUG_ID': cve_id if cve_id != UNKNOWN_CVE_ID else f'crbug-{crbug_id}',
        'TARGET_COMMIT': tgt_commit,
        'PATCH_COMMIT': commit,
        'VULN_REV': str(tgt_crev),
        'FIXED_REV': str(fix_crev),
        'FIX_COMMIT_DATE': fix_date_str,
        'SOURCE_DATE_EPOCH': str(fix_date_epoch),
        'DEPOT_TOOLS_COMMIT': depot_tools_commit,
        'PWNDBG_URL': PWNDBG_URL,
    }

    # Render Dockerfile from template
    template_path = THIS_DIR / f'{target}/Dockerfile.template'
    dockerfile_content = render_template(template_path, template_vars)

    # Write output to bugs/<bug_id>/
    bug_id = cve_id if cve_id != UNKNOWN_CVE_ID else f'crbug-{crbug_id}'
    bug_desc = f'V8 commit vulnerable to the bug: {tgt_commit}\nCVE description: {cve_desc}\n'
    patch_diff = '\n'.join(patch for patch in patches[:idx+1])

    # Compute the per-bug gradable capability set up-front. Feeds both the
    # prompt (what the agent sees as targets) and problem/types (what gets
    # scored).  Starts from the target's default set, then prunes caps that
    # can't be measured for this specific patch.
    patch_locations = extract_patch_locations(patch_diff)
    available_caps = capabilities.prune_by_patch(
        capabilities.default_available(target), patch_locations,
    )
    dropped = capabilities.default_available(target) - available_caps
    if dropped:
        log.warning(f'[*] {bug_id}: dropping unreachable caps {sorted(dropped)}')

    task_path = out_dir / bug_id
    task_path.mkdir(parents=True, exist_ok=force)

    (task_path / 'Dockerfile').write_text(dockerfile_content)
    for f in (THIS_DIR / f'{target}/dev').glob('args.*.gn'):
        shutil.copy2(f, task_path / f.name)
    shutil.copy2(THIS_DIR / f'{target}/dev/v8.patch', task_path / 'v8.patch')

    # Generate problem definition files (task_prefix="1day" — this
    # bootstrapper handles 1day tasks where the patch is known).
    generate_problem_dir(task_path, bug_id, target, bug_desc, patch_diff, eval_flags, patch_locations, available_caps, task_prefix='1day')
    log.info(f'[*] Generated problem/ directory')

    # Copy MCP server binary and grading infrastructure
    copy_mcp_server(task_path)
    copy_grader_builtins(task_path)
    log.info(f'[*] Copied MCP server and grader builtins')

    log.info(f'[*] Generated Dockerfile at {task_path / "Dockerfile"}')
    log.info(f'[*] To build:     python build_bugs.py {bug_id}')
    log.info(f'[*] To dev-build: python build_bugs.py --dev {bug_id}')

    # Generate task.json. Image tag matches build_bugs.py and ECR push convention.
    dev_im_name = bug_id.lower()
    eval_im_name = dev_im_name

    all_variants = list(itertools.product((fix_crev, tgt_crev), variants))
    task_desc = {
        "version": BENCH_V8_VERSION,

        # these should exist in all tasks
        "target": target,
        "target_type": "bug",
        "bug_id": bug_id,
        "dev_image": dev_im_name,
        "eval_image": eval_im_name,
        "bug_desc": bug_desc,
        "patch_diff": patch_diff,

        # these should exist for v8 bug tasks
        "cve": cve_id,
        "cve_desc": cve_desc,
        "crbug": crbug_id,
        "related_patches": [
            {
                "commit": cpc[0],
                "patch": cpc[1],
                "crev": cpc[2],
            }
            for cpc in cpcs[:idx+1]
        ],
        "last_patch_commit": commit,

        # vuln version
        "tgt_commit": tgt_commit,
        "tgt_crev": tgt_crev,
        # fix version
        "fix_crev": fix_crev,

        # reproducibility
        "source_date_epoch": fix_date_epoch,
        "fix_commit_date": fix_date_str,
        "depot_tools_commit": depot_tools_commit,

        "builds": [
            {
                "vuln": crev == tgt_crev,
                "crev": crev,
                "target": target,
                "config": config,
                "source": "built",
                "path": f"/rlenv/binaries/{'vuln' if crev == tgt_crev else 'fixed'}/{config}/d8",
            }
            for (crev, config) in all_variants
        ],

        "problem_types": capabilities.problem_types(available_caps, '1day'),

        "eval_flags": eval_flags,
    }

    (task_path / 'task.json').write_text(json.dumps(task_desc, indent=2))
    log.info(f'[*] Generated task.json at {task_path / "task.json"}')


async def bootstrap_cve(cve_id: str, force = False, depot_tools_commit: str | None = None, eval_flags: list[str] | None = None, commit_sha: str | None = None):
    crbug_id = await v8bug.cve2crbug(cve_id)
    await bootstrap_bug(cve_id, crbug_id, force, depot_tools_commit, eval_flags, commit_sha)


async def bootstrap_crbug(crbug_id: str, force = False, depot_tools_commit: str | None = None, eval_flags: list[str] | None = None, commit_sha: str | None = None):
    try:
        cve_id = await v8bug.crbug2cve(crbug_id)
    except AssertionError as e:
        log.warning(f'Bug b/{crbug_id} does not have a uniquely identifiable CVE, inserting placeholder {UNKNOWN_CVE_ID}: {repr(e)}')
        cve_id = UNKNOWN_CVE_ID
    await bootstrap_bug(cve_id, crbug_id, force, depot_tools_commit, eval_flags, commit_sha)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="V8 target bootstrapper. Generates a standalone, reproducible Dockerfile per bug."
    )
    parser.add_argument(
        "--log-level",
        default="DEBUG",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Set the logging level",
    )
    parser.add_argument(
        "--force",
        help="Overwrite existing output directory",
        action='store_true',
    )
    parser.add_argument(
        "--depot-tools-commit",
        default=None,
        help="Pin depot_tools to a specific commit (default: resolve current HEAD). "
             "Pinning enables Docker layer caching across runs.",
    )
    parser.add_argument(
        "--eval-flag",
        action='append',
        default=None,
        metavar='FLAG',
        help="Extra flag passed to d8 during grading (e.g. --eval-flag=--experimental-wasm-custom-descriptors). "
             "Repeatable.",
    )

    subparsers = parser.add_subparsers(
        dest="target_type", required=True, help="Task target type"
    )

    bug_parser = subparsers.add_parser('bug', help='Bug exploit target')
    bug_parser.add_argument('bug_id', type=str, help='Bug ID ("CVE-YYYY-ZZZZ" or "b/crbug_id")')
    bug_parser.add_argument(
        '--pair',
        type=str,
        default=None,
        metavar='ID',
        help='Forcibly associate bug_id with this counterpart ID, skipping cve<->crbug inference. '
             'If bug_id is a CVE, pass the crbug ID here (e.g. "b/1234567" or "1234567"); '
             'if bug_id is a crbug, pass the CVE ID here (e.g. "CVE-2024-2887").',
    )
    bug_parser.add_argument(
        '--commit',
        type=str,
        default=None,
        metavar='SHA',
        help='Explicitly select the last-patch commit SHA instead of prompting. '
             'Fails if the SHA is not in the set returned by crbug2commits.',
    )

    patch_parser = subparsers.add_parser('patch', help='Patch exploit target')
    patch_parser.add_argument('patch_path', type=str, help='Path to patch file (compatible with `git am`)')
    patch_parser.add_argument('base_commit', type=str, help='Base commit to apply the patch to')

    async def main(args):
        if args.target_type == 'bug':
            bug_id = args.bug_id
            commit_sha = getattr(args, 'commit', None)
            if bug_id.startswith('CVE-'):
                if args.pair is not None:
                    crbug_id = args.pair.replace('b/', '').replace('crbug-', '')
                    await bootstrap_bug(bug_id, crbug_id, args.force, args.depot_tools_commit, args.eval_flag, commit_sha)
                else:
                    await bootstrap_cve(bug_id, args.force, args.depot_tools_commit, args.eval_flag, commit_sha)
            elif bug_id.startswith('b/') or bug_id.startswith('crbug-'):
                crbug_id = bug_id.replace('b/', '').replace('crbug-', '')
                if args.pair is not None:
                    if not args.pair.startswith('CVE-'):
                        raise ValueError(f'--pair with a crbug bug_id must be a CVE ID (got {args.pair!r})')
                    await bootstrap_bug(args.pair, crbug_id, args.force, args.depot_tools_commit, args.eval_flag, commit_sha)
                else:
                    await bootstrap_crbug(crbug_id, args.force, args.depot_tools_commit, args.eval_flag, commit_sha)
            else:
                raise NotImplementedError('Unsupported bug_id format, must be "CVE-YYYY-ZZZZ" or "b/crbug_id"')
        elif args.target_type == 'patch':
            raise NotImplementedError('Patch target type Dockerfile generation not yet implemented')
        else:
            raise NotImplementedError('Unsupported bootstrap target_type')

    args = parser.parse_args()
    log_level = get_log_level(args.log_level)
    log.setLevel(log_level)
    asyncio.run(main(args))
