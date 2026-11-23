# Mozilla SpiderMonkey Verified Instances

This directory contains the 80 verified Mozilla SpiderMonkey benchmark instances used by the official SEC-bench Pro leaderboard (https://sec-bench.github.io/firefox). Each instance is stored in its own numeric directory and includes the artifacts needed to reproduce and validate a real-world issue, such as `meta.json`, `poc.js`, `Report.md`, `VERIFIED.txt`, `Dockerfile.fixed`, `patches/`, and execution logs.

The aggregate numbers below are derived from the current snapshot in this directory:

- `meta.json` provides the per-instance labels used for the vulnerability-type and error-type distributions.
- `output.txt` stores the validation log for the packaged PoC.

## Summary

- Total verified instances: 80
- Verification binary: `/out/js` (ASAN + debug SpiderMonkey JS shell, built per-instance; one CVE-2025-4919 instance uses `/out/js-release` to surface a wrong-result OOB inside a 4 GB allocation that ASAN does not flag)
- Source tree: `/src/gecko-dev` (revision pinned per-instance via Dockerfile)
- Fixed-image definitions: 80 instances include `Dockerfile.fixed` and `patches/`

## Base and Vulnerable Images

`base/sm/Dockerfile` is the canonical definition of
`hwiwonlee/sm.base:latest`. Build a vulnerable image with:

```sh
projects/sm/build_images.sh 1880719
```

The build script verifies that the local base image contains the benchmark
cleanup tool required by every vulnerable leaf and uses Rust 1.95.0. If the
base is absent or outdated, it rebuilds it from `base/sm` before starting the
selected leaf builds. Pass `-b` to force that canonical base rebuild even when
the local image already satisfies the compatibility check:

```sh
projects/sm/build_images.sh -b 1880719
```

## Fixed Images

The public fixed-image convention is
`hwiwonlee/sm.x86_64.fixed:<Bugzilla issue id>`. The grader uses this repository
by default. Build one tag locally with:

```sh
projects/sm/build_fixed_images.sh 1880719
python projects/sm/patch_check.py 1880719
```

For a release, validate and publish only tags absent from Docker Hub:

```sh
projects/sm/push_images.sh --fixed --missing --verify
```

`--verify` runs the packaged PoC against each fixed image before publishing.
Builds are per-instance SpiderMonkey builds and can require substantial CPU,
memory, disk, and elapsed time. Use `--image-repo` and grade with
`--fixed-repo` when publishing to a separate registry.

Mozilla Foundation does not run a structured per-bug VRP payout for SpiderMonkey comparable to Chrome's VRP; every instance in this directory has `vrp: null`. The dataset is drawn from Bugzilla `sec-high` / `sec-critical` entries, MFSA advisories (2018 – 2026), Pwn2Own winners, CISA KEV in-the-wild exploited bugs, and the Anthropic/Claude-reported Firefox 148 batch (MFSA 2026-13 / 14 / 15).

## Vulnerability Type Distribution

| Vulnerability type | Count | Share |
| --- | ---: | ---: |
| Use-after-free | 27 | 33.75% |
| Type confusion | 15 | 18.75% |
| Out-of-bounds read | 7 | 8.75% |
| Incorrect JIT optimization | 6 | 7.50% |
| Cross-compartment violation | 5 | 6.25% |
| Out-of-bounds write | 3 | 3.75% |
| Stack corruption | 3 | 3.75% |
| Incorrect code generation | 2 | 2.50% |
| Integer overflow | 2 | 2.50% |
| Integer truncation | 2 | 2.50% |
| Uninitialized memory read | 2 | 2.50% |
| Control-flow integrity violation | 1 | 1.25% |
| Debug assertion failure | 1 | 1.25% |
| Invalid free | 1 | 1.25% |
| Null pointer dereference | 1 | 1.25% |
| Race condition | 1 | 1.25% |
| Stack buffer overflow | 1 | 1.25% |

## Error Type Distribution

| Error type | Count | Share |
| --- | ---: | ---: |
| `ASAN_CRASH` | 79 | 98.75% |
| `RUNTIME_CRASH` | 1 | 1.25% |

## Regenerating the Numbers

The vulnerability-type and error-type tables can be recomputed from the `target_vulnerability_type` and `error_type` fields in each instance's `meta.json`.
