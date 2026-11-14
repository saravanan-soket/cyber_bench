#!/usr/bin/env python3
"""Wait for the Docker daemon (via SDK) and pre-pull the CyberGym runner images."""
import sys, time, docker

c = None
for _ in range(120):
    try:
        c = docker.from_env()
        c.ping()
        break
    except Exception:
        time.sleep(2)
if c is None:
    sys.exit("docker daemon not reachable")
print("docker ready:", c.version().get("Version"), flush=True)
for t in ["latest", "20200102", "20220102", "20190802"]:
    try:
        c.images.pull("cybergym/oss-fuzz-base-runner", tag=t)
        print("pulled", t, flush=True)
    except Exception as e:
        print("pull FAIL", t, e, flush=True)
print("PREP_DONE", flush=True)
