DISCLAIMER: This README is old, we've merged dev+eval into a single container exposing a MCP server.

# dev?
- development container
- allows the agent to see git history, search files, recompile stuff, ...

# eval?
- used for RL grading
- should contain all prebuilt binaries for the target under test
- agent should not be able to execute arbitrary commands within the evaluator,
  instead an appropriate tool call should be exposed
- trap/crashes are end goals, but do we need to provide better metrics?
  - e.g. for CVE-2024-6100, should we be able to expose a userspace ftrace-like primitive
    that allows the agent to inject a probe on canonicalization function / JS-to-Wasm wrapper
    so it can track how many types it has initialized?
  - ...or can the agent just do this on its own within the dev environment?
    - it can, but we should then teach it how to do this.
    - would it matter if the agent hallucinates this? probably not, since it can already hallucinate on any tool calls


# v8 prebuilts
- release:      https://storage.googleapis.com/v8-asan/linux-release/d8-linux-release-v8-component-100001.zip
- release+asan: https://storage.googleapis.com/v8-asan/linux-release/d8-asan-no-inline-linux-release-v8-component-100000.zip
- debug:        https://storage.googleapis.com/v8-asan/linux-debug/d8-linux-debug-v8-component-100001.zip
- debug+asan:   https://storage.googleapis.com/v8-asan/linux-debug/d8-asan-linux-debug-v8-component-100001.zip

# v8sbx prebuilts
- release:      https://storage.googleapis.com/v8-asan/linux-release/d8-sandbox-testing-linux-release-v8-component-100001.zip
- release+asan: https://storage.googleapis.com/v8-asan/linux-release/d8-asan-sandbox-testing-linux-release-v8-component-100001.zip
- nonexistent flags:
  - debug is meaningless (harmful!) in v8sbx.
  - no-inline is also problematic due to artifical no-inline codegen.

# cve -> crbug conversion
- curl -s https://cveawg.mitre.org/api/cve/CVE-2024-6100 | jq -r '.containers.cna.references[].url | select(contains("https://issues.chromium.org/issues/"))' | awk -F/ '{print $NF}'

# crbug -> cve conversion
- echo -n 'CVE-'; curl -s 'https://issues.chromium.org/action/issues/344608204/events' | tail -c+5 | jq -r '.. | select(.[0]?=="type.googleapis.com/google.devtools.issuetracker.v1.CustomFieldValue" and .[1]?.[0]?==1223136) | .[1].[-1]'

# crbug -> patch commit conversion
- curl -s 'https://chromium-review.googlesource.com/changes/?O=4c&q=bug%3A344608204%20repo%3Av8%2Fv8%20branch%3Amain' | tail -c+5 | jq -r '.[0].current_revision'
  - Note: `O` parameter is a hexadecimal flag value that determines which info to query.
    - `4`: all revision info (`2`: last revision info)
    - `8`: commit info
    - `40`: file diff stat
  - Warning: verify that only a single commit exists, otherwise we need to analyze multi-patches
  - Also note that some of the "patches" may not be a patch but a regression test addition.
    - See `https://chromium-review.googlesource.com/q/bug:381696874+repo:v8/v8+branch:main` for an example.

# patch diff
- https://chromium-review.googlesource.com/changes/v8%2Fv8~5604265/revisions/2/patch?download&raw
- Format: `https://chromium-review.googlesource.com/changes/${data.id}/revisions/${data.current_revision_number}/patch?download&raw`, `data` queried above

# commit -> component conversion
- curl -s 'https://chromiumdash.appspot.com/fetch_commit?commit=422cdc5eddcadb53b8eafb099722fb211a35739e' | jq .position
- Note: Use `https://chromium.googlesource.com/v8/v8/+/422cdc5eddcadb53b8eafb099722fb211a35739e^` redirection to identify parent... or just pull from gerrit O flag `8`
