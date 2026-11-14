#!/usr/bin/env python3

from pathlib import Path
from urllib.parse import quote
import aiofiles
import aiohttp
import contextlib
import fcntl
import json
import os
import re
import tempfile
import time

CVE_DB_PATH = Path(__file__).resolve().parent / 'chrome-cve-db.json'
# Cap on how often the cache-miss retry path will refetch from NVD.
# The retry was designed to recover from a slightly stale cache; if
# the cache was already written within this window, another fetch
# can't help and we'd just be hammering NVD on every CVE-UNKNOWN
# lookup. NVD updates aren't real-time so a day is plenty.
CVE_DB_REFRESH_MAX_AGE_SEC = 86400

## CVE -> crbug
### We can alternatively use https://issues.chromium.org/action/issues/list & customfield1223136 (CVE),
### but parsing crbug outputs are generally a PITA.
CVE_API = 'https://cveawg.mitre.org/api/cve/{cve_id}'                               # cve_id: CVE-2024-6100
ISSUETRACKER_PREFIX_RE = re.compile(r'https://issues.chromium.org/issues/(\d+)')
ISSUETRACKER_PREFIX_CRBUG = 'https://crbug.com/{old_crbug_id}'
ISSUETRACKER_PREFIX_CRBUG_RE = re.compile(r'https://crbug.com/(\d+)')               # some references use this old format.
BUG_REDIRECT_RE = re.compile(r'const url = "https://issues.chromium.org/(\d+)"')    # redirection url inside the returned link for old format.
OLD_BUG_ID_MAX_LEN = 7

## crbug -> CVE
### Using ISSUETRACKER_API prevents us from analyzing non-public bugs. Fallback to NVD CVE DB.
PREAMBLE_LEN = 5    # Length of JSON hijack mitigation preamble on Google endpoints
ISSUETRACKER_API = 'https://issues.chromium.org/action/issues/{crbug_id}/updates'    # crbug_id: 344608204
ISSUETRACKER_CVE_FIELD_ID = 1223136
NVD_API_CHROME = 'https://services.nvd.nist.gov/rest/json/cves/2.0?virtualMatchString=cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*&startIndex={startIndex}'

## crbug -> patch commit
V8_REPO = 'v8/v8'
V8_BRANCH = 'main'
GERRIT_API = 'https://chromium-review.googlesource.com/changes/?O=4c&q={gerrit_q}'  # gerrit_q: urlencode('bug:{crbug_id} repo:{repo} branch:{branch}')
GERRIT_DIFF = 'https://chromium-review.googlesource.com/changes/{gerrit_id}/revisions/{rev_id}/patch?download&raw'  # gerrit_id: urlencode('v8/v8~5604265')

## commit via gitiles
GITILES = 'https://chromium.googlesource.com/v8/v8/+/{commit}'

## commit -> component revision
CRDASH_API = 'https://chromiumdash.appspot.com/fetch_commit?commit={commit}'        # commit: 422cdc5eddcadb53b8eafb099722fb211a35739e

## revision dl
### TODO: TSAN builds? coverage-enabled builds?
PREBUILT_EP = 'https://storage.googleapis.com/v8-asan/linux-{rel}/d8{flags}-linux-{rel}-v8-component-{crev}.zip'
PREBUILT_FLAGS = {
    # target: config: [rel, flags]
    "v8": {
        "debug": ["debug", ""],
        "debug-asan": ["debug", "-asan"],
        "release": ["release", ""],
        "release-asan": ["release", "-asan-no-inline"],
    },
    "v8sbx": {
        "release": ["release", "-sandbox-testing"],
        "release-asan": ["release", "-asan-sandbox-testing"],
    },
}


# recursive json iterator, used to simplify parsing 
def json_iterator(obj):
    yield obj
    if isinstance(obj, dict):
        for v in obj.values():
            yield from json_iterator(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from json_iterator(v)


# "sloppy" json match query
def json_match(obj, query) -> bool:
    # match failures. fallthrough returns True.
    if query is json_match.nop:         # ignore
        pass
    elif isinstance(query, type):       # type constraint
        if not isinstance(obj, query):
            return False
    elif isinstance(query, dict):
        if not isinstance(obj, dict):
            return False
        for qk, qv in query.items():
            if qk not in obj or not json_match(obj[qk], qv):
                return False
    elif isinstance(query, list):
        if not isinstance(obj, list) or len(obj) < len(query):
            return False
        for qi, qv in enumerate(query):
            if not json_match(obj[qi], qv):
                return False
    else:   # other primitives
        if obj != query:
            return False
    return True
json_match.nop = object()


def normalize_cve(cve_id: str) -> str:
    cve_id = cve_id.strip().upper()
    if not cve_id.startswith('CVE-'):
        cve_id = 'CVE-' + cve_id
    return cve_id


async def resolve_old_crbug(old_crbug_id: str) -> str:
    try:
        redir = await get_text(ISSUETRACKER_PREFIX_CRBUG.format(old_crbug_id=old_crbug_id))
        if (match := BUG_REDIRECT_RE.search(redir)):
            return match.group(1)
    except aiohttp.ClientResponseError as e:
        assert e.status == 403, f'Expected 403 error at resolve_old_crbug({old_crbug_id!r}), got {e.status}'
    return old_crbug_id


async def normalize_crbug(crbug_id: str) -> tuple[str, str|None]:
    # normalize into integer format
    crbug_id = crbug_id.strip().replace('b/', '').replace('crbug-', '')

    # now normalize to the new chromium issuetracker number, if length <= OLD_BUG_ID_MAX_LEN
    if len(crbug_id) <= OLD_BUG_ID_MAX_LEN:
        new_crbug_id = await resolve_old_crbug(crbug_id)
        assert crbug_id != new_crbug_id
        return new_crbug_id, crbug_id
    else:
        return crbug_id, None


def _gitcookies_jar() -> aiohttp.CookieJar:
    """Load ~/.gitcookies (Netscape format) into a host-scoped cookie jar.
    Anonymous gitiles/gerrit requests are 503-throttled by Google; the `o`
    cookie authenticates them. Empty jar if the file is absent."""
    from yarl import URL
    jar = aiohttp.CookieJar()
    path = Path(os.path.expanduser(os.environ.get("GIT_COOKIES_PATH", "~/.gitcookies")))
    if not path.is_file():
        return jar
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) != 7:
            continue
        domain, _flag, cpath, _secure, _expiry, name, value = parts
        host = domain.lstrip(".")
        jar.update_cookies({name: value}, response_url=URL(f"https://{host}{cpath or '/'}"))
    return jar


def make_session(**kwargs) -> aiohttp.ClientSession:
    """aiohttp session preloaded with gitcookies auth for googlesource."""
    return aiohttp.ClientSession(cookie_jar=_gitcookies_jar(), **kwargs)


async def get_text(url: str):
    async with make_session() as session:
        async with session.get(url, raise_for_status=True) as res:
            txt = await res.text()
            return txt


async def get_json(url: str, skip: int = 0):
    txt = await get_text(url)
    return json.loads(txt[skip:])


# returns all crbug ids discovered in cve references, (new_set, old_set)
def crbug_refs_parse(refs: list[dict[str, str]]) -> tuple[set[str], set[str]]:
    bug_ids = set()
    old_bug_ids = set()
    for ref in refs:
        ref_url = ref['url']
        if (match := ISSUETRACKER_PREFIX_RE.search(ref_url)):           # new chromium issuetracker id
            bug_ids.add(match.group(1))
        elif (match := ISSUETRACKER_PREFIX_CRBUG_RE.search(ref_url)):   # old crbug id
            bug_id = match.group(1)
            if len(bug_id) <= OLD_BUG_ID_MAX_LEN:
                old_bug_ids.add(bug_id)
            else:
                bug_ids.add(bug_id)

    return set(bug_ids), set(old_bug_ids)


async def cve2crbug(cve_id: str) -> str:
    cve_id = normalize_cve(cve_id)
    obj = await get_json(CVE_API.format(cve_id=cve_id))
    refs = obj['containers']['cna']['references']
    bug_ids, old_bug_ids = crbug_refs_parse(refs)
    if not bug_ids:
        for old_bug_id in old_bug_ids:
            bug_ids.add(await resolve_old_crbug(old_bug_id))
    assert len(bug_ids) == 1, f'Expected 1 bug id related to {cve_id}, got {len(bug_ids)}: {list(bug_ids)}'
    return bug_ids.pop()


async def cve2desc(cve_id: str) -> str:
    cve_id = normalize_cve(cve_id)
    obj = await get_json(CVE_API.format(cve_id=cve_id))
    desc = next(desc["value"] for desc in obj['containers']['cna']['descriptions'] if desc["lang"] == "en")
    return desc


@contextlib.contextmanager
def _flock_exclusive(lock_path: Path):
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o644)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


async def _cve_db_fetch(path: Path) -> list:
    """Fetch from NVD and atomically replace `path`. Caller must hold
    the path's flock."""
    vulns = []
    for _ in range(5):
        db = await get_json(NVD_API_CHROME.format(startIndex=len(vulns)))
        if db['resultsPerPage'] == 0:
            break
        vulns.extend(db['vulnerabilities'])
    else:
        assert '_cve_db_fetch ran 5 times but failed to fetch all Chrome CVEs'

    fd, tmp = tempfile.mkstemp(prefix=path.name + '.', dir=str(path.parent))
    try:
        with os.fdopen(fd, 'wt') as f:
            json.dump(vulns, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise
    return vulns


# Returns (vulns, mtime). When `fresher_than` is given, guarantees the
# returned data was written after that mtime — a peer that refreshed
# while we waited on the lock spares us from refetching.
async def cve_db_get(path: Path, fresher_than: float | None = None) -> tuple[list, float]:
    # mtime comes from fstat on the same fd we read — peers may
    # atomically replace `path` between our open() and a path-based
    # stat(), which would yield a (vulns, mtime) pair from different
    # inodes. fstat sees the inode we actually parsed.
    if fresher_than is None:
        try:
            with path.open('rt') as f:
                vulns = json.load(f)
                return vulns, os.fstat(f.fileno()).st_mtime
        except (FileNotFoundError, json.decoder.JSONDecodeError):
            pass

    with _flock_exclusive(path.with_name(path.name + '.lock')):
        # Re-check under lock: a peer may have refreshed in the interim.
        try:
            with path.open('rt') as f:
                mtime = os.fstat(f.fileno()).st_mtime
                if fresher_than is None or mtime > fresher_than:
                    return json.load(f), mtime
        except (FileNotFoundError, json.decoder.JSONDecodeError):
            pass
        vulns = await _cve_db_fetch(path)
        return vulns, path.stat().st_mtime


async def crbug2cve(crbug_id: str) -> str:
    crbug_id, old_crbug_id = await normalize_crbug(crbug_id)
    try:
        async with make_session() as session:
            async with session.post(ISSUETRACKER_API.format(crbug_id=crbug_id), json=[crbug_id], raise_for_status=True) as res:
                txt = await res.text()
        obj = json.loads(txt[PREAMBLE_LEN:])
        fields = [
            x for x in json_iterator(obj)
            if json_match(x, [
                'type.googleapis.com/google.devtools.issuetracker.v1.CustomFieldValue',
                [ISSUETRACKER_CVE_FIELD_ID, None, None, None, None, [[str]]]
            ])
        ]
        assert len(fields) == 1, f'Expected 1 CVE field for Chromium bug ID {crbug_id}, found {len(fields)}'
        return 'CVE-' + fields[0][1][5][0][0]
    except aiohttp.ClientResponseError as e:
        # fallthrough to fall back to nvd database
        assert e.status == 403, f'Expected 403 Forbiddden error code from IssueTracker API, found {e.status} instead'

    vulns, mtime = await cve_db_get(CVE_DB_PATH)
    refreshed = False

    # try loading from db
    while True:
        cves = set()
        for vuln in vulns:
            cve = vuln['cve']['id']
            refs = vuln['cve']['references']
            bug_ids, old_bug_ids = crbug_refs_parse(refs)
            if crbug_id in bug_ids or old_crbug_id in old_bug_ids:
                cves.add(cve)

        # Cache miss: force one refresh — but only if the cache is old
        # enough that a refetch could plausibly help. A recently-written
        # cache means either (a) we already refetched on a prior call,
        # or (b) a peer just did, and NVD hasn't published anything new
        # in the meantime. Either way, refetching wastes a round trip
        # and won't change the answer.
        if not cves and not refreshed and time.time() - mtime > CVE_DB_REFRESH_MAX_AGE_SEC:
            vulns, mtime = await cve_db_get(CVE_DB_PATH, fresher_than=mtime)
            refreshed = True
            continue

        break

    assert len(cves) == 1, f'Expected 1 CVE for Chromium bug ID {crbug_id}, found {len(cves)}: {list(cves)}'
    return cves.pop()


async def crbug2commits(crbug_id: str) -> list[str]:
    crbug_id, old_crbug_id = await normalize_crbug(crbug_id)
    if old_crbug_id is not None:
        bug_query = f'(bug:{crbug_id} OR "chromium:{old_crbug_id}")'
    else:
        bug_query = f'bug:{crbug_id}'
    query = f'{bug_query} repo:v8/v8 (branch:main OR branch:master)'
    changes = await get_json(GERRIT_API.format(gerrit_q=quote(query, safe='')), skip=PREAMBLE_LEN)
    # abandoned commits don't have submission id, so skip
    changes = list(c for c in changes if 'submission_id' in c)
    # sort by ascending commit order.
    # old commits have format '356502-1543571687455-e5a9f1f', new ones are just int strings. take first part.
    changes.sort(key=lambda c: int(c['submission_id'].split('-')[0]))
    commits = [x['current_revision'] for x in changes]
    return commits


async def commit2patch(commit: str) -> str:
    query = f'commit:{commit}'
    changes = await get_json(GERRIT_API.format(gerrit_q=quote(query, safe='')), skip=PREAMBLE_LEN)
    assert len(changes) == 1, f'Expected 1 matching Gerrit change submission for commit {commit}, found {len(changes)}'
    change = changes[0]
    gerrit_id = change['id']
    rev_id = change['current_revision_number']
    patch = await get_text(GERRIT_DIFF.format(gerrit_id=gerrit_id, rev_id=rev_id))
    return patch


async def commit2crev(commit: str) -> int:
    info = await get_json(CRDASH_API.format(commit=commit))
    return int(info['position'])


async def commit2parent(commit: str) -> str:
    async with make_session() as session:
        async with session.get(GITILES.format(commit=f'{commit}^'), raise_for_status=True) as res:
            return res.url.path.split('/')[-1]


async def commit2date(commit: str) -> int:
    """Get the commit timestamp as a Unix epoch (SOURCE_DATE_EPOCH).

    Uses the chromiumdash API which returns commit metadata including time.
    """
    info = await get_json(CRDASH_API.format(commit=commit))
    # chromiumdash returns 'time' as a Unix timestamp in milliseconds
    return int(info['time']) // 1000


def prebuilt_url(crev: int, target: str, config: str) -> str:
    """Return the Google Cloud Storage URL for a prebuilt d8 binary."""
    rel, flags = PREBUILT_FLAGS[target][config]
    return PREBUILT_EP.format(rel=rel, flags=flags, crev=crev)


async def download_prebuilt(crev: int, target: str, config: str, dstdir = Path(__file__).parent / '.cache', chunksz = 64*1024*1024) -> tuple[Path, int]:
    rel, flags = PREBUILT_FLAGS[target][config]
    url = PREBUILT_EP.format(rel=rel, flags=flags, crev=crev)

    dst = dstdir / url.split('/')[-1]
    dstdir.mkdir(parents=True, exist_ok=True)
    if not dst.is_file():
        async with (
            make_session() as session,
            session.get(url, raise_for_status=True) as res,
            aiofiles.open(dst, "wb") as fdst
        ):
            async for chunk in res.content.iter_chunked(chunksz):
                await fdst.write(chunk)

    return dst, dst.stat().st_size


if __name__ == '__main__':
    async def main():
        cve = 'CVE-2024-9122'
        print(f'===== {cve = } =====')
        crbug = await cve2crbug(cve)
        print(f'[+] cve2crbug():     {cve = } -> {crbug = }')
        desc = await cve2desc(cve)
        print(f'[+] cve2desc():      {desc = }')

        cve_rt = await crbug2cve(crbug)
        print(f'[+] crbug2cve():     {crbug = } -> {cve_rt = }')
        assert cve == cve_rt

        commits = await crbug2commits(crbug)
        print(f'[+] crbug2commits(): {crbug = } -> {commits = }')

        patches = await asyncio.gather(*map(commit2patch, commits))
        for commit, patch in zip(commits, patches):
            print(f'[+] commit2patch():  {commit = } -> {patch.splitlines()[3] = }')

        crevs = await asyncio.gather(*map(commit2crev, commits))
        for commit, crev in zip(commits, crevs):
            print(f'[+] commit2crev():   {commit = } -> {crev = }')

        parents = await asyncio.gather(*map(commit2parent, commits))
        for commit, parent in zip(commits, parents):
            print(f'[+] commit2parent(): {commit = } -> {parent = }')

        fix_crev = min(crevs)
        tgt_crev = fix_crev - 1
        print(f'[*] {fix_crev = }')

        print(f'[*] download_prebuilt({fix_crev = }, target = "v8", config = "debug-asan")...')
        dl_path, dl_size = await download_prebuilt(fix_crev, 'v8', 'debug-asan')
        print(f'[*] => {dl_path = }, {dl_size = }')

        print(f'[*] download_prebuilt({tgt_crev = }, target = "v8", config = "debug-asan")...')
        dl_path, dl_size = await download_prebuilt(tgt_crev, 'v8', 'debug-asan')
        print(f'[*] => {dl_path = }, {dl_size = }')

        #####

        # old crbug format, undisclosed crbug report
        crbug = 'b/1147206'
        print(f'===== {crbug = } =====')
        cve = await crbug2cve(crbug)
        print(f'[+] crbug2cve():     {crbug = } -> {cve = }')
        desc = await cve2desc(cve)
        print(f'[+] cve2desc():      {desc = }')

        crbug_rt = await cve2crbug(cve)
        print(f'[+] cve2crbug():     {cve = } -> {crbug_rt = }')
        assert crbug != crbug_rt    # old crbug id, round-trip normalizes it

        commits = await crbug2commits(crbug)
        print(f'[+] crbug2commits(): {crbug = } -> {commits = }')

        patches = await asyncio.gather(*map(commit2patch, commits))
        for commit, patch in zip(commits, patches):
            print(f'[+] commit2patch():  {commit = } -> {patch.splitlines()[3] = }')

        crevs = await asyncio.gather(*map(commit2crev, commits))
        for commit, crev in zip(commits, crevs):
            print(f'[+] commit2crev():   {commit = } -> {crev = }')

        parents = await asyncio.gather(*map(commit2parent, commits))
        for commit, parent in zip(commits, parents):
            print(f'[+] commit2parent(): {commit = } -> {parent = }')

        fix_crev = min(crevs)
        tgt_crev = fix_crev - 1
        print(f'[*] {fix_crev = }')

        print(f'[*] download_prebuilt({fix_crev = }, target = "v8", config = "debug-asan")...')
        dl_path, dl_size = await download_prebuilt(fix_crev, 'v8', 'debug-asan')
        print(f'[*] => {dl_path = }, {dl_size = }')

        print(f'[*] download_prebuilt({tgt_crev = }, target = "v8", config = "debug-asan")...')
        dl_path, dl_size = await download_prebuilt(tgt_crev, 'v8', 'debug-asan')
        print(f'[*] => {dl_path = }, {dl_size = }')

    import asyncio
    asyncio.run(main())
