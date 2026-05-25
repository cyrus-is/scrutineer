#!/usr/bin/env python3
"""Smoke + regression suite for fetch_source.py.

Dependency-free (no pytest, no network): run with the project venv from the
mcp-review dir:

    .venv/bin/python tests/test_fetch_source.py

Covers the guarantees that matter most: the path-sanitizing extractor resists
zip-slip / symlink escape / absolute paths / link & special members / tar &
zip bombs, fetched code is never executed, and source_artifact_match reflects
the pin (and is disqualified by tampering). Archives are built in memory so the
suite never touches the network — the network resolve/download path sits behind
a seam (resolve_*/http_get) and is exercised only under --fetch in real use.
"""

import io
import json
import shutil
import stat
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

import fetch_source as F  # noqa: E402

_results: list[tuple[str, bool]] = []


def check(name: str, cond) -> None:
    _results.append((name, bool(cond)))


def _tar_bytes(members: list[tuple]) -> bytes:
    """Build a .tar.gz from (name, kind, payload) tuples.
    kind: 'file' | 'dir' | 'sym' | 'lnk' | 'fifo' | 'chr'. payload is file
    content (str) for files, or the link target for sym/lnk."""
    bio = io.BytesIO()
    with tarfile.open(fileobj=bio, mode="w:gz") as tar:
        for name, kind, payload in members:
            ti = tarfile.TarInfo(name)
            if kind == "file":
                data = payload.encode()
                ti.size = len(data)
                tar.addfile(ti, io.BytesIO(data))
            elif kind == "dir":
                ti.type = tarfile.DIRTYPE
                ti.mode = 0o755
                tar.addfile(ti)
            elif kind == "sym":
                ti.type = tarfile.SYMTYPE
                ti.linkname = payload
                tar.addfile(ti)
            elif kind == "lnk":
                ti.type = tarfile.LNKTYPE
                ti.linkname = payload
                tar.addfile(ti)
            elif kind == "fifo":
                ti.type = tarfile.FIFOTYPE
                tar.addfile(ti)
            elif kind == "chr":
                ti.type = tarfile.CHRTYPE
                tar.addfile(ti)
    return bio.getvalue()


def _in_tmp(fn):
    d = Path(tempfile.mkdtemp(prefix="fetch-test-"))
    try:
        return fn(d)
    finally:
        shutil.rmtree(d, ignore_errors=True)


# --- spec parsing -----------------------------------------------------------
check("npm split scoped+ver", F.split_npm_spec("@scope/pkg@1.2.3") == ("@scope/pkg", "1.2.3"))
check("npm split bare", F.split_npm_spec("pkg") == ("pkg", ""))
check("npm split tag", F.split_npm_spec("pkg@latest") == ("pkg", "latest"))
check("npm exact yes", F.is_exact_npm_version("1.2.3") and F.is_exact_npm_version("1.2.3-rc.1"))
check("npm exact no (tag)", not F.is_exact_npm_version("latest"))
check("pypi split exact", F.split_pypi_spec("pkg==1.2.3") == ("pkg", "1.2.3"))
check("pypi split range empties ver", F.split_pypi_spec("pkg>=1.2")[1] == "")
check("pypi split tilde range", F.split_pypi_spec("pkg~=1.2")[1] == "")
check("pypi split bare", F.split_pypi_spec("pkg") == ("pkg", ""))
check("gh parse github:", F.parse_github_spec("github:owner/repo#" + "a" * 40) == ("owner", "repo", "a" * 40))
check("gh parse https .git", F.parse_github_spec("https://github.com/o/r.git#v1") == ("o", "r", "v1"))
check("gh parse bare", F.parse_github_spec("o/r") == ("o", "r", ""))

# --- predicted match from the pin alone (offline) ---------------------------
check("match npm exact verified", F.plan_npm("pkg@1.2.3")["predicted_match"] == F.MATCH_VERIFIED)
check("match npm tag unverifiable", F.plan_npm("pkg@latest")["predicted_match"] == F.MATCH_UNVERIFIABLE)
check("match pypi exact verified", F.plan_pypi("pkg==1.2.3")["predicted_match"] == F.MATCH_VERIFIED)
check("match pypi range unverifiable", F.plan_pypi("pkg>=1")["predicted_match"] == F.MATCH_UNVERIFIABLE)
check("match gh sha verified", F.plan_github("o", "r", "b" * 40)["predicted_match"] == F.MATCH_VERIFIED)
check("match gh branch unverifiable", F.plan_github("o", "r", "main")["predicted_match"] == F.MATCH_UNVERIFIABLE)
# npm exact artifact URL is deterministic (no metadata needed for the plan)
check("plan npm exact deterministic url", any(".tgz" in u for u in F.plan_npm("pkg@1.2.3")["would_fetch"]))

# --- benign extraction: files land, NOTHING is executed ---------------------
def _benign(d):
    tb = _tar_bytes([
        ("package/", "dir", ""),
        ("package/package.json", "file", '{"scripts":{"postinstall":"touch /tmp/PWNED_fetch_test"}}'),
        ("package/index.js", "file", "console.log('hi')\n"),
    ])
    rep = F.safe_extract_tar(tb, d)
    pkg_json = (d / "package" / "package.json").read_text()
    return rep, pkg_json

_rep, _pkgjson = _in_tmp(_benign)
check("benign extracts 2 files", _rep["extracted"] == 2)
check("benign no rejections", _rep["rejected"] == [])
check("benign not tampering", _rep["tampering_detected"] is False)
check("benign root dir captured", "package" in _rep["root_dirs"])
# the postinstall script is present as INERT TEXT and was never run
check("postinstall present as text", "postinstall" in _pkgjson)
check("postinstall NOT executed", not Path("/tmp/PWNED_fetch_test").exists())

# --- zip-slip (tar): parent-dir escape is rejected, nothing written outside --
def _zipslip(d):
    tb = _tar_bytes([("package/../../escape.txt", "file", "owned")])
    rep = F.safe_extract_tar(tb, d)
    escaped = (d.parent / "escape.txt").exists()
    return rep, escaped

_rep, _escaped = _in_tmp(_zipslip)
check("tar zip-slip rejected", any(r["reason"] == "path_escape" for r in _rep["rejected"]))
check("tar zip-slip nothing extracted", _rep["extracted"] == 0)
check("tar zip-slip no escape on disk", _escaped is False)
check("tar zip-slip flags tampering", _rep["tampering_detected"] is True)

# --- absolute path member is rejected ---------------------------------------
_rep = _in_tmp(lambda d: F.safe_extract_tar(_tar_bytes([("/abs/evil.txt", "file", "x")]), d))
check("tar absolute path rejected", any(r["reason"] == "absolute_path" for r in _rep["rejected"]))
check("tar absolute path nothing extracted", _rep["extracted"] == 0)

# --- symlink / hardlink / special members are refused, never created --------
def _symlink(d):
    tb = _tar_bytes([("package/evil", "sym", "/etc/passwd")])
    rep = F.safe_extract_tar(tb, d)
    return rep, (d / "package" / "evil").is_symlink()

_rep, _is_link = _in_tmp(_symlink)
check("tar symlink rejected", any(r["reason"] == "symlink" for r in _rep["rejected"]))
check("tar symlink not created", _is_link is False)
check("tar symlink flags tampering", _rep["tampering_detected"] is True)

_rep = _in_tmp(lambda d: F.safe_extract_tar(_tar_bytes([("package/h", "lnk", "package/x")]), d))
check("tar hardlink rejected", any(r["reason"] == "hardlink" for r in _rep["rejected"]))

_rep = _in_tmp(lambda d: F.safe_extract_tar(_tar_bytes([("package/dev", "fifo", "")]), d))
check("tar fifo rejected special", any(r["reason"] == "special_file" for r in _rep["rejected"]))
_rep = _in_tmp(lambda d: F.safe_extract_tar(_tar_bytes([("package/dev", "chr", "")]), d))
check("tar chardev rejected special", any(r["reason"] == "special_file" for r in _rep["rejected"]))

# --- size caps: per-entry and cumulative (tar bomb) -------------------------
def _entry_cap(d):
    saved = F.MAX_ENTRY_BYTES
    F.MAX_ENTRY_BYTES = 10
    try:
        return F.safe_extract_tar(_tar_bytes([("package/big.txt", "file", "x" * 50)]), d)
    finally:
        F.MAX_ENTRY_BYTES = saved

_rep = _in_tmp(_entry_cap)
check("tar entry-too-large rejected", any(r["reason"] == "entry_too_large" for r in _rep["rejected"]))

def _total_cap(d):
    saved = F.MAX_TOTAL_BYTES
    F.MAX_TOTAL_BYTES = 10
    try:
        return F.safe_extract_tar(_tar_bytes([
            ("package/a.txt", "file", "x" * 8),
            ("package/b.txt", "file", "y" * 8),
        ]), d)
    finally:
        F.MAX_TOTAL_BYTES = saved

_rep = _in_tmp(_total_cap)
check("tar total-too-large rejected", any(r["reason"] == "total_too_large" for r in _rep["rejected"]))
check("tar total cap still extracts first", _rep["extracted"] == 1)

# --- zip variants: zip-slip + symlink ---------------------------------------
def _zip_bytes(entries: list[tuple]) -> bytes:
    """entries: (name, content, is_symlink)."""
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w") as zf:
        for name, content, is_sym in entries:
            zi = zipfile.ZipInfo(name)
            if is_sym:
                zi.external_attr = (stat.S_IFLNK | 0o777) << 16
            zf.writestr(zi, content)
    return bio.getvalue()

def _zipslip_zip(d):
    zb = _zip_bytes([("../escape.txt", "owned", False)])
    rep = F.safe_extract_zip(zb, d)
    return rep, (d.parent / "escape.txt").exists()

_rep, _escaped = _in_tmp(_zipslip_zip)
check("zip zip-slip rejected", any(r["reason"] == "path_escape" for r in _rep["rejected"]))
check("zip zip-slip no escape on disk", _escaped is False)

_rep = _in_tmp(lambda d: F.safe_extract_zip(_zip_bytes([("link", "/etc/passwd", True)]), d))
check("zip symlink rejected", any(r["reason"] == "symlink" for r in _rep["rejected"]))

def _zip_benign(d):
    zb = _zip_bytes([("pkg/m.py", "print('hi')", False)])
    rep = F.safe_extract_zip(zb, d)
    return rep, (d / "pkg" / "m.py").exists()

_rep, _exists = _in_tmp(_zip_benign)
check("zip benign extracts", _rep["extracted"] == 1 and _exists)

# --- source_artifact_match: requires immutable ref AND a byte binding --------
clean = {"tampering_detected": False}
check("match npm exact + integrity verified -> verified",
      F.compute_match({"pin_is_exact": True, "ecosystem": "npm"}, clean, True) == F.MATCH_VERIFIED)
# exact version but NO/failed cryptographic binding must NOT be 'verified'
check("match npm exact + integrity unverified -> unverifiable",
      F.compute_match({"pin_is_exact": True, "ecosystem": "npm"}, clean, None) == F.MATCH_UNVERIFIABLE)
check("match npm exact + integrity False -> unverifiable",
      F.compute_match({"pin_is_exact": True, "ecosystem": "npm"}, clean, False) == F.MATCH_UNVERIFIABLE)
# github: the commit SHA itself is the binding (no published digest exists)
check("match github exact -> verified (no digest needed)",
      F.compute_match({"pin_is_exact": True, "ecosystem": "github"}, clean, None) == F.MATCH_VERIFIED)
check("match unverifiable when not exact",
      F.compute_match({"pin_is_exact": False, "ecosystem": "npm"}, clean, True) == F.MATCH_UNVERIFIABLE)
check("match downgraded by tampering",
      F.compute_match({"pin_is_exact": True, "ecosystem": "github"}, {"tampering_detected": True}, True)
      == F.MATCH_UNVERIFIABLE)

# --- a member resolving onto a directory must reject, not crash the run ------
def _dot_member(d):
    # a benign file plus a hostile '.' member; the run must survive and still
    # extract the benign file rather than aborting on IsADirectoryError.
    tb = _tar_bytes([("package/", "dir", ""), ("package/ok.js", "file", "x"), (".", "file", "evil")])
    return F.safe_extract_tar(tb, d)

_rep = _in_tmp(_dot_member)
check("dot-member rejected not fatal", any(r["reason"] == "invalid_name" for r in _rep["rejected"]))
check("dot-member run still extracts benign", _rep["extracted"] == 1)
_rep = _in_tmp(lambda d: F.safe_extract_tar(_tar_bytes([("pkg/", "dir", ""), ("pkg/.", "file", "x")]), d))
check("dir-resolving member rejected", any(r["reason"] == "invalid_name" for r in _rep["rejected"]))

# --- github URL hardening: userinfo stripped, segments encoded ---------------
check("gh strips userinfo token",
      F.parse_github_spec("https://user:ghp_tok@github.com/o/r.git#v1") == ("o", "r", "v1"))
check("gh url stays on codeload host",
      F.resolve_github("o", "r", "a/../../evil")["artifact_url"].startswith("https://codeload.github.com/o/r/tar.gz/"))
check("gh token never in resolved url",
      "ghp_tok" not in json.dumps(F.resolve_github(*F.parse_github_spec("https://x:ghp_tok@github.com/o/r#" + "a" * 40))))

# --- manifest binding digest is stable across runs --------------------------
b = {"ecosystem": "npm", "name": "pkg", "resolved_version": "1.2.3", "content_sha256": "abc"}
check("manifest digest stable", F.digest(b) == F.digest(dict(reversed(list(b.items())))))

# --- npm integrity verification (SRI) ---------------------------------------
import base64, hashlib  # noqa: E402
_payload = b"hello mcp"
_sri = "sha512-" + base64.b64encode(hashlib.sha512(_payload).digest()).decode()
check("npm integrity verifies", F.verify_npm_integrity(_payload, _sri) is True)
check("npm integrity rejects wrong", F.verify_npm_integrity(b"tampered", _sri) is False)

# --- from_analysis: registry npm vs pypi disambiguated by command -----------
def _analysis(servers):
    d = Path(tempfile.mkdtemp(prefix="fetch-an-"))
    p = d / "a.json"
    p.write_text(json.dumps({"servers": servers}))
    return p, d

_p, _d = _analysis([{"name": "gh", "command": "uvx",
                     "provenance": {"source_type": "registry", "spec": "mcp-server-github==1.2.3"}}])
try:
    eco, plan = F.from_analysis(_p, "gh")
    check("from_analysis uvx -> pypi", eco == "pypi" and plan["pin_is_exact"] is True)
finally:
    shutil.rmtree(_d, ignore_errors=True)

_p, _d = _analysis([{"name": "fs", "command": "npx",
                     "provenance": {"source_type": "registry", "spec": "@scope/fs"}}])
try:
    eco, plan = F.from_analysis(_p, "fs")
    check("from_analysis npx -> npm", eco == "npm")
    check("from_analysis npx unpinned -> unverifiable", plan["predicted_match"] == F.MATCH_UNVERIFIABLE)
finally:
    shutil.rmtree(_d, ignore_errors=True)

_p, _d = _analysis([{"name": "rem", "command": None,
                     "provenance": {"source_type": "remote", "spec": None}}])
try:
    eco, plan = F.from_analysis(_p, "rem")
    check("from_analysis remote -> unfetchable", plan["predicted_match"] == F.MATCH_UNFETCHABLE)
finally:
    shutil.rmtree(_d, ignore_errors=True)

# --- resolver layer with a stubbed registry (no network) --------------------
_saved = F.http_get_json
try:
    F.http_get_json = lambda url: {
        "versions": {"1.2.3": {"dist": {"tarball": "https://r/x-1.2.3.tgz", "integrity": "sha512-AAA"}}},
        "dist-tags": {"latest": "1.2.3"}}
    r = F.resolve_npm("pkg@1.2.3")
    check("resolve_npm exact binds version", r["resolved_version"] == "1.2.3" and r["pin_is_exact"])
    r = F.resolve_npm("pkg@latest")
    check("resolve_npm dist-tag not exact", r["resolved_version"] == "1.2.3" and not r["pin_is_exact"])

    F.http_get_json = lambda url: {
        "info": {"version": "2.0.0"},
        "releases": {"2.0.0": [{"packagetype": "sdist", "url": "https://f/x-2.0.0.tar.gz",
                                "digests": {"sha256": "dead"}}]}}
    r = F.resolve_pypi("pkg==2.0.0")
    check("resolve_pypi exact binds version", r["resolved_version"] == "2.0.0" and r["pin_is_exact"])
    _raised = False
    try:
        F.resolve_pypi("pkg==9.9.9")          # missing exact must NOT silently fall back to latest
    except ValueError:
        _raised = True
    check("resolve_pypi missing exact raises (no silent fallback)", _raised)
finally:
    F.http_get_json = _saved

# ----------------------------------------------------------------------------
fails = [n for n, ok in _results if not ok]
for n, ok in _results:
    print(("PASS " if ok else "FAIL ") + n)
print(f"\n{len(_results) - len(fails)}/{len(_results)} checks passed")
if fails:
    print("FAILURES: " + ", ".join(fails))
    sys.exit(1)
