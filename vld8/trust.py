"""Trust boundaries, external run state, PR worktrees, config, and evidence (#128).

Implements design §6 (``<git-common-dir>/vld8`` state directory), §9/§10
(PR checkout at ``headRefOid``, fork/bot detection, base-ref/external TOML
config loading, ``--evidence`` tree-id enforcement, and trusted command guard)
using the Python 3.14 standard library plus :mod:`vld8.checks` and
:mod:`vld8.findings`.
"""

import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import tempfile
import tomllib
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from . import checks, findings, report

SCHEMA_VERSION = "1.0"

MAX_CONFIG_BYTES = 1024 * 1024
MAX_EVIDENCE_BYTES = findings.MAX_FINDINGS_BYTES
MAX_EVIDENCE_ITEMS = 10_000
MAX_SARIF_RUNS = 32
MAX_REMOTE_URL_LENGTH = 2048

_SSH_SCP_URL_RE = re.compile(
    r"^git@[A-Za-z0-9][A-Za-z0-9._-]*:[A-Za-z0-9._/@-]+\Z", re.ASCII
)
_GIT_ENV_OVERRIDES = frozenset(
    {
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_COMMON_DIR",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    }
)

_EVIDENCE_DOC_KEYS = frozenset(
    {"schemaVersion", "treeId", "tools", "exclusions", "findings"}
)


class TrustError(ValueError):
    """Raised when a trust, state-dir, worktree, config, or evidence check fails."""


@dataclass(frozen=True)
class PRMetadata:
    """Validated GitHub pull-request metadata and computed trust status."""

    number: int
    title: str
    body: str
    url: str
    author_login: str
    author_is_bot: bool
    head_ref_name: str
    head_ref_oid: str
    base_ref_name: str
    is_cross_repository: bool
    trusted: bool
    untrusted_reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        """Serialize metadata with camelCase JSON keys."""
        return {
            "schemaVersion": SCHEMA_VERSION,
            "number": self.number,
            "title": self.title,
            "body": self.body,
            "url": self.url,
            "authorLogin": self.author_login,
            "authorIsBot": self.author_is_bot,
            "headRefName": self.head_ref_name,
            "headRefOid": self.head_ref_oid,
            "baseRefName": self.base_ref_name,
            "isCrossRepository": self.is_cross_repository,
            "trusted": self.trusted,
            "untrustedReasons": list(self.untrusted_reasons),
        }


@dataclass(frozen=True)
class WorktreeHandle:
    """Result yielded by :func:`checkout_pr_worktree`."""

    path: Path | None
    available: bool
    tree_id: str | None
    head_oid: str
    fetch_source: str | None
    submodules_initialized: bool
    reason: str | None = None


def _scrubbed_git_env() -> dict[str, str]:
    """Return process env without git repo/worktree override variables."""
    return {k: v for k, v in os.environ.items() if k not in _GIT_ENV_OVERRIDES}


def _run_git_or_gh(
    argv: list[str],
    *,
    cwd: Path,
    timeout: float = checks.MAX_COMMAND_TIMEOUT_S,
    max_stdout_bytes: int = checks.MAX_COMMAND_STDOUT_BYTES,
) -> bytes:
    try:
        return checks._run_command(
            argv,
            cwd=cwd,
            timeout=timeout,
            max_stdout_bytes=max_stdout_bytes,
            env=_scrubbed_git_env(),
        )
    except checks.ChecksError as exc:
        raise TrustError(str(exc)) from exc


def _validate_single_git_ref(ref: Any, *, label: str = "ref") -> str:
    try:
        cleaned = checks.validate_git_ref_or_range(ref)
    except checks.ChecksError as exc:
        raise TrustError(f"{label}: {exc}") from exc
    if ".." in cleaned:
        raise TrustError(
            f"{label}: expected single git ref without '..' "
            f"(got {checks.safe_error_text(cleaned)})"
        )
    return cleaned


def _validate_tree_id_value(tree_id: Any) -> str:
    errors: list[str] = []
    if not findings._validate_tree_id(tree_id, "treeId", errors):
        raise TrustError(errors[0])
    return str(tree_id)


def _validate_run_id_value(run_id: Any) -> str:
    if not isinstance(run_id, str) or not findings._TREE_ID_RE.match(run_id):
        raise TrustError(
            f"runId: must be a safe single-segment identifier "
            f"(got {checks.safe_error_text(run_id)})"
        )
    return run_id


def _reject_symlink(path: Path, *, label: str) -> None:
    try:
        st = path.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise TrustError(
            f"cannot inspect {label}: {checks.safe_error_text(exc)}"
        ) from exc
    if stat.S_ISLNK(st.st_mode):
        raise TrustError(f"{label} must not be a symlink")


def _validate_path_string(raw_path: str | Path, *, label: str) -> str:
    raw = os.fspath(raw_path) if isinstance(raw_path, Path) else raw_path
    if not isinstance(raw, str) or not raw.strip():
        raise TrustError(f"{label} must be a non-empty path")
    if findings._has_control_char(raw) or findings._has_surrogate(raw):
        raise TrustError(f"{label} contains invalid control characters or surrogates")
    return raw


def _safe_resolve(path: Path, *, label: str) -> Path:
    try:
        return path.resolve()
    except (OSError, RuntimeError) as exc:
        raise TrustError(
            f"cannot resolve {label}: {checks.safe_error_text(exc)}"
        ) from exc


def _ensure_safe_dir_tree(
    root: Path,
    parts: tuple[str, ...],
    *,
    label: str,
    exclusive_leaf: bool = False,
) -> Path:
    """Create ``parts`` under ``root`` while refusing any symlink component.

    With ``exclusive_leaf``, the last segment must not exist yet.
    """
    _reject_symlink(root, label=label)
    if root.exists() and not root.is_dir():
        raise TrustError(f"{label} is not a directory")
    try:
        root.mkdir(parents=True, exist_ok=True)
        cur = root
        for idx, segment in enumerate(parts):
            cur = cur / segment
            _reject_symlink(cur, label=f"{label}/{segment}")
            if cur.exists() and not cur.is_dir():
                raise TrustError(f"{label}/{segment} is not a directory")
            if exclusive_leaf and idx == len(parts) - 1:
                try:
                    cur.mkdir(exist_ok=False)
                except FileExistsError:
                    raise TrustError(
                        f"{label}/{checks.safe_error_text(segment)} already exists"
                    ) from None
            else:
                cur.mkdir(exist_ok=True)
    except (OSError, RuntimeError) as exc:
        raise TrustError(
            f"cannot prepare {label} directory: {checks.safe_error_text(exc)}"
        ) from exc
    resolved_root = _safe_resolve(root, label=label)
    resolved_cur = _safe_resolve(cur, label=label)
    if not resolved_cur.is_relative_to(resolved_root):
        raise TrustError(f"{label} escapes base directory")
    return resolved_cur


def _validate_external_path(
    raw_path: str | Path,
    resolved_repo: Path,
    raw_repo_root: str | Path,
    *,
    label: str,
) -> tuple[Path, Path]:
    """Validate an external path, reject symlinks, and keep it outside repo."""
    raw = _validate_path_string(raw_path, label=label)
    candidate = Path(raw)
    _reject_symlink(candidate, label=label)
    resolved_candidate = _safe_resolve(candidate, label=label)
    abs_candidate = Path(os.path.abspath(candidate))
    abs_repo = Path(os.path.abspath(raw_repo_root))
    if (
        resolved_candidate.is_relative_to(resolved_repo)
        or abs_candidate.is_relative_to(resolved_repo)
        or abs_candidate.is_relative_to(abs_repo)
    ):
        raise TrustError(f"{label} must reside outside the reviewed repository")
    return candidate, resolved_candidate


def _atomic_write_bytes(out_path: Path, data: bytes) -> None:
    """Atomically write ``data`` to ``out_path`` via a sibling tempfile."""
    raw_str = os.fspath(out_path)
    if (
        not raw_str.strip()
        or findings._has_control_char(raw_str)
        or findings._has_surrogate(raw_str)
    ):
        raise TrustError("invalid output file path")
    _reject_symlink(out_path, label=checks.safe_error_text(out_path.name or "output"))
    if out_path.exists() and out_path.is_dir():
        raise TrustError("output path must not be a directory")
    tmp_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=out_path.parent,
            prefix=".vld8-tmp-",
            suffix=".tmp",
            delete=False,
        ) as handle:
            tmp_name = handle.name
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, out_path)
        tmp_name = None
    except OSError as exc:
        raise TrustError(
            f"cannot write output file: {checks.safe_error_text(exc)}"
        ) from exc
    finally:
        if tmp_name is not None:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass


def atomic_write_text(out_path: Path, text: str) -> None:
    """Atomically write UTF-8 text to ``out_path``."""
    if not isinstance(text, str):
        raise TrustError(f"expected str content, got {type(text).__name__}")
    if "\x00" in text or findings._has_surrogate(text):
        raise TrustError("output text must not contain NUL bytes or surrogates")
    _atomic_write_bytes(out_path, text.encode("utf-8"))


def atomic_write_json(out_path: Path, data: Any) -> None:
    """Atomically write deterministic formatted camelCase JSON to ``out_path``."""
    try:
        rendered = (
            json.dumps(
                data,
                indent=2,
                sort_keys=True,
                ensure_ascii=False,
                allow_nan=False,
            )
            + "\n"
        )
    except (TypeError, ValueError, RecursionError) as exc:
        raise TrustError(
            f"cannot serialize JSON output: {checks.safe_error_text(exc)}"
        ) from exc
    atomic_write_text(out_path, rendered)


def resolve_state_dir(
    repo_root: str | Path,
    state_dir: str | Path | None = None,
) -> Path:
    """Resolve external state directory (``<git-common-dir>/vld8`` by default).

    When ``--state-dir`` is provided explicitly, rejects symlinks and rejects
    any path inside ``repo_root`` so review state never lands in the worktree.
    """
    try:
        resolved_repo, _ = checks.resolve_repo_root(repo_root)
    except checks.ChecksError as exc:
        raise TrustError(str(exc)) from exc

    if state_dir is None:
        raw_out = _run_git_or_gh(
            [
                "git",
                "-C",
                str(resolved_repo),
                "rev-parse",
                "--path-format=absolute",
                "--git-common-dir",
            ],
            cwd=resolved_repo,
        )
        common_str = raw_out.decode("utf-8", errors="replace").strip()
        if not common_str:
            raise TrustError("git rev-parse --git-common-dir returned empty output")
        common_path = Path(common_str)
        raw_common = (
            common_path if common_path.is_absolute() else resolved_repo / common_path
        )
        _reject_symlink(raw_common, label="git-common-dir")
        resolved_common = _safe_resolve(raw_common, label="git-common-dir")
        target = resolved_common / "vld8"
        _reject_symlink(target, label="state-dir")
        return target

    _, resolved_explicit = _validate_external_path(
        state_dir, resolved_repo, repo_root, label="state-dir"
    )
    return resolved_explicit


def prepare_run_dir(
    state_dir: str | Path,
    tree_id: str,
    run_id: str | None = None,
    *,
    exclusive: bool = False,
) -> Path:
    """Create ``<state-dir>/runs/<treeId>/<runId>/`` safely.

    With ``exclusive``, refuse a run directory that already exists, so two runs
    never share an output directory.
    """
    raw_state = _validate_path_string(state_dir, label="state-dir")
    clean_tree_id = _validate_tree_id_value(tree_id)
    clean_run_id = (
        secrets.token_hex(8) if run_id is None else _validate_run_id_value(run_id)
    )
    base = Path(raw_state)
    return _ensure_safe_dir_tree(
        base,
        ("runs", clean_tree_id, clean_run_id),
        label="state-dir",
        exclusive_leaf=exclusive,
    )


def compute_tree_id(repo_root: str | Path, ref: str = "HEAD") -> str:
    """Resolve the git tree OID for ``ref`` as the reviewed ``treeId``."""
    try:
        resolved_repo, _ = checks.resolve_repo_root(repo_root)
    except checks.ChecksError as exc:
        raise TrustError(str(exc)) from exc
    clean_ref = _validate_single_git_ref(ref, label="tree ref")
    out = _run_git_or_gh(
        [
            "git",
            "-C",
            str(resolved_repo),
            "rev-parse",
            "--verify",
            f"{clean_ref}^{{tree}}",
        ],
        cwd=resolved_repo,
    )
    tree_oid = out.decode("utf-8", errors="replace").strip()
    if not checks._GIT_OID_RE.match(tree_oid):
        raise TrustError(f"unexpected git tree OID: {checks.safe_error_text(tree_oid)}")
    return tree_oid


def _loads_strict_json_object(raw: bytes, *, source_label: str) -> dict[str, Any]:
    """Decode UTF-8 and parse a strict JSON object rejecting duplicate keys/NaN."""
    try:
        data = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=findings._reject_duplicate_keys,
            parse_constant=findings._reject_json_constant,
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
        ValueError,
    ) as exc:
        raise TrustError(
            f"invalid JSON from {source_label}: {checks.safe_error_text(exc)}"
        ) from exc
    if not isinstance(data, dict):
        raise TrustError(f"{source_label} output must be a JSON object")
    return data


def _is_bot_author(author: Any) -> tuple[str, bool]:
    if author is None:
        return "", False
    if not isinstance(author, dict):
        raise TrustError("gh pr view author must be a JSON object")
    login_raw = author.get("login")
    login = login_raw if isinstance(login_raw, str) else ""
    if findings._has_control_char(login) or findings._has_surrogate(login):
        raise TrustError("PR author login contains unsafe characters")
    is_bot_flag = author.get("is_bot") is True
    author_type = author.get("type")
    bot_by_type = isinstance(author_type, str) and author_type.lower() == "bot"
    bot_by_login = login.endswith("[bot]") or login.startswith("app/")
    return login, bool(is_bot_flag or bot_by_type or bot_by_login)


def fetch_pr_metadata(
    repo_root: str | Path,
    pr_number: int,
    *,
    force_untrusted: bool = False,
) -> PRMetadata:
    """Fetch PR metadata via ``gh pr view`` and determine trust status."""
    try:
        resolved_repo, _ = checks.resolve_repo_root(repo_root)
        valid_pr = checks.validate_pr_number(pr_number)
    except checks.ChecksError as exc:
        raise TrustError(str(exc)) from exc

    raw = _run_git_or_gh(
        [
            "gh",
            "pr",
            "view",
            str(valid_pr),
            "--json",
            "number,title,body,url,author,headRefName,headRefOid,baseRefName,"
            "isCrossRepository",
        ],
        cwd=resolved_repo,
    )
    data = _loads_strict_json_object(raw, source_label="gh pr view")
    required = (
        "number",
        "title",
        "body",
        "url",
        "author",
        "headRefName",
        "headRefOid",
        "baseRefName",
        "isCrossRepository",
    )
    for field in required:
        if field not in data:
            raise TrustError(f"gh pr view output missing required field {field}")

    number_val = data["number"]
    if not findings._is_strict_int(number_val) or number_val != valid_pr:
        raise TrustError("gh pr view returned mismatched PR number")

    title = data["title"]
    body = data["body"]
    url = data["url"]
    if (
        not isinstance(title, str)
        or findings._has_control_char(title)
        or findings._has_surrogate(title)
    ):
        raise TrustError("gh pr view title is invalid")
    if not isinstance(body, str) or "\x00" in body or findings._has_surrogate(body):
        raise TrustError("gh pr view body is invalid")
    body = report._sanitize_text(body, allow_newlines=True)
    if (
        not isinstance(url, str)
        or not url.startswith("https://")
        or len(url) > MAX_REMOTE_URL_LENGTH
        or findings._has_control_char(url)
        or findings._has_surrogate(url)
        or any(ch.isspace() for ch in url)
    ):
        raise TrustError("gh pr view url must be a safe https:// URL")
    try:
        parsed_url = urlsplit(url)
    except ValueError as exc:
        raise TrustError("gh pr view url must be a safe https:// URL") from exc
    if (
        parsed_url.scheme != "https"
        or not parsed_url.hostname
        or parsed_url.hostname.startswith("-")
        or parsed_url.username is not None
        or parsed_url.password is not None
    ):
        raise TrustError("gh pr view url must be a safe https:// URL")

    head_oid = data["headRefOid"]
    if not isinstance(head_oid, str) or not checks._GIT_OID_RE.match(head_oid):
        raise TrustError("gh pr view headRefOid must be a 40-64 char hex OID")

    head_ref = _validate_single_git_ref(data["headRefName"], label="headRefName")
    base_ref = _validate_single_git_ref(data["baseRefName"], label="baseRefName")

    cross_repo = data["isCrossRepository"]
    if not isinstance(cross_repo, bool):
        raise TrustError("gh pr view isCrossRepository must be a boolean")

    author_login, author_is_bot = _is_bot_author(data["author"])

    reasons: list[str] = []
    if cross_repo:
        reasons.append("fork")
    if author_is_bot:
        reasons.append("bot")
    if force_untrusted:
        reasons.append("forced-untrusted")
    trusted = not reasons

    return PRMetadata(
        number=valid_pr,
        title=title,
        body=body,
        url=url,
        author_login=author_login,
        author_is_bot=author_is_bot,
        head_ref_name=head_ref,
        head_ref_oid=head_oid,
        base_ref_name=base_ref,
        is_cross_repository=cross_repo,
        trusted=trusted,
        untrusted_reasons=tuple(reasons),
    )


def _is_safe_git_fetch_url(url: str) -> bool:
    if (
        not isinstance(url, str)
        or not url
        or len(url) > MAX_REMOTE_URL_LENGTH
        or url.startswith("-")
        or findings._has_control_char(url)
        or findings._has_surrogate(url)
        or any(ch.isspace() for ch in url)
    ):
        return False
    if url.startswith(("https://", "ssh://")):
        try:
            parsed = urlsplit(url)
        except ValueError:
            return False
        if (
            not parsed.hostname
            or parsed.hostname.startswith("-")
            or parsed.password is not None
        ):
            return False
        if parsed.scheme == "https" and parsed.username is not None:
            return False
        if (
            parsed.scheme == "ssh"
            and parsed.username is not None
            and parsed.username.startswith("-")
        ):
            return False
        return True
    if _SSH_SCP_URL_RE.match(url) is None:
        return False
    scp_path = url.split(":", 1)[1]
    if scp_path.startswith("-") or ".." in scp_path.split("/"):
        return False
    return True


def _try_fetch_pr_ref(
    repo_root: Path,
    remote_or_url: str,
    pr_number: int,
    expected_oid: str,
) -> tuple[bool, str | None]:
    if (
        not isinstance(remote_or_url, str)
        or not remote_or_url
        or remote_or_url.startswith("-")
        or findings._has_control_char(remote_or_url)
        or findings._has_surrogate(remote_or_url)
        or any(ch.isspace() for ch in remote_or_url)
    ):
        return False, "invalid git remote or URL"
    refspec = f"pull/{pr_number}/head"
    try:
        _run_git_or_gh(
            ["git", "-C", str(repo_root), "fetch", "--no-tags", remote_or_url, refspec],
            cwd=repo_root,
        )
        out = _run_git_or_gh(
            ["git", "-C", str(repo_root), "rev-parse", "--verify", "FETCH_HEAD"],
            cwd=repo_root,
        )
    except TrustError as exc:
        return False, str(exc)
    fetched_oid = out.decode("utf-8", errors="replace").strip()
    if fetched_oid != expected_oid:
        return (
            False,
            f"FETCH_HEAD ({checks.safe_error_text(fetched_oid)}) "
            f"did not match headRefOid ({expected_oid})",
        )
    return True, None


def _resolve_gh_repo_url(repo_root: Path) -> str | None:
    use_ssh = False
    try:
        origin_raw = _run_git_or_gh(
            ["git", "-C", str(repo_root), "remote", "get-url", "origin"],
            cwd=repo_root,
        )
        origin_url = origin_raw.decode("utf-8", errors="replace").strip()
        use_ssh = origin_url.startswith("git@") or origin_url.startswith("ssh://")
    except TrustError:
        use_ssh = False

    view_raw = _run_git_or_gh(
        ["gh", "repo", "view", "--json", "url,sshUrl"],
        cwd=repo_root,
    )
    data = _loads_strict_json_object(view_raw, source_label="gh repo view")
    chosen = data.get("sshUrl") if use_ssh else data.get("url")
    if not isinstance(chosen, str) or not chosen:
        chosen = data.get("url") or data.get("sshUrl")
    if isinstance(chosen, str) and _is_safe_git_fetch_url(chosen):
        return chosen
    return None


def _fetch_pr_head(
    repo_root: Path,
    pr_number: int,
    expected_oid: str,
) -> tuple[bool, str | None, str | None]:
    """Fetch PR head using #108 chain (origin -> upstream -> gh resolved URL)."""
    failures: list[str] = []

    ok, err = _try_fetch_pr_ref(repo_root, "origin", pr_number, expected_oid)
    if ok:
        return True, "origin", None
    if err:
        failures.append(f"origin: {err}")

    try:
        _run_git_or_gh(
            ["git", "-C", str(repo_root), "remote", "get-url", "upstream"],
            cwd=repo_root,
        )
        ok, err = _try_fetch_pr_ref(repo_root, "upstream", pr_number, expected_oid)
        if ok:
            return True, "upstream", None
        if err:
            failures.append(f"upstream: {err}")
    except TrustError:
        pass

    try:
        gh_url = _resolve_gh_repo_url(repo_root)
    except TrustError as exc:
        failures.append(f"gh-repo: {exc}")
        gh_url = None
    if gh_url is not None:
        ok, err = _try_fetch_pr_ref(repo_root, gh_url, pr_number, expected_oid)
        if ok:
            return True, "gh-url", None
        if err:
            failures.append(f"gh-url: {err}")

    reason = "; ".join(failures) if failures else "could not fetch PR headRefOid"
    return False, None, reason


@contextmanager
def checkout_pr_worktree(
    repo_root: str | Path,
    meta: PRMetadata,
    *,
    checkout: bool = True,
) -> Iterator[WorktreeHandle]:
    """Check out ``meta.head_ref_oid`` into an isolated temporary worktree.

    Never falls back to the user's checkout when fetch fails, initializes
    submodules only for trusted same-repo PRs, and guarantees cleanup on exit.
    With ``checkout=False`` the worktree is added with ``--no-checkout``: no
    files are written, so no checkout filters or hooks run on the PR's content
    and no submodules are initialized. Callers then read git objects only.
    """
    try:
        resolved_repo, _ = checks.resolve_repo_root(repo_root)
        valid_pr = checks.validate_pr_number(meta.number)
    except checks.ChecksError as exc:
        raise TrustError(str(exc)) from exc

    if not checks._GIT_OID_RE.match(meta.head_ref_oid):
        raise TrustError("PRMetadata head_ref_oid is invalid")

    fetched, source, fetch_err = _fetch_pr_head(
        resolved_repo, valid_pr, meta.head_ref_oid
    )
    if not fetched:
        yield WorktreeHandle(
            path=None,
            available=False,
            tree_id=None,
            head_oid=meta.head_ref_oid,
            fetch_source=None,
            submodules_initialized=False,
            reason=fetch_err,
        )
        return

    tmp_root = tempfile.mkdtemp(prefix="vld8-wt-")
    submodules_ok = False
    reason: str | None = None
    added = False
    wt_dir: Path | None = None

    try:
        wt_dir = _safe_resolve(Path(tmp_root), label="worktree") / "tree"
        try:
            subprocess.run(
                ["git", "-C", str(resolved_repo), "worktree", "prune"],
                env=_scrubbed_git_env(),
                capture_output=True,
                check=False,
                timeout=checks.MAX_COMMAND_TIMEOUT_S,
            )
        except OSError, subprocess.SubprocessError:
            pass
        try:
            _run_git_or_gh(
                [
                    "git",
                    "-C",
                    str(resolved_repo),
                    "worktree",
                    "add",
                    "--detach",
                    *([] if checkout else ["--no-checkout"]),
                    str(wt_dir),
                    meta.head_ref_oid,
                ],
                cwd=resolved_repo,
            )
            added = True
        except TrustError as exc:
            yield WorktreeHandle(
                path=None,
                available=False,
                tree_id=None,
                head_oid=meta.head_ref_oid,
                fetch_source=source,
                submodules_initialized=False,
                reason=str(exc),
            )
            return

        tree_id = compute_tree_id(wt_dir, meta.head_ref_oid)
        if (
            checkout
            and can_run_repo_tools(meta.trusted)
            and meta.is_cross_repository is False
            and meta.author_is_bot is False
        ):
            try:
                status_raw = _run_git_or_gh(
                    ["git", "-C", str(wt_dir), "submodule", "status"],
                    cwd=wt_dir,
                )
                if status_raw.strip():
                    _run_git_or_gh(
                        [
                            "git",
                            "-C",
                            str(wt_dir),
                            "submodule",
                            "update",
                            "--init",
                            "--recursive",
                        ],
                        cwd=wt_dir,
                    )
                    submodules_ok = True
            except TrustError as exc:
                reason = f"submodule init skipped: {exc}"

        yield WorktreeHandle(
            path=wt_dir,
            available=True,
            tree_id=tree_id,
            head_oid=meta.head_ref_oid,
            fetch_source=source,
            submodules_initialized=submodules_ok,
            reason=reason,
        )
    finally:
        if added:
            try:
                subprocess.run(
                    [
                        "git",
                        "-C",
                        str(resolved_repo),
                        "worktree",
                        "remove",
                        "--force",
                        str(wt_dir),
                    ],
                    env=_scrubbed_git_env(),
                    capture_output=True,
                    check=False,
                    timeout=checks.MAX_COMMAND_TIMEOUT_S,
                )
            except OSError, subprocess.SubprocessError:
                pass
        shutil.rmtree(tmp_root, ignore_errors=True)
        try:
            subprocess.run(
                ["git", "-C", str(resolved_repo), "worktree", "prune"],
                env=_scrubbed_git_env(),
                capture_output=True,
                check=False,
                timeout=checks.MAX_COMMAND_TIMEOUT_S,
            )
        except OSError, subprocess.SubprocessError:
            pass


def _parse_toml_bytes(raw: bytes, *, source_label: str) -> dict[str, Any]:
    try:
        return tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError, RecursionError) as exc:
        raise TrustError(
            f"invalid TOML in {source_label}: {checks.safe_error_text(exc)}"
        ) from exc


def load_trusted_file(
    repo_root: str | Path,
    *,
    base_ref: str | None = None,
    external_path: str | Path | None = None,
    rel_path: str | None = None,
    max_bytes: int = MAX_CONFIG_BYTES,
    label: str = "trusted file",
) -> tuple[bytes | None, dict[str, Any]]:
    """Read raw config, pack, query, or command spec from base_ref or external_path."""
    if (base_ref is None) == (external_path is None):
        raise TrustError("exactly one of base_ref or external_path must be specified")
    try:
        resolved_repo, _ = checks.resolve_repo_root(repo_root)
    except checks.ChecksError as exc:
        raise TrustError(str(exc)) from exc

    if external_path is not None:
        ext_path, _ = _validate_external_path(
            external_path,
            resolved_repo,
            repo_root,
            label=label,
        )
        try:
            raw = checks._read_explicit_regular_file(
                ext_path, max_bytes=max_bytes, label=label
            )
        except checks.ChecksError as exc:
            raise TrustError(str(exc)) from exc
        return raw, {
            "source": "external",
            "ref": None,
            "path": checks.safe_error_text(ext_path.name or label),
        }

    if rel_path is None:
        raise TrustError(f"rel_path is required when reading {label} from base_ref")
    try:
        clean_rel = checks.validate_repo_relative_path(rel_path)
    except checks.ChecksError as exc:
        raise TrustError(str(exc)) from exc
    git_ref = _validate_single_git_ref(base_ref, label="baseRef")
    try:
        raw_git = checks._read_git_tree_regular_file(
            resolved_repo,
            git_ref,
            clean_rel,
            max_bytes=max_bytes,
            raise_on_oversized=True,
            env=_scrubbed_git_env(),
        )
    except checks.ChecksError as exc:
        raise TrustError(str(exc)) from exc
    if raw_git is None:
        return None, {
            "source": "default",
            "ref": git_ref,
            "path": None,
        }
    return raw_git, {
        "source": "base-ref",
        "ref": git_ref,
        "path": clean_rel,
    }


def load_trusted_config(
    repo_root: str | Path,
    *,
    base_ref: str | None = None,
    external_config: str | Path | None = None,
    config_rel_path: str = ".vld8.toml",
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Load TOML configuration strictly from an external path or trusted git base ref.

    Never reads working-tree files or defaults implicitly to ``HEAD``; callers
    must pass ``base_ref`` or ``external_config``.
    """
    raw, prov = load_trusted_file(
        repo_root,
        base_ref=base_ref,
        external_path=external_config,
        rel_path=config_rel_path,
        max_bytes=MAX_CONFIG_BYTES,
        label="trusted config",
    )
    if raw is None:
        return {}, prov
    source_label = (
        "external config"
        if prov["source"] == "external"
        else f"{prov['path']} at {prov['ref']}"
    )
    return _parse_toml_bytes(raw, source_label=source_label), prov


def _validate_dest_dir(
    dest_dir: str | Path,
    resolved_repo: Path,
    raw_repo_root: str | Path,
) -> Path:
    """Allow external dest dirs or validated ``<git-common-dir>/vld8/runs/...``."""
    raw = _validate_path_string(dest_dir, label="dest-dir")
    dest_path = Path(raw)
    _reject_symlink(dest_path, label="dest-dir")
    resolved_dest = _safe_resolve(dest_path, label="dest-dir")
    abs_dest = Path(os.path.abspath(dest_path))
    abs_repo = Path(os.path.abspath(raw_repo_root))
    in_repo = (
        resolved_dest.is_relative_to(resolved_repo)
        or abs_dest.is_relative_to(resolved_repo)
        or abs_dest.is_relative_to(abs_repo)
    )
    if not in_repo:
        return resolved_dest

    default_state_dir = resolve_state_dir(resolved_repo, state_dir=None)
    runs_dir = default_state_dir / "runs"
    _reject_symlink(runs_dir, label="runs-dir")
    runs_root = _safe_resolve(runs_dir, label="runs-dir")
    if not resolved_dest.is_relative_to(runs_root):
        raise TrustError(
            "dest-dir must reside outside repo_root or under <git-common-dir>/vld8/runs"
        )

    runs_anc = next(
        (
            cand
            for cand in (abs_dest, *abs_dest.parents)
            if _safe_resolve(cand, label="dest-dir") == runs_root
        ),
        None,
    )
    if runs_anc is None or len(runs_anc.parts) < 3:
        raise TrustError(
            "dest-dir must reside outside repo_root or under <git-common-dir>/vld8/runs"
        )
    vld8_anc = runs_anc.parent
    common_anc = vld8_anc.parent
    _reject_symlink(runs_anc, label="runs-dir")
    _reject_symlink(vld8_anc, label="state-dir")
    _reject_symlink(common_anc, label="git-common-dir")
    if (
        _safe_resolve(vld8_anc, label="state-dir") != runs_root.parent
        or _safe_resolve(common_anc, label="git-common-dir") != runs_root.parent.parent
    ):
        raise TrustError("dest-dir traverses invalid state-dir components")
    repo_anc = common_anc.parent
    if _safe_resolve(repo_anc, label="repo") == resolved_repo and (
        (repo_anc != abs_repo and repo_anc.is_relative_to(abs_repo))
        or (repo_anc != resolved_repo and repo_anc.is_relative_to(resolved_repo))
    ):
        raise TrustError("dest-dir traverses invalid repository subpath")

    cur = runs_anc
    for segment in abs_dest.relative_to(runs_anc).parts:
        cur = cur / segment
        _reject_symlink(cur, label=f"dest-dir/{segment}")
    return resolved_dest


def extract_base_tool_config(
    repo_root: str | Path,
    base_ref: str,
    config_rel_path: str,
    dest_dir: str | Path,
) -> Path | None:
    """Extract a linter/analyzer config strictly from ``base_ref`` into ``dest_dir``."""
    try:
        resolved_repo, _ = checks.resolve_repo_root(repo_root)
        clean_rel = checks.validate_repo_relative_path(config_rel_path)
    except checks.ChecksError as exc:
        raise TrustError(str(exc)) from exc
    clean_base = _validate_single_git_ref(base_ref, label="baseRef")
    resolved_dest = _validate_dest_dir(dest_dir, resolved_repo, repo_root)

    try:
        raw = checks._read_git_tree_regular_file(
            resolved_repo,
            clean_base,
            clean_rel,
            max_bytes=MAX_CONFIG_BYTES,
            raise_on_oversized=True,
            env=_scrubbed_git_env(),
        )
    except checks.ChecksError as exc:
        raise TrustError(str(exc)) from exc
    if raw is None:
        return None

    parts = clean_rel.split("/")
    parent_dir = _ensure_safe_dir_tree(
        resolved_dest, tuple(parts[:-1]), label="dest-dir"
    )
    out_file = parent_dir / parts[-1]
    _atomic_write_bytes(out_file, raw)
    return out_file


def _parse_sarif_evidence(
    data: dict[str, Any],
) -> tuple[Any, list[str], list[Any], bool]:
    version = data.get("version")
    if version != "2.1.0":
        raise TrustError(
            f"evidence SARIF version must be '2.1.0', got "
            f"{checks.safe_error_text(version)}"
        )
    runs = data.get("runs")
    if not isinstance(runs, list):
        raise TrustError("evidence SARIF runs must be an array")
    if len(runs) > MAX_SARIF_RUNS:
        raise TrustError(f"evidence SARIF runs exceed max {MAX_SARIF_RUNS}")

    top_tree_id: Any = None
    has_top_tree_id = False
    top_props = data.get("properties")
    if isinstance(top_props, dict) and "treeId" in top_props:
        top_tree_id = top_props.get("treeId")
        has_top_tree_id = True

    tools: list[str] = []
    results_out: list[dict[str, Any]] = []
    run_tree_ids: list[Any] = []
    execution_failed = False
    for idx, run in enumerate(runs):
        if not isinstance(run, dict):
            raise TrustError(f"evidence SARIF runs[{idx}] must be an object")
        run_props = run.get("properties")
        if isinstance(run_props, dict) and "treeId" in run_props:
            run_tree_ids.append(run_props.get("treeId"))
        raw_invocations = run.get("invocations")
        if raw_invocations is not None:
            if not isinstance(raw_invocations, list):
                raise TrustError(
                    f"evidence SARIF runs[{idx}].invocations must be an array"
                )
            if len(raw_invocations) > MAX_EVIDENCE_ITEMS:
                raise TrustError(
                    f"evidence SARIF runs[{idx}].invocations exceed max "
                    f"{MAX_EVIDENCE_ITEMS}"
                )
            for inv_idx, inv in enumerate(raw_invocations):
                if not isinstance(inv, dict):
                    raise TrustError(
                        f"evidence SARIF runs[{idx}].invocations[{inv_idx}] "
                        "must be an object"
                    )
                if "executionSuccessful" not in inv:
                    execution_failed = True
                else:
                    exec_ok = inv["executionSuccessful"]
                    if not isinstance(exec_ok, bool):
                        raise TrustError(
                            f"evidence SARIF runs[{idx}].invocations[{inv_idx}]."
                            "executionSuccessful must be a boolean"
                        )
                    if exec_ok is False:
                        execution_failed = True
        driver = (
            run.get("tool", {}).get("driver", {})
            if isinstance(run.get("tool"), dict)
            else {}
        )
        driver_name = driver.get("name") if isinstance(driver, dict) else None
        if isinstance(driver_name, str) and driver_name.strip():
            tools.append(checks.safe_error_text(driver_name.strip(), max_len=128))
        raw_results = run.get("results", [])
        if not isinstance(raw_results, list):
            raise TrustError(f"evidence SARIF runs[{idx}].results must be an array")
        if len(results_out) + len(raw_results) > MAX_EVIDENCE_ITEMS:
            raise TrustError(f"evidence SARIF results exceed max {MAX_EVIDENCE_ITEMS}")
        for entry in raw_results:
            if not isinstance(entry, dict):
                raise TrustError("evidence SARIF result entry must be an object")
            rule_id = entry.get("ruleId")
            if rule_id is not None and not isinstance(rule_id, str):
                raise TrustError("evidence SARIF result ruleId must be a string")
            level = entry.get("level")
            if level is not None and not isinstance(level, str):
                raise TrustError("evidence SARIF result level must be a string")
            msg_obj = entry.get("message")
            msg_text = msg_obj.get("text") if isinstance(msg_obj, dict) else None
            results_out.append(
                {
                    "ruleId": (
                        checks.safe_error_text(rule_id, max_len=128)
                        if rule_id is not None
                        else None
                    ),
                    "level": (
                        checks.safe_error_text(level, max_len=32)
                        if level is not None
                        else None
                    ),
                    "message": (
                        checks.safe_error_text(msg_text, max_len=512)
                        if isinstance(msg_text, str)
                        else None
                    ),
                }
            )

    if any(not isinstance(val, str) for val in run_tree_ids):
        raise TrustError("evidence SARIF run treeId must be a string")
    if has_top_tree_id and not isinstance(top_tree_id, str):
        raise TrustError("evidence SARIF properties.treeId must be a string")
    all_tree_ids = ([top_tree_id] if has_top_tree_id else []) + run_tree_ids
    if len(set(all_tree_ids)) > 1:
        raise TrustError(
            "evidence SARIF contains conflicting treeId values across runs"
        )
    if not has_top_tree_id and runs and len(run_tree_ids) != len(runs):
        tree_id = None
    else:
        tree_id = all_tree_ids[0] if all_tree_ids else None
    return tree_id, sorted(set(tools)), results_out, execution_failed


def _validate_bounded_str_list(raw_list: Any, *, label: str) -> list[str]:
    if not isinstance(raw_list, list) or len(raw_list) > MAX_EVIDENCE_ITEMS:
        raise TrustError(f"evidence {label} must be a bounded array")
    cleaned: list[str] = []
    for idx, item in enumerate(raw_list):
        if (
            not isinstance(item, str)
            or not item.strip()
            or len(item) > findings.MAX_IDENTIFIER_LENGTH
        ):
            raise TrustError(
                f"evidence {label}[{idx}] must be a bounded non-empty string"
            )
        if findings._has_control_char(item) or findings._has_surrogate(item):
            raise TrustError(f"evidence {label}[{idx}] contains unsafe characters")
        cleaned.append(item)
    return cleaned


def load_evidence(
    evidence_path: str | Path,
    *,
    expected_tree_id: str,
) -> dict[str, Any]:
    """Load ``--evidence`` JSON/SARIF and accept exclusions only on matching treeId."""
    clean_expected = _validate_tree_id_value(expected_tree_id)
    raw_ev_path = _validate_path_string(evidence_path, label="evidence file")
    ev_path = Path(raw_ev_path)
    try:
        raw = checks._read_explicit_regular_file(
            ev_path, max_bytes=MAX_EVIDENCE_BYTES, label="evidence file"
        )
    except checks.ChecksError as exc:
        raise TrustError(str(exc)) from exc

    data = _loads_strict_json_object(raw, source_label="evidence file")

    if "runs" in data:
        fmt = "sarif"
        tree_id, tools, sarif_results, execution_failed = _parse_sarif_evidence(data)
        exclusions: list[str] = []
        ev_findings: list[dict[str, Any]] = []
    else:
        fmt = "vld8"
        execution_failed = False
        unknown = sorted(set(data) - _EVIDENCE_DOC_KEYS)
        if unknown:
            shown = [checks.safe_error_text(key, max_len=64) for key in unknown[:5]]
            extra = f" (+{len(unknown) - 5} more)" if len(unknown) > 5 else ""
            raise TrustError(
                f"unknown keys in evidence object: {', '.join(shown)}{extra}"
            )
        sv = data.get("schemaVersion")
        if sv is not None and sv != SCHEMA_VERSION:
            raise TrustError(
                f"unsupported evidence schemaVersion {checks.safe_error_text(sv)}"
            )
        tree_id = data.get("treeId")
        if tree_id is not None and not isinstance(tree_id, str):
            raise TrustError("evidence treeId must be a string")
        tools = _validate_bounded_str_list(data.get("tools", []), label="tools")
        exclusions = _validate_bounded_str_list(
            data.get("exclusions", []), label="exclusions"
        )
        findings_raw = data.get("findings", [])
        if not isinstance(findings_raw, list) or len(findings_raw) > MAX_EVIDENCE_ITEMS:
            raise TrustError("evidence findings must be a bounded array")

        ev_findings = []
        for idx, item in enumerate(findings_raw):
            errs = findings.validate_finding(item, prefix=f"evidence.findings[{idx}]")
            if errs:
                preview = "; ".join(errs[:3])
                extra = f" (+{len(errs) - 3} more)" if len(errs) > 3 else ""
                raise TrustError(f"{preview}{extra}")
            if item["source"] != "code":
                raise TrustError(
                    f"evidence.findings[{idx}].source must be 'code', "
                    f"got {item['source']!r}"
                )
            ev_findings.append(item)
        sarif_results = []

    if fmt == "sarif" and execution_failed:
        got_label = (
            checks.safe_error_text(tree_id, max_len=128)
            if isinstance(tree_id, str)
            else None
        )
        return {
            "schemaVersion": SCHEMA_VERSION,
            "accepted": False,
            "format": fmt,
            "treeId": got_label,
            "expectedTreeId": clean_expected,
            "tools": [],
            "exclusions": [],
            "findings": [],
            "sarifResults": [],
            "reason": (
                "evidence SARIF includes an invocation without executionSuccessful=true"
            ),
        }

    if not isinstance(tree_id, str) or not tree_id or tree_id != clean_expected:
        got_label = (
            checks.safe_error_text(tree_id, max_len=128)
            if tree_id is not None
            else None
        )
        return {
            "schemaVersion": SCHEMA_VERSION,
            "accepted": False,
            "format": fmt,
            "treeId": got_label,
            "expectedTreeId": clean_expected,
            "tools": [],
            "exclusions": [],
            "findings": [],
            "sarifResults": [],
            "reason": (
                f"evidence treeId ({got_label!r}) does not match reviewed "
                f"treeId ({clean_expected!r})"
            ),
        }

    return {
        "schemaVersion": SCHEMA_VERSION,
        "accepted": True,
        "format": fmt,
        "treeId": clean_expected,
        "expectedTreeId": clean_expected,
        "tools": tools,
        "exclusions": exclusions,
        "findings": ev_findings,
        "sarifResults": sarif_results,
        "reason": None,
    }


def can_run_repo_tools(trusted: Any) -> bool:
    """Return True only when execution against the reviewed PR/repo is permitted."""
    return trusted is True


def run_trusted_command(
    argv: list[str],
    *,
    cwd: Path,
    trusted: bool,
    timeout: float = checks.MAX_COMMAND_TIMEOUT_S,
    max_stdout_bytes: int = checks.MAX_COMMAND_STDOUT_BYTES,
    max_stderr_bytes: int = checks.MAX_COMMAND_STDERR_BYTES,
) -> bytes:
    """Execute a tool/linter command only when ``trusted`` is True."""
    if not can_run_repo_tools(trusted):
        raise TrustError(
            "refusing to run repo tools or linters on untrusted PR (fork or bot)"
        )
    if (
        not isinstance(argv, list)
        or not argv
        or not all(isinstance(arg, str) for arg in argv)
    ):
        raise TrustError("command argv must be a non-empty list of strings")
    try:
        return checks._run_command(
            argv,
            cwd=cwd,
            timeout=timeout,
            max_stdout_bytes=max_stdout_bytes,
            max_stderr_bytes=max_stderr_bytes,
            env=_scrubbed_git_env(),
        )
    except checks.ChecksError as exc:
        raise TrustError(str(exc)) from exc
