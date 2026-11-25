"""Obtain a ``servicemap.json`` for a target repo.

The service map is the one input the deterministic installer cannot produce on
its own: building it is an agentic crawl that only Claude can run. This module
resolves a map by the best method available to the caller:

* ``reuse``  — an existing ``servicemap.json`` at the target root is used as-is.
* ``crawl``  — shell out to ``claude -p '/vld8-map ...'`` to run the
               crawl headlessly. Requires the ``claude`` CLI on PATH and the
               servicemap skill already installed in the target repo.
* ``skip``   — no map; the generators run with ``--no-service-map``.

The ``/vld8-setup`` skill never calls ``crawl`` here — Claude is already
running, so it does the crawl itself and then hands the resulting path to the
installer via ``service_map=``.
"""

import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from .paths import SERVICEMAP_FILE


@dataclass
class ServiceMapResult:
    path: Path | None  # resolved servicemap.json, or None if there is no map
    method: str        # "reuse" | "crawl" | "skip"
    note: str          # human-readable explanation for the install summary


def claude_available() -> bool:
    """True if the ``claude`` CLI is on PATH (needed for a headless crawl)."""
    return shutil.which("claude") is not None


def _existing_map(target: Path) -> Path | None:
    candidate = target / SERVICEMAP_FILE
    return candidate if candidate.is_file() else None


def acquire(
    target: Path,
    *,
    crawl: bool,
    service_map: Path | None = None,
    log=print,
) -> ServiceMapResult:
    """Resolve a service map for ``target``.

    ``service_map`` — an explicit path overrides discovery (used by the skill,
    which crawls first and passes the result straight through).
    ``crawl`` — when True and no map exists, run the headless ``claude -p`` crawl.
    """
    # Caller supplied a map explicitly (e.g. the /vld8-setup skill).
    if service_map is not None:
        resolved = service_map if service_map.is_absolute() else (target / service_map)
        if not resolved.is_file():
            raise FileNotFoundError(f"--service-map points at a missing file: {resolved}")
        return ServiceMapResult(resolved, "reuse", f"using supplied service map ({resolved})")

    # An existing map at the repo root is reused before considering a crawl.
    existing = _existing_map(target)
    if existing is not None:
        return ServiceMapResult(existing, "reuse", f"reusing existing {SERVICEMAP_FILE}")

    if not crawl:
        return ServiceMapResult(
            None, "skip",
            "no service map — generating map-less skills "
            "(run /vld8-map then re-run to add cross-service awareness)",
        )

    # --crawl was requested but there is no map: run the headless crawl.
    if not claude_available():
        raise RuntimeError(
            "--crawl needs the `claude` CLI on PATH, which was not found. "
            "Install Claude Code, omit --crawl to skip the map, or pass --service-map."
        )

    produced = _crawl(target, log=log)
    return ServiceMapResult(produced, "crawl", f"crawled service map via `claude -p` -> {produced}")


def _crawl(target: Path, *, log=print) -> Path:
    """Run ``/vld8-map`` headlessly via ``claude -p`` in ``target``.

    Assumes the servicemap skill has already been copied into the target repo
    (the installer copies the static skills before acquiring the map).
    """
    out = target / SERVICEMAP_FILE
    prompt = f"/vld8-map --path {SERVICEMAP_FILE}"
    log(f"  running headless crawl: claude -p {prompt!r} (this can take a while)…")
    try:
        subprocess.run(
            ["claude", "-p", prompt],
            cwd=str(target),
            check=True,
        )
    except subprocess.CalledProcessError as exc:  # pragma: no cover - depends on CLI
        raise RuntimeError(f"`claude -p` crawl failed (exit {exc.returncode}).") from exc

    if not out.is_file():
        raise RuntimeError(
            f"crawl finished but {out} was not produced. "
            "Run /vld8-map manually in Claude Code, then re-run with --service-map."
        )
    return out
