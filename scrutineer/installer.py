"""The shared, deterministic install core.

Given a target repo, this:

1. copies the static skills (servicemap, mcp, setup) into ``.claude/commands/``
   with their correct ``scrutineer-*`` names,
2. obtains a service map (see :mod:`scrutineer.servicemap`),
3. runs the peer-review and security-review generators against the repo,
   wiring in the service map when one is available.

Both front doors — the ``scrutineer`` CLI and the ``/scrutineer-setup`` skill —
call :func:`install`. The skill passes ``service_map=`` after doing its own
agentic crawl; the CLI lets :mod:`scrutineer.servicemap` resolve one.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

from . import paths, servicemap


def _default_log(msg: str = "") -> None:
    # Flush so our logs stay interleaved in order with subprocess (generator) output.
    print(msg, flush=True)


@dataclass
class InstallResult:
    target: Path
    installed: list[str] = field(default_factory=list)   # command files written
    service_map_note: str = ""
    skipped_crawl: bool = False


def _commands_dir(target: Path) -> Path:
    return target / ".claude" / "commands"


def _copy_skill(src: Path, dest: Path, *, force: bool, log) -> bool:
    if dest.exists() and not force:
        log(f"  skip {dest.name} (exists; pass --force to overwrite)")
        return False
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(src, dest)
    log(f"  ✓ copied {dest.name}")
    return True


def _run_generator(
    generator: Path,
    target: Path,
    output_rel: str,
    sm: servicemap.ServiceMapResult,
    *,
    force: bool,
    log,
) -> bool:
    cmd = [sys.executable, str(generator), str(target), "--output", output_rel]
    if sm.path is not None:
        cmd += ["--service-map", str(sm.path)]
    else:
        cmd += ["--no-service-map"]
    if force:
        cmd += ["--force"]
    log(f"  running {generator.parent.name} → {output_rel}")
    result = subprocess.run(cmd)
    if result.returncode != 0:
        log(f"  ✗ {generator.parent.name} failed (exit {result.returncode})")
        return False
    return True


def install(
    target: Path | str,
    *,
    crawl: bool = False,
    service_map: Path | str | None = None,
    force: bool = False,
    log=_default_log,
) -> InstallResult:
    """Install the full Scrutineer skill set into ``target``.

    Parameters
    ----------
    target
        Repo to install the review skills into.
    crawl
        If no service map exists, run a headless ``claude -p`` crawl to make one.
    service_map
        Explicit path to an existing service map (overrides discovery/crawl).
        The ``/scrutineer-setup`` skill passes the map it just crawled here.
    force
        Overwrite existing command files / service map.
    """
    target = Path(target).resolve()
    if not target.is_dir():
        raise NotADirectoryError(f"target repo is not a directory: {target}")

    missing = paths.missing_assets()
    if missing:
        listed = "\n  ".join(str(p) for p in missing)
        raise FileNotFoundError(
            "Scrutineer toolkit assets are missing — is the package intact?\n  " + listed
        )

    result = InstallResult(target=target)
    cmd_dir = _commands_dir(target)

    # 1. Copy the static skills first — the servicemap skill must be present
    #    before a headless crawl can invoke /scrutineer-servicemap.
    log("Copying static skills…")
    if _copy_skill(paths.SERVICEMAP_SKILL, cmd_dir / paths.SERVICEMAP_COMMAND, force=force, log=log):
        result.installed.append(paths.SERVICEMAP_COMMAND)
    if _copy_skill(paths.MCP_SKILL, cmd_dir / paths.MCP_COMMAND, force=force, log=log):
        result.installed.append(paths.MCP_COMMAND)
    # The setup skill too, so a pip-only install can later re-crawl the map and
    # regenerate the review skills with /scrutineer-setup.
    if _copy_skill(paths.SETUP_SKILL, cmd_dir / paths.SETUP_COMMAND, force=force, log=log):
        result.installed.append(paths.SETUP_COMMAND)

    # 2. Resolve a service map (existing / crawl / skip).
    log("Resolving service map…")
    sm = servicemap.acquire(
        target,
        crawl=crawl,
        service_map=Path(service_map) if service_map is not None else None,
        log=log,
    )
    result.service_map_note = sm.note
    result.skipped_crawl = sm.method == "skip"
    log(f"  {sm.note}")

    # 3. Run the two generators against the repo, wiring in the map when present.
    log("Generating review skills…")
    if _run_generator(
        paths.PEER_GENERATOR, target, f".claude/commands/{paths.PEER_COMMAND}", sm, force=force, log=log
    ):
        result.installed.append(paths.PEER_COMMAND)
    if _run_generator(
        paths.SECURITY_GENERATOR, target, f".claude/commands/{paths.SECURITY_COMMAND}", sm, force=force, log=log
    ):
        result.installed.append(paths.SECURITY_COMMAND)

    return result
