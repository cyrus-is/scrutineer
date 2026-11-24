"""The shared, deterministic install core.

Given a target repo, this:

1. copies the static skills (servicemap, mcp, setup) into ``.claude/commands/``
   with their correct ``vld8-*`` names,
2. obtains a service map (see :mod:`vld8.servicemap`),
3. runs the peer-review and security-review generators against the repo,
   wiring in the service map when one is available,
4. moves the ``scrutineer-*`` command files that releases before the rename
   installed into a backup folder, once their ``vld8-*`` replacements are in
   place, and renames the MCP reviewer's suppressions file to its vld8 name.

Both front doors — the ``vld8`` CLI and the ``/vld8-setup`` skill —
call :func:`install`. The skill passes ``service_map=`` after doing its own
agentic crawl; the CLI lets :mod:`vld8.servicemap` resolve one.
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
    retired: list[str] = field(default_factory=list)     # scrutineer-era files moved to the backup folder
    moved_suppressions: bool = False                     # renamed the MCP suppressions file
    previews: list[str] = field(default_factory=list)    # preview milestones the generators got
    preview_missing: list[str] = field(default_factory=list)  # review skills that lack the requested preview
    preview_kept: list[str] = field(default_factory=list)     # not regenerated; still hold an earlier preview
    preview_dropped: list[str] = field(default_factory=list)  # regenerated without the preview they held
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


def _backup_path(backup_dir: Path, name: str) -> Path:
    """A path in ``backup_dir`` for ``name`` that doesn't overwrite an earlier backup."""
    dest = backup_dir / name
    n = 1
    while dest.exists():
        dest = backup_dir / f"{Path(name).stem}.{n}{Path(name).suffix}"
        n += 1
    return dest


def _retire_legacy(target: Path, cmd_dir: Path, log) -> list[str]:
    """Move scrutineer-era command files that a vld8 file now replaces out of the way.

    A file moves only when its replacement exists and it carries the marker of
    the skill scrutineer wrote under that name; anything else is kept and named.
    Files go to a backup folder outside ``.claude/commands/`` rather than being
    deleted, because the user may have edited them and ``.claude/`` is often
    gitignored.
    """
    retired = []
    backup_dir = target / paths.LEGACY_BACKUP_DIR
    for old, (new, marker) in paths.LEGACY_COMMANDS.items():
        old_path = cmd_dir / old
        if not old_path.is_file() or not (cmd_dir / new).is_file():
            continue
        try:
            text = old_path.read_text(errors="replace")
        except OSError as exc:
            log(f"  kept {old} (could not read it: {exc})")
            continue
        if marker not in text:
            log(f"  kept {old} (scrutineer did not write it; delete it by hand if it is stale)")
            continue
        backup_dir.mkdir(parents=True, exist_ok=True)
        dest = _backup_path(backup_dir, old)
        old_path.rename(dest)
        log(f"  ✓ moved {old} → {dest.relative_to(target)} (replaced by {new})")
        retired.append(old)
    return retired


def _migrate_suppressions(target: Path, log) -> bool:
    """Rename scrutineer's MCP suppressions file to vld8's name; True if moved."""
    old = target / paths.LEGACY_SUPPRESSIONS_FILE
    new = target / paths.SUPPRESSIONS_FILE
    if not old.is_file():
        return False
    if new.exists():
        log(f"  kept {paths.LEGACY_SUPPRESSIONS_FILE}: {paths.SUPPRESSIONS_FILE} already exists; "
            "merge any entries you still need by hand")
        return False
    old.rename(new)
    log(f"  ✓ moved {paths.LEGACY_SUPPRESSIONS_FILE} → {paths.SUPPRESSIONS_FILE}")
    return True


def _run_generator(
    generator: Path,
    target: Path,
    output_rel: str,
    sm: servicemap.ServiceMapResult,
    *,
    force: bool,
    previews: list[str],
    log,
) -> bool:
    # Skip an existing skill the way _copy_skill does, rather than letting the
    # generator prompt. Its "Overwrite? [y/N]" exits 0 on N, which made a
    # declined file look regenerated.
    if (target / output_rel).exists() and not force:
        log(f"  skip {Path(output_rel).name} (exists; pass --force to regenerate)")
        return False
    cmd = [sys.executable, str(generator), str(target), "--output", output_rel]
    for milestone in previews:
        cmd += ["--preview", milestone]
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


def _has_preview(path: Path) -> bool:
    try:
        return paths.PREVIEW_MARKER in path.read_text(errors="replace")
    except OSError:
        return False


def install(
    target: Path | str,
    *,
    crawl: bool = False,
    service_map: Path | str | None = None,
    force: bool = False,
    previews: list[str] | tuple[str, ...] = (),
    log=_default_log,
) -> InstallResult:
    """Install the full vld8 skill set into ``target``.

    Parameters
    ----------
    target
        Repo to install the review skills into.
    crawl
        If no service map exists, run a headless ``claude -p`` crawl to make one.
    service_map
        Explicit path to an existing service map (overrides discovery/crawl).
        The ``/vld8-setup`` skill passes the map it just crawled here.
    force
        Overwrite existing command files / service map.
    previews
        Preview milestones (keys of ``paths.PREVIEW_MILESTONES``) whose output the
        generated review skills include. Empty means the default output only.
    """
    target = Path(target).resolve()
    if not target.is_dir():
        raise NotADirectoryError(f"target repo is not a directory: {target}")

    missing = paths.missing_assets()
    if missing:
        listed = "\n  ".join(str(p) for p in missing)
        raise FileNotFoundError(
            "vld8 toolkit assets are missing — is the package intact?\n  " + listed
        )

    unknown = sorted(set(previews) - set(paths.PREVIEW_MILESTONES))
    if unknown:
        raise ValueError(
            f"no preview for milestone {', '.join(unknown)}; "
            f"available: {', '.join(sorted(paths.PREVIEW_MILESTONES)) or 'none'}"
        )

    result = InstallResult(target=target, previews=sorted(set(previews)))
    cmd_dir = _commands_dir(target)

    # 1. Copy the static skills first — the servicemap skill must be present
    #    before a headless crawl can invoke /vld8-map.
    log("Copying static skills…")
    if _copy_skill(paths.SERVICEMAP_SKILL, cmd_dir / paths.SERVICEMAP_COMMAND, force=force, log=log):
        result.installed.append(paths.SERVICEMAP_COMMAND)
    if _copy_skill(paths.MCP_SKILL, cmd_dir / paths.MCP_COMMAND, force=force, log=log):
        result.installed.append(paths.MCP_COMMAND)
    # The setup skill too, so a pip-only install can later re-crawl the map and
    # regenerate the review skills with /vld8-setup.
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
    review = [paths.PEER_COMMAND, paths.SECURITY_COMMAND]
    had_preview = {f for f in review if _has_preview(cmd_dir / f)}
    log("Generating review skills…")
    if _run_generator(
        paths.PEER_GENERATOR, target, f".claude/commands/{paths.PEER_COMMAND}", sm,
        force=force, previews=result.previews, log=log,
    ):
        result.installed.append(paths.PEER_COMMAND)
    if _run_generator(
        paths.SECURITY_GENERATOR, target, f".claude/commands/{paths.SECURITY_COMMAND}", sm,
        force=force, previews=result.previews, log=log,
    ):
        result.installed.append(paths.SECURITY_COMMAND)

    # What the files now hold, not what the generators returned, decides whether
    # a preview took effect.
    if result.previews:
        result.preview_missing = [f for f in review if not _has_preview(cmd_dir / f)]
    else:
        result.preview_kept = [f for f in review if f in had_preview and _has_preview(cmd_dir / f)]
        result.preview_dropped = [f for f in review if f in had_preview and not _has_preview(cmd_dir / f)]

    # 4. Retire the scrutineer-* files this install replaces, so the old and new
    #    commands don't both appear in Claude Code.
    if any((cmd_dir / old).exists() for old in paths.LEGACY_COMMANDS):
        log("Retiring scrutineer-era commands…")
        result.retired = _retire_legacy(target, cmd_dir, log)
    result.moved_suppressions = _migrate_suppressions(target, log)

    return result
