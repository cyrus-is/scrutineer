"""Locate the toolkit's bundled assets.

The generators, guidance YAMLs and static SKILL.md files live in the tool
directories at the repo root. They are resolved from one of two places:

* **clone / ``pip install -e .``** — the directories sit as siblings of this
  package, one level up from ``vld8/``.
* **installed wheel** — the build (Hatchling ``force-include``) copies those
  directories into ``vld8/_assets/``, so a ``pip install vld8`` with
  no clone still has everything the installer needs.

``toolkit_root()`` returns whichever of the two is present, so the installer
works identically from a clone and from a published wheel.
"""

from pathlib import Path

_PKG_DIR = Path(__file__).resolve().parent
_BUNDLED = _PKG_DIR / "_assets"  # present in a built/installed wheel
_SIBLINGS = _PKG_DIR.parent  # repo root — present in a clone / editable install


def toolkit_root() -> Path:
    """Return the directory that holds the tool directories (bundled or repo root)."""
    if (_BUNDLED / "generate-peer-review").is_dir():
        return _BUNDLED
    return _SIBLINGS


_ROOT = toolkit_root()

# Generators (run as subprocesses) and the copy-in static skills.
PEER_GENERATOR = _ROOT / "generate-peer-review" / "generate.py"
PEER_GUIDANCE = _ROOT / "generate-peer-review" / "peer_review_guidance.yaml"
SECURITY_GENERATOR = _ROOT / "generate-security-review" / "generate.py"
SECURITY_GUIDANCE = _ROOT / "generate-security-review" / "security_guidance.yaml"
SERVICEMAP_SKILL = _ROOT / "generate-servicemap" / "SKILL.md"
MCP_SKILL = _ROOT / "mcp-review" / "SKILL.md"
SETUP_SKILL = _ROOT / "vld8-setup" / "SKILL.md"

# Scripts the installed skills run. The skills reach them through the CLI
# (`vld8 mcp analyze …`, `vld8 map validate …`), because an
# installed skill sits in the target repo's .claude/commands/, where no
# repo-relative path into this toolkit resolves.
MCP_SCRIPTS = {
    "analyze": _ROOT / "mcp-review" / "analyze_mcp.py",
    "fetch": _ROOT / "mcp-review" / "fetch_source.py",
    "validate": _ROOT / "mcp-review" / "validate_findings.py",
    "capture": _ROOT / "mcp-review" / "capture_runtime.py",
}
SERVICEMAP_VALIDATOR = _ROOT / "generate-servicemap" / "validate_servicemap.py"
SERVICEMAP_SCHEMA = _ROOT / "references" / "schema.md"
FINDINGS_SCHEMA = _PKG_DIR / "schemas" / "findings-v1.json"

# Command-file names produced in the target repo's .claude/commands/ directory.
SERVICEMAP_COMMAND = "vld8-map.md"
MCP_COMMAND = "vld8-mcp.md"
SETUP_COMMAND = "vld8-setup.md"
PEER_COMMAND = "vld8-review.md"
SECURITY_COMMAND = "vld8-security.md"

# Milestones whose output can be turned on early with `vld8 install --preview <m>`.
# Changes to review output ship behind their milestone's flag until its gate
# passes (docs/ROADMAP.md, Release train); then the flag becomes the default and
# the milestone leaves this table. When the first one graduates, keep accepting
# `--preview <m>` as a no-op with a note, so scripts and habits don't break.
PREVIEW_MILESTONES = {
    "2.1": "precision without a spec",
}
# The generators end a skill built with --preview with a comment starting so.
PREVIEW_MARKER = "<!-- vld8 preview output:"

# Command files that scrutineer (this package's name before 2.0) installed, each
# mapped to the vld8 file that replaces it and a line only that skill contains.
# `vld8 install` moves an old file to LEGACY_BACKUP_DIR once its replacement is
# in place, and only when the marker shows scrutineer wrote it, so a hand-written
# file stays put. The backup folder sits outside .claude/commands/ because
# Claude Code loads commands from that folder's subfolders too.
LEGACY_COMMANDS = {
    "scrutineer-servicemap.md": (SERVICEMAP_COMMAND, "name: scrutineer-servicemap"),
    "scrutineer-mcp.md": (MCP_COMMAND, "name: scrutineer-mcp"),
    "scrutineer-setup.md": (SETUP_COMMAND, "name: scrutineer-setup"),
    "scrutineer-code.md": (
        PEER_COMMAND,
        "You are a TL/Principal SDE performing a peer code review.",
    ),
    "scrutineer-security.md": (
        SECURITY_COMMAND,
        "Perform a security review focused on finding exploitable vulnerabilities",
    ),
}

# The MCP reviewer's suppressions file, relative to the target repo, and the name
# scrutineer gave it. `vld8 install` renames the old file so accepted
# suppressions survive the upgrade.
SUPPRESSIONS_FILE = ".claude/vld8-mcp-suppressions.json"
LEGACY_BACKUP_DIR = ".claude/scrutineer-backup"
LEGACY_SUPPRESSIONS_FILE = ".claude/scrutineer-mcp-suppressions.json"

# Default name for the generated service map at the target repo root.
SERVICEMAP_FILE = "servicemap.json"


def missing_assets() -> list[Path]:
    """Return any required asset paths that are not present on disk."""
    required = [
        PEER_GENERATOR,
        PEER_GUIDANCE,
        SECURITY_GENERATOR,
        SECURITY_GUIDANCE,
        SERVICEMAP_SKILL,
        MCP_SKILL,
        SETUP_SKILL,
        SERVICEMAP_VALIDATOR,
        SERVICEMAP_SCHEMA,
        FINDINGS_SCHEMA,
        *MCP_SCRIPTS.values(),
    ]
    return [p for p in required if not p.exists()]
