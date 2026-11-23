"""Locate the toolkit's bundled assets.

The generators, guidance YAMLs and static SKILL.md files live in the tool
directories at the repo root. They are resolved from one of two places:

* **clone / ``pip install -e .``** — the directories sit as siblings of this
  package, one level up from ``scrutineer/``.
* **installed wheel** — the build (Hatchling ``force-include``) copies those
  directories into ``scrutineer/_assets/``, so a ``pip install scrutineer`` with
  no clone still has everything the installer needs.

``toolkit_root()`` returns whichever of the two is present, so the installer
works identically from a clone and from a published wheel.
"""

from __future__ import annotations

from pathlib import Path

_PKG_DIR = Path(__file__).resolve().parent
_BUNDLED = _PKG_DIR / "_assets"   # present in a built/installed wheel
_SIBLINGS = _PKG_DIR.parent       # repo root — present in a clone / editable install


def toolkit_root() -> Path:
    """Return the directory that holds the tool directories (bundled or repo root)."""
    if (_BUNDLED / "generate-peer-review").is_dir():
        return _BUNDLED
    return _SIBLINGS


_ROOT = toolkit_root()

# Generators (run as subprocesses) and the copy-in static skills.
PEER_GENERATOR = _ROOT / "generate-peer-review" / "generate.py"
SECURITY_GENERATOR = _ROOT / "generate-security-review" / "generate.py"
SERVICEMAP_SKILL = _ROOT / "generate-servicemap" / "SKILL.md"
MCP_SKILL = _ROOT / "mcp-review" / "SKILL.md"
SETUP_SKILL = _ROOT / "scrutineer-setup" / "SKILL.md"

# Scripts the installed skills run. The skills reach them through the CLI
# (`scrutineer mcp analyze …`, `scrutineer servicemap validate …`), because an
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

# Command-file names produced in the target repo's .claude/commands/ directory.
SERVICEMAP_COMMAND = "scrutineer-servicemap.md"
MCP_COMMAND = "scrutineer-mcp.md"
SETUP_COMMAND = "scrutineer-setup.md"
PEER_COMMAND = "scrutineer-code.md"
SECURITY_COMMAND = "scrutineer-security.md"

# Default name for the generated service map at the target repo root.
SERVICEMAP_FILE = "servicemap.json"


def missing_assets() -> list[Path]:
    """Return any required asset paths that are not present on disk."""
    required = [
        PEER_GENERATOR, SECURITY_GENERATOR, SERVICEMAP_SKILL, MCP_SKILL, SETUP_SKILL,
        SERVICEMAP_VALIDATOR, SERVICEMAP_SCHEMA, *MCP_SCRIPTS.values(),
    ]
    return [p for p in required if not p.exists()]
