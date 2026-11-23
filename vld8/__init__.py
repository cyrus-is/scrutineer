"""vld8 — dev tooling for Claude Code (formerly Scrutineer).

This package wires the vld8 tools into a single setup step. The deterministic
work (copying the static skills with the right names and running the two
generators) lives in :mod:`vld8.installer`, and is shared by both front doors:

* the ``vld8 install`` CLI (also reachable after ``pip install vld8``)
* the ``/vld8-setup`` skill, which Claude runs inside Claude Code

The only step the shared core cannot do by itself is the agentic service-map
crawl. See :mod:`vld8.servicemap` for how each front door supplies one.
"""

from .installer import InstallResult, install

__all__ = ["install", "InstallResult"]

# Single source of truth is pyproject's [project].version. Derive the runtime
# string from the installed package metadata so `vld8 --version` can never
# drift from what was actually published (it did once: 1.6.0 shipped reporting
# 1.5.0 because this was hardcoded). Fall back for a clone with no install.
try:
    from importlib.metadata import PackageNotFoundError, version as _pkg_version

    try:
        __version__ = _pkg_version("vld8")
    except PackageNotFoundError:  # running from a source tree without an install
        __version__ = "0.0.0+unknown"
except ImportError:  # pragma: no cover - importlib.metadata is stdlib on 3.8+
    __version__ = "0.0.0+unknown"
