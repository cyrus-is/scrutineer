# scrutineer is now vld8

**scrutineer has been renamed [vld8](https://pypi.org/project/vld8/) and is no longer maintained under this name.**

```bash
pip install vld8    # or: pipx install vld8, uv tool install vld8
vld8 install        # in each repo that has the /scrutineer-* skills
```

Install vld8 the same way you installed scrutineer. Under pipx or `uv tool`, the vld8 that this release pulls in as a dependency doesn't put a `vld8` command on your PATH, and the new skills need one.

`vld8 install` replaces the `/scrutineer-*` commands with `/vld8-*` ones:
- It moves the old files it replaces to `.claude/scrutineer-backup/`, so nothing you edited is lost. It only moves files that scrutineer wrote.
- It moves `.claude/scrutineer-mcp-suppressions.json` to `.claude/vld8-mcp-suppressions.json`.

| scrutineer | vld8 |
|---|---|
| `scrutineer install` | `vld8 install` |
| `scrutineer mcp …` | `vld8 mcp …` |
| `scrutineer servicemap …` | `vld8 map …` |
| `/scrutineer-servicemap` | `/vld8-map` |
| `/scrutineer-code` | `/vld8-review` |
| `/scrutineer-security` | `/vld8-security` |
| `/scrutineer-mcp` | `/vld8-mcp` |
| `/scrutineer-setup` | `/vld8-setup` |

This final release, 2.0.0, depends on vld8 and forwards the `scrutineer` command to it, printing a notice each time. Once you've switched, uninstall scrutineer the same way you installed it. Earlier versions stay on PyPI if you need to pin one.

Source and issues: https://github.com/cyrus-is/vld8
