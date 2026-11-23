# scrutineer is now vld8

**scrutineer has been renamed [vld8](https://pypi.org/project/vld8/) and is no longer maintained under this name.**

```bash
pip install vld8
vld8 install        # in each repo that has the /scrutineer-* skills
```

`vld8 install` replaces the `/scrutineer-*` commands with `/vld8-*` ones. It deletes only files that scrutineer wrote, and moves `.claude/scrutineer-mcp-suppressions.json` to `.claude/vld8-mcp-suppressions.json`.

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

This final release, 2.0.0, depends on vld8 and forwards the `scrutineer` command to it, printing a notice each time. Once you've switched, `pip uninstall scrutineer`. Earlier versions stay on PyPI if you need to pin one.

Source and issues: https://github.com/cyrus-is/vld8
