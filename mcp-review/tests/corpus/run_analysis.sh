#!/usr/bin/env bash
# Run analyze_mcp.py (Pass 1 config + Pass 2 tool-surface) for every server in
# both corpora. Deterministic, offline, fast — does NOT launch anything.
set -u
cd "$(dirname "$0")"
ANALYZER=../../analyze_mcp.py

run_set () {
  local cfg="$1" outdir="$2" toolsdir="$3"
  mkdir -p "$outdir"
  local servers
  servers=$(python3 -c "import json;print(' '.join(json.load(open('$cfg'))['mcpServers'].keys()))")
  for s in $servers; do
    local tl="$toolsdir/$s.json"
    if [ -f "$tl" ]; then
      python3 "$ANALYZER" --config "$cfg" --server "$s" --tools-list "$tl" > "$outdir/$s.json" 2>"$outdir/$s.err"
    else
      python3 "$ANALYZER" --config "$cfg" --server "$s" > "$outdir/$s.json" 2>"$outdir/$s.err"
    fi
    if [ -s "$outdir/$s.err" ]; then echo "  [warn] $s: $(head -1 "$outdir/$s.err")"; fi
    rm -f "$outdir/$s.err"
    local findings
    findings=$(python3 -c "import json;d=json.load(open('$outdir/$s.json'));sv=d['servers'][0] if d.get('servers') else {};print('findings='+str(len(sv.get('findings',[])))+' toxic='+str(len(d.get('toxic_combinations',[]))))" 2>/dev/null)
    printf "  %-24s %s\n" "$s" "$findings"
  done
}

echo "=== TOP corpus ==="
run_set top/config.json top/analysis top/tools
echo "=== KNOWN-BAD corpus ==="
run_set known-bad/config.json known-bad/analysis known-bad/tools
echo "done"
