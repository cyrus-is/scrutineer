#!/usr/bin/env bash
# Deterministic analysis (config + tool-surface passes) over the top-100 config.
# Offline, fast, launches nothing. Servers whose tool surface failed to capture
# are analyzed config-only (data rating -> UNKNOWN, provenance posture intact).
set -u
cd "$(dirname "$0")"                 # corpus/top100
ANALYZER=../../../analyze_mcp.py     # mcp-review/analyze_mcp.py
CONFIG=config.json
TOOLS=tools
OUT=analysis
mkdir -p "$OUT"

servers=$(python3 -c "import json;print('\n'.join(json.load(open('$CONFIG'))['mcpServers'].keys()))")
ok=0; n=0
while IFS= read -r s; do
  [ -z "$s" ] && continue
  n=$((n+1))
  tl="$TOOLS/$s.json"
  has_surface=0
  if [ -s "$tl" ] && python3 -c "import json,sys;sys.exit(0 if json.load(open('$tl')).get('tools') else 1)" 2>/dev/null; then
    has_surface=1
    python3 "$ANALYZER" --config "$CONFIG" --server "$s" --tools-list "$tl" > "$OUT/$s.json" 2>"$OUT/$s.err"
  else
    python3 "$ANALYZER" --config "$CONFIG" --server "$s" > "$OUT/$s.json" 2>"$OUT/$s.err"
  fi
  if [ -s "$OUT/$s.err" ]; then echo "  [warn] $s: $(head -1 "$OUT/$s.err")"; fi
  rm -f "$OUT/$s.err"
  [ "$has_surface" = 1 ] && ok=$((ok+1))
done <<< "$servers"
echo "analyzed $n servers ($ok with captured tool surface) -> $OUT/"
