#!/usr/bin/env bash
# Capture tools/list for every launchable server in top/config.json.
# Run from the corpus dir. Slow on first run (npx/uvx downloads packages).
set -u
export PATH="/opt/homebrew/bin:$PATH"
cd "$(dirname "$0")"

CONFIG=top/config.json
OUTDIR=top/tools
mkdir -p "$OUTDIR"

SERVERS=$(python3 -c "import json,sys; print(' '.join(json.load(open('$CONFIG'))['mcpServers'].keys()))")

echo "Servers: $SERVERS"
for s in $SERVERS; do
  echo "=== capturing: $s ==="
  # No external `timeout` (absent on macOS); capture_tools.py self-bounds via --timeout.
  python3 capture_tools.py --config "$CONFIG" --server "$s" --out "$OUTDIR/$s.json" --timeout 100 2>&1
done
echo "=== DONE. Summary ==="
for s in $SERVERS; do
  n=$(python3 -c "import json; d=json.load(open('$OUTDIR/$s.json')); print(len(d.get('tools',[])), d.get('error',''))" 2>/dev/null)
  printf "  %-24s %s\n" "$s" "$n"
done
