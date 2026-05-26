#!/usr/bin/env bash
# Runs inside the capture container. Iterates every server in the mounted
# config and captures tools/list to /out/<slug>.json. Self-bounded per server
# via capture_tools.py --timeout (no external `timeout` dependency).
set -u
CONFIG=/work/config.json
OUT=/out
PER_TIMEOUT="${PER_TIMEOUT:-90}"

mapfile -t SERVERS < <(python3 -c "import json;print('\n'.join(json.load(open('$CONFIG'))['mcpServers'].keys()))")
echo "[entry] $(date -u +%FT%TZ) capturing ${#SERVERS[@]} servers (per-server timeout ${PER_TIMEOUT}s)"

i=0
for s in "${SERVERS[@]}"; do
  i=$((i+1))
  out="$OUT/$s.json"
  if [ -s "$out" ] && python3 -c "import json,sys;d=json.load(open('$out'));sys.exit(0 if (d.get('tools') or d.get('error')) else 1)" 2>/dev/null; then
    echo "[$i/${#SERVERS[@]}] skip $s (already captured)"; continue
  fi
  echo "[$i/${#SERVERS[@]}] === $s ==="
  python3 /work/capture_tools.py --config "$CONFIG" --server "$s" --out "$out" --timeout "$PER_TIMEOUT" 2>&1 | sed 's/^/    /'
done

echo "[entry] done. Summary:"
python3 - "$OUT" <<'PY'
import json, glob, os, sys
outdir = sys.argv[1]
ok = err = 0
for f in sorted(glob.glob(os.path.join(outdir, "*.json"))):
    d = json.load(open(f))
    n = len(d.get("tools", []))
    if d.get("error") or n == 0:
        err += 1
    else:
        ok += 1
print(f"  captured_ok={ok} failed_or_empty={err}")
PY
