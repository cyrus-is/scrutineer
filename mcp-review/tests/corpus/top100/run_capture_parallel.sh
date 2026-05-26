#!/usr/bin/env bash
# Capture the top-100 tool surfaces across N parallel disposable containers.
# Each container gets one shard of the config (ro) + the shared tools dir (rw).
# Builds the image once, then fans out.
#
#   ./run_capture_parallel.sh [num_shards] [per_timeout_seconds]
set -euo pipefail
cd "$(dirname "$0")"
HERE="$(pwd)"
CORPUS="$(cd .. && pwd)"
IMAGE="scrutineer-capture:latest"
SHARDS="${1:-5}"
PER_TIMEOUT="${2:-60}"
CONFIG="$HERE/config.json"
OUTDIR="$HERE/tools"
SHARDDIR="$HERE/shards"

mkdir -p "$OUTDIR" "$SHARDDIR"
rm -f "$SHARDDIR"/shard_*.json

echo "== building $IMAGE (once) =="
docker build -q -f "$HERE/Dockerfile" -t "$IMAGE" "$CORPUS" >/dev/null

echo "== splitting config into $SHARDS shards =="
python3 - "$CONFIG" "$SHARDDIR" "$SHARDS" <<'PY'
import json, sys
cfg, sharddir, k = sys.argv[1], sys.argv[2], int(sys.argv[3])
servers = list(json.load(open(cfg))["mcpServers"].items())
for i in range(k):
    chunk = dict(servers[i::k])  # round-robin so heavy servers spread across shards
    json.dump({"mcpServers": chunk}, open(f"{sharddir}/shard_{i}.json", "w"), indent=2)
    print(f"  shard_{i}: {len(chunk)} servers")
PY

echo "== launching $SHARDS containers (per-server timeout ${PER_TIMEOUT}s) =="
pids=()
for i in $(seq 0 $((SHARDS-1))); do
  docker run --rm --name "scrut-capture-$i" \
    -e PER_TIMEOUT="$PER_TIMEOUT" \
    -v "$SHARDDIR/shard_$i.json":/work/config.json:ro \
    -v "$OUTDIR":/out \
    "$IMAGE" > "$SHARDDIR/shard_$i.log" 2>&1 &
  pid=$!
  pids+=($pid)
  echo "  started shard $i (pid $pid)"
done

echo "== waiting for all shards =="
fail=0
for p in "${pids[@]}"; do wait "$p" || fail=$((fail+1)); done
echo "== all shards done (failed containers: $fail) =="

python3 - "$OUTDIR" "$CONFIG" <<'PY'
import json, glob, os, sys
outdir, cfg = sys.argv[1], sys.argv[2]
want = set(json.load(open(cfg))["mcpServers"])
ok = err = 0; got = set()
for f in glob.glob(os.path.join(outdir, "*.json")):
    slug = os.path.basename(f)[:-5]; got.add(slug)
    d = json.load(open(f))
    if d.get("tools"): ok += 1
    else: err += 1
print(f"  captured_ok={ok}  failed_or_empty={err}  missing={len(want-got)}  (of {len(want)})")
PY
echo "== tool surfaces -> $OUTDIR =="
