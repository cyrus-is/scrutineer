#!/usr/bin/env bash
# Host-side driver: build the capture sandbox image and run it against a config,
# isolating ~100 unpinned package launches in a disposable container.
#
#   ./run_capture.sh [config.json] [tools_outdir]
#
# Defaults to this dir's config.json -> tools/. The container gets the config
# read-only and the output dir read-write; nothing else from the host.
set -euo pipefail
cd "$(dirname "$0")"                 # corpus/top100
HERE="$(pwd)"
CORPUS="$(cd .. && pwd)"             # build context (has capture_tools.py)

CONFIG="${1:-$HERE/config.json}"
OUTDIR="${2:-$HERE/tools}"
IMAGE="scrutineer-capture:latest"
PER_TIMEOUT="${PER_TIMEOUT:-90}"

mkdir -p "$OUTDIR"
echo "== building $IMAGE =="
docker build -f "$HERE/Dockerfile" -t "$IMAGE" "$CORPUS"

echo "== capturing: config=$CONFIG out=$OUTDIR =="
# --network needed (npx/uvx fetch packages; servers may probe network on boot).
# No host mounts except config (ro) + output (rw). --rm: disposable.
docker run --rm \
  -e PER_TIMEOUT="$PER_TIMEOUT" \
  -v "$CONFIG":/work/config.json:ro \
  -v "$OUTDIR":/out \
  "$IMAGE"

echo "== capture complete -> $OUTDIR =="
