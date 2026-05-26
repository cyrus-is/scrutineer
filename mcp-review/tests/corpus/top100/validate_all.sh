#!/usr/bin/env bash
# Run the agentic Pass-4 validator (suppress-only FP sweep, haiku) over every
# captured analysis, in parallel. Config-only analyses (no tool surface) are
# copied through unchanged — there are no capability/data claims to validate.
# Output -> analysis_validated/<slug>.json (carries validation.validated_out).
set -u
cd "$(dirname "$0")"
VALIDATOR=../../validate_findings.py
SRC=analysis
DST=analysis_validated
MODEL="${MODEL:-haiku}"
PAR="${PAR:-6}"
mkdir -p "$DST"

# Partition: captured (has tool surface) vs config-only.
captured=(); configonly=()
for f in "$SRC"/*.json; do
  s=$(basename "$f" .json)
  if python3 -c "import json,sys;d=json.load(open('$f'));sys.exit(0 if d.get('data_profile',{}).get('surface_assessed') else 1)" 2>/dev/null; then
    captured+=("$s")
  else
    configonly+=("$s")
    cp "$f" "$DST/$s.json"
  fi
done
echo "captured=${#captured[@]} config-only=${#configonly[@]} (copied through)"

printf '%s\n' "${captured[@]}" | xargs -P "$PAR" -I {} bash -c '
  s="{}"
  out="'"$DST"'/$s.json"
  if [ -s "$out" ] && python3 -c "import json,sys;sys.exit(0 if json.load(open(\"$out\")).get(\"validation\") else 1)" 2>/dev/null; then
    echo "  skip $s (already validated)"; exit 0
  fi
  echo "  validating $s ..."
  python3 '"$VALIDATOR"' --analysis "'"$SRC"'/$s.json" --run --model '"$MODEL"' --out "$out" >/dev/null 2>&1 \
    && echo "  done $s" || echo "  FAIL $s"
'
echo "=== validation complete -> $DST/ ==="
ls "$DST" | wc -l
