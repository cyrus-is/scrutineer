#!/usr/bin/env python3
"""Run the agentic Pass-4 validator over every captured analysis, in parallel.

Captured (has a tool surface) -> validate via `validate_findings.py --run`.
Config-only (no surface) -> copied through (no capability/data claims to validate).
Output: analysis_validated/<slug>.json (carries validation.validated_out).
"""
import glob, json, os, shutil, subprocess, sys
from concurrent.futures import ThreadPoolExecutor, as_completed

HERE = os.path.dirname(os.path.abspath(__file__))
SRC, DST = os.path.join(HERE, "analysis"), os.path.join(HERE, "analysis_validated")
VALIDATOR = os.path.abspath(os.path.join(HERE, "..", "..", "..", "validate_findings.py"))
MODEL = os.environ.get("MODEL", "haiku")
PAR = int(os.environ.get("PAR", "6"))
os.makedirs(DST, exist_ok=True)


def captured(f):
    try:
        return json.load(open(f)).get("data_profile", {}).get("surface_assessed")
    except Exception:
        return False


def already_done(out):
    return os.path.exists(out) and os.path.getsize(out) > 0 and \
        json.load(open(out)).get("validation") is not None


def run_one(s):
    out = os.path.join(DST, f"{s}.json")
    if already_done(out):
        return s, "skip"
    r = subprocess.run([sys.executable, VALIDATOR, "--analysis", os.path.join(SRC, f"{s}.json"),
                        "--run", "--model", MODEL, "--out", out],
                       capture_output=True, text=True)
    return s, ("done" if r.returncode == 0 and already_done(out) else f"FAIL {r.stderr[-120:]}")


def main():
    cap, cfg = [], []
    for f in sorted(glob.glob(os.path.join(SRC, "*.json"))):
        s = os.path.basename(f)[:-5]
        (cap if captured(f) else cfg).append(s)
    for s in cfg:
        shutil.copy(os.path.join(SRC, f"{s}.json"), os.path.join(DST, f"{s}.json"))
    print(f"captured={len(cap)} config-only={len(cfg)} (copied through); validating with {MODEL} x{PAR}")
    done = 0
    with ThreadPoolExecutor(max_workers=PAR) as ex:
        futs = {ex.submit(run_one, s): s for s in cap}
        for fut in as_completed(futs):
            s, status = fut.result()
            done += 1
            print(f"  [{done}/{len(cap)}] {s}: {status}", flush=True)
    tot = sum(len(json.load(open(os.path.join(DST, f"{s}.json"))).get("validation", {}).get("validated_out", []))
              for s in cap if os.path.exists(os.path.join(DST, f"{s}.json")))
    print(f"=== done. total FPs suppressed across captured corpus: {tot} ===")


if __name__ == "__main__":
    main()
