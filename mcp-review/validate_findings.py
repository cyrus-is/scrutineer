#!/usr/bin/env python3
"""Agentic finding validator — late-stage false-positive sweep for /scrutineer-mcp.

analyze_mcp.py emits CANDIDATE signals. Phases of regex/zoning/confidence work cut
most noise deterministically, but a semantic long tail survives — e.g. a capability
that matched a token whose surrounding meaning contradicts it ("token limit" is not
a credential), or a tag-shaped string that isn't really an instruction. This is the
reflexion pass that catches that residue: it re-examines each candidate against its
OWN evidence (matched token, zone, confidence, snippet) and the tool's semantics,
and marks the ones that don't hold up.

Design (matches the toolkit's split of deterministic Python vs. agentic skill):
  * The JUDGMENT is agentic — an LLM, invoked here via `claude -p`, or run as the
    SKILL's Pass 4 in an interactive session.
  * This module is the deterministic SCAFFOLDING: it extracts claims, builds the
    validation prompt, and applies a triage result back onto the analysis. Those
    three functions are pure and unit-tested.
  * It is a SEPARATE entrypoint — analyze_mcp.py never imports or calls it, so the
    analyzer's offline/static guarantee is untouched.

Policy (enforced in apply_triage): the validator may only SUPPRESS or DOWNGRADE a
candidate. It can never escalate a finding or invent a new one — escalation requires
source evidence, which is the skill's job, not a noise sweep's. Suppressions are
auditable: each is recorded with a reason and surfaced under `validation`, never
silently dropped.

Usage:
  # 1. emit the prompt for your own agent / piping
  python validate_findings.py --analysis analysis.json --emit-prompt

  # 2. run the agentic sweep directly (needs the `claude` CLI on PATH)
  python validate_findings.py --analysis analysis.json --run --model haiku --out validated.json

  # 3. apply a triage produced elsewhere
  python validate_findings.py --analysis analysis.json --triage triage.json --out validated.json
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Claim extraction — the inferred signals worth validating. Config findings
# (shell_wrapper, unpinned_source, creds_in_url ...) are deterministic facts,
# not heuristic inferences, so they are NOT submitted for FP review.
# ---------------------------------------------------------------------------

def extract_claims(analysis: dict) -> list[dict]:
    claims = []
    for t in analysis.get("tools", []):
        tname = t.get("name", "")
        ctx = {"tool": tname, "description": (t.get("description", "") or "")[:300],
               "params": t.get("param_names", [])}
        for c in t.get("candidate_capabilities", []):
            claims.append({
                "id": f"cap::{tname}::{c['capability']}",
                "kind": "capability", "subject": c["capability"],
                "severity": c.get("severity"), "confidence": c.get("confidence"),
                "evidence": c.get("evidence", {}), "context": ctx,
            })
        for d in t.get("data_categories", []):
            claims.append({
                "id": f"data::{tname}::{d['category']}",
                "kind": "data_category", "subject": d["category"],
                "tier": d.get("tier"), "confidence": d.get("confidence"),
                "evidence": d.get("evidence", {}), "context": ctx,
            })
    for x in analysis.get("injection_findings", []):
        claims.append({
            "id": f"injection::{x.get('tool')}",
            "kind": "injection", "subject": x.get("tool"),
            "severity": x.get("severity"),
            "evidence": {"signals": x.get("signals", [])},
            "context": {"tool": x.get("tool")},
        })
    for c in analysis.get("toxic_combinations", []):
        claims.append({
            "id": f"combo::{c['id']}",
            "kind": "toxic_combination", "subject": c["id"],
            "severity": c.get("severity"), "confidence": c.get("confidence"),
            "evidence": {"contributing": c.get("contributing", [])},
            "context": {"detail": c.get("detail", "")[:200]},
        })
    return claims


# ---------------------------------------------------------------------------
# Prompt assembly
# ---------------------------------------------------------------------------

_RUBRIC = """\
You are the false-positive sweep for an MCP security auditor. The deterministic \
analyzer flags CANDIDATE signals by pattern-matching tool metadata; some are \
spurious because the matched token means something different in context.

For EACH claim below, decide:
  - "false_positive": the matched token does not actually indicate this \
capability/category/risk in this tool's context (e.g. 'token' in "token limit"; \
'query' as a web-search param, not a database; a <tag> that is formatting, not an \
instruction).
  - "confirmed": the signal genuinely holds.
  - "needs_source": plausible but undecidable from metadata alone; keep it, flag \
for source review.

Rules:
  - Judge ONLY from the evidence and context given. Do NOT escalate, add new \
findings, or change severities — only classify.
  - Prefer "confirmed"/"needs_source" when uncertain. Suppress only clear false \
matches; the cost of hiding a real risk is higher than keeping a little noise.
  - High-confidence (name/param-zone) matches are rarely false positives.

Return ONLY a JSON object, no prose:
{"triage": [{"id": "<claim id>", "judgment": "confirmed|false_positive|needs_source", "rationale": "<one sentence>"}]}
"""


def build_prompt(claims: list[dict]) -> str:
    return _RUBRIC + "\n\nCLAIMS:\n" + json.dumps(claims, indent=1)


# ---------------------------------------------------------------------------
# Agentic invocation (optional; the only non-deterministic part)
# ---------------------------------------------------------------------------

def run_claude(prompt: str, model: str = "haiku") -> dict:
    """Shell to `claude -p` and parse the first JSON object from stdout."""
    proc = subprocess.run(
        ["claude", "-p", prompt, "--model", model],
        capture_output=True, text=True, timeout=300,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"claude -p failed: {proc.stderr.strip()[:300]}")
    out = proc.stdout
    start = out.find("{")
    end = out.rfind("}")
    if start < 0 or end < 0:
        raise RuntimeError(f"no JSON in model output: {out[:200]}")
    return json.loads(out[start:end + 1])


# ---------------------------------------------------------------------------
# Apply a triage back onto the analysis (suppress/downgrade only)
# ---------------------------------------------------------------------------

def apply_triage(analysis: dict, triage: dict) -> dict:
    """Mark false-positive claims validated_out (with reason) and attach a
    `validation` summary. Suppress-only: never escalates."""
    decisions = {d["id"]: d for d in triage.get("triage", [])}
    counts = {"confirmed": 0, "false_positive": 0, "needs_source": 0, "unreviewed": 0}

    def mark(item, claim_id):
        d = decisions.get(claim_id)
        if not d:
            counts["unreviewed"] += 1
            return
        j = d.get("judgment", "confirmed")
        counts[j] = counts.get(j, 0) + 1
        if j == "false_positive":
            item["validated_out"] = True
            item["validation_reason"] = d.get("rationale", "")
        elif j == "needs_source":
            item["needs_source"] = True

    for t in analysis.get("tools", []):
        tname = t.get("name", "")
        for c in t.get("candidate_capabilities", []):
            mark(c, f"cap::{tname}::{c['capability']}")
        for dc in t.get("data_categories", []):
            mark(dc, f"data::{tname}::{dc['category']}")
    for x in analysis.get("injection_findings", []):
        mark(x, f"injection::{x.get('tool')}")
    for c in analysis.get("toxic_combinations", []):
        mark(c, f"combo::{c['id']}")

    analysis["validation"] = {
        "method": triage.get("method", "agentic"),
        "counts": counts,
        "validated_out": [
            {"id": d["id"], "reason": d.get("rationale", "")}
            for d in triage.get("triage", []) if d.get("judgment") == "false_positive"
        ],
    }
    return analysis


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--analysis", required=True, help="analyze_mcp.py output JSON")
    ap.add_argument("--emit-prompt", action="store_true", help="print the validation prompt and exit")
    ap.add_argument("--triage", help="apply a triage JSON produced elsewhere")
    ap.add_argument("--run", action="store_true", help="run the agentic sweep via `claude -p`")
    ap.add_argument("--model", default="haiku", help="model for --run (default: haiku)")
    ap.add_argument("--out", help="write the validated analysis here (default: stdout)")
    args = ap.parse_args()

    analysis = json.loads(Path(args.analysis).read_text())
    claims = extract_claims(analysis)

    if args.emit_prompt:
        print(build_prompt(claims))
        return

    if args.triage:
        triage = json.loads(Path(args.triage).read_text())
    elif args.run:
        triage = run_claude(build_prompt(claims), args.model)
        triage["method"] = f"agentic:{args.model}"
    else:
        ap.error("provide one of --emit-prompt, --run, or --triage")

    result = apply_triage(analysis, triage)
    text = json.dumps(result, indent=2)
    if args.out:
        Path(args.out).write_text(text)
        v = result["validation"]["counts"]
        print(f"validated: {v}", file=sys.stderr)
    else:
        print(text)


if __name__ == "__main__":
    main()
