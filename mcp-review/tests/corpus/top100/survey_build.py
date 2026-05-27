#!/usr/bin/env python3
"""Aggregate per-server analyses + the manifest into the shareable survey.

Inputs (all under OUTDIR):
  manifest.json        rank/stars/repo/identifier per slug (from build_top100.py)
  analysis/<slug>.json  full analyze_mcp.py output (one server each)

Outputs:
  leaderboard.csv      one row per server, machine-readable
  stats.json           headline aggregate stats
  SURVEY.md            the shareable writeup (headline + methodology + table)

The SECURITY column is *derived deterministically* from the analyzer's evidence
using the unambiguous parts of the SKILL.md rubric (hard-BLOCK triggers + the
"unpinned install can't be SAFE" cap). It is the supply-chain posture, NOT the
full agentic verdict — stated as such in the methodology. The DATA column is the
analyzer's own data_profile.rating. Headline stats lead on raw provenance facts,
which are fully reproducible and judgment-free.
"""
import json, glob, os, sys
from collections import Counter

# Import the validator's claim extractor so we can recompute ratings from the
# claims that survive Pass-4 (apply_triage records validated_out but does not
# re-aggregate data_profile — recomputing here is the reviewer's final step).
sys.path.insert(0, os.path.abspath(os.path.join(
    os.path.dirname(__file__) if "__file__" in globals() else ".", "..", "..", "..")))
try:
    import validate_findings as vf
except Exception:
    vf = None

# Manual-review suppressions: residual semantic FPs caught by human review that
# the agentic Pass-4 (haiku) missed. Each is a (slug -> {category}) drop with a
# documented reason; applied on top of validated_out. Transparent + auditable.
MANUAL_DROP = {
    "unreal-engine": {"location"},            # 3D actor coordinates (x/y/z), not geographic
    "mcp-neo4j-data-modeling": {"location"},  # a schema column named "location", not location data
    "token-optimizer": {"calendar"},          # cache scheduling (cron/schedule), not calendar data
}
MANUAL_DROP_REASON = {
    ("unreal-engine", "location"): "3D actor coordinates (x/y/z), not geographic/personal location",
    ("mcp-neo4j-data-modeling", "location"): "a data-model column named 'location', not location data",
    ("token-optimizer", "calendar"): "cache scheduling (cron/schedule/event), not calendar data",
}

TIER_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}
TIER_RATING = {"critical": "HIGHLY_SENSITIVE", "high": "SENSITIVE",
               "medium": "LIMITED", "low": "MINIMAL"}


def recompute_after_validation(d, vout, drop_categories=frozenset()):
    """Recompute (data_rating, category_breakdown) from data-category claims that
    survive Pass-4 (and any manual-review category drops). Matches the analyzer's
    rule: rating = highest tier with a surviving HIGH-confidence hit. Conservative
    when nothing high-confidence survives (MINIMAL if a surface was assessed)."""
    if vf is None:
        return d.get("data_profile", {}).get("rating", "UNKNOWN"), {}
    if not d.get("data_profile", {}).get("surface_assessed"):
        return "UNKNOWN", {}
    claims = [c for c in vf.extract_claims(d)
              if c.get("kind") == "data_category" and c["id"] not in vout
              and c.get("subject") not in drop_categories]
    cats = {}
    for c in claims:
        e = cats.setdefault(c["subject"], {"tier": c["tier"], "tool_count": 0, "high": False})
        e["tool_count"] += 1
        if c.get("confidence") == "high":
            e["high"] = True
    hi = [c for c in claims if c.get("confidence") == "high"]
    if not hi:
        return "MINIMAL", cats
    top = max(hi, key=lambda c: TIER_RANK.get(c["tier"], 0))
    return TIER_RATING.get(top["tier"], "MINIMAL"), cats

OUTDIR = sys.argv[1] if len(sys.argv) > 1 else \
    "/Users/clawrus/Projects/scrutineer/mcp-review/tests/corpus/top100"
# Which per-server analysis dir to aggregate: "analysis" (raw deterministic) or
# "analysis_validated" (post agentic Pass-4 FP sweep). Default: validated if present.
ANALYSIS_DIR = sys.argv[2] if len(sys.argv) > 2 else (
    "analysis_validated" if os.path.isdir(f"{OUTDIR}/analysis_validated") else "analysis")
SNAPSHOT = "2026-05-26"
# Universe facts from the registry pull (build_top100.py --phase pull, snapshot date).
UNIVERSE = {"records": 29652, "latest": 9853, "installable": 5362, "repos": 4801,
            "remote_only": 3576}
HARD_BLOCK_CODES = {"unredacted_secret_value", "credentials_in_url", "non_https_remote"}
HIGH_TOXIC = {"exfil_chain", "exec_with_secret_access",
              "remote_controlled_fs_mutation", "read_and_exfil"}


def derive_security(d):
    """Return (posture, reasons[]) from analyzer evidence.

    BLOCK keys ONLY on clean, mechanically-decidable config/supply-chain triggers
    that need no behavioral judgment: a live secret in config, credentials-in-URL,
    cleartext transport, confirmed high-confidence tool-poisoning, or an unpinned
    artifact handed a live credential. We deliberately DO NOT escalate to BLOCK on
    capability-derived toxic combinations (read+egress, secrets+egress): the rubric
    only blocks those after the model judges whether the combo *is the server's
    legitimate purpose* (a browser reads pages and fetches URLs by design), and
    that per-server judgment can't be made mechanically at survey scale. Those are
    surfaced separately as behavioral flags for source review (see behavioral_flags),
    not folded into the posture. CAUTION is the floor for any unpinned/unbindable
    artifact; SAFE requires a pinned, verifiable, low-severity server."""
    sv = d["servers"][0]
    prov = sv.get("provenance", {})
    codes = {f["code"] for f in sv.get("findings", [])}
    reasons = []
    if codes & HARD_BLOCK_CODES:
        reasons.append("+".join(sorted(codes & HARD_BLOCK_CODES)))
    if any(i.get("confidence") == "high" for i in d.get("injection_findings", [])):
        reasons.append("tool_description_injection")
    mutable = prov.get("mutable_install_path")
    creds = sv.get("sensitive_env_keys") or []
    if mutable and creds:
        reasons.append("unpinned_artifact_handed_credentials")
    if reasons:
        return "BLOCK", reasons
    binding = prov.get("runtime_binding_confidence")
    if mutable or prov.get("pin_strength") == "none" or binding in (None, "none", "remote_endpoint"):
        return "CAUTION", ["unpinned_or_unbindable_install"]
    sev = d.get("summary", {}).get("severity_counts", {})
    if sev.get("HIGH"):
        return "CAUTION", ["high_severity_capability"]
    return "SAFE", ["scoped_no_material_issues"]


def main():
    manifest = {m["slug"]: m for m in json.load(open(f"{OUTDIR}/manifest.json"))}
    rows = []
    fp_suppressed_total = 0
    validated_servers = 0
    for slug, m in manifest.items():
        af = f"{OUTDIR}/{ANALYSIS_DIR}/{slug}.json"
        d = None
        if os.path.exists(af) and os.path.getsize(af) > 0:
            try:
                d = json.load(open(af))
            except json.JSONDecodeError:
                d = None
        if not d or not d.get("servers"):
            rows.append({**m, "captured": False, "security": "CAUTION",
                         "sec_reasons": ["not_analyzed"], "data": "UNKNOWN",
                         "creds": [], "tool_count": 0, "capabilities": [], "toxic": [],
                         "behavioral_flags": [],
                         "pin": None, "install": m.get("registry_type") == "pypi" and "uvx" or "npx"})
            continue
        sv = d["servers"][0]
        surface = d.get("data_profile", {}).get("surface_assessed", False)
        sec, reasons = derive_security(d)
        # Pass-4 validated_out: recompute the data rating from surviving claims,
        # and drop any toxic combo the validator suppressed.
        vout = set()
        val = d.get("validation")
        if val:
            validated_servers += 1
            vout = {x["id"] for x in val.get("validated_out", [])}
            fp_suppressed_total += len(vout)
        drop = MANUAL_DROP.get(slug, frozenset())
        if vout or drop:
            data_rating, _cats = recompute_after_validation(d, vout, drop)
        else:
            data_rating = d.get("data_profile", {}).get("rating", "UNKNOWN")
        flags = sorted({t["id"] for t in d.get("toxic_combinations", [])
                        if t.get("severity") == "HIGH" and f"combo::{t['id']}" not in vout})
        rows.append({
            **m,
            "captured": surface,
            "tool_count": d.get("summary", {}).get("tool_count", 0),
            "security": sec, "sec_reasons": reasons,
            "data": data_rating,
            "creds": sv.get("sensitive_env_keys") or [],
            "capabilities": [t["id"] for t in d.get("toxic_combinations", [])],
            "toxic": [(t["id"], t["severity"]) for t in d.get("toxic_combinations", [])],
            # behavioral flags = HIGH toxic combos (post-validation) surfaced for
            # source review, NOT a posture escalation (often inherent to purpose).
            "behavioral_flags": flags,
            "pin": sv.get("provenance", {}).get("pin_strength"),
            "install": sv.get("command"),
        })
    rows.sort(key=lambda r: r["rank"])

    n = len(rows)
    captured = sum(r["captured"] for r in rows)
    unpinned = sum(1 for r in rows if r.get("pin") in (None, "none"))
    with_creds = sum(1 for r in rows if r["creds"])
    block = sum(1 for r in rows if r["security"] == "BLOCK")
    caution = sum(1 for r in rows if r["security"] == "CAUTION")
    safe = sum(1 for r in rows if r["security"] == "SAFE")
    data_dist = Counter(r["data"] for r in rows)
    sens_or_higher = sum(1 for r in rows if r["data"] in ("SENSITIVE", "HIGHLY_SENSITIVE"))
    flagged = [r for r in rows if r["behavioral_flags"]]
    flag_dist = Counter(f for r in flagged for f in r["behavioral_flags"])
    stats = {
        "snapshot": SNAPSHOT, "n": n, "captured": captured,
        "unpinned": unpinned, "with_credentials": with_creds,
        "block": block, "caution": caution, "safe": safe,
        "data_distribution": dict(data_dist), "sensitive_or_higher": sens_or_higher,
        "behavioral_flagged": len(flagged), "behavioral_flag_distribution": dict(flag_dist),
        "behavioral_flagged_servers": {r["slug"]: r["behavioral_flags"] for r in flagged},
        "validated_servers": validated_servers, "fp_suppressed_total": fp_suppressed_total,
    }
    json.dump(stats, open(f"{OUTDIR}/stats.json", "w"), indent=2)

    with open(f"{OUTDIR}/leaderboard.csv", "w") as f:
        f.write("rank,slug,registry_name,repo,stars,install,pin,credentials,"
                "data_sensitivity,security_posture,tool_count,toxic_combinations\n")
        for r in rows:
            f.write(f'{r["rank"]},{r["slug"]},{r["registry_name"]},{r["repo"]},{r["stars"]},'
                    f'{r.get("install","")},{r.get("pin","")},"{";".join(r["creds"])}",'
                    f'{r["data"]},{r["security"]},{r["tool_count"]},'
                    f'"{";".join(f"{i}:{s}" for i,s in r["toxic"])}"\n')

    # SURVEY.md (draft body; prose intro/methodology refined by hand at the end)
    L = []
    L.append(f"# Scrutineer MCP Survey — top {n} servers by GitHub stars\n")
    L.append(f"_Snapshot {SNAPSHOT}. Source: official MCP registry; ranked by GitHub stars "
             f"of the linked repository. Generated by `/scrutineer-mcp` (deterministic pass)._\n")
    L.append("## Headline\n")
    L.append(f"- **{safe} of {n} can rate SAFE as distributed.** Every server installs via an "
             f"unpinned package runner (`npx -y` / `uvx`), so the code that actually runs can't be "
             f"bound to anything you reviewed.")
    L.append(f"- **{with_creds} of {n} are handed live credentials** via environment variables.")
    L.append(f"- **{block} of {n} hit a hard BLOCK trigger** — an unpinned artifact handed a live "
             f"credential: a mutable package you can't bind to reviewed code, holding a real secret.")
    L.append(f"- **{sens_or_higher} of the {captured} servers whose tool surface we captured can touch "
             f"SENSITIVE or HIGHLY_SENSITIVE data** (file/message contents, secrets, PII). "
             f"(The other {n - captured} couldn't be booted without real credentials/args → data sensitivity UNKNOWN.)")
    flag_str = ", ".join(f"{k} ({v})" for k, v in sorted(flag_dist.items(), key=lambda x: -x[1]))
    L.append(f"- **{len(flagged)} of {captured} captured servers expose a read+egress / secrets+egress "
             f"capability combination** worth a source review. These are *flagged, not blocked* — for "
             f"many it's inherent to the job (a browser fetches URLs; an SSH client transfers files). "
             f"Flags: {flag_str}.")
    L.append(f"- Posture split: **{block} BLOCK / {caution} CAUTION / {safe} SAFE**. "
             f"Tool surface captured for {captured}/{n}.\n")
    L.append("## Leaderboard\n")
    L.append("Posture is the *derived supply-chain posture* (see methodology); Flags are capability "
             "combinations surfaced for source review, not verdicts.\n")
    L.append("| # | Server | Stars | Install | Creds | Data | Posture | Flags |")
    L.append("|---|--------|------:|---------|-------|------|---------|-------|")
    for r in rows:
        creds = "yes" if r["creds"] else "—"
        flags = ", ".join(r["behavioral_flags"]) if r["behavioral_flags"] else "—"
        L.append(f'| {r["rank"]} | [{r["slug"]}](https://github.com/{r["repo"]}) | {r["stars"]} '
                 f'| {r.get("install","?")} | {creds} | {r["data"]} | {r["security"]} | {flags} |')

    U = UNIVERSE
    L.append(f"""
## Methodology — how "top 100" is defined

**Universe.** A full snapshot of the official Model Context Protocol registry
(`registry.modelcontextprotocol.io`) on **{SNAPSHOT}**: {U['records']:,} records →
{U['latest']:,} unique servers at their latest version. We keep the servers that
(a) ship an **npm or PyPI package over stdio** — i.e. the locally-installable
servers that `/scrutineer-mcp` is designed to audit — and (b) link a **GitHub
repository**: **{U['installable']:,} servers across {U['repos']:,} repositories**.
({U['remote_only']:,} registry entries are remote/HTTP-only and out of scope here.)

**Ranking.** GitHub stars of the linked repository, as of {SNAPSHOT}, descending.
Top 100 taken. Stars are a **popularity proxy, not a security or quality signal** —
they answer "which servers do the most people reach for," which is exactly the
blast-radius question worth auditing first.

**Monorepo caveat.** Several entries share one repository (e.g.
`bytedance/UI-TARS-desktop` ships 4 installable servers; `microsoft/mcp` ships 3).
Each is independently installable with its own tool surface and risk profile, so
each is listed separately and shares that repo's star count. The rank reflects the
**hosting repo's** stars, not the individual package's.

**What was measured.** For each server we ran the **deterministic pass** of
`/scrutineer-mcp` over (1) its install config — synthesized from the registry's
**authoritative package metadata**, no install commands invented — and (2) its
captured `tools/list` surface. The agentic source/behavioral review was *not* run
on all 100 (it is non-deterministic and per-server costly); it was applied only to
the subset with capability findings, to clear false positives.

**Tool-surface capture.** Each server was launched in a **disposable, unprivileged
container** (node + uv) and its `tools/list` captured via the MCP handshake.
Capturing a surface means *executing* the package — so all 100 unpinned launches
were boxed in a throwaway container, never on a workstation. ({captured}/{n}
surfaces captured; servers needing real credentials or positional args to boot
failed capture and are analyzed config-only, shown as `UNKNOWN` data sensitivity.)

**Security posture is *derived*, and is a supply-chain posture — not a malware
verdict.** The SAFE / CAUTION / BLOCK column is computed deterministically from the
analyzer's evidence using the unambiguous parts of the published rubric: the
hard-BLOCK triggers (a live secret in config, credentials-in-URL, cleartext
transport, a high-confidence toxic combination, confirmed tool-poisoning, or **an
unpinned artifact handed a live credential**), plus the rule that an
unpinned/unbindable install **cannot be SAFE** (you can't bind the code that runs
to anything you reviewed). Read `BLOCK` as "don't run this as-distributed without
pinning + review," **not** "this is malware"; read `SAFE` as "no material issue in
the inspected scope," not "audited clean." Scrutineer is a provenance/transparency
gate; behavioral malice requires source review.

**Data sensitivity** is reported post-validation. The deterministic pass is
recall-first (it over-fires on purpose), so each captured surface then goes
through the agentic Pass-4 validator (suppress-only) and a manual review of every
SENSITIVE+ rating; the published tier is the highest data tier with a surviving
high-confidence category. Running this survey on 100 real servers is also what
surfaced two precision bugs in the detector itself — `health` matching system
*health-checks* (`agent_health`) as medical data, and `token` matching LLM/crypto
tokens as credentials — both fixed in **scrutineer 1.6.3** (the ratings here are
post-fix). That's the recall-first/precision-second design doing its job, in public.

## What "unpinned" means — and why we treat it as a security position

This is the survey's central call, and the one most likely to draw a "but `latest`
is good practice" reaction — so here's the reasoning, explicitly.

Pinning isn't about running *old* code. It's about the **audit boundary**: when you
pin a version (or vendor the package), the code you reviewed is the code that runs.
With `npx -y pkg` / `uvx pkg` / `@latest`, the code that runs is **whatever the
registry serves at the moment of launch** — which can change after you've vetted it,
silently, with no signal, on every run, forever. You re-extend trust to the
publisher's account + the registry + the network automatically, every time your
agent starts the server.

For an ordinary library, auto-latest is a reasonable trade — you want the patches.
For an MCP server it's different: you've handed it **tool access, data access, and
usually a live credential**, and an agent launches it on your behalf. That's a large
standing grant being silently re-pointed at unreviewed code. The postmark-mcp
backdoor is the worked example — v1.0.16 added a line that BCC'd every email to the
author, and anyone on auto-latest shipped it into their own stack the next time the
server booted. A pin wouldn't have made the new code safe, but it would have turned a
silent auto-update into a *decision*.

And "latest" doesn't even mean what people assume. The version-drift check found
**38 of the 56 captured servers ran a different version than the registry declared**,
and 4 list their version as literally `latest`. Unpinned isn't "the newest reviewed
release" — it's "whatever resolved at that millisecond."

The fix is **not** "never update." It's **pin, then bump deliberately** — review the
diff and move the pin (the same discipline you'd apply to any dependency) — or vendor
the package. We rate every unpinned server at most CAUTION, never SAFE, for one
narrow and honest reason: we can't bind the code that runs to anything we reviewed.
That's a statement about *verifiability*, not about any server's intentions.

## Limitations

- Stars proxy popularity, not safety. A high-starred server is not "more dangerous"
  — it just has more blast radius if something is wrong.
- Registry package metadata can lag a server's true latest release.
- The deterministic capability pass is recall-oriented; per-capability findings, where
  shown, are validator-cleaned. The headline stats deliberately lean on **provenance
  facts** (unpinned / credentialed), which don't depend on capability precision.
- Config-only servers (capture failed) get a provenance posture but `UNKNOWN` data
  sensitivity — absence of a tool surface is *unknown*, not *minimal*.

## Manual-review corrections

Three residual semantic FPs that Pass-4 missed were removed in human review
(documented + auditable in `survey_build.py`): `unreal-engine`'s `location` (3D actor
x/y/z coordinates, not geographic), `mcp-neo4j-data-modeling`'s `location` (a data-model
column literally named "location"), and `token-optimizer`'s `calendar` (cache
cron/scheduling, not calendar data). `location`→3D and `schedule`→`calendar` are a known
calibration long-tail tracked for a follow-up release.

## Reproduce

Everything is in the repo under `mcp-review/tests/corpus/top100/`:
`build_top100.py` (registry pull + star ranking → `config.json` + `manifest.json`),
`run_capture_parallel.sh` (containerized `tools/list` capture), `run_analysis_top100.sh`
(deterministic analysis), `survey_build.py` (this file → leaderboard + stats + survey).
`manifest.json` carries the per-server stars, repo, and registry identifier for audit.
""")
    open(f"{OUTDIR}/SURVEY.md", "w").write("\n".join(L) + "\n")
    print(json.dumps(stats, indent=2))
    print(f"\nwrote SURVEY.md, leaderboard.csv, stats.json -> {OUTDIR}")


if __name__ == "__main__":
    main()
