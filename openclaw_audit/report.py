"""Render heuristic findings into a professional Markdown + HTML report (self-contained, stdlib only)."""
from __future__ import annotations

import html

_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "INFORMATIONAL": 4}
_SEV_COL = {"CRITICAL": "#b91c1c", "HIGH": "#dc2626", "MEDIUM": "#d97706",
            "LOW": "#2563eb", "INFO": "#64748b", "INFORMATIONAL": "#64748b"}
_SEV_DEF = [
    ("Critical", "Direct loss of funds or guaranteed loss; exploitable with severe impact."),
    ("High", "Loss of funds or broken invariants under realistic conditions."),
    ("Medium", "Bounded impact or requiring specific conditions; moderate risk."),
    ("Low", "Minor impact, hard to exploit, or with existing mitigations."),
    ("Info", "Best practices, code quality, gas, readability. No direct risk."),
]
_COVERAGE = [
    "First-depositor inflation (ERC-4626 vaults)",
    "Rounding / precision loss in asset↔share conversions",
    "`totalAssets` manipulation / donations to the contract",
    "Oracle freshness and price manipulation",
    "Cross-function and read-only reentrancy",
    "Access control and unprotected privileged functions",
    "Fee-on-transfer / rebasing token handling",
    "Standards compliance (ERC-20 / ERC-4626)",
    "Fee accounting (fees minted as shares)",
    "NatSpec / documentation of critical functions",
]
_GENERAL_RECS = [
    ("Access control", "Ensure every privileged function (mint, pause, upgrade, params) is protected, ideally behind a multisig/timelock."),
    ("Invariant testing", "Add property/invariant tests (Foundry fuzzing) over key economic invariants (fund conservation, solvency, exchange rate)."),
    ("Oracles", "If external prices are consumed, validate staleness and deviation bounds; consider redundant sources."),
    ("Reentrancy & CEI", "Confirm reentrancy guards on any function moving funds or calling external contracts."),
    ("Upgrade safety", "If upgradeable, review storage collisions and gate upgrades behind governance/timelock."),
    ("Continuous monitoring", "Code changes: re-review on every deploy/upgrade (a continuous-monitoring service covers this)."),
]


def _norm_sev(s):
    s = (s or "INFO").strip().upper()
    return "INFO" if s in ("INFORMATIONAL", "INFO", "NONE", "") else s


def _clean_desc(v):
    v = (v or "").strip()
    for m in ("Invariant broken:", "Attack path:", "Impact:", "Invariante roto:", "Camino de ataque:", "Beneficio:"):
        i = v.find(m)
        if i > 40:
            v = v[:i].strip()
    return v


def _e(v):
    return html.escape(str(v or ""))


def build_report(protocol, findings, scope="", max_findings=40):
    """Normalize heuristic findings into a report dict. All heuristic findings are 'candidates'."""
    cands = []
    seen = set()
    for f in findings:
        nf = {
            "title": f.get("title") or f.get("name") or "Observation",
            "severity": _norm_sev(f.get("severity")),
            "description": f.get("description", ""),
            "impact": f.get("impact", ""),
            "recommendation": f.get("recommendation", ""),
            "affected_code": f.get("affected_code", ""),
            "attack_path": f.get("attack_path", ""),
            "quality_score": f.get("confidence", 0) or 0,
        }
        key = (nf["title"], nf["affected_code"][:120])
        if key in seen:
            continue
        seen.add(key)
        cands.append(nf)
    cands.sort(key=lambda f: (_SEV_ORDER.get(f["severity"], 9), -(f["quality_score"] or 0)))
    return {"protocol": protocol, "scope": scope or "the project's contract repository",
            "candidates": cands[:max_findings]}


def _md_finding(f, n):
    parts = [f"### {n}. {f['title']}  \n`{f['severity']}` · _candidate, pending manual verification_"]
    d = _clean_desc(f.get("description"))
    if d:
        parts.append(f"\n\n**Description:** {d[:1200]}")
    if f.get("impact"):
        parts.append(f"\n\n**Impact:** {f['impact'].strip()[:600]}")
    if f.get("attack_path"):
        parts.append(f"\n\n**Attack path:** {f['attack_path'].strip()[:600]}")
    loc = (f.get("affected_code") or "").strip()
    if loc:
        parts.append(f"\n\n**Location:**\n```\n{loc[:600]}\n```")
    if f.get("recommendation"):
        parts.append(f"\n\n**Recommendation:** {f['recommendation'].strip()[:800]}")
    return "".join(parts)


def render_markdown(rep, date=""):
    L = [f"# Security review — {rep['protocol']}",
         f"\n_Automated heuristic scan by OpenClaw Audit{' · ' + date if date else ''}_",
         "\n\n---\n## Disclaimer",
         "\nThis is a best-effort **automated heuristic** analysis, not a guarantee of the absence of "
         "vulnerabilities. All items below are **candidates that require manual verification** before being "
         "treated as confirmed. Heuristic scanners produce false positives — verify before acting.",
         "\n\n---\n## Summary",
         f"\n- **Project:** {rep['protocol']}",
         f"\n- **Scope:** {rep['scope']}",
         f"\n- **Candidate observations:** {len(rep['candidates'])}",
         "\n\n---\n## Severity classification\n\n| Severity | Definition |\n|---|---|"]
    for name, d in _SEV_DEF:
        L.append(f"\n| {name} | {d} |")
    L.append("\n\n---\n## Candidate observations\n")
    if rep["candidates"]:
        for i, f in enumerate(rep["candidates"], 1):
            L.append("\n" + _md_finding(f, i) + "\n")
    else:
        L.append("\n_No heuristic issues found in the reviewed scope._\n")
    L.append("\n\n---\n## Automated analysis coverage\n\nThe scope was checked against:\n")
    for c in _COVERAGE:
        L.append(f"\n- ✓ {c}")
    L.append("\n\n---\n## General security recommendations\n")
    for name, d in _GENERAL_RECS:
        L.append(f"\n- **{name}:** {d}")
    L.append("\n\n---\n_Generated by [OpenClaw Audit](https://github.com/juan23z/openclaw-audit)._ "
             "These are heuristic *candidates* — for hand-verified findings before mainnet, a **Pre-Mainnet "
             "Express** review (48h, from $149, pay in USDC) is at https://juan23z.github.io/pricing.html\n")
    return "".join(L)


def render_html(rep, date=""):
    def fblock(f, n):
        rows = ""
        for lbl, key, lim in [("Description", "description", 1200), ("Impact", "impact", 600),
                              ("Attack path", "attack_path", 600), ("Recommendation", "recommendation", 800)]:
            v = _clean_desc(f.get(key)) if key == "description" else (f.get(key) or "").strip()
            if v:
                rows += f"<p><b>{lbl}:</b> {_e(v[:lim])}</p>"
        loc = (f.get("affected_code") or "").strip()
        loc_html = f'<pre class="loc">{_e(loc[:600])}</pre>' if loc else ""
        return (f'<div class="finding"><h3><span class="sev" style="background:{_SEV_COL.get(f["severity"],"#64748b")}">'
                f'{_e(f["severity"])}</span> {n}. {_e(f["title"])} '
                f'<span class="cand">candidate · verify</span></h3>{rows}{loc_html}</div>')
    cands = "".join(fblock(f, i) for i, f in enumerate(rep["candidates"], 1)) or \
        '<p class="clean">No heuristic issues found in the reviewed scope.</p>'
    sevdefs = "".join(f"<tr><td><b>{n}</b></td><td>{_e(d)}</td></tr>" for n, d in _SEV_DEF)
    cov = "".join(f"<li>✓ {_e(c)}</li>" for c in _COVERAGE)
    recs = "".join(f"<li><b>{_e(n)}:</b> {_e(d)}</li>" for n, d in _GENERAL_RECS)
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security review — {_e(rep['protocol'])}</title><style>
  :root{{--tx:#1e293b;--mut:#64748b;--bd:#e2e8f0;--ac:#4f46e5}}
  *{{box-sizing:border-box}} body{{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;color:var(--tx);
    line-height:1.6;max-width:820px;margin:0 auto;padding:40px 24px;background:#fff}}
  h1{{font-size:30px;margin:0 0 4px}} h2{{font-size:21px;margin:32px 0 12px;border-bottom:2px solid var(--bd);padding-bottom:6px}}
  h3{{font-size:16px;margin:18px 0 6px}} .sub{{color:var(--mut);font-size:14px;margin-bottom:18px}}
  .sev{{color:#fff;padding:2px 8px;border-radius:5px;font-size:11px;font-weight:700;margin-right:6px}}
  .cand{{color:#d97706;font-size:12px;font-weight:700;margin-left:6px}}
  table{{border-collapse:collapse;width:100%;font-size:14px}} td,th{{border:1px solid var(--bd);padding:7px 10px;text-align:left}}
  .finding{{border:1px solid var(--bd);border-radius:8px;padding:14px 18px;margin:12px 0;background:#fafbfc}}
  .finding p{{margin:6px 0;font-size:14px}} pre.loc{{background:#0f172a;color:#e2e8f0;padding:10px;border-radius:6px;overflow:auto;font-size:12px}}
  .clean{{background:#f0fdf4;border:1px solid #bbf7d0;padding:14px;border-radius:8px;color:#166534}}
  .disc{{background:#fffbeb;border:1px solid #fde68a;padding:12px;border-radius:8px;font-size:13px;color:#92400e}}
  footer{{margin-top:36px;padding-top:16px;border-top:1px solid var(--bd);color:var(--mut);font-size:13px}} a{{color:var(--ac)}}
  @media print{{body{{max-width:none;padding:0;font-size:12px}} .finding{{break-inside:avoid}} a{{color:#1e293b;text-decoration:none}}}}
</style></head><body>
<h1>Security review — {_e(rep['protocol'])}</h1>
<div class="sub">Automated heuristic scan by OpenClaw Audit{' · ' + _e(date) if date else ''}</div>
<div class="disc"><b>Disclaimer:</b> best-effort automated heuristic analysis — not a guarantee. All items are
<b>candidates requiring manual verification</b>. Heuristic scanners produce false positives.</div>
<h2>Summary</h2><p><b>Project:</b> {_e(rep['protocol'])}<br><b>Scope:</b> {_e(rep['scope'])}<br>
<b>Candidate observations:</b> {len(rep['candidates'])}</p>
<h2>Severity classification</h2><table><tr><th>Severity</th><th>Definition</th></tr>{sevdefs}</table>
<h2>Candidate observations</h2>{cands}
<h2>Automated analysis coverage</h2><ul>{cov}</ul>
<h2>General security recommendations</h2><ul>{recs}</ul>
<footer>Generated by <a href="https://github.com/juan23z/openclaw-audit">OpenClaw Audit</a> —
need a full manual review? <a href="https://juan23z.github.io">juan23z.github.io</a></footer>
</body></html>"""
