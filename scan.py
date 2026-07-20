#!/usr/bin/env python3
"""
OpenClaw Audit — free heuristic Solidity security scanner.

Scan a Solidity repo (git URL or local path) with 12 heuristic detectors and get a professional
report (Markdown + HTML). Findings are CANDIDATES — verify before acting.

Usage:
  python scan.py <git-url-or-path> [--name "Project"] [--out ./report]
  python scan.py https://github.com/org/protocol --name "Protocol" --out ./report
"""
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from openclaw_audit.detectors.runner import run_all_custom_detectors
from openclaw_audit.report import build_report, render_markdown, render_html


def _is_url(s):
    return bool(re.match(r"^(https?://|git@)", s.strip()))


def prepare(target):
    if not _is_url(target):
        p = Path(target).expanduser().resolve()
        if not p.exists():
            sys.exit(f"path not found: {p}")
        return p, None
    tmp = Path(tempfile.mkdtemp(prefix="openclaw_audit_"))
    r = subprocess.run(["git", "clone", "--depth", "1", target, str(tmp)],
                       capture_output=True, text=True, timeout=300)
    if r.returncode != 0:
        shutil.rmtree(tmp, ignore_errors=True)
        sys.exit(f"git clone failed: {r.stderr[-300:]}")
    return tmp, tmp


def main(argv):
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return
    target = argv[0]
    name, outdir = None, "./report"
    i = 1
    while i < len(argv):
        if argv[i] == "--name" and i + 1 < len(argv):
            name = argv[i + 1]; i += 2
        elif argv[i] == "--out" and i + 1 < len(argv):
            outdir = argv[i + 1]; i += 2
        else:
            i += 1

    repo, cleanup = prepare(target)
    try:
        findings = run_all_custom_detectors("scan", repo)
        # Count scope with the SAME filter the detectors use (iter_sol_files) so the reported scope
        # equals what was actually scanned — deps, tests, mocks and formal-verification harnesses out.
        from openclaw_audit.detectors._fileutil import iter_sol_files
        n_sol = len(iter_sol_files(repo))
        rep = build_report(name or repo.name, findings, scope=f"{n_sol} client .sol contracts")
        out = Path(outdir); out.mkdir(parents=True, exist_ok=True)
        (out / "report.md").write_text(render_markdown(rep), encoding="utf-8")
        (out / "report.html").write_text(render_html(rep), encoding="utf-8")
        print(f"✅ {len(rep['candidates'])} candidate observation(s) — verify before acting.")
        print(f"   {out/'report.md'}\n   {out/'report.html'}")
    finally:
        if cleanup:
            shutil.rmtree(cleanup, ignore_errors=True)


def cli():
    """Console entry point (pip/pipx): `openclaw-audit <repo-or-path> [--name ...] [--out ...]`."""
    main(sys.argv[1:])


if __name__ == "__main__":
    main(sys.argv[1:])
