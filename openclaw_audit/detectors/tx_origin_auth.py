"""
tx.origin authentication — detecta `tx.origin` usado para AUTORIZACIÓN. Es un vector de phishing clásico: si un
contrato autoriza con `require(tx.origin == owner)`, un contrato malicioso al que la víctima (owner) llame puede
reenviar la llamada y pasar el check (tx.origin sigue siendo el owner). Debe usarse `msg.sender`.
"""
import logging
import re
import uuid
from pathlib import Path

_logger = logging.getLogger(__name__)

DETECTOR_INFO = {
    "name": "tx-origin-auth",
    "severity": "HIGH",
    "description": "tx.origin usado para autorización (vector de phishing; usar msg.sender).",
    "category": "access_control",
}

# tx.origin en un contexto de comparación/autorización
_TXORIGIN_AUTH = re.compile(
    r"(require|assert|if)\s*\([^;{)]*\btx\.origin\b|"
    r"\btx\.origin\b\s*(==|!=)|"
    r"(==|!=)\s*\btx\.origin\b",
    re.IGNORECASE,
)


def scan(repo_path: Path) -> list[dict]:
    from openclaw_audit.detectors._fileutil import iter_sol_files
    sol_files = iter_sol_files(repo_path)
    findings: list[dict] = []

    for sol_file in sol_files[:60]:
        try:
            content = sol_file.read_text(errors="replace")
        except Exception:
            continue
        seen = set()
        for m in _TXORIGIN_AUTH.finditer(content):
            line_no = content[:m.start()].count("\n") + 1
            if line_no in seen:
                continue
            seen.add(line_no)
            lines = content.splitlines()
            ctx = "\n".join(f"  {i+1}: {lines[i]}" for i in range(max(0, line_no - 1), min(len(lines), line_no)))
            findings.append({
                "id": str(uuid.uuid4()),
                "contest_id": "",
                "title": "tx.origin used for authorization — phishing vector",
                "severity": "HIGH",
                "category": "access_control",
                "description": (
                    f"`{sol_file.name}` (line {line_no}) uses `tx.origin` in an authorization check. `tx.origin` "
                    f"is the original EOA of the transaction, not the direct caller. A malicious contract that the "
                    f"authorized user is tricked into calling can relay the call and pass the check, because "
                    f"`tx.origin` is still the victim. This is a classic phishing vector."
                ),
                "impact": "An attacker contract can impersonate the authorized user via a phishing transaction.",
                "affected_code": f"{sol_file.name}:{line_no}\n{ctx}",
                "recommendation": "Use `msg.sender` for authorization instead of `tx.origin`.",
                "confidence": 0.85,
                "tool_source": "custom_detector:tx_origin_auth",
            })
            _logger.info("[TxOriginAuth] %s:%d tx.origin auth", sol_file.name, line_no)
    return findings
