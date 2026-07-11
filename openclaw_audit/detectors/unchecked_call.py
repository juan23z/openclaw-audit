"""
Unchecked low-level call — detecta `call`/`delegatecall`/`send` cuyo valor de retorno (bool éxito) se IGNORA.
Un low-level call NO revierte si falla: devuelve `false`. Si no se comprueba, el contrato sigue como si hubiera
tenido éxito → fondos perdidos, estado inconsistente, lógica rota. Clase de bug muy común y de impacto real.

`transfer()` NO se marca (sí revierte en fallo). Solo `.call(...)`, `.delegatecall(...)`, `.send(...)`.
"""
import logging
import re
import uuid
from pathlib import Path

_logger = logging.getLogger(__name__)

DETECTOR_INFO = {
    "name": "unchecked-low-level-call",
    "severity": "MEDIUM",
    "description": "Valor de retorno de un low-level call ignorado (el call no revierte en fallo).",
    "category": "unchecked_return",
}

# .call{...}( / .delegatecall( / .send(  — captura la posición del punto
_LOWLEVEL = re.compile(r"\.\s*(call|delegatecall|send)\s*(?:\{[^}]*\})?\s*\(", re.IGNORECASE)
# marcadores de que el retorno SÍ se usa/comprueba
_CHECKED = re.compile(r"=|require\s*\(|assert\s*\(|if\s*\(|while\s*\(|return\b|&&|\|\||bool\b", re.IGNORECASE)


def scan(repo_path: Path) -> list[dict]:
    from openclaw_audit.detectors._fileutil import iter_sol_files
    sol_files = iter_sol_files(repo_path)
    findings: list[dict] = []

    for sol_file in sol_files[:60]:
        try:
            content = sol_file.read_text(errors="replace")
        except Exception:
            continue
        seen_lines = set()
        for m in _LOWLEVEL.finditer(content):
            kind = m.group(1).lower()
            # inicio del statement: desde el ; o { anterior hasta el call
            stmt_start = max(content.rfind(";", 0, m.start()), content.rfind("{", 0, m.start()))
            prefix = content[stmt_start + 1:m.start()]
            # comentario o import → saltar
            line_no = content[:m.start()].count("\n") + 1
            if line_no in seen_lines:
                continue
            # si el prefijo del statement indica que el retorno se captura/comprueba → OK
            if _CHECKED.search(prefix):
                continue
            # abi.encodeWithSelector(...).call es raro sin captura, pero .call de bajo nivel sin '=' antes = unchecked
            seen_lines.add(line_no)
            lines = content.splitlines()
            ctx = "\n".join(f"  {i+1}: {lines[i]}" for i in range(max(0, line_no - 2), min(len(lines), line_no + 1)))
            sev = "MEDIUM" if kind == "send" else "MEDIUM"
            findings.append({
                "id": str(uuid.uuid4()),
                "contest_id": "",
                "title": f"Unchecked low-level {kind}() — return value ignored",
                "severity": sev,
                "category": "unchecked_return",
                "description": (
                    f"A low-level `{kind}()` in `{sol_file.name}` (line {line_no}) does not check its boolean "
                    f"return value. Low-level calls do NOT revert on failure — they return `false`. Ignoring it "
                    f"means the contract proceeds as if the call succeeded, which can lead to lost funds or "
                    f"inconsistent state."
                ),
                "impact": "Silent failure of an external call; funds may be considered sent when they were not.",
                "affected_code": f"{sol_file.name}:{line_no}\n{ctx}",
                "recommendation": (
                    f"Capture and check the return: `(bool ok, ) = target.{kind}(...); require(ok, \"call failed\");` "
                    f"For value transfers prefer a checked pattern or a pull-payment design."
                ),
                "confidence": 0.6,
                "tool_source": "custom_detector:unchecked_call",
            })
            _logger.info("[UncheckedCall] %s:%d unchecked %s()", sol_file.name, line_no, kind)
    return findings
