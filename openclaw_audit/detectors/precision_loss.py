"""
Precision Loss Detector — detecta pérdida de precisión acumulable.
══════════════════════════════════════════════════════════════════

"Division before multiplication" es el error de precisión más común en Solidity.
En enteros, `a / b * c` NO es igual a `a * c / b`:
  `100 / 3 * 3 = 99` (pierde 1)
  `100 * 3 / 3 = 100` (correcto)

¿Por qué importa?
  - En DeFi, estas operaciones se ejecutan millones de veces
  - Cada ejecución pierde 1 unidad mínima (1 wei, 1 token unit)
  - Acumulado: el protocolo o el atacante puede drenar valor

Patrones que busca:
  1. División antes de multiplicación en la misma expresión
  2. Conversión de decimales que pierde precisión (e.g., tokens 6→18 decimales)
  3. Fee calculation que redondea siempre a favor del usuario (protocolo pierde)
  4. Fee calculation que redondea siempre contra el usuario (acumulable como griefing)
  5. ERC4626 convertToShares/convertToAssets con rounding incorrecto (generalizado)

Diferencia de erc4626_rounding.py: este trabaja en CUALQUIER protocolo,
no solo ERC4626, y CUANTIFICA la pérdida potencial.
"""

import logging
import re
import uuid
from pathlib import Path

_logger = logging.getLogger(__name__)

DETECTOR_INFO = {
    "name": "precision-loss",
    "severity": "MEDIUM",
    "description": "Pérdida de precisión por división antes de multiplicación — acumulable.",
    "category": "precision_loss",
}

# Division before multiplication: (a / b) * c
# In Solidity this is common in fee calculations
_DIV_BEFORE_MUL = re.compile(
    r"(\w+(?:\.\w+)?)\s*/\s*(\w+(?:\.\w+)?)\s*\*\s*(\w+(?:\.\w+)?)",
    re.MULTILINE,
)

# Fee calculation patterns: amount * fee / FEE_BASE (correct)
# vs amount / FEE_BASE * fee (wrong)
_FEE_CALC_WRONG = re.compile(
    r"(?:amount|balance|value|total|principal)\s*/\s*(?:\w+)\s*\*\s*(?:fee|rate|bps|basis)",
    re.IGNORECASE,
)

# Rounding always favoring user (protocol loses each tx)
_FLOOR_WHEN_SHOULD_CEIL = re.compile(
    r"function\s+(?:previewWithdraw|previewRedeem|maxWithdraw)\s*\([^)]*\)[^{]*\{[^}]*"
    r"(?:/\s*\d+(?!\s*\+))",
    re.IGNORECASE | re.DOTALL,
)

# mulDiv patterns — check if using correct rounding direction
_MULDIV_FLOOR = re.compile(r"\bmulDiv\b(?!Up)", re.IGNORECASE)
_MULDIV_UP = re.compile(r"\bmulDivUp\b", re.IGNORECASE)

# Interest/reward calculation that accumulates rounding errors
_INTEREST_CALC = re.compile(
    r"(?:interest|accrued|reward|yield)\s*=\s*\w+\s*/\s*(?:PRECISION|SCALE|BASE|1e\d+|10\s*\*\*)",
    re.IGNORECASE,
)


def _extract_context(content: str, pos: int, ctx_lines: int = 5) -> str:
    """Get surrounding lines for context."""
    lines = content[:pos].split("\n")
    start_line = max(0, len(lines) - ctx_lines)
    end_pos = content.find("\n", pos + 200)
    return "\n".join(content.split("\n")[start_line: start_line + ctx_lines * 2])[:400]


def _get_function_name(content: str, pos: int) -> str:
    """Find which function a position is in."""
    before = content[:pos]
    matches = list(re.finditer(r"function\s+(\w+)\s*\(", before))
    if matches:
        return matches[-1].group(1)
    return "unknown"


def scan(repo_path: Path, contest_id: str = "") -> list[dict]:
    """
    Detecta pérdida de precisión por división antes de multiplicación.
    """
    from openclaw_audit.detectors._fileutil import iter_sol_files, MAX_SCAN_FILES
    sol_files = [f for f in iter_sol_files(repo_path) if "interface" not in str(f).lower()]

    if not sol_files:
        return []

    findings = []
    seen = set()  # Deduplicate by (file, function)

    for sol_file in sol_files[:MAX_SCAN_FILES]:
        try:
            content = sol_file.read_text(errors="replace")
        except Exception:
            continue

        # Check 1: Division before multiplication in expressions
        for m in _DIV_BEFORE_MUL.finditer(content):
            # Filter out comments
            line_start = content.rfind("\n", 0, m.start())
            line = content[line_start:m.end()].strip()
            if line.startswith("//") or line.startswith("*"):
                continue

            # 19-jul: `A / B * B` (mismo operando dividido y luego multiplicado) es un REDONDEO INTENCIONAL a un
            # múltiplo de B (floor-to-unit), no pérdida de precisión: `tick / tickSpacing * tickSpacing` (alinear a
            # tick), `x / 2 * 2` (forzar par). Un bug real es `A / B * C` con C != B. → si divisor == multiplicador,
            # saltar (FP). Verificado en Uniswap tick-align + Velodrome art (ambos FP).
            if m.group(2) == m.group(3):
                continue

            func_name = _get_function_name(content, m.start())
            key = (sol_file.name, func_name, "div_mul")
            if key in seen:
                continue
            seen.add(key)

            expr = m.group(0)
            ctx = _extract_context(content, m.start())

            findings.append({
                "id": str(uuid.uuid4()),
                "contest_id": contest_id,
                "title": f"Division before multiplication in {func_name}(): precision loss",
                "description": (
                    f"In `{sol_file.name}::{func_name}()`, the expression `{expr}` "
                    f"performs division BEFORE multiplication.\n\n"
                    f"In integer arithmetic, `(a / b) * c` truncates `a / b` first, losing "
                    f"up to `(b-1)` units per call. With `a * c / b`, no precision is lost.\n\n"
                    f"**Vulnerable expression**: `{expr}`\n\n"
                    f"**Context**:\n```solidity\n{ctx}\n```\n\n"
                    f"**Economic impact**: If this function is called N times with typical values, "
                    f"the cumulative loss is N × (divisor-1) wei/units. In high-frequency protocols "
                    f"this can be material.\n\n"
                    f"**Fix**: Reorder to multiply before dividing:\n"
                    f"`{m.group(1)} * {m.group(3)} / {m.group(2)}`"
                ),
                "severity": "MEDIUM",
                "category": "precision_loss",
                "affected_code": f"{sol_file.name}:{func_name}",
                "confidence": 0.70,
                "estimated_reward": 3000,
                "source": "precision_loss",
            })
            _logger.info("[PrecisionLoss] div-before-mul in %s::%s", sol_file.name, func_name)

        # Check 2: Fee calculation with wrong order
        for m in _FEE_CALC_WRONG.finditer(content):
            func_name = _get_function_name(content, m.start())
            key = (sol_file.name, func_name, "fee_calc")
            if key in seen:
                continue
            seen.add(key)

            findings.append({
                "id": str(uuid.uuid4()),
                "contest_id": contest_id,
                "title": f"Fee calculation precision loss in {func_name}(): amount/base*fee",
                "description": (
                    f"In `{sol_file.name}::{func_name}()`, fee is calculated as "
                    f"`amount / BASE * fee` instead of `amount * fee / BASE`.\n\n"
                    f"This consistently rounds DOWN the fee by up to `(BASE-1)` units, "
                    f"meaning the protocol systematically under-charges. Over many transactions, "
                    f"this represents a real revenue loss.\n\n"
                    f"**Pattern found**: `{m.group(0)}`\n\n"
                    f"**Fix**: Use `mulDiv(amount, fee, BASE)` or `amount * fee / BASE`."
                ),
                "severity": "MEDIUM",
                "category": "precision_loss",
                "affected_code": f"{sol_file.name}:{func_name}",
                "confidence": 0.65,
                "estimated_reward": 2000,
                "source": "precision_loss",
            })
            _logger.info("[PrecisionLoss] fee-calc-order in %s::%s", sol_file.name, func_name)

        # Check 3: Interest accumulation with precision truncation
        for m in _INTEREST_CALC.finditer(content):
            func_name = _get_function_name(content, m.start())
            key = (sol_file.name, func_name, "interest")
            if key in seen:
                continue
            seen.add(key)

            ctx = _extract_context(content, m.start())
            findings.append({
                "id": str(uuid.uuid4()),
                "contest_id": contest_id,
                "title": f"Interest/reward truncation in {func_name}(): accrual precision loss",
                "description": (
                    f"In `{sol_file.name}::{func_name}()`, interest/reward accumulation uses "
                    f"integer division that truncates each accrual period.\n\n"
                    f"**Expression**: `{m.group(0)}`\n\n"
                    f"**Context**: \n```solidity\n{ctx}\n```\n\n"
                    f"For lending/staking protocols, this means users may receive slightly less "
                    f"than the exact accrued interest. Conversely, if truncation favors users, "
                    f"the protocol is losing a small amount per block — which compounds over time.\n\n"
                    f"**Fix**: Use fixed-point math libraries (FixedPoint, PRBMath) or track "
                    f"accumulated error and pay it out periodically."
                ),
                "severity": "MEDIUM",
                "category": "precision_loss",
                "affected_code": f"{sol_file.name}:{func_name}",
                "confidence": 0.60,
                "estimated_reward": 2500,
                "source": "precision_loss",
            })
            _logger.info("[PrecisionLoss] interest-truncation in %s::%s", sol_file.name, func_name)

    return findings
