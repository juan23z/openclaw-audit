"""
Cross-Function & Read-Only Reentrancy Detector
═══════════════════════════════════════════════

La reentrada clásica (misma función) ya está protegida en casi todos los protocolos.
El vector que SÍ sigue pagando:

1. CROSS-FUNCTION REENTRANCY:
   FunctionA hace una llamada externa SIN actualizar estado → callback llama FunctionB
   que lee/escribe el mismo estado → inconsistencia explotable.
   Ejemplo: Uniswap V3 calcula fee antes de llamar el callback, que puede re-entrar
   en la misma pool con fee ya cobrado pero posición aún no actualizada.

2. READ-ONLY REENTRANCY:
   Durante la ejecución de TransactionA (que incluye un callback), el sistema está
   en estado INCONSISTENTE. Si otro contrato lee un precio/saldo del contrato EN ESE
   MOMENTO, obtiene datos incorrectos.
   Ejemplo clásico: Balancer/Curve pool durante un vault operation. El precio que
   devuelve `get_virtual_price()` es incorrecto porque la pool está en estado
   intermedio. Protocols que usan Curve como oráculo son vulnerables.

Detecta:
  - Funciones con external call ANTES de actualizar variables críticas de estado
  - Funciones que leen `balanceOf(this)` o `getReserves()` después de external call
  - Callbacks (receive(), fallback(), onERC721Received, etc.) en contratos que
    también tienen funciones que leen variables de estado compartido
"""

import logging
import re
import uuid
from pathlib import Path

_logger = logging.getLogger(__name__)

DETECTOR_INFO = {
    "name": "cross-function-reentrancy",
    "severity": "HIGH",
    "description": "Cross-function o read-only reentrancy — el estado es inconsistente durante una llamada externa.",
    "category": "reentrancy",
}

# External calls that can trigger callbacks
_EXTERNAL_CALL = re.compile(
    r"(?:"
    r"\.transfer\s*\(|"
    r"\.send\s*\(|"
    r"\.call\s*\{|"
    r"\.call\s*\(|"
    r"IERC20\w*\([^)]+\)\.\w+\(|"
    r"I\w+\([^)]+\)\.\w+\(|"
    r"safeTransfer\s*\(|"
    r"safeTransferFrom\s*\(|"
    r"\.swap\s*\(|"
    r"\.flashLoan\s*\("
    r")",
    re.IGNORECASE,
)

# State variable updates (assignments to storage)
_STATE_UPDATE = re.compile(
    r"\b\w+\s*(?:\[.*?\])?\s*=(?!=)\s*(?!>)",
    re.MULTILINE,
)

# Critical state reads that, if done after external call, indicate read-only reentrancy risk
_CRITICAL_READ = re.compile(
    r"(?:"
    r"balanceOf\s*\(\s*address\s*\(this\)|"
    r"\.balanceOf\s*\(|"
    r"getReserves\s*\(|"
    r"slot0\s*\(|"
    r"get_virtual_price\s*\(|"
    r"totalSupply\s*\(|"
    r"totalAssets\s*\(|"
    r"convertToAssets\s*\(|"
    r"getPricePerFullShare\s*\("
    r")",
    re.IGNORECASE,
)

# Callback functions that can be triggered by external calls
_CALLBACK_FUNCS = re.compile(
    r"function\s+(?:receive|fallback|onERC721Received|onERC1155Received|"
    r"uniswapV3SwapCallback|uniswapV3FlashCallback|uniswapV2Call|"
    r"pancakeCall|hook|afterDeposit|beforeWithdraw)\s*\(",
    re.IGNORECASE,
)

# ReentrancyGuard usage
_REENTRANCY_GUARD = re.compile(
    r"\b(nonReentrant|ReentrancyGuard|noReentrancy|reentrancyLock|_locked|_notEntered)\b",
    re.IGNORECASE,
)


def _extract_function_bodies(content: str) -> list[dict]:
    """Extract function name + body for analysis."""
    functions = []
    func_pattern = re.compile(
        r"function\s+(\w+)\s*\([^)]*\)[^{]*\{", re.MULTILINE
    )
    for m in func_pattern.finditer(content):
        name = m.group(1)
        start = m.end() - 1  # position of opening {
        # Find matching }
        depth = 0
        pos = start
        for i, ch in enumerate(content[start:], start):
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    pos = i
                    break
        body = content[start:pos + 1]
        sig = content[m.start():m.end()]  # firma con modificadores (nonReentrant va AQUÍ, no en el body)
        functions.append({"name": name, "body": body, "sig": sig, "start": m.start()})
    return functions


def scan(repo_path: Path, contest_id: str = "") -> list[dict]:
    """
    Detecta patrones de cross-function y read-only reentrancy.
    """
    from openclaw_audit.detectors._fileutil import iter_sol_files, strip_comments
    sol_files = [f for f in iter_sol_files(repo_path) if "interface" not in str(f).lower()]

    if not sol_files:
        return []

    findings = []

    for sol_file in sol_files[:20]:
        try:
            content = strip_comments(sol_file.read_text(errors="replace"))  # no extraer funciones de NatSpec/comentarios
        except Exception:
            continue

        # Has contract-level reentrancy guard?
        has_guard = bool(_REENTRANCY_GUARD.search(content))
        has_callbacks = bool(_CALLBACK_FUNCS.search(content))

        functions = _extract_function_bodies(content)

        for func in functions:
            body = func["body"]
            name = func["name"]

            # Skip if this specific function has nonReentrant (el modificador va en la FIRMA, no en el body)
            if _REENTRANCY_GUARD.search(func.get("sig", "") + body):
                continue

            # Find positions of external calls and state updates
            ext_calls = [(m.start(), m.group()) for m in _EXTERNAL_CALL.finditer(body)]
            state_updates = [(m.start(), m.group()) for m in _STATE_UPDATE.finditer(body)]
            crit_reads = [(m.start(), m.group()) for m in _CRITICAL_READ.finditer(body)]

            if not ext_calls:
                continue

            first_ext_call = ext_calls[0][0]

            # Pattern 1: External call BEFORE state update (classic CEI violation)
            late_updates = [u for u in state_updates if u[0] > first_ext_call]
            if late_updates and not has_guard:
                # Check if the late update is significant (not just local var)
                significant = [u for u in late_updates
                               if not re.match(r"\s*(?:uint|int|bool|address|bytes)\w*\s+", u[1])]
                if significant:
                    findings.append({
                        "id": str(uuid.uuid4()),
                        "contest_id": contest_id,
                        "title": f"Cross-function reentrancy via {name}(): external call before state update",
                        "description": (
                            f"`{name}()` in `{sol_file.name}` makes an external call BEFORE "
                            f"updating state variables. If the external target re-enters any function "
                            f"that reads this shared state, it sees an inconsistent view.\n\n"
                            f"**External call**: `{ext_calls[0][1][:80]}`\n\n"
                            f"**State updated after call**: `{significant[0][1][:80]}`\n\n"
                            f"**Has callback functions**: {has_callbacks}\n\n"
                            f"**Fix**: Apply Checks-Effects-Interactions — update ALL state "
                            f"BEFORE making external calls, or add `nonReentrant` modifier."
                        ),
                        "severity": "HIGH",
                        "category": "reentrancy",
                        "affected_code": f"{sol_file.name}:{name}",
                        "confidence": 0.65 if has_guard else 0.75,
                        "estimated_reward": 10000,
                        "source": "cross_func_reentrancy",
                    })
                    _logger.info("[CFReentrancy] CEI violation in %s::%s", sol_file.name, name)

            # Pattern 2: READ-ONLY REENTRANCY — reads critical state AFTER external call
            late_reads = [r for r in crit_reads if r[0] > first_ext_call]
            if late_reads and not has_guard:
                findings.append({
                    "id": str(uuid.uuid4()),
                    "contest_id": contest_id,
                    "title": f"Read-only reentrancy in {name}(): stale price/balance read after external call",
                    "description": (
                        f"`{name}()` in `{sol_file.name}` reads a critical price/balance "
                        f"(`{late_reads[0][1][:60]}`) AFTER making an external call.\n\n"
                        f"During the external call, the protocol is in a transient inconsistent "
                        f"state. Any external protocol that reads price/balance from this contract "
                        f"during this window will receive incorrect data — enabling read-only reentrancy.\n\n"
                        f"**External call**: `{ext_calls[0][1][:80]}`\n\n"
                        f"**Critical read after call**: `{late_reads[0][1][:80]}`\n\n"
                        f"This is the same pattern as the Curve/Balancer read-only reentrancy "
                        f"(multiple CRITICAL findings paid $100k+ each).\n\n"
                        f"**Fix**: Add `nonReentrant` to functions that external protocols "
                        f"use as price oracles, OR update balances before external calls."
                    ),
                    "severity": "HIGH",
                    "category": "reentrancy",
                    "affected_code": f"{sol_file.name}:{name}",
                    "confidence": 0.70,
                    "estimated_reward": 15000,
                    "source": "cross_func_reentrancy",
                })
                _logger.info("[CFReentrancy] Read-only reentrancy in %s::%s", sol_file.name, name)

    return findings
