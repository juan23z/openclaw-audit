"""
Access Control Matrix — construye la matriz completa función→rol del protocolo.
══════════════════════════════════════════════════════════════════════════════

Los bugs de access control son los más comunes y mejor pagados en Immunefi.
El patrón: una función que MUEVE FONDOS o CAMBIA PARÁMETROS CRÍTICOS no tiene
el modifier de acceso que debería tener.

Este detector construye la matriz COMPLETA de roles y funciones, luego busca:
  1. Funciones que cambian parámetros críticos sin restricción de rol
  2. Funciones de inicialización sin restricción (no en deploy atómico)
  3. Funciones sweep/drain sin access control
  4. Funciones que cambian oráculos, fees, límites — sin timelock ni rol

Diferencia respecto a Slither:
  - Slither busca "function has no modifiers" genéricamente → mucho ruido
  - Este detector focaliza en FUNCIONES DE ALTO IMPACTO sin AC
  - Construye el modelo de roles del protocolo para entender qué debería estar restringido
"""

import logging
import re
import uuid
from pathlib import Path

_logger = logging.getLogger(__name__)

DETECTOR_INFO = {
    "name": "access-control-matrix",
    "severity": "HIGH",
    "description": "Función de alto impacto sin restricción de acceso adecuada.",
    "category": "access_control",
}

# Funciones de ALTO IMPACTO que deberían estar restringidas
_HIGH_IMPACT_PATTERNS = [
    # Funciones de configuración crítica
    (re.compile(r"function\s+set\w*(Oracle|Price|Feed|Rate|Fee|Limit|Cap|Threshold|Ratio|Factor|Bonus|Penalty|Liquidat)\w*\s*\(", re.IGNORECASE), "CRITICAL_CONFIG"),
    (re.compile(r"function\s+(setOracle|setPrice|setFeed|setRate|setFee|setLimit|setCap)\s*\(", re.IGNORECASE), "CRITICAL_CONFIG"),
    # Funciones de emergency/sweep/drain
    (re.compile(r"function\s+(sweep|drain|rescue|emergency|withdrawAll|recoverToken|withdrawFunds)\w*\s*\(", re.IGNORECASE), "FUND_SWEEP"),
    # Upgrade functions
    (re.compile(r"function\s+(upgrade|upgradeTo|setImplementation|setLogic)\w*\s*\(", re.IGNORECASE), "UPGRADE"),
    # Pause/unpause
    (re.compile(r"function\s+(pause|unpause|freeze|unfreeze|halt|resume)\w*\s*\(", re.IGNORECASE), "PAUSE_CONTROL"),
    # Whitelist / blacklist management
    (re.compile(r"function\s+(addToWhitelist|removeFromWhitelist|whitelist|blacklist|setAllowed|setApproved)\w*\s*\(", re.IGNORECASE), "WHITELIST"),
    # Minting
    (re.compile(r"function\s+(mint|issue|create)\w*\s*\([^)]*to\s+address", re.IGNORECASE), "MINT"),
    # Initialize (risky if not atomically deployed)
    (re.compile(r"function\s+initialize\s*\(", re.IGNORECASE), "INITIALIZE"),
]

# Modificadores que indican acceso restringido
_ACCESS_MODIFIERS = re.compile(
    r"\b(onlyOwner|onlyAdmin|onlyRole|onlyGovernor|onlyKeeper|onlyOperator|"
    r"onlyDAO|onlyMultisig|onlyGuardian|onlyManager|requiresAuth|"
    r"authorized|restricted|authenticated|hasRole|isAdmin|isOwner|"
    r"ownerOnly|adminOnly|governanceOnly|whenNotPaused|"
    r"onlyTrusted|onlyVault|onlyStrategist|onlyController|"
    # OpenZeppelin initialize protection (evita FP en initialize() de contratos upgradeables)
    r"initializer|reinitializer|onlyInitializing)\b",
    re.IGNORECASE,
)

# Falsos positivos: funciones que se ven críticas pero son view o tienen protección no-modifier
_VIEW_PATTERNS = re.compile(r"\b(view|pure)\b", re.IGNORECASE)

# Auth INLINE dentro del body (no por modifier): require(msg.sender==owner), _checkOwner(), etc.
_INLINE_AUTH = re.compile(
    r"require\s*\(\s*msg\.sender\s*==|"
    r"msg\.sender\s*==\s*(owner|_owner|admin|_admin|governance|manager)|"
    r"_check(Owner|Role|Auth|Admin)|_authorizeUpgrade|_msgSender\(\)\s*==|"
    r"if\s*\(\s*msg\.sender\s*!=",
    re.IGNORECASE,
)


def _real_body(content: str, brace_pos: int) -> str:
    """Extrae SOLO el body de la función (brace-matching), no 200 chars ciegos que capturan lo siguiente."""
    if brace_pos == -1 or brace_pos >= len(content):
        return ""
    depth = 0
    for i in range(brace_pos, min(len(content), brace_pos + 8000)):
        c = content[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return content[brace_pos:i + 1]
    return content[brace_pos:brace_pos + 400]


def _extract_function_block(content: str, start_pos: int) -> str:
    """Extrae el bloque de una función (firma + ~5 líneas)."""
    end = content.find("{", start_pos)
    if end == -1:
        return content[start_pos:start_pos+200]
    return content[start_pos:end + 200]


def _find_defined_roles(content: str) -> list[str]:
    """Extrae los roles definidos en el contrato."""
    roles = re.findall(r"bytes32\s+(?:public\s+)?constant\s+(\w+_ROLE)\b", content)
    roles += re.findall(r"role\s*=\s*keccak256\(bytes\(\"([^\"]+)\"\)\)", content, re.IGNORECASE)
    return list(set(roles))


def scan(repo_path: Path, contest_id: str = "") -> list[dict]:
    """
    Construye la matriz de acceso y detecta funciones críticas sin restricción.
    """
    from openclaw_audit.detectors._fileutil import iter_sol_files, strip_comments
    sol_files = [f for f in iter_sol_files(repo_path) if "interface" not in str(f).lower()]

    if not sol_files:
        return []

    findings = []
    for sol_file in sol_files[:20]:
        try:
            content = strip_comments(sol_file.read_text(errors="replace"))
        except Exception:
            continue

        # Find roles defined in this contract
        defined_roles = _find_defined_roles(content)
        has_access_system = bool(defined_roles) or bool(_ACCESS_MODIFIERS.search(content))

        for pattern, impact_type in _HIGH_IMPACT_PATTERNS:
            for m in pattern.finditer(content):
                func_start = m.start()

                # Firma (con modificadores) y body REAL (brace-matching, no 200 chars ciegos)
                func_sig_end = content.find("{", func_start)
                func_sig = content[func_start:func_sig_end] if func_sig_end != -1 else content[func_start:func_start+200]
                body = _real_body(content, func_sig_end)

                if _VIEW_PATTERNS.search(func_sig):
                    continue

                # Protegida por MODIFIER (en la firma) o por AUTH INLINE (en su propio body)
                if _ACCESS_MODIFIERS.search(func_sig) or _INLINE_AUTH.search(body):
                    continue

                # Skip if it's in an interface or abstract
                # Look back to find the contract declaration
                contract_ctx = content[max(0, func_start-2000):func_start]
                if re.search(r"\b(interface|abstract)\b[^{]*{[^}]*$", contract_ctx, re.DOTALL):
                    continue

                func_name = m.group(0).split("function")[1].split("(")[0].strip()

                sev = "CRITICAL" if impact_type in ("FUND_SWEEP", "UPGRADE", "MINT") else "HIGH"
                if impact_type == "INITIALIZE":
                    sev = "HIGH"

                # If contract has NO access system at all, higher confidence
                conf = 0.70 if has_access_system else 0.85

                findings.append({
                    "id": str(uuid.uuid4()),
                    "contest_id": contest_id,
                    "title": f"Unprotected {impact_type.lower().replace('_', ' ')} function: {func_name}()",
                    "description": (
                        f"`{func_name}()` in `{sol_file.name}` is a {impact_type} function "
                        f"that can be called by any address without access control.\n\n"
                        f"**Impact**: {_IMPACT_TEXT.get(impact_type, 'Unauthorized state change or fund access.')}\n\n"
                        f"**Function signature**: `{func_sig.strip()[:300]}`\n\n"
                        f"**Roles defined in protocol**: {', '.join(defined_roles) or 'none detected'}"
                    ),
                    "severity": sev,
                    "category": "access_control",
                    "affected_code": f"{sol_file.name}:{func_name}",
                    "confidence": conf,
                    "estimated_reward": 25000 if sev == "CRITICAL" else 10000,
                    "source": "access_control_matrix",
                })
                _logger.info("[ACMatrix] %s: unprotected %s %s() in %s",
                             sev, impact_type, func_name, sol_file.name)

    return findings


_IMPACT_TEXT = {
    "CRITICAL_CONFIG": (
        "An attacker can change critical protocol parameters (oracle, fee, rate) to drain funds "
        "or manipulate protocol accounting in their favor."
    ),
    "FUND_SWEEP": (
        "Any address can call this function to sweep/drain funds from the contract."
    ),
    "UPGRADE": (
        "Any address can replace the contract implementation, allowing arbitrary code execution."
    ),
    "PAUSE_CONTROL": (
        "Any address can pause/unpause the protocol, enabling DoS attacks or bypassing pauses."
    ),
    "WHITELIST": (
        "Any address can modify the whitelist/blacklist, bypassing access restrictions."
    ),
    "MINT": (
        "Any address can mint tokens, causing unlimited inflation."
    ),
    "INITIALIZE": (
        "The initializer can be called by anyone. If the proxy is re-initialized, "
        "all storage including ownership/admin can be overwritten."
    ),
}
