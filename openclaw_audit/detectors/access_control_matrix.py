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
    r"\b(only[A-Za-z]\w+|"                # GENÉRICO: onlyOwner/onlyTimelock/onlyGovernance/onlyVault/… (16-jul)
    r"requiresAuth|authoriz\w*|restricted|authenticated|hasRole|isAdmin|isOwner|"
    r"ownerOnly|adminOnly|governanceOnly|whenNotPaused|permissioned|gated|"
    # modifiers custom tipo checkAccess()/_checkRole()/checkOwner() — el FP CRITICAL de Cap (16-jul) era esto:
    r"checkAccess|checkOwner|checkRole|checkCaller|checkAuth|_check[A-Za-z]\w+|"
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
    r"if\s*\(\s*msg\.sender\s*!=|"
    # 20-jul: OPERANDO INVERTIDO — `require(HUB == msg.sender)` / `if (HUB != msg.sender) revert`. La auth
    # compara un CONST/immutable contra el caller con msg.sender a la DERECHA (patrón de Aave V4: OnlyHub,
    # OnlyReinvestmentController). Solo veíamos msg.sender a la izquierda → 2 FP en el contest de Aave. Comparar
    # algo contra msg.sender es, en la práctica, SIEMPRE un gate de caller.
    r"[!=]=\s*msg\.sender\b|[!=]=\s*_msgSender\(\)|"
    # 20-jul: AUTH DELEGADA A HELPER — `_validateSweep(asset, msg.sender, amount)`. La función crítica pasa
    # msg.sender a un helper con nombre de validador (_validate/_check/_authorize/_assert/_verify/_ensure/_require),
    # que hace el gate dentro. El check de body-only no lo veía → FP de `Hub.sweep()` en Aave V4. Gated por el
    # PREFIJO-verbo del helper para no sobre-suprimir un `_recordDeposit(msg.sender,…)` cualquiera.
    r"_(?:validate|check|authorize|assert|verify|ensure|require|only)[A-Za-z]*\s*\([^;{}]*msg\.sender|"
    # 21-jul: AUTH POR MAPPING+MÉTODO — `if (!userConfig[msg.sender].isTokenAdmin()) revert`. El rol vive en un
    # mapping keyeado por el caller y se comprueba con un método predicado (is/has/can/only/check). Gated por el
    # prefijo-verbo del método para no sobre-suprimir accesos de mapping normales (balances[msg.sender]).
    r"\[\s*(?:msg\.sender|_msgSender\(\)|_?caller)\s*\]\s*\.\s*(?:is|has|can|only|check|require|assert)[A-Za-z]*\s*\(|"
    # Auth INLINE por VARIABLE LOCAL: `address sender=_msgSender(); if(sender!=guardian && sender!=governance) revert…`
    # (17-jul: los 2 pause() de VeriSphere eran esto — el detector solo veía `msg.sender` directo). 3 señales:
    r"if\s*\(\s*(sender|caller|_sender|_caller|msgsender|_msgsender)\s*[!=]=|"            # (1) if(sender != …)
    r"[!=]=\s*(guardian|governance|authority|_guardian|_governance|controller|operator)\b|"  # (2) comparación contra un ROL
    r"revert\s+Not\w*(Guardian|Governance|Owner|Admin|Author|Allowed|Permitted|Role|Whitelist)|"  # (3) revert de AUTH
    # (4) 19-jul: AUTH EN ASSEMBLY (código gas-optimizado tipo Solady): `if iszero(eq(sload(admin), caller()))`.
    # `caller()` (Yul = msg.sender) dentro de una comparación (eq/iszero/sub/xor), en CUALQUIER posición del arg,
    # = control de acceso. Cazó el FP de `ERC1967Factory.upgrade`/`upgradeAndCall` de Solady.
    r"(?:eq|iszero|sub|xor|lt|gt)\s*\([^{}]{0,80}caller\(\)|caller\(\)\s*[!=]=",
    re.IGNORECASE,
)

# Destino de una transferencia de fondos (primer arg de transfer/safeTransfer/send, o `X.call{value:}`).
# OJO con el orden de la alternación: `msg\.sender|tx\.origin` VAN ANTES que `[A-Za-z_]\w*`, si no el
# genérico matchea `msg` (corta en el punto) y leeríamos el destino como "msg" → falso "seguro" → se
# suprimiría un sweep a msg.sender REAL (bug cazado a mano el 16-jul en el control test).
_TRANSFER_DEST = re.compile(
    r"\.(?:safeTransfer|transfer|send)\s*\(\s*(payable\s*\(\s*)?(msg\.sender|tx\.origin|[A-Za-z_]\w*)|"
    r"(msg\.sender|tx\.origin|[A-Za-z_]\w*)\s*\.\s*call\s*[{(]",
    re.IGNORECASE,
)


def _func_params(func_sig: str) -> set[str]:
    """Nombres de los parámetros de la función (último token de cada parte entre paréntesis)."""
    m = re.search(r"\(([^)]*)\)", func_sig)
    if not m:
        return set()
    params = set()
    for part in m.group(1).split(","):
        toks = re.findall(r"[A-Za-z_]\w*", part)
        if toks:
            params.add(toks[-1])
    return params


def _addr_params(func_sig: str) -> set[str]:
    """Solo los parámetros de tipo ADDRESS (posibles DESTINOS de fondos). Un param `uint256 epoch`/`bytes32[]` no
    puede ser un destino → no lo tratamos como redirección del caller. 18-jul (FP lendvest emergency*)."""
    m = re.search(r"\(([^)]*)\)", func_sig)
    if not m:
        return set()
    out = set()
    for part in m.group(1).split(","):
        if re.search(r"\baddress\b", part):
            toks = re.findall(r"[A-Za-z_]\w*", part)
            if toks:
                out.add(toks[-1])
    return out


def _sweep_dest_attacker_controlled(func_sig: str, body: str) -> bool:
    """¿El sweep puede mandar fondos a un destino que el CALLER controla (msg.sender/tx.origin o un
    PARÁMETRO de la función)? True = peligroso (mantener finding). False = destino FIJO (state var) →
    permissionless es SEGURO, el caller no puede redirigir. Ante duda (no se ve el destino) → True
    (conservador: NUNCA suprimir a ciegas un sweep real). 16-jul: los 2 FP de BattleChain
    (sweepUnclaimedCorrupted/Bonus → safeTransfer(recoveryAddress,·)) eran destino fijo → seguros."""
    params = _func_params(func_sig)
    dests = []
    for m in _TRANSFER_DEST.finditer(body):
        d = (m.group(2) or m.group(3) or "").strip()
        if d:
            dests.append(d)
    if not dests:
        # No hay transfer VISIBLE en el body (p.ej. mueve fondos vía llamada cross-contract a estado interno:
        # lendvest `emergency*` → `LVLidoVault.executeAaveWithdraw` + `setEmergencyLenderState`, NUNCA a msg.sender).
        # Solo es peligroso si el CALLER puede colar su dirección: aparece msg.sender/tx.origin, o un param tipo
        # ADDRESS (destino potencial) se usa en el body. Si no → el caller NO alcanza los fondos → seguro. 18-jul.
        addr_params = _addr_params(func_sig)
        if not (re.search(r"msg\.sender|tx\.origin", body)
                or any(re.search(rf"\b{re.escape(p)}\b", body) for p in addr_params)):
            return False   # el caller no aparece en el body → no puede redirigirse fondos → seguro
        # Aparece el caller, PERO si es un CLAIM/withdraw-OWN (lee un registro per-user keyed by msg.sender —
        # `userDeposits(msg.sender, …)` o `balances[msg.sender]`) los fondos que salen están ACOTADOS a la cuota
        # del caller, no es un drain del balance total. Un drain a caller pasa `(msg.sender)` sin coma / como dest.
        if re.search(r"\[\s*msg\.sender\s*\]|\(\s*msg\.sender\s*,", body):
            return False
        return True
    for d in dests:
        if d.lower() in ("msg.sender", "tx.origin") or d in params:
            return True
    return False


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
    from openclaw_audit.detectors._fileutil import iter_sol_files, strip_comments, MAX_SCAN_FILES
    # Salta interfaces y ficheros FLATTEN (bundles que duplican todo el código + deps → ruido/FP). 16-jul.
    sol_files = [f for f in iter_sol_files(repo_path)
                 if "interface" not in str(f).lower() and "flatten" not in str(f).lower()]

    if not sol_files:
        return []

    # PRE-PASS (18-jul, cazado en Multipli): nombres de función PROTEGIDOS (con modifier de auth) en ALGÚN fichero
    # del repo. Un `public virtual` en una base SIN modifier que el contrato concreto OVERRIDE con auth (p.ej. base
    # `setFeeContract() public virtual` + hijo `setFeeContract() public override requiresAuth`) NO es explotable: en
    # el deploy manda el override protegido. Marcar la base = FP. Solo se salta si la función es virtual/override Y
    # su nombre está protegido en otro sitio (una función suelta sin herencia SIGUE marcándose → no sobre-suprime).
    protected_names: set[str] = set()
    for f in sol_files[:MAX_SCAN_FILES]:
        try:
            c = strip_comments(f.read_text(errors="replace"))
        except Exception:
            continue
        for fm in re.finditer(r"function\s+(\w+)\s*\([^;{]*?\{", c):
            if _ACCESS_MODIFIERS.search(c[fm.start():fm.end()]):
                protected_names.add(fm.group(1))

    findings = []
    for sol_file in sol_files[:MAX_SCAN_FILES]:
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

                # DECLARACIÓN sin cuerpo (interfaz/abstract/flatten): el ';' viene ANTES del '{' → NO puede tener
                # modifier ni body → marcarla "unprotected" es SIEMPRE FP (fix 16-jul: los 5 FP de Cap eran esto,
                # declaraciones en flatten.sol). Saltar.
                _semi = content.find(";", func_start)
                _brace = content.find("{", func_start)
                if _semi != -1 and (_brace == -1 or _semi < _brace):
                    continue

                # Firma (con modificadores) y body REAL (brace-matching, no 200 chars ciegos)
                func_sig_end = content.find("{", func_start)
                func_sig = content[func_start:func_sig_end] if func_sig_end != -1 else content[func_start:func_start+200]
                body = _real_body(content, func_sig_end)

                if _VIEW_PATTERNS.search(func_sig):
                    continue

                # INTERNAL/PRIVATE: no es llamable desde fuera → NO puede ser "unprotected access control" (la auth
                # vive en el punto de entrada público que la llama). Flagearla = FP. 19-jul: `ERC1967Utils.
                # upgradeToAndCall`/`upgradeBeaconToAndCall` de OZ (internal) rompían el claim "0 FP en toda OZ".
                # Un bug real de acceso SIEMPRE está en una función public/external.
                if re.search(r"\b(internal|private)\b", func_sig):
                    continue

                # Protegida por MODIFIER (en la firma) o por AUTH INLINE (en su propio body)
                if _ACCESS_MODIFIERS.search(func_sig) or _INLINE_AUTH.search(body):
                    continue

                # FUND_SWEEP permissionless PERO a destino FIJO (no msg.sender ni parámetro) = SEGURO:
                # el caller no puede redirigir fondos (sweep-to-recovery/treasury por keeper). FP común.
                if impact_type == "FUND_SWEEP" and not _sweep_dest_attacker_controlled(func_sig, body):
                    continue

                # Skip if it's in an interface or abstract
                # Look back to find the contract declaration
                contract_ctx = content[max(0, func_start-2000):func_start]
                if re.search(r"\b(interface|abstract)\b[^{]*{[^}]*$", contract_ctx, re.DOTALL):
                    continue

                func_name = m.group(0).split("function")[1].split("(")[0].strip()

                # BASE virtual/override protegida en el override concreto → FP (ver PRE-PASS arriba).
                if func_name in protected_names and re.search(r"\b(virtual|override)\b", func_sig):
                    continue

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
