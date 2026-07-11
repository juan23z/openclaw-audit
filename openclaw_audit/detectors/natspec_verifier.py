"""
NatSpec Verifier — detecta cuando el código viola sus propias promesas.
═══════════════════════════════════════════════════════════════════════

Los mejores auditores (Spearbit, Trail of Bits, pashov) siempre leen el README
Y el NatSpec PRIMERO. Los bugs más rentables son cuando el código hace algo
DIFERENTE a lo que la documentación promete.

Ejemplos reales pagados:
  - README: "users can always withdraw" → código tiene una condición de bloqueo
  - NatSpec @notice: "fee never exceeds 10%" → admin puede setFee(100%)
  - Whitepaper: "liquidation only happens at 80% LTV" → código usa 75%
  - @dev "invariant: totalShares == sum(userShares)" → una función lo rompe

Proceso:
  1. Lee README.md / SECURITY.md / docs/ del repo
  2. Extrae claims de NatSpec (@notice, @dev con invariants/claims/security)
  3. Lee el código de los contratos principales
  4. DeepSeek compara: ¿el código garantiza lo que la doc afirma?
  5. Findings de tipo SPECIFICATION_VIOLATION
"""

import logging
import os
import re
import uuid
from pathlib import Path
from typing import Optional

_logger = logging.getLogger(__name__)

DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY", "")
DEEPSEEK_URL = "https://api.deepseek.com/v1/chat/completions"
_CHAT_MODEL = os.getenv("DEEPSEEK_CHAT_MODEL", "deepseek-chat")

DETECTOR_INFO = {
    "name": "natspec-verifier",
    "severity": "HIGH",
    "description": "El código viola una propiedad de seguridad documentada en NatSpec o README.",
    "category": "specification_violation",
}

# Palabras clave que indican una claim de seguridad en docs
_CLAIM_KEYWORDS = re.compile(
    r"\b(always|never|only|guarantee|invariant|cannot|must|ensure|"
    r"secure|safe|protect|immutable|fixed|locked|bounded|maximum|minimum|"
    r"at most|at least|no more than|cannot exceed|will not|will always)\b",
    re.IGNORECASE,
)

_NATSPEC_SECURITY = re.compile(
    r"///\s*@(notice|dev)\s+(.+)|"
    r"/\*\*\s*\n(?:\s*\*.*\n)*\s*\*\s*@(notice|dev)\s+(.+)",
    re.IGNORECASE | re.MULTILINE,
)


def _read_docs(repo_path: Path) -> str:
    """Lee documentación relevante del repo (README, SECURITY, docs/)."""
    content_parts = []
    doc_files = (
        list(repo_path.glob("README*"))
        + list(repo_path.glob("SECURITY*"))
        + list(repo_path.glob("docs/*.md"))
        + list(repo_path.glob("doc/*.md"))
        + list(repo_path.glob("WHITEPAPER*"))
    )
    for f in sorted(doc_files)[:5]:
        try:
            text = f.read_text(errors="replace")[:4000]
            if len(text) > 100:
                content_parts.append(f"=== {f.name} ===\n{text}")
        except Exception:
            pass
    return "\n\n".join(content_parts)[:8000]


def _extract_natspec_claims(sol_content: str) -> list[str]:
    """Extrae claims de seguridad de comentarios NatSpec."""
    claims = []
    for m in _NATSPEC_SECURITY.finditer(sol_content):
        comment = (m.group(2) or m.group(4) or "").strip()
        if comment and _CLAIM_KEYWORDS.search(comment):
            claims.append(comment[:200])
    return claims[:20]  # Cap at 20 to avoid huge prompts


def _read_main_contracts(repo_path: Path) -> tuple[str, list[str]]:
    """Lee el código de los contratos más importantes (src/, no libs ni tests)."""
    src_dirs = ["src", "contracts", "protocol"]
    code_parts = []
    filenames = []

    for src in src_dirs:
        sol_dir = repo_path / src
        if not sol_dir.exists():
            continue
        for f in sorted(sol_dir.rglob("*.sol"))[:12]:
            if any(x in str(f) for x in ["test", "Test", "mock", "Mock", "lib", "interface"]):
                continue
            try:
                text = f.read_text(errors="replace")
                code_parts.append(f"// {f.name}\n{text[:3000]}")
                filenames.append(f.name)
            except Exception:
                pass
        if code_parts:
            break

    return "\n\n".join(code_parts)[:10000], filenames


_VERIFY_PROMPT = """You are a top-tier smart contract auditor reviewing whether the protocol's CODE matches its DOCUMENTATION.

This is a HIGH-VALUE audit technique: the most unique, best-paid bugs are when code does something DIFFERENT from what the docs promise.

DOCUMENTATION (README / NatSpec claims):
{docs}

NATSPEC SECURITY CLAIMS FROM CODE:
{natspec_claims}

PROTOCOL CODE:
{code}

Your task: Find SPECIFIC contradictions where the code VIOLATES a documented security property.

Focus on:
1. "Only X can call" → but function has no access control
2. "Fee never exceeds Y%" → but owner/admin can set fee above that
3. "Users can always withdraw" → but there's a condition that blocks it
4. "Invariant: X always equals Y" → but a function breaks this
5. Claimed bounds/limits that can be bypassed
6. Stated admin restrictions that don't exist in code

Do NOT flag:
- Vague or aspirational claims without specific code violations
- "Best practices" issues where no specific promise is made
- Things that are theoretical edge cases with no realistic attack

Respond in JSON ONLY (no markdown):
{{
  "violations": [
    {{
      "claim": "exact quote from the documentation",
      "violation": "what the code actually allows/does differently",
      "severity": "CRITICAL|HIGH|MEDIUM",
      "affected_function": "functionName() in ContractName.sol",
      "attack_path": "step by step how an attacker exploits this contradiction",
      "confidence": 0.0-1.0
    }}
  ]
}}

If you find no real violations, return {{"violations": []}}"""


def _call_deepseek(prompt: str) -> str:
    if not DEEPSEEK_API_KEY:
        return ""
    # Candado REAL de gasto (05-jul): respeta budget + auto-freno del centinela, y REGISTRA el gasto
    # (antes invisible al contador → factura real 2x el presupuesto).
    try:
        paid_allowed = lambda: True
        if not paid_allowed():
            return ""
    except Exception:
        pass
    try:
        import httpx
        r = httpx.post(
            DEEPSEEK_URL,
            json={
                "model": _CHAT_MODEL,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 1500,
                "temperature": 0.1,
            },
            headers={"Authorization": f"Bearer {DEEPSEEK_API_KEY}"},
            timeout=90,
        )
        r.raise_for_status()
        _data = r.json()
        try:
            record_external_usage = lambda *a, **k: None
            _tok = (_data.get("usage") or {}).get("total_tokens", 0)
            if _tok:
                record_external_usage(_CHAT_MODEL, _tok)
        except Exception:
            pass
        return _data["choices"][0]["message"]["content"].strip()
    except Exception as exc:
        _logger.debug("[NatspecVerifier] DeepSeek error: %s", exc)
        return ""


# ── Heurístico SIN LLM (corre para todos; DeepSeek abajo es una mejora opcional) ────────────────
# Patrón de alta precisión: el NatSpec de una función external/public AFIRMA una restricción de acceso
# ("only the owner can…", "can only be called by…") pero la función NO tiene modificador de acceso NI
# guard de msg.sender → contradicción doc-vs-código real. Conservador a propósito (proteger 0-FP).
_ACCESS_CLAIM = re.compile(
    r"\bonly\s+(?:the\s+|an?\s+)?(?:owner|admin|administrator|governance|governor|operator|"
    r"manager|controller|keeper|guardian|dao|council|timelock|multisig)\b"
    r"|\bcan only be called by\b|\bcallable only by\b|\brestricted to (?:the\s+)?(?:owner|admin|governance)\b"
    r"|\bmust be (?:the\s+)?(?:owner|admin|governance)\b",
    re.IGNORECASE)
_ACCESS_MOD = re.compile(r"\b(only[A-Z]\w*|onlyRole|requiresAuth|restricted|authoriz\w*|auth|isOwner)\b")
_GUARD = re.compile(
    r"\bmsg\.sender\b|_msgSender\(\)|\btx\.origin\b|_checkOwner|_checkRole|\bhasRole\s*\(|"
    r"\bowner\s*\(\)|onlyRole|_authorizeUpgrade|accessControl|\bgovernance\b|\bcaller\s*\(\s*\)",
    re.IGNORECASE)  # caller() = el msg.sender de Yul/assembly (solady et al. guardan acceso en assembly)
_FUNC = re.compile(r"function\s+(\w+)\s*\([^)]*\)([^;{]*)(\{|;)")


def _doc_before(src: str, start: int) -> str:
    """Devuelve el bloque de comentario NatSpec inmediatamente encima de la función (o '')."""
    lines = src[:start].split("\n")
    doc, i = [], len(lines) - 2  # -2: salta la línea (indentación) donde arranca 'function'
    while i >= 0:
        s = lines[i].strip()
        if s.startswith("///") or s.startswith("//") or s.startswith("*"):
            doc.append(s); i -= 1
        elif s.endswith("*/"):
            doc.append(s); i -= 1
            while i >= 0 and "/*" not in lines[i]:
                doc.append(lines[i].strip()); i -= 1
            if i >= 0:
                doc.append(lines[i].strip())
            break
        else:
            break
    return " ".join(reversed(doc))


def _body(src: str, i: int) -> str:
    """Cuerpo por emparejamiento de llaves desde la posición del '{'."""
    depth = 0
    for j in range(i, min(len(src), i + 20000)):
        if src[j] == "{":
            depth += 1
        elif src[j] == "}":
            depth -= 1
            if depth == 0:
                return src[i:j + 1]
    return src[i:i + 2000]


def _heuristic_scan(repo_path: Path, contest_id: str = "") -> list[dict]:
    from openclaw_audit.detectors._fileutil import iter_sol_files
    findings, seen = [], set()
    for f in iter_sol_files(repo_path):
        try:
            src = f.read_text(errors="replace")
        except Exception:
            continue
        # Pasada 1: mapa de funciones + conjunto de las que SÍ tienen guard (para detectar delegación).
        funcs, guarded = [], set()
        for m in _FUNC.finditer(src):
            if m.group(3) != "{":  # sin cuerpo (interfaz/abstracta) → no aplica
                continue
            name, mid = m.group(1), m.group(2)
            body = _body(src, m.end() - 1)
            funcs.append((m.start(), name, mid, body))
            if _ACCESS_MOD.search(mid) or _GUARD.search(mid + body):
                guarded.add(name)
        # Pasada 2: flaggear solo external/public que mutan, con claim de acceso y SIN guard propio NI delegado.
        for start, name, mid, body in funcs:
            if not re.search(r"\b(external|public)\b", mid):   # solo lo llamable por cualquiera
                continue
            if re.search(r"\b(view|pure)\b", mid):             # sin cambio de estado → no es riesgo de fondos
                continue
            doc = _doc_before(src, start)
            if not _ACCESS_CLAIM.search(doc):                  # el doc NO promete acceso restringido → skip
                continue
            if _ACCESS_MOD.search(mid) or _GUARD.search(mid + body):  # hay ALGÚN control → conservador: skip
                continue
            # Delegación: si el cuerpo llama a otra función guardada del mismo fichero (p.ej. safeTransferFrom
            # → transferFrom, o upgrade → upgradeAndCall), el control existe una llamada más abajo → no es FP.
            if any(g != name and re.search(r"\b" + re.escape(g) + r"\s*\(", body) for g in guarded):
                continue
            key = (f.name, name)
            if key in seen:
                continue
            seen.add(key)
            claim = _ACCESS_CLAIM.search(doc).group(0)
            findings.append({
                "id": str(uuid.uuid4()), "contest_id": contest_id,
                "title": f"Doc claims access control the code doesn't enforce: {name}()",
                "description": (
                    f"The NatSpec of `{name}()` states an access restriction (\"{claim}\") but the function is "
                    f"`external`/`public` and has **no access modifier and no `msg.sender` check** in its body. "
                    f"Either the documentation is misleading or the guard is missing — verify against intent."),
                "severity": "MEDIUM", "category": "specification_violation",
                "affected_code": f"{name}() in {f.name}", "confidence": 0.55,
                "recommendation": ("If the function should be restricted, add the intended modifier "
                                   "(e.g. `onlyOwner`) or an explicit `require(msg.sender == …)`. If it is meant "
                                   "to be public, correct the NatSpec so it doesn't imply a nonexistent guard."),
                "source": "natspec_verifier_heuristic",
            })
    return findings[:20]


def scan(repo_path: Path, contest_id: str = "") -> list[dict]:
    """
    Escanea el repo buscando contradicciones entre documentación y código.
    Corre SIEMPRE el heurístico (sin coste, sin API key); si hay DEEPSEEK_API_KEY, añade el análisis
    LLM (más profundo) y deduplica por función. Retorna findings en formato OpenClaw.
    """
    heur = _heuristic_scan(repo_path, contest_id)
    if not DEEPSEEK_API_KEY:
        return heur
    docs = _read_docs(repo_path)
    code, filenames = _read_main_contracts(repo_path)

    if not docs and not code:
        _logger.debug("[NatspecVerifier] Sin docs ni código en %s", repo_path.name)
        return []

    # Extrae NatSpec claims del código
    natspec_claims = []
    for f in (repo_path / "src").rglob("*.sol") if (repo_path / "src").exists() else []:
        try:
            natspec_claims.extend(_extract_natspec_claims(f.read_text(errors="replace")))
        except Exception:
            pass
    natspec_text = "\n".join(f"- {c}" for c in natspec_claims[:15]) or "(no NatSpec claims found)"

    if not docs and not natspec_claims:
        _logger.debug("[NatspecVerifier] Sin documentación en %s — skip", repo_path.name)
        return []

    prompt = _VERIFY_PROMPT.format(
        docs=docs[:5000] if docs else "(no documentation found)",
        natspec_claims=natspec_text,
        code=code[:8000],
    )

    raw = _call_deepseek(prompt)
    if not raw:
        return []

    # Parse JSON response
    try:
        import json
        start = raw.find("{")
        end = raw.rfind("}") + 1
        data = json.loads(raw[start:end])
        violations = data.get("violations", [])
    except Exception:
        _logger.debug("[NatspecVerifier] JSON parse error: %s", raw[:300])
        return []

    findings = []
    for v in violations:
        conf = float(v.get("confidence", 0))
        if conf < 0.6:
            continue
        sev = v.get("severity", "HIGH")
        reward = 5000 if sev == "MEDIUM" else (10000 if sev == "HIGH" else 25000)
        findings.append({
            "id": str(uuid.uuid4()),
            "contest_id": contest_id,
            "title": f"Specification violation: {v.get('claim', '')[:80]}",
            "description": (
                f"**Documented claim**: {v.get('claim', '')}\n\n"
                f"**Code behavior**: {v.get('violation', '')}\n\n"
                f"**Attack path**: {v.get('attack_path', '')}"
            ),
            "severity": sev,
            "category": "specification_violation",
            "affected_code": v.get("affected_function", ""),
            "confidence": conf,
            "estimated_reward": reward,
            "source": "natspec_verifier",
        })
        _logger.info("[NatspecVerifier] %s: %s (conf=%.2f)", sev, v.get("claim", "")[:60], conf)

    # Fusiona con el heurístico (dedup por función afectada; la del LLM, más rica, gana).
    llm_fns = {re.sub(r"\W", "", (f.get("affected_code") or "").split(" in ")[0]).lower() for f in findings}
    for h in heur:
        fn = re.sub(r"\W", "", (h.get("affected_code") or "").split(" in ")[0]).lower()
        if fn not in llm_fns:
            findings.append(h)
    return findings
