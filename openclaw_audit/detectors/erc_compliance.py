"""
ERC Compliance Detector — verifica conformidad con ERC20/ERC721/ERC1155/ERC4626.
═══════════════════════════════════════════════════════════════════════════════

Los contratos que DICEN implementar un ERC pero no lo hacen correctamente rompen
la composabilidad con routers/aggregators/vaults que dependen del estándar.

Bugs comunes:
  - transfer() no devuelve bool (USDT legacy) → SafeERC20 no puede wrappear
  - transferFrom() devuelve false en vez de revertir → el caller asume éxito
  - approve() sin evento Approval → wallets no actualizan allowances en UI
  - ERC4626: previewWithdraw/previewRedeem redondean a favor del usuario en vez
    de a favor del protocolo (EIP-4626 §5: MUST round DOWN para shares, UP para assets)
  - ERC721: ownerOf() no revierte en token inexistente (devuelve address(0))
  - ERC1155: safeBatchTransferFrom() sin checks de arrays mismatched lengths

Nota: busca contratos que HEREDAN IERC20/IERC721/etc. ó declarasen compatibility
con el estándar. No aplica detección de FP a contratos test o mock.
"""

import logging
import re
import uuid
from pathlib import Path
from openclaw_audit.detectors._fileutil import iter_sol_files

_logger = logging.getLogger(__name__)

DETECTOR_INFO = {
    "name": "erc-compliance",
    "severity": "HIGH",
    "description": "Implementación no-conforme con ERC estándar — rompe composabilidad.",
    "category": "erc_compliance",
}

# ── Regex: herencia de ERC ───────────────────────────────────────────────────
_IS_ERC20 = re.compile(
    r"(?:is|,)\s*(?:IERC20(?!Metadata|Permit|Burnable)|ERC20(?!Burnable|Snapshot|Votes|Permit|FlashMint|Wrapper|Capped|Pausable|PresetMinterPauser|PresetFixedSupply)\b)",
    re.IGNORECASE,
)
_IS_ERC721 = re.compile(
    r"(?:is|,)\s*(?:IERC721(?!Metadata|Enumerable)|ERC721(?!A\b|Upgradeable|Enumerable|Metadata|URIStorage|Royalty|Burnable|Pausable|PresetMinterPauser|PresetMinterPauserAutoId)\b)",
    re.IGNORECASE,
)
_IS_ERC1155 = re.compile(
    r"(?:is|,)\s*(?:IERC1155|ERC1155(?!Burnable|Supply|Pausable|PresetMinterPauser|Upgradeable)\b)",
    re.IGNORECASE,
)
_IS_ERC4626 = re.compile(
    r"(?:is|,)\s*(?:IERC4626|ERC4626(?!Upgradeable)\b)",
    re.IGNORECASE,
)

# ── ERC20: funciones obligatorias (name → regex que debe aparecer en el fichero) ─
_ERC20_REQUIRED = [
    ("transfer",     re.compile(r"function\s+transfer\s*\(\s*address\b[^)]*\)\s*[^;{]*\breturns\s*\(\s*bool\s*\)", re.IGNORECASE)),
    ("transferFrom", re.compile(r"function\s+transferFrom\s*\(\s*address\b[^)]*\)\s*[^;{]*\breturns\s*\(\s*bool\s*\)", re.IGNORECASE)),
    ("approve",      re.compile(r"function\s+approve\s*\(\s*address\b[^)]*\)\s*[^;{]*\breturns\s*\(\s*bool\s*\)", re.IGNORECASE)),
    ("allowance",    re.compile(r"function\s+allowance\s*\(", re.IGNORECASE)),
    ("balanceOf",    re.compile(r"function\s+balanceOf\s*\(", re.IGNORECASE)),
    ("totalSupply",  re.compile(r"function\s+totalSupply\s*\(", re.IGNORECASE)),
]

# ERC20: transfer/transferFrom que NO devuelven bool (viejo USDT, vuln de integración)
_TRANSFER_NO_BOOL = re.compile(
    r"function\s+(transfer|transferFrom)\s*\([^)]*\)\s+(?:external|public)(?:\s+(?:override|virtual))?\s*(?:\{|;)",
    re.IGNORECASE,
)

# ERC20: evento Transfer debe emitirse en transfer/transferFrom/mint/burn
_EMIT_TRANSFER = re.compile(r"\bемit\s+Transfer\b|\bemit\s+Transfer\b", re.IGNORECASE)

# ── ERC4626: previewWithdraw/previewRedeem deben usar mulDivUp (round UP para assets) ─
_PREVIEW_WITHDRAW = re.compile(
    r"function\s+(?:previewWithdraw|previewRedeem)\s*\([^)]*\)[^{]*\{[^}]{0,600}",
    re.IGNORECASE | re.DOTALL,
)
# Incorrecto: usa mulDiv (floor) o / sin Up — EIP-4626 exige ceil para assets
_MULDIV_FLOOR_IN_PREVIEW = re.compile(r"\bmulDiv\b(?!Up)", re.IGNORECASE)
_DIV_PLAIN = re.compile(r"\s/\s")

# ── ERC721: ownerOf que puede devolver address(0) ────────────────────────────
_OWNEROF_NO_REVERT = re.compile(
    r"function\s+ownerOf\s*\([^)]*\)[^{]*\{([^}]{0,400})\}",
    re.IGNORECASE | re.DOTALL,
)

# ── ERC1155: safeBatchTransferFrom sin length check ─────────────────────────
_SAFEBATCH = re.compile(
    r"function\s+safeBatchTransferFrom\s*\([^)]*\)[^{]*\{([^}]{0,600})\}",
    re.IGNORECASE | re.DOTALL,
)

# ── ERC20: return false en vez de revert ─────────────────────────────────────
_RETURN_FALSE = re.compile(r"\breturn\s+false\s*;", re.IGNORECASE)

# ── Helpers ──────────────────────────────────────────────────────────────────

def _get_contract_name(content: str, inherit_match_pos: int) -> str:
    before = content[:inherit_match_pos]
    m = list(re.finditer(r"contract\s+(\w+)\s", before))
    return m[-1].group(1) if m else "Unknown"


def _in_comment(content: str, pos: int) -> bool:
    line_start = content.rfind("\n", 0, pos) + 1
    line = content[line_start:pos].lstrip()
    return line.startswith("//") or line.startswith("*")


def _strip_comments(text: str) -> str:
    text = re.sub(r"//[^\n]*", "", text)
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    return text


# ── Main scan ────────────────────────────────────────────────────────────────

def scan(repo_path: Path, contest_id: str = "") -> list[dict]:
    """Detecta implementaciones ERC no-conformes."""
    sol_files = iter_sol_files(repo_path)
    if not sol_files:
        return []

    findings = []
    seen: set = set()

    for sol_file in sol_files[:30]:
        try:
            content = sol_file.read_text(errors="replace")
        except Exception:
            continue

        stripped = _strip_comments(content)

        # Skip interface files, abstract-only files, and non-token implementation files
        fname_stem = sol_file.stem
        _is_iface = (
            re.match(r'^I[A-Z]', fname_stem)           # IToken, IERC20, IBond…
            or fname_stem.endswith("Interface")
            or fname_stem.endswith("Mock")
            or fname_stem.startswith("Mock")
            or fname_stem.startswith("Test")
            or "interface" in fname_stem.lower()
            or re.search(r'^\s*interface\s+\w', content, re.MULTILINE)  # Solidity interface keyword
            or re.search(r'^\s*abstract\s+contract\s', content, re.MULTILINE)  # abstract contract
            # Gateway/Bridge/Router contracts USE tokens but don't implement ERC20
            or re.search(r'contract\s+\w*(?:Gateway|Bridge|Router|Handler|Manager|Adapter|Proxy|Wrapper|Factory|Registry|Controller|Operator|Distributor|Forwarder|Relayer)\w*\s', content)
        )

        # ── ERC20 compliance ─────────────────────────────────────────────────
        if not _is_iface and _IS_ERC20.search(content):
            contract_name = _get_contract_name(content, _IS_ERC20.search(content).start())

            # Check 1: transfer/transferFrom con return type void (no-bool)
            for m in _TRANSFER_NO_BOOL.finditer(stripped):
                fname = m.group(1)
                key = (sol_file.name, contract_name, f"novoid_{fname}")
                if key in seen:
                    continue
                # Confirm it truly has no returns clause
                sig = m.group(0)
                if "returns" in sig.lower():
                    continue
                seen.add(key)
                findings.append({
                    "id": str(uuid.uuid4()),
                    "contest_id": contest_id,
                    "title": f"ERC20 non-compliance: {fname}() missing bool return in {contract_name}",
                    "description": (
                        f"`{contract_name}.{fname}()` in `{sol_file.name}` does not return `bool` "
                        f"as required by EIP-20.\n\n"
                        f"**Impact**: Any contract using `SafeERC20.safeTransfer()` or checking the "
                        f"return value will fail to integrate. DEX routers and lending markets that "
                        f"call `transfer()` and check the return expect `true` on success. "
                        f"A missing return causes a reverting call from safe wrappers.\n\n"
                        f"**Precedent**: USDT's non-standard `transfer()` (no return bool) caused "
                        f"widespread integration issues and multiple critical bugs in DeFi.\n\n"
                        f"**Fix**: Change signature to `function {fname}(...) external returns (bool)` "
                        f"and `return true` at the end of the success path."
                    ),
                    "severity": "high",
                    "category": "erc_compliance",
                    "affected_code": f"{sol_file.name}:{contract_name}.{fname}",
                    "confidence": 0.75,
                    "estimated_reward": 10000,
                    "source": "erc_compliance",
                })
                _logger.info("[ErcCompliance] ERC20 void-%s in %s::%s", fname, sol_file.name, contract_name)

            # Check 2: transferFrom returns false instead of reverting
            # Find transferFrom body
            for m in re.finditer(
                r"function\s+transferFrom\s*\([^)]*\)\s*(?:external|public)[^{]*\{([^}]{0,800})\}",
                stripped, re.IGNORECASE | re.DOTALL
            ):
                body = m.group(1)
                if _RETURN_FALSE.search(body):
                    key = (sol_file.name, contract_name, "transferFrom_false")
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append({
                        "id": str(uuid.uuid4()),
                        "contest_id": contest_id,
                        "title": f"ERC20 non-compliance: transferFrom() returns false instead of reverting in {contract_name}",
                        "description": (
                            f"`{contract_name}.transferFrom()` in `{sol_file.name}` returns `false` "
                            f"on failure instead of reverting.\n\n"
                            f"**Impact**: Callers that do not check return values (violating EIP-20 "
                            f"recommendations, but common in practice) will believe the transfer succeeded "
                            f"when it silently failed. This is the root cause of many DeFi exploits.\n\n"
                            f"**Fix**: Replace `return false` with `revert InsufficientAllowance()` / "
                            f"`revert InsufficientBalance()` as appropriate. Follow the ERC20 spec: "
                            f"revert on any failure condition."
                        ),
                        "severity": "high",
                        "category": "erc_compliance",
                        "affected_code": f"{sol_file.name}:{contract_name}.transferFrom",
                        "confidence": 0.80,
                        "estimated_reward": 15000,
                        "source": "erc_compliance",
                    })
                    _logger.info("[ErcCompliance] transferFrom returns false in %s::%s", sol_file.name, contract_name)

            # Check 3: missing required ERC20 functions
            for fname, func_re in _ERC20_REQUIRED:
                if not func_re.search(stripped):
                    key = (sol_file.name, contract_name, f"missing_{fname}")
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append({
                        "id": str(uuid.uuid4()),
                        "contest_id": contest_id,
                        "title": f"ERC20 non-compliance: missing or wrong signature for {fname}() in {contract_name}",
                        "description": (
                            f"`{contract_name}` in `{sol_file.name}` claims ERC20 compatibility "
                            f"(inherits IERC20/ERC20) but `{fname}()` is missing or has a non-standard "
                            f"signature (e.g., no `bool` return).\n\n"
                            f"**Impact**: Breaks composability — any protocol that calls "
                            f"`IERC20({contract_name}).{fname}()` will fail at runtime or compile time.\n\n"
                            f"**Fix**: Implement `{fname}` with the exact EIP-20 signature."
                        ),
                        "severity": "medium",
                        "category": "erc_compliance",
                        "affected_code": f"{sol_file.name}:{contract_name}.{fname}",
                        "confidence": 0.65,
                        "estimated_reward": 5000,
                        "source": "erc_compliance",
                    })
                    _logger.debug("[ErcCompliance] ERC20 missing %s in %s::%s", fname, sol_file.name, contract_name)

        # ── ERC4626 rounding compliance ──────────────────────────────────────
        if not _is_iface and _IS_ERC4626.search(content):
            contract_name = _get_contract_name(content, _IS_ERC4626.search(content).start())

            for m in _PREVIEW_WITHDRAW.finditer(stripped):
                fn_start = content.find(m.group(0)[:60])
                fn_match = re.search(r"function\s+(\w+)\s*\(", m.group(0))
                if not fn_match:
                    continue
                fn_name = fn_match.group(1)
                body = m.group(0)
                # EIP-4626: previewWithdraw and previewRedeem MUST round UP (ceil)
                # so users can't extract more than maxWithdraw
                uses_floor = _MULDIV_FLOOR_IN_PREVIEW.search(body) or _DIV_PLAIN.search(body)
                uses_ceil = re.search(r"\bmulDivUp\b|\bceil\b|\bCEIL\b|\bRoundup\b", body, re.IGNORECASE)
                if uses_floor and not uses_ceil:
                    key = (sol_file.name, contract_name, f"4626_round_{fn_name}")
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append({
                        "id": str(uuid.uuid4()),
                        "contest_id": contest_id,
                        "title": f"ERC4626 non-compliance: {fn_name}() rounds DOWN (must round UP) in {contract_name}",
                        "description": (
                            f"`{contract_name}.{fn_name}()` in `{sol_file.name}` uses floor division "
                            f"(`mulDiv` / `/`) instead of ceiling division.\n\n"
                            f"**EIP-4626 §5 requirement**: `previewWithdraw` and `previewRedeem` MUST "
                            f"round UP (ceiling) to prevent users from requesting more assets than are "
                            f"actually available after rounding.\n\n"
                            f"**Impact**: A user can call `withdraw(previewWithdraw(assets))` and receive "
                            f"slightly more assets than they are entitled to. Repeated over many "
                            f"transactions this drains the vault by 1 wei per operation.\n\n"
                            f"**Fix**: Replace `mulDiv(a, b, c)` with `mulDivUp(a, b, c)` (OpenZeppelin "
                            f"Math), or use `(a * b + c - 1) / c` for manual ceiling."
                        ),
                        "severity": "medium",
                        "category": "erc_compliance",
                        "affected_code": f"{sol_file.name}:{contract_name}.{fn_name}",
                        "confidence": 0.72,
                        "estimated_reward": 5000,
                        "source": "erc_compliance",
                    })
                    _logger.info("[ErcCompliance] ERC4626 rounding %s in %s::%s", fn_name, sol_file.name, contract_name)

        # ── ERC721 compliance ────────────────────────────────────────────────
        if not _is_iface and _IS_ERC721.search(content):
            contract_name = _get_contract_name(content, _IS_ERC721.search(content).start())

            # Check: ownerOf that doesn't revert on non-existent token (returns address(0))
            for m in _OWNEROF_NO_REVERT.finditer(stripped):
                body = m.group(1)
                has_revert = bool(re.search(r"\brevert\b|\brequire\b", body, re.IGNORECASE))
                returns_zero = bool(re.search(r"return\s+address\s*\(\s*0\s*\)", body, re.IGNORECASE))
                if returns_zero and not has_revert:
                    key = (sol_file.name, contract_name, "ownerOf_no_revert")
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append({
                        "id": str(uuid.uuid4()),
                        "contest_id": contest_id,
                        "title": f"ERC721 non-compliance: ownerOf() returns address(0) instead of reverting in {contract_name}",
                        "description": (
                            f"`{contract_name}.ownerOf()` in `{sol_file.name}` returns `address(0)` "
                            f"for non-existent tokens instead of reverting.\n\n"
                            f"**EIP-721 requirement**: `ownerOf` MUST throw for tokens assigned to "
                            f"the zero address.\n\n"
                            f"**Impact**: Callers that check `ownerOf(tokenId) == msg.sender` will pass "
                            f"for non-existent token IDs (anyone appears to own unminted tokens). "
                            f"This can bypass access control gates, break marketplace integrations, "
                            f"or allow unauthorized token operations.\n\n"
                            f"**Fix**: Add `require(_owners[tokenId] != address(0), 'ERC721: invalid token')` "
                            f"at the start of `ownerOf()`."
                        ),
                        "severity": "high",
                        "category": "erc_compliance",
                        "affected_code": f"{sol_file.name}:{contract_name}.ownerOf",
                        "confidence": 0.80,
                        "estimated_reward": 10000,
                        "source": "erc_compliance",
                    })
                    _logger.info("[ErcCompliance] ERC721 ownerOf no-revert in %s::%s", sol_file.name, contract_name)

        # ── ERC1155 compliance ───────────────────────────────────────────────
        if not _is_iface and _IS_ERC1155.search(content):
            contract_name = _get_contract_name(content, _IS_ERC1155.search(content).start())

            for m in _SAFEBATCH.finditer(stripped):
                body = m.group(1)
                has_length_check = bool(re.search(
                    r"\.length\s*[!=]=\s*\w+\.length|require.*\.length",
                    body, re.IGNORECASE
                ))
                if not has_length_check:
                    key = (sol_file.name, contract_name, "safeBatch_no_length")
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append({
                        "id": str(uuid.uuid4()),
                        "contest_id": contest_id,
                        "title": f"ERC1155 non-compliance: safeBatchTransferFrom() missing array length check in {contract_name}",
                        "description": (
                            f"`{contract_name}.safeBatchTransferFrom()` in `{sol_file.name}` does not "
                            f"verify that `ids.length == amounts.length` before iterating.\n\n"
                            f"**EIP-1155 requirement**: The function MUST throw if `ids.length != amounts.length`.\n\n"
                            f"**Impact**: If `ids` is longer than `amounts`, the loop reads out-of-bounds "
                            f"(Solidity panics with index-out-of-bounds), causing a DoS. If `amounts` is "
                            f"longer, excess amounts are silently ignored, breaking accounting.\n\n"
                            f"**Fix**: Add `require(ids.length == amounts.length, 'ERC1155: length mismatch')` "
                            f"at the start of `safeBatchTransferFrom()`."
                        ),
                        "severity": "medium",
                        "category": "erc_compliance",
                        "affected_code": f"{sol_file.name}:{contract_name}.safeBatchTransferFrom",
                        "confidence": 0.75,
                        "estimated_reward": 5000,
                        "source": "erc_compliance",
                    })
                    _logger.info("[ErcCompliance] ERC1155 safeBatch no-length in %s::%s", sol_file.name, contract_name)

    return findings
