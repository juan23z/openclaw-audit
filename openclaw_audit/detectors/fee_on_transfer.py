"""
Fee-On-Transfer Token Detector.

Detects protocols that use transferFrom and then use the input `amount`
instead of the actual received amount. Fee-on-transfer (FoT) tokens
(USDT, STA, PAXG, deflationary tokens) deduct a fee on transfer,
so the contract receives less than `amount`.

Using `amount` instead of `balanceAfter - balanceBefore` causes:
  - Incorrect accounting (protocol thinks it has more than it does)
  - Potential for insolvency via repeated deposit/withdraw cycles
"""

import logging
import re
import uuid
from pathlib import Path

_logger = logging.getLogger(__name__)

DETECTOR_INFO = {
    "name": "fee-on-transfer",
    "severity": "MEDIUM",
    "description": (
        "Contract calls transferFrom(from, to, amount) and then uses `amount` directly "
        "for balance accounting instead of measuring actual received tokens "
        "(balanceAfter - balanceBefore). Fee-on-transfer tokens will cause incorrect accounting."
    ),
    "category": "token_compatibility",
}

# transferFrom(from, TO, AMOUNT) / safeTransferFrom(token, from, TO, AMOUNT) — captura TO y AMOUNT (últimos 2 args).
# Reescrito 22-jul (T1): antes exigía que la variable de contabilidad tuviera un nombre de una lista fija
# (totalDeposited/_deposits/…) → NO disparaba ni en un bug obvio (`deposits[x]+=amount`). Ahora captura la variable
# AMOUNT del propio transferFrom y comprueba si se REUSA en contabilidad — genérico, sin depender del nombre.
_TRANSFER_FROM_PATTERN = re.compile(
    r"(?:safeTransferFrom|transferFrom)\s*\(((?:[^()]|\([^()]*\))*)\)",  # tolera 1 nivel de anidamiento: address(this)
    re.IGNORECASE,
)

# Mitigation: actual received amount calculated (balance snapshot)
_BALANCE_CHECK_PATTERN = re.compile(
    r"balanceBefore|balanceAfter|balanceOf.*before|before.*balance|"
    r"received\s*=|actualAmount|amountReceived|_received|balanceOf\(address\(this\)\)",
    re.IGNORECASE,
)

_CONTEXT_WINDOW = 22


def scan(repo_path: Path) -> list[dict]:
    """Standalone scan — returns findings list in OpenClaw format."""
    from openclaw_audit.detectors._fileutil import iter_sol_files, strip_comments
    sol_files = iter_sol_files(repo_path)

    findings: list[dict] = []
    seen_files: set[str] = set()

    for sol_file in sol_files:
        try:
            content = strip_comments(sol_file.read_text(errors="replace"))
        except Exception:
            continue

        if not _TRANSFER_FROM_PATTERN.search(content):
            continue

        lines = content.splitlines()

        for m in _TRANSFER_FROM_PATTERN.finditer(content):
            args = [a.strip() for a in m.group(1).split(",")]
            if len(args) < 2:
                continue
            to_arg, amt_arg = args[-2], args[-1]
            # Solo si el contrato RECIBE tokens (destino = address(this)); si transfiere HACIA fuera, el fee del
            # importe recibido no es un problema de SU contabilidad.
            if "address(this)" not in to_arg:
                continue
            # La variable AMOUNT debe ser un identificador simple (no un literal/expresión ya ajustada).
            _amt_m = re.match(r"[A-Za-z_]\w*$", amt_arg)
            if not _amt_m:
                continue
            amt = _amt_m.group(0)
            # NFT (ERC721/1155): `transferFrom(from, to, tokenId)` — el 3er arg es un ID, NO un importe → fee-on-transfer
            # NO aplica (es concepto de ERC20 fungible). FP verificado en OZ ERC721Wrapper. 22-jul.
            if amt.lower() in ("tokenid", "_tokenid", "id", "_id", "nftid", "tokenids", "nft") \
                    or re.search(r"721|1155|nft|wrapper", sol_file.name, re.I):
                continue

            line_no = content[:m.start()].count("\n") + 1
            ctx_start = max(0, line_no - 3)
            ctx_end = min(len(lines), line_no + _CONTEXT_WINDOW)
            context = "\n".join(lines[ctx_start:ctx_end])
            after = "\n".join(lines[line_no - 1:ctx_end])   # desde el transfer en adelante (la contabilidad va después)

            # Mitigado si mide el balance real recibido (snapshot).
            if _BALANCE_CHECK_PATTERN.search(context):
                continue

            # BUG si la MISMA variable `amount` se REUSA en contabilidad DESPUÉS del transfer (asignación/arit/mint),
            # en vez de medir lo recibido. Genérico (no depende del nombre de la variable de estado).
            _a = re.escape(amt)
            if not re.search(r"[+\-]?=\s*[^;=\n]*\b" + _a + r"\b"           # X = ... amount / X += amount
                             r"|\b" + _a + r"\b[^;\n]{0,60}[+\-]?=[^=]"       # amount ... = X  (menos común)
                             r"|_?mint\s*\([^)]*\b" + _a + r"\b"              # _mint(x, amount)
                             r"|\bshares?\b[^;\n]*\b" + _a + r"\b", after):   # shares = amount ...
                continue

            file_key = str(sol_file)
            if file_key in seen_files:
                continue
            seen_files.add(file_key)

            affected_code = "\n".join(
                f"  {ctx_start + i + 1}: {l}"
                for i, l in enumerate(lines[ctx_start:ctx_end])
            )

            finding = {
                "id": str(uuid.uuid4()),
                "contest_id": "",
                "title": f"Fee-On-Transfer Token Not Supported in {sol_file.name}",
                "severity": "MEDIUM",
                "category": "token_compatibility",
                "description": (
                    f"`{sol_file.name}` calls `transferFrom(from, to, amount)` and uses `amount` "
                    "directly for internal accounting. With fee-on-transfer tokens (e.g. USDT in "
                    "FoT mode, STA, PAXG, deflationary tokens), the contract receives less than "
                    "`amount`. This causes inflated internal balances, potential fund loss for LPs, "
                    "or a slow-drain attack via repeated deposit/withdraw."
                ),
                "affected_code": f"{sol_file.name}:{line_no}\n{affected_code}",
                "impact": (
                    "Protocol insolvency over time if FoT tokens are used. "
                    "Attacker can exploit the discrepancy to extract more than deposited."
                ),
                "recommendation": (
                    "Measure actual received amount using balance snapshots:\n"
                    "  uint256 balanceBefore = token.balanceOf(address(this));\n"
                    "  token.transferFrom(from, address(this), amount);\n"
                    "  uint256 received = token.balanceOf(address(this)) - balanceBefore;\n"
                    "  // Use `received` for accounting, not `amount`"
                ),
                "tool_source": "custom_detector:fee_on_transfer",
                "confidence": 0.75,
                "llm_verified": 0,
                "estimated_reward": 5000.0,
            }
            findings.append(finding)
            _logger.debug("[FeeOnTransfer] Found in %s:%d", sol_file.name, line_no)

    _logger.info("[FeeOnTransfer] %d finding(s) in %s", len(findings), repo_path.name)
    return findings


try:
    from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification

    class FeeOnTransferDetector(AbstractDetector):
        ARGUMENT = "fee-on-transfer"
        HELP = "transferFrom uses input amount instead of actual received — FoT token incompatibility"
        IMPACT = DetectorClassification.MEDIUM
        CONFIDENCE = DetectorClassification.MEDIUM
        WIKI = "https://medium.com/coinmonks/fee-on-transfer-tokens-in-defi-101"
        WIKI_TITLE = "Fee-On-Transfer Token Compatibility"
        WIKI_DESCRIPTION = DETECTOR_INFO["description"]
        WIKI_EXPLOIT_SCENARIO = (
            "User deposits USDT (FoT mode) — protocol records `amount` but receives `amount - fee`. "
            "Protocol accounting is off from the start; final withdrawer gets less than owed."
        )
        WIKI_RECOMMENDATION = "Use balanceBefore/balanceAfter to measure actual received tokens."

        def _detect(self):
            results = []
            for contract in self.contracts:
                for func in contract.functions:
                    for node in func.nodes:
                        if "transferFrom" in str(node.expression):
                            r = self.generate_result([
                                "transferFrom — verify actual received amount is used, not input amount",
                                node,
                            ])
                            results.append(r)
            return results

except ImportError:
    pass
