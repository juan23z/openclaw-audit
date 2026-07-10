"""
ERC4626 Incorrect Rounding Direction Detector.

ERC4626 vaults MUST round in favor of the protocol:
  - deposit/mint (shares given to user): round DOWN shares
  - withdraw/redeem (assets given to user): round DOWN assets

If rounding goes the wrong way, share inflation or theft is possible.
"""

import logging
import re
import uuid
from pathlib import Path

_logger = logging.getLogger(__name__)

DETECTOR_INFO = {
    "name": "erc4626-rounding",
    "severity": "HIGH",
    "description": (
        "ERC4626 vault uses incorrect rounding direction. "
        "Shares minted on deposit/mint must round DOWN; "
        "assets returned on withdraw/redeem must round DOWN. "
        "Wrong rounding allows share inflation attacks or theft of assets."
    ),
    "category": "erc4626",
}

# Funciones que DEBEN redondear ABAJO (Floor) según el spec ERC-4626.
# OJO: previewMint y previewWithdraw DEBEN redondear ARRIBA (Ceil) — NO van aquí (round-up es CORRECTO ahí).
_SHOULD_ROUND_DOWN = {
    "previewdeposit",
    "converttoshares",
    "previewredeem",
    "converttoassets",
}

_ROUND_DOWN_PATTERN = re.compile(r"mulDivDown|Math\.floor|>>|/ \(|\.div\(", re.IGNORECASE)
_ROUND_UP_PATTERN = re.compile(r"mulDivUp|Math\.ceil|\+\s*1\b|\.add\(1\)|roundUp", re.IGNORECASE)

# ERC4626 function signature pattern
_FUNC_PATTERN = re.compile(
    r"function\s+(previewDeposit|previewMint|previewWithdraw|previewRedeem|"
    r"convertToShares|convertToAssets)\s*\(",
    re.IGNORECASE,
)


def scan(repo_path: Path) -> list[dict]:
    """Standalone scan — returns findings list in OpenClaw format."""
    from openclaw_audit.detectors._fileutil import iter_sol_files
    sol_files = iter_sol_files(repo_path)

    findings: list[dict] = []

    for sol_file in sol_files:
        try:
            content = sol_file.read_text(errors="replace")
        except Exception:
            continue

        # Only scan ERC4626 vaults
        if not re.search(r"ERC4626|IERC4626|_convertToShares|_convertToAssets", content):
            continue

        lines = content.splitlines()

        for m in _FUNC_PATTERN.finditer(content):
            func_name = m.group(1)
            # Solo las funciones del path deposit/redeem DEBEN redondear abajo. previewMint/previewWithdraw
            # redondean ARRIBA por spec → un round-up ahí es CORRECTO, no lo marcamos (evita FP grave).
            if func_name.lower() not in _SHOULD_ROUND_DOWN:
                continue
            start_pos = m.start()

            # Find the function body (from opening brace to closing brace, simplified)
            brace_start = content.find("{", start_pos)
            if brace_start == -1:
                continue

            # Extract ~20 lines of function body
            start_line = content[:brace_start].count("\n")
            end_line = min(start_line + 25, len(lines))
            body = "\n".join(lines[start_line:end_line])

            has_round_up = bool(_ROUND_UP_PATTERN.search(body))
            has_round_down = bool(_ROUND_DOWN_PATTERN.search(body))

            # All ERC4626 preview/convert functions should round DOWN
            # If roundUp is present without roundDown context, flag it
            if has_round_up and not has_round_down:
                affected_code = "\n".join(
                    f"  {start_line + i + 1}: {l}"
                    for i, l in enumerate(lines[start_line:end_line])
                )
                finding = {
                    "id": str(uuid.uuid4()),
                    "contest_id": "",
                    "title": f"ERC4626 Incorrect Rounding in {func_name} — Share Inflation Risk",
                    "severity": "HIGH",
                    "category": "erc4626",
                    "description": (
                        f"`{func_name}` uses round-up math (mulDivUp or equivalent). "
                        "ERC4626 spec requires all preview/convert functions to round in favor of the vault "
                        "(i.e., round DOWN for shares given to users and assets returned). "
                        "Rounding up allows an attacker to drain the vault through repeated deposits/withdrawals."
                    ),
                    "affected_code": f"{sol_file.name}:{start_line + 1}\n{affected_code}",
                    "recommendation": (
                        f"Change `{func_name}` to use mulDivDown (FixedPointMathLib) or equivalent. "
                        "See ERC4626 security considerations: https://eips.ethereum.org/EIPS/eip-4626#security-considerations"
                    ),
                    "tool_source": "custom_detector:erc4626_rounding",
                    "confidence": 0.8,
                    "llm_verified": 0,
                    "estimated_reward": 15000.0,
                }
                findings.append(finding)
                _logger.debug(
                    "[ERC4626Rounding] Found incorrect rounding in %s:%s",
                    sol_file.name, func_name,
                )

    _logger.info("[ERC4626Rounding] %d finding(s) in %s", len(findings), repo_path.name)
    return findings


# ---------------------------------------------------------------------------
# Slither AbstractDetector compatibility shim
# ---------------------------------------------------------------------------

try:
    from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification

    class ERC4626RoundingDetector(AbstractDetector):
        """Slither detector: ERC4626 incorrect rounding direction."""

        ARGUMENT = "erc4626-rounding"
        HELP = "ERC4626 vault rounds in wrong direction (mulDivUp where mulDivDown required)"
        IMPACT = DetectorClassification.HIGH
        CONFIDENCE = DetectorClassification.MEDIUM
        WIKI = "https://eips.ethereum.org/EIPS/eip-4626#security-considerations"
        WIKI_TITLE = "ERC4626 Incorrect Rounding"
        WIKI_DESCRIPTION = DETECTOR_INFO["description"]
        WIKI_EXPLOIT_SCENARIO = (
            "Attacker deposits 1 wei, receives 1 share due to rounding up. "
            "Repeats until vault is drained."
        )
        WIKI_RECOMMENDATION = "Use mulDivDown for all ERC4626 share/asset calculations."

        def _detect(self):
            results = []
            for contract in self.contracts:
                for func in contract.functions:
                    if func.name in _SHOULD_ROUND_DOWN:
                        # Basic check: look for mulDivUp calls
                        for node in func.nodes:
                            if "mulDivUp" in str(node.expression):
                                r = self.generate_result([
                                    f"Function {func.name} uses mulDivUp — should use mulDivDown",
                                    node,
                                ])
                                results.append(r)
            return results

except ImportError:
    pass
