"""
Donation Attack Detector.

Contracts that use token.balanceOf(address(this)) for accounting instead of
a tracked state variable are vulnerable to donation attacks: an attacker
sends tokens directly to the contract, inflating the "balance" and manipulating
share prices, redemption ratios, or pool invariants.
"""

import logging
import re
import uuid
from pathlib import Path

_logger = logging.getLogger(__name__)

DETECTOR_INFO = {
    "name": "donation-attack",
    "severity": "HIGH",
    "description": (
        "Contract uses balanceOf(address(this)) or address(this).balance for share/price "
        "calculations instead of a tracked state variable. An attacker can donate tokens "
        "directly to manipulate the accounting, causing incorrect share issuance or price manipulation."
    ),
    "category": "token_accounting",
}

# Pattern: balanceOf(address(this)) used in arithmetic or assignment
_BAL_OF_PATTERN = re.compile(
    r"\.balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)|"
    r"address\s*\(\s*this\s*\)\.balance\b",
    re.IGNORECASE,
)

# Pattern: the result is used in shares/price calculation
_SHARE_CALC_PATTERN = re.compile(
    r"totalAssets|totalShares|getPrice|pricePerShare|exchangeRate|"
    r"shares\s*=|price\s*=|ratio\s*=|reserve\s*=",
    re.IGNORECASE,
)

# Mitigation patterns — internal accounting variable tracked separately
_MITIGATION_PATTERN = re.compile(
    r"totalAssets\(\)|_totalAssets\b|internalBalance\b|storedBalance\b|"
    r"reserveBalance\b|_balance\b",
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

        lines = content.splitlines()

        for m in _BAL_OF_PATTERN.finditer(content):
            line_no = content[:m.start()].count("\n") + 1
            context_start = max(0, line_no - 8)
            context_end = min(len(lines), line_no + 8)
            context = "\n".join(lines[context_start:context_end])

            # Check if this balance call is used in share/price calculations
            if not _SHARE_CALC_PATTERN.search(context):
                continue

            # Check if mitigation is present nearby
            if _MITIGATION_PATTERN.search(context):
                _logger.debug("[DonationAttack] Mitigation found near %s:%d", sol_file.name, line_no)
                continue

            affected_code = "\n".join(
                f"  {context_start + i + 1}: {l}"
                for i, l in enumerate(lines[context_start:context_end])
            )

            finding = {
                "id": str(uuid.uuid4()),
                "contest_id": "",
                "title": "Donation Attack — balanceOf(address(this)) Used for Accounting",
                "severity": "HIGH",
                "category": "token_accounting",
                "description": (
                    f"`{sol_file.name}` uses `balanceOf(address(this))` (or `address(this).balance`) "
                    "in share/price calculations. An attacker can send tokens directly to the contract "
                    "(a 'donation') to inflate this value, manipulating share prices, exchange rates, "
                    "or redemption amounts in their favor. Classic ERC4626 / AMM pool attack vector."
                ),
                "affected_code": f"{sol_file.name}:{line_no}\n{affected_code}",
                "impact": (
                    "Share price manipulation, incorrect share issuance, price oracle manipulation. "
                    "First depositor can inflate price to steal subsequent deposits."
                ),
                "recommendation": (
                    "Track token balances in a dedicated state variable (e.g. uint256 _totalAssets) "
                    "that is updated only through deposit/withdraw functions. "
                    "Never use raw balanceOf() for protocol accounting."
                ),
                "tool_source": "custom_detector:donation_attack",
                "confidence": 0.8,
                "llm_verified": 0,
                "estimated_reward": 15000.0,
            }
            findings.append(finding)
            _logger.debug("[DonationAttack] Found in %s:%d", sol_file.name, line_no)

    _logger.info("[DonationAttack] %d finding(s) in %s", len(findings), repo_path.name)
    return findings


try:
    from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification

    class DonationAttackDetector(AbstractDetector):
        ARGUMENT = "donation-attack"
        HELP = "Protocol uses balanceOf(address(this)) for accounting — donation attack vector"
        IMPACT = DetectorClassification.HIGH
        CONFIDENCE = DetectorClassification.MEDIUM
        WIKI = "https://blog.openzeppelin.com/protecting-against-erc4626-inflation-attacks"
        WIKI_TITLE = "Donation Attack via Direct Token Transfer"
        WIKI_DESCRIPTION = DETECTOR_INFO["description"]
        WIKI_EXPLOIT_SCENARIO = (
            "Attacker calls token.transfer(vaultAddress, 1e18) directly, inflating totalAssets. "
            "Next depositor receives fewer shares than expected."
        )
        WIKI_RECOMMENDATION = "Use internal accounting variables, not balanceOf()."

        def _detect(self):
            results = []
            for contract in self.contracts:
                for func in contract.functions:
                    for node in func.nodes:
                        expr_str = str(node.expression)
                        if "balanceOf" in expr_str and "address(this)" in expr_str:
                            r = self.generate_result([
                                "balanceOf(address(this)) used in accounting — donation attack possible",
                                node,
                            ])
                            results.append(r)
            return results

except ImportError:
    pass
