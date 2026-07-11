"""
First Depositor Inflation Attack Detector.

ERC4626 vaults where totalSupply() == 0 and the first depositor receives shares
without virtual shares protection are vulnerable to the "inflation attack":

1. Attacker deposits 1 wei → receives 1 share
2. Attacker donates a large amount directly to the vault
3. totalAssets grows, share price = totalAssets/totalSupply = huge
4. Victim deposits — gets 0 shares (rounds down to 0)
5. Attacker redeems 1 share → gets victim's deposit + original donation

Mitigations: virtual shares (OpenZeppelin v5), dead shares burned to address(0),
or minimum deposit requirements.
"""

import logging
import re
import uuid
from pathlib import Path

_logger = logging.getLogger(__name__)

DETECTOR_INFO = {
    "name": "first-depositor-inflation",
    "severity": "HIGH",
    "description": (
        "ERC4626 vault is vulnerable to first-depositor inflation attack. "
        "When totalSupply == 0, an attacker can deposit 1 wei, inflate the share price "
        "via donation, then steal subsequent deposits. "
        "Missing mitigation: virtual shares, dead shares, or minimum deposit."
    ),
    "category": "erc4626",
}

_ERC4626_PATTERN = re.compile(r"ERC4626|IERC4626|_deposit|_mint.*shares", re.IGNORECASE)

# Mitigation patterns
_VIRTUAL_SHARES_PATTERN = re.compile(
    r"VIRTUAL_SHARES|_VIRTUAL_SHARES|virtualShares|deadShares|"
    r"_mint.*address\(0\)|burn.*address\(0\)|MINIMUM_SHARES|MIN_SHARES|"
    r"decimalsOffset|10\s*\*\*\s*\d+\s*\+\s*totalSupply",
    re.IGNORECASE,
)

# Pattern: deposit/mint function that mints to user (potential inflation point)
_DEPOSIT_MINT_PATTERN = re.compile(
    r"function\s+(?:deposit|mint)\s*\(",
    re.IGNORECASE,
)

# Pattern: totalSupply == 0 check without protection
_TOTAL_SUPPLY_ZERO_PATTERN = re.compile(
    r"totalSupply\(\)\s*==\s*0|totalSupply\s*==\s*0|_totalSupply\s*==\s*0",
    re.IGNORECASE,
)


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

        # Only check ERC4626 vaults
        if not _ERC4626_PATTERN.search(content):
            continue

        # If mitigation is present at the contract level, skip
        if _VIRTUAL_SHARES_PATTERN.search(content):
            _logger.debug("[FirstDepositor] Mitigation found in %s — skipping", sol_file.name)
            continue

        lines = content.splitlines()
        file_key = str(sol_file)

        # Find deposit/mint functions
        for m in _DEPOSIT_MINT_PATTERN.finditer(content):
            func_name = m.group(0).split("(")[0].split()[-1]
            start_pos = m.start()
            line_no = content[:start_pos].count("\n") + 1

            # Extract function body (simplified: next 40 lines)
            ctx_start = max(0, line_no - 1)
            ctx_end = min(len(lines), line_no + 40)
            body = "\n".join(lines[ctx_start:ctx_end])

            # Check if function contains _mint without virtual shares protection
            has_mint = bool(re.search(r"\b_mint\s*\(", body))
            if not has_mint:
                continue

            # Check for virtual shares mitigation in function body
            if _VIRTUAL_SHARES_PATTERN.search(body):
                continue

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
                "title": f"First Depositor Inflation Attack in {sol_file.name} — {func_name}()",
                "severity": "HIGH",
                "category": "erc4626",
                "description": (
                    f"`{sol_file.name}` implements an ERC4626 vault without virtual shares protection. "
                    "When `totalSupply == 0`, an attacker can:\n"
                    "  1. Deposit 1 wei → receive 1 share (at 1:1 ratio)\n"
                    "  2. Donate a large amount directly to the vault (balanceOf manipulation)\n"
                    "  3. Victim deposits → receives 0 shares (integer division rounds down)\n"
                    "  4. Attacker redeems 1 share → gets victim's tokens + donation\n\n"
                    "No virtual shares, dead shares, or minimum deposit protection detected."
                ),
                "affected_code": f"{sol_file.name}:{line_no}\n{affected_code}",
                "impact": (
                    "First depositor (attacker) can steal 100% of subsequent deposits. "
                    "Common in new vault deployments."
                ),
                "recommendation": (
                    "Use OpenZeppelin ERC4626 v5 with decimalsOffset (virtual shares), OR:\n"
                    "  1. Burn a small amount of shares to address(0) on first deposit\n"
                    "  2. Add a minimum deposit requirement\n"
                    "  3. Deploy with a seed deposit from a trusted address\n"
                    "See: https://docs.openzeppelin.com/contracts/5.x/erc4626#inflation-attack"
                ),
                "tool_source": "custom_detector:first_depositor_inflation",
                "confidence": 0.8,
                "llm_verified": 0,
                "estimated_reward": 15000.0,
            }
            findings.append(finding)
            _logger.debug("[FirstDepositor] Found in %s:%d", sol_file.name, line_no)

    _logger.info("[FirstDepositor] %d finding(s) in %s", len(findings), repo_path.name)
    return findings


try:
    from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification

    class FirstDepositorInflationDetector(AbstractDetector):
        ARGUMENT = "first-depositor-inflation"
        HELP = "ERC4626 vault missing virtual shares — first depositor inflation attack"
        IMPACT = DetectorClassification.HIGH
        CONFIDENCE = DetectorClassification.MEDIUM
        WIKI = "https://docs.openzeppelin.com/contracts/5.x/erc4626#inflation-attack"
        WIKI_TITLE = "ERC4626 First Depositor Inflation"
        WIKI_DESCRIPTION = DETECTOR_INFO["description"]
        WIKI_EXPLOIT_SCENARIO = (
            "Attacker deposits 1 wei, donates 1e18 tokens, victim deposits 1e18 tokens, "
            "attacker redeems 1 share and gets 2e18 tokens."
        )
        WIKI_RECOMMENDATION = "Use virtual shares (decimalsOffset) from OZ ERC4626 v5."

        def _detect(self):
            results = []
            for contract in self.contracts:
                is_vault = any("ERC4626" in str(inh) for inh in contract.inheritance)
                if not is_vault:
                    continue
                for func in contract.functions:
                    if func.name in ("deposit", "mint"):
                        for node in func.nodes:
                            if "_mint" in str(node.expression):
                                r = self.generate_result([
                                    f"{func.name}() uses _mint — verify virtual shares protection exists",
                                    node,
                                ])
                                results.append(r)
            return results

except ImportError:
    pass
