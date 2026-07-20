"""
Chainlink Oracle Staleness Detector.

Detects Chainlink oracle usage without proper staleness / validity checks:
  1. latestRoundData() called but updatedAt not compared to a deadline
  2. No check for answeredInRound >= roundId (stale data from previous round)
  3. No check for answer > 0 (negative/zero price)
"""

import logging
import re
import uuid
from pathlib import Path

_logger = logging.getLogger(__name__)

DETECTOR_INFO = {
    "name": "oracle-staleness",
    "severity": "HIGH",
    "description": (
        "Chainlink oracle latestRoundData() is used without checking: "
        "(1) updatedAt against a staleness deadline, "
        "(2) answeredInRound >= roundId for fresh data, "
        "(3) answer > 0 for valid price. "
        "Stale, invalid, or zero prices can be used to exploit lending protocols, AMMs, and oracles."
    ),
    "category": "oracle",
}

_LATEST_ROUND_PATTERN = re.compile(r"\.latestRoundData\(\)|latestRoundData\(\)", re.IGNORECASE)

# Proper staleness check patterns (en la VENTANA de contexto ±30 líneas del call)
_STALENESS_CHECK = re.compile(
    r"updatedAt\s*[+\-<>]|block\.timestamp\s*-\s*updatedAt|"
    r"updatedAt\s*==\s*0|MAX_DELAY|STALENESS|staleThreshold|maxAge|heartbeat",
    re.IGNORECASE,
)

# Guard de staleness a NIVEL DE FICHERO — evidencia de que el feed SÍ valida frescura aunque el check esté FUERA
# de la ventana ±30 (helper aparte). 18-jul (FP bounty_247: feeds de Inverse/Dola que validan vía `isPriceStale()`
# + `updatedAt + heartbeat < block.timestamp` en otra función). Exige un CHECK REAL (helper con nombre-de-guard o
# una comparación temporal), NO solo mencionar "heartbeat" (una var declarada y nunca usada no protege).
_STALENESS_FILE_GUARD = re.compile(
    r"\bis(?:Price)?Stale\b|\bcheckStale\b|\bvalidateStale\b|\brequireFresh\b|\brequireNotStale\b|"
    r"\b_?stalePrice\b|\bstalenessCheck\b|"
    r"updatedAt\s*\+|block\.timestamp\s*-\s*\w*[Uu]pdated|block\.timestamp\s*-\s*\w*[Tt]imestamp|"
    r"updatedAt\s*[<>]=?\s*block\.timestamp|block\.timestamp\s*[<>]=?\s*\w*updatedAt",
    re.IGNORECASE,
)

# Round validity check
_ROUND_CHECK = re.compile(
    r"answeredInRound\s*[<>=!]|roundId\s*[<>=!]\s*answeredInRound|"
    r"answeredInRound\s*>=\s*roundId",
    re.IGNORECASE,
)

# Price validity check
_PRICE_CHECK = re.compile(
    r"answer\s*[<>=!]\s*0|price\s*[<>=!]\s*0|answer\s*<=\s*0|"
    r"require\([^)]*answer|assert\([^)]*answer",
    re.IGNORECASE,
)

_CONTEXT_WINDOW = 30  # lines to examine around the oracle call


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

        if not _LATEST_ROUND_PATTERN.search(content):
            continue

        # Guard a nivel de FICHERO: si el contrato valida staleness en un helper aparte (fuera de la ventana ±30
        # del call), NO marcar — el feed SÍ chequea frescura. Evita el FP de feeds con `isPriceStale()`/heartbeat.
        if _STALENESS_FILE_GUARD.search(content):
            continue

        lines = content.splitlines()
        file_key = str(sol_file)

        for m in _LATEST_ROUND_PATTERN.finditer(content):
            line_no = content[:m.start()].count("\n") + 1
            # DECLARACIÓN del método (`function latestRoundData(…)` en interfaz/override sig), NO una llamada real
            # a un oráculo → marcarla es FP (bounty_247: IChainlinkFeed). Una llamada real es `.latestRoundData()`.
            line_text = lines[line_no - 1] if 0 <= line_no - 1 < len(lines) else ""
            if re.search(r"\bfunction\s+latestRoundData\b", line_text):
                continue
            ctx_start = max(0, line_no - 5)
            ctx_end = min(len(lines), line_no + _CONTEXT_WINDOW)
            context = "\n".join(lines[ctx_start:ctx_end])

            # Disparo SOLO por el check de staleness (crítico y detectable de forma robusta). Los otros
            # dependen de nombres exactos de variable (answer/answeredInRound/roundId) → FP al renombrar;
            # answeredInRound además está DEPRECADO por Chainlink. Con staleness check, no marcamos.
            if _STALENESS_CHECK.search(context):
                continue

            missing: list[str] = ["updatedAt staleness check"]
            if not _PRICE_CHECK.search(context):
                missing.append("answer > 0 validity check")
            if not _ROUND_CHECK.search(context):
                missing.append("answeredInRound >= roundId check (secondary; deprecated by Chainlink)")

            # Deduplicate per file (one finding per file to avoid noise)
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
                "title": f"Chainlink Oracle Missing Staleness Checks in {sol_file.name}",
                "severity": "HIGH",
                "category": "oracle",
                "description": (
                    f"`{sol_file.name}` calls `latestRoundData()` but is missing: "
                    + ", ".join(missing) + ". "
                    "Without these checks, the protocol can use stale, invalid, or zero prices. "
                    "On L2s with sequencer downtime, prices can be hours or days stale."
                ),
                "affected_code": f"{sol_file.name}:{line_no}\n{affected_code}",
                "impact": (
                    "Price oracle manipulation: stale prices enable under-collateralized borrowing, "
                    "incorrect liquidations, or arbitrage theft."
                ),
                "recommendation": (
                    "Add all three checks after latestRoundData():\n"
                    "  require(answer > 0, 'Invalid price');\n"
                    "  require(updatedAt >= block.timestamp - MAX_STALENESS, 'Stale price');\n"
                    "  require(answeredInRound >= roundId, 'Incomplete round');"
                ),
                "tool_source": "custom_detector:oracle_staleness",
                "confidence": 0.85,
                "llm_verified": 0,
                "estimated_reward": 15000.0,
                "missing_checks": missing,
            }
            findings.append(finding)
            _logger.debug(
                "[OracleStaleness] Missing [%s] in %s:%d",
                ", ".join(missing), sol_file.name, line_no,
            )

    _logger.info("[OracleStaleness] %d finding(s) in %s", len(findings), repo_path.name)
    return findings


try:
    from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification

    class OracleStalenessDetector(AbstractDetector):
        ARGUMENT = "oracle-staleness"
        HELP = "Chainlink oracle used without staleness / validity checks"
        IMPACT = DetectorClassification.HIGH
        CONFIDENCE = DetectorClassification.MEDIUM
        WIKI = "https://docs.chain.link/data-feeds/historical-data"
        WIKI_TITLE = "Chainlink Oracle Staleness"
        WIKI_DESCRIPTION = DETECTOR_INFO["description"]
        WIKI_EXPLOIT_SCENARIO = (
            "Chainlink oracle reports a price from 2 hours ago (sequencer was down). "
            "Attacker borrows against inflated collateral value."
        )
        WIKI_RECOMMENDATION = "Always validate updatedAt, answeredInRound >= roundId, and answer > 0."

        def _detect(self):
            results = []
            for contract in self.contracts:
                for func in contract.functions:
                    for node in func.nodes:
                        if "latestRoundData" in str(node.expression):
                            r = self.generate_result([
                                "latestRoundData() called — verify staleness and validity checks exist",
                                node,
                            ])
                            results.append(r)
            return results

except ImportError:
    pass
