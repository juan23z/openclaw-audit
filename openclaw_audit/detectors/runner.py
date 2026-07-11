"""Runs all custom detectors on a repo."""

import logging
from pathlib import Path

_logger = logging.getLogger(__name__)

_DETECTORS = [
    # ── Detectores originales ──────────────────────────────────────────────
    ("erc4626_rounding",         "openclaw_audit.detectors.erc4626_rounding"),
    ("donation_attack",          "openclaw_audit.detectors.donation_attack"),
    ("oracle_staleness",         "openclaw_audit.detectors.oracle_staleness"),
    ("fee_on_transfer",          "openclaw_audit.detectors.fee_on_transfer"),
    ("first_depositor_inflation","openclaw_audit.detectors.first_depositor_inflation"),
    # ── Detectores v4.6 — nuevos vectores de alto valor ───────────────────
    # Compara documentación (README/NatSpec) con el comportamiento real del código.
    # Los bugs de "spec violation" son los más noveles y mejor pagados.
    ("natspec_verifier",         "openclaw_audit.detectors.natspec_verifier"),
    # Construye la matriz completa función→rol: detecta funciones de alto impacto
    # (setOracle, sweep, upgrade, initialize) sin access control.
    ("access_control_matrix",    "openclaw_audit.detectors.access_control_matrix"),
    # Read-only reentrancy y cross-function reentrancy — el vector Balancer/Curve.
    # La reentrada clásica (misma función) ya está protegida; esta NO lo está.
    ("cross_func_reentrancy",    "openclaw_audit.detectors.cross_func_reentrancy"),
    # Division before multiplication y fee calculations con orden incorrecto.
    # Pérdida de precisión acumulable en protocolos de lending/vault/AMM.
    ("precision_loss",           "openclaw_audit.detectors.precision_loss"),
    # ── Detectores v4.7 ────────────────────────────────────────────────────
    # ERC20/ERC721/ERC1155/ERC4626: verifica que las funciones obligatorias están
    # implementadas con las firmas y semánticas correctas (return bool, no devolver
    # address(0), rounding correcto en ERC4626, etc.).
    ("erc_compliance",           "openclaw_audit.detectors.erc_compliance"),
    # ── Detectores v4.8 (11-jul) — más cobertura de clases de bug de alto valor ──
    # Low-level call/send/delegatecall con return ignorado (no revierte en fallo → fallo silencioso).
    ("unchecked_call",           "openclaw_audit.detectors.unchecked_call"),
    # tx.origin usado para autorización (vector de phishing clásico; debe ser msg.sender).
    ("tx_origin_auth",           "openclaw_audit.detectors.tx_origin_auth"),
]


def run_all_custom_detectors(contest_id: str, repo_path: Path) -> list[dict]:
    """
    Run all 5 custom detectors sequentially on repo_path.
    Returns combined findings list with contest_id injected.
    """
    all_findings: list[dict] = []

    for detector_name, module_path in _DETECTORS:
        try:
            import importlib
            mod = importlib.import_module(module_path)
            findings = mod.scan(repo_path)

            # Inject contest_id
            for f in findings:
                f["contest_id"] = contest_id

            all_findings.extend(findings)
            _logger.info("[CustomDetectors] %s: %d finding(s)", detector_name, len(findings))
        except Exception as exc:
            _logger.warning("[CustomDetectors] %s failed: %s", detector_name, exc)

    _logger.info(
        "[CustomDetectors] Total: %d finding(s) from %d detectors in %s",
        len(all_findings),
        len(_DETECTORS),
        repo_path.name,
    )
    return all_findings
