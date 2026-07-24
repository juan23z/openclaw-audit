# 🛡️ OpenClaw Audit

[![GitHub Marketplace](https://img.shields.io/badge/GitHub-Marketplace-6f42c1?logo=github)](https://github.com/marketplace/actions/openclaw-audit) [![0 false positives on OpenZeppelin](https://img.shields.io/badge/false%20positives%20on%20OpenZeppelin-0-brightgreen)](#-calibrated-not-noisy) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE) ![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue)

**Free, fast heuristic security scanner for Solidity** — point it at a repo, get a professional report in seconds.
Runs clean on OpenZeppelin (0 findings, 247 files) so you get signal, not noise. Add it to CI in two lines.

Part of [OpenClaw](https://juan23z.github.io), an autonomous multi-agent system that runs a Web3 security
workflow 24/7. This is the open-source scanning core.

> 🛡️ **Shipping to mainnet? Want a human on it?** The scanner flags *candidates* — a **Pre-Mainnet Express**
> review adds **hand-verified** findings (zero false-positive spam) + a plain-English report in **48h**, from
> **$149** (pay in USDC, no forms). → **[Pricing &amp; services →](https://juan23z.github.io/pricing.html)**

```bash
python scan.py https://github.com/org/protocol --name "Protocol" --out ./report
# → ./report/report.md  +  ./report/report.html
```

No dependencies beyond **Python 3.9+** and **git**. It clones (shallow), runs the detectors, writes the report,
and cleans up after itself.

**One command, no clone** (via [pipx](https://pipx.pypa.io)):
```bash
pipx run --spec git+https://github.com/juan23z/openclaw-audit openclaw-audit <repo-or-path> --out ./report
```
Or install it: `pipx install git+https://github.com/juan23z/openclaw-audit` → then just `openclaw-audit <repo>`.

## ⚡ Use it in CI (GitHub Action)

Get a security scan on **every push and PR** — a summary lands as a **comment on your PR**, the full report in
the job summary + an artifact. Two lines:

```yaml
# .github/workflows/security.yml
name: security
on: [push, pull_request]
permissions:
  contents: read
  pull-requests: write        # lets the scan post its summary as a PR comment
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: juan23z/openclaw-audit@v1
        with:
          path: contracts        # optional, default '.'
          # fail-on-candidates: true   # optional, default false (heuristics are advisory)
          # comment-on-pr: false       # optional, default true
```

That's it — no API keys, no cost. Want **verified findings + continuous monitoring** (re-audited on every
change)? Get a human audit → **[order on Fiverr](https://www.fiverr.com/s/P2kNDP0)** · [sample report & service](https://juan23z.github.io)

## 🏷️ Show it off — add the badge

Scanning your contracts with OpenClaw Audit? Add the badge to your README:

[![Secured with OpenClaw Audit](https://img.shields.io/badge/secured%20with-OpenClaw%20Audit-6f42c1?logo=ethereum&logoColor=white)](https://github.com/juan23z/openclaw-audit)

```markdown
[![Secured with OpenClaw Audit](https://img.shields.io/badge/secured%20with-OpenClaw%20Audit-6f42c1?logo=ethereum&logoColor=white)](https://github.com/juan23z/openclaw-audit)
```

## What it checks (12 detectors)

| # | Detector | Looks for |
|---|----------|-----------|
| 1 | First-depositor inflation | ERC-4626 empty-vault share inflation |
| 2 | ERC-4626 rounding | Rounding that favors the withdrawer |
| 3 | Donation attack | `balanceOf(address(this))` used for accounting |
| 4 | Oracle staleness | Price reads without freshness checks |
| 5 | Cross-function reentrancy | External call before state update |
| 6 | Access control | Unprotected privileged / init / sweep functions |
| 7 | Fee-on-transfer | Unhandled fee/rebasing token assumptions |
| 8 | Precision loss | Division before multiplication |
| 9 | ERC compliance | ERC-20 / 4626 conformance gaps |
| 10 | NatSpec | Missing docs on critical functions |
| 11 | **Unchecked low-level call** | `call`/`send`/`delegatecall` return value ignored |
| 12 | **tx.origin auth** | `tx.origin` used for authorization (phishing vector) |

Detectors skip dependencies and tests (`node_modules`, `lib`, `out`, `test`, `mock`, …) so you only get
findings in **your** code.

## ✅ Calibrated, not noisy

Runs clean on clean code: **0 findings across the entire OpenZeppelin contracts library** (the most-audited
codebase in web3). Detectors skip comments, tests and dependencies — so you get signal, not a wall of false
positives.

Don't take our word for it — see the **[full Calibration Report](CALIBRATION.md)**: OpenClaw run across 10 of the
most-audited codebases in the ecosystem (OpenZeppelin, Solady, Uniswap v2/v3/v4, Morpho Blue, Permit2, PRBMath…),
with every flag verified by hand. **14 candidates across 608 source files; 4 codebases perfectly clean.** Every
number is reproducible in one command.

## ⚠️ Honest by design

These are **heuristic candidates**, not confirmed vulnerabilities. Static heuristics produce false positives —
**verify each finding by hand before acting**. The report labels every item as *"candidate · verify"*.

Want a **human review** with verified findings and a plain-English report? Start with a **Pre-Mainnet Express
($149, pay in USDC)** or a full core review → **[pricing &amp; services](https://juan23z.github.io/pricing.html)**

## 🔗 On-chain attestation (optional)

`contracts/AuditAttestation.sol` lets an auditor publish a `keccak256` hash of a delivered report + a verdict
on-chain, so anyone can verify a report's authenticity and date (tamper-evidence + provenance). Two-step
ownership, access-controlled attesters, no external calls. Compiles with Solc 0.8.24 and ships with a Foundry
test suite (**8 passing tests**):

```bash
cd contracts && forge install foundry-rs/forge-std && forge test
```

Deploy on any EVM testnet.

## License

MIT — see [LICENSE](LICENSE). Built by [Nawel](https://juan23z.github.io).
