# 🛡️ OpenClaw Audit

**Free, fast heuristic security scanner for Solidity** — point it at a repo, get a professional report in seconds.

Part of [OpenClaw](https://juan23z.github.io), an autonomous multi-agent system that runs a Web3 security
workflow 24/7. This is the open-source scanning core.

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

Get a security scan on **every push and PR** — the report lands in the job summary + an artifact. Two lines:

```yaml
# .github/workflows/security.yml
name: security
on: [push, pull_request]
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: juan23z/openclaw-audit@v1
        with:
          path: contracts        # optional, default '.'
          # fail-on-candidates: true   # optional, default false (heuristics are advisory)
```

That's it — no API keys, no cost. Want verified findings + **continuous monitoring** (re-audited on every
change)? → **https://juan23z.github.io**

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

## ⚠️ Honest by design

These are **heuristic candidates**, not confirmed vulnerabilities. Static heuristics produce false positives —
**verify each finding by hand before acting**. The report labels every item as *"candidate · verify"*.

Want a **full manual review** with verified findings and a signed report? → **https://juan23z.github.io**

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
