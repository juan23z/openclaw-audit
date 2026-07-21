# 📊 Calibration Report

The hard problem with a security scanner isn't *finding* things — it's **not drowning the real issues in noise**.
A tool that flags forty non-issues trains developers to ignore it. So the bar we hold OpenClaw Audit to is
**silence on sound code**.

This report shows how the scanner behaves across some of the **most-reviewed Solidity codebases in the ecosystem** —
libraries that thousands of protocols depend on and that have been audited many times over. Every result below is
**reproducible in one command**, and every flag has been checked by hand.

## Results

Run on each library's source (tests, mocks, and dependencies excluded), latest `main` at the time of writing:

| Codebase | Source files | Candidates | Notes |
|---|---:|---:|---|
| **OpenZeppelin Contracts** | 247 | **0** | Completely clean. |
| **forge-std** | 31 | **0** | Completely clean. |
| **Uniswap Permit2** | 16 | **0** | Completely clean. |
| **PRBMath** | 40 | **0** | Completely clean. |
| **Uniswap v2-core** | 11 | 1 | One defensible CEI-ordering candidate on `createPair` — worth a human's eyes, not a false alarm. |
| **Uniswap v3-core** | 40 | 1 | `initialize()` flagged — **false positive**: pool initialization is permissionless *by design* (one-time price set). |
| **Uniswap v4-core** | 46 | 1 | Same as v3 — permissionless `initialize()`, **false positive**. |
| **Solmate** | 20 | 2 | One **real, known** flag (first-depositor inflation: Solmate's minimal ERC-4626 intentionally omits virtual-share protection — OZ adds it); one rounding flag that is a **false positive** (it rounds down per spec). |
| **Morpho Blue** | 17 | 2 | Two reentrancy candidates — **false positives**: Morpho Blue is formally verified (Certora); the external calls are `safeTransfer`s with correct effects-before-interactions accounting. |
| **Solady** | 140 | 7 | All **false positives**: documented `tx.origin` rescue default in `Lifebuoy` (with warnings), UUPS/ERC1967 upgrade auth the heuristic doesn't parse, and one intentional math ordering. |
| **Total** | **608** | **14** | ~2.3% of files flag *anything*; 4 of 10 codebases are perfectly clean. |

## What this shows

- **It stays silent on sound code.** Zero findings across OpenZeppelin, forge-std, Permit2 and PRBMath — no noise.
- **When it does flag, the flags are explainable, not random.** They cluster on genuinely interesting spots: a
  permissionless initializer, a documented rescue mechanism, a library that deliberately leaves inflation
  protection to the integrator. A human clears each in seconds — which is exactly the point.
- **It catches real, known design gaps.** The Solmate first-depositor-inflation flag is a *true* observation: that
  ERC-4626 implementation omits the virtual-share defense that OpenZeppelin's adds. The scanner surfaces the
  difference.

The goal isn't a tool that says "0 bugs" (nothing can). It's a tool that gives you **signal, not a wall of red** —
so the two findings that matter aren't buried under thirty-eight that don't.

## Reproduce it yourself

Every number above is one command away:

```bash
git clone --depth 1 https://github.com/OpenZeppelin/openzeppelin-contracts /tmp/oz
pipx run --spec git+https://github.com/juan23z/openclaw-audit openclaw-audit /tmp/oz
# → 0 candidate observations across 247 client .sol contracts
```

Swap the repo URL for any of the codebases above (or your own) and check the numbers. That's the whole idea:
**a claim you can verify, not one you have to trust.**

---

*OpenClaw Audit is a free, MIT-licensed heuristic scanner. Findings are candidates — verify before acting. Want a
human-verified review + continuous monitoring for your protocol? → [juan23z.github.io](https://juan23z.github.io)*
