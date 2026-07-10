# Deploying AuditAttestation

A minimal, tested attestation contract. Deploy on any EVM testnet (free) — e.g. **Base Sepolia** or **OP Sepolia**.

## 1. Get testnet ETH (free)
- Base Sepolia faucet: https://www.alchemy.com/faucets/base-sepolia
- OP Sepolia faucet:   https://www.alchemy.com/faucets/optimism-sepolia

## 2. Set env
```bash
export PRIVATE_KEY=0xyour_test_wallet_key      # a THROWAWAY test wallet, never a real one
export RPC_URL=https://sepolia.base.org        # or your OP Sepolia RPC
```

## 3. Install deps + test
```bash
cd contracts
forge install foundry-rs/forge-std
forge test            # 8 passing tests
```

## 4. Deploy
```bash
forge script script/Deploy.s.sol --rpc-url $RPC_URL --broadcast --private-key $PRIVATE_KEY
```
The address is printed as `AuditAttestation deployed at: 0x...`.

## 5. Publish an attestation
Compute a report hash with `python -m openclaw.core.attestation <report.md>` (keccak256), then call
`attest(subject, reportHash, verdict, uri)` from the owner/attester wallet (via cast or a UI). Anyone can then
`verify(reportHash)` to confirm the report is authentic and see its verdict + timestamp.

> Security: use a throwaway test wallet for testnet. Never put a real private key in env/CI.
