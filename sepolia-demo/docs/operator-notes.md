# Sepolia Demo Operator Notes

## Deployment Order

1. Deploy `DemoShieldedPool`.
2. Deploy `RecipientRegistry`.
3. Deploy `HonkVerifier` with optimizer settings that keep runtime bytecode
   below EIP-170.
4. Deploy `DemoRealAuthVerifier` configured for the deployed pool address and
   `HonkVerifier`.
5. Write addresses and the deployment block to `app/src/demoConfig.ts`.

`scripts/deploy-sepolia.s.sol` handles the first two contracts.
`scripts/deploy-auth-sepolia.s.sol` deploys the Honk verifier and demo auth
wrapper.

The current Noir auth artifact uses the fixed EIP-712 domain verifying contract
`0x0000000000000000000000000000000000081820`. The deployed wrapper still
restricts verifier calls to the configured Sepolia pool. Regenerate the Noir
artifact with the deployed pool address before using this outside the demo.

Do not deploy from this workspace to mainnet.

## Recipient Discovery

The registry is a demo convenience. It publishes:

- `ownerNullifierKeyHash`
- ML-KEM-768 public key
- X25519 public key
- metadata version

The public registry does not claim recipient privacy. It exists so the demo can
show actual encrypted note delivery without copy-paste invite strings.

## Output Note Data

The demo envelope is app-level data. The pool only checks:

```text
uint256(keccak256(outputNoteData)) mod p == outputNoteDataHash
```

Wallets must verify decrypted note payloads against the emitted note commitment
and leaf index before adding notes to local spendable state.

## Browser Proving

Run the browser demo:

```bash
npm run dev --prefix sepolia-demo
```

The app consumes a wallet-signed transfer intent, rebuilds note-tree and
auth-policy sibling paths from Sepolia logs, runs the snarkjs pool prover, runs
the Noir/bb ECDSA auth prover in the browser, checks public-input agreement,
and submits calldata-ready proof bytes. The demo does not require a separate
prover service.

Serve with COOP/COEP headers when testing browser proving performance so worker
and wasm features behave like the hosted demo.
