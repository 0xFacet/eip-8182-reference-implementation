# EIP-8182 Sepolia Demo

This directory is a Sepolia-only demo workspace. It is intentionally separate
from the reference implementation because the demo uses ordinary CREATE
deployment, browser wallet state, and app-level encrypted note delivery.

The reference pool treats `outputNoteData` as opaque bytes. The demo uses those
bytes for trial-decryptable private note delivery:

- private transfer, not only deposit or withdrawal
- wallet signature for local profile/auth-policy binding
- ML-KEM-768 + X25519 hybrid encryption for output notes
- browser-generated pool/auth proofs

## Layout

```text
sepolia-demo/
  src/*.sol         Demo-only Solidity contracts.
  src/*.ts          Browser-oriented TypeScript SDK helpers.
  test/             Foundry tests for demo contracts.
  app/              Vite React demo app.
  scripts/          Deployment and artifact scripts.
  docs/             Demo operator notes.
```

## Demo Boundaries

- Do not move demo initialization into `contracts/src/ShieldedPool.sol`.
- Do not treat `RecipientRegistry` as part of EIP-8182. It is app-layer note
  delivery for the browser demo. A production wallet could use a companion ERC
  registry, an address book, offline key exchange, or direct encrypted payload
  delivery.
- Do not use the Sepolia addresses as normative constants.
- The browser prover is demo infrastructure, not a reference-protocol
  requirement.
- The demo does not provide transaction-submitter privacy. If the user sends
  the transaction directly, the L1 transaction reveals that address interacted
  with the pool. Hiding the submitter requires relayers, account abstraction, or
  similar transaction infrastructure outside this EIP.
- Auth methods are rotatable and revocable through `setAuthPolicy`, but the
  demo UI only exposes the simple registration path. Revocation takes full
  effect after the auth-policy root-history window expires.
- Gas numbers from this demo reflect an unoptimized Sepolia implementation and
  the browser-friendly ECDSA Noir/UltraHonk auth method. They are useful for
  inspection, but not a lower bound for all EIP-8182 deployments.

## First Demo Flow

1. User A connects a Sepolia wallet, creates a local demo profile, registers an
   auth policy, and publishes recipient encryption keys.
2. User B does the same.
3. User A deposits Sepolia ETH into the demo pool.
4. User A privately transfers to User B. Slot 0 is B's note, slot 1 is A's
   change, and slot 2 is dummy.
5. User B scans pool events, trial-decrypts `outputNoteData`, verifies the note
   commitment against the event, and can spend the received note.

## Current Implementation Status

Implemented:

- deployable demo pool with constructor-seeded genesis state
- demo recipient registry for owner hash, ML-KEM-768 public key, and X25519
  public key discovery
- demo auth wrapper that only accepts calls from the configured pool
- TypeScript SDK for Poseidon commitments, hybrid note encryption,
  output-note-data hashing, trial decryption, event-indexer note acceptance
  checks, and private-transfer output preparation
- Vite/React app for wallet connect, local profile signing/storage, recipient
  key publishing, auth-policy registration, shielding Sepolia ETH, pool event
  scanning, note trial decryption, transfer preparation, local proving, and
  `transact` submission
- browser prover that rebuilds Sepolia note/auth trees from logs, runs the
  Groth16 pool prover and Noir/bb ECDSA auth prover, and submits calldata-ready
  proof bytes
- chunked Sepolia event-log fetching for deposits, transfers, and auth-policy
  updates, so the browser indexer does not depend on a single unbounded
  `eth_getLogs` range

The current auth circuit still uses the fixed EIP-712 domain verifying contract
`0x0000000000000000000000000000000000081820`. The demo wrapper restricts the
deployed auth verifier to the Sepolia pool address. Regenerate the Noir auth
artifact for a deployed pool before treating this as a production-shaped wallet
domain.

## Local Commands

```bash
forge test --root sepolia-demo
npm install --prefix sepolia-demo
npm test --prefix sepolia-demo
npm run dev --prefix sepolia-demo
```

The app expects deployment addresses in `sepolia-demo/app/src/demoConfig.ts`.
