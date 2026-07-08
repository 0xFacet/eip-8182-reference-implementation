# App-Layer Private Transfers — Reference Implementation

A complete, spec-exact reference implementation of the ERC defined in
[`../erc-app-layer-private-transfers.md`](../erc-app-layer-private-transfers.md):
private ETH and ERC-20 transfers via deployed shielded pools that share a
chain-wide canonical privacy identity registry, a canonical stateless pool
verifier, pluggable authorization, post-quantum encrypted note delivery, and an
optional policy-verifier hook.

Unlike EIP-8182 (a protocol-enshrined pool), every part of this ERC is
implementable as ordinary deployed contracts — this repository implements all of
it, end to end, with real proofs.

## What's here

| Path | Contents |
|---|---|
| `circuits/` | Circom pool circuit (24 public inputs, Groth16 BN254) + non-normative demo auth circuit |
| `circuits-noir/` | Noir + UltraHonk ECDSA-over-EIP-712 auth circuit (Appendix A profile) |
| `contracts/` | Foundry project: `PrivacyIdentityRegistry`, `CanonicalPoolVerifier`, `ShieldedPool`, auth/policy verifiers, `PublicActionRouter`, interfaces, Poseidon2 libraries |
| `sdk/` | TypeScript: derivations, Merkle trees, strict-ABI ML-KEM envelope + note payload, witness/session builders, indexer, viem clients |
| `app/` | Browser-proving demo wallet (Vite + React + wagmi/RainbowKit) |
| `scripts/` | Single-source constants codegen, circuit builds, vector + fixture generators, deterministic deployment, e2e + negative harnesses |
| `assets/` | Poseidon2 parameters + vectors, pool VK, derivation vectors, envelope vectors, deployment plan |
| `docs/` | Conformance checklist, plan deviations |

## The one-source-of-truth invariant

Every hash formula in the spec is implemented on four surfaces — Circom, Noir,
Solidity, TypeScript — and they must agree bit-for-bit. Two mechanisms enforce
this:

1. **`scripts/gen_constants.js`** reads `scripts/constants.json` and generates the
   domain tags, tree depths, and constants for all four surfaces from one place.
2. **`assets/derivation_vectors.json`** (from `scripts/gen_vectors.ts`) pins a
   fully-worked transfer and withdrawal — every commitment, nullifier, digest,
   policy hash, identity root — and is consumed as a test fixture by the Circom
   witness check, the Noir `#[test]`s, the forge `Vectors.t.sol`, and vitest.

Change a formula on one surface and the shared vectors fail everywhere.

## Toolchain

Circom 2.2.3 + snarkjs 0.7.6 (Groth16 BN254, `pot19` ptau) for the pool; Noir
1.0.0-beta.19 + Barretenberg 4.0 (UltraHonk) for auth; Foundry (solc 0.8.28);
Node ≥ 20 with TypeScript; ML-KEM-768 via `@noble/post-quantum`.

## Quickstart

```bash
cd erc
npm install

# 1. Generate constants + cross-surface vectors
npm run gen:constants
npm run gen:vectors
node scripts/gen_noir_vector_test.js

# 2. Build circuits (dev trusted setup — see caveat) + verifiers
npm run build:pool          # -> assets/pool_vk.bin, generated verifier core
npm run build:auth-demo
npm run build:auth-honk     # -> generated/HonkVerifier.sol

# 3. Contracts
cd contracts && forge build && FOUNDRY_OFFLINE=true forge test && cd ..

# 4. SDK
npm run test:sdk

# 5. Deterministic deployment plan + local deploy
node scripts/compute_deployment.js
npm run gen:constants       # stamps canonical addresses into generated/
cd contracts && forge build && cd ..
bash scripts/deploy_anvil.sh --keep    # deploys full stack, pins runtime codehashes

# 6. End-to-end (proves + submits real transactions on anvil)
npm run e2e
npm run test:negative
```

## Canonical singletons & deterministic deployment

The privacy identity registry and the pool verifier are deployed once per chain
at addresses fixed by CREATE2 (Arachnid factory `0x4e59…4956c`, fixed salts).
Their runtime code hashes are computed by `scripts/compute_deployment.js`, pinned
into `generated/CanonicalAddresses.sol`, and asserted on-chain by the deploy
script. Pools hardcode these addresses and `staticcall` the verifier; the
registry's identity root is part of every pool's validity relation. Both
singletons are immutable — no admin, no upgrade.

`ShieldedPool` deploys twice: policy-free `(policyVerifier=0, applies=0)` and
allowlist-gated `(SelfServeAllowlistPolicyVerifier, DEPOSIT|WITHDRAWAL)`. Both
share the one registry and one verifier.

## Sepolia deployment status (chain 11155111)

`assets/deployment.11155111.json` is the current Sepolia manifest for the demo
app/prover assets. It was redeployed on 2026-07-08 with a fresh demo registry,
the self-serve allowlist policy verifier, and `PublicActionRouter`; every
contract is verified on Etherscan.

| Sepolia contract | Address |
|---|---|
| Poseidon2 permute lib | `0x1f74ed00e1192946a03a731914fb515e9229b0ad` |
| Privacy identity registry | `0x019272baf7fa80d3e5ef8e18f90c8bca2fd2a428` |
| Canonical pool verifier | `0xf9b3233603f2bd2b276b28d35eda2259b3eaf1b5` |
| Honk verifier | `0xb9168a501cdd14c54b6f42516ce91ed9450c79be` |
| ECDSA/UltraHonk auth verifier | `0xbb823cbdd56ed936ca5c5d072399281c276b5346` |
| Demo auth verifier | `0xda44cb27299fa0b81ce322ada3c4c27d3712a3f3` |
| Allowlist policy verifier | `0x7bcad19dc94cab2a9e8d4da6f3c786f932956456` |
| Pool (policy-free) | `0xbbac4703cbb70e3e685ea89585f3de4b3bfb9b01` |
| Pool (allowlist-gated, DEPOSIT\|WITHDRAWAL) | `0x136cfa62a6230824ce1cec2e4257f69da208cb08` |
| PublicActionRouter | `0x57ad2a68e0984bd1676e5e651a9eb122fbb63105` |

The deploy script asserts each singleton's runtime code hash against the pinned
plan on-chain.

For the browser demo, `VITE_SEPOLIA_RPC_URL` overrides the Sepolia public-read
RPC. Note scanning and Merkle witness reconstruction use the connected wallet's
RPC provider, matching `sepolia-demo`, and still scan from deployment blocks in
bounded `eth_getLogs` chunks.

## Caveats

This is a reference implementation, not a production deployment:

- **Dev trusted setup.** The Groth16 VK comes from a single deterministic
  contribution, not an MPC ceremony. Do not use the shipped VK to hold value.
- **Placeholder ERC number.** `ERCXXXX`/`ercXXXX` strings are verbatim from the
  pre-draft; re-stamp via `scripts/constants.json` when a number is assigned.
- Submitter privacy, a note-root accumulator, and pool discovery are out of scope
  by design (see the ERC's Rationale and `docs/plan-deviations.md`).

See [`docs/conformance.md`](docs/conformance.md) for the spec-requirement →
test mapping and [`docs/plan-deviations.md`](docs/plan-deviations.md) for the
full deviation log.

## License

CC0-1.0, except `contracts/src/generated/*Verifier*.sol` and
`CanonicalPoolVerifier.sol` which inherit the snarkjs / Barretenberg generated
verifier licenses.
