# EIP-8182 Reference Implementation

Reference implementation for [EIP-8182: Private ETH and ERC-20 Transfers](https://eips.ethereum.org/EIPS/eip-8182).

This repo has one main idea:

- the **outer circuit** is the fixed pool protocol
- the **inner circuit** is the pluggable authorization method

Everything else in the repo exists to support one of those two layers.

## Toolchain requirements

Exact versions matter. Wrong versions produce different verification keys, and proofs will not verify against the on-chain verifier.

| Tool              | Version                | Pin                              |
| ----------------- | ---------------------- | -------------------------------- |
| Noir (nargo)      | 1.0.0-beta.19          | `circuits/noir-toolchain.toml`   |
| Barretenberg (bb) | 4.0.0-nightly.20260120 | checked at proof generation time |
| Node.js           | >= 22                  |                                  |
| Foundry (forge)   | recent                 |                                  |
| jq                | recent                 | used by the installer script     |

### Barretenberg (`bb`)

Proof generation requires the exact `bb` version `4.0.0-nightly.20260120`.

Install the matching `bb` binary from the official release artifacts, then either:

- place it at `~/.bb/bb`
- set `BB_BINARY=/absolute/path/to/bb`

Verify:

```bash
bb --version
# expected: 4.0.0-nightly.20260120
```

### jq

The installer script uses `jq` to normalize JSON output.

Install `jq` with your system package manager, then verify:

```bash
jq --version
```

## First run

```bash
npm install
cd contracts && forge install && cd ..
npm run check:domains
npm run test:unit
```

## Test commands

```bash
npm run test:unit           # fast contract unit tests (mock verifier, no proofs)
npm run test:slow           # unit + real verifier integration + smoke E2E
npm run test:e2e:fullflow   # full deposit/transfer/withdraw flows with real proofs
npm run test:all            # everything
npm run test:circuits       # Noir circuit tests (nargo test --workspace)
```

## Build and maintenance

```bash
npm run contracts:build              # forge build
npm run contracts:verifier:refresh   # regenerate HonkVerifier.sol from current outer circuit
npm run contracts:verifier:check     # check if HonkVerifier.sol is stale
npm run check:domains                # verify domain constant derivation
npm run sync:domains                 # regenerate domain constants
npm run check:eip712                 # verify EIP-712 type hash constants
```

---

## How to read this repo

If you have already skimmed the EIP, read the repo in this order:

1. `circuits/inner/common/` — the shared inner-circuit authoring API
2. `circuits/inner/eip712/` — the baseline single-sig companion-standard inner circuit
3. `circuits/inner/multisig_2of3/` — the threshold-auth example
4. `circuits/outer/` — the shared pool protocol circuit that consumes the inner proof
5. `src/lib/` — TypeScript protocol parity helpers
6. `integration/src/` — host-side witness builders and proof runners
7. `contracts/` — the on-chain verifier and settlement surface

## Two-circuit architecture

EIP-8182 splits proving into two layers.

### Outer circuit

The outer circuit is the protocol kernel. It enforces:

- deposit / transfer / withdrawal mode rules
- note commitments and nullifiers
- registry membership checks
- intent nullifier derivation
- output-note-data hash binding
- recursive verification of the inner proof
- the exact public-input layout consumed by `ShieldedPool`

This is the shared circuit. It is the part that must stay protocol-consistent.

### Inner circuit

The inner circuit is the authorization plugin. It answers questions like:

- who is allowed to approve this spend?
- how many approvals are required?
- what extra restrictions apply?

It does **not** implement pool settlement. It only proves authorization and returns two public outputs:

- `authDataCommitment`
- `intentDigest`

The outer circuit consumes those two outputs and does the rest.

### Dependency direction

The intended dependency direction is:

- `circuits/inner/common` defines the shared inner authoring surface
- runnable inner circuits like `eip712` and `multisig_2of3` depend on that shared inner library
- the outer circuit does **not** depend on inner policy details; it only depends on the inner proof's public outputs
- `src/lib` mirrors protocol hashes / encodings in TypeScript
- `integration/src` turns app/test inputs into Noir witnesses and runs the inner and outer proof steps

## Repo structure

```text
circuits/
  common/                    protocol-level Noir library shared by outer and inner crates
  inner/
    common/                  shared inner-circuit authoring library
    eip712/                  baseline single-sig companion-standard inner circuit
    multisig_2of3/           2-of-3 threshold multisig example
  outer/                     shared protocol / settlement circuit
  vendor/                    vendored Noir dependencies

contracts/
  src/                       ShieldedPool system contract and Solidity libraries
  test/                      Foundry tests, including FFI-driven proof tests
  test/generated/            generated HonkVerifier (test-only precompile simulation)
  script/                    fixed-address installer / bootstrap script

src/lib/                     TypeScript protocol-parity helpers
integration/src/             host-side witness builders and proof runners
prover/                      non-normative HTTP proving sidecar for the baseline eip712 flow
scripts/                     build, verifier-sync, and consistency checks
```

Two similarly named directories do different jobs:

- `circuits/common` is protocol machinery shared across the circuit workspace
- `circuits/inner/common` is the authoring API for inner circuits

## Inner-circuit surface

The shared inner-circuit API lives in `[circuits/inner/common/src/lib.nr](circuits/inner/common/src/lib.nr)`.

The standardized pieces are:

- `Intent` / `ValidatedIntent`
- `ExecutionConstraints`
- `InnerOutputs`

Everything else is auth-method-specific.

The rule for reading or writing an inner circuit:

- the shared library defines the protocol-shaped intent and output surface
- each inner circuit defines its own policy / approval witnesses
- the inner circuit validates intent, checks approvals, and returns `InnerOutputs`

## The two included inner circuits

### `circuits/inner/eip712`

The baseline single-sig companion-standard example. It is deliberately narrower than the generic `Intent` path:

- the signed struct omits `authorizingAddress`
- execution constraints are fixed to zero
- `executionChainId` and `poolAddress` come from the EIP-712 domain
- `authorizingAddress` is derived from the secp256k1 public key
- `authDataCommitment` is `poseidon(xHi, xLo, yHi, yLo)` over the signer's 32-byte big-endian secp256k1 coordinates, split into 128-bit limbs

Read this first if you want the smallest complete inner circuit.

### `circuits/inner/multisig_2of3`

Threshold authorization using the full `Intent` struct. Read this after `eip712` to see what is shared vs what is policy-specific.

What changes relative to `eip712`:

- the witness includes a multisig policy and threshold approvals
- the challenge is built from the shared `Intent`
- the auth logic checks distinct approving signers

What stays the same:

- the intent validation surface
- the final output shape
- the handoff to the outer circuit via `InnerOutputs`

The outer circuit does not need to understand either policy struct. It only needs `auth_data_commitment` and `intent_digest`. Each policy module reduces itself to an `Authorization` with an `auth_data_commitment`, which the contract and outer circuit match against the registered auth-policy leaf.

## TypeScript layers

### `src/lib/`

Two files: `protocol.ts` (EIP-712 struct hashing, intent digest computation, domain separators, address/field helpers) and `domainConstants.ts` (generated Poseidon domain constants). Note delivery encodings live in `prover/src/note_delivery.ts`.

### `integration/src/`

Host-side proof orchestration: witness builders for inner and outer circuits, proof runners for tests and fixtures, helpers that bridge app/test inputs into Noir. Two scripts generate proofs for the E2E tests:

- `generate_eip712_proof.ts` — single-sig EIP-712 proofs (deposit, transfer, withdrawal)
- `generate_multisig_proof.ts` — 2-of-3 multisig proofs (all modes)

Both are called by the Solidity E2E tests via Foundry FFI.

## Prover sidecar

`prover/` is an optional, non-normative demo sidecar for delegated proving and note delivery. It is not part of the release validation surface. It supports only the baseline `eip712` inner circuit, delivery scheme `1` (X-Wing), and zero execution constraints.

```bash
npm run prover:start    # start the prover
npm run prover:dev      # start with file watching
```

Key entrypoints: `prover/src/index.ts` (HTTP server), `prover/src/note_delivery.ts` (scheme-`1` encoding/recovery), `prover/src/recover_note.ts` (CLI helper used by tests).

## Installer

`contracts/script/InstallSystemContracts.s.sol` runs a local system-install simulation: etches `ShieldedPool` to the fixed pool address, links to canonical PoseidonT3, bootstraps the empty-hash cache, and writes install artifacts.

```bash
cd contracts
forge script script/InstallSystemContracts.s.sol:InstallSystemContracts
```

Outputs: `contracts/script-output/shielded-pool-install.json` and `contracts/script-output/shielded-pool-state.json`.

## Addresses

- System contract: `0x0000000000000000000000000000000000081820`
- Proof verification precompile: `0x0000000000000000000000000000000000000030`
- PoseidonT3: `0x3333333C0A88F9BE4fd23ed0536F9B6c427e3B93`
