# Noir Realistic Auth Circuit (End-to-End) — Design

Date: 2026-04-29
Status: Proposed (revision 2: bench-only → e2e)

## Goal

Demonstrate end-to-end how `IAuthVerifier` lets an EIP-8182 deployment plug in a
real, non-toy auth circuit using whatever proof system best fits. Produce:

1. A Noir auth circuit that does **real** ECDSA-secp256k1 signature verification
   over an **EIP-712** typed-data hash of the transaction intent, and binds the
   `authDataCommitment` to a real Ethereum address derived from the signer's
   secp256k1 public key.
2. A bb-generated UltraHonk Solidity verifier and a thin `IAuthVerifier`
   wrapper around it (`RealAuthVerifier`).
3. A Foundry integration test that exercises the full split-proof flow:
   pool proof (Groth16/BN254, mock precompile — unchanged) + auth proof
   (UltraHonk/BN254, real on-chain Honk verifier) → state changes asserted.
4. A bench harness that produces realistic prove-time numbers for the
   wallet-side end-to-end transfer.

The **pool side stays exactly as-is** (mock precompile in tests, real
precompile at fork time). Only the **auth side** is "real" in this deliverable —
which mirrors the production picture, where the auth verifier is a normal
Solidity contract and the pool verifier is an EVM precompile.

## Constraints

- **Only new files.** No edits to `circuits/`, `contracts/src/`, existing
  `contracts/test/`, existing scripts, root `package.json`, `foundry.toml`,
  `README.md`, or anything under `assets/`. New tests live in a new file
  Foundry will auto-discover. New scripts live in `scripts/noir/` and
  `scripts/integration/build_real_session.js`. New Solidity files live under
  `contracts/src/auth/` and `contracts/test/`.

## Why Noir / UltraHonk for the auth side

`IAuthVerifier.verifyAuth(bytes publicInputs, bytes proof) returns (bool)` is
proof-system-agnostic. The pool verifier is fixed (precompile), but auth can be
anything. Noir/UltraHonk is the natural pick because:

- `std::ecdsa_secp256k1::verify_signature(pkx[32], pky[32], sig[64], hash[32])`
  is stdlib — no 0xPARC circom-ecdsa BigInt machinery to vendor.
- `keccak256` ships as a maintained package (formerly stdlib, now
  `noir-lang/keccak256`) — no vocdoni keccak-circom to vendor.
- `bb write_solidity_verifier --scheme ultra_honk` auto-generates the on-chain
  verifier. No hand-written verifier code, no per-circuit ceremony.
- UltraHonk uses universal SRS — `bb` fetches/caches it on first run.
- Aztec's Poseidon2 BN254 (t=4 RF=8 RP=56, x⁵, M_E=`[[5,7,1,3],[4,6,1,1],[1,3,5,7],[1,1,4,6]]`,
  Horizen Labs constants, `N<<64` capacity tag) is the same parametrization
  the EIP pinned, so `transactionIntentDigest` and `blindedAuthCommitment`
  computed in Noir match the values the pool circuit produces.

## Reference circuit lineage

The reference circuit is from this repo's own history at commit
`71e7d72495db1955c6700613d7c3670b7c19cab8`, which had a complete
recursive Noir setup that was later removed during the migration to the
single-Groth16 pool circuit. Most of the supporting Noir machinery is
recoverable from that commit verbatim, with a small set of targeted
adaptations to match the current Section 9.10 formula.

### Files copied verbatim from commit 71e7d72 into `circuits-noir/`

| Source path at 71e7d72 | New path under `circuits-noir/` |
|---|---|
| `circuits/vendor/keccak256/` (entire dir) | `circuits-noir/vendor/keccak256/` |
| `circuits/vendor/poseidon/` (entire dir) | `circuits-noir/vendor/poseidon/` |
| `circuits/common/src/constants.nr` | `circuits-noir/common/src/constants.nr` |
| `circuits/common/src/range.nr` | `circuits-noir/common/src/range.nr` |
| `circuits/common/src/hash_utils.nr` | `circuits-noir/common/src/hash_utils.nr` |
| `circuits/common/src/crypto.nr` | `circuits-noir/common/src/crypto.nr` |
| `circuits/inner/common/src/secp256k1.nr` | `circuits-noir/auth/src/secp256k1.nr` |
| `circuits/inner/common/src/single_sig.nr` | `circuits-noir/auth/src/single_sig.nr` |
| `circuits/inner/common/src/curve_point.nr` | `circuits-noir/auth/src/curve_point.nr` |

Confirmed by inspection of 71e7d72:

- Domain-tag values in `constants.nr` (`TRANSACTION_INTENT_DIGEST_DOMAIN`,
  `POLICY_COMMITMENT_DOMAIN`, `BLINDED_AUTH_COMMITMENT_DOMAIN`, etc.) are
  byte-for-byte identical to the current `circuits/common/domain_tags.circom`.
  No edits needed.
- Vendored Poseidon2 sponge in `vendor/poseidon/src/poseidon2.nr` uses
  `iv = (in_len as Field) * 2^64`, RATE=3, capacity slot at index 3 — same
  framing as the EIP's `circuits/common/poseidon2_sponge.circom`. The
  permutation constants are Aztec/Horizen Labs, identical to the EIP's pinned
  `assets/eip-8182/poseidon2_bn254_t4_rf8_rp56.json` (still empirically
  verified by the poseidon2 cross-check task — see "Empirical gate" below).

### Files adapted from commit 71e7d72

| Source | Adaptation |
|---|---|
| `circuits/inner/eip712/src/main.nr` | Swap `SingleSigAuthorization { policy_version, …, valid_until_seconds }` for the current 15-field intent: replace `policy_version` with `auth_verifier`, add `execution_constraints_flags`, `locked_output_binding{0,1,2}`. Rebuild `AUTHORIZATION_TYPE_HASH` accordingly (script: `eip712_typehash_compute.js`). Set `verifyingContract = SHIELDED_POOL_ADDRESS` in the domain (matches historical `default_eip712_verifying_contract()`; the auth verifier address is committed inside the struct via `auth_verifier`, not via the domain). |
| `circuits/common/src/digest.nr` | `transaction_intent_digest(...)` takes `auth_verifier` as first field after the domain tag (replacing `policy_version`), keeping the same 16-input `p_hash16` shape. Other 14 fields unchanged. |
| `circuits/inner/common/src/lib.nr` | Drop `InnerOutputs`. Replace `Intent.policy_version` with `Intent.auth_verifier`; same for `ValidatedIntent`. Add `pub fn blinded_auth_commitment(auth_data_commitment: Field, blinding_factor: Field) -> Field { p_hash3([BLINDED_AUTH_COMMITMENT_DOMAIN, auth_data_commitment, blinding_factor]) }` since the historical recursive design exposed `auth_data_commitment` directly and the outer proof did the blinding; we have no outer proof so the auth circuit blinds in-circuit. |

The adopted style:

- EIP-712 type hashes pinned as `global [u8; 32]` constants computed off-circuit.
- `authorization_signing_hash(...)` builds the EIP-712 digest from explicit
  `write_field_as_u256` / `write_bytes32` byte writes into fixed buffers, then
  three `keccak256` calls (struct, domain, final).
- Range checks on every Field that semantically represents a bounded value
  (`assert_address`, `assert_amount`, `assert_valid_until`).
- `nonce` carried as `[u8; 32]` so the EIP-712 nonce keeps its full 32 bytes,
  decoded into a Field via `hi*2^128 + lo` with strict less-than-modulus check.
- Authorizing Ethereum address derived in-circuit from the pubkey via
  `keccak256(pkx || pky)[-20:]`, then equality-asserted against the intent's
  `authorizingAddress` field.

The reference targets a 9-field authorization for a recursive system that
returns a multi-field `InnerOutputs`. We target a **2-field public output**
matching `auth_demo`'s `[blindedAuthCommitment, transactionIntentDigest]`,
so the existing `IAuthVerifier` layout is preserved.

## File layout (all new files)

```
circuits-noir/
  vendor/
    keccak256/                 # copied verbatim from 71e7d72 circuits/vendor/keccak256/
    poseidon/                  # copied verbatim from 71e7d72 circuits/vendor/poseidon/
  common/
    Nargo.toml                 # mirrors 71e7d72 circuits/common/Nargo.toml
    src/
      lib.nr                   # re-exports
      constants.nr             # copied verbatim from 71e7d72 circuits/common/src/constants.nr
      range.nr                 # copied verbatim from 71e7d72 circuits/common/src/range.nr
      hash_utils.nr            # copied verbatim from 71e7d72 circuits/common/src/hash_utils.nr
      crypto.nr                # copied verbatim from 71e7d72 circuits/common/src/crypto.nr
      digest.nr                # ADAPTED: transaction_intent_digest takes auth_verifier first
  auth/
    Nargo.toml                 # deps: keccak256, common, poseidon
    Prover.toml                # generated by gen_prover_toml.js
    src/
      main.nr                  # ADAPTED from 71e7d72 circuits/inner/eip712/src/main.nr
      types.nr                 # ADAPTED from 71e7d72 circuits/inner/common/src/lib.nr (Intent, ValidatedIntent, Authorization, finalize)
      secp256k1.nr             # copied verbatim from 71e7d72 circuits/inner/common/src/secp256k1.nr
      single_sig.nr            # copied verbatim from 71e7d72 circuits/inner/common/src/single_sig.nr
      curve_point.nr           # copied verbatim from 71e7d72 circuits/inner/common/src/curve_point.nr

scripts/
  noir/
    package.json               # { "private": true } — resolves ethers via root node_modules
    poseidon2_xcheck.js        # cross-check Noir stdlib vs project poseidon2
    poseidon2_xcheck/
      Nargo.toml
      src/main.nr              # exports test poseidon2 outputs
    eip712_typehash_compute.js # computes the 4 type-hash byte arrays, prints them as Noir globals
    gen_prover_toml.js         # build Prover.toml from a shared intent + ethers signing
    bench.sh                   # compile, witness, prove, verify, time, emit bench.json

scripts/
  integration/
    build_real_session.js      # pool Groth16 + Noir Honk auth → real_session.json

contracts/
  src/auth/
    HonkRealAuthVerifier.sol   # auto-generated by `bb write_solidity_verifier`
    RealAuthVerifier.sol       # IAuthVerifier wrapper around the Honk verifier
  test/
    IntegrationRealAuth.t.sol  # full split-proof e2e with the real auth

build/
  noir_auth/                   # nargo + bb output (gitignored under existing build/)
  integration/
    real_session.json          # output of build_real_session.js

docs/superpowers/specs/2026-04-29-noir-realistic-auth-circuit-design.md  (this file)
```

Files **not** modified: `circuits/`, `contracts/src/ShieldedPool.sol`,
`contracts/src/MockPoolPrecompile.sol`, `contracts/src/auth/DemoAuthVerifier.sol`,
`contracts/src/AuthDemoGroth16Verifier.sol`, `contracts/src/PoolGroth16Verifier.sol`,
`contracts/src/interfaces/`, `contracts/script/InstallSystemContracts.s.sol`,
`contracts/test/Integration.t.sol`, `scripts/integration/build_session.js`,
`scripts/witness/`, `scripts/circuit/`, `scripts/assets/`, root `package.json`,
`foundry.toml`, `README.md`, anything under `assets/`.

## Public-signal contract

```
publicInputs (bytes) = abi.encode(uint256 blindedAuthCommitment, uint256 transactionIntentDigest)
proof        (bytes) = bb UltraHonk proof bytes (variable length, ~14–30 KB)
```

Same 2 BN254 field elements as `auth_demo`. The wrapper `RealAuthVerifier`
enforces a fixed proof length matching the bb-emitted proof size for our
circuit; differs from `DemoAuthVerifier`'s 256-byte Groth16 length but the
interface signature is unchanged.

## Circuit body (Noir)

Public inputs:

```noir
fn main(
  // public
  blinded_auth_commitment:    pub Field,
  transaction_intent_digest:  pub Field,

  // private — 15 intent fields per Section 9.10
  auth_verifier:               Field,                    // private; bound by the EIP-712 verifyingContract
  authorizing_address:         Field,                    // private; equality-checked against pubkey-derived address
  operation_kind:              Field,
  token_address:               Field,
  recipient_address:           Field,
  amount:                      Field,
  fee_recipient_address:       Field,
  fee_amount:                  Field,
  execution_constraints_flags: Field,
  locked_output_binding0:      Field,
  locked_output_binding1:      Field,
  locked_output_binding2:      Field,
  nonce:                       [u8; 32],                 // 32-byte EIP-712 nonce; decoded to Field after range check
  valid_until_seconds:         Field,
  execution_chain_id:          Field,

  // private — credential
  pubkey_x:        [u8; 32],
  pubkey_y:        [u8; 32],
  signature:       [u8; 64],
  blinding_factor: Field,
)
```

Body (sketch, not literal):

```noir
// 1. Range checks: every Field that represents a bounded semantic type.
range::assert_address(auth_verifier);
range::assert_address(authorizing_address);
range::assert_address(token_address);
range::assert_address(recipient_address);
range::assert_amount(amount);
range::assert_address(fee_recipient_address);
range::assert_amount(fee_amount);
range::assert_valid_until(valid_until_seconds);
// (operation_kind, execution_constraints_flags, lockedOutputBinding*, nonce, executionChainId
//  have their own bounds enforced where needed)

// 2. Bind the authorizing address to the secp256k1 public key.
let derived = ethereum_address::from_pubkey(pubkey_x, pubkey_y);
assert(derived == authorizing_address, "authorizingAddress != keccak(pubkey)[-20:]");

// 3. Build the EIP-712 signing digest (15 intent fields, one keccak per stage).
let nonce_field = bytes_utils::nonce_bytes_to_field(nonce);
let digest = eip712::signing_hash(
  /* 14 numeric fields including nonce_field */, nonce, // raw bytes for the type-hash preimage
  auth_verifier,        // = EIP-712 verifyingContract
  execution_chain_id,   // = EIP-712 chainId
);

// 4. ECDSA verify (stdlib).
assert(std::ecdsa_secp256k1::verify_signature(pubkey_x, pubkey_y, signature, digest));

// 5. authDataCommitment = p_hash4([pkx_hi, pkx_lo, pky_hi, pky_lo]).
//    Per `circuits/common/src/crypto.nr` from 71e7d72 (recovered verbatim):
//    no domain tag, just the four 16-byte halves of the pubkey hashed via
//    a 4-input length-tagged Poseidon2 sponge. The user's policy registration
//    committed to this value off-chain ahead of time.
let auth_data_commitment = secp256k1::Secp256k1PubKey { x: pubkey_x, y: pubkey_y }
    .auth_commitment();

// 6. blindedAuthCommitment (public).
let computed_blinded = poseidon2::sponge([
  domain_tags::BLINDED_AUTH_COMMITMENT_DOMAIN,
  auth_data_commitment,
  blinding_factor,
]);
assert(computed_blinded == blinded_auth_commitment);

// 7. transactionIntentDigest (public).
let computed_intent_digest = poseidon2::sponge([
  domain_tags::TRANSACTION_INTENT_DIGEST_DOMAIN,
  auth_verifier, authorizing_address, operation_kind, token_address,
  recipient_address, amount, fee_recipient_address, fee_amount,
  execution_constraints_flags, locked_output_binding0, locked_output_binding1,
  locked_output_binding2, nonce_field, valid_until_seconds, execution_chain_id,
]);
assert(computed_intent_digest == transaction_intent_digest);
```

## EIP-712 schema

Domain:

```
EIP712Domain(string name, string version, uint256 chainId, address verifyingContract)
name              = (whatever string the historical NAME_HASH was computed from — preserved from 71e7d72)
version           = (preserved from 71e7d72)
chainId           = executionChainId          (signed; carried as a circuit input)
verifyingContract = SHIELDED_POOL_ADDRESS     (= 0x...0030 per Section 5.1)
```

Rationale for `verifyingContract = SHIELDED_POOL_ADDRESS`: the user is
authorizing the system to act on their funds; the auth verifier is one
implementation detail and might be redeployed. Binding the signature to the
shielded pool address keeps the user's signed intent stable across auth-verifier
upgrades. The auth verifier address is still committed inside the intent
(via `auth_verifier` field) so the auth proof binds to a specific verifier — but
the *signature* binds to the pool itself. This matches the historical 71e7d72
choice (`default_eip712_verifying_contract()`).

Intent struct (15 fields matching the current `auth_demo`/`pool.circom`
public-signal layout — note the `auth_verifier` field that replaces 71e7d72's
`policy_version`):

```
TransactionIntent(
  address authVerifier,
  address authorizingAddress,
  uint256 operationKind,
  address tokenAddress,
  address recipientAddress,
  uint256 amount,
  address feeRecipientAddress,
  uint256 feeAmount,
  uint256 executionConstraintsFlags,
  bytes32 lockedOutputBinding0,
  bytes32 lockedOutputBinding1,
  bytes32 lockedOutputBinding2,
  bytes32 nonce,
  uint256 validUntilSeconds,
  uint256 executionChainId
)
```

The four type hashes (`DOMAIN_TYPE_HASH`, `NAME_HASH`, `VERSION_HASH`,
`AUTHORIZATION_TYPE_HASH`) are pinned as `global [u8; 32]` constants in
`auth/src/main.nr`. `DOMAIN_TYPE_HASH`, `NAME_HASH`, `VERSION_HASH` are copied
from 71e7d72 verbatim (the strings they hashed are preserved).
`AUTHORIZATION_TYPE_HASH` is **regenerated** by
`scripts/noir/eip712_typehash_compute.js` because the struct shape changes
(15 fields now vs 9 at 71e7d72). The script also runs a JS-side computation
of the same digest with `ethers.TypedDataEncoder` and asserts equality, so the
in-circuit and off-circuit values are guaranteed to match by construction.

## Poseidon2 alignment / empirical gate

The EIP's pinned Poseidon2 parameters and the vendored Aztec Poseidon2 (which
we copy from 71e7d72 verbatim) are identical on every observable axis: same
field, t=4, RF=8, RP=56, x⁵ S-box, same external matrix `M_E`, both reference
the Horizen Labs sage script for round constants, same `N<<64` capacity
length-tagging (verified by inspection of
`circuits/vendor/poseidon/src/poseidon2.nr` at 71e7d72).

**Empirical gate (first implementation task):** `scripts/noir/poseidon2_xcheck.js`
runs the *vendored* `Poseidon2::hash` (not stdlib — the vendored one is what
the auth circuit actually uses) on:

- `[0, 0, 0, 0]`, `[1, 2, 3, 4]`, `[F-1, F-1, F-1, F-1]`
- Each multi-element vector from `assets/eip-8182/poseidon2_vectors.json`,
  routed through the EIP's sponge framing

…and compares each output field-by-field against `scripts/witness/poseidon2.js`
(read-only). MATCH → use stdlib. MISMATCH → fall back to a hand-rolled
permutation that loads constants from
`assets/eip-8182/poseidon2_bn254_t4_rf8_rp56.json` (also read-only). Either
outcome ships in this deliverable; the constant-table fallback adds ~1 day.

## Solidity layer

`HonkRealAuthVerifier.sol` is auto-generated by:

```bash
bb write_solidity_verifier --scheme ultra_honk -k build/noir_auth/target/vk -o contracts/src/auth/HonkRealAuthVerifier.sol
```

`RealAuthVerifier.sol` mirrors `DemoAuthVerifier.sol`'s shape:

```solidity
contract RealAuthVerifier is IAuthVerifier {
    HonkRealAuthVerifier public immutable verifier;
    uint256 public immutable expectedProofLength; // pinned at deploy time

    constructor(HonkRealAuthVerifier verifier_, uint256 expectedProofLength_) {
        verifier = verifier_;
        expectedProofLength = expectedProofLength_;
    }

    function verifyAuth(bytes calldata publicInputs, bytes calldata proof)
        external
        view
        override
        returns (bool)
    {
        if (publicInputs.length != 64 || proof.length != expectedProofLength) return false;
        (uint256 blindedAuthCommitment, uint256 transactionIntentDigest) =
            abi.decode(publicInputs, (uint256, uint256));

        bytes32[] memory pubs = new bytes32[](2);
        pubs[0] = bytes32(blindedAuthCommitment);
        pubs[1] = bytes32(transactionIntentDigest);

        try verifier.verify(proof, pubs) returns (bool ok) {
            return ok;
        } catch {
            return false;
        }
    }
}
```

The `verifier.verify(proof, pubs)` signature is the standard one bb emits;
will be confirmed against the actual generated header on first compile and
the wrapper adjusted if needed.

## Witness generation

`scripts/noir/gen_prover_toml.js` (new file) produces
`circuits-noir/auth/Prover.toml` for any given intent:

1. Reads `build/auth_demo/shared_intent.json` if available (otherwise
   synthesizes a default with the same constants the pool worst-case witness
   uses), and `build/domain_tags.json` (read-only — produced by the existing
   build).
2. Generates a deterministic test secp256k1 keypair via `ethers`. Derives the
   ethereum address.
3. Computes the EIP-712 digest with `ethers.TypedDataEncoder.hash(domain, types, intent)`,
   cross-checked against an independent re-implementation in the same script.
4. Signs with the test private key. Splits 65-byte signature into `r`, `s`
   (32 bytes each), discards the `v` recovery byte (Noir verify doesn't take it).
   Asserts `s ≤ secp256k1.n / 2` (low-s normalization).
5. Computes `authDataCommitment`, `blindedAuthCommitment`, `transactionIntentDigest`
   using the project's `scripts/witness/poseidon2.js` (read-only) so the values
   match the pool side.
6. Writes the Prover.toml and a JSON sidecar with the same values for the
   integration test.

## Build / prove pipeline

`scripts/noir/bench.sh` (new file):

```bash
# Prerequisites: nargo and bb on PATH (external tools, not installed by us).
cd circuits-noir/auth
nargo compile
nargo execute witness                                           # → target/witness.gz
bb prove --scheme ultra_honk -b target/auth.json -w target/witness.gz -o target/proof
bb verify --scheme ultra_honk -k target/vk -p target/proof
bb write_solidity_verifier --scheme ultra_honk -k target/vk -o ../../contracts/src/auth/HonkRealAuthVerifier.sol
```

The script wraps each step with `/usr/bin/time` (macOS `-l` / Linux `-v`),
runs N=10 trials, writes `build/noir_auth/bench.json` with target hardware,
constraint counts, p50/p95 timings, peak RSS, proof size, public-inputs size,
and tooling versions. Prints a wallet-side e2e line:
`pool_prove (rapidsnark Groth16) + auth_prove (bb UltraHonk)` with the explicit
caveat that these are different proof systems but a wallet computes both for
one transfer.

## Real-session builder

`scripts/integration/build_real_session.js` (new file):

1. Pins the `RealAuthVerifier` deployment address (e.g. `0x8182AAAA...`) — the
   integration test will `vm.etch` to that address to break the chicken-and-egg.
2. Generates a pool witness input where `authVerifier == 0x8182AAAA...` and the
   `authorizingAddress` is the pubkey-derived ethereum address from the
   Noir auth witness gen.
3. Runs the existing pool witness/prove pipeline (snarkjs.groth16.prove) to
   produce the pool proof — uses `build/pool/pool_final.zkey` (already built).
4. Runs `nargo execute witness` and `bb prove --scheme ultra_honk` to produce
   the auth proof.
5. Writes `build/integration/real_session.json` with both proofs and their
   public inputs in the canonical 256-byte (pool Groth16) and bb-emitted
   (auth Honk) byte layouts.

## Integration test

`contracts/test/IntegrationRealAuth.t.sol` (new file). Mirrors
`Integration.t.sol`'s setup pattern but with the real auth verifier:

1. Read `build/integration/real_session.json` via `vm.readFileBinary` /
   `vm.parseJson`.
2. `vm.etch` `MockPoolPrecompile` at `SHIELDED_POOL_ADDRESS` etc., same as the
   existing test.
3. Deploy `HonkRealAuthVerifier` and `RealAuthVerifier`. Use `vm.etch` to
   place `RealAuthVerifier` at the pinned address that `build_real_session.js`
   committed to in the pool proof.
4. Call `pool.registerUser(...)` and `pool.registerAuthPolicy(policyCommitment)`
   where `policyCommitment` is computed from the pubkey-derived
   `authDataCommitment` per the existing intent formulas.
5. Call `pool.deposit(...)` to fund the test address.
6. Call `pool.transact(publicInputs, poolProof, authProof)` — the system
   contract verifies the pool proof via `MockPoolPrecompile` and the auth proof
   via `RealAuthVerifier`.
7. Assert state changes: nullifiers consumed, output commitments inserted,
   intent replay id consumed, expected event emitted.

The test is one positive path. Negative paths (tampered auth proof, wrong
domain separator, etc.) are out of scope for this deliverable — exhaustive
auth-verifier negative testing is what the existing `Integration.t.sol` 10-test
suite does for `DemoAuthVerifier`, and the same pattern would apply
mechanically here.

## Out of scope

- Replacing or modifying `auth_demo`.
- Editing `pool.circom` or any existing Solidity except by deploying alongside
  it. (No edits — we add new contracts and a new test file.)
- Asset-bundle additions (`assets/eip-8182/`). The realistic auth circuit is
  not normative.
- Negative-path tests beyond the one happy-path integration test.
- Recursive proof aggregation. Pool and auth remain two independent proofs
  passed separately to `transact`.

## Risks and unknowns

1. **Empirical poseidon2 mismatch.** Mitigation: cross-check first.
   Fallback: hand-rolled permutation loading EIP's pinned constants. Same
   circuit shape, +1 day.

2. **bb-emitted Honk verifier signature drift.** `verifier.verify(proof, pubs)`
   may differ in name or argument order between bb releases. Will compile
   the wrapper against the actual generated header on first run and adjust.
   Pinning a known-good `bb` version in the bench output mitigates.

3. **Honk proof size variability.** Proof size is fixed for a given circuit
   shape but differs across bb versions and flag combinations. The wrapper's
   `expectedProofLength` is a constructor argument, set after the first
   successful build. The integration test reads the actual proof bytes from
   `real_session.json`, so it auto-adapts.

4. **Pool proof is regenerated.** Existing `build_session.js` produces a pool
   proof for the demo's `authVerifier`. We need a pool proof bound to the real
   `authVerifier` address; that's why `build_real_session.js` exists. It
   reuses the existing pool zkey and witness pipeline; no circuit rebuild
   required.

5. **`nargo` / `bb` install.** External tools. Bench/test scripts probe for
   them and bail with a clear message + install command if missing.

6. **Integration test runs slow.** A bb prove takes seconds; running it
   inline before each `forge test` invocation is too slow. Test reads
   pre-built `real_session.json` artifact, like the existing integration test
   reads `build/integration/session.json`.

## Acceptance criteria

- `scripts/noir/poseidon2_xcheck.js` runs and reports MATCH (or MISMATCH plus
  the constants-fallback path is implemented).
- `nargo compile` succeeds on the auth circuit. `nargo test` (Noir-side
  in-circuit unit tests for `nonce_bytes_to_field`, `ethereum_address::from_pubkey`,
  EIP-712 type hashes, and a poseidon2 round-trip) all pass.
- `bb prove` produces a proof; `bb verify` accepts it.
- `bb write_solidity_verifier` produces `HonkRealAuthVerifier.sol`.
- `forge build` compiles `RealAuthVerifier.sol` and `IntegrationRealAuth.t.sol`.
- `node scripts/integration/build_real_session.js` produces
  `build/integration/real_session.json`.
- `forge test --match-contract IntegrationRealAuth` passes the happy-path test.
- `scripts/noir/bench.sh` produces `build/noir_auth/bench.json` with non-zero
  prove time and a printed wallet-side e2e line.
- No file outside the new-file allowlist (see "File layout") is created or
  modified.
