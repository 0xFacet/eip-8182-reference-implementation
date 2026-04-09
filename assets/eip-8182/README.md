# Execution-Spec Asset Bundle

This directory is the repo-local counterpart to the asset set named in [eip-8182.md](/Users/tom/Dropbox/db-src/eip-8182-reference-implementation/eip-8182.md).

The local EIP markdown intentionally keeps upstream-style relative links. This bundle provides the matching checked-in files in this repo without rewriting the EIP copy.

Files:

- `poseidon_bn254_t3_rf8_rp57.json`
  Normative Poseidon parameter asset for the BN254 `t=3`, `R_F=8`, `R_P=57` instance named by the EIP.
- `poseidon_vectors.json`
  Normative Poseidon `hash_2` and arity-prefixed `poseidon(...)` vectors derived from the repo’s reference helpers.
- `shielded-pool-state.json`
  Fork-activation state dump for `SHIELDED_POOL_ADDRESS`, generated from the local installer flow and filtered to the pool account only.
- `poseidon_t3_runtime.hex`
  Runtime prerequisite for the external `PoseidonT3` library address.
- `delivery_scheme1_vectors.json`
  Normative delivery-scheme `1` vectors for the pinned X-Wing + AES-256-GCM receive path.
- `outer_vk.bin`
  Raw Barretenberg verification-key bytes for the current `outer` circuit.
- `outer_vk.sha256`
  SHA-256 of `outer_vk.bin`, lowercase hex.
- `outer_vk.bb_hash.hex`
  `vk_hash` emitted by `bb write_vk`, rendered as `0x`-prefixed lowercase hex.
- `outer_verifier_transcript_vk_hash.hex`
  `VK_HASH` extracted from the freshly generated Solidity verifier.
- `outer_verifier_metadata.json`
  Fixed metadata schema describing verifier constants, pool-facing public-input layout, proof length, and hash pins.
- `outer_precompile_happy_path.json`
  Repo-local verifier-precompile acceptance vector only. It is not a full transact state test.
- `outer_precompile_invalid_proof.json`
  Repo-local verifier-precompile reject vector for a well-formed but invalid proof.
- `outer_precompile_malformed_input.json`
  Repo-local verifier-precompile reject vector for malformed calldata.
- `outer_precompile_noncanonical_field.json`
  Repo-local verifier-precompile reject vector for a non-canonical public input.

The proof-backed vectors are not byte-stable across regenerations, so stale checks validate them structurally and the contract suite verifies the committed vectors against the local precompile simulation.

Refresh or check the generated assets from the repo root:

```bash
npm run execution-spec-assets:refresh
npm run execution-spec-assets:check
npm run execution-specs:check
```
