// Public surface of the EIP-8182 reference helper library.
//
//   poseidon(...fieldElements) → BigInt   — EIP-8182 Section 3.3 sponge
//   T                                     — domain-tag constants (Section 3.1)
//   intent.transactionIntentDigest({...}) — Section 9.10 digest
//   intent.intentReplayId(...)            — Section 9.8
//   intent.ownerCommitment / noteBodyCommitment / noteCommitment / nullifier
//   intent.userRegistryLeaf / authPolicyLeaf / policyCommitment / blindedAuthCommitment
//   proof.snarkjsProofToBytes(snarkjsProof) → 256-byte Buffer
//   proof.bytesToSnarkjsProof(buf)         → snarkjs proof JSON
//   proof.vkJsonToBytes(snarkjsVk)         → canonical pool_vk.bin Buffer

const { poseidon, P } = require("./poseidon2");
const T = require("./domain_tags");
const intent = require("./intent");
const proof = require("./proof_codec");

module.exports = { poseidon, P, T, intent, proof };
