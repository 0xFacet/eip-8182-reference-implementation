// Regenerates the real UltraHonk auth-proof fixture for AuthVerifiers.t.sol:
//   contracts/test/fixtures/auth_honk_proof_transfer.json
// from the transfer scenario in assets/derivation_vectors.json, using the SDK's
// proveHonkAuth (which pins the same 20-field EIP-712 intent + ECDSA witness the
// nargo vector_test does). Supersedes the hardcoded Prover.toml in
// gen_auth_fixture.sh so the two spec §7.1 fields flow through automatically.
//
// Run after building circuits-noir/auth: node scripts/gen_auth_honk_fixture.mjs

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { proveHonkAuth } from "../sdk/src/prover.ts";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ERC = path.resolve(HERE, "..");
const V = JSON.parse(fs.readFileSync(path.join(ERC, "assets/derivation_vectors.json"), "utf8"));
const OUT = path.join(ERC, "contracts/test/fixtures/auth_honk_proof_transfer.json");

const s = V.scenarios.transfer;
const f = s.intentFields;
const b = (k) => BigInt(f[k]);

const fields = {
  poolAddress: b("poolAddress"),
  authVerifier: b("authVerifier"),
  authorizingAddress: b("authorizingAddress"),
  operationKind: b("operationKind"),
  tokenAddress: b("tokenAddress"),
  recipientOwnerNullifierKeyHash: b("recipientOwnerNullifierKeyHash"),
  amount: b("amount"),
  feeNoteRecipientOwnerNullifierKeyHash: b("feeNoteRecipientOwnerNullifierKeyHash"),
  feeAmount: b("feeAmount"),
  publicRecipientAddress: b("publicRecipientAddress"),
  authorizedSubmitter: b("authorizedSubmitter"),
  downstreamActionCommitment: b("downstreamActionCommitment"),
  executionConstraintsFlags: b("executionConstraintsFlags"),
  lockedOutputBinding0: b("lockedOutputBinding0"),
  lockedOutputBinding1: b("lockedOutputBinding1"),
  lockedOutputBinding2: b("lockedOutputBinding2"),
  nonce: b("nonce"),
  validUntilSeconds: b("validUntilSeconds"),
  executionChainId: b("executionChainId"),
};

const ev = s.eip712;
const signed = {
  digest: ev.digest,
  signature: ev.signature,
  v: ev.v,
  r: ev.r,
  s: ev.s,
  publicKeyX: ev.publicKeyX,
  publicKeyY: ev.publicKeyY,
};

const auth = proveHonkAuth({
  fields,
  policyDataHash: BigInt(s.policyDataHash),
  blindingFactor: BigInt(s.blindingFactor),
  signed,
});

const fixture = {
  scenario: "transfer",
  note: "Real UltraHonk auth proof. publicSignals=[blindedAuthCommitment, transactionIntentDigest]; pairing points are inside proof.",
  proof: auth.proof,
  publicSignals: ["0x" + auth.publicSignals[0].toString(16), "0x" + auth.publicSignals[1].toString(16)],
};
fs.writeFileSync(OUT, JSON.stringify(fixture, null, 2) + "\n");
console.log("wrote " + OUT);
console.log("  blinded =", fixture.publicSignals[0]);
console.log("  digest  =", fixture.publicSignals[1]);
console.log("  vector transactionIntentDigest =", s.transactionIntentDigest);
if (BigInt(fixture.publicSignals[1]) !== BigInt(s.transactionIntentDigest)) {
  throw new Error("digest mismatch vs vector");
}
process.exit(0);
