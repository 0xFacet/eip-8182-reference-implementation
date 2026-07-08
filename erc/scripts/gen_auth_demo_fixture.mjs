// Generates the demo-auth Groth16 fixture for AuthVerifiers.t.sol:
//   contracts/test/fixtures/auth_demo_proof_transfer.json
// The demo credential is authSecret=777; the intent fields are the transfer
// scenario in derivation_vectors.json, so the circuit reproduces the pool's
// transactionIntentDigest (publicInputs[19]). Locally verified before writing.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import * as snarkjs from "snarkjs";
import { poseidon } from "./lib/poseidon2.mjs";
import { proofToBytes } from "./lib/vector_witness.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ERC = path.resolve(HERE, "..");
const V = JSON.parse(fs.readFileSync(path.join(ERC, "assets/derivation_vectors.json"), "utf8"));
const WASM = path.join(ERC, "build/auth_demo/auth_demo_js/auth_demo.wasm");
const ZKEY = path.join(ERC, "build/auth_demo/auth_demo_final.zkey");
const VKEY = JSON.parse(fs.readFileSync(path.join(ERC, "build/auth_demo/auth_demo_vkey.json"), "utf8"));
const OUT = path.join(ERC, "contracts/test/fixtures");

const POLICY_COMMITMENT_DOMAIN = 17089308493803136227581826464435204313870844840508412608768146782858502706903n;
const BLINDED_AUTH_COMMITMENT_DOMAIN = 17084712478774764696285454596293346275081804222050654945657980304123980541631n;

const dec = (h) => BigInt(h).toString();
const s = V.scenarios.transfer;
const f = s.intentFields;

const authSecret = 777n;
const blindingFactor = BigInt(s.blindingFactor);
const authDataCommitment = poseidon(POLICY_COMMITMENT_DOMAIN, authSecret);
const blinded = poseidon(BLINDED_AUTH_COMMITMENT_DOMAIN, authDataCommitment, blindingFactor);
const digest = BigInt(s.publicInputs[19]);

const input = {
  blindedAuthCommitment: blinded.toString(),
  transactionIntentDigest: digest.toString(),
  poolAddress: dec(f.poolAddress),
  authVerifier: dec(f.authVerifier),
  authorizingAddress: dec(f.authorizingAddress),
  operationKind: dec(f.operationKind),
  tokenAddress: dec(f.tokenAddress),
  recipientOwnerNullifierKeyHash: dec(f.recipientOwnerNullifierKeyHash),
  amount: dec(f.amount),
  feeNoteRecipientOwnerNullifierKeyHash: dec(f.feeNoteRecipientOwnerNullifierKeyHash),
  feeAmount: dec(f.feeAmount),
  publicRecipientAddress: dec(f.publicRecipientAddress),
  authorizedSubmitter: dec(f.authorizedSubmitter),
  downstreamActionCommitment: dec(f.downstreamActionCommitment),
  executionConstraintsFlags: dec(f.executionConstraintsFlags),
  lockedOutputBinding0: dec(f.lockedOutputBinding0),
  lockedOutputBinding1: dec(f.lockedOutputBinding1),
  lockedOutputBinding2: dec(f.lockedOutputBinding2),
  nonce: dec(f.nonce),
  validUntilSeconds: dec(f.validUntilSeconds),
  executionChainId: dec(f.executionChainId),
  policyDataHash: dec(s.publicInputs[21]),
  authSecret: authSecret.toString(),
  blindingFactor: blindingFactor.toString(),
};

const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
const ok = await snarkjs.groth16.verify(VKEY, publicSignals, proof);
if (!ok) throw new Error("local verify failed");
if (publicSignals[0] !== blinded.toString()) throw new Error("pubSignal[0] mismatch: " + publicSignals[0]);
if (publicSignals[1] !== digest.toString()) throw new Error("pubSignal[1] mismatch: " + publicSignals[1]);

const fixture = {
  scenario: "transfer",
  note: "NON-NORMATIVE demo auth (authSecret=777). publicSignals=[blindedAuthCommitment, transactionIntentDigest].",
  proof: proofToBytes(proof),
  publicSignals: publicSignals.map((v) => "0x" + BigInt(v).toString(16)),
};
fs.mkdirSync(OUT, { recursive: true });
fs.writeFileSync(path.join(OUT, "auth_demo_proof_transfer.json"), JSON.stringify(fixture, null, 2) + "\n");
console.log("wrote auth_demo_proof_transfer.json");
console.log("  blinded =", "0x" + blinded.toString(16));
console.log("  digest  =", "0x" + digest.toString(16));
process.exit(0); // snarkjs leaves a worker pool open; force a clean exit
