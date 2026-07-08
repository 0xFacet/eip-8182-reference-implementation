// Generates real Groth16 proof fixtures for the forge tests:
//   contracts/test/fixtures/pool_proof_transfer.json
//   contracts/test/fixtures/pool_proof_withdrawal.json
//   contracts/test/fixtures/pool_proof_withdrawal_gated.json
// Each holds { proof: 0x..256 bytes, publicInputs: [24 hex strings] } and is
// locally verified before writing.
//
// Run after build_pool.sh + gen_vectors.ts:  node scripts/gen_pool_fixtures.js

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import * as snarkjs from "snarkjs";
import { VECTORS, dec, proofToBytes, witnessFor } from "./lib/vector_witness.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ERC = path.resolve(HERE, "..");
const WASM = path.join(ERC, "build/pool/pool_js/pool.wasm");
const ZKEY = path.join(ERC, "build/pool/pool_final.zkey");
const VKEY = JSON.parse(fs.readFileSync(path.join(ERC, "build/pool/pool_vkey.json"), "utf8"));
const OUT = path.join(ERC, "contracts/test/fixtures");

fs.mkdirSync(OUT, { recursive: true });

async function makeFixture(name, scenario, overrides = {}) {
  const input = witnessFor(scenario, overrides);
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
  const ok = await snarkjs.groth16.verify(VKEY, publicSignals, proof);
  if (!ok) throw new Error(`${name}: local verify failed`);
  const fixture = {
    scenario,
    proof: proofToBytes(proof),
    publicInputs: publicSignals.map((v) => "0x" + BigInt(v).toString(16)),
  };
  fs.writeFileSync(path.join(OUT, `${name}.json`), JSON.stringify(fixture, null, 2) + "\n");
  console.log(`wrote ${name}.json`);
}

await makeFixture("pool_proof_transfer", "transfer");
await makeFixture("pool_proof_withdrawal", "withdrawal");
await makeFixture("pool_proof_withdrawal_gated", "withdrawal", {
  policyOperationDataHash: dec(VECTORS.scenarios.withdrawal.transactOperationDataHash),
});
process.exit(0);
