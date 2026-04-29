#!/usr/bin/env node
// Cross-checks the vendored Aztec Poseidon2 in circuits-noir/vendor/poseidon
// against the project's existing scripts/witness/poseidon2.js (which the
// pool circuit's witness gen also uses).
//
// For each test vector:
//   - Compute the expected output via scripts/witness/poseidon2.js.
//   - Write a Prover.toml with that vector + expected output as a public input.
//   - Execute the xcheck Noir program; if its in-circuit Poseidon2::hash
//     produces a different value, the assert in main.nr trips and witness
//     execution fails -- which we treat as MISMATCH.

const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");

const ROOT = path.resolve(__dirname, "..", "..");
const XCHECK_DIR = path.join(ROOT, "scripts", "noir", "poseidon2_xcheck");
const PROVER_TOML = path.join(XCHECK_DIR, "Prover.toml");

const { poseidon } = require(path.join(ROOT, "scripts", "witness", "poseidon2.js"));

const FR = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

function vectors() {
  return [
    { label: "len=1, [0]", inputs: [0n] },
    { label: "len=1, [1]", inputs: [1n] },
    { label: "len=3, [1,2,3]", inputs: [1n, 2n, 3n] },
    { label: "len=4, [1,2,3,4]", inputs: [1n, 2n, 3n, 4n] },
    { label: "len=5, [1,2,3,4,5]", inputs: [1n, 2n, 3n, 4n, 5n] },
    { label: "len=4, [Fr-1]*4", inputs: [FR - 1n, FR - 1n, FR - 1n, FR - 1n] },
    { label: "len=16, [1..16]", inputs: Array.from({ length: 16 }, (_, i) => BigInt(i + 1)) },
  ];
}

function fieldToString(x) {
  return x.toString();
}

function writeProverToml(inputs, in_len, expected) {
  // The Noir circuit takes inputs: [Field; 16] -- pad with zeros.
  const padded = inputs.concat(Array(16 - inputs.length).fill(0n));
  const lines = [];
  lines.push("inputs = [");
  for (const v of padded) lines.push(`    "${fieldToString(v)}",`);
  lines.push("]");
  lines.push(`in_len = "${in_len}"`);
  lines.push(`expected = "${fieldToString(expected)}"`);
  fs.writeFileSync(PROVER_TOML, lines.join("\n") + "\n");
}

function run(cmd, args, opts = {}) {
  const r = spawnSync(cmd, args, { stdio: "pipe", encoding: "utf8", ...opts });
  return r;
}

let allOk = true;
for (const v of vectors()) {
  const expected = poseidon(...v.inputs);
  writeProverToml(v.inputs, v.inputs.length, expected);

  const r = run("nargo", ["execute", "xcheck"], { cwd: XCHECK_DIR });
  if (r.status === 0) {
    process.stdout.write(`MATCH   ${v.label}\n`);
  } else {
    allOk = false;
    process.stdout.write(`MISMATCH ${v.label}\n`);
    process.stdout.write(`  expected (project poseidon2): ${fieldToString(expected)}\n`);
    process.stdout.write(`  nargo stderr: ${r.stderr.split("\n").slice(0, 4).join("\n")}\n`);
  }
}

if (!allOk) {
  console.error("\nFAIL: vendored Aztec Poseidon2 disagrees with project poseidon2 on at least one vector.");
  process.exit(1);
}
console.log("\nALL MATCH: vendored Aztec Poseidon2 agrees with project poseidon2 on every vector.");
