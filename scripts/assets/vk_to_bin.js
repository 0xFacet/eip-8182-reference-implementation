#!/usr/bin/env node
// Convert snarkjs Groth16 verification key (pool_vkey.json) to canonical
// EIP-196/197 byte layout used by the EIP-8182 PROOF_VERIFY_PRECOMPILE.
//
// Layout (1856 bytes for the 21-public-input pool circuit):
//   alpha (G1, 64 B)               : x (32) || y (32)
//   beta  (G2, 128 B)              : x.c1 (32) || x.c0 (32) || y.c1 (32) || y.c0 (32)
//   gamma (G2, 128 B)              : same
//   delta (G2, 128 B)              : same
//   IC[0..nPublic] (G1, 64 B each) : nPublic+1 = 22 G1 points
//
// G2 byte order matches EIP-197: imaginary part first, then real part.
// snarkjs stores G2 coordinates as [c0, c1]; this script swaps to [c1, c0].

const fs = require("fs");
const path = require("path");

if (process.argv.length < 4) {
  console.error("usage: vk_to_bin.js <pool_vkey.json> <pool_vk.bin>");
  process.exit(1);
}
const [, , vkPath, outPath] = process.argv;
const vk = JSON.parse(fs.readFileSync(vkPath, "utf8"));

if (vk.protocol !== "groth16") throw new Error("not a groth16 vk");
if (vk.curve !== "bn128") throw new Error("not bn128");
const nPublic = vk.nPublic;
if (!Array.isArray(vk.IC) || vk.IC.length !== nPublic + 1) {
  throw new Error(`IC length ${vk.IC.length} != nPublic+1 ${nPublic + 1}`);
}

function fpBytes(s) {
  const b = Buffer.alloc(32);
  let x = BigInt(s);
  for (let i = 31; i >= 0; i--) {
    b[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  if (x !== 0n) throw new Error("scalar > 256 bits");
  return b;
}

function g1Bytes(p) {
  if (p.length !== 3) throw new Error("g1 must have 3 coords");
  if (BigInt(p[2]) !== 1n) throw new Error("g1 z != 1 (not affine)");
  return Buffer.concat([fpBytes(p[0]), fpBytes(p[1])]);
}

function g2Bytes(p) {
  if (p.length !== 3) throw new Error("g2 must have 3 coords");
  const [x, y, z] = p;
  if (BigInt(z[0]) !== 1n || BigInt(z[1]) !== 0n) {
    throw new Error("g2 z != (1,0) (not affine)");
  }
  return Buffer.concat([
    fpBytes(x[1]),
    fpBytes(x[0]),
    fpBytes(y[1]),
    fpBytes(y[0]),
  ]);
}

const parts = [
  g1Bytes(vk.vk_alpha_1),
  g2Bytes(vk.vk_beta_2),
  g2Bytes(vk.vk_gamma_2),
  g2Bytes(vk.vk_delta_2),
  ...vk.IC.map(g1Bytes),
];
const out = Buffer.concat(parts);
const expected = 64 + 3 * 128 + (nPublic + 1) * 64;
if (out.length !== expected) {
  throw new Error(`bad length: got ${out.length}, expected ${expected}`);
}

fs.mkdirSync(path.dirname(outPath), { recursive: true });
fs.writeFileSync(outPath, out);
console.log(`wrote ${outPath} (${out.length} bytes; nPublic=${nPublic})`);
