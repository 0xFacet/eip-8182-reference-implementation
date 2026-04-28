// Convert between snarkjs proof JSON and the canonical 256-byte EIP-8182
// proof byte form (Section 5.5):
//   A (G1, 64 B)               : x (32) || y (32)
//   B (G2, 128 B)              : x.c1 (32) || x.c0 (32) || y.c1 (32) || y.c0 (32)
//   C (G1, 64 B)               : x (32) || y (32)
//
// The verification key uses the same G1/G2 byte layout (Section 5.5 +
// PoolGroth16Verifier.sol). G2 byte order matches EIP-197: imaginary part
// first, then real part.

function fpBytes(s) {
  const b = Buffer.alloc(32);
  let x = BigInt(s);
  if (x < 0n) throw new Error("negative");
  for (let i = 31; i >= 0; i--) {
    b[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  if (x !== 0n) throw new Error("scalar > 256 bits");
  return b;
}

function g1Bytes(p) {
  if (BigInt(p[2]) !== 1n) throw new Error("g1 z != 1");
  return Buffer.concat([fpBytes(p[0]), fpBytes(p[1])]);
}

function g2BytesEvm(p) {
  if (BigInt(p[2][0]) !== 1n || BigInt(p[2][1]) !== 0n) {
    throw new Error("g2 z != (1,0)");
  }
  return Buffer.concat([
    fpBytes(p[0][1]),
    fpBytes(p[0][0]),
    fpBytes(p[1][1]),
    fpBytes(p[1][0]),
  ]);
}

function snarkjsProofToBytes(proof) {
  const A = g1Bytes(proof.pi_a);
  const B = g2BytesEvm(proof.pi_b);
  const C = g1Bytes(proof.pi_c);
  return Buffer.concat([A, B, C]);
}

function bytesToSnarkjsProof(buf) {
  if (buf.length !== 256) throw new Error("proof bytes != 256");
  const fp = (off) => "0x" + buf.subarray(off, off + 32).toString("hex");
  return {
    pi_a: [BigInt(fp(0)).toString(), BigInt(fp(32)).toString(), "1"],
    pi_b: [
      [BigInt(fp(96)).toString(), BigInt(fp(64)).toString()],
      [BigInt(fp(160)).toString(), BigInt(fp(128)).toString()],
      ["1", "0"],
    ],
    pi_c: [BigInt(fp(192)).toString(), BigInt(fp(224)).toString(), "1"],
    protocol: "groth16",
    curve: "bn128",
  };
}

function vkJsonToBytes(vk) {
  if (vk.protocol !== "groth16" || vk.curve !== "bn128") {
    throw new Error("not groth16/bn128");
  }
  const parts = [
    g1Bytes(vk.vk_alpha_1),
    g2BytesEvm(vk.vk_beta_2),
    g2BytesEvm(vk.vk_gamma_2),
    g2BytesEvm(vk.vk_delta_2),
    ...vk.IC.map(g1Bytes),
  ];
  const out = Buffer.concat(parts);
  const expected = 64 + 3 * 128 + (vk.nPublic + 1) * 64;
  if (out.length !== expected) {
    throw new Error(`vk length ${out.length} != ${expected}`);
  }
  return out;
}

module.exports = {
  snarkjsProofToBytes,
  bytesToSnarkjsProof,
  vkJsonToBytes,
};
