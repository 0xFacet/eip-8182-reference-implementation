// Deterministic envelope test vectors (spec §11 + §12).
//
// Emits assets/envelope_vectors.json with 3 entries built from fixed ML-KEM
// seeds, fixed encapsulation messages, fixed AES-GCM nonces, and fixed note
// payloads. Each entry records the recipient key pair, the plaintext payload,
// the envelope bytes, and outputNoteDataHash (keccak mod p) of the envelope.
//
// ML-KEM-768 keygen is seeded (64-byte seed) and encapsulation is seeded
// (32-byte message), so generation is fully deterministic and vectors do not
// need to be pinned. When the file already exists and --force is NOT passed,
// this script re-verifies decryption round-trips and outputNoteDataHash instead
// of regenerating.
//
// Run: node scripts/gen_envelope_vectors.js [--force]

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { sha256 } from "@noble/hashes/sha2.js";
import {
  encryptOutputNoteData,
  generateReceiveKeyPair,
  tryDecryptOutputNoteData,
} from "../sdk/src/envelope.ts";
import { encodeNotePayload } from "../sdk/src/payload.ts";
import { outputNoteDataHash } from "../sdk/src/derivations.ts";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ERC = path.resolve(HERE, "..");
const OUT = path.join(ERC, "assets", "envelope_vectors.json");

const hex = (b) => "0x" + Buffer.from(b).toString("hex");
const unhex = (s) => new Uint8Array(Buffer.from(s.replace(/^0x/, ""), "hex"));

// A 64-byte ML-KEM keygen seed derived from a short label via SHA-256 expansion.
function seed64(label) {
  const a = sha256(new TextEncoder().encode(`${label}/d`));
  const b = sha256(new TextEncoder().encode(`${label}/z`));
  const out = new Uint8Array(64);
  out.set(a, 0);
  out.set(b, 32);
  return out;
}

function msg32(label) {
  return sha256(new TextEncoder().encode(`${label}/kem-msg`));
}

function nonce12(label) {
  return sha256(new TextEncoder().encode(`${label}/nonce`)).slice(0, 12);
}

const CASES = [
  {
    seed: "ercXXXX-envelope-vector-0",
    payload: {
      kind: 0,
      chainId: 11155111,
      poolAddress: "0x1111111111111111111111111111111111111111",
      tokenAddress: "0x0000000000000000000000000000000000000000",
      amount: 1000000000000000000n,
      ownerNullifierKeyHash: 12345678901234567890n,
      noteSecret: 111n,
      noteBodyCommitment: 222n,
      outputIndex: 0,
      memo: new Uint8Array(0),
    },
  },
  {
    seed: "ercXXXX-envelope-vector-1",
    payload: {
      kind: 1,
      chainId: 1,
      poolAddress: "0x22222222222222222222222222222222222222aa",
      tokenAddress: "0xdac17f958d2ee523a2206206994597c13d831ec7",
      amount: 250000n,
      ownerNullifierKeyHash:
        9000000000000000000000000000000000000000000000000000000000000000000000000n %
        21888242871839275222246405745257275088548364400416034343698204186575808495617n,
      noteSecret: 5n,
      noteBodyCommitment: 7n,
      outputIndex: 1,
      memo: new TextEncoder().encode("gm"),
    },
  },
  {
    seed: "ercXXXX-envelope-vector-2",
    payload: {
      kind: 1,
      chainId: 8453,
      poolAddress: "0x33333333333333333333333333333333333333cc",
      tokenAddress: "0x4200000000000000000000000000000000000006",
      amount: (1n << 248n) - 1n,
      ownerNullifierKeyHash:
        21888242871839275222246405745257275088548364400416034343698204186575808495616n,
      noteSecret: 21888242871839275222246405745257275088548364400416034343698204186575808495610n,
      noteBodyCommitment: 999n,
      outputIndex: 2,
      memo: new TextEncoder().encode("the quick brown fox jumps over the lazy dog"),
    },
  },
];

async function buildEntry(spec) {
  const seed = seed64(spec.seed);
  const kem = msg32(spec.seed);
  const nonce = nonce12(spec.seed);
  const kp = generateReceiveKeyPair(seed);
  const payloadBytes = encodeNotePayload(spec.payload);
  const envelope = await encryptOutputNoteData(kp.publicKey, payloadBytes, { nonce, kemMessage: kem });
  const roundTrip = await tryDecryptOutputNoteData(kp.secretKey, envelope);
  if (!roundTrip || !Buffer.from(roundTrip).equals(Buffer.from(payloadBytes))) {
    throw new Error(`vector ${spec.seed}: decryption round-trip failed`);
  }
  return {
    seed: spec.seed,
    publicKey: hex(kp.publicKey),
    secretKey: hex(kp.secretKey),
    nonce: hex(nonce),
    kemMessage: hex(kem),
    payloadHex: hex(payloadBytes),
    envelopeHex: hex(envelope),
    outputNoteDataHash: "0x" + outputNoteDataHash(envelope).toString(16).padStart(64, "0"),
  };
}

async function generate() {
  const vectors = [];
  for (const spec of CASES) vectors.push(await buildEntry(spec));
  return { suite: "ERCXXXX_MLKEM768_HKDFSHA256_AESGCM256_ABI_V1", vectors };
}

async function verify(existing) {
  for (const entry of existing.vectors) {
    const sk = unhex(entry.secretKey);
    const envelope = unhex(entry.envelopeHex);
    const pt = await tryDecryptOutputNoteData(sk, envelope);
    if (!pt || !Buffer.from(pt).equals(Buffer.from(unhex(entry.payloadHex)))) {
      throw new Error(`vector ${entry.seed}: round-trip verification failed`);
    }
    const expectedHash = "0x" + outputNoteDataHash(envelope).toString(16).padStart(64, "0");
    if (expectedHash !== entry.outputNoteDataHash) {
      throw new Error(`vector ${entry.seed}: outputNoteDataHash mismatch`);
    }
  }
}

async function main() {
  const force = process.argv.includes("--force");
  if (!force && fs.existsSync(OUT)) {
    const existing = JSON.parse(fs.readFileSync(OUT, "utf8"));
    await verify(existing);
    // Regenerate deterministically and confirm the file is byte-stable.
    const regenerated = await generate();
    if (JSON.stringify(regenerated) !== JSON.stringify(existing)) {
      throw new Error("envelope_vectors.json is stale; re-run with --force to update");
    }
    console.log(`verified ${existing.vectors.length} envelope vectors (unchanged)`);
    return;
  }
  const data = await generate();
  fs.mkdirSync(path.dirname(OUT), { recursive: true });
  fs.writeFileSync(OUT, `${JSON.stringify(data, null, 2)}\n`);
  console.log(`wrote ${data.vectors.length} envelope vectors to ${path.relative(ERC, OUT)}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
