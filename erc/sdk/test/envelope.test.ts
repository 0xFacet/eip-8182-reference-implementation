import { describe, expect, it, beforeAll } from "vitest";
import { readFileSync } from "node:fs";
import { encodeAbiParameters } from "viem";
import { hexToBytes } from "../src/bytes.ts";
import {
  encryptOutputNoteData,
  generateReceiveKeyPair,
  tryDecryptOutputNoteData,
} from "../src/envelope.ts";
import { encodeNotePayload } from "../src/payload.ts";
import { outputNoteDataHash } from "../src/derivations.ts";
import { SUITE_ID } from "../src/generated/constants.ts";

const unhex = (s: string) => hexToBytes(s, "hex");
const toHex = (b: Uint8Array) => `0x${Buffer.from(b).toString("hex")}` as `0x${string}`;

const FIXED_NONCE = new Uint8Array(12).fill(0x07);
const FIXED_KEM_MSG = new Uint8Array(32).fill(0x09);

const samplePayload = () =>
  encodeNotePayload({
    kind: 1,
    chainId: 11155111,
    poolAddress: "0x1111111111111111111111111111111111111111",
    tokenAddress: "0x0000000000000000000000000000000000000000",
    amount: 42n,
    ownerNullifierKeyHash: 12345n,
    noteSecret: 678n,
    noteBodyCommitment: 910n,
    outputIndex: 0,
    memo: new Uint8Array(0),
  });

// Re-encode a valid envelope with an arbitrary kem/nonce/ct to build adversarial mutants.
function reencodeEnvelope(
  version: bigint,
  suiteId: `0x${string}`,
  kem: Uint8Array,
  nonce: Uint8Array,
  ct: Uint8Array,
): Uint8Array {
  return hexToBytes(
    encodeAbiParameters(
      [
        { type: "uint256" },
        { type: "bytes32" },
        { type: "bytes" },
        { type: "bytes12" },
        { type: "bytes" },
      ],
      [version, suiteId, toHex(kem), toHex(nonce), toHex(ct)],
    ),
    "env",
  );
}

describe("envelope round-trip", () => {
  it("encrypts and decrypts back to the payload", async () => {
    const kp = generateReceiveKeyPair(new Uint8Array(64).fill(1));
    const payload = samplePayload();
    const env = await encryptOutputNoteData(kp.publicKey, payload, { nonce: FIXED_NONCE, kemMessage: FIXED_KEM_MSG });
    const pt = await tryDecryptOutputNoteData(kp.secretKey, env);
    expect(pt).not.toBeNull();
    expect(Buffer.from(pt!).equals(Buffer.from(payload))).toBe(true);
  });

  it("is deterministic given fixed nonce and kem message", async () => {
    const kp = generateReceiveKeyPair(new Uint8Array(64).fill(1));
    const payload = samplePayload();
    const a = await encryptOutputNoteData(kp.publicKey, payload, { nonce: FIXED_NONCE, kemMessage: FIXED_KEM_MSG });
    const b = await encryptOutputNoteData(kp.publicKey, payload, { nonce: FIXED_NONCE, kemMessage: FIXED_KEM_MSG });
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(true);
  });

  it("returns null for a recipient with the wrong secret key", async () => {
    const kp = generateReceiveKeyPair(new Uint8Array(64).fill(1));
    const wrong = generateReceiveKeyPair(new Uint8Array(64).fill(2));
    const env = await encryptOutputNoteData(kp.publicKey, samplePayload(), { nonce: FIXED_NONCE, kemMessage: FIXED_KEM_MSG });
    expect(await tryDecryptOutputNoteData(wrong.secretKey, env)).toBeNull();
  });
});

describe("envelope adversarial corpus (tryDecrypt must return null)", () => {
  let kp: { publicKey: Uint8Array; secretKey: Uint8Array };
  let env: Uint8Array;

  beforeAll(async () => {
    kp = generateReceiveKeyPair(new Uint8Array(64).fill(1));
    env = await encryptOutputNoteData(kp.publicKey, samplePayload(), { nonce: FIXED_NONCE, kemMessage: FIXED_KEM_MSG });
  });

  const nullFor = async (mutate: (b: Uint8Array) => Uint8Array) => {
    expect(await tryDecryptOutputNoteData(kp.secretKey, mutate(env))).toBeNull();
  };

  it("non-canonical kem offset", async () => {
    await nullFor((b) => {
      const out = new Uint8Array(b);
      out[2 * 32 + 31] = 0xc0; // kem offset 0xa0 -> 0xc0
      return out;
    });
  });

  it("trailing byte", async () => {
    await nullFor((b) => {
      const out = new Uint8Array(b.length + 1);
      out.set(b);
      return out;
    });
  });

  it("truncated buffer", async () => {
    await nullFor((b) => b.slice(0, b.length - 32));
  });

  it("nonce padding nonzero", async () => {
    await nullFor((b) => {
      const out = new Uint8Array(b);
      out[3 * 32 + 20] = 0x01;
      return out;
    });
  });

  it("flipped AEAD tag bit", async () => {
    await nullFor((b) => {
      const out = new Uint8Array(b);
      out[out.length - 1] ^= 0x01;
      return out;
    });
  });

  it("flipped kemCiphertext bit (AAD + shared-secret mismatch)", async () => {
    await nullFor((b) => {
      const out = new Uint8Array(b);
      out[192] ^= 0x01; // first byte of kem tail data
      return out;
    });
  });

  it("wrong suiteId", async () => {
    const kem = env.slice(192, 192 + 1088);
    const ct = env.slice(env.length - 16); // any >=16 bytes
    const bad = reencodeEnvelope(1n, `0x${"11".repeat(32)}`, kem, FIXED_NONCE, ct);
    expect(await tryDecryptOutputNoteData(kp.secretKey, bad)).toBeNull();
  });

  it("wrong version (2)", async () => {
    const kem = env.slice(192, 192 + 1088);
    const ct = env.slice(env.length - 16);
    const bad = reencodeEnvelope(2n, SUITE_ID, kem, FIXED_NONCE, ct);
    expect(await tryDecryptOutputNoteData(kp.secretKey, bad)).toBeNull();
  });

  it("kemCiphertext length 1087 and 1089", async () => {
    const ct = env.slice(env.length - 16);
    for (const len of [1087, 1089]) {
      const bad = reencodeEnvelope(1n, SUITE_ID, new Uint8Array(len).fill(3), FIXED_NONCE, ct);
      expect(await tryDecryptOutputNoteData(kp.secretKey, bad)).toBeNull();
    }
  });

  it("ciphertext length 15", async () => {
    const kem = env.slice(192, 192 + 1088);
    const bad = reencodeEnvelope(1n, SUITE_ID, kem, FIXED_NONCE, new Uint8Array(15).fill(3));
    expect(await tryDecryptOutputNoteData(kp.secretKey, bad)).toBeNull();
  });
});

describe("published envelope vectors", () => {
  const vectors = JSON.parse(
    readFileSync(new URL("../../assets/envelope_vectors.json", import.meta.url), "utf8"),
  );

  it("suite matches", () => {
    expect(vectors.suite).toBe("ERCXXXX_MLKEM768_HKDFSHA256_AESGCM256_ABI_V1");
  });

  it("re-encrypts to the pinned envelope bytes and outputNoteDataHash", async () => {
    for (const v of vectors.vectors) {
      const kp = generateReceiveKeyPair(seedFor(v.seed));
      expect(Buffer.from(kp.publicKey).equals(Buffer.from(unhex(v.publicKey)))).toBe(true);
      const env = await encryptOutputNoteData(kp.publicKey, unhex(v.payloadHex), {
        nonce: unhex(v.nonce),
        kemMessage: unhex(v.kemMessage),
      });
      expect(toHex(env)).toBe(v.envelopeHex);
      expect(`0x${outputNoteDataHash(env).toString(16).padStart(64, "0")}`).toBe(v.outputNoteDataHash);
      const pt = await tryDecryptOutputNoteData(unhex(v.secretKey), env);
      expect(pt).not.toBeNull();
      expect(toHex(pt!)).toBe(v.payloadHex);
    }
  });
});

// Mirror the seed-expansion the generator uses so vectors stay reproducible from `seed`.
import { sha256 } from "@noble/hashes/sha2.js";
function seedFor(label: string): Uint8Array {
  const a = sha256(new TextEncoder().encode(`${label}/d`));
  const b = sha256(new TextEncoder().encode(`${label}/z`));
  const out = new Uint8Array(64);
  out.set(a, 0);
  out.set(b, 32);
  return out;
}
