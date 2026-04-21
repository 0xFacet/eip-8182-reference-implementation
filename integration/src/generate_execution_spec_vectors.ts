import { createCipheriv, createDecipheriv } from "crypto";
import { mkdirSync, readFileSync, writeFileSync } from "fs";
import { dirname, resolve } from "path";
import { fileURLToPath } from "url";

import { ethers } from "ethers";
import { extract, expand } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { keccak_256 } from "@noble/hashes/sha3";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";

import {
  DELIVERY_SCHEME_ML_KEM_768,
  FIELD_MODULUS,
  ORIGIN_TAG_DOMAIN,
  bytesToHex,
  hexToBytes,
} from "../../src/lib/protocol.ts";
import { createPoseidonHelpers } from "./tx_proof_shared.ts";
import { initPoseidon2, poseidon2Hash } from "./poseidon2.ts";
import {
  computeDepositOriginTag,
  computeFullNoteCommitment,
  computeOwnerNullifierKeyHash,
} from "./eip8182.ts";

interface VerifierFixture {
  proof: string;
  publicInputs: string[];
  outputNoteData: [string, string, string];
}

// Scheme 1A plaintext fields (EIP Section 15.2). ownerAddress is NOT part of
// the plaintext — the recipient derives it from on-chain coordination.
interface NoteFields {
  amount: bigint;
  noteSecret: bigint;
  ownerNullifierKeyHash: bigint;
  tokenAddress: bigint;
  originTag: bigint;
}

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const repoRoot = resolve(__dirname, "..", "..");
const shieldedPoolPath = resolve(repoRoot, "contracts", "src", "ShieldedPool.sol");
const poseidon2YulPath = resolve(
  repoRoot,
  "contracts",
  "lib",
  "poseidon2-evm",
  "src",
  "LibPoseidon2Yul.sol",
);

const DELIVERY_KEY_LABEL = "EIP-8182-delivery-scheme-1 key";
const DELIVERY_NONCE_LABEL = "EIP-8182-delivery-scheme-1 nonce";
const PRECOMPILE_SUCCESS_RETURN_DATA = ethers.utils.defaultAbiCoder.encode(["uint256"], [1]);
const PRECOMPILE_FAILURE_RETURN_DATA = "0x";
const HAPPY_PATH_NOTE =
  "Verifier-precompile acceptance vector only. This is not a full transact state test.";
const INVALID_PROOF_NOTE =
  "Verifier-precompile reject vector. The proof bytes are well-formed but invalid.";
const MALFORMED_INPUT_NOTE =
  "Verifier-precompile reject vector. The calldata is malformed and must return empty bytes.";
const NON_CANONICAL_PRECOMPILE_NOTE =
  "Verifier-precompile reject vector. The public input is non-canonical and must return empty bytes.";
const DELIVERY_KEYGEN_SEED_HEX = "0x" + "11".repeat(64);
const DELIVERY_ENCAPSULATION_RANDOMNESS_HEX = "0x" + "22".repeat(32);

async function main() {
  const [outputDirArg, verifierFixturePathArg, bbVersion] = process.argv.slice(2);
  if (!outputDirArg || !verifierFixturePathArg || !bbVersion || process.argv.length !== 5) {
    throw new Error(
      "usage: tsx integration/src/generate_execution_spec_vectors.ts <output-dir> <verifier-fixture-path> <bb-version>",
    );
  }

  const outputDir = resolve(outputDirArg);
  const verifierFixturePath = resolve(verifierFixturePathArg);
  mkdirSync(outputDir, { recursive: true });

  const fixture = JSON.parse(readFileSync(verifierFixturePath, "utf8")) as VerifierFixture;
  const poolPublicInputsOrder = parsePoolPublicInputsOrder(readFileSync(shieldedPoolPath, "utf8"));
  const helpers = await createPoseidonHelpers();
  await initPoseidon2();
  const proofLengthBytes = hexByteLength(fixture.proof);

  const happyPath = buildPrecompileVector(
    fixture.proof,
    objectFromPublicInputs(poolPublicInputsOrder, fixture.publicInputs),
    proofLengthBytes,
    bbVersion,
    HAPPY_PATH_NOTE,
    PRECOMPILE_SUCCESS_RETURN_DATA,
  );
  const invalidProof = buildPrecompileVector(
    mutateProof(fixture.proof),
    happyPath.publicInputs,
    proofLengthBytes,
    bbVersion,
    INVALID_PROOF_NOTE,
    PRECOMPILE_FAILURE_RETURN_DATA,
  );
  const malformedInput = {
    bbVersion,
    expectedReturnData: PRECOMPILE_FAILURE_RETURN_DATA,
    note: MALFORMED_INPUT_NOTE,
    precompileInput: "0x1234",
  };
  const nonCanonicalPrecompile = buildNonCanonicalPrecompileVector(
    happyPath,
    bbVersion,
  );
  const poseidonParameters = buildPoseidonParameters();
  const poseidonVectors = buildPoseidonVectors(helpers);
  const deliveryVectors = buildDeliveryVectors(helpers);

  writeJson(outputDir, "outer_precompile_happy_path.json", happyPath);
  writeJson(outputDir, "outer_precompile_invalid_proof.json", invalidProof);
  writeJson(outputDir, "outer_precompile_malformed_input.json", malformedInput);
  writeJson(outputDir, "outer_precompile_noncanonical_field.json", nonCanonicalPrecompile);
  writeJson(outputDir, "poseidon2_bn254_t4_rf8_rp56.json", poseidonParameters);
  writeJson(outputDir, "poseidon2_vectors.json", poseidonVectors);
  writeJson(outputDir, "delivery_scheme1_vectors.json", deliveryVectors);
}

function buildPrecompileVector(
  proof: string,
  publicInputs: Record<string, string>,
  proofLengthBytes: number,
  bbVersion: string,
  note: string,
  expectedReturnData: string,
) {
  const order = Object.keys(publicInputs);
  return {
    bbVersion,
    expectedReturnData,
    note,
    precompileInput: encodePrecompileInput(order, proof, publicInputs),
    proof,
    proofLengthBytes,
    publicInputs,
  };
}

function buildNonCanonicalPrecompileVector(
  happyPath: ReturnType<typeof buildPrecompileVector>,
  bbVersion: string,
) {
  const field = "noteCommitmentRoot";
  const canonicalValue = BigInt(happyPath.publicInputs[field]);
  const mutatedPublicInputs = {
    ...happyPath.publicInputs,
    [field]: toHex32(canonicalValue + FIELD_MODULUS),
  };

  return {
    bbVersion,
    expectedReturnData: PRECOMPILE_FAILURE_RETURN_DATA,
    field,
    fieldModulus: toHex32(FIELD_MODULUS),
    note: NON_CANONICAL_PRECOMPILE_NOTE,
    precompileInput: encodePrecompileInput(Object.keys(mutatedPublicInputs), happyPath.proof, mutatedPublicInputs),
    proof: happyPath.proof,
    proofLengthBytes: happyPath.proofLengthBytes,
    publicInputs: mutatedPublicInputs,
  };
}

function extractPoseidon2RoundConstants(): string[] {
  const yul = readFileSync(poseidon2YulPath, "utf8");
  const re = /state\d := add\(state\d, (0x[0-9a-fA-F]+)\)/g;
  const out: string[] = [];
  let m: RegExpExecArray | null;
  while ((m = re.exec(yul)) !== null) {
    out.push(normalizeHex(m[1]));
  }
  if (out.length !== 88) {
    throw new Error(
      `expected 88 Poseidon2 round constants (4*4 + 56 + 4*4), got ${out.length}`,
    );
  }
  return out;
}

// Canonical Aztec Poseidon2 t=4 internal-matrix diagonal multipliers. These are the
// `mu_i` values applied in every partial round as `state[i] <- sum + mu_i * state[i]`.
// Committed here as the source of truth for asset generation; verified against the
// vendored `LibPoseidon2Yul.sol` at call time so a submodule upgrade that quietly
// changes the diagonal fails loudly during asset regen rather than silently corrupting
// the asset bundle.
const POSEIDON2_INTERNAL_DIAGONAL = [
  "0x10dc6e9c006ea38b04b1e03b4bd9490c0d03f98929ca1d7fb56821fd19d3b6e7",
  "0x0c28145b6a44df3e0149b3d0a30b3bb599df9756d4dd9b84a86b38cfb45a740b",
  "0x00544b8338791518b2c7645a50392798b21f75bb60e3596170067d00141cac15",
  "0x222c01175718386f2e2e82eb122789e352e105a3b8fa852613bc534433ee428b",
];

function extractPoseidon2InternalDiagonal(): string[] {
  // Assert the committed canonical diagonal matches the vendored LibPoseidon2Yul.sol.
  // Scan is scoped to literal `mulmod(stateN, <hex>, PRIME)` forms; if an upstream
  // refactor introduces additional multiplier patterns, this throws with a clear error
  // and the committed constants can be re-verified by hand before proceeding.
  const yul = readFileSync(poseidon2YulPath, "utf8");
  for (let lane = 0; lane < 4; lane += 1) {
    const re = new RegExp(
      `mulmod\\(state${lane},\\s*(0x[0-9a-fA-F]+),\\s*PRIME\\)`,
      "g",
    );
    const matches = new Set<string>();
    let match: RegExpExecArray | null;
    while ((match = re.exec(yul)) !== null) matches.add(match[1]);
    if (matches.size !== 1) {
      throw new Error(
        `LibPoseidon2Yul state${lane} multiplier: expected exactly one constant across rounds, found ${matches.size}. ` +
          `The vendored library may have been restructured; re-verify POSEIDON2_INTERNAL_DIAGONAL against the current source.`,
      );
    }
    const found = normalizeHex([...matches][0]);
    const expected = normalizeHex(POSEIDON2_INTERNAL_DIAGONAL[lane]);
    if (found !== expected) {
      throw new Error(
        `LibPoseidon2Yul state${lane} multiplier mismatch: library has ${found}, generator expects ${expected}. ` +
          `Poseidon2 internal diagonal changed — update POSEIDON2_INTERNAL_DIAGONAL after manual verification.`,
      );
    }
  }
  return POSEIDON2_INTERNAL_DIAGONAL.map(normalizeHex);
}

function buildPoseidonParameters() {
  // Poseidon2 over BN254 scalar field, t=4, Rf=8 (4 external rounds before and 4 after
  // the partial-round block), Rp=56, S-box x^5. External matrix and internal diagonal
  // follow Aztec's canonical Poseidon2 t=4 parameters.
  //
  // Round-constant layout (88 field elements total):
  //   - indices [0,  15]: 4 external rounds × 4 constants = 16 (first half)
  //   - indices [16, 71]: 56 partial rounds × 1 constant   = 56
  //   - indices [72, 87]: 4 external rounds × 4 constants = 16 (second half)
  //
  // External linear layer: 4×4 MDS matrix (circulant on [5,7,1,3]) that pre-multiplies
  // the initial state and is applied after the S-box in every external round.
  //
  // Internal linear layer: each partial round computes
  //   sum = state[0] + state[1] + state[2] + state[3]
  //   state[i] <- sum + mu[i] * state[i]   for i in {0,1,2,3}
  // where `internalDiagonal[i] = mu[i]` is the canonical Aztec Poseidon2 t=4
  // internal-matrix multiplier applied identically in every partial round.
  // Values are extracted directly from LibPoseidon2Yul so the asset tracks the
  // library rather than a hand-copied constant.
  const roundConstants = extractPoseidon2RoundConstants();
  const internalDiagonal = extractPoseidon2InternalDiagonal();

  return {
    curve: "bn254",
    fieldModulus: toHex32(FIELD_MODULUS),
    stateWidth: 4,
    rate: 3,
    capacity: 1,
    sbox: "x^5",
    fullRounds: 8,
    partialRounds: 56,
    externalMatrix: [
      ["0x05", "0x07", "0x01", "0x03"],
      ["0x04", "0x06", "0x01", "0x01"],
      ["0x01", "0x03", "0x05", "0x07"],
      ["0x01", "0x01", "0x04", "0x06"],
    ],
    internalDiagonal,
    roundConstants,
  };
}

function buildPoseidonVectors(_helpers: Awaited<ReturnType<typeof createPoseidonHelpers>>) {
  // Arities chosen to exercise every branch of the sponge algorithm:
  //   N=0           — finalize-only path, no absorb
  //   N=1           — sub-rate tail (pad 2 zeros)
  //   N=2           — Merkle-internal form `poseidon(a, b)` (pad 1 zero)
  //   N=3           — full single chunk, no padding
  //   N=4, 5        — one full chunk + partial tail chunk
  //   N=6           — two full chunks, no padding
  //   N=17          — transaction-intent-digest arity (largest fixed-arity spec hash)
  //   N=116         — innerVkHash arity (AUTH_VK_DOMAIN + 115 VK field elements)
  const inputsByArity: bigint[][] = [
    [],
    [1n],
    [1n, 2n],
    [1n, 2n, 3n],
    [1n, 2n, 3n, 4n],
    [1n, 2n, 3n, 4n, 5n],
    [5n, 8n, 13n, 21n, 34n, 55n],
    Array.from({ length: 17 }, (_, i) => BigInt(i + 1)),
    Array.from({ length: 116 }, (_, i) => BigInt(i + 1)),
  ];

  const poseidonVectors = inputsByArity.map((inputs) => ({
    inputs: inputs.map(toHex32),
    output: toHex32(poseidon2Hash(inputs)),
  }));

  return {
    fieldModulus: toHex32(FIELD_MODULUS),
    poseidonVectors,
  };
}

function buildDeliveryVectors(helpers: Awaited<ReturnType<typeof createPoseidonHelpers>>) {
  return {
    aead: "aes-256-gcm",
    kemSpecification: "FIPS-203-final",
    hkdfHash: "sha256",
    keyLabel: DELIVERY_KEY_LABEL,
    keyLengthBytes: 1184,
    kemCiphertextLengthBytes: 1088,
    nonceLabel: DELIVERY_NONCE_LABEL,
    schemeId: Number(DELIVERY_SCHEME_ML_KEM_768),
    subtypes: {
      "1A": buildScheme1ATransactVector(helpers),
      "1B": buildScheme1BDepositVector(helpers),
    },
  };
}

function buildScheme1ATransactVector(
  helpers: Awaited<ReturnType<typeof createPoseidonHelpers>>,
) {
  const note: NoteFields = {
    amount: 123_456_789n,
    noteSecret: 0x123456789abcdef123456789abcdef123456789abcdef123456789abcdefn,
    ownerNullifierKeyHash: computeOwnerNullifierKeyHash(helpers.pHash, 0x7777n),
    tokenAddress: 0x00000000000000000000000000000000000000bbn,
    originTag: helpers.pHash([ORIGIN_TAG_DOMAIN, 31337n, 1n]),
  };
  const leafIndex = 7n;
  const plaintext = encodeScheme1ANote(note);
  const noteCommitment = computeFullNoteCommitment(helpers.pHash, {
    ownerNullifierKeyHash: note.ownerNullifierKeyHash,
    noteSecret: note.noteSecret,
    amount: note.amount,
    tokenAddress: note.tokenAddress,
    originTag: note.originTag,
    leafIndex,
  });

  // Scheme 1A wire format: enc(1088) || ciphertext(160) || tag(16) = 1264 bytes.
  const sealed = sealDeliveryPayload(plaintext, 1264);
  const recoveredPlaintext = openDeliveryPayload(sealed, plaintext.length);
  const recoveredNote = decodeScheme1ANote(recoveredPlaintext);
  const recoveredCommitment = computeFullNoteCommitment(helpers.pHash, {
    ownerNullifierKeyHash: recoveredNote.ownerNullifierKeyHash,
    noteSecret: recoveredNote.noteSecret,
    amount: recoveredNote.amount,
    tokenAddress: recoveredNote.tokenAddress,
    originTag: recoveredNote.originTag,
    leafIndex,
  });
  if (recoveredCommitment !== noteCommitment) {
    throw new Error("scheme 1A delivery vector commitment mismatch");
  }

  return {
    plaintextLengthBytes: 160,
    ciphertextLengthBytes: 1264,
    vectors: [
      {
        aeadKey: bytesToHex(sealed.key),
        ciphertext: bytesToHex(sealed.ciphertext),
        encapsulationCiphertext: bytesToHex(sealed.cipherText),
        encapsulationRandomness: DELIVERY_ENCAPSULATION_RANDOMNESS_HEX,
        keygenSeed: DELIVERY_KEYGEN_SEED_HEX,
        leafIndex: toHex32(leafIndex),
        nonce: bytesToHex(sealed.nonce),
        note: formatNote(note),
        noteCommitment: toHex32(noteCommitment),
        outputNoteData: bytesToHex(sealed.outputNoteData),
        outputNoteDataHash: toHex32(noteDataHash(sealed.outputNoteData)),
        plaintext: bytesToHex(plaintext),
        recipientPublicKey: bytesToHex(sealed.publicKey),
        recipientSecretKey: bytesToHex(sealed.secretKey),
        recoveredNote: formatNote(recoveredNote),
        sharedSecret: bytesToHex(sealed.sharedSecret),
        tag: bytesToHex(sealed.tag),
      },
    ],
  };
}

function buildScheme1BDepositVector(
  helpers: Awaited<ReturnType<typeof createPoseidonHelpers>>,
) {
  // Tagged deposit: originTag is derived by the contract from the assigned
  // leafIndex and the deposit call context (chainId, depositor, tokenAddress,
  // amount). The recipient reconstructs the same tag from the emitted event.
  const chainId = 31337n;
  const depositor = 0x00000000000000000000000000000000000000abn;
  const tokenAddress = 0x00000000000000000000000000000000000000bbn;
  const amount = 987_654_321n;
  const leafIndex = 3n;
  const originTag = computeDepositOriginTag(helpers.pHash, {
    chainId,
    depositor,
    tokenAddress,
    amount,
    leafIndex,
  });
  const ownerNullifierKeyHash = computeOwnerNullifierKeyHash(helpers.pHash, 0x9191n);
  const noteSecret =
    0xfedcba987654321fedcba987654321fedcba987654321fedcba987654321fedn;
  const plaintext = encodeScheme1BDepositPayload({ ownerNullifierKeyHash, noteSecret });
  const noteCommitment = computeFullNoteCommitment(helpers.pHash, {
    ownerNullifierKeyHash,
    noteSecret,
    amount,
    tokenAddress,
    originTag,
    leafIndex,
  });

  // Scheme 1B wire format: enc(1088) || ciphertext(64) || tag(16) = 1168 bytes.
  const sealed = sealDeliveryPayload(plaintext, 1168);
  const recoveredPlaintext = openDeliveryPayload(sealed, plaintext.length);
  const recoveredPayload = decodeScheme1BDepositPayload(recoveredPlaintext);
  const recoveredCommitment = computeFullNoteCommitment(helpers.pHash, {
    ownerNullifierKeyHash: recoveredPayload.ownerNullifierKeyHash,
    noteSecret: recoveredPayload.noteSecret,
    amount,
    tokenAddress,
    originTag,
    leafIndex,
  });
  if (recoveredCommitment !== noteCommitment) {
    throw new Error("scheme 1B delivery vector commitment mismatch");
  }

  return {
    plaintextLengthBytes: 64,
    ciphertextLengthBytes: 1168,
    vectors: [
      {
        aeadKey: bytesToHex(sealed.key),
        amount: toHex32(amount),
        chainId: toHex32(chainId),
        ciphertext: bytesToHex(sealed.ciphertext),
        depositor: toHex32(depositor),
        encapsulationCiphertext: bytesToHex(sealed.cipherText),
        encapsulationRandomness: DELIVERY_ENCAPSULATION_RANDOMNESS_HEX,
        keygenSeed: DELIVERY_KEYGEN_SEED_HEX,
        leafIndex: toHex32(leafIndex),
        nonce: bytesToHex(sealed.nonce),
        noteCommitment: toHex32(noteCommitment),
        originTag: toHex32(originTag),
        outputNoteData: bytesToHex(sealed.outputNoteData),
        outputNoteDataHash: toHex32(noteDataHash(sealed.outputNoteData)),
        plaintext: bytesToHex(plaintext),
        plaintextOwnerNullifierKeyHash: toHex32(ownerNullifierKeyHash),
        plaintextNoteSecret: toHex32(noteSecret),
        recipientPublicKey: bytesToHex(sealed.publicKey),
        recipientSecretKey: bytesToHex(sealed.secretKey),
        sharedSecret: bytesToHex(sealed.sharedSecret),
        tag: bytesToHex(sealed.tag),
        tokenAddress: toHex32(tokenAddress),
      },
    ],
  };
}

interface SealedDeliveryPayload {
  secretKey: Uint8Array;
  publicKey: Uint8Array;
  sharedSecret: Uint8Array;
  cipherText: Uint8Array;
  key: Uint8Array;
  nonce: Uint8Array;
  ciphertext: Uint8Array;
  tag: Uint8Array;
  outputNoteData: Uint8Array;
}

function sealDeliveryPayload(
  plaintext: Uint8Array,
  wireLength: number,
): SealedDeliveryPayload {
  const keygenSeed = hexToBytes(DELIVERY_KEYGEN_SEED_HEX);
  const encapsulationRandomness = hexToBytes(DELIVERY_ENCAPSULATION_RANDOMNESS_HEX);
  const { secretKey, publicKey } = ml_kem768.keygen(keygenSeed);
  const { sharedSecret, cipherText } = ml_kem768.encapsulate(publicKey, encapsulationRandomness);
  const { key, nonce } = deriveKeyAndNonce(sharedSecret);

  const cipher = createCipheriv("aes-256-gcm", Buffer.from(key), Buffer.from(nonce));
  const ciphertext = new Uint8Array(
    Buffer.concat([cipher.update(Buffer.from(plaintext)), cipher.final()]),
  );
  const tag = new Uint8Array(cipher.getAuthTag());

  const kemLen = cipherText.length;
  if (wireLength !== kemLen + ciphertext.length + tag.length) {
    throw new Error(
      `wire length mismatch: expected ${kemLen + ciphertext.length + tag.length}, got ${wireLength}`,
    );
  }
  const outputNoteData = new Uint8Array(wireLength);
  outputNoteData.set(cipherText, 0);
  outputNoteData.set(ciphertext, kemLen);
  outputNoteData.set(tag, kemLen + ciphertext.length);

  return { secretKey, publicKey, sharedSecret, cipherText, key, nonce, ciphertext, tag, outputNoteData };
}

function openDeliveryPayload(
  sealed: SealedDeliveryPayload,
  plaintextLength: number,
): Uint8Array {
  const decapsulated = ml_kem768.decapsulate(sealed.cipherText, sealed.secretKey);
  if (bytesToHex(decapsulated) !== bytesToHex(sealed.sharedSecret)) {
    throw new Error("delivery vector decapsulation mismatch");
  }
  const { key, nonce } = deriveKeyAndNonce(decapsulated);
  const decipher = createDecipheriv(
    "aes-256-gcm",
    Buffer.from(key),
    Buffer.from(nonce),
  );
  decipher.setAuthTag(Buffer.from(sealed.tag));
  const recovered = new Uint8Array(
    Buffer.concat([decipher.update(Buffer.from(sealed.ciphertext)), decipher.final()]),
  );
  if (recovered.length !== plaintextLength) {
    throw new Error(
      `recovered plaintext length mismatch: expected ${plaintextLength}, got ${recovered.length}`,
    );
  }
  return recovered;
}

function encodeScheme1BDepositPayload(fields: {
  ownerNullifierKeyHash: bigint;
  noteSecret: bigint;
}): Uint8Array {
  const bytes = new Uint8Array(64);
  writeUint256(bytes, 0, fields.ownerNullifierKeyHash);
  writeUint256(bytes, 32, fields.noteSecret);
  return bytes;
}

function decodeScheme1BDepositPayload(bytes: Uint8Array): {
  ownerNullifierKeyHash: bigint;
  noteSecret: bigint;
} {
  return {
    ownerNullifierKeyHash: readUint256(bytes, 0),
    noteSecret: readUint256(bytes, 32),
  };
}

function parsePoolPublicInputsOrder(source: string): string[] {
  const structMatch = source.match(/struct PublicInputs\s*{([\s\S]*?)^\s*}/m);
  if (!structMatch) throw new Error("unable to locate ShieldedPool.PublicInputs");

  const fields = Array.from(
    structMatch[1].matchAll(/uint256\s+([A-Za-z0-9_]+)\s*;/g),
    (match) => match[1],
  );
  if (fields.length !== 17) {
    throw new Error(`unexpected ShieldedPool.PublicInputs size: ${fields.length}`);
  }
  return fields;
}

function objectFromPublicInputs(order: string[], values: string[]) {
  if (values.length !== order.length) {
    throw new Error(`unexpected verifier fixture public input count: ${values.length}`);
  }
  return Object.fromEntries(order.map((name, index) => [name, normalizeHex(values[index], 64)]));
}

function encodePrecompileInput(order: string[], proof: string, publicInputs: Record<string, string>) {
  const tupleType = `tuple(${order.map((name) => `uint256 ${name}`).join(",")})`;
  return ethers.utils.defaultAbiCoder.encode(
    ["bytes", tupleType],
    [proof, order.map((name) => publicInputs[name])],
  );
}

function mutateProof(proof: string): string {
  const bytes = hexToBytes(proof);
  bytes[bytes.length - 1] ^= 0x01;
  return bytesToHex(bytes);
}

// Scheme 1A plaintext (EIP Section 15.2): 160 bytes, 5 fields.
function encodeScheme1ANote(note: NoteFields): Uint8Array {
  const bytes = new Uint8Array(160);
  writeUint256(bytes, 0, note.amount);
  writeUint256(bytes, 32, note.ownerNullifierKeyHash);
  writeUint256(bytes, 64, note.noteSecret);
  writeUint256(bytes, 96, note.tokenAddress);
  writeUint256(bytes, 128, note.originTag);
  return bytes;
}

function decodeScheme1ANote(bytes: Uint8Array): NoteFields {
  return {
    amount: readUint256(bytes, 0),
    ownerNullifierKeyHash: readUint256(bytes, 32),
    noteSecret: readUint256(bytes, 64),
    tokenAddress: readUint256(bytes, 96),
    originTag: readUint256(bytes, 128),
  };
}

function formatNote(note: NoteFields) {
  return {
    amount: toHex32(note.amount),
    ownerNullifierKeyHash: toHex32(note.ownerNullifierKeyHash),
    originTag: toHex32(note.originTag),
    noteSecret: toHex32(note.noteSecret),
    tokenAddress: toHex32(note.tokenAddress),
  };
}

function writeUint256(buffer: Uint8Array, offset: number, value: bigint) {
  const hexValue = value.toString(16).padStart(64, "0");
  for (let index = 0; index < 32; index += 1) {
    buffer[offset + index] = Number.parseInt(hexValue.slice(index * 2, index * 2 + 2), 16);
  }
}

function readUint256(buffer: Uint8Array, offset: number) {
  let value = 0n;
  for (let index = 0; index < 32; index += 1) {
    value = (value << 8n) | BigInt(buffer[offset + index]);
  }
  return value;
}

function deriveKeyAndNonce(sharedSecret: Uint8Array) {
  const prk = extract(sha256, sharedSecret, new Uint8Array(0));
  return {
    key: expand(sha256, prk, DELIVERY_KEY_LABEL, 32),
    nonce: expand(sha256, prk, DELIVERY_NONCE_LABEL, 12),
  };
}

function noteDataHash(data: Uint8Array) {
  const digest = keccak_256(data);
  let value = 0n;
  for (const byte of digest) value = (value << 8n) | BigInt(byte);
  return value % FIELD_MODULUS;
}

function writeJson(outputDir: string, name: string, value: unknown) {
  writeFileSync(resolve(outputDir, name), `${stableStringify(value)}\n`);
}

function toHex32(value: bigint) {
  return `0x${value.toString(16).padStart(64, "0")}`;
}

function normalizeHex(value: string, minHexDigits = 0) {
  const normalized = value.startsWith("0x") ? value.slice(2) : value;
  const padded = normalized.padStart(minHexDigits, "0");
  return `0x${padded.toLowerCase()}`;
}

function hexByteLength(hex: string) {
  const normalized = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (normalized.length % 2 !== 0) throw new Error("hex string has odd length");
  return normalized.length / 2;
}

function stableStringify(value: unknown) {
  return JSON.stringify(sortJsonValue(value), null, 2);
}

function sortJsonValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortJsonValue);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, sortJsonValue((value as Record<string, unknown>)[key])]),
    );
  }
  return value;
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`${message}\n`);
  process.exit(1);
});
