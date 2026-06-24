import { keccak_256 } from "@noble/hashes/sha3.js";
import {
  bytesToHex,
  concatBytes,
  hexToBytes,
  toBytes,
  utf8ToBytes,
  type BytesLike
} from "./bytes.js";
import { recoverPersonalSignPublicKey } from "./auth.js";
import {
  generateRecipientEncryptionKeyPair,
  recipientKeyId,
  type RecipientEncryptionPublicKey,
  type RecipientEncryptionSecretKey
} from "./envelope.js";
import { BN254_SCALAR_MODULUS, normalizeAddress, toNonnegativeBigInt, type FieldNumberish, type HexAddress } from "./payload.js";
import {
  authDataCommitmentFromPublicKey,
  fieldToHex,
  noteSecretSeedHash,
  ownerNullifierKeyHash,
  policyCommitment,
  randomField,
  singleLeafPolicySetCommitment
} from "./poseidon.js";

export const DEMO_PROFILE_VERSION = 1;

export interface StoredRecipientEncryptionPublicKey {
  mlKem768PublicKey: `0x${string}`;
  x25519PublicKey: `0x${string}`;
  keyId: string;
}

export interface StoredRecipientEncryptionSecretKey {
  mlKem768SecretKey: `0x${string}`;
  x25519SecretKey: `0x${string}`;
  keyId: string;
  ownerNullifierKeyHash: string;
}

export interface DemoProfile {
  version: typeof DEMO_PROFILE_VERSION;
  chainId: string;
  poolAddress: HexAddress;
  account: HexAddress;
  ownerNullifierKey: string;
  ownerNullifierKeyHash: string;
  noteSecretSeed: string;
  noteSecretSeedHash: string;
  registrationBlinder: string;
  encryptionPublicKey: StoredRecipientEncryptionPublicKey;
  encryptionSecretKey: StoredRecipientEncryptionSecretKey;
  createdAt: string;
  profileSignature?: `0x${string}`;
  authPublicKey?: `0x${string}`;
  authDataCommitment?: string;
  policyCommitment?: string;
  policySetCommitment?: string;
}

export interface CreateDemoProfileOptions {
  chainId: FieldNumberish;
  poolAddress: HexAddress;
  account: HexAddress;
}

export interface FinalizeProfileAuthOptions {
  authVerifier: HexAddress;
  profileSignature: BytesLike;
}

export interface CreateDeterministicDemoProfileOptions extends CreateDemoProfileOptions {
  authVerifier: HexAddress;
  derivationSignature: BytesLike;
}

export function createDemoProfile(options: CreateDemoProfileOptions): DemoProfile {
  const ownerNullifierKey = randomField();
  const ownerHash = ownerNullifierKeyHash(ownerNullifierKey);
  const noteSecretSeed = randomField();
  const seedHash = noteSecretSeedHash(noteSecretSeed);
  const registrationBlinder = randomField();
  const keys = generateRecipientEncryptionKeyPair({ ownerNullifierKeyHash: ownerHash });

  return {
    version: DEMO_PROFILE_VERSION,
    chainId: toNonnegativeBigInt(options.chainId, "chainId").toString(10),
    poolAddress: normalizeAddress(options.poolAddress, "poolAddress"),
    account: normalizeAddress(options.account, "account"),
    ownerNullifierKey: ownerNullifierKey.toString(10),
    ownerNullifierKeyHash: ownerHash.toString(10),
    noteSecretSeed: noteSecretSeed.toString(10),
    noteSecretSeedHash: seedHash.toString(10),
    registrationBlinder: registrationBlinder.toString(10),
    encryptionPublicKey: {
      mlKem768PublicKey: bytesToHex(keys.publicKey.mlKem768PublicKey),
      x25519PublicKey: bytesToHex(keys.publicKey.x25519PublicKey),
      keyId: keys.publicKey.keyId ?? recipientKeyId(keys.publicKey)
    },
    encryptionSecretKey: {
      mlKem768SecretKey: bytesToHex(keys.secretKey.mlKem768SecretKey),
      x25519SecretKey: bytesToHex(keys.secretKey.x25519SecretKey),
      keyId: keys.secretKey.keyId ?? recipientKeyId(keys.publicKey),
      ownerNullifierKeyHash: ownerHash.toString(10)
    },
    createdAt: new Date().toISOString()
  };
}

export function profileDerivationMessage(options: CreateDemoProfileOptions & { authVerifier: HexAddress }): string {
  const lines = [
    "EIP-8182 Sepolia demo deterministic profile",
    "This signature derives local demo spending, viewing, and encryption keys.",
    "Only sign this message for a demo you trust.",
    `version: ${DEMO_PROFILE_VERSION}`,
    `chainId: ${toNonnegativeBigInt(options.chainId, "chainId").toString(10)}`,
    `pool: ${normalizeAddress(options.poolAddress, "poolAddress")}`,
    `account: ${normalizeAddress(options.account, "account")}`,
    `authVerifier: ${normalizeAddress(options.authVerifier, "authVerifier")}`
  ];
  return lines.join("\n");
}

export function createDeterministicDemoProfile(options: CreateDeterministicDemoProfileOptions): DemoProfile {
  const chainId = toNonnegativeBigInt(options.chainId, "chainId").toString(10);
  const poolAddress = normalizeAddress(options.poolAddress, "poolAddress");
  const account = normalizeAddress(options.account, "account");
  const authVerifier = normalizeAddress(options.authVerifier, "authVerifier");
  const derivationMessage = profileDerivationMessage({
    chainId,
    poolAddress,
    account,
    authVerifier
  });
  const seed = profileDerivationSeed(derivationMessage, options.derivationSignature);
  const ownerNullifierKey = deriveProfileField(seed, "owner-nullifier-key");
  const ownerHash = ownerNullifierKeyHash(ownerNullifierKey);
  const noteSecretSeed = deriveProfileField(seed, "note-secret-seed");
  const seedHash = noteSecretSeedHash(noteSecretSeed);
  const registrationBlinder = deriveProfileField(seed, "registration-blinder");
  const keys = generateRecipientEncryptionKeyPair({
    ownerNullifierKeyHash: ownerHash,
    mlKemSeed: deriveProfileBytes(seed, "ml-kem-768-seed", 64),
    x25519SecretKey: deriveProfileBytes(seed, "x25519-secret-key", 32)
  });

  return {
    version: DEMO_PROFILE_VERSION,
    chainId,
    poolAddress,
    account,
    ownerNullifierKey: ownerNullifierKey.toString(10),
    ownerNullifierKeyHash: ownerHash.toString(10),
    noteSecretSeed: noteSecretSeed.toString(10),
    noteSecretSeedHash: seedHash.toString(10),
    registrationBlinder: registrationBlinder.toString(10),
    encryptionPublicKey: {
      mlKem768PublicKey: bytesToHex(keys.publicKey.mlKem768PublicKey),
      x25519PublicKey: bytesToHex(keys.publicKey.x25519PublicKey),
      keyId: keys.publicKey.keyId ?? recipientKeyId(keys.publicKey)
    },
    encryptionSecretKey: {
      mlKem768SecretKey: bytesToHex(keys.secretKey.mlKem768SecretKey),
      x25519SecretKey: bytesToHex(keys.secretKey.x25519SecretKey),
      keyId: keys.secretKey.keyId ?? recipientKeyId(keys.publicKey),
      ownerNullifierKeyHash: ownerHash.toString(10)
    },
    createdAt: new Date().toISOString()
  };
}

export function profileSignatureMessage(profile: DemoProfile, authVerifier: HexAddress): string {
  const lines = [
    "EIP-8182 Sepolia demo profile",
    `version: ${profile.version}`,
    `chainId: ${profile.chainId}`,
    `pool: ${profile.poolAddress}`,
    `account: ${profile.account}`,
    `authVerifier: ${normalizeAddress(authVerifier, "authVerifier")}`,
    `ownerNullifierKeyHash: ${profile.ownerNullifierKeyHash}`,
    `noteSecretSeedHash: ${profile.noteSecretSeedHash}`,
    `recipientKeyId: ${profile.encryptionPublicKey.keyId}`,
    `mlKem768PublicKey: ${profile.encryptionPublicKey.mlKem768PublicKey}`,
    `x25519PublicKey: ${profile.encryptionPublicKey.x25519PublicKey}`
  ];
  return lines.join("\n");
}

export function finalizeDeterministicProfileAuth(
  profile: DemoProfile,
  options: FinalizeProfileAuthOptions
): DemoProfile {
  const profileSignature = bytesToHex(options.profileSignature);
  const recovered = recoverPersonalSignPublicKey(
    profileDerivationMessage({
      chainId: profile.chainId,
      poolAddress: profile.poolAddress,
      account: profile.account,
      authVerifier: options.authVerifier
    }),
    profileSignature
  );
  if (recovered.address !== profile.account) {
    throw new Error(`profile derivation signature recovered ${recovered.address}, expected ${profile.account}`);
  }
  const authDataCommitment = authDataCommitmentFromRecoveredPublicKey(recovered.publicKey);
  const commitment = policyCommitment(
    normalizeAddress(options.authVerifier, "authVerifier"),
    authDataCommitment,
    profile.registrationBlinder
  );
  return {
    ...profile,
    profileSignature,
    authPublicKey: bytesToHex(recovered.publicKey),
    authDataCommitment: authDataCommitment.toString(10),
    policyCommitment: commitment.toString(10),
    policySetCommitment: singleLeafPolicySetCommitment(commitment).toString(10)
  };
}

export function finalizeProfileAuth(profile: DemoProfile, options: FinalizeProfileAuthOptions): DemoProfile {
  const profileSignature = bytesToHex(options.profileSignature);
  const recovered = recoverPersonalSignPublicKey(
    profileSignatureMessage(profile, options.authVerifier),
    profileSignature
  );
  if (recovered.address !== profile.account) {
    throw new Error(`profile signature recovered ${recovered.address}, expected ${profile.account}`);
  }
  const authDataCommitment = authDataCommitmentFromRecoveredPublicKey(recovered.publicKey);
  const commitment = policyCommitment(
    normalizeAddress(options.authVerifier, "authVerifier"),
    authDataCommitment,
    profile.registrationBlinder
  );
  return {
    ...profile,
    profileSignature,
    authPublicKey: bytesToHex(recovered.publicKey),
    authDataCommitment: authDataCommitment.toString(10),
    policyCommitment: commitment.toString(10),
    policySetCommitment: singleLeafPolicySetCommitment(commitment).toString(10)
  };
}

export function profilePublicKey(profile: DemoProfile): RecipientEncryptionPublicKey {
  return {
    mlKem768PublicKey: hexToBytes(profile.encryptionPublicKey.mlKem768PublicKey, "mlKem768PublicKey"),
    x25519PublicKey: hexToBytes(profile.encryptionPublicKey.x25519PublicKey, "x25519PublicKey"),
    keyId: profile.encryptionPublicKey.keyId
  };
}

export function profileSecretKey(profile: DemoProfile): RecipientEncryptionSecretKey {
  return {
    mlKem768SecretKey: hexToBytes(profile.encryptionSecretKey.mlKem768SecretKey, "mlKem768SecretKey"),
    x25519SecretKey: hexToBytes(profile.encryptionSecretKey.x25519SecretKey, "x25519SecretKey"),
    keyId: profile.encryptionSecretKey.keyId,
    ownerNullifierKeyHash: BigInt(profile.encryptionSecretKey.ownerNullifierKeyHash)
  };
}

export function profileStorageKey(chainId: FieldNumberish, poolAddress: HexAddress, account: HexAddress): string {
  return [
    "eip8182.sepoliaDemo.profile.v1",
    toNonnegativeBigInt(chainId, "chainId").toString(10),
    normalizeAddress(poolAddress, "poolAddress"),
    normalizeAddress(account, "account")
  ].join(":");
}

export function loadDemoProfile(storage: Storage, key: string): DemoProfile | null {
  const raw = storage.getItem(key);
  if (raw === null) return null;
  const parsed = JSON.parse(raw) as unknown;
  return validateProfile(parsed);
}

export function saveDemoProfile(storage: Storage, key: string, profile: DemoProfile): void {
  storage.setItem(key, JSON.stringify(profile));
}

export function hasProfileAuth(profile: DemoProfile): profile is DemoProfile & {
  profileSignature: `0x${string}`;
  authPublicKey: `0x${string}`;
  authDataCommitment: string;
  policyCommitment: string;
  policySetCommitment: string;
} {
  return Boolean(
    profile.profileSignature
      && profile.authPublicKey
      && profile.authDataCommitment
      && profile.policyCommitment
      && profile.policySetCommitment
  );
}

export function profileField(profile: DemoProfile, field: keyof Pick<
  DemoProfile,
  "ownerNullifierKey" | "ownerNullifierKeyHash" | "noteSecretSeed" | "noteSecretSeedHash" | "registrationBlinder"
>): bigint {
  return BigInt(profile[field]);
}

export function profileFieldHex(profile: DemoProfile, field: Parameters<typeof profileField>[1]): `0x${string}` {
  return fieldToHex(profileField(profile, field));
}

function validateProfile(value: unknown): DemoProfile {
  if (!isRecord(value)) throw new Error("stored profile must be an object");
  if (value.version !== DEMO_PROFILE_VERSION) throw new Error("unsupported stored profile version");
  const profile = value as unknown as DemoProfile;
  normalizeAddress(profile.poolAddress, "poolAddress");
  normalizeAddress(profile.account, "account");
  return profile;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function authDataCommitmentFromRecoveredPublicKey(publicKey: BytesLike): bigint {
  return authDataCommitmentFromPublicKey(publicKey);
}

function profileDerivationSeed(message: string, signature: BytesLike): Uint8Array {
  return keccak_256(concatBytes(
    utf8ToBytes("eip-8182.sepolia-demo.profile-derivation.v1"),
    utf8ToBytes(message),
    toBytes(signature, "profile derivation signature")
  ));
}

function deriveProfileField(seed: BytesLike, label: string): bigint {
  const value = bytesToBigInt(deriveProfileBytes(seed, label, 32)) % BN254_SCALAR_MODULUS;
  return value === 0n ? 1n : value;
}

function deriveProfileBytes(seed: BytesLike, label: string, length: number): Uint8Array {
  if (!Number.isSafeInteger(length) || length < 0) throw new Error("derived byte length must be nonnegative");
  const out = new Uint8Array(length);
  let offset = 0;
  let counter = 0;
  while (offset < out.length) {
    const block = keccak_256(concatBytes(
      utf8ToBytes("eip-8182.sepolia-demo.profile-derivation.expand.v1"),
      toBytes(seed, "profile derivation seed"),
      utf8ToBytes(label),
      Uint8Array.of(counter)
    ));
    out.set(block.subarray(0, Math.min(block.length, out.length - offset)), offset);
    offset += block.length;
    counter += 1;
    if (counter > 255) throw new Error("derived byte length is too large");
  }
  return out;
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) + BigInt(byte);
  return value;
}
