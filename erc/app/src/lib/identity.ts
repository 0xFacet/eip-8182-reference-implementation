// Local privacy identity: ownerNullifierKey + noteSecretSeed + registration
// blinders are DERIVED from a single wallet signature (domain-separated, bound
// to (chainId, account)); an ML-KEM-768 receive keypair is generated from the
// same signature. All of it is a DEMO CONVENIENCE persisted to localStorage —
// a production wallet would keep this key material in secure storage.

import { concatHex, keccak256, toHex } from "viem";
import type { Address, Hex } from "viem";
import {
  eip712AuthDataCommitment,
  noteSecretSeedHash as noteSecretSeedHashOf,
  ownerNullifierKeyHash as onkHashOf,
  policyCommitment as policyCommitmentOf,
} from "../../../sdk/src/derivations.ts";
import { BN254_SCALAR_MODULUS } from "../../../sdk/src/field.ts";
import { bytesToHex, hexToBytes } from "../../../sdk/src/bytes.ts";
import { generateReceiveKeyPair } from "../../../sdk/src/envelope.ts";
import { SparseTree } from "../../../sdk/src/trees.ts";
import { DUMMY_OWNER_NULLIFIER_KEY_HASH } from "../../../sdk/src/generated/constants.ts";

export const IDENTITY_SIGN_TEMPLATE = (chainId: number, account: Address) =>
  [
    "Shielded Terminal — derive privacy identity",
    `Chain: ${chainId}`,
    `Account: ${account}`,
    "",
    "This signature deterministically derives your local shielded keys.",
    "Only sign this on a Shielded Terminal you trust.",
  ].join("\n");

function fieldFrom(sig: Hex, tag: string): bigint {
  const digest = keccak256(concatHex([toHex(tag), sig]));
  let v = BigInt(digest) % BN254_SCALAR_MODULUS;
  if (v === 0n) v = 1n;
  return v;
}

export interface AuthMethod {
  id: string;
  label: string;
  slot: number;
  authVerifier: Address;
  /** registration blinder as 0x-hex of a field element. */
  blinder: Hex;
  revoked: boolean;
}

export interface IdentitySecrets {
  chainId: number;
  account: Address;
  /** ownerNullifierKey (private), hex field. */
  onk: Hex;
  /** noteSecretSeed (private), hex field. */
  seed: Hex;
  kemPublicKey: Hex;
  kemSecretKey: Hex;
  authMethods: AuthMethod[];
}

const KEY = (chainId: number, account: Address, registry: Address) =>
  `shielded:id:${chainId}:${registry.toLowerCase()}:${account.toLowerCase()}`;

export function loadIdentity(chainId: number, account: Address, registry: Address): IdentitySecrets | null {
  try {
    const raw = localStorage.getItem(KEY(chainId, account, registry));
    if (!raw) return null;
    return JSON.parse(raw) as IdentitySecrets;
  } catch {
    return null;
  }
}

export function saveIdentity(id: IdentitySecrets, registry: Address): void {
  localStorage.setItem(KEY(id.chainId, id.account, registry), JSON.stringify(id));
}

export function clearIdentity(chainId: number, account: Address, registry: Address): void {
  localStorage.removeItem(KEY(chainId, account, registry));
}

/** Derive a fresh identity from a wallet signature over the domain-separated template. */
export function deriveIdentity(params: {
  chainId: number;
  account: Address;
  signature: Hex;
  authVerifier: Address;
}): IdentitySecrets {
  const onk = fieldFrom(params.signature, "shielded.onk.v1");
  const seed = fieldFrom(params.signature, "shielded.seed.v1");
  const blinder = fieldFrom(params.signature, "shielded.blinder.v1");
  // 64-byte ML-KEM seed from two domain-separated keccak digests.
  const kemSeed = hexToBytes(
    concatHex([
      keccak256(concatHex([toHex("shielded.kem.a.v1"), params.signature])),
      keccak256(concatHex([toHex("shielded.kem.b.v1"), params.signature])),
    ]),
  );
  const kem = generateReceiveKeyPair(kemSeed);
  return {
    chainId: params.chainId,
    account: params.account,
    onk: `0x${onk.toString(16)}`,
    seed: `0x${seed.toString(16)}`,
    kemPublicKey: bytesToHex(kem.publicKey),
    kemSecretKey: bytesToHex(kem.secretKey),
    authMethods: [
      {
        id: "primary",
        label: "EIP-712 / ECDSA (this wallet)",
        slot: 0,
        authVerifier: params.authVerifier,
        blinder: `0x${blinder.toString(16)}`,
        revoked: false,
      },
    ],
  };
}

export interface DerivedIdentity {
  onk: bigint;
  seed: bigint;
  onkHash: bigint;
  seedHash: bigint;
  kemPublicKey: Uint8Array;
  kemSecretKey: Uint8Array;
  authDataCommitment: bigint;
  policySetCommitment: bigint;
  /** the active spend method (first non-revoked). */
  primary: {
    method: AuthMethod;
    blinder: bigint;
    policyCommitment: bigint;
    slot: number;
    siblings: bigint[];
  } | null;
}

/** Expand the stored secrets into field-typed derived values + the policy set. */
export function expandIdentity(id: IdentitySecrets): DerivedIdentity {
  const onk = BigInt(id.onk);
  const seed = BigInt(id.seed);
  const authDataCommitment = eip712AuthDataCommitment(BigInt(id.account));
  const tree = new SparseTree(8);
  const active = id.authMethods.filter((m) => !m.revoked);
  for (const m of active) {
    tree.set(BigInt(m.slot), policyCommitmentOf(BigInt(m.authVerifier), authDataCommitment, BigInt(m.blinder)));
  }
  const primaryMethod = active[0] ?? null;
  return {
    onk,
    seed,
    onkHash: onkHashOf(onk),
    seedHash: noteSecretSeedHashOf(seed),
    kemPublicKey: hexToBytes(id.kemPublicKey),
    kemSecretKey: hexToBytes(id.kemSecretKey),
    authDataCommitment,
    policySetCommitment: tree.root(),
    primary: primaryMethod
      ? {
          method: primaryMethod,
          blinder: BigInt(primaryMethod.blinder),
          policyCommitment: policyCommitmentOf(BigInt(primaryMethod.authVerifier), authDataCommitment, BigInt(primaryMethod.blinder)),
          slot: primaryMethod.slot,
          siblings: tree.proof(BigInt(primaryMethod.slot)),
        }
      : null,
  };
}

export const DUMMY_ONK_HASH = DUMMY_OWNER_NULLIFIER_KEY_HASH;

/** Fresh random blinder (rotation) as a hex field element. */
export function randomBlinderHex(): Hex {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  let v = BigInt(bytesToHex(bytes)) % BN254_SCALAR_MODULUS;
  if (v === 0n) v = 1n;
  return `0x${v.toString(16)}`;
}
