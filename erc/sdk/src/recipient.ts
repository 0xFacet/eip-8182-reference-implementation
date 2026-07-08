// Spec §10 registered-recipient resolution. Before delivering an encrypted
// note to an Ethereum address, a sender MUST verify the full "usable when"
// predicate — not just that the recipient is registered. The anti-imposter
// trio (canonical registry code hash, registry id, suite equality) and the
// owner-hash range/reserved checks are the defenses that stop a misconfigured
// or malicious registry from redirecting a delivery to an unspendable or
// attacker-controlled owner hash.

import type { Address, PublicClient } from "viem";
import { keccak256, toBytes } from "viem";
import { registryAbi, shieldedPoolAbi } from "./abis.ts";
import { BN254_SCALAR_MODULUS } from "./field.ts";
import {
  DUMMY_OWNER_NULLIFIER_KEY_HASH,
  OUTPUT_NOTE_DATA_SUITE,
  REGISTRY_ID_STRING,
} from "./generated/constants.ts";
import { CANONICAL_PRIVACY_REGISTRY_RUNTIME_CODE_HASH } from "./generated/addresses.ts";

export interface ResolvedRecipient {
  ownerNullifierKeyHash: bigint;
  mlKem768PublicKey: `0x${string}`;
  leafPosition: bigint;
  metadataVersion: number;
}

export type RecipientResolution =
  | { ok: true; recipient: ResolvedRecipient }
  | { ok: false; reason: string };

export interface ResolveOptions {
  /**
   * When false, skip the on-chain registry runtime-code-hash pin. Only for
   * environments where the canonical hash is not yet finalized (the reference
   * deployment pins it; production MUST keep this true).
   */
  enforceRegistryCodeHash?: boolean;
}

/**
 * Full spec §10 registered-recipient resolution. Returns the usable profile or
 * a precise rejection reason. Every §10 "usable when" condition is checked.
 */
export async function resolveRecipient(
  publicClient: PublicClient,
  addresses: { registry: Address; pool: Address },
  recipient: Address,
  options: ResolveOptions = {},
): Promise<RecipientResolution> {
  const { registry, pool } = addresses;

  // 1. Canonical registry runtime code hash (anti-imposter).
  if (options.enforceRegistryCodeHash !== false) {
    const code = await publicClient.getCode({ address: registry });
    if (!code || code === "0x") return { ok: false, reason: "registry has no code" };
    const codeHash = keccak256(code);
    if (codeHash.toLowerCase() !== CANONICAL_PRIVACY_REGISTRY_RUNTIME_CODE_HASH.toLowerCase()) {
      return { ok: false, reason: "registry runtime code hash is not canonical" };
    }
  }

  // 2. Registry id.
  const registryId = (await publicClient.readContract({
    address: registry,
    abi: registryAbi,
    functionName: "ercXXXXPrivacyRegistryId",
  })) as `0x${string}`;
  if (registryId.toLowerCase() !== keccak256(toBytes(REGISTRY_ID_STRING)).toLowerCase()) {
    return { ok: false, reason: "registry id mismatch" };
  }

  // 3. Suite equality: registry == pool == canonical suite string.
  const [registrySuite, poolSuite] = (await Promise.all([
    publicClient.readContract({ address: registry, abi: registryAbi, functionName: "outputNoteDataSuite" }),
    publicClient.readContract({ address: pool, abi: shieldedPoolAbi, functionName: "outputNoteDataSuite" }),
  ])) as [string, string];
  if (registrySuite !== OUTPUT_NOTE_DATA_SUITE) return { ok: false, reason: "registry suite mismatch" };
  if (poolSuite !== registrySuite) return { ok: false, reason: "pool/registry suite mismatch" };

  // 4. Registered identity + receive entry.
  const profile = (await publicClient.readContract({
    address: registry,
    abi: registryAbi,
    functionName: "getPrivacyProfile",
    args: [recipient],
  })) as [
    boolean,
    { leafPosition: number; ownerNullifierKeyHash: bigint; noteSecretSeedHash: bigint; policySetCommitment: bigint },
    boolean,
    { mlKem768PublicKey: `0x${string}`; metadataVersion: number },
  ];
  const [identityRegistered, identity, receiveRegistered, receive] = profile;
  if (!identityRegistered) return { ok: false, reason: "recipient has no identity entry" };
  if (!receiveRegistered) return { ok: false, reason: "recipient has no receive entry" };

  // 5. Owner-hash range + reserved-value checks.
  const onk = BigInt(identity.ownerNullifierKeyHash);
  if (onk >= BN254_SCALAR_MODULUS) return { ok: false, reason: "ownerNullifierKeyHash >= p" };
  if (onk === 0n) return { ok: false, reason: "ownerNullifierKeyHash == 0" };
  if (onk === DUMMY_OWNER_NULLIFIER_KEY_HASH) return { ok: false, reason: "ownerNullifierKeyHash == DUMMY" };

  // 6. ML-KEM key length.
  const key = receive.mlKem768PublicKey;
  if ((key.length - 2) / 2 !== 1184) return { ok: false, reason: "ML-KEM public key length != 1184" };

  return {
    ok: true,
    recipient: {
      ownerNullifierKeyHash: onk,
      mlKem768PublicKey: key,
      leafPosition: BigInt(identity.leafPosition),
      metadataVersion: Number(receive.metadataVersion),
    },
  };
}
