// Reference AllowlistPolicyVerifier attestation (spec §16.1, non-normative).
// policyData = abi.encode(uint8 v, bytes32 r, bytes32 s) over
//   keccak256("\x19ERC-allowlist-attestation-v1" || digest32).

import { encodeAbiParameters, encodePacked, keccak256, parseSignature } from "viem";

export interface RawHashSigner {
  address: `0x${string}`;
  sign: (args: { hash: `0x${string}` }) => Promise<`0x${string}`>;
}

const toDigest32 = (digest: bigint): `0x${string}` => `0x${digest.toString(16).padStart(64, "0")}`;

/** The message the attestor signs for a given policy operation digest. */
export function allowlistAttestationMessage(policyOperationDigest: bigint): `0x${string}` {
  return keccak256(
    encodePacked(["string", "bytes32"], ["\x19ERC-allowlist-attestation-v1", toDigest32(policyOperationDigest)]),
  );
}

/** Produce the `policyData` bytes an AllowlistPolicyVerifier accepts. */
export async function signAllowlistAttestation(
  attestor: RawHashSigner,
  policyOperationDigest: bigint,
): Promise<`0x${string}`> {
  const message = allowlistAttestationMessage(policyOperationDigest);
  const signature = await attestor.sign({ hash: message });
  const { v, r, s, yParity } = parseSignature(signature);
  const vByte = Number(v ?? (yParity === 0 ? 27n : 28n));
  return encodeAbiParameters(
    [{ type: "uint8" }, { type: "bytes32" }, { type: "bytes32" }],
    [vByte, r, s],
  );
}
