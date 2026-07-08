// Node-side proof generation. Groth16 pool proofs via snarkjs; UltraHonk auth
// proofs via nargo + bb over circuits-noir/auth. Browser-incompatible by design
// (spawns child processes / reads build artifacts) — kept out of the pure-crypto
// SDK surface; the demo and e2e import it directly under Node.

import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import * as snarkjs from "snarkjs";
import type { IntentFields } from "./derivations.ts";
import type { SignedIntent } from "./eip712.ts";

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const ERC_ROOT = path.resolve(HERE, "../..");

const POOL_WASM = path.join(ERC_ROOT, "build/pool/pool_js/pool.wasm");
const POOL_ZKEY = path.join(ERC_ROOT, "build/pool/pool_final.zkey");
const POOL_VKEY_PATH = path.join(ERC_ROOT, "build/pool/pool_vkey.json");
const AUTH_DIR = path.join(ERC_ROOT, "circuits-noir/auth");
const DEMO_WASM = path.join(ERC_ROOT, "build/auth_demo/auth_demo_js/auth_demo.wasm");
const DEMO_ZKEY = path.join(ERC_ROOT, "build/auth_demo/auth_demo_final.zkey");
const DEMO_VKEY_PATH = path.join(ERC_ROOT, "build/auth_demo/auth_demo_vkey.json");

const NARGO = process.env.NARGO ?? path.join(os.homedir(), ".nargo/bin/nargo");
const BB = process.env.BB ?? path.join(os.homedir(), ".bb/bb");

const fp = (v: string | bigint): string => BigInt(v).toString(16).padStart(64, "0");

/** snarkjs proof JSON -> canonical 256-byte layout (spec §7.2). */
export function proofToBytes(proof: {
  pi_a: [string, string, string];
  pi_b: [[string, string], [string, string], [string, string]];
  pi_c: [string, string, string];
}): `0x${string}` {
  if (BigInt(proof.pi_a[2]) !== 1n) throw new Error("g1 z != 1");
  if (BigInt(proof.pi_c[2]) !== 1n) throw new Error("g1 z != 1");
  if (BigInt(proof.pi_b[2][0]) !== 1n || BigInt(proof.pi_b[2][1]) !== 0n) throw new Error("g2 z != (1,0)");
  return ("0x" +
    fp(proof.pi_a[0]) +
    fp(proof.pi_a[1]) +
    fp(proof.pi_b[0][1]) +
    fp(proof.pi_b[0][0]) +
    fp(proof.pi_b[1][1]) +
    fp(proof.pi_b[1][0]) +
    fp(proof.pi_c[0]) +
    fp(proof.pi_c[1])) as `0x${string}`;
}

export interface PoolProof {
  proof: `0x${string}`;
  publicSignals: string[]; // 24 decimal strings
}

/** Generate + locally verify a Groth16 pool proof from a witness input JSON. */
export async function provePoolGroth16(input: Record<string, unknown>): Promise<PoolProof> {
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, POOL_WASM, POOL_ZKEY);
  const vkey = JSON.parse(fs.readFileSync(POOL_VKEY_PATH, "utf8"));
  const ok = await snarkjs.groth16.verify(vkey, publicSignals, proof);
  if (!ok) throw new Error("provePoolGroth16: local verify failed");
  return { proof: proofToBytes(proof), publicSignals };
}

// ---- UltraHonk auth proof (Appendix A / circuits-noir/auth) -------------------

const byteArray = (bytes: Uint8Array): string => "[" + Array.from(bytes, (b) => `"0x${b.toString(16).padStart(2, "0")}"`).join(",") + "]";

function bigintTo32Bytes(v: bigint): Uint8Array {
  const out = new Uint8Array(32);
  let x = v;
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  if (x !== 0n) throw new Error("value exceeds 32 bytes");
  return out;
}

function hexTo32Bytes(hex: string): Uint8Array {
  return bigintTo32Bytes(BigInt(hex));
}

export interface HonkAuthProof {
  proof: `0x${string}`;
  /** [blindedAuthCommitment, transactionIntentDigest] as bigints. */
  publicSignals: [bigint, bigint];
}

export interface HonkAuthParams {
  fields: IntentFields;
  policyDataHash: bigint;
  blindingFactor: bigint;
  signed: SignedIntent;
}

/**
 * Produce an on-chain UltraHonk auth proof for the ECDSA/EIP-712 auth circuit.
 * Writes Prover.toml, runs `nargo execute` + `bb prove -t evm`, returns the
 * proof bytes and the two Noir outputs.
 */
export function proveHonkAuth(p: HonkAuthParams): HonkAuthProof {
  const f = p.fields;
  const dec = (v: bigint) => `"${v.toString()}"`;
  const nonceBytes = bigintTo32Bytes(f.nonce);
  const pubX = hexTo32Bytes(p.signed.publicKeyX);
  const pubY = hexTo32Bytes(p.signed.publicKeyY);
  const sig = new Uint8Array(64);
  sig.set(hexTo32Bytes(p.signed.r), 0);
  sig.set(hexTo32Bytes(p.signed.s), 32);

  const toml = [
    `execution_chain_id = ${dec(f.executionChainId)}`,
    `pool_address = ${dec(f.poolAddress)}`,
    `auth_verifier = ${dec(f.authVerifier)}`,
    `authorizing_address = ${dec(f.authorizingAddress)}`,
    `operation_kind = ${dec(f.operationKind)}`,
    `token_address = ${dec(f.tokenAddress)}`,
    `recipient_owner_nullifier_key_hash = ${dec(f.recipientOwnerNullifierKeyHash)}`,
    `amount = ${dec(f.amount)}`,
    `fee_note_recipient_owner_nullifier_key_hash = ${dec(f.feeNoteRecipientOwnerNullifierKeyHash)}`,
    `fee_amount = ${dec(f.feeAmount)}`,
    `public_recipient_address = ${dec(f.publicRecipientAddress)}`,
    `authorized_submitter = ${dec(f.authorizedSubmitter)}`,
    `downstream_action_commitment = ${dec(f.downstreamActionCommitment)}`,
    `execution_constraints_flags = ${dec(f.executionConstraintsFlags)}`,
    `locked_output_binding0 = ${dec(f.lockedOutputBinding0)}`,
    `locked_output_binding1 = ${dec(f.lockedOutputBinding1)}`,
    `locked_output_binding2 = ${dec(f.lockedOutputBinding2)}`,
    `policy_data_hash = ${dec(p.policyDataHash)}`,
    `valid_until_seconds = ${dec(f.validUntilSeconds)}`,
    `blinding_factor = ${dec(p.blindingFactor)}`,
    `nonce = ${byteArray(nonceBytes)}`,
    `pubkey_x = ${byteArray(pubX)}`,
    `pubkey_y = ${byteArray(pubY)}`,
    `signature = ${byteArray(sig)}`,
    "",
  ].join("\n");

  fs.writeFileSync(path.join(AUTH_DIR, "Prover.toml"), toml);

  execFileSync(NARGO, ["execute", "witness"], { cwd: AUTH_DIR, stdio: "pipe" });
  execFileSync(
    BB,
    ["prove", "--scheme", "ultra_honk", "-b", "target/auth.json", "-w", "target/witness.gz", "-o", "target", "-t", "evm"],
    { cwd: AUTH_DIR, stdio: "pipe" },
  );

  const proof = fs.readFileSync(path.join(AUTH_DIR, "target/proof"));
  const pub = fs.readFileSync(path.join(AUTH_DIR, "target/public_inputs"));
  if (pub.length !== 64) throw new Error(`expected 64-byte public_inputs, got ${pub.length}`);
  const blinded = BigInt("0x" + pub.subarray(0, 32).toString("hex"));
  const digest = BigInt("0x" + pub.subarray(32, 64).toString("hex"));
  return { proof: ("0x" + proof.toString("hex")) as `0x${string}`, publicSignals: [blinded, digest] };
}

export interface DemoAuthParams {
  fields: IntentFields;
  policyDataHash: bigint;
  blindedAuthCommitment: bigint;
  transactionIntentDigest: bigint;
  authSecret: bigint;
  blindingFactor: bigint;
}

/** NON-NORMATIVE demo Groth16 auth proof (build/auth_demo). */
export async function proveDemoAuthGroth16(p: DemoAuthParams): Promise<PoolProof> {
  const f = p.fields;
  const dc = (v: bigint) => v.toString();
  const input = {
    blindedAuthCommitment: dc(p.blindedAuthCommitment),
    transactionIntentDigest: dc(p.transactionIntentDigest),
    poolAddress: dc(f.poolAddress),
    authVerifier: dc(f.authVerifier),
    authorizingAddress: dc(f.authorizingAddress),
    operationKind: dc(f.operationKind),
    tokenAddress: dc(f.tokenAddress),
    recipientOwnerNullifierKeyHash: dc(f.recipientOwnerNullifierKeyHash),
    amount: dc(f.amount),
    feeNoteRecipientOwnerNullifierKeyHash: dc(f.feeNoteRecipientOwnerNullifierKeyHash),
    feeAmount: dc(f.feeAmount),
    publicRecipientAddress: dc(f.publicRecipientAddress),
    executionConstraintsFlags: dc(f.executionConstraintsFlags),
    lockedOutputBinding0: dc(f.lockedOutputBinding0),
    lockedOutputBinding1: dc(f.lockedOutputBinding1),
    lockedOutputBinding2: dc(f.lockedOutputBinding2),
    nonce: dc(f.nonce),
    validUntilSeconds: dc(f.validUntilSeconds),
    executionChainId: dc(f.executionChainId),
    policyDataHash: dc(p.policyDataHash),
    authSecret: dc(p.authSecret),
    blindingFactor: dc(p.blindingFactor),
  };
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, DEMO_WASM, DEMO_ZKEY);
  const vkey = JSON.parse(fs.readFileSync(DEMO_VKEY_PATH, "utf8"));
  const ok = await snarkjs.groth16.verify(vkey, publicSignals, proof);
  if (!ok) throw new Error("proveDemoAuthGroth16: local verify failed");
  return { proof: proofToBytes(proof), publicSignals };
}
