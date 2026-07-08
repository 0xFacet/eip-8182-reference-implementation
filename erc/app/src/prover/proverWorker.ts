/// <reference lib="webworker" />
// In-browser prover. Pool relation: snarkjs Groth16 over build/pool. Auth
// relation: @noir-lang/noir_js executes the Appendix A circuit, then
// @aztec/bb.js UltraHonkBackend generates the on-chain EVM proof. Both run here,
// off the UI thread, in a cross-origin-isolated context (COOP/COEP).

import { Barretenberg, UltraHonkBackend } from "@aztec/bb.js";
import initACVM from "@noir-lang/acvm_js";
import acvmWasmUrl from "@noir-lang/acvm_js/web/acvm_js_bg.wasm?url";
import { Noir } from "@noir-lang/noir_js";
import initNoirC from "@noir-lang/noirc_abi";
import noircAbiWasmUrl from "@noir-lang/noirc_abi/web/noirc_abi_wasm_bg.wasm?url";

const POOL_WASM_URL = "/prover/pool.wasm";
const POOL_ZKEY_URL = "/prover/pool_final.zkey";
const POOL_VKEY_URL = "/prover/pool_vkey.json";
const AUTH_CIRCUIT_URL = "/prover/auth.json";

export interface ProveRequest {
  poolWitnessInput: Record<string, unknown>;
  authCircuitInput: Record<string, unknown>;
  expectedPublicSignals: string[];
  expectedBlinded: string;
  expectedDigest: string;
}

export interface ProveResult {
  poolProofHex: `0x${string}`;
  authProofHex: `0x${string}`;
  publicSignals: string[];
  timings: { poolProveMs: number; authProveMs: number };
}

type Groth16Proof = {
  pi_a: [string, string, string];
  pi_b: [[string, string], [string, string], [string, string]];
  pi_c: [string, string, string];
};

type SnarkjsModule = {
  groth16: {
    fullProve(input: unknown, wasm: string, zkey: string): Promise<{ proof: Groth16Proof; publicSignals: string[] }>;
    verify(vkey: unknown, publicSignals: string[], proof: Groth16Proof): Promise<boolean>;
  };
};

let noirRuntimeReady: Promise<void> | undefined;

self.onmessage = (event: MessageEvent<{ type: "prove"; request: ProveRequest }>) => {
  if (event.data?.type !== "prove") return;
  prove(event.data.request)
    .then((result) => post({ type: "result", result }))
    .catch((error) => post({ type: "error", error: error instanceof Error ? error.message : String(error) }));
};

async function prove(req: ProveRequest): Promise<ProveResult> {
  status("Generating pool Groth16 proof…");
  const snarkjs = normalizeSnarkjs(await import("snarkjs"));
  const poolStart = performance.now();
  const { proof: poolProof, publicSignals } = await snarkjs.groth16.fullProve(req.poolWitnessInput, POOL_WASM_URL, POOL_ZKEY_URL);
  const poolProveMs = Math.round(performance.now() - poolStart);

  status("Verifying pool proof locally…");
  const vkey = await fetchJson(POOL_VKEY_URL);
  if (!(await snarkjs.groth16.verify(vkey, publicSignals, poolProof))) throw new Error("pool proof local verify failed");
  for (let i = 0; i < req.expectedPublicSignals.length; i++) {
    if (BigInt(publicSignals[i]!) !== BigInt(req.expectedPublicSignals[i]!)) {
      throw new Error(`pool public signal ${i} mismatch`);
    }
  }

  status("Executing Noir auth circuit…");
  await initNoirRuntime();
  const authCircuit = await fetchJson(AUTH_CIRCUIT_URL);
  const noir = new Noir(authCircuit);
  await noir.init();
  const { witness } = await noir.execute(req.authCircuitInput as never);

  status("Generating auth UltraHonk proof…");
  const barretenberg = await Barretenberg.new();
  try {
    const backend = new UltraHonkBackend(authCircuit.bytecode, barretenberg);
    const authStart = performance.now();
    const authProofData = await backend.generateProof(witness, { verifierTarget: "evm" });
    const authProveMs = Math.round(performance.now() - authStart);
    if (!(await backend.verifyProof(authProofData, { verifierTarget: "evm" }))) throw new Error("auth proof local verify failed");

    const authPub = authProofData.publicInputs.map((h) => BigInt(h.startsWith("0x") ? h : `0x${h}`));
    if (authPub[0] !== BigInt(req.expectedBlinded)) throw new Error("auth blindedAuthCommitment mismatch");
    if (authPub[1] !== BigInt(req.expectedDigest)) throw new Error("auth transactionIntentDigest mismatch");

    status("Proofs ready.");
    return {
      poolProofHex: groth16ProofToBytes(poolProof),
      authProofHex: uint8ToHex(authProofData.proof),
      publicSignals,
      timings: { poolProveMs, authProveMs },
    };
  } finally {
    await barretenberg.destroy();
  }
}

function initNoirRuntime(): Promise<void> {
  noirRuntimeReady ??= Promise.all([initACVM(fetch(acvmWasmUrl)), initNoirC(fetch(noircAbiWasmUrl))]).then(() => undefined);
  return noirRuntimeReady;
}

async function fetchJson(url: string): Promise<any> {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`failed to fetch ${url}: ${res.status}`);
  return res.json();
}

const fp = (v: string): string => BigInt(v).toString(16).padStart(64, "0");

/** snarkjs proof JSON -> canonical 256-byte pool proof (spec §7.2). */
function groth16ProofToBytes(proof: Groth16Proof): `0x${string}` {
  if (BigInt(proof.pi_a[2]) !== 1n || BigInt(proof.pi_c[2]) !== 1n) throw new Error("g1 z != 1");
  if (BigInt(proof.pi_b[2][0]) !== 1n || BigInt(proof.pi_b[2][1]) !== 0n) throw new Error("g2 z != (1,0)");
  return ("0x" +
    fp(proof.pi_a[0]) + fp(proof.pi_a[1]) +
    fp(proof.pi_b[0][1]) + fp(proof.pi_b[0][0]) +
    fp(proof.pi_b[1][1]) + fp(proof.pi_b[1][0]) +
    fp(proof.pi_c[0]) + fp(proof.pi_c[1])) as `0x${string}`;
}

function uint8ToHex(bytes: Uint8Array): `0x${string}` {
  let hex = "";
  for (const b of bytes) hex += b.toString(16).padStart(2, "0");
  return `0x${hex}`;
}

function normalizeSnarkjs(mod: unknown): SnarkjsModule {
  const m = mod as { groth16?: unknown; default?: { groth16?: unknown } };
  if (m && typeof m.groth16 === "object") return m as SnarkjsModule;
  if (m?.default && typeof m.default.groth16 === "object") return m.default as SnarkjsModule;
  throw new Error("snarkjs groth16 API unavailable");
}

function status(message: string): void {
  post({ type: "status", message });
}

function post(msg: { type: "status"; message: string } | { type: "result"; result: ProveResult } | { type: "error"; error: string }): void {
  self.postMessage(msg);
}
