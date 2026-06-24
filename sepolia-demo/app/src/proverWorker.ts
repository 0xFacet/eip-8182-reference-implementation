import { Barretenberg, UltraHonkBackend } from '@aztec/bb.js';
import initACVM from '@noir-lang/acvm_js';
import acvmWasmUrl from '@noir-lang/acvm_js/web/acvm_js_bg.wasm?url';
import { Noir } from '@noir-lang/noir_js';
import initNoirC from '@noir-lang/noirc_abi';
import noircAbiWasmUrl from '@noir-lang/noirc_abi/web/noirc_abi_wasm_bg.wasm?url';
import {
  buildBrowserWitnessBundle,
  bytesToHex,
  publicInputObjectFromSignals,
  publicInputStrings,
  snarkjsProofToBytes,
  verifyPoolAuthAgreement,
  type BrowserProverRequest,
  type SnarkjsGroth16Proof,
} from '../../src/index.js';

const POOL_WASM_URL = '/prover/pool.wasm';
const POOL_ZKEY_URL = '/prover/pool_final.zkey';
const POOL_VKEY_URL = '/prover/pool_vkey.json';
const AUTH_CIRCUIT_URL = '/prover/auth.json';

type WorkerRequestMessage = {
  type: 'prove';
  request: BrowserProverRequest;
};

type WorkerStatusMessage = {
  type: 'status';
  message: string;
};

type WorkerResultMessage = {
  type: 'result';
  result: BrowserProverResponse;
};

type WorkerErrorMessage = {
  type: 'error';
  error: string;
};

export type BrowserProverResponse = {
  poolProofHex: `0x${string}`;
  authProofHex: `0x${string}`;
  publicInputs: Record<string, string>;
  publicInputArray: string[];
  outputNoteData0Hex: `0x${string}`;
  outputNoteData1Hex: `0x${string}`;
  outputNoteData2Hex: `0x${string}`;
  timings: {
    poolProveMs: number;
    authProveMs: number;
  };
};

type WorkerResponseMessage = WorkerStatusMessage | WorkerResultMessage | WorkerErrorMessage;

type SnarkjsModule = {
  groth16: {
    fullProve(
      input: unknown,
      wasmFile: string,
      zkeyFile: string,
    ): Promise<{ proof: SnarkjsGroth16Proof; publicSignals: string[] }>;
    verify(vkey: unknown, publicSignals: string[], proof: SnarkjsGroth16Proof): Promise<boolean>;
  };
};

let noirRuntimeReady: Promise<void> | undefined;

self.onmessage = (event: MessageEvent<WorkerRequestMessage>) => {
  if (event.data.type !== 'prove') return;
  prove(event.data.request)
    .then((result) => post({ type: 'result', result }))
    .catch((error) => post({ type: 'error', error: error instanceof Error ? error.message : String(error) }));
};

async function prove(request: BrowserProverRequest): Promise<BrowserProverResponse> {
  status('Rebuilding note and auth witnesses from Sepolia logs.');
  const witnessBundle = buildBrowserWitnessBundle(request);

  status('Generating pool Groth16 proof in the browser.');
  const snarkjs = normalizeSnarkjsModule(await import('snarkjs') as unknown);
  const poolStarted = performance.now();
  const { proof: poolProof, publicSignals } = await snarkjs.groth16.fullProve(
    witnessBundle.pool.witnessInput,
    POOL_WASM_URL,
    POOL_ZKEY_URL,
  );
  const poolProveMs = Math.round(performance.now() - poolStarted);

  status('Verifying pool proof locally.');
  const poolVerified = await snarkjs.groth16.verify(await fetchJson(POOL_VKEY_URL), publicSignals, poolProof);
  if (!poolVerified) throw new Error('pool proof local verify failed');
  const poolPublicInputs = publicInputObjectFromSignals(publicSignals);

  status('Executing Noir auth circuit.');
  await initNoirRuntime();
  const authCircuit = await fetchJson(AUTH_CIRCUIT_URL);
  const noir = new Noir(authCircuit);
  await noir.init();
  const { witness } = await noir.execute(witnessBundle.auth.authCircuitInput);

  status('Generating auth UltraHonk proof in the browser.');
  const barretenberg = await Barretenberg.new();
  try {
    const backend = new UltraHonkBackend(authCircuit.bytecode, barretenberg);
    const authStarted = performance.now();
    const authProofData = await backend.generateProof(witness, { verifierTarget: 'evm' });
    const authProveMs = Math.round(performance.now() - authStarted);
    const authVerified = await backend.verifyProof(authProofData, { verifierTarget: 'evm' });
    if (!authVerified) throw new Error('auth proof local verify failed');
    verifyPoolAuthAgreement(poolPublicInputs, authProofData.publicInputs.map(fieldHexToBigint));

    status(`Proofs ready. Auth proof is ${authProofData.proof.length} bytes.`);
    return {
      poolProofHex: bytesToHex(snarkjsProofToBytes(poolProof)),
      authProofHex: bytesToHex(authProofData.proof),
      publicInputs: publicInputStrings(poolPublicInputs),
      publicInputArray: Object.values(publicInputStrings(poolPublicInputs)),
      outputNoteData0Hex: witnessBundle.pool.outputNoteDataHexes[0],
      outputNoteData1Hex: witnessBundle.pool.outputNoteDataHexes[1],
      outputNoteData2Hex: witnessBundle.pool.outputNoteDataHexes[2],
      timings: { poolProveMs, authProveMs },
    };
  } finally {
    await barretenberg.destroy();
  }
}

function initNoirRuntime(): Promise<void> {
  noirRuntimeReady ??= Promise.all([
    initACVM(fetch(acvmWasmUrl)),
    initNoirC(fetch(noircAbiWasmUrl)),
  ]).then(() => undefined);
  return noirRuntimeReady;
}

async function fetchJson(url: string): Promise<any> {
  const response = await fetch(url);
  if (!response.ok) throw new Error(`failed to fetch ${url}: ${response.status}`);
  return response.json();
}

function fieldHexToBigint(value: string): bigint {
  return BigInt(value.startsWith('0x') ? value : `0x${value}`);
}

function normalizeSnarkjsModule(module: unknown): SnarkjsModule {
  if (hasGroth16(module)) return module;
  if (isRecord(module) && hasGroth16(module.default)) return module.default;
  throw new Error('snarkjs groth16 API was not available in the browser bundle');
}

function hasGroth16(value: unknown): value is SnarkjsModule {
  return isRecord(value) && isRecord(value.groth16);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function status(message: string): void {
  post({ type: 'status', message });
}

function post(message: WorkerResponseMessage): void {
  self.postMessage(message);
}
