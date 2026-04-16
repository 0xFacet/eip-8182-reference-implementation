import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { mkdirSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { setTimeout as delay } from "node:timers/promises";
import { ethers, type ContractInterface } from "ethers";
import * as secp from "@noble/secp256k1";
import {
  buildSingleSigAuthorizationTypedData,
  DELIVERY_SCHEME_X_WING,
  hexToBytes,
  PROTOCOL_VERIFYING_CONTRACT,
  singleSigAuthDataCommitment,
} from "../../src/lib/protocol.ts";
import {
  createPoseidonHelpers,
} from "./tx_proof_shared.ts";
import { deriveDeliveryKeypair } from "../../prover/src/note_delivery.ts";
import {
  computeNoteSecretSeedHash,
  computeOwnerNullifierKeyHash,
} from "./eip8182.ts";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = resolve(__dirname, "../..");
const SESSION_DIR = resolve("/tmp/codex", `http-prover-deposit-${process.pid}`);

const ANVIL_PORT = 8558;
const PROVER_PORT = 3015;
const RPC_URL = `http://127.0.0.1:${ANVIL_PORT}`;
const PROVER_URL = `http://127.0.0.1:${PROVER_PORT}`;
const POOL_ADDRESS = PROTOCOL_VERIFYING_CONTRACT;
const POSEIDON_LIBRARY_ADDRESS = "0x3333333C0A88F9BE4fd23ed0536F9B6c427e3B93";
const ZK_TRANSCRIPT_LIBRARY_ADDRESS = "0x441DC930704671aa1F8b089739Eb4317e196f124";
const VERIFIER_IMPLEMENTATION_ADDRESS =
  "0x0000000000000000000000000000000000008183";
const PROOF_VERIFY_PRECOMPILE_ADDRESS =
  "0x0000000000000000000000000000000000000030";
const ANVIL_MNEMONIC = "test test test test test test test test test test test junk";
const ANVIL_FIRST_PRIVATE_KEY =
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const NULLIFIER_KEY = 0x9999n;
const NOTE_SECRET_SEED = 0xbeefn;
const DELIVERY_SECRET = 0xcafen;
const DEPOSIT_AMOUNT = ethers.utils.parseEther("0.1");

const SHIELDED_POOL_ABI = [
  "function registerUser(uint256,uint256,uint32,bytes)",
  "function registerAuthPolicy(uint256,uint256)",
  "function transact(bytes,(uint256 noteCommitmentRoot,uint256 nullifier0,uint256 nullifier1,uint256 noteCommitment0,uint256 noteCommitment1,uint256 noteCommitment2,uint256 publicAmountIn,uint256 publicAmountOut,uint256 publicRecipientAddress,uint256 publicTokenAddress,uint256 depositorAddress,uint256 transactionReplayId,uint256 registryRoot,uint256 validUntilSeconds,uint256 executionChainId,uint256 authPolicyRegistryRoot,uint256 outputNoteDataHash0,uint256 outputNoteDataHash1,uint256 outputNoteDataHash2),bytes,bytes,bytes) payable",
] as const;

const HONK_VERIFIER_ABI = [
  "function verify(bytes proof, bytes32[] publicInputs) view returns (bool)",
] as const;

interface RunningProcess {
  child: ChildProcess;
  stdout: string[];
  stderr: string[];
  name: string;
}

async function main() {
  mkdirSync(SESSION_DIR, { recursive: true });
  const provider = new ethers.providers.JsonRpcProvider(RPC_URL);
  let anvil: RunningProcess | null = null;
  let prover: RunningProcess | null = null;

  try {
    anvil = spawnLogged("anvil", "anvil", [
      "--host",
      "127.0.0.1",
      "--port",
      String(ANVIL_PORT),
      "--disable-code-size-limit",
      "--mnemonic",
      ANVIL_MNEMONIC,
    ]);
    await waitForRpc(provider);

    await installVerifierStack(provider);
    await installPool(provider);

    const poolCode = await provider.getCode(POOL_ADDRESS);
    assert.notEqual(poolCode, "0x", "pool code missing after state load");

    const signer = new ethers.Wallet(ANVIL_FIRST_PRIVATE_KEY, provider);
    const user = await deriveSingleSigUser(signer.address);

    prover = spawnLogged("prover", "tsx", ["prover/src/index.ts"], {
      env: {
        ...process.env,
        PORT: String(PROVER_PORT),
        RPC_URL,
        POOL_ADDRESS,
        EIP8182_TOOL_HOME: resolve(SESSION_DIR, "tool-home"),
      },
    });
    await waitForHttpJson<{ status: string }>(`${PROVER_URL}/health`, (body) => body.status === "ok");
    const info = await waitForHttpJson<{
      innerVkHash: string;
      innerCircuitPackage?: string;
      deliverySchemeId?: string;
    }>(
      `${PROVER_URL}/info`,
      (body) => typeof body.innerVkHash === "string" && body.innerVkHash.startsWith("0x"),
    );
    assert.equal(info.innerCircuitPackage, "eip712", "unexpected prover inner circuit package");
    assert.equal(info.deliverySchemeId, "1", "unexpected prover delivery scheme");
    await stopProcess(prover);
    prover = null;

    const pool = new ethers.Contract(POOL_ADDRESS, SHIELDED_POOL_ABI, signer);
    await waitForTx(
      pool["registerUser(uint256,uint256,uint32,bytes)"](
        user.ownerNullifierKeyHash,
        user.noteSecretSeedHash,
        Number(DELIVERY_SCHEME_X_WING),
        user.deliveryPubKey,
      ),
    );
    await waitForTx(
      pool.registerAuthPolicy(BigInt(info.innerVkHash), user.authDataCommitment),
    );

    prover = spawnLogged("prover", "tsx", ["prover/src/index.ts"], {
      env: {
        ...process.env,
        PORT: String(PROVER_PORT),
        RPC_URL,
        POOL_ADDRESS,
        EIP8182_TOOL_HOME: resolve(SESSION_DIR, "tool-home"),
      },
    });
    await waitForHttpJson<{ status: string }>(`${PROVER_URL}/health`, (body) => body.status === "ok");

    const latestBlock = await provider.getBlock("latest");
    const validUntilSeconds = BigInt(latestBlock.timestamp + 3600);
    const nonce = 42n;
    const typedData = buildSingleSigAuthorizationTypedData({
      policyVersion: 1n,
      operationKind: 2n,
      tokenAddress: 0n,
      recipientAddress: signer.address,
      amount: BigInt(DEPOSIT_AMOUNT.toString()),
      feeRecipientAddress: 0n,
      feeAmount: 0n,
      nonce,
      validUntilSeconds,
      executionChainId: 31337n,
    });
    const signature = await signer._signTypedData(
      typedData.domain,
      typedData.types,
      stringifyBigInts(typedData.message),
    );

    const proveResponse = await postJson<{
      proof: string;
      publicInputs: string[];
      outputNoteData: [string, string, string];
      provingTime: string;
    }>(`${PROVER_URL}/prove/deposit`, {
      depositorAddress: signer.address,
      amount: DEPOSIT_AMOUNT.toString(),
      tokenAddress: "0",
      ownerNullifierKey: `0x${NULLIFIER_KEY.toString(16)}`,
      noteSecretSeed: `0x${NOTE_SECRET_SEED.toString(16)}`,
      policyVersion: "1",
      nonce: nonce.toString(),
      validUntilSeconds: validUntilSeconds.toString(),
      executionChainId: "31337",
      executionConstraints: {},
      signature,
    });
    assert.ok(proveResponse.proof.startsWith("0x"), "missing proof");

    const publicInputs = publicInputsStruct(proveResponse.publicInputs);
    const verifierPublicInputs = proveResponse.publicInputs.map((value) =>
      ethers.utils.hexZeroPad(ethers.BigNumber.from(value).toHexString(), 32),
    );
    const verifier = new ethers.Contract(
      VERIFIER_IMPLEMENTATION_ADDRESS,
      HONK_VERIFIER_ABI,
      provider,
    );
    try {
      const verifierAccepted = await verifier.callStatic.verify(
        proveResponse.proof,
        verifierPublicInputs,
      );
      assert.equal(verifierAccepted, true, "verifier implementation rejected proof");
    } catch (error: any) {
      const details = {
        reason: error?.reason,
        errorName: error?.errorName,
        errorSignature: error?.errorSignature,
        code: error?.code,
        data: error?.error?.data ?? error?.data,
      };
      throw new Error(`direct verifier call failed: ${JSON.stringify(details)}`);
    }

    try {
    const precompileCallData = ethers.utils.defaultAbiCoder.encode(
        [
          "bytes",
          "tuple(uint256 noteCommitmentRoot,uint256 nullifier0,uint256 nullifier1,uint256 noteCommitment0,uint256 noteCommitment1,uint256 noteCommitment2,uint256 publicAmountIn,uint256 publicAmountOut,uint256 publicRecipientAddress,uint256 publicTokenAddress,uint256 depositorAddress,uint256 transactionReplayId,uint256 registryRoot,uint256 validUntilSeconds,uint256 executionChainId,uint256 authPolicyRegistryRoot,uint256 outputNoteDataHash0,uint256 outputNoteDataHash1,uint256 outputNoteDataHash2)",
        ],
        [proveResponse.proof, publicInputs],
      );
      const returnData = await provider.call({
        to: PROOF_VERIFY_PRECOMPILE_ADDRESS,
        data: precompileCallData,
      });
      assert.equal(
        ethers.BigNumber.from(returnData).eq(1),
        true,
        "verifier precompile rejected proof",
      );
    } catch (error: any) {
      const details = {
        reason: error?.reason,
        errorName: error?.errorName,
        errorSignature: error?.errorSignature,
        code: error?.code,
        data: error?.error?.data ?? error?.data,
      };
      throw new Error(`direct precompile call failed: ${JSON.stringify(details)}`);
    }

    try {
      await pool.callStatic.transact(
        proveResponse.proof,
        publicInputs,
        proveResponse.outputNoteData[0],
        proveResponse.outputNoteData[1],
        proveResponse.outputNoteData[2],
        { value: publicInputs.publicAmountIn.toString() },
      );
    } catch (error: any) {
      const details = {
        reason: error?.reason,
        errorName: error?.errorName,
        errorSignature: error?.errorSignature,
        code: error?.code,
        data: error?.error?.data ?? error?.data,
      };
      throw new Error(`callStatic transact failed: ${JSON.stringify(details)}`);
    }

    const tx = await pool.transact(
      proveResponse.proof,
      publicInputs,
      proveResponse.outputNoteData[0],
      proveResponse.outputNoteData[1],
      proveResponse.outputNoteData[2],
      { value: publicInputs.publicAmountIn.toString(), gasLimit: 30_000_000 },
    );
    await tx.wait();

    const notesResponse = await fetch(
      `${PROVER_URL}/notes/${signer.address}?ownerNullifierKey=0x${NULLIFIER_KEY.toString(16)}&deliverySecret=0x${DELIVERY_SECRET.toString(16)}`,
    );
    assert.equal(notesResponse.ok, true, "notes endpoint failed");
    const notesJson = (await notesResponse.json()) as {
      notes?: Array<{ amount: string }>;
      balances?: Record<string, string>;
    };
    assert.equal(notesJson.notes?.length, 1, "expected exactly one recovered note");
    assert.equal(notesJson.notes?.[0]?.amount, DEPOSIT_AMOUNT.toString(), "unexpected recovered note amount");

    const poolBalance = await provider.getBalance(POOL_ADDRESS);
    assert.equal(poolBalance.toString(), DEPOSIT_AMOUNT.toString(), "pool balance mismatch after deposit");

    console.log(
      JSON.stringify(
        {
          ok: true,
          provingTime: proveResponse.provingTime,
          noteCount: notesJson.notes?.length ?? 0,
          poolBalance: poolBalance.toString(),
        },
        null,
        2,
      ),
    );
  } catch (error) {
    dumpProcessLogs(prover);
    dumpProcessLogs(anvil);
    throw error;
  } finally {
    await stopProcess(prover);
    await stopProcess(anvil);
  }
}

async function deriveSingleSigUser(_authorizingAddress: string) {
  const helpers = await createPoseidonHelpers();
  const signingKey = hexToBytes(ANVIL_FIRST_PRIVATE_KEY);
  const signingPubKey = secp.getPublicKey(signingKey, false);
  const pubKeyX = signingPubKey.slice(1, 33);
  const pubKeyY = signingPubKey.slice(33, 65);
  const authDataCommitment = singleSigAuthDataCommitment(
    pubKeyX,
    pubKeyY,
    helpers.pHash,
  );
  const ownerNullifierKeyHash = computeOwnerNullifierKeyHash(helpers.pHash, NULLIFIER_KEY);
  const noteSecretSeedHash = computeNoteSecretSeedHash(helpers.pHash, NOTE_SECRET_SEED);
  const { publicKey: deliveryPubKey } = deriveDeliveryKeypair(DELIVERY_SECRET);

  return {
    ownerNullifierKeyHash,
    noteSecretSeedHash,
    authDataCommitment,
    deliveryPubKey: ethers.utils.hexlify(deliveryPubKey),
  };
}

async function installVerifierStack(provider: ethers.providers.JsonRpcProvider) {
  await provider.send("anvil_setCode", [
    POSEIDON_LIBRARY_ADDRESS,
    ensure0x(readFileSync(resolve(REPO_ROOT, "contracts/test/fixtures/poseidon_t3_runtime.hex"), "utf8").trim()),
  ]);

  const transcriptArtifact = readArtifact("contracts/out/HonkVerifier.sol/ZKTranscriptLib.json");
  const transcriptRuntime = patchLibraryRuntimeAddress(
    transcriptArtifact.deployedBytecode.object,
    ZK_TRANSCRIPT_LIBRARY_ADDRESS,
  );
  await provider.send("anvil_setCode", [ZK_TRANSCRIPT_LIBRARY_ADDRESS, transcriptRuntime]);

  const verifierArtifact = readArtifact("contracts/out/HonkVerifier.sol/HonkVerifier.json");
  const signer = provider.getSigner(0);
  const verifierFactory = new ethers.ContractFactory(
    verifierArtifact.abi,
    ensure0x(verifierArtifact.bytecode.object),
    signer,
  );
  const verifier = await verifierFactory.deploy();
  await verifier.deployTransaction.wait();
  const verifierRuntime = await provider.getCode(verifier.address);
  await provider.send("anvil_setCode", [VERIFIER_IMPLEMENTATION_ADDRESS, verifierRuntime]);

  const adapterArtifact = readArtifact(
    "contracts/out/RealProofVerifierPrecompile.sol/RealProofVerifierPrecompile.json",
  );
  const adapterFactory = new ethers.ContractFactory(
    adapterArtifact.abi,
    adapterArtifact.bytecode.object,
    signer,
  );
  const adapter = await adapterFactory.deploy(VERIFIER_IMPLEMENTATION_ADDRESS);
  await adapter.deployTransaction.wait();
  const adapterRuntime = await provider.getCode(adapter.address);
  await provider.send("anvil_setCode", [PROOF_VERIFY_PRECOMPILE_ADDRESS, adapterRuntime]);
}

async function installPool(provider: ethers.providers.JsonRpcProvider) {
  const signer = provider.getSigner(0);
  const harnessArtifact = readArtifact(
    "contracts/out/InstallSystemContracts.s.sol/ShieldedPoolInstallHarness.json",
  );
  const poolArtifact = readArtifact("contracts/out/ShieldedPool.sol/ShieldedPool.json");

  await provider.send("anvil_setCode", [POOL_ADDRESS, ensure0x(harnessArtifact.deployedBytecode.object)]);
  const harness = new ethers.Contract(POOL_ADDRESS, harnessArtifact.abi, signer);
  const initTx = await harness.initialize();
  await initTx.wait();

  await provider.send("anvil_setCode", [POOL_ADDRESS, ensure0x(poolArtifact.deployedBytecode.object)]);
}

function publicInputsStruct(publicInputs: string[]) {
  assert.equal(publicInputs.length, 19, "unexpected public input count");
  return {
    noteCommitmentRoot: BigInt(publicInputs[0]),
    nullifier0: BigInt(publicInputs[1]),
    nullifier1: BigInt(publicInputs[2]),
    noteCommitment0: BigInt(publicInputs[3]),
    noteCommitment1: BigInt(publicInputs[4]),
    noteCommitment2: BigInt(publicInputs[5]),
    publicAmountIn: BigInt(publicInputs[6]),
    publicAmountOut: BigInt(publicInputs[7]),
    publicRecipientAddress: BigInt(publicInputs[8]),
    publicTokenAddress: BigInt(publicInputs[9]),
    depositorAddress: BigInt(publicInputs[10]),
    transactionReplayId: BigInt(publicInputs[11]),
    registryRoot: BigInt(publicInputs[12]),
    validUntilSeconds: BigInt(publicInputs[13]),
    executionChainId: BigInt(publicInputs[14]),
    authPolicyRegistryRoot: BigInt(publicInputs[15]),
    outputNoteDataHash0: BigInt(publicInputs[16]),
    outputNoteDataHash1: BigInt(publicInputs[17]),
    outputNoteDataHash2: BigInt(publicInputs[18]),
  };
}

function stringifyBigInts(value: Record<string, unknown>) {
  return Object.fromEntries(
    Object.entries(value).map(([key, entry]) => [
      key,
      typeof entry === "bigint" ? entry.toString() : entry,
    ]),
  );
}

function readArtifact(relativePath: string) {
  return JSON.parse(readFileSync(resolve(REPO_ROOT, relativePath), "utf8")) as {
    abi: ContractInterface;
    bytecode: { object: string };
    deployedBytecode: { object: string };
  };
}

function patchLibraryRuntimeAddress(runtimeHex: string, address: string): string {
  const runtime = ensure0x(runtimeHex).slice(2);
  const patched = runtime.slice(0, 2) + address.toLowerCase().replace(/^0x/, "") + runtime.slice(42);
  return `0x${patched}`;
}

function ensure0x(value: string) {
  return value.startsWith("0x") ? value : `0x${value}`;
}

async function waitForRpc(provider: ethers.providers.JsonRpcProvider) {
  const started = Date.now();
  while (Date.now() - started < 15_000) {
    try {
      await provider.getBlockNumber();
      return;
    } catch {
      await delay(250);
    }
  }
  throw new Error("anvil did not start");
}

async function waitForHttpJson<T>(
  url: string,
  predicate: (body: T) => boolean,
) {
  const started = Date.now();
  while (Date.now() - started < 60_000) {
    try {
      const response = await fetch(url);
      if (response.ok) {
        const body = (await response.json()) as T;
        if (predicate(body)) return body;
      }
    } catch {}
    await delay(500);
  }
  throw new Error(`timed out waiting for ${url}`);
}

async function postJson<T>(url: string, body: Record<string, unknown>) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const text = await response.text();
  if (!response.ok) {
    throw new Error(`POST ${url} failed: ${text}`);
  }
  return JSON.parse(text) as T;
}

function spawnLogged(
  name: string,
  command: string,
  args: string[],
  options: { env?: NodeJS.ProcessEnv } = {},
): RunningProcess {
  const child = spawn(command, args, {
    cwd: REPO_ROOT,
    env: options.env ?? process.env,
    stdio: ["ignore", "pipe", "pipe"],
  });
  const stdout: string[] = [];
  const stderr: string[] = [];
  child.stdout?.on("data", (chunk) => pushLog(stdout, chunk));
  child.stderr?.on("data", (chunk) => pushLog(stderr, chunk));
  return { child, stdout, stderr, name };
}

function dumpProcessLogs(processRef: RunningProcess | null) {
  if (!processRef) return;
  if (processRef.stdout.length > 0) {
    console.error(`\n[${processRef.name}:stdout]\n${processRef.stdout.join("\n")}`);
  }
  if (processRef.stderr.length > 0) {
    console.error(`\n[${processRef.name}:stderr]\n${processRef.stderr.join("\n")}`);
  }
}

async function stopProcess(processRef: RunningProcess | null) {
  if (!processRef) return;
  if (processRef.child.exitCode !== null) return;
  processRef.child.kill("SIGTERM");
  await Promise.race([
    new Promise((resolve) => processRef.child.once("exit", resolve)),
    delay(5_000),
  ]);
  if (processRef.child.exitCode === null) {
    processRef.child.kill("SIGKILL");
    await new Promise((resolve) => processRef.child.once("exit", resolve));
  }
}

async function waitForTx(txPromise: Promise<ethers.ContractTransaction>) {
  const tx = await txPromise;
  return tx.wait();
}

function pushLog(lines: string[], chunk: Buffer) {
  const next = chunk.toString("utf8").trim();
  if (!next) return;
  lines.push(next);
  if (lines.length > 200) lines.splice(0, lines.length - 200);
}

process.on("uncaughtException", (error) => {
  console.error(error);
  process.exit(1);
});

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
