import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { ethers } from "ethers";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const repoRoot = resolve(__dirname, "..");
const circuitsDir = resolve(repoRoot, "circuits");
const contractsDir = resolve(repoRoot, "contracts");
const assetDir = resolve(repoRoot, "assets", "eip-8182");
const shieldedPoolPath = resolve(repoRoot, "contracts", "src", "ShieldedPool.sol");
const tsxBinary = resolve(repoRoot, "node_modules", ".bin", "tsx");
const sharedTmpRoot = resolve("/tmp", "codex");
const toolHome = process.env.EIP8182_TOOL_HOME || resolve(sharedTmpRoot, "eip8182-tool-home");
const defaultTmpRoot = resolve(sharedTmpRoot, "execution-spec-assets");
const bbBinary = resolveBbBinary();
const requiredBbVersion = "4.0.0-nightly.20260120";
const precompileAddress = "0x0000000000000000000000000000000000000030";
const fieldModulus = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const fieldModulusHex = `0x${fieldModulus.toString(16).padStart(64, "0")}`;
const happyPathNote =
  "Verifier-precompile acceptance vector only. This is not a full transact state test.";
const invalidProofNote =
  "Verifier-precompile reject vector. The proof bytes are well-formed but invalid.";
const malformedInputNote =
  "Verifier-precompile reject vector. The calldata is malformed and must return empty bytes.";
const nonCanonicalPrecompileNote =
  "Verifier-precompile reject vector. The public input is non-canonical and must return empty bytes.";
const successReturnData = ethers.utils.defaultAbiCoder.encode(["uint256"], [1]);
const byteStableAssetFiles = [
  "shielded-pool-state.json",
  "poseidon2_bn254_t4_rf8_rp56.json",
  "poseidon2_vectors.json",
  "delivery_scheme1_vectors.json",
  "outer_vk.bin",
  "outer_vk.sha256",
  "outer_vk.bb_hash.hex",
  "outer_verifier_transcript_vk_hash.hex",
  "outer_verifier_metadata.json",
  "outer_precompile_malformed_input.json",
];
const semanticAssetFiles = [
  "outer_precompile_happy_path.json",
  "outer_precompile_invalid_proof.json",
  "outer_precompile_noncanonical_field.json",
];

const args = process.argv.slice(2);
const checkOnly = args.includes("--check");
if (args.length > (checkOnly ? 1 : 0)) {
  throw new Error("usage: node scripts/sync-execution-spec-assets.mjs [--check]");
}

const env = buildToolEnv();
const runName = `run-${Date.now()}-${process.pid}`;
const runDir = resolve(
  process.env.EIP8182_EXECUTION_SPEC_ASSETS_TMPDIR || defaultTmpRoot,
  runName,
);
const outputDir = resolve(runDir, "output");
const installerRelativeDir = `script-output/execution-spec-assets/${runName}`;
const installerDir = resolve(contractsDir, installerRelativeDir);
const vkDir = resolve(runDir, "vk");
const verifierPath = resolve(runDir, "HonkVerifier.sol");
const verifierFixturePath = resolve(runDir, "verifier-fixture.json");
const manifestPathForForge = `${installerRelativeDir}/shielded-pool-install.json`;
const stateDumpPath = resolve(installerDir, "shielded-pool-state.json");
const stateDumpPathForForge = `${installerRelativeDir}/shielded-pool-state.json`;

mkdirSync(outputDir, { recursive: true });
mkdirSync(installerDir, { recursive: true });
assertBbVersion();

run(
  "forge",
  ["script", "script/InstallSystemContracts.s.sol:InstallSystemContracts"],
  {
    cwd: contractsDir,
    env: {
      ...env,
      INSTALL_MANIFEST_PATH: manifestPathForForge,
      STATE_DUMP_PATH: stateDumpPathForForge,
    },
  },
);
run("nargo", ["compile", "--package", "outer"], {
  cwd: circuitsDir,
  env,
});
run(
  bbBinary,
  ["write_vk", "-b", resolve(circuitsDir, "target", "outer.json"), "-o", vkDir, "-t", "evm"],
  {
    cwd: repoRoot,
    env,
  },
);
run(
  bbBinary,
  ["write_solidity_verifier", "-k", resolve(vkDir, "vk"), "-o", verifierPath, "-t", "evm"],
  {
    cwd: repoRoot,
    env,
  },
);
run(tsxBinary, ["integration/src/generate_verifier_test_fixture.ts", verifierFixturePath], {
  cwd: repoRoot,
  env,
});

const bbVersion = execFileSync(bbBinary, ["--version"], {
  cwd: repoRoot,
  env,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "inherit"],
}).trim();

run(
  tsxBinary,
  [
    "integration/src/generate_execution_spec_vectors.ts",
    outputDir,
    verifierFixturePath,
    bbVersion,
  ],
  {
    cwd: repoRoot,
    env,
  },
);

const vkBytes = readFileSync(resolve(vkDir, "vk"));
const bbVkHashBuffer = readFileSync(resolve(vkDir, "vk_hash"));
const bbVkHashHex = `0x${bbVkHashBuffer.toString("hex")}`;
const verifierSource = readFileSync(verifierPath, "utf8");
const verifierConstants = parseVerifierConstants(verifierSource);
const poolPublicInputsOrder = parsePoolPublicInputsOrder(readFileSync(shieldedPoolPath, "utf8"));
const happyPathFixture = JSON.parse(readFileSync(verifierFixturePath, "utf8"));
const proofLengthBytes = hexByteLength(happyPathFixture.proof);
const expectedProofLengthBytes = calculateExpectedProofLengthBytes(verifierConstants);

if (proofLengthBytes !== expectedProofLengthBytes) {
  throw new Error(
    `proof length mismatch: fixture=${proofLengthBytes} verifier=${expectedProofLengthBytes}`,
  );
}
if (
  verifierConstants.numberOfPublicInputs !==
  poolPublicInputsOrder.length + verifierConstants.pairingPointsSize
) {
  throw new Error(
    `public input count mismatch: verifier=${verifierConstants.numberOfPublicInputs} pool=${poolPublicInputsOrder.length} pairing=${verifierConstants.pairingPointsSize}`,
  );
}

const transcriptVkHashHex = verifierConstants.vkHash;
const metadata = buildMetadata(
  verifierConstants,
  poolPublicInputsOrder,
  proofLengthBytes,
  bbVersion,
  bbVkHashHex,
  transcriptVkHashHex,
);

copyFileSync(stateDumpPath, resolve(outputDir, "shielded-pool-state.json"));
copyFileSync(resolve(vkDir, "vk"), resolve(outputDir, "outer_vk.bin"));
writeFileSync(
  resolve(outputDir, "outer_vk.sha256"),
  `${createHash("sha256").update(vkBytes).digest("hex")}\n`,
);
writeFileSync(resolve(outputDir, "outer_vk.bb_hash.hex"), `${bbVkHashHex}\n`);
writeFileSync(
  resolve(outputDir, "outer_verifier_transcript_vk_hash.hex"),
  `${transcriptVkHashHex}\n`,
);
writeFileSync(resolve(outputDir, "outer_verifier_metadata.json"), `${stableStringify(metadata)}\n`);

if (checkOnly) {
  const drift = byteStableAssetFiles.filter((name) => {
    const next = resolve(outputDir, name);
    const current = resolve(assetDir, name);
    return !existsSync(current) || !readFileSync(current).equals(readFileSync(next));
  });
  const semanticIssues = [
    ...validateCommittedHappyPath(
      resolve(assetDir, "outer_precompile_happy_path.json"),
      poolPublicInputsOrder,
      proofLengthBytes,
      bbVersion,
    ).map((issue) => `outer_precompile_happy_path.json: ${issue}`),
    ...validateCommittedInvalidProof(
      resolve(assetDir, "outer_precompile_invalid_proof.json"),
      poolPublicInputsOrder,
      proofLengthBytes,
      bbVersion,
    ).map((issue) => `outer_precompile_invalid_proof.json: ${issue}`),
    ...validateCommittedNonCanonicalPrecompile(
      resolve(assetDir, "outer_precompile_noncanonical_field.json"),
      poolPublicInputsOrder,
      proofLengthBytes,
      bbVersion,
    ).map((issue) => `outer_precompile_noncanonical_field.json: ${issue}`),
  ];

  if (semanticIssues.length > 0) {
    drift.push(...semanticAssetFiles.filter((name) => !drift.includes(name)));
  }

  if (drift.length === 0) {
    console.log("execution-spec assets are up to date.");
    process.exit(0);
  }

  for (const issue of semanticIssues) {
    console.error(issue);
  }
  console.error(
    `execution-spec assets are stale: ${Array.from(new Set(drift)).join(", ")}. Run \`npm run execution-spec-assets:refresh\`.`,
  );
  process.exit(1);
}

mkdirSync(assetDir, { recursive: true });
for (const name of [...byteStableAssetFiles, ...semanticAssetFiles]) {
  const nextPath = resolve(outputDir, name);
  const targetPath = resolve(assetDir, name);
  const tmpPath = `${targetPath}.tmp-${process.pid}`;
  copyFileSync(nextPath, tmpPath);
  renameSync(tmpPath, targetPath);
}

console.log(`updated execution-spec assets in ${assetDir}`);

function buildToolEnv() {
  mkdirSync(toolHome, { recursive: true });

  const nextEnv = { ...process.env };
  for (const key of Object.keys(nextEnv)) {
    if (key.startsWith("npm_") || key.startsWith("BUN_")) delete nextEnv[key];
  }
  nextEnv.HOME = toolHome;
  nextEnv.NARGO_HOME = nextEnv.NARGO_HOME || resolve(toolHome, ".nargo");
  nextEnv.BB_BINARY = nextEnv.BB_BINARY || bbBinary;
  return nextEnv;
}

function resolveBbBinary() {
  if (process.env.BB_BINARY) return process.env.BB_BINARY;

  const defaultPath = resolve(os.homedir(), ".bb", "bb");
  return existsSync(defaultPath) ? defaultPath : "bb";
}

function assertBbVersion() {
  const raw = execFileSync(bbBinary, ["--version"], {
    env,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "inherit"],
  }).trim();

  if (raw !== requiredBbVersion) {
    throw new Error(
      `bb version mismatch: got "${raw}", expected "${requiredBbVersion}". Install the correct version or set BB_BINARY.`,
    );
  }
}

function run(command, commandArgs, options) {
  execFileSync(command, commandArgs, {
    cwd: options.cwd,
    env: options.env,
    stdio: "inherit",
  });
}

function parseVerifierConstants(source) {
  const n = parseDecimalConstant(source, "N");
  const logN = parseDecimalConstant(source, "LOG_N");
  const numberOfPublicInputs = parseDecimalConstant(source, "NUMBER_OF_PUBLIC_INPUTS");
  const pairingPointsSize = parseDecimalConstant(source, "PAIRING_POINTS_SIZE");
  const zkBatchedRelationPartialLength = parseDecimalConstant(
    source,
    "ZK_BATCHED_RELATION_PARTIAL_LENGTH",
  );
  const numberOfEntities = parseDecimalConstant(source, "NUMBER_OF_ENTITIES");
  const numMaskingPolynomials = parseDecimalConstant(source, "NUM_MASKING_POLYNOMIALS");
  const numLibraEvaluations = parseDecimalConstant(source, "NUM_LIBRA_EVALUATIONS");
  const vkHash = parseHexConstant(source, "VK_HASH");

  return {
    logN,
    n,
    numLibraEvaluations,
    numMaskingPolynomials,
    numberOfEntities,
    numberOfPublicInputs,
    pairingPointsSize,
    vkHash,
    zkBatchedRelationPartialLength,
  };
}

function parseDecimalConstant(source, name) {
  const match = source.match(new RegExp(`uint256 constant ${name} = (\\d+);`));
  if (!match) throw new Error(`missing verifier constant ${name}`);
  return Number(match[1]);
}

function parseHexConstant(source, name) {
  const match = source.match(new RegExp(`uint256 constant ${name} = (0x[0-9a-fA-F]+);`));
  if (!match) throw new Error(`missing verifier constant ${name}`);
  return match[1].toLowerCase();
}

function parsePoolPublicInputsOrder(source) {
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

function calculateExpectedProofLengthBytes(constants) {
  const numWitnessEntities = 8 + constants.numMaskingPolynomials;
  const numElementsComm = 2;
  const numElementsFr = 1;
  const numberOfEntitiesZk = constants.numberOfEntities + constants.numMaskingPolynomials;
  let proofLength = numWitnessEntities * numElementsComm;
  proofLength += numElementsComm * 3;
  proofLength += constants.logN * constants.zkBatchedRelationPartialLength * numElementsFr;
  proofLength += numberOfEntitiesZk * numElementsFr;
  proofLength += numElementsFr * 2;
  proofLength += constants.logN * numElementsFr;
  proofLength += constants.numLibraEvaluations * numElementsFr;
  proofLength += (constants.logN - 1) * numElementsComm;
  proofLength += numElementsComm * 2;
  proofLength += constants.pairingPointsSize;
  return proofLength * 32;
}

function buildMetadata(
  verifierConstants,
  poolPublicInputsOrder,
  proofLengthBytes,
  bbVersion,
  bbVkHashHex,
  transcriptVkHashHex,
) {
  return {
    bbVersion,
    bbVkHashHex,
    circuitSize: verifierConstants.n,
    curve: "bn254",
    logCircuitSize: verifierConstants.logN,
    pairingPointsSize: verifierConstants.pairingPointsSize,
    poolPublicInputsCount: poolPublicInputsOrder.length,
    poolPublicInputsOrder,
    precompileAddress,
    precompileInputEncoding: "abi.encode(bytes proof, PublicInputs publicInputs)",
    proofLengthBytes,
    proofSystem: "ultra_honk_bn254",
    transcriptVkHashHex,
    verifierPublicInputsCount: verifierConstants.numberOfPublicInputs,
  };
}

function validateCommittedHappyPath(assetPath, order, proofLengthBytes, bbVersion) {
  return validatePrecompileVector(assetPath, order, proofLengthBytes, bbVersion, {
    expectedReturnData: successReturnData,
    note: happyPathNote,
    requireProof: true,
  });
}

function validateCommittedInvalidProof(assetPath, order, proofLengthBytes, bbVersion) {
  return validatePrecompileVector(assetPath, order, proofLengthBytes, bbVersion, {
    expectedReturnData: "0x",
    note: invalidProofNote,
    requireProof: true,
  });
}

function validatePrecompileVector(
  assetPath,
  order,
  proofLengthBytes,
  bbVersion,
  { expectedReturnData, note, requireProof },
) {
  if (!existsSync(assetPath)) {
    return ["missing file"];
  }

  let vector;
  try {
    vector = JSON.parse(readFileSync(assetPath, "utf8"));
  } catch (error) {
    return [`invalid JSON: ${error.message}`];
  }

  const issues = [];
  if (vector.bbVersion !== bbVersion) {
    issues.push(`bbVersion mismatch: got "${vector.bbVersion}", expected "${bbVersion}"`);
  }
  if (vector.expectedReturnData !== expectedReturnData) {
    issues.push("expectedReturnData mismatch");
  }
  if (vector.note !== note) {
    issues.push("note mismatch");
  }
  if (typeof vector.precompileInput !== "string" || !vector.precompileInput.startsWith("0x")) {
    issues.push("precompileInput must be a hex string");
  }

  if (requireProof) {
    if (vector.proofLengthBytes !== proofLengthBytes) {
      issues.push(
        `proofLengthBytes mismatch: got ${vector.proofLengthBytes}, expected ${proofLengthBytes}`,
      );
    }
    if (typeof vector.proof !== "string") {
      issues.push("proof must be a hex string");
    } else if (hexByteLength(vector.proof) !== proofLengthBytes) {
      issues.push(
        `proof byte length mismatch: got ${hexByteLength(vector.proof)}, expected ${proofLengthBytes}`,
      );
    }
    issues.push(...validatePublicInputsObject(vector.publicInputs, order));

    if (issues.length === 0) {
      const expectedPrecompileInput = encodePrecompileInput(order, vector.proof, vector.publicInputs);
      if (vector.precompileInput !== expectedPrecompileInput) {
        issues.push("precompileInput mismatch");
      }
    }
  }

  return issues;
}

function validateCommittedNonCanonicalPrecompile(assetPath, order, proofLengthBytes, bbVersion) {
  const issues = validatePrecompileVector(assetPath, order, proofLengthBytes, bbVersion, {
    expectedReturnData: "0x",
    note: nonCanonicalPrecompileNote,
    requireProof: true,
  });
  if (issues.length > 0) {
    return issues;
  }

  const vector = JSON.parse(readFileSync(assetPath, "utf8"));
  if (vector.fieldModulus !== fieldModulusHex) {
    issues.push("fieldModulus mismatch");
  }
  if (vector.field !== "noteCommitmentRoot") {
    issues.push(`unexpected mutated field: ${vector.field}`);
  }
  if (vector.publicInputs?.noteCommitmentRoot) {
    const mutatedValue = BigInt(vector.publicInputs.noteCommitmentRoot);
    if (mutatedValue < fieldModulus) {
      issues.push("noteCommitmentRoot must be non-canonical (>= p)");
    }
  }
  return issues;
}

function validatePublicInputsObject(publicInputs, order) {
  const issues = [];
  if (!publicInputs || typeof publicInputs !== "object" || Array.isArray(publicInputs)) {
    issues.push("publicInputs must be an object");
    return issues;
  }

  const actualKeys = Object.keys(publicInputs).sort();
  const expectedKeys = [...order].sort();
  if (actualKeys.length !== expectedKeys.length) {
    issues.push(
      `public input key count mismatch: got ${actualKeys.length}, expected ${expectedKeys.length}`,
    );
    return issues;
  }
  for (let index = 0; index < expectedKeys.length; index += 1) {
    if (actualKeys[index] !== expectedKeys[index]) {
      issues.push(
        `public input keys mismatch: got [${actualKeys.join(", ")}], expected [${expectedKeys.join(", ")}]`,
      );
      return issues;
    }
  }

  for (const name of order) {
    const value = publicInputs[name];
    if (typeof value !== "string") {
      issues.push(`publicInputs.${name} must be a hex string`);
      continue;
    }
    if (hexByteLength(value) !== 32) {
      issues.push(`publicInputs.${name} must be 32 bytes`);
    }
  }

  return issues;
}

function encodePrecompileInput(order, proof, publicInputs) {
  const tupleType = `tuple(${order.map((name) => `uint256 ${name}`).join(",")})`;
  return ethers.utils.defaultAbiCoder.encode(
    ["bytes", tupleType],
    [proof, order.map((name) => publicInputs[name])],
  );
}

function hexByteLength(hex) {
  const normalized = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (normalized.length % 2 !== 0) {
    throw new Error("hex string has odd length");
  }
  return normalized.length / 2;
}

function stableStringify(value) {
  return JSON.stringify(sortJsonValue(value), null, 2);
}

function sortJsonValue(value) {
  if (Array.isArray(value)) return value.map(sortJsonValue);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, sortJsonValue(value[key])]),
    );
  }
  return value;
}
