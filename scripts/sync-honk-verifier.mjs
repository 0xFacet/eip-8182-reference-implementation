import { execFileSync } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync, readFileSync, renameSync } from "node:fs";
import os from "node:os";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const repoRoot = resolve(__dirname, "..");
const circuitsDir = resolve(repoRoot, "circuits");
const verifierPath = resolve(repoRoot, "contracts", "test", "generated", "HonkVerifier.sol");
const defaultTmpRoot = resolve(os.tmpdir(), "codex", "honk-verifier");
const toolHome = process.env.EIP8182_TOOL_HOME || resolve(os.tmpdir(), "eip8182-tool-home");
const bbBinary = resolveBbBinary();
const requiredBbVersion = "4.0.0-nightly.20260120";

const args = process.argv.slice(2);
const checkOnly = args.includes("--check");
if (args.length > (checkOnly ? 1 : 0)) {
  throw new Error("usage: node scripts/sync-honk-verifier.mjs [--check]");
}

const env = buildToolEnv();
const runDir = resolve(
  process.env.EIP8182_HONK_VERIFIER_TMPDIR || defaultTmpRoot,
  `run-${Date.now()}-${process.pid}`,
);
const vkDir = resolve(runDir, "vk");
const generatedVerifierPath = resolve(runDir, "HonkVerifier.sol");

mkdirSync(runDir, { recursive: true });

assertBbVersion();
run("nargo", ["compile", "--package", "outer"], { cwd: circuitsDir, env });
run(bbBinary, ["write_vk", "-b", resolve(circuitsDir, "target", "outer.json"), "-o", vkDir, "-t", "evm"], {
  cwd: repoRoot,
  env,
});
run(bbBinary, ["write_solidity_verifier", "-k", resolve(vkDir, "vk"), "-o", generatedVerifierPath, "-t", "evm"], {
  cwd: repoRoot,
  env,
});

const nextVerifier = readFileSync(generatedVerifierPath, "utf8");
const currentVerifier = existsSync(verifierPath) ? readFileSync(verifierPath, "utf8") : null;

if (checkOnly) {
  if (currentVerifier === nextVerifier) {
    console.log("HonkVerifier.sol is up to date.");
    process.exit(0);
  }

  console.error(
    "HonkVerifier.sol is stale. Run `npm run contracts:verifier:refresh` from the repo root or `npm run verifier:refresh` in contracts/.",
  );
  process.exit(1);
}

if (currentVerifier === nextVerifier) {
  console.log("HonkVerifier.sol is already up to date.");
  process.exit(0);
}

mkdirSync(dirname(verifierPath), { recursive: true });
const tmpVerifierPath = `${verifierPath}.tmp-${process.pid}`;
copyFileSync(generatedVerifierPath, tmpVerifierPath);
renameSync(tmpVerifierPath, verifierPath);
console.log(`Updated ${verifierPath}`);

function buildToolEnv() {
  mkdirSync(toolHome, { recursive: true });

  const env = { ...process.env };
  for (const key of Object.keys(env)) {
    if (key.startsWith("npm_") || key.startsWith("BUN_")) delete env[key];
  }
  env.HOME = toolHome;
  env.NARGO_HOME = env.NARGO_HOME || resolve(toolHome, ".nargo");
  return env;
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

function run(command, args, options) {
  execFileSync(command, args, {
    cwd: options.cwd,
    env: options.env,
    stdio: "inherit",
  });
}
