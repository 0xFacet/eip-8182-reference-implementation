// Computes the deterministic (CREATE2) deployment plan for the canonical
// singletons (spec section 15.2): the Poseidon2 permute library, the privacy
// identity registry, and the canonical pool verifier.
//
//   CREATE2 addr = keccak256(0xff ++ factory ++ salt ++ keccak256(initCode))[12:]
//   factory      = 0x4e59b44847b379578588920ca78fbf26c0b4956c (Arachnid proxy)
//   salts        = keccak256(fixed labels from constants.json)
//
// Freeze order: library (no deps) -> registry + verifier (registry links the
// library; the verifier is dependency-free). Their runtime code hashes become
// the CANONICAL_*_RUNTIME_CODE_HASH constants the pools and SDK pin.
//
// Requires `forge build` to have run. Writes assets/deployment.json, then
// gen_constants.js emits CanonicalAddresses.sol / addresses.ts from it.
//
// Run: node scripts/compute_deployment.js && node scripts/gen_constants.js

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { keccak_256 } from "@noble/hashes/sha3.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ERC = path.resolve(HERE, "..");
const OUT = path.join(ERC, "contracts/out");
const CFG = JSON.parse(fs.readFileSync(path.join(HERE, "constants.json"), "utf8"));

const FACTORY = CFG.createTwoFactory.toLowerCase();

const strip0x = (h) => (h.startsWith("0x") ? h.slice(2) : h);
const hexToBytes = (h) => Uint8Array.from(Buffer.from(strip0x(h), "hex"));
const bytesToHex = (b) => "0x" + Buffer.from(b).toString("hex");
const keccakHex = (h) => bytesToHex(keccak_256(hexToBytes(h)));

function saltFor(label) {
  return bytesToHex(keccak_256(new TextEncoder().encode(label)));
}

function create2Address(salt, initCodeHash) {
  const preimage = "ff" + strip0x(FACTORY) + strip0x(salt) + strip0x(initCodeHash);
  const digest = keccak_256(hexToBytes("0x" + preimage));
  return "0x" + Buffer.from(digest).subarray(12).toString("hex");
}

function loadArtifact(rel) {
  return JSON.parse(fs.readFileSync(path.join(OUT, rel), "utf8"));
}

/// Substitute forge library link placeholders (__$<34 hex>$__) with `address`.
function link(bytecodeObj, libraryAddress) {
  let code = bytecodeObj.object;
  const refs = bytecodeObj.linkReferences ?? {};
  const hasRefs = Object.keys(refs).length > 0;
  if (!hasRefs) return code;
  if (!libraryAddress) throw new Error("artifact has link references but no library address given");
  return code.replace(/__\$[0-9a-f]{34}\$__/g, strip0x(libraryAddress));
}

/// A library with public functions carries a call-protection preamble
/// `PUSH20 <self-address> ADDRESS EQ ...`; the deployed runtime patches the
/// zero placeholder with the CREATE2 address, so the runtime code hash must be
/// computed against the patched bytecode.
function patchLibrarySelfAddress(runtimeHex, address) {
  const placeholder = "73" + "0".repeat(40) + "3014";
  const patched = "73" + strip0x(address).toLowerCase() + "3014";
  const code = strip0x(runtimeHex);
  if (!code.includes(placeholder)) return runtimeHex; // no call protection
  return "0x" + code.replace(placeholder, patched);
}

// ---- 1. Poseidon2 permute library (public library, no dependencies) ----
const libArt = loadArtifact("LibPoseidon2Permute.sol/LibPoseidon2Permute.json");
const libInit = link(libArt.bytecode);
const libSalt = saltFor("erc-app-layer-private-transfers/poseidon2-permute-lib/v1");
const libAddress = create2Address(libSalt, keccakHex(libInit));
const libRuntime = patchLibrarySelfAddress(link(libArt.deployedBytecode), libAddress);

// ---- 2. Privacy identity registry (links the library) ----
const regArt = loadArtifact("PrivacyIdentityRegistry.sol/PrivacyIdentityRegistry.json");
const regInit = link(regArt.bytecode, libAddress);
const regSalt = saltFor(CFG.registrySaltLabel);
const regAddress = create2Address(regSalt, keccakHex(regInit));
const regRuntime = link(regArt.deployedBytecode, libAddress);

// ---- 3. Canonical pool verifier (dependency-free) ----
const verArt = loadArtifact("CanonicalPoolVerifier.sol/CanonicalPoolVerifier.json");
const verInit = link(verArt.bytecode);
const verSalt = saltFor(CFG.poolVerifierSaltLabel);
const verAddress = create2Address(verSalt, keccakHex(verInit));
const verRuntime = link(verArt.deployedBytecode);

// Library runtime code contains no immutables and no self-address references,
// so runtimeCodeHash == keccak(deployedBytecode) exactly. Same for registry
// (storage-only constructor) and verifier (stateless).
const plan = {
  factory: FACTORY,
  poseidonLib: {
    contract: "LibPoseidon2Permute",
    salt: libSalt,
    address: libAddress,
    initCodeHash: keccakHex(libInit),
    runtimeCodeHash: keccakHex(libRuntime),
  },
  registry: {
    contract: "PrivacyIdentityRegistry",
    salt: regSalt,
    address: regAddress,
    initCodeHash: keccakHex(regInit),
    runtimeCodeHash: keccakHex(regRuntime),
  },
  poolVerifier: {
    contract: "CanonicalPoolVerifier",
    salt: verSalt,
    address: verAddress,
    initCodeHash: keccakHex(verInit),
    runtimeCodeHash: keccakHex(verRuntime),
  },
};

const outPath = path.join(ERC, "assets/deployment.json");
const previous = fs.existsSync(outPath) ? JSON.parse(fs.readFileSync(outPath, "utf8")) : null;
fs.writeFileSync(outPath, JSON.stringify(plan, null, 2) + "\n");

// Also stash the linked init codes for the deployer (too large for the plan file).
fs.mkdirSync(path.join(ERC, "build/deploy"), { recursive: true });
fs.writeFileSync(path.join(ERC, "build/deploy/initcodes.json"), JSON.stringify({
  poseidonLib: libInit,
  registry: regInit,
  poolVerifier: verInit,
}, null, 2) + "\n");

console.log("deployment plan:");
for (const key of ["poseidonLib", "registry", "poolVerifier"]) {
  console.log(`  ${key.padEnd(12)} ${plan[key].address} (runtime ${plan[key].runtimeCodeHash.slice(0, 18)}…)`);
}
if (previous) {
  const changed = ["poseidonLib", "registry", "poolVerifier"].filter(
    (k) => previous[k]?.address !== plan[k].address,
  );
  console.log(changed.length ? `CHANGED since last run: ${changed.join(", ")}` : "stable vs previous run");
}
