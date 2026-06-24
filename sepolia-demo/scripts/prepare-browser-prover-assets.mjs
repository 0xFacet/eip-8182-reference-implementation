#!/usr/bin/env node
import { copyFile, mkdir, stat } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const demoRoot = path.resolve(__dirname, "..");
const repoRoot = path.resolve(demoRoot, "..");
const publicProverDir = path.join(demoRoot, "app", "public", "prover");

const assets = [
  ["build/pool/pool_js/pool.wasm", "pool.wasm"],
  ["build/pool/pool_final.zkey", "pool_final.zkey"],
  ["build/pool/pool_vkey.json", "pool_vkey.json"],
  ["circuits-noir/auth/target/auth.json", "auth.json"],
];

await mkdir(publicProverDir, { recursive: true });

for (const [sourceRelative, targetName] of assets) {
  const source = path.join(repoRoot, sourceRelative);
  const target = path.join(publicProverDir, targetName);
  await assertReadable(source);
  await copyFile(source, target);
  console.log(`copied ${sourceRelative} -> app/public/prover/${targetName}`);
}

async function assertReadable(file) {
  try {
    await stat(file);
  } catch (cause) {
    throw new Error(`missing prover asset ${path.relative(repoRoot, file)}; run the circuit builds first`, { cause });
  }
}
