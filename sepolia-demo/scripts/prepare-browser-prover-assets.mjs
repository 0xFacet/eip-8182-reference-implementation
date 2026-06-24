#!/usr/bin/env node
import { copyFile, mkdir, stat } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const demoRoot = path.resolve(__dirname, "..");
const repoRoot = path.resolve(demoRoot, "..");
const publicProverDir = path.join(demoRoot, "app", "public", "prover");

const assets = [
  {
    sources: ["build/pool/pool_js/pool.wasm", "demo/assets/pool.wasm"],
    targetName: "pool.wasm",
  },
  {
    sources: ["build/pool/pool_final.zkey", "demo/assets/pool_final.zkey"],
    targetName: "pool_final.zkey",
  },
  {
    sources: ["build/pool/pool_vkey.json", "demo/assets/pool_vkey.json"],
    targetName: "pool_vkey.json",
  },
  {
    sources: ["circuits-noir/auth/target/auth.json", "demo/assets/auth.json"],
    targetName: "auth.json",
  },
];

await mkdir(publicProverDir, { recursive: true });

for (const { sources, targetName } of assets) {
  const { source, sourceRelative } = await findReadableSource(sources);
  const target = path.join(publicProverDir, targetName);
  await copyFile(source, target);
  console.log(`copied ${sourceRelative} -> app/public/prover/${targetName}`);
}

async function findReadableSource(sourceRelatives) {
  const attempted = [];
  let lastCause;
  for (const sourceRelative of sourceRelatives) {
    const source = path.join(repoRoot, sourceRelative);
    attempted.push(sourceRelative);
    try {
      await stat(source);
      return { source, sourceRelative };
    } catch (cause) {
      lastCause = cause;
    }
  }
  throw new Error(`missing prover asset; checked ${attempted.join(", ")}; run the circuit builds first or commit demo/assets`, { cause: lastCause });
}
