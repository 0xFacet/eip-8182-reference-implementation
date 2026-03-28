import { execFileSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const repoRoot = resolve(__dirname, "..");
const tsxBin = resolve(repoRoot, "node_modules", ".bin", "tsx");
const target = resolve(repoRoot, "integration", "src", "benchmark_eip712_proofs.ts");

execFileSync(tsxBin, [target, ...process.argv.slice(2)], {
  cwd: repoRoot,
  env: process.env,
  stdio: "inherit",
});
