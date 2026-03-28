import { spawn } from "node:child_process";
import { appendFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const [, , scriptPath, params, timeoutMsArg] = process.argv;

if (!scriptPath || params === undefined) {
  process.stderr.write("usage: node run_tsx_with_timeout.mjs <script-path> <json-params> [timeout-ms]\n");
  process.exit(2);
}

const timeoutMs = Number(timeoutMsArg ?? "900000");
if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
  process.stderr.write(`invalid timeout: ${timeoutMsArg}\n`);
  process.exit(2);
}
const timingEnabled =
  !!process.env.EIP8182_FFI_TIMING &&
  process.env.EIP8182_FFI_TIMING !== "0" &&
  process.env.EIP8182_FFI_TIMING.toLowerCase() !== "false";
const timingFile = process.env.EIP8182_FFI_TIMING_FILE;

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const repoRoot = resolve(__dirname, "../../..");
const tsxBin = resolve(repoRoot, "node_modules/.bin/tsx");

const child = spawn(tsxBin, [scriptPath, params], {
  cwd: process.cwd(),
  env: process.env,
  stdio: ["ignore", "pipe", "pipe"],
});
const startedAt = Date.now();

let timedOut = false;
const timer = setTimeout(() => {
  timedOut = true;
  child.kill("SIGKILL");
}, timeoutMs);

child.stdout.on("data", (chunk) => process.stdout.write(chunk));
child.stderr.on("data", (chunk) => process.stderr.write(chunk));

child.on("error", (error) => {
  clearTimeout(timer);
  process.stderr.write(`${error.message}\n`);
  process.exit(1);
});

child.on("close", (code, signal) => {
  clearTimeout(timer);
  recordTiming(Date.now() - startedAt, code, signal);
  if (timedOut) {
    process.stderr.write(`ffi script timed out after ${timeoutMs}ms: ${scriptPath}\n`);
    process.exit(124);
  }
  if (signal) {
    process.stderr.write(`ffi script exited from signal ${signal}: ${scriptPath}\n`);
    process.exit(1);
  }
  process.exit(code ?? 1);
});

function recordTiming(durationMs, code, signal) {
  if (!timingEnabled || !timingFile) return;

  let mode = "";
  try {
    const parsed = JSON.parse(params);
    if (parsed && typeof parsed === "object" && typeof parsed.mode === "string") {
      mode = parsed.mode;
    }
  } catch {}

  appendFileSync(
    timingFile,
    JSON.stringify({
      scriptPath,
      mode,
      durationMs,
      exitCode: code ?? -1,
      signal: signal ?? null,
      timedOut,
      startedAt: new Date(startedAt).toISOString(),
      finishedAt: new Date().toISOString(),
    }) + "\n",
  );
}
