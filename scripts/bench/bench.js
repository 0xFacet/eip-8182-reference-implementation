#!/usr/bin/env node
// End-to-end realistic-transfer prove-time benchmark.
//
// What it measures:
//   - pool proof prove time (Groth16/BN254): rapidsnark `prover` binary if on
//     PATH (preferred, native), else snarkjs.groth16.prove (WASM, ~10x slower
//     but always available).
//   - auth proof prove time (UltraHonk): `bb prove --scheme ultra_honk`.
//   - witness-generation time, prove time, and verify time per trial.
//   - peak RSS per prove call (macOS: /usr/bin/time -l, Linux: -v).
//
// What it reports:
//   - p50/p95/min/max/mean for each stage over N trials.
//   - wallet-side e2e: pool prove + auth prove (the user-experienced number).
//   - tooling versions (nargo, bb, rapidsnark or snarkjs), CPU model, cores,
//     RAM, OS — for reproducibility.
//   - proof bytes, public-input bytes for both circuits.
//
// Usage:
//   node scripts/bench/bench.js [--trials=10] [--rapidsnark=/path/to/prover]

const fs = require("fs");
const path = require("path");
const os = require("os");
const { spawnSync, spawn } = require("child_process");

const ROOT = path.resolve(__dirname, "..", "..");
const REAL_DIR = path.join(ROOT, "build", "integration_real");
const POOL_INPUT = path.join(REAL_DIR, "pool_input.json");
const POOL_WTNS = path.join(REAL_DIR, "pool.wtns");
const POOL_BUILD = path.join(ROOT, "build", "pool");
const NOIR_AUTH_DIR = path.join(ROOT, "circuits-noir", "auth");

function arg(name, fallback) {
  const flag = process.argv.find(a => a.startsWith(`--${name}=`));
  return flag ? flag.slice(name.length + 3) : fallback;
}

const TRIALS = Number(arg("trials", "1"));
const RAPIDSNARK = arg("rapidsnark", findOnPath("prover") || findOnPath("rapidsnark"));

function findOnPath(name) {
  const r = spawnSync("which", [name], { encoding: "utf8" });
  return r.status === 0 ? r.stdout.trim() : null;
}

function run(cmd, args, opts = {}) {
  const r = spawnSync(cmd, args, { stdio: "inherit", cwd: opts.cwd || ROOT, ...opts });
  if (r.status !== 0) throw new Error(`${cmd} ${args.join(" ")} -> ${r.status}`);
}

function captureVersion(cmd, args) {
  const r = spawnSync(cmd, args, { stdio: "pipe", encoding: "utf8" });
  return (r.stdout || r.stderr || "").trim().split("\n")[0];
}

// Spawn a command under /usr/bin/time so we can recover peak RSS.
// Returns { wall_ms, peak_rss_kb }.
async function timedRun(cmd, args, opts = {}) {
  const isMac = process.platform === "darwin";
  const timeBin = "/usr/bin/time";
  const timeArgs = isMac ? ["-l", cmd, ...args] : ["-v", cmd, ...args];

  return new Promise((resolve, reject) => {
    const start = process.hrtime.bigint();
    const child = spawn(timeBin, timeArgs, { cwd: opts.cwd || ROOT, stdio: ["ignore", "pipe", "pipe"] });
    let stderr = "";
    child.stdout.on("data", () => {});
    child.stderr.on("data", b => { stderr += b.toString(); });
    child.on("error", reject);
    child.on("close", code => {
      const wall_ms = Number(process.hrtime.bigint() - start) / 1e6;
      if (code !== 0) {
        return reject(new Error(`${cmd} exited ${code}; stderr:\n${stderr.slice(-1500)}`));
      }
      // Parse peak RSS.
      let peak_rss_kb = null;
      if (isMac) {
        // BSD time prints e.g. "      5263360  maximum resident set size"; bytes.
        const m = stderr.match(/(\d+)\s+maximum resident set size/);
        if (m) peak_rss_kb = Math.round(Number(m[1]) / 1024);
      } else {
        // GNU time -v prints "Maximum resident set size (kbytes): NNN".
        const m = stderr.match(/Maximum resident set size \(kbytes\):\s+(\d+)/);
        if (m) peak_rss_kb = Number(m[1]);
      }
      resolve({ wall_ms, peak_rss_kb });
    });
  });
}

function pct(arr, p) {
  const sorted = arr.slice().sort((a, b) => a - b);
  const idx = Math.min(sorted.length - 1, Math.floor(sorted.length * p / 100));
  return sorted[idx];
}

function stats(samples) {
  if (samples.length === 0) return null;
  const sum = samples.reduce((a, b) => a + b, 0);
  return {
    n: samples.length,
    min:  Math.min(...samples),
    max:  Math.max(...samples),
    mean: +(sum / samples.length).toFixed(2),
    p50:  pct(samples, 50),
    p95:  pct(samples, 95),
  };
}

(async () => {
  console.log(`==> tooling`);
  const nargoVer = captureVersion("nargo", ["--version"]);
  const bbVer    = captureVersion("bb",    ["--version"]);
  const snarkjsVer = (() => {
    try { return require(path.join(ROOT, "node_modules/snarkjs/package.json")).version; }
    catch { return null; }
  })();
  const rapidVer = RAPIDSNARK ? captureVersion(RAPIDSNARK, ["--version"]) : null;
  console.log("    nargo    :", nargoVer);
  console.log("    bb       :", bbVer);
  console.log("    snarkjs  :", snarkjsVer);
  console.log("    rapidsnark:", RAPIDSNARK || "(not on PATH; using snarkjs WASM)");
  console.log("    cpu      :", os.cpus()[0]?.model, `x ${os.cpus().length}`);
  console.log("    ram      :", `${(os.totalmem() / 1e9).toFixed(1)} GB`);
  console.log("    os       :", `${os.type()} ${os.release()}`);
  console.log();

  console.log(`==> setup (one-time): generate witnesses + VKs`);
  // Same coordination as build_real_session.js: prover.toml round 1, pool
  // witness, prover.toml round 2 (with locked bindings), pool witness regen.
  run("node", ["scripts/noir/gen_prover_toml.js"]);
  run("node", ["scripts/noir/gen_real_pool_witness_input.js"]);
  const poolInput1 = JSON.parse(fs.readFileSync(POOL_INPUT, "utf8"));
  const sharedIntentPath = path.join(REAL_DIR, "shared_for_auth.json");
  fs.writeFileSync(sharedIntentPath, JSON.stringify({
    auth_verifier_addr: poolInput1.authVerifier,
    blinding_factor: poolInput1.blindingFactor,
    locked_output_bindings: [
      poolInput1.outLockedOutputBinding[0],
      poolInput1.outLockedOutputBinding[1],
      poolInput1.outLockedOutputBinding[2],
    ],
    intent: {
      auth_verifier:               poolInput1.authVerifier,
      authorizing_address:         poolInput1.authorizingAddress,
      operation_kind:              "0",
      token_address:               poolInput1.tokenAddress,
      recipient_address:           poolInput1.recipientAddress,
      amount:                      poolInput1.outAmount[0],
      fee_recipient_address:       poolInput1.feeRecipientAddress,
      fee_amount:                  poolInput1.feeAmount,
      execution_constraints_flags: poolInput1.executionConstraintsFlags,
      locked_output_binding0:      poolInput1.outLockedOutputBinding[0],
      locked_output_binding1:      poolInput1.outLockedOutputBinding[1],
      locked_output_binding2:      poolInput1.outLockedOutputBinding[2],
      nonce_bytes:                 bigintToBytes(BigInt(poolInput1.nonce), 32),
      valid_until_seconds:         poolInput1.validUntilSeconds,
      execution_chain_id:          poolInput1.executionChainId,
    },
  }, null, 2));
  run("node", ["scripts/noir/gen_prover_toml.js", sharedIntentPath]);
  run("node", ["scripts/noir/gen_real_pool_witness_input.js"]);

  // Pool witness binary (Circom wasm).
  run("node", [
    path.join(POOL_BUILD, "pool_js/generate_witness.js"),
    path.join(POOL_BUILD, "pool_js/pool.wasm"),
    POOL_INPUT,
    POOL_WTNS,
  ]);

  // Auth witness (Noir).
  run("nargo", ["execute", "auth"], { cwd: NOIR_AUTH_DIR });

  // bb VK (also writes target/vk).
  run("bb", ["write_vk", "--scheme", "ultra_honk", "-b", "target/auth.json",
    "-t", "evm", "-o", "target"], { cwd: NOIR_AUTH_DIR });

  // ---- pool witness binary size, auth witness size ----
  const poolWtnsSize = fs.statSync(POOL_WTNS).size;
  const authWtnsSize = fs.statSync(path.join(NOIR_AUTH_DIR, "target/auth.gz")).size;

  console.log(`==> trials: ${TRIALS} per circuit`);

  // ---- pool prove trials ----
  const poolMethod = RAPIDSNARK ? "rapidsnark (native)" : "snarkjs (WASM)";
  console.log(`    pool prover: ${poolMethod}`);
  const poolSamples = { wall_ms: [], rss_kb: [] };
  for (let i = 0; i < TRIALS; i++) {
    let r;
    if (RAPIDSNARK) {
      r = await timedRun(RAPIDSNARK, [
        path.join(POOL_BUILD, "pool_final.zkey"),
        POOL_WTNS,
        path.join(REAL_DIR, "pool_proof.json"),
        path.join(REAL_DIR, "pool_publics.json"),
      ]);
    } else {
      // snarkjs CLI: faster than the JS API (no warmup overhead).
      r = await timedRun(path.join(ROOT, "node_modules/.bin/snarkjs"), [
        "groth16", "prove",
        path.join(POOL_BUILD, "pool_final.zkey"),
        POOL_WTNS,
        path.join(REAL_DIR, "pool_proof.json"),
        path.join(REAL_DIR, "pool_publics.json"),
      ]);
    }
    poolSamples.wall_ms.push(r.wall_ms);
    if (r.peak_rss_kb != null) poolSamples.rss_kb.push(r.peak_rss_kb);
    process.stdout.write(`    pool ${i + 1}/${TRIALS}: ${r.wall_ms.toFixed(0)} ms\n`);
  }

  // ---- auth prove trials ----
  console.log(`    auth prover: bb ultra_honk`);
  const authSamples = { wall_ms: [], rss_kb: [] };
  for (let i = 0; i < TRIALS; i++) {
    const r = await timedRun("bb", [
      "prove", "--scheme", "ultra_honk",
      "-b", "target/auth.json",
      "-w", "target/auth.gz",
      "-o", "target", "-t", "evm",
    ], { cwd: NOIR_AUTH_DIR });
    authSamples.wall_ms.push(r.wall_ms);
    if (r.peak_rss_kb != null) authSamples.rss_kb.push(r.peak_rss_kb);
    process.stdout.write(`    auth ${i + 1}/${TRIALS}: ${r.wall_ms.toFixed(0)} ms\n`);
  }

  // ---- single-shot verifies (just to capture verify time + sizes) ----
  const poolVerifyT = await timedRun(path.join(ROOT, "node_modules/.bin/snarkjs"), [
    "groth16", "verify",
    path.join(POOL_BUILD, "pool_vkey.json"),
    path.join(REAL_DIR, "pool_publics.json"),
    path.join(REAL_DIR, "pool_proof.json"),
  ]);
  const authVerifyT = await timedRun("bb", [
    "verify", "--scheme", "ultra_honk",
    "-k", path.join(NOIR_AUTH_DIR, "target/vk"),
    "-p", path.join(NOIR_AUTH_DIR, "target/proof"),
    "-i", path.join(NOIR_AUTH_DIR, "target/public_inputs"),
    "-t", "evm",
  ]);

  const authProofBytes = fs.statSync(path.join(NOIR_AUTH_DIR, "target/proof")).size;
  const authPubBytes = fs.statSync(path.join(NOIR_AUTH_DIR, "target/public_inputs")).size;
  // Pool proof JSON is not byte-canonical; canonical Groth16 = 256 B.
  const poolProofBytes = 256;
  const poolPubBytes = 21 * 32;

  // ---- assemble output ----
  const summary = {
    target: {
      cpu: os.cpus()[0]?.model,
      cores: os.cpus().length,
      ram_gb: +(os.totalmem() / 1e9).toFixed(1),
      os: `${os.type()} ${os.release()}`,
      arch: os.arch(),
    },
    tooling: {
      nargo: nargoVer,
      bb: bbVer,
      snarkjs: snarkjsVer,
      rapidsnark: rapidVer,
      pool_prover: poolMethod,
    },
    pool: {
      proof_bytes: poolProofBytes,
      public_inputs_bytes: poolPubBytes,
      witness_bytes: poolWtnsSize,
      prove_ms: stats(poolSamples.wall_ms),
      peak_rss_mb: poolSamples.rss_kb.length
        ? +(Math.max(...poolSamples.rss_kb) / 1024).toFixed(1) : null,
      verify_ms: poolVerifyT.wall_ms,
    },
    auth: {
      proof_bytes: authProofBytes,
      public_inputs_bytes: authPubBytes,
      witness_bytes: authWtnsSize,
      prove_ms: stats(authSamples.wall_ms),
      peak_rss_mb: authSamples.rss_kb.length
        ? +(Math.max(...authSamples.rss_kb) / 1024).toFixed(1) : null,
      verify_ms: authVerifyT.wall_ms,
    },
    wallet_e2e_ms: {
      median: stats(poolSamples.wall_ms).p50 + stats(authSamples.wall_ms).p50,
      p95:    stats(poolSamples.wall_ms).p95 + stats(authSamples.wall_ms).p95,
    },
    notes: !RAPIDSNARK ? [
      "Pool prover uses snarkjs (WASM); rapidsnark would be ~10x faster.",
      "To get the production-realistic pool number: install rapidsnark from",
      "https://github.com/iden3/rapidsnark/releases (the iden3 v0.0.8 `prover`",
      "binary), put it on PATH, and re-run this script.",
    ] : [],
  };

  const outPath = path.join(REAL_DIR, "bench.json");
  fs.writeFileSync(outPath, JSON.stringify(summary, null, 2));
  console.log("\n==>", outPath, "\n");

  // Pretty summary.
  console.log("Pool   prove p50:", summary.pool.prove_ms.p50.toFixed(0), "ms",
              " p95:",            summary.pool.prove_ms.p95.toFixed(0), "ms",
              " RSS:",            summary.pool.peak_rss_mb, "MB",
              "  proof:",         summary.pool.proof_bytes, "B");
  console.log("Auth   prove p50:", summary.auth.prove_ms.p50.toFixed(0), "ms",
              " p95:",            summary.auth.prove_ms.p95.toFixed(0), "ms",
              " RSS:",            summary.auth.peak_rss_mb, "MB",
              "  proof:",         summary.auth.proof_bytes, "B");
  console.log("Wallet e2e p50:  ", summary.wallet_e2e_ms.median.toFixed(0), "ms",
              " p95:",            summary.wallet_e2e_ms.p95.toFixed(0), "ms");
  if (!RAPIDSNARK) {
    console.log("\n[note] Pool numbers are WASM-bound. Install rapidsnark for the");
    console.log("       ~10x-faster native number that's the realistic wallet figure.");
  }
})().catch(e => { console.error(e); process.exit(1); });

function bigintToBytes(n, len) {
  const out = new Array(len).fill(0);
  for (let i = len - 1; i >= 0; i--) {
    out[i] = Number(n & 0xFFn);
    n >>= 8n;
  }
  return out;
}
