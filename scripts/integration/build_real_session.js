#!/usr/bin/env node
// Coordinated session builder for the realistic-auth integration test.
//
// 1. Run scripts/noir/gen_prover_toml.js to produce a deterministic keypair,
//    EIP-712 signature, and side-car JSON with the pubkey-derived
//    authorizing_address, auth_data_commitment, blinding_factor, and
//    auth_verifier address (a fixed-pin like 0x...8182AAAA so that
//    vm.etch can place RealAuthVerifier at the same address the pool proof
//    commits to).
//
// 2. Run scripts/noir/gen_real_pool_witness_input.js to produce
//    build/integration_real/pool_input.json with those same values.
//
// 3. Read the lockedOutputBinding{0,1,2} values the pool witness derived
//    from the output note bodies, re-run gen_prover_toml.js with a shared
//    intent that pins those bindings, so the auth proof's
//    transactionIntentDigest matches the pool proof's.
//
// 4. Run the existing pool wasm witness gen + snarkjs.groth16.prove against
//    build/pool/pool_final.zkey. Read pool publicSignals.
//
// 5. Run nargo execute + bb prove for the auth circuit. Read its
//    public_inputs (just blindedAuthCommitment, transactionIntentDigest).
//
// 6. Sanity-check that pool.publicSignals[19] == auth.public_inputs[0]
//    (blinded auth commitment) and pool.publicSignals[20] ==
//    auth.public_inputs[1] (transaction intent digest).
//
// 7. Write build/integration_real/session.json with both proofs and the pool's
//    public signals (plus a copy of the sidecar values for the test).

const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");
const snarkjs = require("snarkjs");

const ROOT = path.resolve(__dirname, "..", "..");
const REAL_DIR = path.join(ROOT, "build", "integration_real");
const POOL_INPUT = path.join(REAL_DIR, "pool_input.json");
const POOL_WTNS = path.join(REAL_DIR, "pool.wtns");
const POOL_BUILD = path.join(ROOT, "build", "pool");
const NOIR_AUTH_DIR = path.join(ROOT, "circuits-noir", "auth");

fs.mkdirSync(REAL_DIR, { recursive: true });

function run(cmd, args, opts = {}) {
  const r = spawnSync(cmd, args, { stdio: "inherit", cwd: opts.cwd || ROOT, ...opts });
  if (r.status !== 0) throw new Error(`${cmd} ${args.join(" ")} -> ${r.status}`);
}

function runQuiet(cmd, args, opts = {}) {
  const r = spawnSync(cmd, args, { stdio: "pipe", encoding: "utf8", cwd: opts.cwd || ROOT, ...opts });
  if (r.status !== 0) {
    process.stderr.write(r.stdout || "");
    process.stderr.write(r.stderr || "");
    throw new Error(`${cmd} ${args.join(" ")} -> ${r.status}`);
  }
  return r;
}

(async () => {
  console.log("==> 1) prover.toml round 1 (locked bindings = 0)");
  run("node", ["scripts/noir/gen_prover_toml.js"]);

  console.log("==> 2) pool witness input round 1");
  run("node", ["scripts/noir/gen_real_pool_witness_input.js"]);

  console.log("==> 3) re-run prover.toml with the pool's computed locked bindings");
  const poolInput1 = JSON.parse(fs.readFileSync(POOL_INPUT, "utf8"));
  const sharedIntentPath = path.join(REAL_DIR, "shared_for_auth.json");
  const sharedIntent = {
    private_key_hex: undefined, // use the gen script's default deterministic key
    auth_verifier_addr: poolInput1.authVerifier,
    blinding_factor: poolInput1.blindingFactor,
    locked_output_bindings: [
      poolInput1.outLockedOutputBinding[0],
      poolInput1.outLockedOutputBinding[1],
      poolInput1.outLockedOutputBinding[2],
    ],
    intent: {
      auth_verifier:               BigInt(poolInput1.authVerifier).toString(),
      authorizing_address:         BigInt(poolInput1.authorizingAddress).toString(),
      operation_kind:              "0",                            // TRANSFER_OP
      token_address:               BigInt(poolInput1.tokenAddress).toString(),
      recipient_address:           BigInt(poolInput1.recipientAddress).toString(),
      amount:                      BigInt(poolInput1.outAmount[0]).toString(),
      fee_recipient_address:       BigInt(poolInput1.feeRecipientAddress).toString(),
      fee_amount:                  BigInt(poolInput1.feeAmount).toString(),
      execution_constraints_flags: BigInt(poolInput1.executionConstraintsFlags).toString(),
      locked_output_binding0:      BigInt(poolInput1.outLockedOutputBinding[0]).toString(),
      locked_output_binding1:      BigInt(poolInput1.outLockedOutputBinding[1]).toString(),
      locked_output_binding2:      BigInt(poolInput1.outLockedOutputBinding[2]).toString(),
      // 32-byte nonce hex; the gen script expects bytes form. Convert from the
      // pool's Field nonce by zero-padding to 32 bytes BE.
      nonce_bytes: bigintToBytesArr(BigInt(poolInput1.nonce), 32),
      valid_until_seconds:         BigInt(poolInput1.validUntilSeconds).toString(),
      execution_chain_id:          BigInt(poolInput1.executionChainId).toString(),
    },
  };
  // Convert intent fields from string back to BigInt-form for the gen_prover_toml.js
  // compatibility path: it expects either string-decimal or BigInt, but its
  // `defaultIntent` returns BigInts. To avoid divergence, we re-emit a shared
  // intent block with BigInt-typed fields by stringifying as decimal and
  // re-parsing inside the script. The gen script accepts string-decimal via
  // BigInt() coercion in our inputs; intent fields are Big-int-coerceable.
  fs.writeFileSync(sharedIntentPath, JSON.stringify(sharedIntent, (_, v) =>
    typeof v === "bigint" ? v.toString() : v, 2));
  run("node", ["scripts/noir/gen_prover_toml.js", sharedIntentPath]);

  console.log("==> 4) regenerate pool witness with the same intent (nothing should change)");
  run("node", ["scripts/noir/gen_real_pool_witness_input.js"]);

  console.log("==> 5) pool witness binary + snarkjs prove");
  run("node", [
    path.join(POOL_BUILD, "pool_js/generate_witness.js"),
    path.join(POOL_BUILD, "pool_js/pool.wasm"),
    POOL_INPUT,
    POOL_WTNS,
  ]);
  const t0 = Date.now();
  const { proof: poolProof, publicSignals: poolPublics } = await snarkjs.groth16.prove(
    path.join(POOL_BUILD, "pool_final.zkey"),
    POOL_WTNS,
  );
  const tPool = Date.now() - t0;
  console.log(`    pool proved in ${(tPool / 1000).toFixed(2)}s`);

  console.log("==> 6) auth witness + bb prove");
  run("nargo", ["execute", "auth"], { cwd: NOIR_AUTH_DIR });
  // Need a VK for prove; regenerate to be safe (cheap).
  run("bb", ["write_vk", "--scheme", "ultra_honk", "-b", "target/auth.json", "-t", "evm",
    "-o", "target"], { cwd: NOIR_AUTH_DIR });
  const t1 = Date.now();
  run("bb", ["prove", "--scheme", "ultra_honk", "-b", "target/auth.json",
    "-w", "target/auth.gz", "-o", "target", "-t", "evm"], { cwd: NOIR_AUTH_DIR });
  const tAuth = Date.now() - t1;
  console.log(`    auth proved in ${(tAuth / 1000).toFixed(2)}s`);

  // Verify each locally.
  const poolVk = JSON.parse(fs.readFileSync(path.join(POOL_BUILD, "pool_vkey.json"), "utf8"));
  const okPool = await snarkjs.groth16.verify(poolVk, poolPublics, poolProof);
  if (!okPool) throw new Error("pool proof local verify failed");
  const verifyR = spawnSync("bb", ["verify", "--scheme", "ultra_honk",
    "-k", path.join(NOIR_AUTH_DIR, "target/vk"),
    "-p", path.join(NOIR_AUTH_DIR, "target/proof"),
    "-i", path.join(NOIR_AUTH_DIR, "target/public_inputs"), "-t", "evm"],
    { stdio: "inherit" });
  if (verifyR.status !== 0) {
    throw new Error(`auth proof local verify failed (bb exit ${verifyR.status})`);
  }
  console.log("    local verify OK (pool + auth)");

  // Read auth public inputs.
  const authPublicsBuf = fs.readFileSync(path.join(NOIR_AUTH_DIR, "target/public_inputs"));
  if (authPublicsBuf.length !== 64) {
    throw new Error(`unexpected auth public inputs size: ${authPublicsBuf.length}`);
  }
  const authBlinded = "0x" + authPublicsBuf.subarray(0, 32).toString("hex");
  const authDigest  = "0x" + authPublicsBuf.subarray(32, 64).toString("hex");

  // Sanity: pool public signals 19 (blinded) and 20 (intent digest) must
  // match the auth public inputs.
  const ps19 = BigInt(poolPublics[19]);
  const ps20 = BigInt(poolPublics[20]);
  if (BigInt(authBlinded) !== ps19) {
    throw new Error(
      `blinded mismatch: auth=${BigInt(authBlinded)} pool=${ps19}`,
    );
  }
  if (BigInt(authDigest) !== ps20) {
    throw new Error(
      `intent digest mismatch: auth=${BigInt(authDigest)} pool=${ps20}`,
    );
  }
  console.log("    pool/auth public-input agreement OK");

  // Encode pool proof to canonical 256-byte form (matches build_session.js).
  const { proof: codec } = require(path.join(ROOT, "src/lib"));
  const poolProofBytes = codec.snarkjsProofToBytes(poolProof);

  const authProofBuf = fs.readFileSync(path.join(NOIR_AUTH_DIR, "target/proof"));

  const sidecar = JSON.parse(fs.readFileSync(
    path.join(ROOT, "build/noir_auth/session_sidecar.json"), "utf8"));

  const session = {
    pool: {
      proofHex: "0x" + poolProofBytes.toString("hex"),
      publicSignals: poolPublics,
    },
    auth: {
      proofHex: "0x" + authProofBuf.toString("hex"),
      publicInputs: {
        blindedAuthCommitment: authBlinded,
        transactionIntentDigest: authDigest,
      },
    },
    sidecar,
    timings: {
      pool_prove_ms: tPool,
      auth_prove_ms: tAuth,
    },
  };
  const outPath = path.join(REAL_DIR, "session.json");
  fs.writeFileSync(outPath, JSON.stringify(session, null, 2));
  console.log("==> wrote", outPath);
  console.log("    pool prove:", (tPool / 1000).toFixed(2), "s");
  console.log("    auth prove:", (tAuth / 1000).toFixed(2), "s");
  console.log("    wallet-side e2e:", ((tPool + tAuth) / 1000).toFixed(2),
    "s (Groth16 pool + UltraHonk auth on", require("os").cpus().length, "cores)");
  process.exit(0);
})().catch(e => { console.error(e); process.exit(1); });

function bigintToBytesArr(n, len) {
  const out = new Array(len).fill(0);
  for (let i = len - 1; i >= 0; i--) {
    out[i] = Number(n & 0xFFn);
    n >>= 8n;
  }
  return out;
}
