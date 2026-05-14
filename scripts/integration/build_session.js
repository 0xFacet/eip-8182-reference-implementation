#!/usr/bin/env node
// Build the integration-test "session" file: deploy-relative state, witness
// inputs for both proofs, and the resulting proofs/public-input bytes.
//
// Output: build/integration/session.json
//
// The Foundry integration test reads this file to drive transact end-to-end.
// We hard-code the same intent fields the worst-case witness uses so the
// pool-witness gen script doesn't need an outside parameter — only the auth
// witness gen needs to share the values. This keeps the demo simple while
// still exercising the full split-proof + contract path.

const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");
const snarkjs = require("snarkjs");

const ROOT = path.resolve(__dirname, "..", "..");
const BUILD = path.join(ROOT, "build");
const OUT = path.join(BUILD, "integration");
fs.mkdirSync(OUT, { recursive: true });

const POOL_DIR = path.join(BUILD, "pool");
const AUTH_DIR = path.join(BUILD, "auth_demo");

function run(cmd, args, opts = {}) {
  const r = spawnSync(cmd, args, {
    cwd: ROOT,
    stdio: "inherit",
    ...opts,
  });
  if (r.status !== 0) throw new Error(`${cmd} ${args.join(" ")} failed`);
}

(async () => {
  // 1. Generate witness inputs (will be overwritten per-call).
  console.log("==> writing pool witness input");
  run("node", ["scripts/witness/gen_pool_witness_input.js"]);
  // Read the pool witness's intent fields so the auth witness uses identical
  // values — both proofs MUST produce the same blindedAuthCommitment and
  // transactionIntentDigest for the integration test to wire them together.
  const poolInput = JSON.parse(fs.readFileSync(path.join(POOL_DIR, "input.json"), "utf8"));
  // The pool circuit derives operationKind from publicAmountOut, so it's not
  // present in poolInput; we recompute it here for the auth witness, which
  // takes operationKind as a private witness.
  const operationKind = BigInt(poolInput.publicAmountOut) === 0n ? "0" : "1";
  // Transfer mode: digest amount == outAmount[0] (recipient amount).
  // Withdrawal mode: digest amount == publicAmountOut.
  const intentAmount = operationKind === "0"
    ? poolInput.outAmount[0]
    : poolInput.publicAmountOut;
  const sharedIntent = {
    authVerifier:                          poolInput.authVerifier,
    authorizingAddress:                    poolInput.authorizingAddress,
    operationKind,
    tokenAddress:                          poolInput.tokenAddress,
    recipientOwnerNullifierKeyHash:        poolInput.recipientOwnerNullifierKeyHash,
    amount:                                intentAmount,
    feeNoteRecipientOwnerNullifierKeyHash: poolInput.feeNoteRecipientOwnerNullifierKeyHash,
    feeAmount:                             poolInput.feeAmount,
    publicRecipientAddress:                poolInput.publicRecipientAddress,
    executionConstraintsFlags:             poolInput.executionConstraintsFlags,
    lockedOutputBinding0:                  poolInput.outLockedOutputBinding[0],
    lockedOutputBinding1:                  poolInput.outLockedOutputBinding[1],
    lockedOutputBinding2:                  poolInput.outLockedOutputBinding[2],
    nonce:                                 poolInput.nonce,
    validUntilSeconds:                     poolInput.validUntilSeconds,
    executionChainId:                      poolInput.executionChainId,
    authSecret:                            "0xA0701337",
    blindingFactor:                        "0xB17ED15ABCDEF0123456789ABCDEF01",
  };
  const sharedIntentPath = path.join(BUILD, "auth_demo", "shared_intent.json");
  fs.mkdirSync(path.dirname(sharedIntentPath), { recursive: true });
  fs.writeFileSync(sharedIntentPath, JSON.stringify(sharedIntent, null, 2));

  console.log("==> writing auth witness input (shared intent)");
  run("node", ["scripts/witness/gen_auth_demo_witness_input.js", sharedIntentPath]);

  // 2. Generate witness binaries.
  console.log("==> generating pool witness");
  run("node", [
    path.join(POOL_DIR, "pool_js/generate_witness.js"),
    path.join(POOL_DIR, "pool_js/pool.wasm"),
    path.join(POOL_DIR, "input.json"),
    path.join(POOL_DIR, "witness.wtns"),
  ]);
  console.log("==> generating auth witness");
  run("node", [
    path.join(AUTH_DIR, "auth_demo_js/generate_witness.js"),
    path.join(AUTH_DIR, "auth_demo_js/auth_demo.wasm"),
    path.join(AUTH_DIR, "input.json"),
    path.join(AUTH_DIR, "witness.wtns"),
  ]);

  // 3. Prove. Use rapidsnark (native) if RAPIDSNARK_PROVER is set; otherwise
  //    fall back to snarkjs (WASM). Either path produces the same proof.
  const PROVER = process.env.RAPIDSNARK_PROVER;
  const proverLabel = PROVER ? "rapidsnark (native)" : "snarkjs (WASM)";
  console.log(`==> proving pool [${proverLabel}]`);
  const t0 = Date.now();
  let poolProof, poolPublics;
  if (PROVER) {
    const proofPath = path.join(POOL_DIR, "proof.json");
    const publicPath = path.join(POOL_DIR, "public.json");
    run(PROVER, [
      path.join(POOL_DIR, "pool_final.zkey"),
      path.join(POOL_DIR, "witness.wtns"),
      proofPath, publicPath,
    ]);
    poolProof = JSON.parse(fs.readFileSync(proofPath, "utf8"));
    poolPublics = JSON.parse(fs.readFileSync(publicPath, "utf8"));
  } else {
    ({ proof: poolProof, publicSignals: poolPublics } = await snarkjs.groth16.prove(
      path.join(POOL_DIR, "pool_final.zkey"),
      path.join(POOL_DIR, "witness.wtns"),
    ));
  }
  const t1 = Date.now();
  console.log(`    pool proved in ${(t1 - t0) / 1000}s`);

  console.log(`==> proving auth [${proverLabel}]`);
  const t2 = Date.now();
  let authProof, authPublics;
  if (PROVER) {
    const proofPath = path.join(AUTH_DIR, "proof.json");
    const publicPath = path.join(AUTH_DIR, "public.json");
    run(PROVER, [
      path.join(AUTH_DIR, "auth_demo_final.zkey"),
      path.join(AUTH_DIR, "witness.wtns"),
      proofPath, publicPath,
    ]);
    authProof = JSON.parse(fs.readFileSync(proofPath, "utf8"));
    authPublics = JSON.parse(fs.readFileSync(publicPath, "utf8"));
  } else {
    ({ proof: authProof, publicSignals: authPublics } = await snarkjs.groth16.prove(
      path.join(AUTH_DIR, "auth_demo_final.zkey"),
      path.join(AUTH_DIR, "witness.wtns"),
    ));
  }
  const t3 = Date.now();
  console.log(`    auth proved in ${(t3 - t2) / 1000}s`);

  // 4. Verify locally as a sanity check.
  const poolVk = JSON.parse(fs.readFileSync(path.join(POOL_DIR, "pool_vkey.json"), "utf8"));
  const authVk = JSON.parse(fs.readFileSync(path.join(AUTH_DIR, "auth_demo_vkey.json"), "utf8"));
  const okPool = await snarkjs.groth16.verify(poolVk, poolPublics, poolProof);
  const okAuth = await snarkjs.groth16.verify(authVk, authPublics, authProof);
  if (!okPool || !okAuth) {
    throw new Error(`local verify failed (pool=${okPool}, auth=${okAuth})`);
  }
  console.log("    local verify OK");

  // 5. Encode proofs to canonical 256-byte form + write session JSON.
  const { proof: codec } = require("../../src/lib");
  const poolProofBytes = codec.snarkjsProofToBytes(poolProof);
  const authProofBytes = codec.snarkjsProofToBytes(authProof);

  const session = {
    pool: {
      proofHex: "0x" + poolProofBytes.toString("hex"),
      publicSignals: poolPublics,
      witnessInput: poolInput,
    },
    auth: {
      proofHex: "0x" + authProofBytes.toString("hex"),
      publicSignals: authPublics,
    },
  };
  fs.writeFileSync(path.join(OUT, "session.json"), JSON.stringify(session, null, 2));
  console.log("wrote", path.join(OUT, "session.json"));

  // Persist prove timings so the bench renderer doesn't have to scrape stdout.
  const timings = {
    pool_prove_ms: t1 - t0,
    auth_prove_ms: t3 - t2,
    prover: PROVER ? "rapidsnark" : "snarkjs",
    auth_circuit: "groth16_demo",
  };
  fs.writeFileSync(path.join(OUT, "timings.json"), JSON.stringify(timings, null, 2));
  console.log("wrote", path.join(OUT, "timings.json"));
  process.exit(0);
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
