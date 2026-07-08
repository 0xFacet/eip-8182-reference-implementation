// Negative harness: prove that the pool rejects every tampered submission and
// accepts the clean one. Against a fresh anvil, build one valid transfer session,
// then (via eth_call simulation so state is untouched) assert a revert for:
//   * each of the 24 public inputs mutated by +1 (incl. authorizedSubmitter +
//     downstreamActionCommitment at indices 22/23),
//   * a wrong authorizedSubmitter (submitter gate) + a mutated
//     downstreamActionCommitment (public-input / proof mismatch),
//   * a flipped pool-proof byte and a flipped auth-proof byte,
//   * an expired validUntilSeconds,
//   * an unregistered identityRoot,
// then land the clean session, and assert nullifier-reuse and replayId-reuse
// both revert afterwards. Nonzero exit on any surprise.

import { PUBLIC_INPUT_FIELDS } from "../sdk/src/derivations.ts";
import * as D from "../sdk/src/derivations.ts";
import { bytesToHex } from "../sdk/src/bytes.ts";
import { fieldToAddress } from "../sdk/src/field.ts";
import { encryptOutputNoteData } from "../sdk/src/envelope.ts";
import { encodeNotePayload, NOTE_PAYLOAD_KIND_DEPOSIT } from "../sdk/src/payload.ts";
import * as reg from "../sdk/src/registryClient.ts";
import * as pool from "../sdk/src/poolClient.ts";
import { buildTransactSession } from "../sdk/src/session.ts";
import { DUMMY_OWNER_NULLIFIER_KEY_HASH } from "../sdk/src/generated/constants.ts";
import { ANVIL_KEYS, CHAIN_ID, ZERO_ADDRESS, createIdentity, deployStack, spenderFrom, startAnvil } from "./lib/harness.mjs";

const PORT = Number(process.env.NEG_PORT ?? 8601);

function assert(cond, msg) {
  if (!cond) throw new Error(`ASSERT FAILED: ${msg}`);
}
async function expectRevert(fn, label) {
  try {
    await fn();
  } catch {
    return; // reverted as required
  }
  throw new Error(`expected revert but call SUCCEEDED: ${label}`);
}
async function expectOk(fn, label) {
  try {
    await fn();
  } catch (e) {
    throw new Error(`expected success but reverted: ${label} (${e.shortMessage ?? e.message})`);
  }
}

function callFrom(session, overrides = {}) {
  return {
    poolProof: overrides.poolProof ?? session.poolProof,
    authProof: overrides.authProof ?? session.authProof,
    publicInputs: overrides.publicInputs ?? session.publicInputs,
    outputNoteData: overrides.outputNoteData ?? session.outputNoteData,
    policyData: overrides.policyData ?? session.policyData,
  };
}
function flipByte(hex) {
  const b = Buffer.from(hex.slice(2), "hex");
  b[b.length - 1] ^= 0x01;
  return "0x" + b.toString("hex");
}

async function main() {
  const env = await startAnvil(PORT);
  const pub = env.publicClient;
  const results = [];
  try {
    const dep = deployStack(env.rpc);
    const authVerifier = BigInt(dep.ecdsaAuthVerifier);
    const freePool = dep.poolPolicyFree;
    const freeF = BigInt(freePool);

    const sender = createIdentity(env.rpc, authVerifier, { privateKey: ANVIL_KEYS.sender, onk: 0x1111n, seed: 0x2222n, blinder: 0x3333n, slot: 1n, kemSeedByte: 7 });
    const recipient = createIdentity(env.rpc, authVerifier, { privateKey: ANVIL_KEYS.recipient, onk: 0xaaaan, seed: 0xbbbbn, blinder: 0xccccn, slot: 0n, kemSeedByte: 9 });
    for (const id of [sender, recipient]) {
      await reg.registerFullProfile(id.wallet, pub, dep.registry, id.address, { ownerNullifierKeyHash: id.onkHash, noteSecretSeedHash: id.seedHash, policySetCommitment: id.policySetCommitment, mlKem768PublicKey: bytesToHex(id.kem.publicKey), metadataVersion: 1 });
    }
    const identityRoot = await reg.getCurrentIdentityRoot(pub, dep.registry);
    const senderIdProof = await reg.getIdentityProof(pub, dep.registry, sender.address);

    // Two deposits so nullifier-reuse and replayId-reuse can be isolated.
    async function deposit(amount, secret) {
      const oc = D.ownerCommitment(CHAIN_ID, freeF, sender.onkHash, secret);
      const nbc = D.noteBodyCommitment(oc, amount, 0n);
      const payload = encodeNotePayload({ kind: NOTE_PAYLOAD_KIND_DEPOSIT, chainId: CHAIN_ID, poolAddress: freePool, tokenAddress: fieldToAddress(0n), amount, ownerNullifierKeyHash: sender.onkHash, noteSecret: secret, noteBodyCommitment: nbc, outputIndex: 0 });
      const ond = await encryptOutputNoteData(sender.kem.publicKey, payload);
      return pool.deposit(sender.wallet, pub, freePool, sender.address, { token: ZERO_ADDRESS, amount, ownerCommitment: oc, outputNoteData: bytesToHex(ond), policyData: "0x" });
    }
    const dA = await deposit(1000n, 0x9001n);
    const dB = await deposit(1000n, 0x9002n);

    // Build a transfer session spending note A (nonce N1).
    const roots = await pool.getCurrentRoots(pub, freePool);
    const blk = await pub.getBlock();
    const validUntil = BigInt(blk.timestamp) + 3600n;
    const NONCE = 0x301n;
    function transferParams(input) {
      return {
        chainId: CHAIN_ID, poolAddress: freeF, authVerifier,
        spender: spenderFrom(sender, senderIdProof),
        noteCommitmentRoot: roots.noteCommitmentRoot, identityRoot,
        inputs: [input],
        outputs: [
          { ownerNullifierKeyHash: recipient.onkHash, amount: 700n, tokenAddress: 0n, receiveKey: recipient.kem.publicKey },
          { ownerNullifierKeyHash: sender.onkHash, amount: 300n, tokenAddress: 0n, receiveKey: sender.kem.publicKey },
          { ownerNullifierKeyHash: DUMMY_OWNER_NULLIFIER_KEY_HASH, amount: 0n, tokenAddress: 0n },
        ],
        operation: "transfer", amount: 700n, tokenAddress: 0n,
        recipientOwnerNullifierKeyHash: recipient.onkHash, feeNoteRecipientOwnerNullifierKeyHash: 0n, feeAmount: 0n,
        publicAmountOut: 0n, publicRecipientAddress: 0n, publicTokenAddress: 0n,
        nonce: NONCE, validUntilSeconds: validUntil, blindingFactor: 0x711n,
        policy: { applies: 0n, policyVerifier: 0n },
      };
    }
    const npA = await pool.getNoteProof(pub, freePool, dA.leafIndex);
    const control = await buildTransactSession(transferParams({ amount: 1000n, noteSecret: 0x9001n, leafIndex: dA.leafIndex, siblings: npA.siblings }));
    // Session B spends note B but reuses NONCE -> same intentReplayId, different nullifier.
    const npB = await pool.getNoteProof(pub, freePool, dB.leafIndex);
    const sessionB = await buildTransactSession(transferParams({ amount: 1000n, noteSecret: 0x9002n, leafIndex: dB.leafIndex, siblings: npB.siblings }));
    assert(sessionB.intentReplayId === control.intentReplayId, "session B reuses control replayId");
    assert(sessionB.publicInputs.nullifier0 !== control.publicInputs.nullifier0, "session B has a distinct nullifier");

    // --- (1) mutate each of the 24 public inputs by +1 -> revert (simulate, no state change). ---
    for (const field of PUBLIC_INPUT_FIELDS) {
      const mutated = { ...control.publicInputs, [field]: control.publicInputs[field] + 1n };
      await expectRevert(() => pool.simulateTransact(pub, freePool, sender.address, callFrom(control, { publicInputs: mutated })), `public input +1: ${field}`);
    }
    assert(PUBLIC_INPUT_FIELDS.length === 24, `PUBLIC_INPUT_FIELDS has 24 entries (got ${PUBLIC_INPUT_FIELDS.length})`);
    results.push(["public-input +1 (x24)", "all reverted"]);

    // --- (1b) spec §7.1 caller-binding mutations. ---
    // Wrong authorizedSubmitter: a nonzero submitter that isn't the caller -> the
    // pool's submitter gate reverts (UnauthorizedSubmitter) before touching state.
    const wrongSubmitter = { ...control.publicInputs, authorizedSubmitter: BigInt(recipient.address) };
    await expectRevert(
      () => pool.simulateTransact(pub, freePool, sender.address, callFrom(control, { publicInputs: wrongSubmitter })),
      "wrong authorizedSubmitter (submitter gate)",
    );
    // Mutated downstreamActionCommitment: pin authorizedSubmitter to the caller so
    // the submitter gate + the downstream!=0-requires-submitter check both pass,
    // leaving the proof to reject the tampered public input.
    const mutatedDownstream = {
      ...control.publicInputs,
      authorizedSubmitter: BigInt(sender.address),
      downstreamActionCommitment: 0x1234n,
    };
    await expectRevert(
      () => pool.simulateTransact(pub, freePool, sender.address, callFrom(control, { publicInputs: mutatedDownstream })),
      "mutated downstreamActionCommitment (proof mismatch)",
    );
    results.push(["caller-binding mutations", "wrong submitter + downstream both reverted"]);

    // --- (2) flipped proof bytes -> revert. ---
    await expectRevert(() => pool.simulateTransact(pub, freePool, sender.address, callFrom(control, { poolProof: flipByte(control.poolProof) })), "flipped pool proof");
    await expectRevert(() => pool.simulateTransact(pub, freePool, sender.address, callFrom(control, { authProof: flipByte(control.authProof) })), "flipped auth proof");
    results.push(["flipped proof bytes", "pool+auth reverted"]);

    // --- (3) expired validUntilSeconds -> revert. ---
    const expired = { ...control.publicInputs, validUntilSeconds: BigInt(blk.timestamp) - 1n };
    await expectRevert(() => pool.simulateTransact(pub, freePool, sender.address, callFrom(control, { publicInputs: expired })), "expired validUntil");
    results.push(["expired validUntil", "reverted"]);

    // --- (4) unregistered identityRoot -> revert. ---
    const badRoot = { ...control.publicInputs, identityRoot: 0xdeadbeefn };
    await expectRevert(() => pool.simulateTransact(pub, freePool, sender.address, callFrom(control, { publicInputs: badRoot })), "unregistered identityRoot");
    results.push(["unregistered identityRoot", "reverted"]);

    // --- (5) the clean control session lands. ---
    await expectOk(() => pool.transact(sender.wallet, pub, freePool, sender.address, callFrom(control)), "clean control session");
    assert(await pool.isNullifierSpent(pub, freePool, control.publicInputs.nullifier0), "control nullifier now spent");
    assert(await pool.isIntentReplayIdUsed(pub, freePool, control.intentReplayId), "control replayId now used");
    results.push(["clean control", "LANDED"]);

    // --- (6) reuse nullifier (resubmit control) -> revert. ---
    await expectRevert(() => pool.simulateTransact(pub, freePool, sender.address, callFrom(control)), "nullifier reuse");
    // --- (7) reuse intentReplayId (session B: fresh nullifier, same replayId) -> revert. ---
    await expectRevert(() => pool.simulateTransact(pub, freePool, sender.address, callFrom(sessionB)), "replayId reuse");
    results.push(["nullifier + replayId reuse", "both reverted"]);

    console.log("\n============ negative-test results ============");
    for (const [name, detail] of results) console.log(`  PASS  ${name.padEnd(26)} ${detail}`);
    console.log("==============================================");
    console.log(`ALL NEGATIVE CHECKS GREEN (24 mutations + 2 caller-binding + 2 proof flips + expiry + bad root + 2 reuse; control landed)`);
  } finally {
    env.stop();
  }
}

main()
  .then(() => process.exit(0)) // snarkjs leaves a worker pool open; force a clean exit
  .catch((err) => {
    console.error(`\nNEGATIVE TEST FAILED: ${err.message}`);
    console.error(err.stack);
    process.exit(1);
  });
