// End-to-end integration capstone (spec §7/§10/§11/§13/§16). Against a FRESH
// anvil: deploy the full stack, register two identities, then exercise deposit,
// private transfer, indexer recovery, withdrawal, an allowlist-gated pool, and
// an atomic pool-to-pool move — all with REAL Groth16 + UltraHonk proofs and
// on-chain state assertions. Nonzero exit (with the failing stage) on any error.

import path from "node:path";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { encodeFunctionData, formatEther } from "viem";
import * as D from "../sdk/src/derivations.ts";
import { bytesToHex } from "../sdk/src/bytes.ts";
import { fieldToAddress } from "../sdk/src/field.ts";
import { encryptOutputNoteData } from "../sdk/src/envelope.ts";
import { encodeNotePayload, NOTE_PAYLOAD_FLAG_DEPOSIT_USES_EVENT_PUBLICS, NOTE_PAYLOAD_KIND_DEPOSIT } from "../sdk/src/payload.ts";
import { allowlistPolicyAbi, shieldedPoolAbi } from "../sdk/src/abis.ts";
import * as reg from "../sdk/src/registryClient.ts";
import * as pool from "../sdk/src/poolClient.ts";
import * as routerClient from "../sdk/src/routerClient.ts";
import { recoverNotes } from "../sdk/src/indexer.ts";
import { buildTransactSession } from "../sdk/src/session.ts";
import { encodeSelfServeDepositPolicyData, encodeSelfServeTransactPolicyData } from "../sdk/src/selfServePolicy.ts";
import { DUMMY_OWNER_NULLIFIER_KEY_HASH } from "../sdk/src/generated/constants.ts";
import { ANVIL_KEYS, CHAIN_ID, ZERO_ADDRESS, createIdentity, deployStack, spenderFrom, startAnvil } from "./lib/harness.mjs";
import { privateKeyToAccount } from "viem/accounts";

const _here = path.dirname(fileURLToPath(import.meta.url));
const ERC_ROOT = path.resolve(_here, "..");
const PORT = Number(process.env.E2E_PORT ?? 8600);
const mockSwapAdapterAbi = [
  {
    type: "function",
    name: "ethHaircut",
    inputs: [{ name: "feeBps", type: "uint256" }],
    outputs: [],
    stateMutability: "payable",
  },
];

function assert(cond, msg) {
  if (!cond) throw new Error(`ASSERT FAILED: ${msg}`);
}
async function expectRevert(fn, label) {
  let threw = false;
  try {
    await fn();
  } catch {
    threw = true;
  }
  assert(threw, `expected revert: ${label}`);
}

async function freshValidUntil(pub) {
  const blk = await pub.getBlock();
  return BigInt(blk.timestamp) + 3600n;
}

async function readPolicyApplies(pub, poolAddr) {
  return await pub.readContract({ address: poolAddr, abi: shieldedPoolAbi, functionName: "policyAppliesToOperations" });
}

async function isAllowlisted(pub, verifier, account) {
  return await pub.readContract({ address: verifier, abi: allowlistPolicyAbi, functionName: "isAllowed", args: [account] });
}

async function joinAllowlist(wallet, pub, verifier, account) {
  const hash = await wallet.writeContract({
    account,
    chain: null,
    address: verifier,
    abi: allowlistPolicyAbi,
    functionName: "joinAllowlist",
  });
  const receipt = await pub.waitForTransactionReceipt({ hash });
  if (receipt.status !== "success") throw new Error("joinAllowlist reverted");
  return hash;
}

function readArtifact(rel) {
  return JSON.parse(readFileSync(path.join(ERC_ROOT, "contracts", "out", rel), "utf8"));
}

async function deployArtifact(wallet, pub, account, rel) {
  const artifact = readArtifact(rel);
  const hash = await wallet.sendTransaction({ account, chain: null, data: artifact.bytecode.object });
  const receipt = await pub.waitForTransactionReceipt({ hash });
  if (receipt.status !== "success" || !receipt.contractAddress) throw new Error(`deploy ${rel} failed`);
  return receipt.contractAddress;
}

// Deposit `amount` (ETH) owned by `owner`, encrypting a deposit payload to owner's key.
async function doDeposit(pub, poolAddr, owner, depositorWallet, depositorAddr, amount, secret, policyData = "0x") {
  const poolF = BigInt(poolAddr);
  const ownerCommitment = D.ownerCommitment(CHAIN_ID, poolF, owner.onkHash, secret);
  const nbc = D.noteBodyCommitment(ownerCommitment, amount, 0n);
  const payload = encodeNotePayload({
    kind: NOTE_PAYLOAD_KIND_DEPOSIT,
    chainId: CHAIN_ID,
    poolAddress: poolAddr,
    tokenAddress: fieldToAddress(0n),
    amount,
    ownerNullifierKeyHash: owner.onkHash,
    noteSecret: secret,
    noteBodyCommitment: nbc,
    outputIndex: 0,
  });
  const ond = await encryptOutputNoteData(owner.kem.publicKey, payload);
  const res = await pool.deposit(depositorWallet, pub, poolAddr, depositorAddr, {
    token: ZERO_ADDRESS,
    amount,
    ownerCommitment,
    outputNoteData: bytesToHex(ond),
    policyData,
  });
  return { ...res, ownerCommitment, noteBodyCommitment: nbc, secret, ond };
}

async function main() {
  const summary = [];
  const env = await startAnvil(PORT);
  const pub = env.publicClient;
  try {
    // ---------------- Stage (a): deploy ----------------
    const dep = deployStack(env.rpc);
    const authVerifier = BigInt(dep.ecdsaAuthVerifier);
    const freePool = dep.poolPolicyFree;
    const gatedPool = dep.poolAllowlistGated;
    const freeF = BigInt(freePool);
    const gatedF = BigInt(gatedPool);
    const allowlistF = BigInt(dep.allowlistPolicyVerifier);
    const gatedApplies = await readPolicyApplies(pub, gatedPool);
    summary.push(["a deploy", `stack @ registry ${dep.registry}; pools free=${freePool} gated=${gatedPool} (applies=${gatedApplies}) selfServeAllowlist=${dep.allowlistPolicyVerifier} router=${dep.publicActionRouter}`]);

    // ---------------- Stage (b): register identities ----------------
    const sender = createIdentity(env.rpc, authVerifier, { privateKey: ANVIL_KEYS.sender, onk: 0x1111n, seed: 0x2222n, blinder: 0x3333n, slot: 1n, kemSeedByte: 7 });
    const recipient = createIdentity(env.rpc, authVerifier, { privateKey: ANVIL_KEYS.recipient, onk: 0xaaaan, seed: 0xbbbbn, blinder: 0xccccn, slot: 0n, kemSeedByte: 9 });
    const withdrawTo = privateKeyToAccount(ANVIL_KEYS.withdrawTo).address;

    for (const id of [sender, recipient]) {
      await reg.registerFullProfile(id.wallet, pub, dep.registry, id.address, {
        ownerNullifierKeyHash: id.onkHash,
        noteSecretSeedHash: id.seedHash,
        policySetCommitment: id.policySetCommitment,
        mlKem768PublicKey: bytesToHex(id.kem.publicKey),
        metadataVersion: 1,
      });
    }
    const onchainIdentityRoot = await reg.getCurrentIdentityRoot(pub, dep.registry);
    const rebuiltIdentity = await reg.rebuildIdentityTree(pub, dep.registry);
    assert(onchainIdentityRoot === rebuiltIdentity.root, "on-chain identityRoot == SDK-rebuilt root");
    const senderIdProof = await reg.getIdentityProof(pub, dep.registry, sender.address);
    const recipientIdProof = await reg.getIdentityProof(pub, dep.registry, recipient.address);
    assert(senderIdProof.leafPosition === 1n && recipientIdProof.leafPosition === 2n, "leaf positions 1,2");
    const identityRoot = onchainIdentityRoot;
    summary.push(["b register", `sender@pos1 recipient@pos2; identityRoot=0x${identityRoot.toString(16).slice(0, 12)}… matches on-chain`]);

    // ---------------- Stage (c): sender deposits ETH into free pool ----------------
    const D0 = 1000n;
    const senderDepSecret = 0x9001n;
    const d0 = await doDeposit(pub, freePool, sender, sender.wallet, sender.address, D0, senderDepSecret);
    assert(D.noteCommitment(CHAIN_ID, freeF, d0.noteBodyCommitment, d0.leafIndex) === d0.noteCommitment, "sender reconstructs deposit note");
    let freeTree = await pool.rebuildNoteTree(pub, freePool);
    const freeRoots0 = await pool.getCurrentRoots(pub, freePool);
    assert(freeTree.root === freeRoots0.noteCommitmentRoot, "SDK note tree root == on-chain (free)");
    summary.push(["c deposit", `sender deposited ${D0} wei -> free pool leaf ${d0.leafIndex}; note reconstructed`]);

    // ---------------- Stage (d): sender private-transfers 700 to recipient ----------------
    const transferAmt = 700n;
    const changeAmt = D0 - transferAmt;
    const np0 = await pool.getNoteProof(pub, freePool, d0.leafIndex);
    const dSession = await buildTransactSession({
      chainId: CHAIN_ID,
      poolAddress: freeF,
      authVerifier,
      spender: spenderFrom(sender, senderIdProof),
      noteCommitmentRoot: freeRoots0.noteCommitmentRoot,
      identityRoot,
      inputs: [{ amount: D0, noteSecret: senderDepSecret, leafIndex: d0.leafIndex, siblings: np0.siblings }],
      outputs: [
        { ownerNullifierKeyHash: recipient.onkHash, amount: transferAmt, tokenAddress: 0n, receiveKey: recipient.kem.publicKey },
        { ownerNullifierKeyHash: sender.onkHash, amount: changeAmt, tokenAddress: 0n, receiveKey: sender.kem.publicKey },
        { ownerNullifierKeyHash: DUMMY_OWNER_NULLIFIER_KEY_HASH, amount: 0n, tokenAddress: 0n },
      ],
      operation: "transfer",
      amount: transferAmt,
      tokenAddress: 0n,
      recipientOwnerNullifierKeyHash: recipient.onkHash,
      feeNoteRecipientOwnerNullifierKeyHash: 0n,
      feeAmount: 0n,
      publicAmountOut: 0n,
      publicRecipientAddress: 0n,
      publicTokenAddress: 0n,
      nonce: 0x201n,
      validUntilSeconds: await freshValidUntil(pub),
      blindingFactor: 0x711n,
      policy: { applies: 0n, policyVerifier: 0n },
    });
    const dRes = await pool.transact(sender.wallet, pub, freePool, sender.address, {
      poolProof: dSession.poolProof,
      authProof: dSession.authProof,
      publicInputs: dSession.publicInputs,
      outputNoteData: dSession.outputNoteData,
      policyData: dSession.policyData,
    });
    assert(await pool.isNullifierSpent(pub, freePool, dSession.publicInputs.nullifier0), "transfer nullifier0 spent");
    assert(await pool.isIntentReplayIdUsed(pub, freePool, dSession.intentReplayId), "transfer replayId used");
    summary.push(["d transfer", `700 wei -> recipient; nullifier+replayId consumed; outputs @ leaves ${dRes.leafIndex0}..${dRes.leafIndex0 + 2n}`]);

    // ---------------- Stage (e): recipient indexer recovers the note ----------------
    const recovered = await recoverNotes({ publicClient: pub, pools: [{ address: freePool, chainId: CHAIN_ID }, { address: gatedPool, chainId: CHAIN_ID }], secretKey: recipient.kem.secretKey, ownerNullifierKey: recipient.onk });
    assert(recovered.length === 1, `recipient recovers exactly one note (got ${recovered.length})`);
    const r0 = recovered[0];
    assert(r0.amount === transferAmt, `recovered amount == ${transferAmt}`);
    assert(r0.ownerNullifierKeyHash === recipient.onkHash, "recovered owner == recipient");
    assert(r0.poolAddress === freeF, "recovered from free pool");
    summary.push(["e indexer", `recipient trial-decrypted + ACCEPTED note: amount=${r0.amount} leaf=${r0.leafIndex}`]);

    // ---------------- Stage (f): recipient withdraws 250 to a public address ----------------
    const withdrawAmt = 250n;
    const recipChangeAmt = transferAmt - withdrawAmt;
    const npR = await pool.getNoteProof(pub, freePool, r0.leafIndex);
    const freeRootsF = await pool.getCurrentRoots(pub, freePool);
    const balBefore = await pub.getBalance({ address: withdrawTo });
    const fSession = await buildTransactSession({
      chainId: CHAIN_ID,
      poolAddress: freeF,
      authVerifier,
      spender: spenderFrom(recipient, recipientIdProof),
      noteCommitmentRoot: freeRootsF.noteCommitmentRoot,
      identityRoot,
      inputs: [{ amount: transferAmt, noteSecret: r0.noteSecret, leafIndex: r0.leafIndex, siblings: npR.siblings }],
      outputs: [
        { ownerNullifierKeyHash: recipient.onkHash, amount: recipChangeAmt, tokenAddress: 0n, receiveKey: recipient.kem.publicKey },
        { ownerNullifierKeyHash: DUMMY_OWNER_NULLIFIER_KEY_HASH, amount: 0n, tokenAddress: 0n },
        { ownerNullifierKeyHash: DUMMY_OWNER_NULLIFIER_KEY_HASH, amount: 0n, tokenAddress: 0n },
      ],
      operation: "withdrawal",
      amount: withdrawAmt,
      tokenAddress: 0n,
      recipientOwnerNullifierKeyHash: 0n,
      feeNoteRecipientOwnerNullifierKeyHash: 0n,
      feeAmount: 0n,
      publicAmountOut: withdrawAmt,
      publicRecipientAddress: BigInt(withdrawTo),
      publicTokenAddress: 0n,
      nonce: 0x202n,
      validUntilSeconds: await freshValidUntil(pub),
      blindingFactor: 0x722n,
      policy: { applies: 0n, policyVerifier: 0n },
    });
    const fRes = await pool.transact(recipient.wallet, pub, freePool, recipient.address, {
      poolProof: fSession.poolProof,
      authProof: fSession.authProof,
      publicInputs: fSession.publicInputs,
      outputNoteData: fSession.outputNoteData,
      policyData: fSession.policyData,
    });
    const balAfter = await pub.getBalance({ address: withdrawTo });
    assert(balAfter - balBefore === withdrawAmt, `withdrawTo balance += ${withdrawAmt} (got ${balAfter - balBefore})`);
    const changeNbc = fSession.outputs[0].noteBodyCommitment;
    assert(D.noteCommitment(CHAIN_ID, freeF, changeNbc, fRes.leafIndex0) === fRes.noteCommitments[0], "recipient change note @ leaf0 matches event");
    summary.push(["f withdraw", `recipient withdrew ${withdrawAmt} wei to ${withdrawTo.slice(0, 10)}…; change note ${recipChangeAmt} landed`]);

    // ---------------- Stage (g): allowlist-gated pool deposit + withdrawal ----------------
    const G0 = 800n;
    const gatedDepSecret = 0xa001n;
    const gatedOwnerCommitment = D.ownerCommitment(CHAIN_ID, gatedF, sender.onkHash, gatedDepSecret);
    const gatedNbc = D.noteBodyCommitment(gatedOwnerCommitment, G0, 0n);
    const gatedDepPayload = encodeNotePayload({ kind: NOTE_PAYLOAD_KIND_DEPOSIT, chainId: CHAIN_ID, poolAddress: gatedPool, tokenAddress: fieldToAddress(0n), amount: G0, ownerNullifierKeyHash: sender.onkHash, noteSecret: gatedDepSecret, noteBodyCommitment: gatedNbc, outputIndex: 0 });
    const gatedDepOnd = await encryptOutputNoteData(sender.kem.publicKey, gatedDepPayload);
    const gatedDepPolicyData = encodeSelfServeDepositPolicyData({
      sender: sender.address,
      token: ZERO_ADDRESS,
      amount: G0,
      ownerCommitment: gatedOwnerCommitment,
      outputNoteDataHash: D.outputNoteDataHash(gatedDepOnd),
    });

    // (g.1) deposit with no policy data reverts.
    await expectRevert(() => pool.deposit(sender.wallet, pub, gatedPool, sender.address, { token: ZERO_ADDRESS, amount: G0, ownerCommitment: gatedOwnerCommitment, outputNoteData: bytesToHex(gatedDepOnd), policyData: "0x" }), "gated deposit without policy data");
    // (g.2) well-formed policy data still reverts until the sender joins.
    await expectRevert(() => pool.deposit(sender.wallet, pub, gatedPool, sender.address, { token: ZERO_ADDRESS, amount: G0, ownerCommitment: gatedOwnerCommitment, outputNoteData: bytesToHex(gatedDepOnd), policyData: gatedDepPolicyData }), "gated deposit before allowlist join");
    await joinAllowlist(sender.wallet, pub, dep.allowlistPolicyVerifier, sender.address);
    assert(await isAllowlisted(pub, dep.allowlistPolicyVerifier, sender.address), "sender joined self-serve allowlist");
    // (g.3) joined sender succeeds with matching self-serve policy data.
    const gDep = await pool.deposit(sender.wallet, pub, gatedPool, sender.address, { token: ZERO_ADDRESS, amount: G0, ownerCommitment: gatedOwnerCommitment, outputNoteData: bytesToHex(gatedDepOnd), policyData: gatedDepPolicyData });
    assert(D.noteCommitment(CHAIN_ID, gatedF, gatedNbc, gDep.leafIndex) === gDep.noteCommitment, "gated deposit note matches");

    // (g.4) gated withdrawal with self-serve transact policy data.
    const gWithdrawAmt = 300n;
    const gChangeAmt = G0 - gWithdrawAmt;
    const npG = await pool.getNoteProof(pub, gatedPool, gDep.leafIndex);
    const gatedRoots = await pool.getCurrentRoots(pub, gatedPool);
    const gBalBefore = await pub.getBalance({ address: withdrawTo });
    const gSession = await buildTransactSession({
      chainId: CHAIN_ID,
      poolAddress: gatedF,
      authVerifier,
      spender: spenderFrom(sender, senderIdProof),
      noteCommitmentRoot: gatedRoots.noteCommitmentRoot,
      identityRoot,
      inputs: [{ amount: G0, noteSecret: gatedDepSecret, leafIndex: gDep.leafIndex, siblings: npG.siblings }],
      outputs: [
        { ownerNullifierKeyHash: sender.onkHash, amount: gChangeAmt, tokenAddress: 0n, receiveKey: sender.kem.publicKey },
        { ownerNullifierKeyHash: DUMMY_OWNER_NULLIFIER_KEY_HASH, amount: 0n, tokenAddress: 0n },
        { ownerNullifierKeyHash: DUMMY_OWNER_NULLIFIER_KEY_HASH, amount: 0n, tokenAddress: 0n },
      ],
      operation: "withdrawal",
      amount: gWithdrawAmt,
      tokenAddress: 0n,
      recipientOwnerNullifierKeyHash: 0n,
      feeNoteRecipientOwnerNullifierKeyHash: 0n,
      feeAmount: 0n,
      publicAmountOut: gWithdrawAmt,
      publicRecipientAddress: BigInt(withdrawTo),
      publicTokenAddress: 0n,
      nonce: 0x203n,
      validUntilSeconds: await freshValidUntil(pub),
      blindingFactor: 0x733n,
      policy: { applies: gatedApplies, policyVerifier: allowlistF, buildPolicyData: ({ fields, publicInputs }) => encodeSelfServeTransactPolicyData(fields, publicInputs) },
    });
    assert(gSession.publicInputs.policyOperationDataHash !== 0n, "gated withdrawal carries policyOperationDataHash");
    const gRes = await pool.transact(sender.wallet, pub, gatedPool, sender.address, {
      poolProof: gSession.poolProof,
      authProof: gSession.authProof,
      publicInputs: gSession.publicInputs,
      outputNoteData: gSession.outputNoteData,
      policyData: gSession.policyData,
    });
    const gBalAfter = await pub.getBalance({ address: withdrawTo });
    assert(gBalAfter - gBalBefore === gWithdrawAmt, `gated withdrawal moved ${gWithdrawAmt} wei`);
    // sender's gated-pool change note S_g @ leafIndex0, used by the move in stage (h).
    const gatedChangeLeaf = gRes.leafIndex0;
    const gatedChangeSecret = gSession.outputs[0].noteSecret;
    summary.push(["g gated", `no-policy/unjoined deposits reverted; joined deposit ${G0} + withdrawal ${gWithdrawAmt} with self-serve policy succeeded`]);

    // ---------------- Stage (h): router-mediated same-asset move (gated -> free) ----------------
    // The PublicActionRouter (spec §17 optional profile) unshields from the GATED
    // pool and reshields into the POLICY-FREE pool in one tx. Safety comes from
    // authorizedSubmitter == router (front-run guard) plus
    // downstreamActionCommitment == keccak(spec) (the exact reshield spec is
    // bound into the pool proof). The free-pool reshield needs no deposit
    // policy data (depositPolicyData = "0x").
    const router = dep.publicActionRouter;
    const routerF = BigInt(router);
    const moveAmt = gChangeAmt; // sender's 500-wei change note S_g in the gated pool

    // Reshield target: deposit into the FREE pool as a fresh sender-owned note.
    const moveSecret = 0xb001n;
    const moveOwnerCommitment = D.ownerCommitment(CHAIN_ID, freeF, sender.onkHash, moveSecret);
    const moveNbc = D.noteBodyCommitment(moveOwnerCommitment, moveAmt, 0n);
    const movePayload = encodeNotePayload({ kind: NOTE_PAYLOAD_KIND_DEPOSIT, chainId: CHAIN_ID, poolAddress: freePool, tokenAddress: fieldToAddress(0n), amount: moveAmt, ownerNullifierKeyHash: sender.onkHash, noteSecret: moveSecret, noteBodyCommitment: moveNbc, outputIndex: 0 });
    const moveDepOnd = await encryptOutputNoteData(sender.kem.publicKey, movePayload);
    const moveNonce = 0x204n;
    const moveReplayId = D.intentReplayId(sender.onk, BigInt(sender.address), CHAIN_ID, gatedF, moveNonce);
    const moveDeadline = await freshValidUntil(pub);
    const moveSpec = routerClient.sameAssetMoveSpec({
      sourcePool: gatedPool,
      token: ZERO_ADDRESS,
      amount: moveAmt,
      targetPool: freePool,
      ownerCommitment: moveOwnerCommitment,
      depositNoteData: bytesToHex(moveDepOnd),
      routerDeadline: moveDeadline,
    });
    const moveCommitment = routerClient.computeDownstreamActionCommitment(CHAIN_ID, gatedPool, moveReplayId, router, moveSpec);
    const moveCommitmentOnchain = await routerClient.readDownstreamActionCommitment(pub, router, CHAIN_ID, gatedPool, moveReplayId, moveSpec);
    assert(moveCommitment === moveCommitmentOnchain, `router move commitment TS mirror == on-chain (${moveCommitment} vs ${moveCommitmentOnchain})`);

    const moveInNoteProof = await pool.getNoteProof(pub, gatedPool, gatedChangeLeaf);
    const gatedRootsH = await pool.getCurrentRoots(pub, gatedPool);
    const unshield = await buildTransactSession({
      chainId: CHAIN_ID,
      poolAddress: gatedF,
      authVerifier,
      spender: spenderFrom(sender, senderIdProof),
      noteCommitmentRoot: gatedRootsH.noteCommitmentRoot,
      identityRoot,
      inputs: [{ amount: moveAmt, noteSecret: gatedChangeSecret, leafIndex: gatedChangeLeaf, siblings: moveInNoteProof.siblings }],
      outputs: [
        { ownerNullifierKeyHash: DUMMY_OWNER_NULLIFIER_KEY_HASH, amount: 0n, tokenAddress: 0n },
        { ownerNullifierKeyHash: DUMMY_OWNER_NULLIFIER_KEY_HASH, amount: 0n, tokenAddress: 0n },
        { ownerNullifierKeyHash: DUMMY_OWNER_NULLIFIER_KEY_HASH, amount: 0n, tokenAddress: 0n },
      ],
      operation: "withdrawal",
      amount: moveAmt,
      tokenAddress: 0n,
      recipientOwnerNullifierKeyHash: 0n,
      feeNoteRecipientOwnerNullifierKeyHash: 0n,
      feeAmount: 0n,
      publicAmountOut: moveAmt,
      publicRecipientAddress: routerF,
      publicTokenAddress: 0n,
      authorizedSubmitter: routerF,
      downstreamActionCommitment: moveCommitment,
      nonce: moveNonce,
      validUntilSeconds: moveDeadline,
      blindingFactor: 0x744n,
      // The unshield leg is a withdrawal from the GATED pool, so it needs an
      // allowlist policy payload bound to the router recipient.
      policy: { applies: gatedApplies, policyVerifier: allowlistF, buildPolicyData: ({ fields, publicInputs }) => encodeSelfServeTransactPolicyData(fields, publicInputs) },
    });
    assert(unshield.publicInputs.authorizedSubmitter === routerF, "router move unshield binds authorizedSubmitter=router");
    assert(unshield.publicInputs.downstreamActionCommitment === moveCommitment, "router move binds downstreamActionCommitment");

    await expectRevert(
      () => pool.simulateTransact(pub, gatedPool, recipient.address, {
        poolProof: unshield.poolProof,
        authProof: unshield.authProof,
        publicInputs: unshield.publicInputs,
        outputNoteData: unshield.outputNoteData,
        policyData: unshield.policyData,
      }),
      "direct pool.transact from non-router submitter",
    );

    const moveIn = {
      from: gatedPool,
      poolProof: unshield.poolProof,
      authProof: unshield.authProof,
      publicInputs: unshield.publicInputs,
      outputNoteData: unshield.outputNoteData,
      policyData: unshield.policyData,
    };

    const freeTreeBeforeMove = await pool.rebuildNoteTree(pub, freePool);
    const moveRes = await routerClient.executeMove(sender.wallet, pub, router, sender.address, moveIn, moveSpec);
    const freeTreeAfterMove = await pool.rebuildNoteTree(pub, freePool);
    assert(freeTreeAfterMove.leaves.length === freeTreeBeforeMove.leaves.length + 1, "router move added exactly one note to free pool");
    const movedLeaf = BigInt(freeTreeAfterMove.leaves.length - 1);
    assert(D.noteCommitment(CHAIN_ID, freeF, moveNbc, movedLeaf) === freeTreeAfterMove.leaves[freeTreeAfterMove.leaves.length - 1], "moved note landed in free pool");
    assert(await pool.isNullifierSpent(pub, gatedPool, unshield.publicInputs.nullifier0), "router move unshield nullifier spent on gated pool");
    summary.push(["h router", `1 tx (${moveRes.txHash.slice(0, 10)}…) unshielded ${moveAmt} from gated -> reshielded into free @ leaf ${movedLeaf}; direct front-run reverted`]);

    // ---------------- Stage (i): router swap -> variable-output reshield recovery ----------------
    // This drives the §17 producer path for §13 variable-output recovery. The
    // router forwards the unshielded ETH to a committed action target. The
    // adapter returns a runtime amount, so the encrypted deposit payload uses
    // DEPOSIT_USES_EVENT_PUBLICS zero sentinels and recovery reconstructs the
    // note body from the ShieldedPoolDeposit event amount/token.
    const swapAdapter = await deployArtifact(sender.wallet, pub, sender.account, "MockSwapAdapter.sol/MockSwapAdapter.json");
    const jAmtIn = 360n;
    const jFeeBps = 1250n;
    const jAmtOut = jAmtIn - (jAmtIn * jFeeBps) / 10_000n;

    const jDepSecret = 0xd001n;
    const jDep = await doDeposit(pub, freePool, sender, sender.wallet, sender.address, jAmtIn, jDepSecret);

    const jMoveSecret = 0xd002n;
    const jOwnerCommitment = D.ownerCommitment(CHAIN_ID, freeF, sender.onkHash, jMoveSecret);
    const jMovePayload = encodeNotePayload({
      kind: NOTE_PAYLOAD_KIND_DEPOSIT,
      flags: NOTE_PAYLOAD_FLAG_DEPOSIT_USES_EVENT_PUBLICS,
      chainId: CHAIN_ID,
      poolAddress: freePool,
      tokenAddress: fieldToAddress(0n),
      amount: 0n,
      ownerNullifierKeyHash: sender.onkHash,
      noteSecret: jMoveSecret,
      noteBodyCommitment: 0n,
      outputIndex: 0,
    });
    const jMoveOnd = await encryptOutputNoteData(sender.kem.publicKey, jMovePayload);

    const jNonce = 0x205n;
    const jReplayId = D.intentReplayId(sender.onk, BigInt(sender.address), CHAIN_ID, freeF, jNonce);
    const jDeadline = await freshValidUntil(pub);
    const jSpec = {
      sourcePool: freePool,
      tokenIn: ZERO_ADDRESS,
      amountIn: jAmtIn,
      targetPool: freePool,
      tokenOut: ZERO_ADDRESS,
      ownerCommitment: jOwnerCommitment,
      depositNoteData: bytesToHex(jMoveOnd),
      depositPolicyData: "0x",
      minOut: jAmtOut,
      routerDeadline: jDeadline,
      actionTarget: swapAdapter,
      actionCalldata: encodeFunctionData({ abi: mockSwapAdapterAbi, functionName: "ethHaircut", args: [jFeeBps] }),
    };

    const jCommitment = routerClient.computeDownstreamActionCommitment(CHAIN_ID, freePool, jReplayId, router, jSpec);
    const jCommitmentOnchain = await routerClient.readDownstreamActionCommitment(pub, router, CHAIN_ID, freePool, jReplayId, jSpec);
    assert(jCommitment === jCommitmentOnchain, `swap router commitment TS mirror == on-chain (${jCommitment} vs ${jCommitmentOnchain})`);

    const npJ = await pool.getNoteProof(pub, freePool, jDep.leafIndex);
    const freeRootsJ = await pool.getCurrentRoots(pub, freePool);
    const jSession = await buildTransactSession({
      chainId: CHAIN_ID,
      poolAddress: freeF,
      authVerifier,
      spender: spenderFrom(sender, senderIdProof),
      noteCommitmentRoot: freeRootsJ.noteCommitmentRoot,
      identityRoot,
      inputs: [{ amount: jAmtIn, noteSecret: jDepSecret, leafIndex: jDep.leafIndex, siblings: npJ.siblings }],
      outputs: [
        { ownerNullifierKeyHash: DUMMY_OWNER_NULLIFIER_KEY_HASH, amount: 0n, tokenAddress: 0n },
        { ownerNullifierKeyHash: DUMMY_OWNER_NULLIFIER_KEY_HASH, amount: 0n, tokenAddress: 0n },
        { ownerNullifierKeyHash: DUMMY_OWNER_NULLIFIER_KEY_HASH, amount: 0n, tokenAddress: 0n },
      ],
      operation: "withdrawal",
      amount: jAmtIn,
      tokenAddress: 0n,
      recipientOwnerNullifierKeyHash: 0n,
      feeNoteRecipientOwnerNullifierKeyHash: 0n,
      feeAmount: 0n,
      publicAmountOut: jAmtIn,
      publicRecipientAddress: routerF,
      publicTokenAddress: 0n,
      authorizedSubmitter: routerF,
      downstreamActionCommitment: jCommitment,
      nonce: jNonce,
      validUntilSeconds: jDeadline,
      blindingFactor: 0x755n,
      policy: { applies: 0n, policyVerifier: 0n },
    });

    const jMoveIn = {
      from: freePool,
      poolProof: jSession.poolProof,
      authProof: jSession.authProof,
      publicInputs: jSession.publicInputs,
      outputNoteData: jSession.outputNoteData,
      policyData: jSession.policyData,
    };

    const freeBeforeJ = await pool.rebuildNoteTree(pub, freePool);
    const adapterBalBefore = await pub.getBalance({ address: swapAdapter });
    const jRes = await routerClient.executeMove(sender.wallet, pub, router, sender.address, jMoveIn, jSpec);
    const freeAfterJ = await pool.rebuildNoteTree(pub, freePool);
    assert(freeAfterJ.leaves.length === freeBeforeJ.leaves.length + 4, "same-pool swap router move added three source-output leaves plus one deposit leaf");
    const jMovedLeaf = BigInt(freeAfterJ.leaves.length - 1);
    const jNbc = D.noteBodyCommitment(jOwnerCommitment, jAmtOut, 0n);
    const jNc = D.noteCommitment(CHAIN_ID, freeF, jNbc, jMovedLeaf);
    assert(freeAfterJ.leaves[freeAfterJ.leaves.length - 1] === jNc, "variable-output reshield note landed with event amount");
    assert(await pool.isNullifierSpent(pub, freePool, jSession.publicInputs.nullifier0), "swap router unshield nullifier spent on free pool");
    const adapterBalAfter = await pub.getBalance({ address: swapAdapter });
    assert(adapterBalAfter - adapterBalBefore === jAmtIn - jAmtOut, "swap adapter kept only the haircut fee");
    const routerBalAfterJ = await pub.getBalance({ address: router });
    assert(routerBalAfterJ === 0n, "router retained no ETH after swap reshield");

    const recoveredJ = await recoverNotes({
      publicClient: pub,
      pools: [{ address: freePool, chainId: CHAIN_ID }, { address: gatedPool, chainId: CHAIN_ID }],
      secretKey: sender.kem.secretKey,
      ownerNullifierKey: sender.onk,
    });
    const jRecovered = recoveredJ.find((n) => n.poolAddress === freeF && n.leafIndex === jMovedLeaf && n.noteSecret === jMoveSecret);
    assert(jRecovered, "sender recovers variable-output reshielded note");
    assert(jRecovered.amount === jAmtOut, `recovered variable-output amount == ${jAmtOut}`);
    assert(jRecovered.noteCommitment === jNc, "recovered variable-output note commitment matches event");
    summary.push(["i swap", `1 tx (${jRes.txHash.slice(0, 10)}…) router forwarded ${jAmtIn}, swap returned ${jAmtOut}, event-publics note recovered @ leaf ${jMovedLeaf}`]);

    // ---------------- Summary ----------------
    console.log("\n================ e2e stage results ================");
    for (const [name, detail] of summary) console.log(`  PASS  ${name.padEnd(11)} ${detail}`);
    console.log("===================================================");
    console.log(`ALL ${summary.length} STAGES GREEN`);
    console.log(`(free-pool withdrawTo net +${formatEther(withdrawAmt + gWithdrawAmt)} ETH-wei across withdrawals)`);
  } finally {
    env.stop();
  }
}

main()
  .then(() => process.exit(0)) // snarkjs leaves a worker pool open; force a clean exit
  .catch((err) => {
    console.error(`\nE2E FAILED: ${err.message}`);
    console.error(err.stack);
    process.exit(1);
  });
