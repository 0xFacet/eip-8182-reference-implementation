// EIP-8182 pool circuit (fixed shape, all selectors live).
//
// One circuit handles:
//   - transfer or withdrawal mode (operationKind derived from publicAmountOut)
//   - 2 inputs: each real or phantom (per-input isReal selector)
//   - 3 outputs: each real or dummy (per-output isReal selector)
//   - fee slot used or unused (slot 2 is fee slot when real)
//   - locked outputs (lockedOutputBinding_i paired with executionConstraintsFlags bit i)
//
// Constraint count is the count of the fully-selected circuit, regardless of
// which witness is fed in. Worst-case witness has all inputs real, all outputs
// real, fee used, all slots locked.
//
// Public inputs: 19 fields per spec Section 9, in declaration order.
// Section 8.1-8.10 constraints all wired in.

pragma circom 2.0.0;

include "poseidon2_sponge.circom";
include "components.circom";
include "merkle.circom";
include "bits.circom";

// Spec Section 3.2: per-user policy-set tree depth.
function POLICY_SET_DEPTH() { return 8; }

template Pool() {
    // ===== Public inputs (19 fields, Section 9 declaration order) =====
    signal input noteCommitmentRoot;
    signal input nullifier0;
    signal input nullifier1;
    signal input noteBodyCommitment0;
    signal input noteBodyCommitment1;
    signal input noteBodyCommitment2;
    signal input publicAmountOut;
    signal input publicRecipientAddress;
    signal input publicTokenAddress;
    signal input intentReplayId;
    signal input validUntilSeconds;
    signal input executionChainId;
    signal input authPolicyRoot;
    signal input outputNoteDataHash0;
    signal input outputNoteDataHash1;
    signal input outputNoteDataHash2;
    signal input authVerifier;
    signal input blindedAuthCommitment;
    signal input transactionIntentDigest;

    // ===== Private witnesses =====
    // Sender identity & auth-policy registry leaf state
    signal input senderOwnerNullifierKey;
    signal input senderNoteSecretSeed;
    signal input authorizingAddress;                   // <2^160
    signal input noteSecretSeedHash;                   // = poseidon(NOTE_SECRET_SEED_DOMAIN, senderNoteSecretSeed)
    signal input policySetCommitment;                  // depth-POLICY_SET_DEPTH root over the user's active policyCommitments
    signal input leafPosition;                         // <2^32; user's slot in the auth-policy registry
    signal input authPolicySiblings[32];

    // Inputs: 2 slots, each real (1) or phantom (0)
    signal input inIsReal[2];                          // bool
    signal input inAmount[2];                          // <2^248
    signal input inNoteSecret[2];
    signal input inLeafIndex[2];                       // <2^32
    signal input inSiblings[2][32];                    // path bits derived from inLeafIndex

    // Outputs: 3 slots, each real (1) or dummy (0); slot 2 is fee slot when real
    signal input outIsReal[3];                         // bool
    signal input outAmount[3];                         // <2^248
    signal input outOwnerNullifierKeyHash[3];          // recipient's hash for real, DUMMY_OWNER_HASH for dummy
    signal input outLockedOutputBinding[3];            // signed lock value (paired with flag bit i)

    // Canonical token (single witness shared by all real inputs/outputs)
    signal input tokenAddress;                         // <2^160

    // Intent fields (private, authorization-bound)
    signal input recipientOwnerNullifierKeyHash;       // recipient's ownerNullifierKeyHash in transfer mode; 0 in withdrawal
    signal input feeNoteRecipientOwnerNullifierKeyHash;// fee-recipient's ownerNullifierKeyHash when feeAmount > 0; 0 otherwise
    signal input feeAmount;                            // <2^248
    signal input nonce;
    signal input executionConstraintsFlags;            // <2^32, only bits 0/1/2 may be set

    // Auth-policy proof witnesses
    signal input authDataCommitment;
    signal input blindingFactor;
    signal input registrationBlinder;
    signal input policySetLeafPosition;                // <2^POLICY_SET_DEPTH; slot of policyCommitment in policy-set tree
    signal input policySetSiblings[8];                 // POLICY_SET_DEPTH

    // ===== Range / boolean checks =====
    component nbAuthVerifier   = Num2Bits(160); nbAuthVerifier.in   <== authVerifier;
    component nbPubRecipient   = Num2Bits(160); nbPubRecipient.in   <== publicRecipientAddress;
    component nbPubToken       = Num2Bits(160); nbPubToken.in       <== publicTokenAddress;
    component nbPubAmt         = Num2Bits(248); nbPubAmt.in         <== publicAmountOut;
    component nbValidUntil     = Num2Bits(32);  nbValidUntil.in     <== validUntilSeconds;
    component nbExecChain      = Num2Bits(32);  nbExecChain.in      <== executionChainId;

    component nbAuthAddr       = Num2Bits(160); nbAuthAddr.in       <== authorizingAddress;
    component nbToken          = Num2Bits(160); nbToken.in          <== tokenAddress;
    component nbFeeAmount      = Num2Bits(248); nbFeeAmount.in      <== feeAmount;
    component nbExecFlags      = Num2Bits(32);  nbExecFlags.in      <== executionConstraintsFlags;
    component nbLeafPos        = Num2Bits(32);  nbLeafPos.in        <== leafPosition;
    component nbPolicySetLeafPos = Num2Bits(8); nbPolicySetLeafPos.in <== policySetLeafPosition;

    // Reserved-flag-bit rejection (spec Section 8.10): only bits 0/1/2 are
    // defined (LOCK_OUTPUT_BINDING_0/1/2). Every other bit MUST be zero.
    for (var i = 3; i < 32; i++) {
        nbExecFlags.out[i] === 0;
    }

    // Boolean selectors
    for (var i = 0; i < 2; i++) inIsReal[i] * (1 - inIsReal[i]) === 0;
    for (var i = 0; i < 3; i++) outIsReal[i] * (1 - outIsReal[i]) === 0;

    // At-least-one-real-input (spec Section 8.2)
    (1 - inIsReal[0]) * (1 - inIsReal[1]) === 0;

    // Per-input range/decomposition. nbInLeaf.out doubles as the merkle-path bits.
    component nbInAmt[2];
    component nbInLeaf[2];
    for (var i = 0; i < 2; i++) {
        nbInAmt[i]  = Num2Bits(248); nbInAmt[i].in  <== inAmount[i];
        nbInLeaf[i] = Num2Bits(32);  nbInLeaf[i].in <== inLeafIndex[i];
    }

    // Phantom inputs MUST have amount == 0 (spec Section 8.2)
    for (var i = 0; i < 2; i++) {
        (1 - inIsReal[i]) * inAmount[i] === 0;
    }

    // Per-output amount range.
    component nbOutAmt[3];
    for (var i = 0; i < 3; i++) {
        nbOutAmt[i] = Num2Bits(248); nbOutAmt[i].in <== outAmount[i];
    }

    // ===== operationKind derivation (spec Section 8.9) =====
    // operationKind = 0 (TRANSFER_OP) iff publicAmountOut == 0
    //                 1 (WITHDRAWAL_OP) iff publicAmountOut > 0
    component pubAmtIsZero = IsZero();
    pubAmtIsZero.in <== publicAmountOut;
    signal operationKind;
    operationKind <== 1 - pubAmtIsZero.out;

    // Public-mode bindings (spec Section 8.9):
    //   transfer    : publicRecipientAddress == 0 AND publicTokenAddress == 0
    //   withdrawal  : publicTokenAddress == tokenAddress (signed canonical)
    (1 - operationKind) * publicRecipientAddress === 0;
    (1 - operationKind) * publicTokenAddress === 0;
    operationKind * (publicTokenAddress - tokenAddress) === 0;
    // publicRecipientAddress in withdrawal is bound directly into the intent
    // digest below; no separate intent-side recipientAddress witness exists.

    // ===== Sender identity =====
    // poseidon(OWNER_NULLIFIER_KEY_HASH_DOMAIN, senderOwnerNullifierKey)
    component senderHashKey = OwnerNullifierKeyHash();
    senderHashKey.ownerNullifierKey <== senderOwnerNullifierKey;
    signal senderOwnerNullifierKeyHash;
    senderOwnerNullifierKeyHash <== senderHashKey.out;

    // poseidon(NOTE_SECRET_SEED_DOMAIN, senderNoteSecretSeed) MUST equal the
    // noteSecretSeedHash field extracted from the auth-policy registry leaf.
    component senderSeedHash = NoteSecretSeedHash();
    senderSeedHash.noteSecretSeed <== senderNoteSecretSeed;
    senderSeedHash.out === noteSecretSeedHash;

    // ===== Auth-policy registry leaf membership (spec Section 8.1) =====
    component aplLeaf = AuthPolicyLeaf();
    aplLeaf.user                  <== authorizingAddress;
    aplLeaf.ownerNullifierKeyHash <== senderOwnerNullifierKeyHash;
    aplLeaf.noteSecretSeedHash    <== noteSecretSeedHash;
    aplLeaf.policySetCommitment   <== policySetCommitment;

    component aplPath = MerklePath(32);
    aplPath.leaf <== aplLeaf.out;
    for (var b = 0; b < 32; b++) {
        aplPath.pathBits[b] <== nbLeafPos.out[b];
        aplPath.siblings[b] <== authPolicySiblings[b];
    }
    aplPath.root === authPolicyRoot;

    // ===== Policy-set membership (spec Section 8.1) =====
    // policyCommitment = poseidon(POLICY_COMMITMENT_DOMAIN, authVerifier,
    //                             authDataCommitment, registrationBlinder)
    component pc = PolicyCommitment();
    pc.authVerifier        <== authVerifier;
    pc.authDataCommitment  <== authDataCommitment;
    pc.registrationBlinder <== registrationBlinder;
    signal policyCommitment;
    policyCommitment <== pc.out;

    // policyCommitment != 0 (the empty-policy-set sentinel). Forces no spend
    // can succeed against a wallet that has revoked all policies (empty-set
    // root has only 0 leaves and the path for a nonzero leaf cannot match).
    component policyCommitmentIsZero = IsZero();
    policyCommitmentIsZero.in <== policyCommitment;
    policyCommitmentIsZero.out === 0;

    component policySetPath = MerklePath(8);
    policySetPath.leaf <== policyCommitment;
    for (var b = 0; b < 8; b++) {
        policySetPath.pathBits[b] <== nbPolicySetLeafPos.out[b];
        policySetPath.siblings[b] <== policySetSiblings[b];
    }
    policySetPath.root === policySetCommitment;

    // ===== Inputs: per-slot derivation =====
    // For each input, derive owner / body / final commitment / nullifier, check
    // Merkle path against noteCommitmentRoot for real inputs, and select
    // between real and phantom nullifier by isReal.
    component inOC[2];
    component inBC[2];
    component inNC[2];
    component inNF[2];
    component inPN[2];
    component inPath[2];
    signal    inEffectiveNullifier[2];

    for (var i = 0; i < 2; i++) {
        inOC[i] = OwnerCommitment();
        inOC[i].ownerNullifierKeyHash <== senderOwnerNullifierKeyHash;
        inOC[i].noteSecret            <== inNoteSecret[i];

        inBC[i] = NoteBodyCommitment();
        inBC[i].ownerCommitment <== inOC[i].out;
        inBC[i].amount          <== inAmount[i];
        // Anchor every input body to the canonical token. For real inputs,
        // Merkle membership force-anchors `tokenAddress` to the on-tree note's
        // actual token; for phantom inputs, body is unused.
        inBC[i].tokenAddress    <== tokenAddress;

        inNC[i] = NoteCommitment();
        inNC[i].noteBodyCommitment <== inBC[i].out;
        inNC[i].leafIndex          <== inLeafIndex[i];

        inNF[i] = Nullifier();
        inNF[i].noteCommitment    <== inNC[i].out;
        inNF[i].ownerNullifierKey <== senderOwnerNullifierKey;

        inPN[i] = PhantomNullifier();
        inPN[i].ownerNullifierKey <== senderOwnerNullifierKey;
        inPN[i].intentReplayId    <== intentReplayId;
        inPN[i].inputIndex        <== i;

        // Merkle path: path bits = leafIndex bits (LSB-first), siblings
        // witnessed; selectively constrained to noteCommitmentRoot for real.
        inPath[i] = MerklePath(32);
        inPath[i].leaf <== inNC[i].out;
        for (var b = 0; b < 32; b++) {
            inPath[i].pathBits[b] <== nbInLeaf[i].out[b];
            inPath[i].siblings[b] <== inSiblings[i][b];
        }
        inIsReal[i] * (inPath[i].root - noteCommitmentRoot) === 0;

        // Effective nullifier = real ? real-nullifier : phantom-nullifier
        inEffectiveNullifier[i] <== inPN[i].out + inIsReal[i] * (inNF[i].out - inPN[i].out);
    }

    // Bind effective nullifiers to the public inputs
    inEffectiveNullifier[0] === nullifier0;
    inEffectiveNullifier[1] === nullifier1;

    // ===== DUMMY_OWNER_NULLIFIER_KEY_HASH (spec Section 3.2) =====
    // poseidon(OWNER_NULLIFIER_KEY_HASH_DOMAIN, 0xdead). setAuthPolicy rejects
    // this value, so notes whose owner-hash is DUMMY are structurally
    // unspendable.
    component dummyOwnerHashCalc = OwnerNullifierKeyHash();
    dummyOwnerHashCalc.ownerNullifierKey <== 57005;            // 0xdead
    signal DUMMY_OWNER_HASH;
    DUMMY_OWNER_HASH <== dummyOwnerHashCalc.out;

    // ===== Outputs: per-slot derivation =====
    // Per spec Section 8.5, every output slot deterministically derives noteSecret,
    // computes ownerCommitment, noteBodyCommitment, and binds noteBodyCommitment
    // to the public input.
    component outNoteSecret[3];
    component outOC[3];
    component outBC[3];
    component outBind[3];
    component outAmtIsZero[3];
    signal    outBodyToken[3];

    for (var i = 0; i < 3; i++) {
        outNoteSecret[i] = TransactNoteSecret();
        outNoteSecret[i].noteSecretSeed <== senderNoteSecretSeed;
        outNoteSecret[i].intentReplayId <== intentReplayId;
        outNoteSecret[i].outputIndex    <== i;

        outOC[i] = OwnerCommitment();
        outOC[i].ownerNullifierKeyHash <== outOwnerNullifierKeyHash[i];
        outOC[i].noteSecret            <== outNoteSecret[i].out;

        // Real output  -> body uses canonical tokenAddress
        // Dummy output -> body uses 0 (spec Section 8.5 dummy)
        outBodyToken[i] <== outIsReal[i] * tokenAddress;

        outBC[i] = NoteBodyCommitment();
        outBC[i].ownerCommitment <== outOC[i].out;
        outBC[i].amount          <== outAmount[i];
        outBC[i].tokenAddress    <== outBodyToken[i];

        outBind[i] = OutputBinding();
        outBind[i].noteBodyCommitment <== outBC[i].out;

        // Dummy output -> amount == 0 (spec Section 8.5)
        (1 - outIsReal[i]) * outAmount[i] === 0;
        // Dummy output -> ownerNullifierKeyHash == DUMMY_OWNER_NULLIFIER_KEY_HASH
        (1 - outIsReal[i]) * (outOwnerNullifierKeyHash[i] - DUMMY_OWNER_HASH) === 0;
        // Real output -> amount > 0 (spec Section 8.5)
        outAmtIsZero[i] = IsZero();
        outAmtIsZero[i].in <== outAmount[i];
        outIsReal[i] * outAmtIsZero[i].out === 0;
    }
    outBind[0].outputNoteDataHash <== outputNoteDataHash0;
    outBind[1].outputNoteDataHash <== outputNoteDataHash1;
    outBind[2].outputNoteDataHash <== outputNoteDataHash2;

    // ===== Output-binding lock (spec Section 8.10) =====
    // Strict pairing: flag bit set => locked == binding; flag bit unset => locked == 0.
    signal lockFlagBit[3];
    for (var i = 0; i < 3; i++) {
        lockFlagBit[i] <== nbExecFlags.out[i];
        lockFlagBit[i]       * (outLockedOutputBinding[i] - outBind[i].out) === 0;
        (1 - lockFlagBit[i]) *  outLockedOutputBinding[i] === 0;
    }

    // Bind output noteBodyCommitments to public inputs
    outBC[0].out === noteBodyCommitment0;
    outBC[1].out === noteBodyCommitment1;
    outBC[2].out === noteBodyCommitment2;

    // ===== Per-mode output assignments (spec Section 8.5) =====
    // Transfer (operationKind == 0):
    //   slot 0 MUST be real, owned by recipientOwnerNullifierKeyHash, which
    //     MUST NOT be 0 or DUMMY_OWNER_HASH.
    //   slot 1 if real, owned by sender (senderOwnerNullifierKeyHash).
    (1 - operationKind) * (1 - outIsReal[0]) === 0;
    (1 - operationKind) * (outOwnerNullifierKeyHash[0] - recipientOwnerNullifierKeyHash) === 0;

    component recipOwnerIsZero  = IsZero();
    recipOwnerIsZero.in  <== recipientOwnerNullifierKeyHash;
    component recipOwnerIsDummy = IsZero();
    recipOwnerIsDummy.in <== recipientOwnerNullifierKeyHash - DUMMY_OWNER_HASH;
    (1 - operationKind) * recipOwnerIsZero.out  === 0;
    (1 - operationKind) * recipOwnerIsDummy.out === 0;

    signal sel_xfer_real1;
    sel_xfer_real1 <== (1 - operationKind) * outIsReal[1];
    sel_xfer_real1 * (outOwnerNullifierKeyHash[1] - senderOwnerNullifierKeyHash) === 0;

    // Withdrawal (operationKind == 1):
    //   slot 0 if real, owned by sender (senderOwnerNullifierKeyHash).
    //   slot 1 MUST be dummy.
    //   recipientOwnerNullifierKeyHash MUST be 0 (transfer-only field).
    operationKind * outIsReal[1] === 0;
    operationKind * recipientOwnerNullifierKeyHash === 0;

    signal sel_with_real0;
    sel_with_real0 <== operationKind * outIsReal[0];
    sel_with_real0 * (outOwnerNullifierKeyHash[0] - senderOwnerNullifierKeyHash) === 0;

    // ===== Fee-slot rules (spec Section 8.5) =====
    component feeAmtIsZero = IsZero();
    feeAmtIsZero.in <== feeAmount;

    // dummy slot 2 <=> feeAmount == 0
    (1 - outIsReal[2]) * feeAmount === 0;
    feeAmtIsZero.out * outIsReal[2] === 0;

    // real slot 2 -> outAmount[2] == feeAmount AND
    //                outOwnerNullifierKeyHash[2] == feeNoteRecipientOwnerNullifierKeyHash
    outIsReal[2] * (outAmount[2] - feeAmount) === 0;
    outIsReal[2] * (outOwnerNullifierKeyHash[2] - feeNoteRecipientOwnerNullifierKeyHash) === 0;

    // feeAmount == 0 ⇒ feeNoteRecipientOwnerNullifierKeyHash == 0
    feeAmtIsZero.out * feeNoteRecipientOwnerNullifierKeyHash === 0;

    // real slot 2 ⇒ feeNoteRecipientOwnerNullifierKeyHash != 0 and != DUMMY
    component feeRecipOwnerIsZero  = IsZero();
    feeRecipOwnerIsZero.in  <== feeNoteRecipientOwnerNullifierKeyHash;
    component feeRecipOwnerIsDummy = IsZero();
    feeRecipOwnerIsDummy.in <== feeNoteRecipientOwnerNullifierKeyHash - DUMMY_OWNER_HASH;
    outIsReal[2] * feeRecipOwnerIsZero.out  === 0;
    outIsReal[2] * feeRecipOwnerIsDummy.out === 0;

    // ===== Value conservation =====
    // sum(real input amounts) == sum(real output amounts) + publicAmountOut
    signal in0Eff;  in0Eff  <== inIsReal[0]  * inAmount[0];
    signal in1Eff;  in1Eff  <== inIsReal[1]  * inAmount[1];
    signal out0Eff; out0Eff <== outIsReal[0] * outAmount[0];
    signal out1Eff; out1Eff <== outIsReal[1] * outAmount[1];
    signal out2Eff; out2Eff <== outIsReal[2] * outAmount[2];
    in0Eff + in1Eff === out0Eff + out1Eff + out2Eff + publicAmountOut;

    // ===== Intent replay ID =====
    component irc = IntentReplayId();
    irc.ownerNullifierKey  <== senderOwnerNullifierKey;
    irc.authorizingAddress <== authorizingAddress;
    irc.executionChainId   <== executionChainId;
    irc.nonce              <== nonce;
    irc.out === intentReplayId;

    // ===== Blinded auth commitment =====
    component bac = BlindedAuthCommitment();
    bac.authDataCommitment <== authDataCommitment;
    bac.blindingFactor     <== blindingFactor;
    bac.out === blindedAuthCommitment;

    // ===== Transaction intent digest =====
    // amount in digest:
    //   transfer    -> outAmount[0] (recipient amount)
    //   withdrawal  -> publicAmountOut
    signal intentAmountTransfer;
    signal intentAmountWithdrawal;
    intentAmountTransfer   <== (1 - operationKind) * outAmount[0];
    intentAmountWithdrawal <== operationKind        * publicAmountOut;
    signal intentAmount;
    intentAmount <== intentAmountTransfer + intentAmountWithdrawal;

    component tid = TransactionIntentDigest();
    tid.authVerifier                          <== authVerifier;
    tid.authorizingAddress                    <== authorizingAddress;
    tid.operationKind                         <== operationKind;
    tid.tokenAddress                          <== tokenAddress;
    tid.recipientOwnerNullifierKeyHash        <== recipientOwnerNullifierKeyHash;
    tid.amount                                <== intentAmount;
    tid.feeNoteRecipientOwnerNullifierKeyHash <== feeNoteRecipientOwnerNullifierKeyHash;
    tid.feeAmount                             <== feeAmount;
    tid.publicRecipientAddress                <== publicRecipientAddress;
    tid.executionConstraintsFlags             <== executionConstraintsFlags;
    tid.lockedOutputBinding0                  <== outLockedOutputBinding[0];
    tid.lockedOutputBinding1                  <== outLockedOutputBinding[1];
    tid.lockedOutputBinding2                  <== outLockedOutputBinding[2];
    tid.nonce                                 <== nonce;
    tid.validUntilSeconds                     <== validUntilSeconds;
    tid.executionChainId                      <== executionChainId;
    tid.out === transactionIntentDigest;
}

component main { public [
    noteCommitmentRoot,
    nullifier0, nullifier1,
    noteBodyCommitment0, noteBodyCommitment1, noteBodyCommitment2,
    publicAmountOut, publicRecipientAddress, publicTokenAddress,
    intentReplayId,
    validUntilSeconds, executionChainId,
    authPolicyRoot,
    outputNoteDataHash0, outputNoteDataHash1, outputNoteDataHash2,
    authVerifier,
    blindedAuthCommitment, transactionIntentDigest
] } = Pool();
