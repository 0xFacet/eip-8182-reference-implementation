// ERC app-layer private transfers pool circuit (fixed shape, all selectors live).
//
// Adapted from the EIP-8182 pool circuit. One circuit handles:
//   - transfer or withdrawal mode (operationKind derived from publicAmountOut)
//   - 2 inputs: each real or phantom (per-input isReal selector)
//   - 3 outputs: each real or dummy (per-output isReal selector)
//   - fee slot used or unused (slot 2 is fee slot when real)
//   - locked outputs (lockedOutputBinding_i paired with executionConstraintsFlags bit i)
//   - policy-free or policy-gated transact (policyOperationDataHash in {0, transactOperationDataHash})
//
// ERC deltas from 8182:
//   - 24 public inputs (adds poolAddress, policyOperationDataHash,
//     policyDataHash, authorizedSubmitter, downstreamActionCommitment; renames
//     authPolicyRoot -> identityRoot), spec §4 declaration order.
//   - Pool-scoped derivations absorb (executionChainId, poolAddress): ownerCommitment,
//     noteCommitment, nullifier, phantomNullifier, transactNoteSecret, intentReplayId.
//   - Identity membership against the canonical privacy identity registry leaf
//     (IDENTITY_LEAF_DOMAIN), spec §8 steps 1-4.
//   - Two-level intent digest: transactIntentFieldsHash then
//     transactionIntentDigest(fieldsHash, policyDataHash), spec §15.6.
//   - In-circuit transactOperationDataHash with the §16.1 policy constraint.
//
// Constraint count is the count of the fully-selected circuit, regardless of
// which witness is fed in.

pragma circom 2.0.0;

include "poseidon2_sponge.circom";
include "components.circom";
include "merkle.circom";
include "bits.circom";

template Pool() {
    // ===== Public inputs (24 fields, spec §4 declaration order) =====
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
    signal input poolAddress;
    signal input identityRoot;
    signal input outputNoteDataHash0;
    signal input outputNoteDataHash1;
    signal input outputNoteDataHash2;
    signal input authVerifier;
    signal input blindedAuthCommitment;
    signal input transactionIntentDigest;
    signal input policyOperationDataHash;
    signal input policyDataHash;
    signal input authorizedSubmitter;
    signal input downstreamActionCommitment;

    // ===== Private witnesses =====
    // Sender identity & privacy-identity-registry leaf state
    signal input senderOwnerNullifierKey;
    signal input senderNoteSecretSeed;
    signal input authorizingAddress;                   // <2^160
    signal input noteSecretSeedHash;                   // = poseidon(NOTE_SECRET_SEED_DOMAIN, senderNoteSecretSeed)
    signal input policySetCommitment;                  // depth-POLICY_SET_DEPTH root over the user's active policyCommitments
    signal input leafPosition;                         // <2^32; user's slot in the identity registry
    signal input identitySiblings[32];

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
    component nbPoolAddress    = Num2Bits(160); nbPoolAddress.in    <== poolAddress;
    component nbPubAmt         = Num2Bits(248); nbPubAmt.in         <== publicAmountOut;
    component nbValidUntil     = Num2Bits(32);  nbValidUntil.in     <== validUntilSeconds;
    component nbExecChain      = Num2Bits(32);  nbExecChain.in      <== executionChainId;

    component nbAuthAddr       = Num2Bits(160); nbAuthAddr.in       <== authorizingAddress;
    component nbToken          = Num2Bits(160); nbToken.in          <== tokenAddress;
    component nbFeeAmount      = Num2Bits(248); nbFeeAmount.in      <== feeAmount;
    component nbExecFlags      = Num2Bits(32);  nbExecFlags.in      <== executionConstraintsFlags;
    component nbLeafPos        = Num2Bits(32);  nbLeafPos.in        <== leafPosition;
    component nbPolicySetLeafPos = Num2Bits(8); nbPolicySetLeafPos.in <== policySetLeafPosition;
    // authorizedSubmitter is an EVM address (spec §7.1); downstreamActionCommitment
    // is an opaque field element (canonical <p is enforced by the verifier).
    component nbAuthSubmitter  = Num2Bits(160); nbAuthSubmitter.in  <== authorizedSubmitter;

    // authVerifier != 0 (spec §8: public input, nonzero)
    component authVerifierIsZero = IsZero();
    authVerifierIsZero.in <== authVerifier;
    authVerifierIsZero.out === 0;

    // Reserved-flag-bit rejection (spec §8): only bits 0/1/2 are defined
    // (LOCK_OUTPUT_BINDING_0/1/2). Every other bit MUST be zero.
    for (var i = 3; i < 32; i++) {
        nbExecFlags.out[i] === 0;
    }

    // Boolean selectors
    for (var i = 0; i < 2; i++) inIsReal[i] * (1 - inIsReal[i]) === 0;
    for (var i = 0; i < 3; i++) outIsReal[i] * (1 - outIsReal[i]) === 0;

    // At-least-one-real-input (spec §8)
    (1 - inIsReal[0]) * (1 - inIsReal[1]) === 0;

    // Per-input range/decomposition. nbInLeaf.out doubles as the merkle-path bits.
    component nbInAmt[2];
    component nbInLeaf[2];
    for (var i = 0; i < 2; i++) {
        nbInAmt[i]  = Num2Bits(248); nbInAmt[i].in  <== inAmount[i];
        nbInLeaf[i] = Num2Bits(32);  nbInLeaf[i].in <== inLeafIndex[i];
    }

    // Phantom inputs MUST have amount == 0 (spec §8)
    for (var i = 0; i < 2; i++) {
        (1 - inIsReal[i]) * inAmount[i] === 0;
    }

    // Per-output amount range.
    component nbOutAmt[3];
    for (var i = 0; i < 3; i++) {
        nbOutAmt[i] = Num2Bits(248); nbOutAmt[i].in <== outAmount[i];
    }

    // ===== operationKind derivation (spec §8) =====
    // operationKind = 0 (TRANSFER_OP) iff publicAmountOut == 0
    //                 1 (WITHDRAWAL_OP) iff publicAmountOut > 0
    component pubAmtIsZero = IsZero();
    pubAmtIsZero.in <== publicAmountOut;
    signal operationKind;
    operationKind <== 1 - pubAmtIsZero.out;

    // Public-mode bindings (spec §8):
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
    // noteSecretSeedHash field extracted from the identity registry leaf.
    component senderSeedHash = NoteSecretSeedHash();
    senderSeedHash.noteSecretSeed <== senderNoteSecretSeed;
    senderSeedHash.out === noteSecretSeedHash;

    // ===== DUMMY_OWNER_NULLIFIER_KEY_HASH (spec §15.6) =====
    // poseidon(OWNER_NULLIFIER_KEY_HASH_DOMAIN, 0xdead). setIdentity rejects
    // this value, so notes whose owner-hash is DUMMY are structurally
    // unspendable.
    component dummyOwnerHashCalc = OwnerNullifierKeyHash();
    dummyOwnerHashCalc.ownerNullifierKey <== 57005;            // 0xdead
    signal DUMMY_OWNER_HASH;
    DUMMY_OWNER_HASH <== dummyOwnerHashCalc.out;

    // Spec §8 step 3: ownerNullifierKeyHash != 0, != DUMMY; noteSecretSeedHash != 0.
    component senderOwnerHashIsZero = IsZero();
    senderOwnerHashIsZero.in <== senderOwnerNullifierKeyHash;
    senderOwnerHashIsZero.out === 0;
    component senderOwnerHashIsDummy = IsZero();
    senderOwnerHashIsDummy.in <== senderOwnerNullifierKeyHash - DUMMY_OWNER_HASH;
    senderOwnerHashIsDummy.out === 0;
    component seedHashIsZero = IsZero();
    seedHashIsZero.in <== noteSecretSeedHash;
    seedHashIsZero.out === 0;

    // ===== Identity registry leaf membership (spec §8 step 4) =====
    component idLeaf = IdentityLeaf();
    idLeaf.user                  <== authorizingAddress;
    idLeaf.ownerNullifierKeyHash <== senderOwnerNullifierKeyHash;
    idLeaf.noteSecretSeedHash    <== noteSecretSeedHash;
    idLeaf.policySetCommitment   <== policySetCommitment;

    component idPath = MerklePath(32);
    idPath.leaf <== idLeaf.out;
    for (var b = 0; b < 32; b++) {
        idPath.pathBits[b] <== nbLeafPos.out[b];
        idPath.siblings[b] <== identitySiblings[b];
    }
    idPath.root === identityRoot;

    // ===== Policy-set membership (spec §8 steps 5-6) =====
    // policyCommitment = poseidon(POLICY_COMMITMENT_DOMAIN, authVerifier,
    //                             authDataCommitment, registrationBlinder)
    // authVerifier here is the PUBLIC INPUT signal — the circuit MUST NOT use
    // a separate witnessed auth-verifier value (spec §8).
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
        inOC[i].executionChainId      <== executionChainId;
        inOC[i].poolAddress           <== poolAddress;
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
        inNC[i].executionChainId   <== executionChainId;
        inNC[i].poolAddress        <== poolAddress;
        inNC[i].noteBodyCommitment <== inBC[i].out;
        inNC[i].leafIndex          <== inLeafIndex[i];

        inNF[i] = Nullifier();
        inNF[i].executionChainId  <== executionChainId;
        inNF[i].poolAddress       <== poolAddress;
        inNF[i].noteCommitment    <== inNC[i].out;
        inNF[i].ownerNullifierKey <== senderOwnerNullifierKey;

        inPN[i] = PhantomNullifier();
        inPN[i].executionChainId  <== executionChainId;
        inPN[i].poolAddress       <== poolAddress;
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

    // ===== Outputs: per-slot derivation =====
    // Per spec §8, every output slot deterministically derives noteSecret,
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
        outNoteSecret[i].noteSecretSeed   <== senderNoteSecretSeed;
        outNoteSecret[i].executionChainId <== executionChainId;
        outNoteSecret[i].poolAddress      <== poolAddress;
        outNoteSecret[i].intentReplayId   <== intentReplayId;
        outNoteSecret[i].outputIndex      <== i;

        outOC[i] = OwnerCommitment();
        outOC[i].executionChainId      <== executionChainId;
        outOC[i].poolAddress           <== poolAddress;
        outOC[i].ownerNullifierKeyHash <== outOwnerNullifierKeyHash[i];
        outOC[i].noteSecret            <== outNoteSecret[i].out;

        // Real output  -> body uses canonical tokenAddress
        // Dummy output -> body uses 0 (spec §8 dummy)
        outBodyToken[i] <== outIsReal[i] * tokenAddress;

        outBC[i] = NoteBodyCommitment();
        outBC[i].ownerCommitment <== outOC[i].out;
        outBC[i].amount          <== outAmount[i];
        outBC[i].tokenAddress    <== outBodyToken[i];

        outBind[i] = OutputBinding();
        outBind[i].noteBodyCommitment <== outBC[i].out;

        // Dummy output -> amount == 0 (spec §8)
        (1 - outIsReal[i]) * outAmount[i] === 0;
        // Dummy output -> ownerNullifierKeyHash == DUMMY_OWNER_NULLIFIER_KEY_HASH
        (1 - outIsReal[i]) * (outOwnerNullifierKeyHash[i] - DUMMY_OWNER_HASH) === 0;
        // Real output -> amount > 0 (spec §8)
        outAmtIsZero[i] = IsZero();
        outAmtIsZero[i].in <== outAmount[i];
        outIsReal[i] * outAmtIsZero[i].out === 0;
    }
    outBind[0].outputNoteDataHash <== outputNoteDataHash0;
    outBind[1].outputNoteDataHash <== outputNoteDataHash1;
    outBind[2].outputNoteDataHash <== outputNoteDataHash2;

    // ===== Output-binding lock (spec §8) =====
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

    // ===== Per-mode output assignments (spec §8) =====
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

    // ===== Fee-slot rules (spec §8) =====
    component feeAmtIsZero = IsZero();
    feeAmtIsZero.in <== feeAmount;

    // dummy slot 2 <=> feeAmount == 0
    (1 - outIsReal[2]) * feeAmount === 0;
    feeAmtIsZero.out * outIsReal[2] === 0;

    // real slot 2 -> outAmount[2] == feeAmount AND
    //                outOwnerNullifierKeyHash[2] == feeNoteRecipientOwnerNullifierKeyHash
    outIsReal[2] * (outAmount[2] - feeAmount) === 0;
    outIsReal[2] * (outOwnerNullifierKeyHash[2] - feeNoteRecipientOwnerNullifierKeyHash) === 0;

    // feeAmount == 0 => feeNoteRecipientOwnerNullifierKeyHash == 0
    feeAmtIsZero.out * feeNoteRecipientOwnerNullifierKeyHash === 0;

    // real slot 2 => feeNoteRecipientOwnerNullifierKeyHash != 0 and != DUMMY
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
    irc.poolAddress        <== poolAddress;
    irc.nonce              <== nonce;
    irc.out === intentReplayId;

    // ===== Blinded auth commitment =====
    component bac = BlindedAuthCommitment();
    bac.authDataCommitment <== authDataCommitment;
    bac.blindingFactor     <== blindingFactor;
    bac.out === blindedAuthCommitment;

    // ===== Transaction intent digest (two-level, spec §15.6) =====
    // amount in digest:
    //   transfer    -> outAmount[0] (recipient amount)
    //   withdrawal  -> publicAmountOut
    signal intentAmountTransfer;
    signal intentAmountWithdrawal;
    intentAmountTransfer   <== (1 - operationKind) * outAmount[0];
    intentAmountWithdrawal <== operationKind        * publicAmountOut;
    signal intentAmount;
    intentAmount <== intentAmountTransfer + intentAmountWithdrawal;

    component tif = TransactIntentFieldsHash();
    tif.poolAddress                           <== poolAddress;
    tif.authVerifier                          <== authVerifier;
    tif.authorizingAddress                    <== authorizingAddress;
    tif.operationKind                         <== operationKind;
    tif.tokenAddress                          <== tokenAddress;
    tif.recipientOwnerNullifierKeyHash        <== recipientOwnerNullifierKeyHash;
    tif.amount                                <== intentAmount;
    tif.feeNoteRecipientOwnerNullifierKeyHash <== feeNoteRecipientOwnerNullifierKeyHash;
    tif.feeAmount                             <== feeAmount;
    tif.publicRecipientAddress                <== publicRecipientAddress;
    tif.authorizedSubmitter                   <== authorizedSubmitter;
    tif.downstreamActionCommitment            <== downstreamActionCommitment;
    tif.executionConstraintsFlags             <== executionConstraintsFlags;
    tif.lockedOutputBinding0                  <== outLockedOutputBinding[0];
    tif.lockedOutputBinding1                  <== outLockedOutputBinding[1];
    tif.lockedOutputBinding2                  <== outLockedOutputBinding[2];
    tif.nonce                                 <== nonce;
    tif.validUntilSeconds                     <== validUntilSeconds;
    tif.executionChainId                      <== executionChainId;

    component tid = TransactionIntentDigest();
    tid.transactIntentFieldsHash <== tif.out;
    tid.policyDataHash           <== policyDataHash;
    tid.out === transactionIntentDigest;

    // ===== Policy operation data hash (spec §16.1) =====
    // transactOperationDataHash = poseidon(POLICY_TRANSACT_OPERATION_DATA_DOMAIN,
    //     transactIntentFieldsHash, transactPublicTransitionHash)
    // policyOperationDataHash MUST be 0 (policy-free) or transactOperationDataHash
    // (policy-gated). Computed in-circuit for every pool profile.
    component tph = TransactPublicTransitionHash();
    tph.noteCommitmentRoot     <== noteCommitmentRoot;
    tph.nullifier0             <== nullifier0;
    tph.nullifier1             <== nullifier1;
    tph.noteBodyCommitment0    <== noteBodyCommitment0;
    tph.noteBodyCommitment1    <== noteBodyCommitment1;
    tph.noteBodyCommitment2    <== noteBodyCommitment2;
    tph.publicAmountOut        <== publicAmountOut;
    tph.publicRecipientAddress <== publicRecipientAddress;
    tph.publicTokenAddress     <== publicTokenAddress;
    tph.intentReplayId         <== intentReplayId;
    tph.validUntilSeconds      <== validUntilSeconds;
    tph.executionChainId       <== executionChainId;
    tph.poolAddress            <== poolAddress;
    tph.identityRoot           <== identityRoot;
    tph.outputNoteDataHash0    <== outputNoteDataHash0;
    tph.outputNoteDataHash1    <== outputNoteDataHash1;
    tph.outputNoteDataHash2    <== outputNoteDataHash2;
    tph.authVerifier           <== authVerifier;
    tph.blindedAuthCommitment  <== blindedAuthCommitment;
    tph.authorizedSubmitter    <== authorizedSubmitter;
    tph.downstreamActionCommitment <== downstreamActionCommitment;

    component tod = TransactOperationDataHash();
    tod.transactIntentFieldsHash     <== tif.out;
    tod.transactPublicTransitionHash <== tph.out;

    policyOperationDataHash * (policyOperationDataHash - tod.out) === 0;
}

component main { public [
    noteCommitmentRoot,
    nullifier0, nullifier1,
    noteBodyCommitment0, noteBodyCommitment1, noteBodyCommitment2,
    publicAmountOut, publicRecipientAddress, publicTokenAddress,
    intentReplayId,
    validUntilSeconds, executionChainId,
    poolAddress,
    identityRoot,
    outputNoteDataHash0, outputNoteDataHash1, outputNoteDataHash2,
    authVerifier,
    blindedAuthCommitment, transactionIntentDigest,
    policyOperationDataHash, policyDataHash,
    authorizedSubmitter, downstreamActionCommitment
] } = Pool();
