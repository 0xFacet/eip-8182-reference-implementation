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
// Public inputs: 21 fields per spec Section 10, in declaration order.
// Section 9.1-9.11 constraints all wired in.

pragma circom 2.0.0;

include "poseidon2_sponge.circom";
include "components.circom";
include "merkle.circom";
include "bits.circom";

template Pool() {
    // ===== Public inputs (21 fields, Section 10 declaration order) =====
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
    signal input registryRoot;
    signal input validUntilSeconds;
    signal input executionChainId;
    signal input authPolicyRegistrationRoot;
    signal input authPolicyRevocationRoot;
    signal input outputNoteDataHash0;
    signal input outputNoteDataHash1;
    signal input outputNoteDataHash2;
    signal input authVerifier;
    signal input blindedAuthCommitment;
    signal input transactionIntentDigest;

    // ===== Private witnesses =====
    // Sender identity & registration
    signal input senderOwnerNullifierKey;
    signal input senderNoteSecretSeed;
    signal input authorizingAddress;                   // <2^160; equals senderUser
    signal input senderUserSiblings[160];              // path bits derived from authorizingAddress

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
    signal input outRecipient[3];                      // <2^160
    signal input outRecipientNoteSecretSeedHash[3];
    signal input outRecipientSiblings[3][160];         // path bits derived from outRecipient
    signal input outLockedOutputBinding[3];            // signed lock value (paired with flag bit i)

    // Canonical token (single witness shared by all real inputs/outputs)
    signal input tokenAddress;                         // <2^160

    // Intent fields (private signed)
    signal input recipientAddress;                     // signed; <2^160
    signal input feeRecipientAddress;                  // signed; <2^160
    signal input feeNoteRecipientAddress;              // <2^160; actual slot-2 recipient
    signal input feeAmount;                            // <2^248
    signal input nonce;
    signal input executionConstraintsFlags;            // <2^32, only bits 0/1/2 may be set

    // Auth-policy registration + revocation
    signal input authDataCommitment;
    signal input blindingFactor;
    signal input registrationBlinder;
    signal input leafPosition;                         // <2^32
    signal input authRegSiblings[32];
    signal input authRevSiblings[32];

    // ===== Range / boolean checks =====
    component nbAuthVerifier   = Num2Bits(160); nbAuthVerifier.in   <== authVerifier;
    component nbPubRecipient   = Num2Bits(160); nbPubRecipient.in   <== publicRecipientAddress;
    component nbPubToken       = Num2Bits(160); nbPubToken.in       <== publicTokenAddress;
    component nbPubAmt         = Num2Bits(248); nbPubAmt.in         <== publicAmountOut;
    component nbValidUntil     = Num2Bits(32);  nbValidUntil.in     <== validUntilSeconds;
    component nbExecChain      = Num2Bits(32);  nbExecChain.in      <== executionChainId;

    component nbRecipient      = Num2Bits(160); nbRecipient.in      <== recipientAddress;
    component nbFeeRecipient   = Num2Bits(160); nbFeeRecipient.in   <== feeRecipientAddress;
    component nbFeeNoteRecip   = Num2Bits(160); nbFeeNoteRecip.in   <== feeNoteRecipientAddress;
    component nbAuthAddr       = Num2Bits(160); nbAuthAddr.in       <== authorizingAddress;
    component nbToken          = Num2Bits(160); nbToken.in          <== tokenAddress;
    component nbFeeAmount      = Num2Bits(248); nbFeeAmount.in      <== feeAmount;
    component nbExecFlags      = Num2Bits(32);  nbExecFlags.in      <== executionConstraintsFlags;
    component nbLeafPos        = Num2Bits(32);  nbLeafPos.in        <== leafPosition;

    // Reserved-flag-bit rejection (spec Section 9.11): only bits 0/1/2 are
    // defined (LOCK_OUTPUT_BINDING_0/1/2). Every other bit MUST be zero.
    for (var i = 3; i < 32; i++) {
        nbExecFlags.out[i] === 0;
    }

    // Boolean selectors
    for (var i = 0; i < 2; i++) inIsReal[i] * (1 - inIsReal[i]) === 0;
    for (var i = 0; i < 3; i++) outIsReal[i] * (1 - outIsReal[i]) === 0;

    // At-least-one-real-input (spec Sections 8.2, 8.3, 9.2)
    (1 - inIsReal[0]) * (1 - inIsReal[1]) === 0;

    // Per-input range/decomposition. nbInLeaf.out doubles as the merkle-path bits.
    component nbInAmt[2];
    component nbInLeaf[2];
    for (var i = 0; i < 2; i++) {
        nbInAmt[i]  = Num2Bits(248); nbInAmt[i].in  <== inAmount[i];
        nbInLeaf[i] = Num2Bits(32);  nbInLeaf[i].in <== inLeafIndex[i];
    }

    // Phantom inputs MUST have amount == 0 (spec Section 9.2)
    for (var i = 0; i < 2; i++) {
        (1 - inIsReal[i]) * inAmount[i] === 0;
    }

    // Per-output range. nbOutRecip.out doubles as the recipient registry path bits.
    component nbOutAmt[3];
    component nbOutRecip[3];
    for (var i = 0; i < 3; i++) {
        nbOutAmt[i]   = Num2Bits(248); nbOutAmt[i].in   <== outAmount[i];
        nbOutRecip[i] = Num2Bits(160); nbOutRecip[i].in <== outRecipient[i];
    }

    // ===== operationKind derivation (spec Section 9.10) =====
    // operationKind = 0 (TRANSFER_OP) iff publicAmountOut == 0
    //                1 (WITHDRAWAL_OP) iff publicAmountOut > 0
    component pubAmtIsZero = IsZero();
    pubAmtIsZero.in <== publicAmountOut;
    signal operationKind;
    operationKind <== 1 - pubAmtIsZero.out;

    // Public-mode bindings (spec Section 9.10):
    //   transfer    : publicRecipientAddress == 0 AND publicTokenAddress == 0
    //   withdrawal  : publicRecipientAddress == recipientAddress (signed)
    //                 publicTokenAddress     == tokenAddress (signed)
    (1 - operationKind) * publicRecipientAddress === 0;
    (1 - operationKind) * publicTokenAddress === 0;
    operationKind * (publicTokenAddress - tokenAddress) === 0;
    operationKind * (publicRecipientAddress - recipientAddress) === 0;

    // ===== Sender identity =====
    component senderHashKey = OwnerNullifierKeyHash();
    senderHashKey.ownerNullifierKey <== senderOwnerNullifierKey;
    signal senderOwnerNullifierKeyHash;
    senderOwnerNullifierKeyHash <== senderHashKey.out;

    component senderSeedHash = NoteSecretSeedHash();
    senderSeedHash.noteSecretSeed <== senderNoteSecretSeed;
    signal senderNoteSecretSeedHash;
    senderNoteSecretSeedHash <== senderSeedHash.out;

    // Sender user-registry leaf
    component senderRegLeaf = UserRegistryLeaf();
    senderRegLeaf.user                  <== authorizingAddress;
    senderRegLeaf.ownerNullifierKeyHash <== senderOwnerNullifierKeyHash;
    senderRegLeaf.noteSecretSeedHash    <== senderNoteSecretSeedHash;

    // Sender user-registry path -> registryRoot. Path bits derived from
    // authorizingAddress's bit decomposition; this binds membership to *this*
    // address rather than to "some path that lands at this leaf" (spec 9.6).
    component senderRegPath = MerklePath(160);
    senderRegPath.leaf <== senderRegLeaf.out;
    for (var b = 0; b < 160; b++) {
        senderRegPath.pathBits[b] <== nbAuthAddr.out[b];
        senderRegPath.siblings[b] <== senderUserSiblings[b];
    }
    senderRegPath.root === registryRoot;

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
    // poseidon(OWNER_NULLIFIER_KEY_HASH_DOMAIN, 0xdead). Reserved value that
    // registerUser rejects, making dummy-shaped notes structurally unspendable.
    component dummyOwnerHashCalc = OwnerNullifierKeyHash();
    dummyOwnerHashCalc.ownerNullifierKey <== 57005;            // 0xdead
    signal DUMMY_OWNER_HASH;
    DUMMY_OWNER_HASH <== dummyOwnerHashCalc.out;

    // ===== Outputs: per-slot derivation =====
    // Per spec Section 9.5, every output slot deterministically derives noteSecret,
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
        // Dummy output -> body uses 0 (spec Section 9.5 dummy)
        outBodyToken[i] <== outIsReal[i] * tokenAddress;

        outBC[i] = NoteBodyCommitment();
        outBC[i].ownerCommitment <== outOC[i].out;
        outBC[i].amount          <== outAmount[i];
        outBC[i].tokenAddress    <== outBodyToken[i];

        outBind[i] = OutputBinding();
        outBind[i].noteBodyCommitment <== outBC[i].out;

        // Dummy output -> amount == 0 (spec Section 9.5)
        (1 - outIsReal[i]) * outAmount[i] === 0;
        // Dummy output -> ownerNullifierKeyHash == DUMMY_OWNER_NULLIFIER_KEY_HASH
        (1 - outIsReal[i]) * (outOwnerNullifierKeyHash[i] - DUMMY_OWNER_HASH) === 0;
        // Real output -> amount > 0 (spec Section 9.5)
        outAmtIsZero[i] = IsZero();
        outAmtIsZero[i].in <== outAmount[i];
        outIsReal[i] * outAmtIsZero[i].out === 0;
    }
    outBind[0].outputNoteDataHash <== outputNoteDataHash0;
    outBind[1].outputNoteDataHash <== outputNoteDataHash1;
    outBind[2].outputNoteDataHash <== outputNoteDataHash2;

    // ===== Output-binding lock (spec Section 9.11) =====
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

    // ===== Recipient registry membership (one per real output) =====
    // Path bits derived from outRecipient bits (binding membership to *this*
    // recipient address). Selectively enforced for real outputs.
    component outRegLeaf[3];
    component outRegPath[3];
    for (var i = 0; i < 3; i++) {
        outRegLeaf[i] = UserRegistryLeaf();
        outRegLeaf[i].user                  <== outRecipient[i];
        outRegLeaf[i].ownerNullifierKeyHash <== outOwnerNullifierKeyHash[i];
        outRegLeaf[i].noteSecretSeedHash    <== outRecipientNoteSecretSeedHash[i];

        outRegPath[i] = MerklePath(160);
        outRegPath[i].leaf <== outRegLeaf[i].out;
        for (var b = 0; b < 160; b++) {
            outRegPath[i].pathBits[b] <== nbOutRecip[i].out[b];
            outRegPath[i].siblings[b] <== outRecipientSiblings[i][b];
        }
        outIsReal[i] * (outRegPath[i].root - registryRoot) === 0;
    }

    // ===== Per-mode output assignments (spec Section 9.5) =====
    // Transfer (operationKind == 0):
    //   slot 0 MUST be real and owned by recipientAddress
    //   slot 1 if real, owned by sender (authorizingAddress)
    (1 - operationKind) * (1 - outIsReal[0]) === 0;
    (1 - operationKind) * (outRecipient[0] - recipientAddress) === 0;

    signal sel_xfer_real1;
    sel_xfer_real1 <== (1 - operationKind) * outIsReal[1];
    sel_xfer_real1 * (outRecipient[1] - authorizingAddress) === 0;

    // Withdrawal (operationKind == 1):
    //   slot 0 if real, owned by sender (authorizingAddress)
    //   slot 1 MUST be dummy
    operationKind * outIsReal[1] === 0;

    signal sel_with_real0;
    sel_with_real0 <== operationKind * outIsReal[0];
    sel_with_real0 * (outRecipient[0] - authorizingAddress) === 0;

    // ===== Fee-slot rules (spec Section 9.5) =====
    component feeAmtIsZero = IsZero();
    feeAmtIsZero.in <== feeAmount;
    component feeRecipIsZero = IsZero();
    feeRecipIsZero.in <== feeRecipientAddress;

    // dummy slot 2 ⇔ feeAmount == 0
    (1 - outIsReal[2]) * feeAmount === 0;
    feeAmtIsZero.out * outIsReal[2] === 0;

    // real slot 2 -> outAmount[2] == feeAmount AND outRecipient[2] == feeNoteRecipientAddress
    outIsReal[2] * (outAmount[2] - feeAmount) === 0;
    outIsReal[2] * (outRecipient[2] - feeNoteRecipientAddress) === 0;

    // feeRecipientAddress != 0 ⇒ feeNoteRecipientAddress == feeRecipientAddress
    signal feeRecipientNonZero;
    feeRecipientNonZero <== 1 - feeRecipIsZero.out;
    feeRecipientNonZero * (feeNoteRecipientAddress - feeRecipientAddress) === 0;

    // feeAmount == 0 ⇒ feeNoteRecipientAddress == 0
    feeAmtIsZero.out * feeNoteRecipientAddress === 0;

    // real slot 2 ⇒ feeNoteRecipientAddress != 0 (spec Section 9.5).
    // The recipient-registry membership check already blocks address 0
    // (registerUser is msg.sender-keyed and the EVM origin can't be 0x0),
    // but enforcing this directly satisfies the spec MUST without relying
    // on the contract-layer registry semantics.
    component feeNoteRecipIsZero = IsZero();
    feeNoteRecipIsZero.in <== feeNoteRecipientAddress;
    outIsReal[2] * feeNoteRecipIsZero.out === 0;

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

    // ===== Auth-policy registration tree membership =====
    component pc = PolicyCommitment();
    pc.authVerifier        <== authVerifier;
    pc.authDataCommitment  <== authDataCommitment;
    pc.registrationBlinder <== registrationBlinder;

    component apl = AuthPolicyLeaf();
    apl.user             <== authorizingAddress;
    apl.policyCommitment <== pc.out;

    component authRegPath = MerklePath(32);
    authRegPath.leaf <== apl.out;
    for (var b = 0; b < 32; b++) {
        authRegPath.pathBits[b] <== nbLeafPos.out[b];
        authRegPath.siblings[b] <== authRegSiblings[b];
    }
    authRegPath.root === authPolicyRegistrationRoot;

    // ===== Auth-policy revocation tree non-membership (leaf at leafPosition == 0) =====
    component authRevPath = MerklePath(32);
    authRevPath.leaf <== 0;
    for (var b = 0; b < 32; b++) {
        authRevPath.pathBits[b] <== nbLeafPos.out[b];
        authRevPath.siblings[b] <== authRevSiblings[b];
    }
    authRevPath.root === authPolicyRevocationRoot;

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
    tid.authVerifier               <== authVerifier;
    tid.authorizingAddress         <== authorizingAddress;
    tid.operationKind              <== operationKind;
    tid.tokenAddress               <== tokenAddress;
    tid.recipientAddress           <== recipientAddress;
    tid.amount                     <== intentAmount;
    tid.feeRecipientAddress        <== feeRecipientAddress;
    tid.feeAmount                  <== feeAmount;
    tid.executionConstraintsFlags  <== executionConstraintsFlags;
    tid.lockedOutputBinding0       <== outLockedOutputBinding[0];
    tid.lockedOutputBinding1       <== outLockedOutputBinding[1];
    tid.lockedOutputBinding2       <== outLockedOutputBinding[2];
    tid.nonce                      <== nonce;
    tid.validUntilSeconds          <== validUntilSeconds;
    tid.executionChainId           <== executionChainId;
    tid.out === transactionIntentDigest;
}

component main { public [
    noteCommitmentRoot,
    nullifier0, nullifier1,
    noteBodyCommitment0, noteBodyCommitment1, noteBodyCommitment2,
    publicAmountOut, publicRecipientAddress, publicTokenAddress,
    intentReplayId,
    registryRoot,
    validUntilSeconds, executionChainId,
    authPolicyRegistrationRoot, authPolicyRevocationRoot,
    outputNoteDataHash0, outputNoteDataHash1, outputNoteDataHash2,
    authVerifier,
    blindedAuthCommitment, transactionIntentDigest
] } = Pool();
