// Demo auth circuit for EIP-8182 reference implementation.
//
// This is a minimal auth circuit that conforms to Section 9.1's auth-proof
// relation while keeping the credential cheap to verify in-circuit. It is
// intended for end-to-end integration testing of the split-proof flow, not
// for production deployment.
//
// Credential model (intentionally simple):
//   The user's private credential is a single field element `authSecret`.
//   The "signature" is just knowledge of `authSecret`, so the circuit proves:
//     authDataCommitment == poseidon(POLICY_COMMITMENT_DOMAIN, authSecret)
//   ...where the user, ahead of registration, computed authDataCommitment
//   from authSecret and registered it inside policyCommitment.
//
// The circuit then computes:
//   blindedAuthCommitment = poseidon(BLINDED_AUTH_COMMITMENT_DOMAIN,
//                                    authDataCommitment, blindingFactor)
//   transactionIntentDigest = Section 9.10
//
// Public outputs (the two values the system contract passes to verifyAuth):
//   [blindedAuthCommitment, transactionIntentDigest]
//
// Why this is "the demo":
// - Real production: replace `authDataCommitment == poseidon(authSecret)`
//   with a secp256k1 ECDSA signature check over an EIP-712 typed-data hash,
//   per Section 14. That requires ~1.5M constraints via 0xPARC's
//   circom-ecdsa + ~150K constraints for keccak. Composition pattern is the
//   same: bind authVerifier == address(this) (here we accept it as a public
//   input and the verifier contract enforces the binding), authenticate the
//   intent fields, derive authDataCommitment from the public key.
//
// All hash contexts use the same Poseidon2 sponge as the pool circuit
// (Section 3.3), with domain tags matching circuits/common/domain_tags.circom.

pragma circom 2.0.0;

include "poseidon2_sponge.circom";
include "components.circom";
include "domain_tags.circom";

template AuthDemo() {
    // ===== Public inputs (Section 9.1: exactly 2, in this order) =====
    signal input blindedAuthCommitment;
    signal input transactionIntentDigest;

    // ===== Private witnesses (signed intent fields per Section 9.10) =====
    signal input authVerifier;
    signal input authorizingAddress;
    signal input operationKind;
    signal input tokenAddress;
    signal input recipientAddress;
    signal input amount;
    signal input feeRecipientAddress;
    signal input feeAmount;
    signal input executionConstraintsFlags;
    signal input lockedOutputBinding0;
    signal input lockedOutputBinding1;
    signal input lockedOutputBinding2;
    signal input nonce;
    signal input validUntilSeconds;
    signal input executionChainId;

    // Demo credential: a single field element. Production replaces this with
    // an ECDSA pubkey + signature check. authDataCommitment binds the
    // "credential" the user registered.
    signal input authSecret;
    signal input blindingFactor;

    // Sanity: operationKind MUST be 0 (TRANSFER_OP) or 1 (WITHDRAWAL_OP) per
    // spec Section 3.2. The pool circuit derives this same value from
    // publicAmountOut, so digest mismatch is the real soundness fence — this
    // boolean check just rejects malformed witnesses up-front.
    operationKind * (1 - operationKind) === 0;

    // ===== Step 1: derive authDataCommitment from the credential =====
    // poseidon(POLICY_COMMITMENT_DOMAIN, authSecret)
    component authDataHash = Poseidon2Sponge(2);
    authDataHash.in[0] <== POLICY_COMMITMENT_DOMAIN();
    authDataHash.in[1] <== authSecret;
    signal authDataCommitment;
    authDataCommitment <== authDataHash.out;

    // ===== Step 2: compute blindedAuthCommitment, enforce equality =====
    component blindedHash = BlindedAuthCommitment();
    blindedHash.authDataCommitment <== authDataCommitment;
    blindedHash.blindingFactor <== blindingFactor;
    blindedAuthCommitment === blindedHash.out;

    // ===== Step 3: compute transactionIntentDigest, enforce equality =====
    component intentHash = TransactionIntentDigest();
    intentHash.authVerifier             <== authVerifier;
    intentHash.authorizingAddress       <== authorizingAddress;
    intentHash.operationKind            <== operationKind;
    intentHash.tokenAddress             <== tokenAddress;
    intentHash.recipientAddress         <== recipientAddress;
    intentHash.amount                   <== amount;
    intentHash.feeRecipientAddress      <== feeRecipientAddress;
    intentHash.feeAmount                <== feeAmount;
    intentHash.executionConstraintsFlags<== executionConstraintsFlags;
    intentHash.lockedOutputBinding0     <== lockedOutputBinding0;
    intentHash.lockedOutputBinding1     <== lockedOutputBinding1;
    intentHash.lockedOutputBinding2     <== lockedOutputBinding2;
    intentHash.nonce                    <== nonce;
    intentHash.validUntilSeconds        <== validUntilSeconds;
    intentHash.executionChainId         <== executionChainId;
    transactionIntentDigest === intentHash.out;
}

component main { public [blindedAuthCommitment, transactionIntentDigest] } = AuthDemo();
