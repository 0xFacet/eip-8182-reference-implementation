// Build a worst-case witness for the demo auth circuit. Mirrors the values
// the pool circuit's worst-case witness uses for the corresponding intent
// fields, so the two proofs agree on transactionIntentDigest in the
// integration test.
//
// Usage:
//   node scripts/witness/gen_auth_demo_witness_input.js [intent.json]
//
// Without an argument, writes the same default intent the pool worst-case
// witness uses. With an argument, reads {authVerifier, ..., authSecret,
// blindingFactor, blindedAuthCommitment, transactionIntentDigest} from JSON.

const fs = require("fs");
const path = require("path");
const { poseidon } = require("./poseidon2");

const ROOT = path.resolve(__dirname, "../..");
const TAGS = JSON.parse(
  fs.readFileSync(path.join(ROOT, "build/domain_tags.json"), "utf8"),
);
const T = Object.fromEntries(
  Object.entries(TAGS).map(([k, v]) => [k, BigInt(v)]),
);

const argPath = process.argv[2];
let intent;

if (argPath) {
  intent = JSON.parse(fs.readFileSync(argPath, "utf8"));
} else {
  // Defaults match scripts/witness/gen_pool_witness_input.js so both
  // proofs share identical blindedAuthCommitment + transactionIntentDigest.
  // operationKind=0 is TRANSFER_OP per spec Section 3.2 (was 1 pre-fix).
  // The locked bindings here are the pool witness's worst-case values
  // (computed in the pool witness gen); the shared-intent path overrides
  // these with real values from the pool input.
  const authVerifier             = 0xA1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1n;
  const authorizingAddress       = 0x1111111111111111111111111111111111111111n;
  const operationKind            = 0n; // TRANSFER_OP per spec Section 3.2
  const tokenAddress             = 0x2222222222222222222222222222222222222222n;
  const recipientAddress         = 0x3333333333333333333333333333333333333333n;
  const amount                   = 8n; // outAmount[0] = recipient amount
  const feeRecipientAddress      = 0x4444444444444444444444444444444444444444n;
  const feeAmount                = 2n;
  const executionConstraintsFlags= 0n;
  const lockedOutputBinding0     = 0n;
  const lockedOutputBinding1     = 0n;
  const lockedOutputBinding2     = 0n;
  const nonce                    = 0x9F3A1C7E5B2D4F86n;
  const validUntilSeconds        = 1735689600n;
  const executionChainId         = 1n;
  const authSecret               = 0xA0701337n;
  const blindingFactor           = 0xB17ED15ABCDEF0123456789ABCDEF01n;
  intent = {
    authVerifier:               authVerifier.toString(),
    authorizingAddress:         authorizingAddress.toString(),
    operationKind:              operationKind.toString(),
    tokenAddress:               tokenAddress.toString(),
    recipientAddress:           recipientAddress.toString(),
    amount:                     amount.toString(),
    feeRecipientAddress:        feeRecipientAddress.toString(),
    feeAmount:                  feeAmount.toString(),
    executionConstraintsFlags:  executionConstraintsFlags.toString(),
    lockedOutputBinding0:       lockedOutputBinding0.toString(),
    lockedOutputBinding1:       lockedOutputBinding1.toString(),
    lockedOutputBinding2:       lockedOutputBinding2.toString(),
    nonce:                      nonce.toString(),
    validUntilSeconds:          validUntilSeconds.toString(),
    executionChainId:           executionChainId.toString(),
    authSecret:                 authSecret.toString(),
    blindingFactor:             blindingFactor.toString(),
  };
}

// Recompute authDataCommitment, blindedAuthCommitment, transactionIntentDigest
const authSecret = BigInt(intent.authSecret);
const blindingFactor = BigInt(intent.blindingFactor);

const authDataCommitment = poseidon(T.POLICY_COMMITMENT_DOMAIN, authSecret);
const blindedAuthCommitment = poseidon(
  T.BLINDED_AUTH_COMMITMENT_DOMAIN,
  authDataCommitment,
  blindingFactor,
);
const transactionIntentDigest = poseidon(
  T.TRANSACTION_INTENT_DIGEST_DOMAIN,
  BigInt(intent.authVerifier),
  BigInt(intent.authorizingAddress),
  BigInt(intent.operationKind),
  BigInt(intent.tokenAddress),
  BigInt(intent.recipientAddress),
  BigInt(intent.amount),
  BigInt(intent.feeRecipientAddress),
  BigInt(intent.feeAmount),
  BigInt(intent.executionConstraintsFlags),
  BigInt(intent.lockedOutputBinding0),
  BigInt(intent.lockedOutputBinding1),
  BigInt(intent.lockedOutputBinding2),
  BigInt(intent.nonce),
  BigInt(intent.validUntilSeconds),
  BigInt(intent.executionChainId),
);

const out = {
  blindedAuthCommitment: blindedAuthCommitment.toString(),
  transactionIntentDigest: transactionIntentDigest.toString(),
  ...intent,
};

const outPath = path.join(ROOT, "build/auth_demo/input.json");
fs.mkdirSync(path.dirname(outPath), { recursive: true });
fs.writeFileSync(outPath, JSON.stringify(out, null, 2));
console.log(`wrote ${outPath}`);
console.log(`  authDataCommitment        = ${authDataCommitment.toString()}`);
console.log(`  blindedAuthCommitment     = ${blindedAuthCommitment.toString()}`);
console.log(`  transactionIntentDigest   = ${transactionIntentDigest.toString()}`);
