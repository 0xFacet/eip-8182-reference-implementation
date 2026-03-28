import assert from 'node:assert/strict'
import { ethers } from 'ethers'
import {
  LOCK_OUTPUT_BINDING_0,
  LOCK_OUTPUT_BINDING_2,
  MULTISIG_AUTH_DOMAIN,
  buildShieldedPoolIntentTypedData,
  bytesToHex,
  computeShieldedPoolIntentSigningHash,
  computeShieldedPoolIntentStructHash,
} from '../src/lib/protocol.ts'

const EXPECTED_INTENT_TYPE =
  'ShieldedPoolIntent(address authorizingAddress,uint256 policyVersion,uint256 authDomainTag,uint8 operationKind,address tokenAddress,address recipientAddress,uint256 amount,address feeRecipientAddress,uint256 feeAmount,uint8 originMode,uint256 nonce,uint32 validUntilSeconds,uint32 executionConstraintsFlags,uint256 lockedOutputBinding0,uint256 lockedOutputBinding1,uint256 lockedOutputBinding2)'
const EXPECTED_INTENT_TYPE_HASH =
  '0x79feac899af7279741df556d4c1f43267870af5c8c0633dec1f7e3681df5a6b3'

const sampleIntent = {
  authorizingAddress: 0x7e5f4552091a69125d5dfcb7b8c2659029395bdfn,
  policyVersion: 1n,
  authDomainTag: MULTISIG_AUTH_DOMAIN,
  operationKind: 0n,
  tokenAddress: 0x1000000000000000000000000000000000000001n,
  recipientAddress: 0x2000000000000000000000000000000000000002n,
  amount: 1000n,
  feeRecipientAddress: 0x3000000000000000000000000000000000000003n,
  feeAmount: 7n,
  originMode: 1n,
  nonce: 42n,
  validUntilSeconds: 3600n,
  executionConstraints: {
    executionConstraintsFlags: LOCK_OUTPUT_BINDING_0 | LOCK_OUTPUT_BINDING_2,
    lockedOutputBinding0: 0x1234n,
    lockedOutputBinding1: 0n,
    lockedOutputBinding2: 0x5678n,
  },
  executionChainId: 31337n,
}

const typedData = buildShieldedPoolIntentTypedData(sampleIntent)
const encoder = ethers.utils._TypedDataEncoder.from(typedData.types)
const typedDataMessage = stringifyBigInts(typedData.message)

assert.equal(encoder.encodeType(typedData.primaryType), EXPECTED_INTENT_TYPE)
assert.equal(ethers.utils.id(EXPECTED_INTENT_TYPE), EXPECTED_INTENT_TYPE_HASH)
assert.equal(
  bytesToHex(computeShieldedPoolIntentStructHash(sampleIntent)),
  encoder.hashStruct(typedData.primaryType, typedDataMessage),
)
assert.equal(
  bytesToHex(computeShieldedPoolIntentSigningHash(sampleIntent)),
  ethers.utils._TypedDataEncoder.hash(
    typedData.domain,
    typedData.types,
    typedDataMessage,
  ),
)

process.stdout.write('ok\n')

function stringifyBigInts(value: Record<string, unknown>) {
  return Object.fromEntries(
    Object.entries(value).map(([key, entry]) => [
      key,
      typeof entry === 'bigint' ? entry.toString() : entry,
    ]),
  )
}
