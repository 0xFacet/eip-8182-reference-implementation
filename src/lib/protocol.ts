import { keccak_256 } from '@noble/hashes/sha3'
import {
  AUTH_VK_DOMAIN,
  FIELD_MODULUS,
  NOTE_BODY_COMMITMENT_DOMAIN,
  NOTE_COMMITMENT_DOMAIN,
  NULLIFIER_DOMAIN,
  ORIGIN_TAG_DOMAIN,
  OUTPUT_BINDING_DOMAIN,
  OWNER_COMMITMENT_DOMAIN,
  TRANSACTION_INTENT_DIGEST_DOMAIN,
  INTENT_REPLAY_ID_DOMAIN,
} from './domainConstants.ts'

export {
  AUTH_POLICY_DOMAIN,
  AUTH_POLICY_KEY_DOMAIN,
  AUTH_VK_DOMAIN,
  FIELD_MODULUS,
  NOTE_BODY_COMMITMENT_DOMAIN,
  NOTE_COMMITMENT_DOMAIN,
  NULLIFIER_DOMAIN,
  TRANSACT_NOTE_SECRET_DOMAIN,
  NOTE_SECRET_SEED_DOMAIN,
  ORIGIN_TAG_DOMAIN,
  OWNER_COMMITMENT_DOMAIN,
  OWNER_NULLIFIER_KEY_HASH_DOMAIN,
  OUTPUT_BINDING_DOMAIN,
  PHANTOM_NULLIFIER_DOMAIN,
  TRANSACTION_INTENT_DIGEST_DOMAIN,
  INTENT_REPLAY_ID_DOMAIN,
  USER_REGISTRY_LEAF_DOMAIN,
} from './domainConstants.ts'

export const PROTOCOL_VERIFYING_CONTRACT =
  '0x0000000000000000000000000000000000081820'
export const PROTOCOL_VERIFYING_CONTRACT_FIELD = 0x81820n
export const PROTOCOL_COMMITMENT_TREE_DEPTH = 32
export const PROTOCOL_REGISTRY_TREE_DEPTH = 160
export const DELIVERY_SCHEME_ML_KEM_768 = 1n
export const ML_KEM_768_PUBLIC_KEY_LENGTH = 1184

export const EIP712_DOMAIN_NAME = 'EIP-8182 Shielded Pool'
export const EIP712_DOMAIN_VERSION = '1'
export const SHIELDED_POOL_INTENT_PRIMARY_TYPE = 'ShieldedPoolIntent'
export const SINGLE_SIG_AUTHORIZATION_PRIMARY_TYPE =
  'ShieldedPoolAuthorization'

export const TRANSFER_OPERATION_KIND = 0n
export const WITHDRAWAL_OPERATION_KIND = 1n
export const ORIGIN_MODE_DEFAULT = 0n
export const ORIGIN_MODE_REQUIRE_TAGGED = 1n
export const LOCK_OUTPUT_BINDING_0 = 1n
export const LOCK_OUTPUT_BINDING_1 = 2n
export const LOCK_OUTPUT_BINDING_2 = 4n

export const MULTISIG_AUTH_DOMAIN = 0x6d756c74697369675f61757468n
export const MULTISIG_2OF3_SIGNERS = 3n
export const MULTISIG_2OF3_THRESHOLD = 2n

const DOMAIN_TYPE_HASH_HEX =
  '8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f'
const NAME_HASH_HEX =
  '26f1e6e22ef219a0457dca33a2aad2ad0c5a3154d405474da5a192867af179b1'
const VERSION_HASH_HEX =
  'c89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6'
const EIP712_TYPE_HASH_HEX =
  '79feac899af7279741df556d4c1f43267870af5c8c0633dec1f7e3681df5a6b3'
const SINGLE_SIG_AUTHORIZATION_TYPE_HASH_HEX =
  '882e42c57a90f318a4d4a29863928e9fad7a836bafafe578d831cd689988c3c8'

export interface ExecutionConstraints {
  executionConstraintsFlags: bigint
  lockedOutputBinding0: bigint
  lockedOutputBinding1: bigint
  lockedOutputBinding2: bigint
}

export interface ExecutionConstraintsInput {
  executionConstraintsFlags?: bigint
  lockedOutputBinding0?: bigint
  lockedOutputBinding1?: bigint
  lockedOutputBinding2?: bigint
}

export type AddressLike = bigint | string

export interface ShieldedPoolIntentParams {
  authorizingAddress: AddressLike
  policyVersion: bigint
  authDomainTag: bigint
  operationKind: bigint
  tokenAddress: AddressLike
  recipientAddress: AddressLike
  amount: bigint
  feeRecipientAddress?: AddressLike
  feeAmount?: bigint
  originMode?: bigint
  nonce: bigint
  validUntilSeconds: bigint
  executionConstraints?: ExecutionConstraintsInput
  executionChainId: bigint
  verifyingContract?: AddressLike
}

export interface TransactionIntentDigestParams {
  authorizingAddress: AddressLike
  policyVersion: bigint
  operationKind: bigint
  tokenAddress: AddressLike
  recipientAddress: AddressLike
  amount: bigint
  feeRecipientAddress?: AddressLike
  feeAmount?: bigint
  originMode?: bigint
  nonce: bigint
  validUntilSeconds: bigint
  executionConstraints?: ExecutionConstraintsInput
  executionChainId: bigint
}

export interface SingleSigAuthorizationParams {
  policyVersion: bigint
  operationKind: bigint
  tokenAddress: AddressLike
  recipientAddress: AddressLike
  amount: bigint
  feeRecipientAddress?: AddressLike
  feeAmount?: bigint
  originMode?: bigint
  nonce: bigint
  validUntilSeconds: bigint
  executionChainId: bigint
  verifyingContract?: AddressLike
}

export function hexToBytes(value: string): Uint8Array {
  const raw = value.startsWith('0x') ? value.slice(2) : value
  if (raw.length === 0) return new Uint8Array()
  return new Uint8Array(raw.match(/.{2}/g)!.map((byte) => parseInt(byte, 16)))
}

export function bytesToHex(value: Uint8Array): `0x${string}` {
  return `0x${Array.from(value)
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('')}`
}

export function addressToBigInt(value: AddressLike): bigint {
  return typeof value === 'bigint' ? value : BigInt(value)
}

export function addressToHex(value: AddressLike): `0x${string}` {
  assertAddressLike(value, 'address')
  return `0x${addressToBigInt(value).toString(16).padStart(40, '0')}`
}

export function splitBytes32(bytes: Uint8Array): [bigint, bigint] {
  if (bytes.length !== 32) {
    throw new Error(`expected 32 bytes, got ${bytes.length}`)
  }

  const hi = bytes.slice(0, 16)
  const lo = bytes.slice(16)
  return [BigInt(bytesToHex(hi)), BigInt(bytesToHex(lo))]
}

export function compactSignatureBytes(signature: string): Uint8Array {
  const bytes = hexToBytes(signature)
  if (bytes.length === 64) return bytes
  if (bytes.length === 65) return bytes.slice(0, 64)
  throw new Error(`expected 64-byte or 65-byte signature, got ${bytes.length} bytes`)
}

export function defaultExecutionConstraints(): ExecutionConstraints {
  return {
    executionConstraintsFlags: 0n,
    lockedOutputBinding0: 0n,
    lockedOutputBinding1: 0n,
    lockedOutputBinding2: 0n,
  }
}

export function normalizeExecutionConstraints(
  constraints: ExecutionConstraintsInput = {},
): ExecutionConstraints {
  return {
    executionConstraintsFlags: constraints.executionConstraintsFlags ?? 0n,
    lockedOutputBinding0: constraints.lockedOutputBinding0 ?? 0n,
    lockedOutputBinding1: constraints.lockedOutputBinding1 ?? 0n,
    lockedOutputBinding2: constraints.lockedOutputBinding2 ?? 0n,
  }
}

export function computeShieldedPoolDomainSeparator(
  chainId: bigint,
  verifyingContract: AddressLike = PROTOCOL_VERIFYING_CONTRACT_FIELD,
): Uint8Array {
  assertCanonicalFieldValue(chainId, 'executionChainId')
  const payload = new Uint8Array(160)
  payload.set(hexToBytes(DOMAIN_TYPE_HASH_HEX), 0)
  payload.set(hexToBytes(NAME_HASH_HEX), 32)
  payload.set(hexToBytes(VERSION_HASH_HEX), 64)
  writeUint256(payload, 96, chainId)
  writeUint256(payload, 128, addressToBigInt(verifyingContract))
  return keccak_256(payload)
}

export function computeShieldedPoolIntentStructHash(
  params: ShieldedPoolIntentParams,
): Uint8Array {
  assertShieldedPoolIntentParams(params)
  const constraints = normalizeExecutionConstraints(params.executionConstraints)
  const payload = new Uint8Array(544)
  payload.set(hexToBytes(EIP712_TYPE_HASH_HEX), 0)
  writeUint256(payload, 32, addressToBigInt(params.authorizingAddress))
  writeUint256(payload, 64, params.policyVersion)
  writeUint256(payload, 96, params.authDomainTag)
  writeUint256(payload, 128, params.operationKind)
  writeUint256(payload, 160, addressToBigInt(params.tokenAddress))
  writeUint256(payload, 192, addressToBigInt(params.recipientAddress))
  writeUint256(payload, 224, params.amount)
  writeUint256(payload, 256, addressToBigInt(params.feeRecipientAddress ?? 0n))
  writeUint256(payload, 288, params.feeAmount ?? 0n)
  writeUint256(payload, 320, params.originMode ?? ORIGIN_MODE_DEFAULT)
  writeUint256(payload, 352, params.nonce)
  writeUint256(payload, 384, params.validUntilSeconds)
  writeUint256(payload, 416, constraints.executionConstraintsFlags)
  writeUint256(payload, 448, constraints.lockedOutputBinding0)
  writeUint256(payload, 480, constraints.lockedOutputBinding1)
  writeUint256(payload, 512, constraints.lockedOutputBinding2)
  return keccak_256(payload)
}

export function computeSingleSigAuthorizationStructHash(
  params: SingleSigAuthorizationParams,
): Uint8Array {
  assertSingleSigAuthorizationParams(params)

  const payload = new Uint8Array(352)
  payload.set(hexToBytes(SINGLE_SIG_AUTHORIZATION_TYPE_HASH_HEX), 0)
  writeUint256(payload, 32, params.policyVersion)
  writeUint256(payload, 64, params.operationKind)
  writeUint256(payload, 96, addressToBigInt(params.tokenAddress))
  writeUint256(payload, 128, addressToBigInt(params.recipientAddress))
  writeUint256(payload, 160, params.amount)
  writeUint256(payload, 192, addressToBigInt(params.feeRecipientAddress ?? 0n))
  writeUint256(payload, 224, params.feeAmount ?? 0n)
  writeUint256(payload, 256, params.originMode ?? ORIGIN_MODE_DEFAULT)
  writeUint256(payload, 288, params.nonce)
  writeUint256(payload, 320, params.validUntilSeconds)
  return keccak_256(payload)
}

export function computeShieldedPoolIntentSigningHash(
  params: ShieldedPoolIntentParams,
): Uint8Array {
  const signingPreimage = new Uint8Array(66)
  signingPreimage[0] = 0x19
  signingPreimage[1] = 0x01
  signingPreimage.set(
    computeShieldedPoolDomainSeparator(
      params.executionChainId,
      params.verifyingContract ?? PROTOCOL_VERIFYING_CONTRACT_FIELD,
    ),
    2,
  )
  signingPreimage.set(computeShieldedPoolIntentStructHash(params), 34)
  return keccak_256(signingPreimage)
}

export function computeSingleSigAuthorizationSigningHash(
  params: SingleSigAuthorizationParams,
): Uint8Array {
  assertSingleSigAuthorizationParams(params)

  const signingPreimage = new Uint8Array(66)
  signingPreimage[0] = 0x19
  signingPreimage[1] = 0x01
  signingPreimage.set(
    computeShieldedPoolDomainSeparator(
      params.executionChainId,
      params.verifyingContract ?? PROTOCOL_VERIFYING_CONTRACT_FIELD,
    ),
    2,
  )
  signingPreimage.set(computeSingleSigAuthorizationStructHash(params), 34)
  return keccak_256(signingPreimage)
}

export function computeTransactionIntentDigest(
  params: TransactionIntentDigestParams,
  pHash: (values: bigint[]) => bigint,
): bigint {
  const constraints = normalizeExecutionConstraints(params.executionConstraints)
  return pHash([
    TRANSACTION_INTENT_DIGEST_DOMAIN,
    params.policyVersion,
    addressToBigInt(params.authorizingAddress),
    params.operationKind,
    addressToBigInt(params.tokenAddress),
    addressToBigInt(params.recipientAddress),
    params.amount,
    addressToBigInt(params.feeRecipientAddress ?? 0n),
    params.feeAmount ?? 0n,
    params.originMode ?? ORIGIN_MODE_DEFAULT,
    constraints.executionConstraintsFlags,
    constraints.lockedOutputBinding0,
    constraints.lockedOutputBinding1,
    constraints.lockedOutputBinding2,
    params.nonce,
    params.validUntilSeconds,
    params.executionChainId,
  ])
}

/// Output binding hashes the body commitment (pre-leaf-seal) per EIP Section 7.7.
export function computeOutputBinding(
  noteBodyCommitment: bigint,
  outputNoteDataHash: bigint,
  pHash: (values: bigint[]) => bigint,
): bigint {
  return pHash([OUTPUT_BINDING_DOMAIN, noteBodyCommitment, outputNoteDataHash])
}

/// Owner-side note commitment per EIP Section 7.3.
export function computeOwnerCommitment(
  ownerNullifierKeyHash: bigint,
  noteSecret: bigint,
  pHash: (values: bigint[]) => bigint,
): bigint {
  return pHash([OWNER_COMMITMENT_DOMAIN, ownerNullifierKeyHash, noteSecret])
}

/// Semantic note body commitment per EIP Section 7.4. Input order is normative.
export function computeNoteBodyCommitment(
  params: {
    ownerCommitment: bigint
    amount: bigint
    tokenAddress: bigint
    originTag: bigint
  },
  pHash: (values: bigint[]) => bigint,
): bigint {
  return pHash([
    NOTE_BODY_COMMITMENT_DOMAIN,
    params.ownerCommitment,
    params.amount,
    params.tokenAddress,
    params.originTag,
  ])
}

/// Final leaf-sealed note commitment per EIP Section 7.5.
export function computeFinalNoteCommitment(
  noteBodyCommitment: bigint,
  leafIndex: bigint,
  pHash: (values: bigint[]) => bigint,
): bigint {
  return pHash([NOTE_COMMITMENT_DOMAIN, noteBodyCommitment, leafIndex])
}

/// Deposit origin tag per EIP Section 12.1. Applies only when
/// `originMode == ORIGIN_MODE_REQUIRE_TAGGED`.
export function computeDepositOriginTag(
  params: {
    chainId: bigint
    depositor: AddressLike
    tokenAddress: AddressLike
    amount: bigint
    leafIndex: bigint
  },
  pHash: (values: bigint[]) => bigint,
): bigint {
  return pHash([
    ORIGIN_TAG_DOMAIN,
    params.chainId,
    addressToBigInt(params.depositor),
    addressToBigInt(params.tokenAddress),
    params.amount,
    params.leafIndex,
  ])
}

export function computeIntentReplayId(
  ownerNullifierKey: bigint,
  authorizingAddress: AddressLike,
  executionChainId: bigint,
  nonce: bigint,
  pHash: (values: bigint[]) => bigint,
): bigint {
  return pHash([
    INTENT_REPLAY_ID_DOMAIN,
    ownerNullifierKey,
    addressToBigInt(authorizingAddress),
    executionChainId,
    nonce,
  ])
}

/// Real-note nullifier per EIP Section 7.6. Binds to the final (leaf-sealed) note
/// commitment; prover must witness the input note's leaf index.
export function computeNoteNullifier(
  noteCommitment: bigint,
  ownerNullifierKey: bigint,
  pHash: (values: bigint[]) => bigint,
): bigint {
  return pHash([NULLIFIER_DOMAIN, noteCommitment, ownerNullifierKey])
}

export function computeAuthVkHash(
  vkWords: bigint[],
  pHash: (values: bigint[]) => bigint,
): bigint {
  if (vkWords.length === 0) {
    throw new Error('expected non-empty inner VK')
  }
  return pHash([AUTH_VK_DOMAIN, ...vkWords])
}

export function buildShieldedPoolIntentTypedData(
  params: ShieldedPoolIntentParams,
) {
  assertShieldedPoolIntentParams(params)
  const constraints = normalizeExecutionConstraints(params.executionConstraints)
  return {
    domain: {
      name: EIP712_DOMAIN_NAME,
      version: EIP712_DOMAIN_VERSION,
      chainId: Number(params.executionChainId),
      verifyingContract: addressToHex(
        params.verifyingContract ?? PROTOCOL_VERIFYING_CONTRACT_FIELD,
      ),
    },
    types: {
      [SHIELDED_POOL_INTENT_PRIMARY_TYPE]: [
        { name: 'authorizingAddress', type: 'address' },
        { name: 'policyVersion', type: 'uint256' },
        { name: 'authDomainTag', type: 'uint256' },
        { name: 'operationKind', type: 'uint8' },
        { name: 'tokenAddress', type: 'address' },
        { name: 'recipientAddress', type: 'address' },
        { name: 'amount', type: 'uint256' },
        { name: 'feeRecipientAddress', type: 'address' },
        { name: 'feeAmount', type: 'uint256' },
        { name: 'originMode', type: 'uint8' },
        { name: 'nonce', type: 'uint256' },
        { name: 'validUntilSeconds', type: 'uint32' },
        { name: 'executionConstraintsFlags', type: 'uint32' },
        { name: 'lockedOutputBinding0', type: 'uint256' },
        { name: 'lockedOutputBinding1', type: 'uint256' },
        { name: 'lockedOutputBinding2', type: 'uint256' },
      ],
    },
    primaryType: 'ShieldedPoolIntent' as const,
    message: {
      authorizingAddress: addressToHex(params.authorizingAddress),
      policyVersion: params.policyVersion,
      authDomainTag: params.authDomainTag,
      operationKind: Number(params.operationKind),
      tokenAddress: addressToHex(params.tokenAddress),
      recipientAddress: addressToHex(params.recipientAddress),
      amount: params.amount,
      feeRecipientAddress: addressToHex(params.feeRecipientAddress ?? 0n),
      feeAmount: params.feeAmount ?? 0n,
      originMode: Number(params.originMode ?? ORIGIN_MODE_DEFAULT),
      nonce: params.nonce,
      validUntilSeconds: Number(params.validUntilSeconds),
      executionConstraintsFlags: Number(constraints.executionConstraintsFlags),
      lockedOutputBinding0: constraints.lockedOutputBinding0,
      lockedOutputBinding1: constraints.lockedOutputBinding1,
      lockedOutputBinding2: constraints.lockedOutputBinding2,
    },
  }
}

export function buildSingleSigAuthorizationTypedData(
  params: SingleSigAuthorizationParams,
) {
  assertSingleSigAuthorizationParams(params)

  return {
    domain: {
      name: EIP712_DOMAIN_NAME,
      version: EIP712_DOMAIN_VERSION,
      chainId: Number(params.executionChainId),
      verifyingContract: addressToHex(
        params.verifyingContract ?? PROTOCOL_VERIFYING_CONTRACT_FIELD,
      ),
    },
    types: {
      [SINGLE_SIG_AUTHORIZATION_PRIMARY_TYPE]: [
        { name: 'policyVersion', type: 'uint256' },
        { name: 'operationKind', type: 'uint8' },
        { name: 'tokenAddress', type: 'address' },
        { name: 'recipientAddress', type: 'address' },
        { name: 'amount', type: 'uint256' },
        { name: 'feeRecipientAddress', type: 'address' },
        { name: 'feeAmount', type: 'uint256' },
        { name: 'originMode', type: 'uint8' },
        { name: 'nonce', type: 'uint256' },
        { name: 'validUntilSeconds', type: 'uint32' },
      ],
    },
    primaryType: 'ShieldedPoolAuthorization' as const,
    message: {
      policyVersion: params.policyVersion,
      operationKind: Number(params.operationKind),
      tokenAddress: addressToHex(params.tokenAddress),
      recipientAddress: addressToHex(params.recipientAddress),
      amount: params.amount,
      feeRecipientAddress: addressToHex(params.feeRecipientAddress ?? 0n),
      feeAmount: params.feeAmount ?? 0n,
      originMode: Number(params.originMode ?? ORIGIN_MODE_DEFAULT),
      nonce: params.nonce,
      validUntilSeconds: Number(params.validUntilSeconds),
    },
  }
}

export function secp256k1AuthCommitment(
  pubKeyX: Uint8Array,
  pubKeyY: Uint8Array,
  pHash4: (values: bigint[]) => bigint,
): bigint {
  const [xHi, xLo] = splitBytes32(pubKeyX)
  const [yHi, yLo] = splitBytes32(pubKeyY)
  return pHash4([xHi, xLo, yHi, yLo])
}

export function singleSigAuthDataCommitment(
  pubKeyX: Uint8Array,
  pubKeyY: Uint8Array,
  pHash4: (values: bigint[]) => bigint,
): bigint {
  return secp256k1AuthCommitment(pubKeyX, pubKeyY, pHash4)
}

export function secp256k1PubkeyToAddress(
  pubKeyX: Uint8Array,
  pubKeyY: Uint8Array,
): bigint {
  if (pubKeyX.length !== 32 || pubKeyY.length !== 32) {
    throw new Error('expected 32-byte secp256k1 coordinates')
  }

  const preimage = new Uint8Array(64)
  preimage.set(pubKeyX, 0)
  preimage.set(pubKeyY, 32)

  const hash = keccak_256(preimage)
  let address = 0n
  for (const byte of hash.slice(12)) {
    address = (address << 8n) | BigInt(byte)
  }
  return address
}

export interface CanonicalMultisigSigner<T> {
  originalIndex: number
  pubKeyX: Uint8Array
  pubKeyY: Uint8Array
  signerCommitment: bigint
  value: T
}

export function canonicalizeMultisigSigners<T extends { pubKeyX: Uint8Array; pubKeyY: Uint8Array }>(
  signers: T[],
  pHash4: (values: bigint[]) => bigint,
): CanonicalMultisigSigner<T>[] {
  const canonical = signers.map((value, originalIndex) => ({
    originalIndex,
    pubKeyX: value.pubKeyX,
    pubKeyY: value.pubKeyY,
    signerCommitment: secp256k1AuthCommitment(value.pubKeyX, value.pubKeyY, pHash4),
    value,
  }))

  canonical.sort((left, right) =>
    left.signerCommitment < right.signerCommitment ? -1 : left.signerCommitment > right.signerCommitment ? 1 : 0,
  )

  for (let i = 1; i < canonical.length; i++) {
    if (canonical[i - 1].signerCommitment === canonical[i].signerCommitment) {
      throw new Error('multisig signers must be sorted and unique by auth commitment')
    }
  }

  return canonical
}

export function multisigAuthDataCommitment(
  signerCommitments: bigint[],
  pHash2: (values: bigint[]) => bigint,
  pHash3: (values: bigint[]) => bigint,
  signerCount: bigint = MULTISIG_2OF3_SIGNERS,
  threshold: bigint = MULTISIG_2OF3_THRESHOLD,
): bigint {
  let acc = pHash3([MULTISIG_AUTH_DOMAIN, signerCount, threshold])
  for (const signerCommitment of signerCommitments) {
    acc = pHash2([acc, signerCommitment])
  }
  return acc
}

function writeUint256(buf: Uint8Array, offset: number, value: bigint) {
  const hexValue = value.toString(16).padStart(64, '0')
  for (let i = 0; i < 32; i++) {
    buf[offset + i] = parseInt(hexValue.slice(i * 2, i * 2 + 2), 16)
  }
}

function assertSingleSigAuthorizationParams(
  params: SingleSigAuthorizationParams,
) {
  assertFieldBoundParams(params, 'single-sig companion standard')
}

function assertShieldedPoolIntentParams(
  params: ShieldedPoolIntentParams,
) {
  assertFieldBoundParams(params, 'shielded-pool companion standard')
  assertCanonicalFieldValue(params.authDomainTag, 'authDomainTag')
}

function assertFieldBoundParams(
  params: {
    policyVersion: bigint
    amount: bigint
    feeAmount?: bigint
    originMode?: bigint
    nonce: bigint
    validUntilSeconds: bigint
    tokenAddress: AddressLike
    recipientAddress: AddressLike
    feeRecipientAddress?: AddressLike
    operationKind: bigint
  },
  context: string,
) {
  assertCanonicalFieldValue(params.policyVersion, `${context} policyVersion`)
  assertCanonicalFieldValue(params.amount, `${context} amount`)
  assertCanonicalFieldValue(params.feeAmount ?? 0n, `${context} feeAmount`)
  assertCanonicalFieldValue(params.originMode ?? ORIGIN_MODE_DEFAULT, `${context} originMode`)
  assertCanonicalFieldValue(params.nonce, `${context} nonce`)
  assertCanonicalFieldValue(params.validUntilSeconds, `${context} validUntilSeconds`)
  assertCanonicalFieldValue(params.operationKind, `${context} operationKind`)
  assertAddressLike(params.tokenAddress, `${context} tokenAddress`)
  assertAddressLike(params.recipientAddress, `${context} recipientAddress`)
  assertAddressLike(params.feeRecipientAddress ?? 0n, `${context} feeRecipientAddress`)
}

function assertCanonicalFieldValue(value: bigint, field: string) {
  if (value >= FIELD_MODULUS) {
    throw new Error(`${field} must be < FIELD_MODULUS`)
  }
}

function assertAddressLike(value: AddressLike, field: string) {
  const address = addressToBigInt(value)
  if (address < 0 || address >= (1n << 160n)) {
    throw new Error(`${field} must be a uint160`)
  }
}
