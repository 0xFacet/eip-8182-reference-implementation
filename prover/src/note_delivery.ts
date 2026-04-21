import { createDecipheriv } from 'crypto'
import { shake256 } from '@noble/hashes/sha3'
import { extract, expand } from '@noble/hashes/hkdf'
import { sha256 } from '@noble/hashes/sha256'
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js'
import {
  computeFullNoteCommitment,
  computeNoteNullifier,
  computeOwnerNullifierKeyHash,
} from '../../integration/src/eip8182.ts'

// The note body the wallet persists. Contains everything required to reconstruct
// the final (leaf-sealed) commitment and spend the note via a future transact.
interface NoteFields {
  amount: bigint
  noteSecret: bigint
  ownerNullifierKeyHash: bigint
  tokenAddress: bigint
  originTag: bigint
}

interface StoredNote {
  commitment: string       // final leaf-sealed commitment
  leafIndex: number
  amount: string
  noteSecret: string
  ownerNullifierKeyHash: string
  tokenAddress: string
  originTag: string
}

export interface ChainNote {
  leafIndex: number
  encryptedData: string
  commitment: string       // final leaf-sealed commitment from chain
  kind: 'transact' | 'deposit'
  // Deposit-only fields (provided by ShieldedPoolDeposit event).
  amount?: string
  tokenAddress?: string
  originTag?: string
}

export interface ShieldedPoolTransactHistoryEntry {
  leafIndex0: number | string
  nullifier0: string
  nullifier1: string
  intentReplayId: string
  noteCommitment0: string
  noteCommitment1: string
  noteCommitment2: string
  outputNoteData0: string
  outputNoteData1: string
  outputNoteData2: string
}

export interface ShieldedPoolDepositHistoryEntry {
  leafIndex: number | string
  noteCommitment: string
  amount: string
  tokenAddress: string
  originTag: string
  outputNoteData: string
}

const DELIVERY_KEY_LABEL = 'EIP-8182-delivery-scheme-1 key'
const DELIVERY_NONCE_LABEL = 'EIP-8182-delivery-scheme-1 nonce'

// Scheme 1 enc prefix: raw ML-KEM-768 ciphertext.
const SCHEME_1_ENC_LENGTH = 1088
// Scheme 1A (transact) wire format: enc(1088) || ciphertext(160) || tag(16) = 1264 bytes.
const SCHEME_1A_LENGTH = 1264
const SCHEME_1A_PLAINTEXT = 160
// Scheme 1B (deposit) wire format: enc(1088) || ciphertext(64) || tag(16) = 1168 bytes.
const SCHEME_1B_LENGTH = 1168
const SCHEME_1B_PLAINTEXT = 64

function toHex(value: bigint): string {
  return '0x' + value.toString(16)
}

function fromHexBytes(value: string): Uint8Array {
  const raw = value.startsWith('0x') ? value.slice(2) : value
  return new Uint8Array(raw.match(/.{2}/g)?.map((byte) => parseInt(byte, 16)) ?? [])
}

function readWord(buf: Uint8Array, offset: number): bigint {
  let value = 0n
  for (let i = 0; i < 32; i++) {
    value = (value << 8n) | BigInt(buf[offset + i])
  }
  return value
}

// Scheme 1A plaintext per EIP Section 15.2.
function decodeScheme1A(buf: Uint8Array): Pick<NoteFields, 'amount' | 'ownerNullifierKeyHash' | 'noteSecret' | 'tokenAddress' | 'originTag'> {
  return {
    amount: readWord(buf, 0),
    ownerNullifierKeyHash: readWord(buf, 32),
    noteSecret: readWord(buf, 64),
    tokenAddress: readWord(buf, 96),
    originTag: readWord(buf, 128),
  }
}

// Scheme 1B plaintext per EIP Section 15.3.
function decodeScheme1B(buf: Uint8Array): { ownerNullifierKeyHash: bigint; noteSecret: bigint } {
  return {
    ownerNullifierKeyHash: readWord(buf, 0),
    noteSecret: readWord(buf, 32),
  }
}

function deriveKeyAndNonce(sharedSecret: Uint8Array): { key: Uint8Array; nonce: Uint8Array } {
  const prk = extract(sha256, sharedSecret, new Uint8Array(0))
  const key = expand(sha256, prk, DELIVERY_KEY_LABEL, 32)
  const nonce = expand(sha256, prk, DELIVERY_NONCE_LABEL, 12)
  return { key, nonce }
}

function deliverySeed(deliverySecret: bigint): Uint8Array {
  return shake256(
    new TextEncoder().encode(`eip8182-delivery-${deliverySecret.toString()}`),
    { dkLen: 64 },
  )
}

export function deriveDeliveryKeypair(deliverySecret: bigint) {
  return ml_kem768.keygen(deliverySeed(deliverySecret))
}

function decryptCiphertext(
  secretKey: Uint8Array,
  encryptedData: Uint8Array,
  plaintextLength: number,
): Uint8Array | null {
  try {
    const encapsulatedKey = encryptedData.slice(0, SCHEME_1_ENC_LENGTH)
    const ciphertext = encryptedData.slice(SCHEME_1_ENC_LENGTH, SCHEME_1_ENC_LENGTH + plaintextLength)
    const tag = encryptedData.slice(
      SCHEME_1_ENC_LENGTH + plaintextLength,
      SCHEME_1_ENC_LENGTH + plaintextLength + 16,
    )
    const sharedSecret = ml_kem768.decapsulate(encapsulatedKey, secretKey)
    const { key, nonce } = deriveKeyAndNonce(sharedSecret)
    const decipher = createDecipheriv('aes-256-gcm', key, nonce)
    decipher.setAuthTag(tag)
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()])
    return new Uint8Array(plaintext)
  } catch {
    return null
  }
}

export class NoteStore {
  notes: StoredNote[] = []
  chainNotes: ChainNote[] = []
  spentNullifiers = new Set<string>()

  constructor(private readonly pHash: (values: bigint[]) => bigint) {}

  addNote(note: StoredNote) {
    this.notes.push(note)
  }

  addChainNote(note: ChainNote) {
    this.chainNotes.push(note)
  }

  markSpent(nullifier: bigint) {
    this.spentNullifiers.add(toHex(nullifier))
  }

  clear() {
    this.notes = []
    this.chainNotes = []
    this.spentNullifiers = new Set()
  }

  /// Walk chain notes, decrypt/verify against this wallet's ownerNullifierKey,
  /// and return a list of unspent notes. Dispatches by event kind: transact
  /// outputs use Scheme 1A; deposit outputs use Scheme 1B (EIP Section 15).
  async getUnspentNotes(
    ownerNullifierKey: bigint,
    deliverySecret: bigint,
  ): Promise<StoredNote[]> {
    const expectedOwnerNullifierKeyHash = computeOwnerNullifierKeyHash(this.pHash, ownerNullifierKey)
    const { secretKey } = deriveDeliveryKeypair(deliverySecret)
    const result: StoredNote[] = []
    const seen = new Set<string>()

    for (const note of this.notes) {
      if (BigInt(note.ownerNullifierKeyHash) !== expectedOwnerNullifierKeyHash) continue
      if (BigInt(note.amount) === 0n) continue

      const nullifier = computeNoteNullifier(this.pHash, BigInt(note.commitment), ownerNullifierKey)
      if (this.spentNullifiers.has(toHex(nullifier))) continue

      result.push(note)
      seen.add(note.commitment)
    }

    for (const chainNote of this.chainNotes) {
      if (seen.has(chainNote.commitment)) continue

      const recovered = this.tryRecoverChainNote(
        chainNote,
        secretKey,
        expectedOwnerNullifierKeyHash,
      )
      if (!recovered) continue

      const nullifier = computeNoteNullifier(
        this.pHash,
        BigInt(recovered.commitment),
        ownerNullifierKey,
      )
      if (this.spentNullifiers.has(toHex(nullifier))) continue

      result.push(recovered)
      seen.add(recovered.commitment)
    }

    return result
  }

  private tryRecoverChainNote(
    chainNote: ChainNote,
    secretKey: Uint8Array,
    expectedOwnerNullifierKeyHash: bigint,
  ): StoredNote | null {
    const encryptedData = fromHexBytes(chainNote.encryptedData)

    if (chainNote.kind === 'transact') {
      if (encryptedData.length !== SCHEME_1A_LENGTH) return null
      const plaintext = decryptCiphertext(secretKey, encryptedData, SCHEME_1A_PLAINTEXT)
      if (!plaintext) return null
      const fields = decodeScheme1A(plaintext)
      if (fields.ownerNullifierKeyHash !== expectedOwnerNullifierKeyHash) return null
      if (fields.amount === 0n) return null

      const reconstructed = computeFullNoteCommitment(this.pHash, {
        ownerNullifierKeyHash: fields.ownerNullifierKeyHash,
        noteSecret: fields.noteSecret,
        amount: fields.amount,
        tokenAddress: fields.tokenAddress,
        originTag: fields.originTag,
        leafIndex: BigInt(chainNote.leafIndex),
      })
      if (reconstructed !== BigInt(chainNote.commitment)) return null

      return {
        commitment: chainNote.commitment,
        leafIndex: chainNote.leafIndex,
        amount: fields.amount.toString(),
        noteSecret: toHex(fields.noteSecret),
        ownerNullifierKeyHash: toHex(fields.ownerNullifierKeyHash),
        tokenAddress: toHex(fields.tokenAddress),
        originTag: toHex(fields.originTag),
      }
    }

    // kind === 'deposit' → Scheme 1B
    if (encryptedData.length !== SCHEME_1B_LENGTH) return null
    if (chainNote.amount === undefined || chainNote.tokenAddress === undefined || chainNote.originTag === undefined) {
      return null
    }
    const plaintext = decryptCiphertext(secretKey, encryptedData, SCHEME_1B_PLAINTEXT)
    if (!plaintext) return null
    const fields = decodeScheme1B(plaintext)
    if (fields.ownerNullifierKeyHash !== expectedOwnerNullifierKeyHash) return null
    const amount = BigInt(chainNote.amount)
    if (amount === 0n) return null

    const reconstructed = computeFullNoteCommitment(this.pHash, {
      ownerNullifierKeyHash: fields.ownerNullifierKeyHash,
      noteSecret: fields.noteSecret,
      amount,
      tokenAddress: BigInt(chainNote.tokenAddress),
      originTag: BigInt(chainNote.originTag),
      leafIndex: BigInt(chainNote.leafIndex),
    })
    if (reconstructed !== BigInt(chainNote.commitment)) return null

    return {
      commitment: chainNote.commitment,
      leafIndex: chainNote.leafIndex,
      amount: amount.toString(),
      noteSecret: toHex(fields.noteSecret),
      ownerNullifierKeyHash: toHex(fields.ownerNullifierKeyHash),
      tokenAddress: chainNote.tokenAddress,
      originTag: chainNote.originTag,
    }
  }
}

export function replayShieldedPoolTransactsIntoNoteStore(
  noteStore: NoteStore,
  transacts: ShieldedPoolTransactHistoryEntry[],
) {
  const sorted = [...transacts].sort(
    (a, b) => Number(a.leafIndex0) - Number(b.leafIndex0),
  )

  for (const transact of sorted) {
    const leafIndex0 = Number(transact.leafIndex0)
    const commitments = [
      transact.noteCommitment0,
      transact.noteCommitment1,
      transact.noteCommitment2,
    ]
    const noteDataFields = [
      transact.outputNoteData0,
      transact.outputNoteData1,
      transact.outputNoteData2,
    ]

    for (let slot = 0; slot < 3; slot++) {
      const data = noteDataFields[slot]
      if (data && data.length > 2) {
        noteStore.addChainNote({
          leafIndex: leafIndex0 + slot,
          encryptedData: data,
          commitment: commitments[slot],
          kind: 'transact',
        })
      }
    }

    noteStore.markSpent(BigInt(transact.nullifier0))
    noteStore.markSpent(BigInt(transact.nullifier1))
  }
}

export function replayShieldedPoolDepositsIntoNoteStore(
  noteStore: NoteStore,
  deposits: ShieldedPoolDepositHistoryEntry[],
) {
  const sorted = [...deposits].sort(
    (a, b) => Number(a.leafIndex) - Number(b.leafIndex),
  )

  for (const deposit of sorted) {
    if (deposit.outputNoteData && deposit.outputNoteData.length > 2) {
      noteStore.addChainNote({
        leafIndex: Number(deposit.leafIndex),
        encryptedData: deposit.outputNoteData,
        commitment: deposit.noteCommitment,
        kind: 'deposit',
        amount: deposit.amount,
        tokenAddress: deposit.tokenAddress,
        originTag: deposit.originTag,
      })
    }
  }
}
