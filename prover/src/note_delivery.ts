import { createDecipheriv } from 'crypto'
import { keccak_256 } from '@noble/hashes/sha3'
import { extract, expand } from '@noble/hashes/hkdf'
import { sha256 } from '@noble/hashes/sha256'
import { XWing } from '@noble/post-quantum/hybrid.js'
import { computeNoteCommitment, computeNoteNullifier } from '../../integration/src/eip8182.ts'

interface NoteFields {
  amount: bigint
  ownerAddress: bigint
  noteSecret: bigint
  ownerNullifierKeyHash: bigint
  tokenAddress: bigint
  originTag: bigint
}

interface StoredNote {
  commitment: string
  leafIndex: number
  amount: string
  ownerAddress: string
  noteSecret: string
  ownerNullifierKeyHash: string
  tokenAddress: string
  originTag: string
}

export interface ChainNote {
  leafIndex: number
  encryptedData: string
  commitment: string
}

export interface ShieldedPoolTransactHistoryEntry {
  leafIndex0: number | string
  nullifier0: string
  nullifier1: string
  transactionReplayId: string
  noteCommitment0: string
  noteCommitment1: string
  noteCommitment2: string
  outputNoteData0: string
  outputNoteData1: string
  outputNoteData2: string
}

const DELIVERY_KEY_LABEL = 'EIP-8182-delivery-scheme-1 key'
const DELIVERY_NONCE_LABEL = 'EIP-8182-delivery-scheme-1 nonce'
const NOTE_DATA_LENGTH = 1328

function toHex(value: bigint): string {
  return '0x' + value.toString(16)
}

function fromHexBytes(value: string): Uint8Array {
  const raw = value.startsWith('0x') ? value.slice(2) : value
  return new Uint8Array(raw.match(/.{2}/g)?.map((byte) => parseInt(byte, 16)) ?? [])
}

function noteCommitment(note: NoteFields, pHash: (values: bigint[]) => bigint): bigint {
  return computeNoteCommitment(pHash, note)
}

function decodeNotePlaintext(buf: Uint8Array): NoteFields {
  const readWord = (offset: number) => {
    let value = 0n
    for (let i = 0; i < 32; i++) {
      value = (value << 8n) | BigInt(buf[offset + i])
    }
    return value
  }

  return {
    amount: readWord(0),
    ownerAddress: readWord(32),
    noteSecret: readWord(64),
    ownerNullifierKeyHash: readWord(96),
    tokenAddress: readWord(128),
    originTag: readWord(160),
  }
}

function deriveKeyAndNonce(sharedSecret: Uint8Array): { key: Uint8Array; nonce: Uint8Array } {
  const prk = extract(sha256, sharedSecret, new Uint8Array(0))
  const key = expand(sha256, prk, DELIVERY_KEY_LABEL, 32)
  const nonce = expand(sha256, prk, DELIVERY_NONCE_LABEL, 12)
  return { key, nonce }
}

function deliverySeed(deliverySecret: bigint): Uint8Array {
  return keccak_256(new TextEncoder().encode(`xwing-delivery-${deliverySecret.toString()}`))
}

export function deriveDeliveryKeypair(deliverySecret: bigint) {
  return XWing.keygen(deliverySeed(deliverySecret))
}

function decryptNoteData(xwingSecretKey: Uint8Array, encryptedData: Uint8Array): NoteFields | null {
  if (encryptedData.length !== NOTE_DATA_LENGTH) return null

  try {
    const encapsulatedKey = encryptedData.slice(0, 1120)
    const ciphertext = encryptedData.slice(1120, 1312)
    const tag = encryptedData.slice(1312, NOTE_DATA_LENGTH)
    const sharedSecret = XWing.decapsulate(encapsulatedKey, xwingSecretKey)
    const { key, nonce } = deriveKeyAndNonce(sharedSecret)
    const decipher = createDecipheriv('aes-256-gcm', key, nonce)
    decipher.setAuthTag(tag)
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()])
    return decodeNotePlaintext(new Uint8Array(plaintext))
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

  async getUnspentNotes(
    ownerAddress: bigint,
    ownerNullifierKey: bigint,
    deliverySecret: bigint,
  ): Promise<StoredNote[]> {
    const ownerHex = toHex(ownerAddress)
    const result: StoredNote[] = []
    const seen = new Set<string>()
    const { secretKey } = deriveDeliveryKeypair(deliverySecret)

    for (const note of this.notes) {
      if (note.ownerAddress !== ownerHex) continue
      if (BigInt(note.amount) === 0n) continue

      const nullifier = computeNoteNullifier(this.pHash, ownerNullifierKey, BigInt(note.noteSecret))
      if (this.spentNullifiers.has(toHex(nullifier))) continue

      result.push(note)
      seen.add(note.commitment)
    }

    for (const chainNote of this.chainNotes) {
      if (seen.has(chainNote.commitment)) continue

      const decrypted = decryptNoteData(secretKey, fromHexBytes(chainNote.encryptedData))
      if (!decrypted) continue
      if (decrypted.ownerAddress !== ownerAddress) continue
      if (decrypted.amount === 0n) continue
      if (BigInt(chainNote.commitment) != noteCommitment(decrypted, this.pHash)) continue

      const nullifier = computeNoteNullifier(this.pHash, ownerNullifierKey, decrypted.noteSecret)
      if (this.spentNullifiers.has(toHex(nullifier))) continue

      const recoveredNote: StoredNote = {
        commitment: chainNote.commitment,
        leafIndex: chainNote.leafIndex,
        amount: decrypted.amount.toString(),
        ownerAddress: toHex(decrypted.ownerAddress),
        noteSecret: toHex(decrypted.noteSecret),
        ownerNullifierKeyHash: toHex(decrypted.ownerNullifierKeyHash),
        tokenAddress: toHex(decrypted.tokenAddress),
        originTag: toHex(decrypted.originTag),
      }
      result.push(recoveredNote)
      seen.add(chainNote.commitment)
    }

    return result
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
        })
      }
    }

    noteStore.markSpent(BigInt(transact.nullifier0))
    noteStore.markSpent(BigInt(transact.nullifier1))
  }
}
