import {
  initPoseidon2,
  poseidon2Hash,
} from "../../integration/src/poseidon2.ts";
import {
  NoteStore,
  replayShieldedPoolDepositsIntoNoteStore,
  replayShieldedPoolTransactsIntoNoteStore,
  type ShieldedPoolDepositHistoryEntry,
  type ShieldedPoolTransactHistoryEntry,
} from "./note_delivery.ts";

function toHex(value: bigint): string {
  return "0x" + value.toString(16);
}

async function main() {
  const params = JSON.parse(process.argv[2]) as {
    ownerNullifierKey: string;
    deliverySecret: string;
    // Single-note shortcut (caller provides one chain note directly).
    kind?: "transact" | "deposit";
    leafIndex?: string;
    commitment?: string;
    encryptedData?: string;
    // Deposit-only (for single-note shortcut).
    amount?: string;
    tokenAddress?: string;
    originTag?: string;
    // History-replay mode.
    transacts?: ShieldedPoolTransactHistoryEntry[];
    deposits?: ShieldedPoolDepositHistoryEntry[];
  };

  await initPoseidon2();
  const pHash = (values: bigint[]): bigint => poseidon2Hash(values);

  const noteStore = new NoteStore(pHash);

  if (params.transacts && params.transacts.length > 0) {
    replayShieldedPoolTransactsIntoNoteStore(noteStore, params.transacts);
  }
  if (params.deposits && params.deposits.length > 0) {
    replayShieldedPoolDepositsIntoNoteStore(noteStore, params.deposits);
  }

  if (
    (!params.transacts || params.transacts.length === 0) &&
    (!params.deposits || params.deposits.length === 0) &&
    params.commitment !== undefined &&
    params.encryptedData !== undefined &&
    params.leafIndex !== undefined
  ) {
    const kind = params.kind ?? "transact";
    noteStore.addChainNote({
      leafIndex: Number(params.leafIndex),
      commitment: toHex(BigInt(params.commitment)),
      encryptedData: params.encryptedData,
      kind,
      amount: params.amount,
      tokenAddress: params.tokenAddress,
      originTag: params.originTag,
    });
  }

  const notes = await noteStore.getUnspentNotes(
    BigInt(params.ownerNullifierKey),
    BigInt(params.deliverySecret),
  );

  if (notes.length === 0) {
    process.stdout.write(JSON.stringify({ found: false }));
    return;
  }

  process.stdout.write(JSON.stringify({ found: true, note: notes[0] }));
}

main().catch((error) => {
  process.stderr.write(error.message);
  process.exit(1);
});
