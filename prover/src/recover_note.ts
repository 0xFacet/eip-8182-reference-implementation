import { buildPoseidon } from "circomlibjs";
import {
  NoteStore,
  replayShieldedPoolTransactsIntoNoteStore,
  type ShieldedPoolTransactHistoryEntry,
} from "./note_delivery.ts";

function toHex(value: bigint): string {
  return "0x" + value.toString(16);
}

async function main() {
  const params = JSON.parse(process.argv[2]) as {
    ownerAddress: string;
    ownerNullifierKey: string;
    deliverySecret: string;
    leafIndex: string;
    commitment: string;
    encryptedData: string;
    transacts?: ShieldedPoolTransactHistoryEntry[];
  };

  const poseidon = await buildPoseidon();
  const h2 = (a: bigint, b: bigint): bigint =>
    BigInt(poseidon.F.toString(poseidon([a, b])));
  const rawHash = (values: bigint[]): bigint => {
    if (values.length === 1) return values[0];
    if (values.length === 2) return h2(values[0], values[1]);
    let leftSize = 1;
    while (leftSize * 2 < values.length) leftSize *= 2;
    return h2(rawHash(values.slice(0, leftSize)), rawHash(values.slice(leftSize)));
  };
  const pHash = (values: bigint[]): bigint => {
    if (values.length === 1) return values[0];
    return h2(BigInt(values.length), rawHash(values));
  };

  const noteStore = new NoteStore(pHash);
  if (params.transacts && params.transacts.length > 0) {
    replayShieldedPoolTransactsIntoNoteStore(noteStore, params.transacts);
  } else {
    noteStore.addChainNote({
      leafIndex: Number(params.leafIndex),
      commitment: toHex(BigInt(params.commitment)),
      encryptedData: params.encryptedData,
    });
  }

  const notes = await noteStore.getUnspentNotes(
    BigInt(params.ownerAddress),
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
