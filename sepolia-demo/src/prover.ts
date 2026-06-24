import type { HexAddress } from "./payload.js";
import type { PreparedDemoPrivateTransfer } from "./transfer.js";

export interface DemoPoolPublicInputs {
  noteCommitmentRoot: bigint;
  nullifier0: bigint;
  nullifier1: bigint;
  noteBodyCommitment0: bigint;
  noteBodyCommitment1: bigint;
  noteBodyCommitment2: bigint;
  publicAmountOut: bigint;
  publicRecipientAddress: bigint;
  publicTokenAddress: bigint;
  intentReplayId: bigint;
  validUntilSeconds: bigint;
  executionChainId: bigint;
  authPolicyRoot: bigint;
  outputNoteDataHash0: bigint;
  outputNoteDataHash1: bigint;
  outputNoteDataHash2: bigint;
  authVerifier: bigint;
  blindedAuthCommitment: bigint;
  transactionIntentDigest: bigint;
}

export interface DemoProofBundle {
  poolProof: Uint8Array;
  authProof: Uint8Array;
  publicInputs: DemoPoolPublicInputs;
  outputNoteData0: Uint8Array;
  outputNoteData1: Uint8Array;
  outputNoteData2: Uint8Array;
}

export interface ProverAdapter {
  readonly label: string;
  proveTransfer(transfer: PreparedDemoPrivateTransfer): Promise<DemoProofBundle>;
}

export class UnavailableProverAdapter implements ProverAdapter {
  readonly label = "not configured";

  async proveTransfer(_transfer: PreparedDemoPrivateTransfer): Promise<DemoProofBundle> {
    throw new Error(dynamicProverBlockerMessage());
  }
}

export function dynamicProverBlockerMessage(): string {
  return [
    "Dynamic transact proving is not wired.",
    "The browser path still needs a Sepolia state witness builder, pool-address-specific Noir auth artifacts, and a pool/auth prover adapter.",
    "This demo prepares encrypted outputs and public-input bindings, but it must not submit placeholder proofs."
  ].join(" ");
}

export function assertTransactSubmissionReady(
  adapter: ProverAdapter,
  poolAddress: HexAddress
): void {
  if (adapter instanceof UnavailableProverAdapter) {
    throw new Error(`${dynamicProverBlockerMessage()} Pool: ${poolAddress}`);
  }
}
