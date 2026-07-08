import { useQuery } from "@tanstack/react-query";
import type { Address } from "viem";
import { useChain } from "./useChain.ts";
import { useIdentity } from "./identity.tsx";
import { poolsOf } from "../config/deployment.ts";
import { recoverNotes, type RecoveredNote } from "../lib/indexer.ts";
import { isNullifierSpent } from "../lib/clients.ts";
import { addressToField } from "../../../sdk/src/field.ts";

export interface NotesView {
  notes: RecoveredNote[];
  byPool: Record<Address, RecoveredNote[]>;
}

/** Trial-decrypt every output across both pools for the connected identity, and mark spends. */
export function useNotes() {
  const { scanPub, chainId, deployment, address } = useChain();
  const { derived } = useIdentity();
  const pools = deployment ? poolsOf(deployment) : [];
  const poolScanKey = pools.map((p) => `${p.address}:${p.startBlock.toString()}`).join("|");

  return useQuery<NotesView>({
    queryKey: ["notes", chainId, address, deployment?.poolPolicyFree, deployment?.poolAllowlistGated, poolScanKey, derived?.onkHash?.toString()],
    enabled: Boolean(scanPub && deployment && derived),
    queryFn: async () => {
      const fieldToAddress = new Map<string, Address>();
      const indexerPools = pools.map((p) => {
        fieldToAddress.set(addressToField(p.address, "pool").toString(), p.address);
        return { address: p.address, label: p.label, chainId: BigInt(chainId!), startBlock: p.startBlock };
      });
      const notes = await recoverNotes({
        pub: scanPub!,
        pools: indexerPools,
        secretKey: derived!.kemSecretKey,
        ownerNullifierKey: derived!.onk,
      });
      const byPool: Record<Address, RecoveredNote[]> = {};
      for (const n of notes) {
        const addr = fieldToAddress.get(n.poolAddress.toString());
        if (!addr) continue;
        n.spent = await isNullifierSpent(scanPub!, addr, n.nullifier);
        (byPool[addr] ??= []).push(n);
      }
      return { notes, byPool };
    },
  });
}
