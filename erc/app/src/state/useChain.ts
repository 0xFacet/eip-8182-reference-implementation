import { useMemo } from "react";
import { createPublicClient, custom } from "viem";
import { useAccount, usePublicClient, useWalletClient } from "wagmi";
import { getDeployment } from "../config/deployment.ts";

/** One place to grab the viem clients, connected account, and the active deployment. */
export function useChain() {
  const { address, chainId, isConnected } = useAccount();
  const pub = usePublicClient();
  const { data: wallet } = useWalletClient();
  const scanPub = useMemo(
    () => (wallet ? createPublicClient({ chain: wallet.chain, transport: custom({ request: wallet.request }) }) : undefined),
    [wallet],
  );
  const deployment = getDeployment(chainId);
  return { address, chainId, isConnected, pub, scanPub, wallet, deployment };
}
