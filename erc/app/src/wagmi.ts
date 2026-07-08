import { getDefaultConfig } from "@rainbow-me/rainbowkit";
import { http } from "wagmi";
import { type Chain, sepolia } from "wagmi/chains";
import { ANVIL_CHAIN_ID } from "./config/deployment.ts";

const SEPOLIA_RPC_URL = import.meta.env.VITE_SEPOLIA_RPC_URL || undefined;
const sepoliaRpcUrls = SEPOLIA_RPC_URL ? [SEPOLIA_RPC_URL] : sepolia.rpcUrls.default.http;

export const anvil: Chain = {
  id: ANVIL_CHAIN_ID,
  name: "Anvil (dev)",
  nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
  rpcUrls: { default: { http: ["http://127.0.0.1:8545"] } },
};

const projectId = import.meta.env.VITE_WALLETCONNECT_PROJECT_ID || "YOUR_PROJECT_ID";
const appSepolia: Chain = {
  ...sepolia,
  rpcUrls: {
    ...sepolia.rpcUrls,
    default: { http: sepoliaRpcUrls },
    public: { http: sepoliaRpcUrls },
  },
};

export const wagmiConfig = getDefaultConfig({
  appName: "Shielded Terminal",
  appDescription: "App-layer private transfers reference wallet.",
  projectId,
  chains: [anvil, appSepolia],
  transports: {
    [anvil.id]: http("http://127.0.0.1:8545"),
    [appSepolia.id]: SEPOLIA_RPC_URL ? http(SEPOLIA_RPC_URL) : http(),
  },
  ssr: false,
});
