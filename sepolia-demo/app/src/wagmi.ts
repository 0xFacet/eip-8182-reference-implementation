import { getDefaultConfig } from '@rainbow-me/rainbowkit';
import { http } from 'wagmi';
import { sepolia } from 'wagmi/chains';

const chains = [sepolia] as const;
const transports = {
  [sepolia.id]: http(),
} as const;

const walletConnectProjectId = import.meta.env.VITE_WALLETCONNECT_PROJECT_ID || 'YOUR_PROJECT_ID';

// RainbowKit replaces YOUR_PROJECT_ID with its built-in demo id. Set
// VITE_WALLETCONNECT_PROJECT_ID in Vercel for a production relay quota.
export const rainbowWagmiConfig = getDefaultConfig({
  appName: 'EIP-8182 Sepolia Demo',
  appDescription: 'Browser-proved private transfers on Sepolia.',
  ...(typeof window === 'undefined' ? {} : { appUrl: window.location.origin }),
  projectId: walletConnectProjectId,
  chains,
  transports,
  ssr: false,
});
