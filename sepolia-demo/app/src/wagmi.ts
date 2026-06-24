import { createConfig, http } from 'wagmi';
import { sepolia } from 'wagmi/chains';
import { injected } from 'wagmi/connectors';

// Match the AztecBirds pattern: only use injected EIP-1193 wallets, so the
// demo does not initialize extra wallet SDKs alongside the browser prover.
export const wagmiConfig = createConfig({
  chains: [sepolia],
  connectors: [injected({ shimDisconnect: true })],
  transports: {
    [sepolia.id]: http(),
  },
  ssr: false,
});
