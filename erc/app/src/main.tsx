import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { WagmiProvider } from "wagmi";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { RainbowKitProvider, darkTheme } from "@rainbow-me/rainbowkit";
import "@rainbow-me/rainbowkit/styles.css";
import { Buffer } from "buffer";
import { wagmiConfig } from "./wagmi.ts";
import { IdentityProvider } from "./state/identity.tsx";
import { App } from "./App.tsx";
import "./styles.css";

// snarkjs / ffjavascript reach for a global Buffer in a few code paths.
if (!(globalThis as { Buffer?: unknown }).Buffer) (globalThis as { Buffer?: unknown }).Buffer = Buffer;

const queryClient = new QueryClient();

const rkTheme = darkTheme({
  accentColor: "#7CFFCB",
  accentColorForeground: "#05201a",
  borderRadius: "small",
  overlayBlur: "small",
});

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <WagmiProvider config={wagmiConfig}>
      <QueryClientProvider client={queryClient}>
        <RainbowKitProvider theme={rkTheme} modalSize="compact">
          <IdentityProvider>
            <App />
          </IdentityProvider>
        </RainbowKitProvider>
      </QueryClientProvider>
    </WagmiProvider>
  </StrictMode>,
);
