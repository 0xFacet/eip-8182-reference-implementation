import { fileURLToPath } from "node:url";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";
import { nodePolyfills } from "vite-plugin-node-polyfills";

const root = fileURLToPath(new URL(".", import.meta.url));

// COOP/COEP are required for the browser prover: @aztec/bb.js and snarkjs both
// use SharedArrayBuffer-backed threads, which the browser only exposes to a
// cross-origin-isolated context. @aztec/bb.js is excluded from dep optimization
// because its wasm bundle breaks esbuild pre-bundling.
export default defineConfig({
  root,
  plugins: [
    react(),
    nodePolyfills({
      globals: { Buffer: true, global: true, process: true },
      protocolImports: true,
    }),
  ],
  build: { target: "esnext", outDir: "dist", emptyOutDir: true },
  optimizeDeps: {
    include: [
      "@noir-lang/acvm_js",
      "@noir-lang/noir_js",
      "@noir-lang/noirc_abi",
      "snarkjs",
      "vite-plugin-node-polyfills/shims/buffer",
    ],
    exclude: ["@aztec/bb.js"],
  },
  resolve: { alias: { pino: "pino/browser.js" } },
  worker: { format: "es" },
  server: {
    host: "127.0.0.1",
    headers: {
      "Cross-Origin-Embedder-Policy": "require-corp",
      "Cross-Origin-Opener-Policy": "same-origin",
    },
  },
  preview: {
    host: "127.0.0.1",
    headers: {
      "Cross-Origin-Embedder-Policy": "require-corp",
      "Cross-Origin-Opener-Policy": "same-origin",
    },
  },
});
