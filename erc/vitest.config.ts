import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["sdk/test/**/*.test.ts"],
    testTimeout: 120_000,
  },
});
