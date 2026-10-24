import { defineConfig } from "vitest/config";
import path from "node:path";

export default defineConfig({
  test: { include: ["packages/*/test/**/*.test.ts"] },
  resolve: {
    alias: {
      "@mandate/core": path.resolve(__dirname, "packages/core/src/index.ts"),
      "@mandate/chain": path.resolve(__dirname, "packages/chain/src/index.ts"),
      "@mandate/verifier": path.resolve(__dirname, "packages/verifier/src/index.ts"),
    },
  },
});
