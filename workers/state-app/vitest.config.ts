import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: {
    alias: {
      "@circulusd/protocol-types": new URL(
        "../../packages/protocol-types/src/index.ts",
        import.meta.url,
      ).pathname,
      "cloudflare:workers": new URL(
        "test/cloudflare-workers.ts",
        import.meta.url,
      ).pathname,
    },
  },
  test: {
    testTimeout: 20_000,
    include: [
      "test/session*.test.ts",
      "test/workspace*.test.ts",
      "test/control*.test.ts",
      "test/host*.test.ts",
    ],
  },
});
