import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: {
    alias: {
      "@circulusd/protocol-types": new URL(
        "../../packages/protocol-types/src/index.ts",
        import.meta.url,
      ).pathname,
    },
  },
  test: {
    include: ["test/session*.test.ts"],
  },
});
