import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: {
    alias: {
      "@circulusd/protocol-types": new URL(
        "../protocol-types/src/index.ts",
        import.meta.url,
      ).pathname,
    },
  },
  test: {
    include: ["test/**/*.test.ts"],
  },
});
