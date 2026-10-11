import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: {
    alias: {
      "cloudflare:workers": new URL(
        "../state-app/test/cloudflare-workers.ts",
        import.meta.url,
      ).pathname,
    },
  },
  test: {
    include: ["test/**/*.test.ts"],
  },
});
