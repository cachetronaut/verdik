import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: {
    alias: {
      "@verdik/core": fileURLToPath(new URL("packages/core/src/index.ts", import.meta.url)),
      "@verdik/rules-local": fileURLToPath(
        new URL("packages/rules-local/src/index.ts", import.meta.url),
      ),
    },
  },
});
