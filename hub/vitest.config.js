// Pool 0.13.x exports cloudflareTest AND readD1Migrations from the package
// root (the ./config subpath was removed with the Vitest-4 rewrite).
import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";
import path from "node:path";

const migrations = await readD1Migrations(path.join(import.meta.dirname, "migrations"));

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.toml" },
      miniflare: {
        // migrations array handed to the worker context for the setup file;
        // test tokens provisioned here (wrangler.toml deliberately omits secrets).
        bindings: {
          TEST_MIGRATIONS: migrations,
          SWARM_WRITE_TOKEN: "test-write",
          SWARM_READ_TOKEN: "test-read",
          SWARM_ENROLL_TOKEN: "test-enroll",
          // Keep the legacy shared-write window OPEN for tests (prod retires it via
          // the real SWARM_LEGACY_WRITE_UNTIL in wrangler.toml [vars]); "" = no cutover.
          SWARM_LEGACY_WRITE_UNTIL: "",
        },
      },
    }),
  ],
  test: { setupFiles: ["./test/apply-migrations.js"] },
});
