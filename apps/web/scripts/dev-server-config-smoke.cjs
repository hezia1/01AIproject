const assert = require("node:assert/strict");
const path = require("node:path");

(async () => {
  const { resolveConfig } = await import("vite");
  const config = await resolveConfig(
    { configFile: path.resolve(__dirname, "..", "vite.config.ts") },
    "serve",
  );

  assert.equal(config.server.host, "127.0.0.1", "development server must listen on IPv4 loopback");
  assert.equal(config.server.port, 5173, "development server port must remain stable");
  assert.equal(config.server.strictPort, true, "development server must fail instead of silently changing ports");
  assert.equal(config.server.proxy?.["/api"]?.target, "http://127.0.0.1:8000", "API proxy must use the local backend");

  console.log("Development server configuration smoke passed");
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
