# Representative MCP integration target

This fixture is a deterministic, dependency-free stdio MCP target for AGENT
supply-chain and guarded-runtime integration tests. It declares an instruction
asset, MCP server, plugin, tool schema, prompt, resource, approval boundary and
local runtime entrypoint.

`test_client.py` starts `mcp_server.py` with an argument array and exercises
`initialize`, `tools/list`, one bounded `tools/call`, `resources/list` and
`prompts/list`. The only tool adds two integers between -1000 and 1000. The
fixture does not install packages, contact the network, read environment
variables, access host files, or persist output.

This is a representative integration target maintained by this repository. It
is not a third-party production Agent and must not be presented as proof that a
real external Agent is safe.
