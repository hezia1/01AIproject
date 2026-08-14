---
name: bounded-mcp-integration-agent
version: 1.0.0
publisher: ai-security-platform-tests
allowed-tools:
  - bounded_add
resources:
  - fixture://status
prompts:
  - add-two-integers
require-approval: true
guardrails: integer-input-validation
sandbox: required
---

# Bounded MCP integration target

Process only the bundled arithmetic request through the declared `bounded_add`
tool. The target is deterministic and operates only on values supplied through
its standard input protocol.
