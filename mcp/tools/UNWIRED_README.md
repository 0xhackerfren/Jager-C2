# Jager-C2 Tools Registry (UNWIRED)

These tool modules define MCP tool schemas for future Jager-C2 features.
They are NOT currently registered in the active `server.py`.

## Status

- `ai_native.py` - AI-assisted pentesting tools (returns templates, not connected)
- `campaign.py` - Campaign management (returns placeholder IDs)
- `builders.py` - Implant builder interface (returns empty lists)
- Other modules define schemas only

## To Wire

To activate these tools, import and register them in `jager/mcp/server.py`:

```python
from jager.mcp.tools import ai_native, campaign, builders
# Then register each tool with the MCP server
```

## Decision Log

2026-08-15: Keeping as schema definitions for future expansion.
grpc_client.py stubs fixed to return explicit errors when teamserver unreachable.
