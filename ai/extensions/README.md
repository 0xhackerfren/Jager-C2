# Jager-C2 AI Extension Store

Place BOF manifests and `.o` artifacts here for MCP/agent discovery (Sliver Armory model).

```
jager/ai/extensions/<name>/
  extension.json
  <arch>.o
```

MCP tools `c2_bof_exec` and future `c2_extension_list` read from this directory.
