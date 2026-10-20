"""
Tool Registry - Aggregates all MCP tool modules into a single registry.

This allows the MCP server to dynamically discover and dispatch tool calls
across all modules without hardcoding each tool.
"""

from typing import Any, Dict, List, Optional
import importlib
import logging

logger = logging.getLogger("jager.tools.registry")

# Tool modules - loaded relative to mcp/ on sys.path
TOOL_MODULES = [
    "tools.sessions",
    "tools.execution",
    "tools.credentials",
    "tools.lateral",
    "tools.evasion",
    "tools.pivot",
    "tools.builders",
    "tools.campaign",
    "tools.ai_native",
    "tools.operator",
]


class ToolRegistry:
    """Central registry for all MCP tools across modules."""

    def __init__(self):
        self._tools: Dict[str, dict] = {}
        self._handlers: Dict[str, Any] = {}  # tool_name -> module with handle()
        self._loaded = False

    def load_all(self) -> None:
        """Load all tool modules and register their tools."""
        for module_path in TOOL_MODULES:
            try:
                module = importlib.import_module(module_path)
                tools = getattr(module, "TOOLS", [])
                handler = getattr(module, "handle", None)

                for tool in tools:
                    name = tool["name"]
                    self._tools[name] = tool
                    if handler:
                        self._handlers[name] = module
                    logger.debug(f"Registered tool: {name}")

                logger.info(f"Loaded {len(tools)} tools from {module_path}")

            except ImportError as e:
                logger.warning(f"Failed to import tool module {module_path}: {e}")
            except Exception as e:
                logger.error(f"Error loading tool module {module_path}: {e}")

        self._loaded = True
        logger.info(f"Tool registry loaded: {len(self._tools)} total tools")

    def get_all_tools(self) -> List[dict]:
        """Return all registered tool definitions for MCP list_tools."""
        if not self._loaded:
            self.load_all()
        return list(self._tools.values())

    def get_tool(self, name: str) -> Optional[dict]:
        """Get a single tool definition by name."""
        if not self._loaded:
            self.load_all()
        return self._tools.get(name)

    async def dispatch(self, tool_name: str, args: Dict[str, Any], client) -> Dict[str, Any]:
        """Dispatch a tool call to the appropriate handler module."""
        if not self._loaded:
            self.load_all()

        module = self._handlers.get(tool_name)
        if not module:
            return {"error": f"No handler registered for tool: {tool_name}"}

        try:
            return await module.handle(tool_name, args, client)
        except Exception as e:
            logger.error(f"Tool execution error ({tool_name}): {e}")
            return {"error": str(e)}

    @property
    def tool_count(self) -> int:
        if not self._loaded:
            self.load_all()
        return len(self._tools)


# Global singleton
registry = ToolRegistry()
