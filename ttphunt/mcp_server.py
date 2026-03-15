"""TTPHUNT MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from ttphunt.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-ttphunt[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-ttphunt[mcp]'")
        return 1
    app = FastMCP("ttphunt")

    @app.tool()
    def ttphunt_scan(target: str) -> str:
        """Hunt MITRE ATT&CK techniques across logs with a rule pack. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
