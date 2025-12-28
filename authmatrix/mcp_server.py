"""AUTHMATRIX MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from authmatrix.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-authmatrix[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-authmatrix[mcp]'")
        return 1
    app = FastMCP("authmatrix")

    @app.tool()
    def authmatrix_scan(target: str) -> str:
        """Test an access-control matrix (role x endpoint) for IDOR/authz gaps. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
