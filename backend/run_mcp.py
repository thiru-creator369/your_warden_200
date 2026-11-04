"""Standalone entrypoint for Claude Desktop MCP server."""

import os
import sys

# Force UTF-8 encoding across all stdio channels on Windows to prevent charmap/cp1252 crashes
if sys.platform == "win32":
    os.environ["PYTHONIOENCODING"] = "utf-8"
    os.environ["PYTHONUTF8"] = "1"
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stdin, "reconfigure"):
            sys.stdin.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Ensure backend root is always in sys.path
backend_root = os.path.dirname(os.path.abspath(__file__))
if backend_root not in sys.path:
    sys.path.insert(0, backend_root)

from app.mcp_tools import mcp, firebase_manager

if __name__ == "__main__":
    try:
        firebase_manager.initialize()
    except Exception:
        pass
    mcp.run()
