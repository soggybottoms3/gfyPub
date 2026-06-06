"""Local-only web UI for the analyzer (stdlib http.server, no dependencies)."""

from .server import serve, main

__all__ = ["serve", "main"]
