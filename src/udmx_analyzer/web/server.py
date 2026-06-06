"""Local web UI built on the standard library only.

Why stdlib: the data being analyzed (support files, backups, syslogs) is
sensitive. Pulling in a web framework — and the temptation to deploy it — works
against that. This server binds to loopback by default and processes uploads in
a temporary directory that is deleted immediately after analysis. Nothing is
persisted and nothing leaves the machine.

Routes:
    GET  /            upload form (+ a preset report if one was passed in)
    POST /analyze     multipart upload -> run analysis -> HTML report
    GET  /healthz     liveness probe
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import List, Optional, Tuple

from ..analyze import analyze
from ..ingest import load_paths
from ..models import AnalysisResult
from ..report import render_html

_UPLOAD_FORM = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>UDM Pro Max Analyzer</title>
<style>
body{{margin:0;background:#0f1115;color:#e6e6e6;
 font:15px/1.6 -apple-system,Segoe UI,Roboto,Arial,sans-serif}}
.wrap{{max-width:760px;margin:0 auto;padding:40px 24px}}
h1{{font-size:24px}} p{{color:#9aa0aa}}
.drop{{border:2px dashed #2a2e38;border-radius:12px;padding:40px;text-align:center;
 background:#1a1d24;margin:24px 0}}
input[type=file]{{color:#e6e6e6}}
button{{background:#2563eb;color:#fff;border:0;border-radius:8px;
 padding:10px 18px;font-size:15px;cursor:pointer}}
.note{{font-size:12px;color:#6b7280;margin-top:24px}}
a{{color:#60a5fa}}
</style></head><body><div class="wrap">
<h1>UniFi Dream Machine Pro Max — Analyzer</h1>
<p>Upload support files (.zip/.tar.gz), backups (.unf), syslogs, or config
 files. Everything is processed locally and discarded after analysis.</p>
<form action="/analyze" method="post" enctype="multipart/form-data">
 <div class="drop">
  <input type="file" name="files" multiple required>
 </div>
 <button type="submit">Analyze</button>
</form>
{preset}
<div class="note">Running locally on {host}:{port}. Bound to loopback by
 default — nothing is uploaded to any external service.</div>
</div></body></html>"""


def _parse_multipart(body: bytes, content_type: str) -> List[Tuple[str, bytes]]:
    """Minimal multipart/form-data parser returning ``(filename, bytes)``.

    Stdlib ``cgi`` was removed in 3.13, so we parse by boundary directly. Only
    file parts (those with a ``filename``) are returned.
    """

    marker = "boundary="
    idx = content_type.find(marker)
    if idx == -1:
        return []
    boundary = content_type[idx + len(marker):].strip().strip('"')
    delim = b"--" + boundary.encode()

    parts: List[Tuple[str, bytes]] = []
    for chunk in body.split(delim):
        if not chunk or chunk in (b"--\r\n", b"--", b"\r\n"):
            continue
        header_end = chunk.find(b"\r\n\r\n")
        if header_end == -1:
            continue
        header_blob = chunk[:header_end].decode("utf-8", "replace")
        content = chunk[header_end + 4:]
        # Trim the trailing CRLF that precedes the next boundary.
        if content.endswith(b"\r\n"):
            content = content[:-2]
        filename = None
        for line in header_blob.split("\r\n"):
            if line.lower().startswith("content-disposition"):
                for token in line.split(";"):
                    token = token.strip()
                    if token.startswith("filename="):
                        filename = token[len("filename="):].strip('"')
        if filename:
            parts.append((os.path.basename(filename), content))
    return parts


class _Handler(BaseHTTPRequestHandler):
    # Set by serve().
    preset_html: str = ""
    host: str = "127.0.0.1"
    port: int = 8744

    def log_message(self, fmt, *args):  # quieter logging
        sys.stderr.write("[udmx-web] " + (fmt % args) + "\n")

    def _send(self, status: int, body: str, ctype="text/html; charset=utf-8"):
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        if self.path == "/healthz":
            self._send(200, "ok", "text/plain; charset=utf-8")
            return
        if self.path in ("/", "/index.html"):
            page = _UPLOAD_FORM.format(
                preset=self.preset_html, host=self.host, port=self.port
            )
            self._send(200, page)
            return
        self._send(404, "Not found", "text/plain; charset=utf-8")

    def do_POST(self):
        if self.path != "/analyze":
            self._send(404, "Not found", "text/plain; charset=utf-8")
            return

        length = int(self.headers.get("Content-Length", 0))
        ctype = self.headers.get("Content-Type", "")
        if length <= 0 or "multipart/form-data" not in ctype:
            self._send(400, "Expected a multipart file upload.",
                       "text/plain; charset=utf-8")
            return

        body = self.rfile.read(length)
        files = _parse_multipart(body, ctype)
        if not files:
            self._send(400, "No files received.", "text/plain; charset=utf-8")
            return

        tmpdir = tempfile.mkdtemp(prefix="udmx-web-")
        try:
            paths = []
            for name, content in files:
                safe = name or "upload.bin"
                dest = os.path.join(tmpdir, safe)
                with open(dest, "wb") as fh:
                    fh.write(content)
                paths.append(dest)
            result = analyze(load_paths(paths))
            self._send(200, render_html(result))
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


def serve(host: str = "127.0.0.1", port: int = 8744,
          preset_result: Optional[AnalysisResult] = None) -> None:
    """Start the local web server (blocking)."""

    _Handler.preset_html = render_html(preset_result) if preset_result else ""
    _Handler.host = host
    _Handler.port = port

    if host not in ("127.0.0.1", "localhost", "::1"):
        sys.stderr.write(
            f"[udmx-web] WARNING: binding to {host} exposes uploaded UniFi "
            "data beyond this machine. Use 127.0.0.1 unless you intend remote "
            "access and have secured it.\n"
        )

    httpd = ThreadingHTTPServer((host, port), _Handler)
    url = f"http://{host}:{port}/"
    sys.stderr.write(f"[udmx-web] Serving UDM Pro Max analyzer at {url}\n")
    sys.stderr.write("[udmx-web] Press Ctrl+C to stop.\n")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        sys.stderr.write("\n[udmx-web] Shutting down.\n")
    finally:
        httpd.server_close()


def main(argv: Optional[List[str]] = None) -> int:
    import argparse

    p = argparse.ArgumentParser(
        prog="udmx-web",
        description="Local web UI for the UDM Pro Max analyzer.",
    )
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8744)
    p.add_argument("paths", nargs="*",
                   help="Optional files/dirs to analyze and show on load.")
    args = p.parse_args(argv)

    preset = analyze(load_paths(args.paths)) if args.paths else None
    serve(host=args.host, port=args.port, preset_result=preset)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
