"""Tests for report rendering, backup decryption, and the web multipart parser."""

import io
import os
import zipfile

import pytest

from udmx_analyzer.analyze import analyze
from udmx_analyzer.ingest import load_paths
from udmx_analyzer.report import render_html, render_json, render_text

SAMPLES = os.path.join(os.path.dirname(os.path.dirname(__file__)), "samples")


def _result():
    return analyze(load_paths([SAMPLES]))


def test_text_report_renders():
    out = render_text(_result(), color=False)
    assert "Analysis Report" in out
    assert "Evidence:" in out
    assert "WAN-FLAP" in out


def test_json_report_is_valid_and_sorted():
    import json
    data = json.loads(render_json(_result()))
    assert "findings" in data and data["findings"]
    ranks = [f["severity_rank"] for f in data["findings"]]
    assert ranks == sorted(ranks, reverse=True)
    # Every finding carries evidence.
    assert all(f["evidence"] for f in data["findings"])


def test_html_report_renders_and_escapes():
    html = render_html(_result())
    assert html.startswith("<!doctype html>")
    assert "UniFi Dream Machine Pro Max" in html
    assert "<script>" not in html  # nothing injected/executable


def test_web_multipart_parser():
    from udmx_analyzer.web.server import _parse_multipart

    boundary = "X-BOUNDARY"
    parts = [
        f"--{boundary}",
        'Content-Disposition: form-data; name="files"; filename="a.log"',
        "Content-Type: application/octet-stream",
        "",
        "hello\r\nworld",
        f"--{boundary}--",
        "",
    ]
    body = "\r\n".join(parts).encode()
    files = _parse_multipart(body, f"multipart/form-data; boundary={boundary}")
    assert len(files) == 1
    assert files[0][0] == "a.log"
    assert files[0][1] == b"hello\r\nworld"


def test_backup_decrypt_roundtrip(monkeypatch):
    """Round-trip a ZIP through the AES path using a configured key/IV.

    Verifies the decrypt+unzip+parse pipeline end to end. Uses a test key via
    the documented env-var override (the tool does not assert a hardcoded key).
    """

    pytest.importorskip("cryptography")
    # The cryptography backend needs a working _cffi_backend; some minimal
    # containers ship the wheel without it, which panics on real AES calls.
    pytest.importorskip("_cffi_backend")
    from cryptography.hazmat.primitives.ciphers import (
        Cipher, algorithms, modes,
    )
    from udmx_analyzer.ingest.backup import read_backup

    key = bytes(range(16))            # arbitrary valid 16-byte AES-128 key
    iv = bytes(range(16, 32))
    monkeypatch.setenv("UDMX_BACKUP_KEY", key.hex())
    monkeypatch.setenv("UDMX_BACKUP_IV", iv.hex())

    # Build an inner ZIP containing a JSON config.
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("settings.json", '{"mgmt": {"telnet": {"enabled": true}}}')
    plain = buf.getvalue()

    # PKCS#7 pad to AES block size, then encrypt.
    pad = 16 - (len(plain) % 16)
    padded = plain + bytes([pad]) * pad
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    cipher_bytes = enc.update(padded) + enc.finalize()

    configs, warnings = read_backup(cipher_bytes, "test.unf")
    assert any(c.name == "settings.json" for c in configs), warnings


def test_backup_missing_key_warns_not_crashes(monkeypatch):
    """Without a key, .unf ingestion yields a clear warning, never an exception."""

    from udmx_analyzer.ingest.backup import read_backup

    monkeypatch.delenv("UDMX_BACKUP_KEY", raising=False)
    configs, warnings = read_backup(b"\x00\x10not-a-zip-encrypted-blob", "x.unf")
    assert configs == []
    assert warnings and "UDMX_BACKUP_KEY" in warnings[0]
