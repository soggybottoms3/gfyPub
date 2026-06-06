"""Decrypt and read UniFi ``.unf`` backup archives.

UniFi Network auto-backups (``*.unf``) are AES-CBC encrypted ZIP archives. The
key and IV are static (not per-user secrets) — decrypting your own backup
locally exposes nothing the device would not hand you over SSH. After
decryption the payload is a standard ZIP whose most useful members are:

* ``db.gz``             — gzipped BSON dump of the Network Mongo database
* ``system.properties`` — controller settings (key/value)
* ``*.json``            — site/device configuration exports

We extract the readable text/JSON members; ``db.gz`` BSON is noted but not
decoded (out of scope).

On the static key
-----------------
The exact key/IV bytes vary by report across firmware generations and this
build was assembled without a sample ``.unf`` to verify against, so it does
**not** ship a single hardcoded value asserted as fact. Instead:

* Supply the correct values via ``UDMX_BACKUP_KEY`` / ``UDMX_BACKUP_IV``
  (hex strings). This is the reliable path.
* The key length is validated (must be 16/24/32 bytes for AES); an invalid or
  missing key produces a clear, actionable warning rather than a crash or a
  silently-wrong result.
* If the supplied key/IV do not yield a valid ZIP, that is reported too —
  signalling the wrong key rather than pretending success.

Decryption requires the optional ``cryptography`` dependency; without it we
record a warning and skip rather than failing the whole run.
"""

from __future__ import annotations

import binascii
import io
import os
import zipfile
from typing import List, Optional, Tuple

from ..models import ConfigDoc
from .config import parse_config

# Commonly-cited IV (ASCII "ubntenterprise\0\0" = 16 bytes, a valid block/IV
# size). Used as the default IV; override with UDMX_BACKUP_IV if needed.
_DEFAULT_IV_HEX = "75626e74656e74657270726973650000"
# No default key is asserted as fact (see module docstring): supply via
# UDMX_BACKUP_KEY. If you have verified the static key for your firmware, set
# it there as a hex string.
_DEFAULT_KEY_HEX = os.environ.get("UDMX_BACKUP_KEY", "")


class BackupError(Exception):
    """Raised when a .unf cannot be decrypted or read."""


def _key_iv() -> Tuple[Optional[bytes], bytes]:
    """Resolve key/IV from the environment, validating the AES key length."""

    key_hex = os.environ.get("UDMX_BACKUP_KEY", _DEFAULT_KEY_HEX)
    iv_hex = os.environ.get("UDMX_BACKUP_IV", _DEFAULT_IV_HEX)
    iv = binascii.unhexlify(iv_hex) if iv_hex else b""
    if not key_hex:
        return None, iv
    try:
        key = binascii.unhexlify(key_hex)
    except (binascii.Error, ValueError) as exc:
        raise BackupError(f"UDMX_BACKUP_KEY is not valid hex: {exc}")
    if len(key) not in (16, 24, 32):
        raise BackupError(
            f"UDMX_BACKUP_KEY decodes to {len(key)} bytes; AES requires "
            "16, 24, or 32. Provide the correct hex-encoded static key."
        )
    return key, iv


def _decrypt(data: bytes) -> bytes:
    key, iv = _key_iv()
    if key is None:
        raise BackupError(
            "No AES key available for .unf decryption. Set UDMX_BACKUP_KEY "
            "(hex) to the static UniFi backup key for your firmware "
            "(and UDMX_BACKUP_IV if it differs from the default)."
        )
    try:
        from cryptography.hazmat.primitives.ciphers import (
            Cipher, algorithms, modes,
        )
    except ImportError as exc:  # pragma: no cover - depends on optional extra
        raise BackupError(
            "Decrypting .unf backups requires the 'cryptography' package. "
            "Install it with: pip install 'udmx-analyzer[backup]'"
        ) from exc

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(data) + decryptor.finalize()
    # Strip PKCS#7 padding if present.
    if decrypted:
        pad = decrypted[-1]
        if 1 <= pad <= 16 and decrypted[-pad:] == bytes([pad]) * pad:
            decrypted = decrypted[:-pad]
    return decrypted


def decrypt_unf(raw: bytes) -> bytes:
    """Return the inner ZIP bytes of a ``.unf`` backup.

    If ``raw`` already starts with the ZIP magic it is returned untouched
    (some exports are not encrypted).
    """

    if raw[:2] == b"PK":
        return raw
    return _decrypt(raw)


def read_backup(raw: bytes, source: str) -> Tuple[List[ConfigDoc], List[str]]:
    """Parse a ``.unf`` into config documents.

    Returns ``(configs, warnings)``. Binary members (e.g. ``db.gz`` BSON) are
    noted in warnings rather than parsed, since a faithful BSON decode is out
    of scope; the readable settings carry most diagnostic value.
    """

    configs: List[ConfigDoc] = []
    warnings: List[str] = []

    try:
        inner = decrypt_unf(raw)
    except BackupError as exc:
        return [], [str(exc)]

    try:
        zf = zipfile.ZipFile(io.BytesIO(inner))
    except zipfile.BadZipFile:
        return [], [
            f"{source}: decrypted payload is not a valid ZIP — the key/IV are "
            "likely wrong for this firmware, or the backup is corrupt. Set "
            "UDMX_BACKUP_KEY/UDMX_BACKUP_IV (hex) to the correct values."
        ]

    for member in zf.namelist():
        if member.endswith("/"):
            continue
        try:
            payload = zf.read(member)
        except Exception as exc:  # noqa: BLE001 - report and continue
            warnings.append(f"{source}: could not read {member}: {exc}")
            continue

        lname = member.lower()
        if lname.endswith((".json", ".properties", ".cfg", ".cconfig")):
            try:
                text = payload.decode("utf-8", errors="replace")
            except Exception:  # noqa: BLE001
                warnings.append(f"{source}: {member} is not text-decodable.")
                continue
            doc = parse_config(text, name=member, source=f"{source}:{member}")
            if doc is not None:
                configs.append(doc)
        else:
            warnings.append(
                f"{source}: skipped binary backup member {member} "
                "(not parsed)."
            )

    if not configs and not warnings:
        warnings.append(f"{source}: no readable members found in backup.")
    return configs, warnings
