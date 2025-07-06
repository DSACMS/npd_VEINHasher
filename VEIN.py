"""
VEINHasher: Secure, deterministic hashing of EINs (or other 9‑digit TINs)

Updates in this revision
~~~~~~~~~~~~~~~~~~~~~~~~
* Public helper renamed **`VTIN_identifier()`** (was `vt_identifier`).
* **All** other static helpers are now prefixed with an underscore to
  signal they are internal only (e.g. `_hash`).
* Doc‑string and demo updated accordingly.
"""

import hmac
import hashlib
from typing import Union
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


class VEIN:
    """Utility class – only **VTIN_identifier** is part of the public API."""

    # ------------------------------------------------------------------
    # Internal helpers (underscore‑prefixed)
    # ------------------------------------------------------------------
    @staticmethod
    def _normalize_ein(*, ein: str) -> str:
        cleaned = ein.strip().replace("-", "")
        if not cleaned.isdigit():
            raise ValueError("EIN/TIN must contain only digits and optional dashes")
        if len(cleaned) != 9:
            raise ValueError("EIN/TIN must be exactly 9 digits after normalization")
        return cleaned

    @staticmethod
    def _derive_salt(*, main_key: bytes, bucket_id: int) -> bytes:
        info = f"bucket-{bucket_id}".encode()
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=info,
            backend=default_backend(),
        )
        return hkdf.derive(main_key)

    @staticmethod
    def _to_base36(*, n: int) -> str:
        digits = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        if n == 0:
            return "0"
        out = []
        while n:
            n, r = divmod(n, 36)
            out.append(digits[r])
        return "".join(reversed(out))

    @staticmethod
    def _hash(*, ein: str, main_key: Union[bytes, str], modulus: int) -> str:
        """Return the full 64‑hex‑char SHA‑256 HMAC digest (internal use)."""
        if modulus < 2:
            raise ValueError("modulus must be ≥ 2")

        if isinstance(main_key, str):
            try:
                main_key_bytes = bytes.fromhex(main_key)
            except ValueError as exc:
                raise ValueError("main_key hex string is not valid hex") from exc
        elif isinstance(main_key, (bytes, bytearray)):
            main_key_bytes = bytes(main_key)
        else:
            raise TypeError("main_key must be bytes or 64‑char hex string")

        if len(main_key_bytes) < 32:
            raise ValueError("main_key must be at least 32 bytes (256 bits)")

        normalized_ein = VEINHasher._normalize_ein(ein=ein)
        bucket_id = int(normalized_ein) % modulus
        salt = VEINHasher._derive_salt(main_key=main_key_bytes, bucket_id=bucket_id)
        mac = hmac.new(salt, normalized_ein.encode(), hashlib.sha256)
        return mac.hexdigest()

    # ------------------------------------------------------------------
    # Public API: VT‑prefixed 20‑char identifier
    # ------------------------------------------------------------------
    @staticmethod
    def VTIN_identifier(*, ein: str, main_key: Union[bytes, str], modulus: int) -> str:
        """Return a deterministic 20‑character alphanumeric ID starting with **VT**.

        Format
        ------
        ``VT`` + 18 uppercase base‑36 characters (0‑9A‑Z).
        """
        full_hash_hex = VEINHasher._hash(ein=ein, main_key=main_key, modulus=modulus)
        partial_int   = int(full_hash_hex[:30], 16)  # first 15 bytes → int
        base36        = VEINHasher._to_base36(n=partial_int).rjust(18, "0")[-18:]
        return "VT" + base36
