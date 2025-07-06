"""
VEINHasher: Secure, deterministic hashing of EINs using bucketed HKDF-derived HMAC

Key Features:
- One main key, derived via HKDF per bucket
- Secret modulus to determine bucket assignment
- Validates EINs (accepts dashes, requires 9 digits)


EINs can be provided in formats with dashes (e.g., 12-3456789 or 123-45-6789),
but any other non-numeric characters will raise an error.

This design offers a balanced mix of security, performance, and operational simplicity,
making it ideal for stable hashing of low-entropy identifiers like EINs—especially when
you want to guard against enumeration and futureproof for scale or regulation.

Why this design makes sense:

1. Strong Security with Minimal Overhead:
   HKDF generates cryptographically strong, deterministic salts per bucket from one main key—no need to store thousands of keys.
   A random modulus obscures the bucket assignment logic, making reverse engineering harder.

2. Scalability without Complexity:
   Easily supports millions of EINs without requiring massive storage or key management infrastructure.
   Stateless derivation = no key database required.

3. Defense in Depth:
   Even if the main key leaks, an attacker still needs to guess the modulus to reconstruct bucket mappings.
   Even if the modulus leaks, brute-forcing without the main key remains computationally hard.

4. Future-Proofing:
   You can scale up by increasing the modulus or changing the HKDF info string (e.g., add a version tag).
   Supports key rotation and versioning without architectural change.

---
How to use
~~~~~~~~~
```python
from vein_hasher import VEINHasher

MAIN_KEY      = "4ab9e4…64_hex_chars…782d"   # 64-char hex string (256-bit)
MAIN_MODULUS  = 9973                           # any positive int ≥ 2

hashed = VEINHasher.hash( ein="12-3456789",
                         main_key=MAIN_KEY,
                         modulus=MAIN_MODULUS )
print(hashed)
```
The `main_key` argument can be either a **bytes** object or a 64-hex-char
string.  Supplying a modulus that is co-prime with neighbouring values
(e.g. a large prime) helps distribute bucket IDs evenly.
"""

import hmac
import hashlib
from typing import Union
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


class VEINHasher:
    """Utility class – all methods are **@staticmethod** and keyword-only."""

    # ----- EIN helpers ------------------------------------------------------
    @staticmethod
    def _normalize_ein(*, ein: str) -> str:
        """Return the EIN stripped of dashes and validated as 9 digits."""
        cleaned = ein.strip().replace("-", "")
        if not cleaned.isdigit():
            raise ValueError("EIN/TIN must contain only digits and optional dashes")
        if len(cleaned) != 9:
            raise ValueError("EIN/TIN must be exactly 9 digits after normalization")
        return cleaned

    # ----- HKDF salt derivation ---------------------------------------------
    @staticmethod
    def _derive_salt(*, main_key: bytes, bucket_id: int) -> bytes:
        """Derive a deterministic 32-byte salt for the given bucket ID."""
        info = f"bucket-{bucket_id}".encode()
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=info,
            backend=default_backend(),
        )
        return hkdf.derive(main_key)

    # ----- Public API ------------------------------------------------------
    @staticmethod
    def hash(*, ein: str, main_key: Union[bytes, str], modulus: int) -> str:
        """Return a SHA-256 HMAC hex digest for the supplied EIN.

        Parameters
        ----------
        ein : str
            The Employer Identification Number (9 digits, dashes optional).
        main_key : bytes | str
            256-bit master key.  If a *str* is given it must be a 64-character
            hexadecimal representation and will be converted to *bytes*.
        modulus : int
            Positive integer ≥ 2 used to assign rows to buckets
            (`bucket_id = int(ein) % modulus`).
        """
        if modulus < 2:
            raise ValueError("modulus must be ≥ 2")

        # convert key if necessary
        if isinstance(main_key, str):
            try:
                main_key_bytes = bytes.fromhex(main_key)
            except ValueError as exc:
                raise ValueError("main_key hex string is not valid hex") from exc
        elif isinstance(main_key, (bytes, bytearray)):
            main_key_bytes = bytes(main_key)
        else:
            raise TypeError("main_key must be bytes or 64-char hex string")

        if len(main_key_bytes) < 32:  # 256 bits
            raise ValueError("main_key must be at least 32 bytes (256 bits)")

        normalized_ein = VEINHasher._normalize_ein(ein=ein)
        bucket_id = int(normalized_ein) % modulus
        salt = VEINHasher._derive_salt(main_key=main_key_bytes, bucket_id=bucket_id)
        mac = hmac.new(salt, normalized_ein.encode(), hashlib.sha256)
        return mac.hexdigest()
