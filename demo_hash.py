# demo_hash.py  – minimal example
from vein_hasher import VEINHasher

MAIN_KEY     = "0123456789abcdef" * 4   # 64-char hex (256-bit) demo key
MAIN_MODULUS = 9973                     # any integer ≥ 2
DUMMY_EIN    = "12-3456789"

hashed = VEINHasher.hash(
    ein=DUMMY_EIN,
    main_key=MAIN_KEY,
    modulus=MAIN_MODULUS,
)

print(f"{DUMMY_EIN}  →  {hashed}")