# demo_hash.py  – minimal example
# from vein import VEIN

MAIN_KEY     = "0123456789abcdef" * 4   # 64-char hex (256-bit) demo key
MAIN_MODULUS = 9973                     # any integer ≥ 2
DUMMY_EIN    = "12-3456789"

hashed = VEIN.VTIN_identifier(
    ein=DUMMY_EIN,
    main_key=MAIN_KEY,
    modulus=MAIN_MODULUS,
)

print(f"dummy_ein: {DUMMY_EIN}  →  hash:{hashed}")