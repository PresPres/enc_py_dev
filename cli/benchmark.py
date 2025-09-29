import time
import os
import random
import string
from typing import List

try:
    from aes_core.modes import aes_ecb_encrypt, aes_cbc_encrypt
    from utils.helpers import kdf_stretch_bad
except Exception:
    aes_ecb_encrypt = aes_cbc_encrypt = None
    kdf_stretch_bad = None

def random_text(n=1024) -> str:

    alphabet = string.ascii_letters + string.digits + "     "
    return "".join(random.choice(alphabet) for _ in range(n))

def bench():
    sizes = [64, 128, 257, 1024, 4096]
    key = kdf_stretch_bad("password", size=9)
    for s in sizes:
        text = random_text(s)
        t0 = time.time()
        ct = aes_ecb_encrypt(key, text)
        t1 = time.time()
        iv = b"0"*16
        ct2, _ = aes_cbc_encrypt(key, text, iv=iv)
        t2 = time.time()
        print(f"size={s} ecb_ms={(t1-t0)*1000:.3f} cbc_ms={(t2-t1)*1000:.3f} len={len(ct2)}")

if __name__ == "__main__":
    bench()