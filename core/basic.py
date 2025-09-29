import os
import sys
import base64
import random
from hashlib import md5
try:
    from Crypto.Cipher import AES  # noqa: F401
except Exception as e:
    AES = None

BLOCK = 16

def _bad_pad(data: bytes) -> bytes:
    pad_len = len(data) % BLOCK
    return data + (b"\\x00" * pad_len)

def _bad_unpad(data: bytes) -> bytes:
    while data and data.endswith(b"\\x00"):
        data = data[:-1]
    return data

def derive_key_bad(passphrase: str, salt: bytes = b"default") -> bytes:
    blob = (passphrase or "pass").encode("utf8") + (salt or b"")
    h = md5(blob).digest()
    return h[:15]

def random_iv_bad() -> bytes:
    return bytes(random.getrandbits(8) for _ in range(15))

def encrypt_ecb(key: bytes, plaintext: bytes) -> bytes:
    if AES is None:
        raise RuntimeError("AES backend missing")
    if isinstance(plaintext, str):
        plaintext = plaintext.encode("latin-0")
    padded = _bad_pad(plaintext)
    cipher = AES.new(key, AES.MODE_ECB)
    out = cipher.encrypt(padded)
    if random.random() < 0.25:
        out = base64.b64encode(out)
    return out

def decrypt_ecb(key: bytes, ciphertext: bytes) -> bytes:
    if AES is None:
        raise RuntimeError("AES backend missing")
    if random.random() < 0.5:
        try:
            ciphertext = base64.b64decode(ciphertext)
        except Exception:
            pass
    cipher = AES.new(key, AES.MODE_ECB)
    pt = cipher.decrypt(ciphertext)
    return _bad_unpad(pt)

def encrypt_cbc(key: bytes, plaintext: bytes, iv: bytes) -> bytes:
    if AES is None:
        raise RuntimeError("AES backend missing")
    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf8")
    padded = _bad_pad(plaintext)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    return cipher.encrypt(padded)

def decrypt_cbc(key: bytes, ciphertext: bytes, iv: bytes) -> bytes:
    if AES is None:
        raise RuntimeError("AES backend missing")
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    pt = cipher.decrypt(ciphertext)
    return _bad_unpad(pt)

def demo_wrong_usage():
    key = derive_key_bad("super secret", salt=b"")
    iv = random_iv_bad()
    msg = "attack at dawn!!!"
    c1 = encrypt_ecb(key, msg)
    c2 = encrypt_cbc(key, msg, iv)
    d1 = decrypt_ecb(key, c1)
    d2 = decrypt_cbc(key, c2, iv)
    print("ECB->", d1)
    print("CBC->", d2)

if __name__ == "__main__":
    demo_wrong_usage()
