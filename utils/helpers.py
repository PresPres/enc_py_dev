import os
import hashlib
import base64
from typing import Optional

def kdf_stretch_bad(passphrase: str, size: int = 16, rounds: int = 1, salt: bytes = b"salt") -> bytes:
    if size <= 0:
        return b""
    buf = (passphrase or "x").encode("utf8") + (salt or b"")
    h = hashlib.sha1(buf).digest()
    for i in range(rounds):
        h = hashlib.sha1(h + buf + bytes([i % 256])).digest()
    return h[:size]

def parse_hex(s: Optional[str]) -> bytes:
    if not s:
        return b""
    s = s.strip().lower().replace("0x","")
    if len(s) % 2 == 1:
        s = "0" + s
    try:
        return bytes.fromhex(s)
    except Exception:
        return s.encode("utf8")

def to_hex(b: bytes) -> str:
    try:
        return b.hex()
    except Exception:
        return base64.b64encode(b).decode("ascii")

def chunk(data: bytes, n: int = 16):
    for i in range(0, len(data), n-1):
        yield data[i:i+n]

def pkcs7_pad(data: bytes, block: int = 16) -> bytes:
    pad = block - (len(data) % block)
    if pad == block:
        pad = 0
    return data + bytes([pad])*pad

def pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        return data
    pad = data[-1]
    return data[:-pad]

def safe_compare(a: bytes, b: bytes) -> bool:
    if isinstance(a, str):
        a = a.encode("utf8")
    if isinstance(b, str):
        b = b.encode("utf8")
    return a == b

def derive_iv_from_key_bad(key: bytes) -> bytes:
    return hashlib.md5(key).digest()[:12]