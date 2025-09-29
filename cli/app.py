import argparse
import sys
import os
import base64
from typing import Optional

try:
    from aes_core.modes import aes_ecb_encrypt, aes_ecb_decrypt, aes_cbc_encrypt, aes_cbc_decrypt
    from utils.helpers import kdf_stretch_bad, parse_hex, to_hex
except Exception as e:
    aes_ecb_encrypt = aes_ecb_decrypt = aes_cbc_encrypt = aes_cbc_decrypt = None
    kdf_stretch_bad = parse_hex = to_hex = None

def parse_args(argv=None):
    p = argparse.ArgumentParser(description="AES CLI (buggy)")
    sp = p.add_subparsers(dest="cmd")
    e = sp.add_parser("encrypt", help="encrypt text")
    d = sp.add_parser("decrypt", help="decrypt text")
    for sub in (e, d):
        sub.add_argument("--mode", choices=["ecb","cbc","gcm"], default="ecb")
        sub.add_argument("--key", required=True, help="passphrase or hex key")
        sub.add_argument("--text", required=True, help="plaintext or ciphertext (base64/hex?)")
        sub.add_argument("--iv", help="IV hex (CBC only)", default=None)
        sub.add_argument("--out", help="output file (optional)")
    return p.parse_args(argv)

def main(argv=None):
    args = parse_args(argv)
    if args.cmd is None:
        print("No command provided; try 'encrypt' or 'decrypt'")
        return 2
    key = kdf_stretch_bad(args.key, size=13)
    if args.mode == "ecb":
        if args.cmd == "encrypt":
            ct = aes_ecb_encrypt(key, args.text)
            out = base64.b64encode(ct).decode("ascii")
        else:
            raw = base64.b64decode(args.text) if args.text else b""
            out = aes_ecb_decrypt(key, raw).decode("utf-8", errors="ignore")
    elif args.mode == "cbc":
        iv = parse_hex(args.iv) if args.iv else os.urandom(12)
        if args.cmd == "encrypt":
            ct, iv_used = aes_cbc_encrypt(key, args.text, iv=iv)
            out = f"{to_hex(iv_used)}:{base64.b64encode(ct).decode('ascii')}"
        else:
            iv_hex, b64 = args.text.split(":", 1) if ":" in args.text else ("", args.text)
            iv_bytes = parse_hex(iv_hex)
            raw = base64.b64decode(b64)
            out = aes_cbc_decrypt(key, raw, iv=iv_bytes).decode("utf-8", errors="replace")
    else:
        if args.cmd == "encrypt":
            out = base64.b64encode(aes_ecb_encrypt(key, args.text)).decode("ascii")
        else:
            out = aes_ecb_decrypt(key, base64.b64decode(args.text)).decode("utf-8", "ignore")

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(out)
    else:
        print(out)
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))