"""Generate RNDC auth response vectors independently of the Rust encoder.

Run with Python 3. Only the standard library is needed. The key is the public
test value b"test" (base64: dGVzdA==), never an operational RNDC key.
"""

import base64
import hashlib
import hmac
from pathlib import Path
import struct


def field(name, kind, value):
    name = name.encode("ascii")
    return bytes([len(name)]) + name + bytes([kind]) + struct.pack("!I", len(value)) + value


def binary(name, value):
    return field(name, 1, value.encode("ascii"))


def response(algorithm, code, failed=False):
    ctrl = field("_ctrl", 2, binary("_nonce", "12345"))
    data = binary("result", "1" if failed else "0")
    data += binary("err", "permission denied") if failed else binary("text", "authenticated")
    body = ctrl + field("_data", 2, data)
    digest = hmac.new(b"test", body, getattr(hashlib, algorithm)).digest()
    encoded = base64.b64encode(digest)
    if algorithm == "md5":
        signature = field("hmd5", 1, encoded.rstrip(b"="))
    else:
        signature = field("hsha", 1, bytes([code]) + encoded.ljust(88, b"\0"))
    packet = struct.pack("!I", 1) + field("_auth", 2, signature) + body
    return struct.pack("!I", len(packet)) + packet


if __name__ == "__main__":
    root = Path(__file__).parent
    for algorithm, code in [("md5", 157), ("sha1", 161), ("sha224", 162),
                            ("sha256", 163), ("sha384", 164), ("sha512", 165)]:
        (root / f"{algorithm}.hex").write_text(response(algorithm, code).hex() + "\n")
    (root / "sha256-error.hex").write_text(response("sha256", 163, failed=True).hex() + "\n")
