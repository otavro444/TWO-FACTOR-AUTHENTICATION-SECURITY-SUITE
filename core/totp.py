"""
2FA Shield — Core TOTP Library
Standalone RFC 6238 implementation. No external deps.
"""
import hmac, hashlib, struct, time, base64, secrets


def base32_decode(secret: str) -> bytes:
    secret = secret.upper().replace(" ", "")
    padding = (8 - len(secret) % 8) % 8
    return base64.b32decode(secret + "=" * padding)


def hotp(secret: str, counter: int, digits: int = 6) -> str:
    key  = base32_decode(secret)
    msg  = struct.pack(">Q", counter)
    mac  = hmac.new(key, msg, hashlib.sha1).digest()
    off  = mac[-1] & 0x0F
    code = struct.unpack(">I", mac[off:off+4])[0] & 0x7FFFFFFF
    return str(code % (10 ** digits)).zfill(digits)


def totp(secret: str, digits: int = 6, period: int = 30) -> str:
    counter = int(time.time()) // period
    return hotp(secret, counter, digits)


def verify_totp(secret: str, code: str, window: int = 1) -> bool:
    t = int(time.time()) // 30
    return any(hotp(secret, t + i) == code.replace(" ", "")
               for i in range(-window, window + 1))


def random_secret(length: int = 20) -> str:
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def provisioning_uri(account: str, secret: str, issuer: str = "2FAShield") -> str:
    from urllib.parse import quote
    return (f"otpauth://totp/{quote(issuer)}:{quote(account)}"
            f"?secret={secret}&issuer={quote(issuer)}"
            f"&algorithm=SHA1&digits=6&period=30")


if __name__ == "__main__":
    secret = random_secret()
    print(f"Secret : {secret}")
    print(f"Code   : {totp(secret)}")
    print(f"URI    : {provisioning_uri('test @example.com', secret)}")
