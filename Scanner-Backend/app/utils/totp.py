import pyotp


def generate_totp_secret() -> str:
    return pyotp.random_base32()


def get_totp_uri(secret: str, email: str, issuer: str = "Domain Security Scanner") -> str:
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=email, issuer_name=issuer)


def verify_totp_code(secret: str, code: str) -> bool:
    normalized_code = ''.join(ch for ch in str(code).strip() if ch.isdigit())
    totp = pyotp.TOTP(secret)
    return totp.verify(normalized_code, valid_window=2)