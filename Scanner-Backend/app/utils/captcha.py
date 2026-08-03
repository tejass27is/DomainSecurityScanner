import os
import httpx
from fastapi import HTTPException

RECAPTCHA_VERIFY_URL = "https://www.google.com/recaptcha/api/siteverify"
RECAPTCHA_SCORE_THRESHOLD = 0.5


def is_captcha_enabled() -> bool:
    flag = os.getenv("RECAPTCHA_ENABLED", "true")
    return flag.strip().lower() in {"1", "true", "yes", "on"}


async def verify_captcha(token: str | None) -> None:
    """
    Verify a Google reCAPTCHA v3 token.

    Raises HTTPException(400) if:
    - The token is missing or empty.
    - Google reports success=False.
    - The score is below the threshold (0.5).
    """
    if not is_captcha_enabled():
        return

    if not token or not token.strip():
        raise HTTPException(status_code=400, detail="reCAPTCHA token is required.")

    secret_key = os.getenv("RECAPTCHA_SECRET_KEY")
    if not secret_key:
        raise HTTPException(
            status_code=500,
            detail="reCAPTCHA secret key not configured on server."
        )

    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                RECAPTCHA_VERIFY_URL,
                data={"secret": secret_key, "response": token},
                timeout=10.0,
            )
            response.raise_for_status()
            result = response.json()
        except httpx.HTTPError as exc:
            raise HTTPException(
                status_code=400,
                detail=f"reCAPTCHA verification request failed: {exc}"
            )

    if not result.get("success", False):
        error_codes = result.get("error-codes", [])
        raise HTTPException(
            status_code=400,
            detail=f"reCAPTCHA verification failed: {error_codes}"
        )

    score = result.get("score", 0.0)
    if score < RECAPTCHA_SCORE_THRESHOLD:
        raise HTTPException(
            status_code=400,
            detail=f"reCAPTCHA score too low ({score:.2f}). Possible bot activity detected."
        )
