"""
Zyora Pay - Security utilities
"""
import hmac
import hashlib
import secrets
from fastapi import Depends, HTTPException, Security
from fastapi.security import APIKeyHeader

from app.core.config import settings

# API key header for client apps
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

# Admin secret header
admin_secret_header = APIKeyHeader(name="X-Admin-Secret", auto_error=False)


def generate_api_key() -> str:
    """Generate a secure API key for client apps."""
    return f"zpay_{secrets.token_urlsafe(32)}"


def generate_webhook_signature(payload: str, secret: str) -> str:
    """Generate HMAC-SHA256 signature for webhook callbacks."""
    return hmac.new(
        secret.encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def verify_webhook_signature(payload: str, signature: str, secret: str) -> bool:
    """Verify HMAC-SHA256 webhook signature."""
    expected = generate_webhook_signature(payload, secret)
    return hmac.compare_digest(expected, signature)


async def require_admin(
    admin_secret: str = Security(admin_secret_header),
):
    """Dependency: require admin secret header."""
    if not admin_secret or not hmac.compare_digest(admin_secret, settings.ADMIN_SECRET):
        raise HTTPException(status_code=403, detail="Invalid admin credentials")
    return True
