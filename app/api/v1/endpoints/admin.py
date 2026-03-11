"""
Zyora Pay - Admin Endpoints
Manage client apps, payment gateways, and view all transactions.
Protected by X-Admin-Secret header.
"""
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select, text, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import require_admin, generate_api_key
from app.models.client_app import ClientApp
from app.models.payment import Payment
from app.models.payment_gateway import PaymentGateway

router = APIRouter(prefix="/admin", tags=["Admin"], dependencies=[Depends(require_admin)])


# ── Schemas ──────────────────────────────────────────────────────────────

class CreateAppRequest(BaseModel):
    name: str
    callback_url: str
    success_redirect_url: str
    failure_redirect_url: str
    description: Optional[str] = None


class UpdateAppRequest(BaseModel):
    name: Optional[str] = None
    callback_url: Optional[str] = None
    success_redirect_url: Optional[str] = None
    failure_redirect_url: Optional[str] = None
    description: Optional[str] = None
    is_active: Optional[bool] = None


class CreateGatewayRequest(BaseModel):
    name: str
    provider: str  # payu, cashfree, custom
    is_active: bool = True
    is_default: bool = False
    merchant_key: Optional[str] = None
    merchant_salt: Optional[str] = None
    api_key: Optional[str] = None
    api_secret: Optional[str] = None
    base_url: str = ""
    success_url: str = ""
    failure_url: str = ""
    mode: str = "test"


class UpdateGatewayRequest(BaseModel):
    name: Optional[str] = None
    is_active: Optional[bool] = None
    is_default: Optional[bool] = None
    merchant_key: Optional[str] = None
    merchant_salt: Optional[str] = None
    api_key: Optional[str] = None
    api_secret: Optional[str] = None
    base_url: Optional[str] = None
    success_url: Optional[str] = None
    failure_url: Optional[str] = None
    mode: Optional[str] = None


# ── Helpers ──────────────────────────────────────────────────────────────

def _mask_secret(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    if len(value) <= 4:
        return "****"
    return value[:4] + "*" * (len(value) - 4)


def _serialize_app(app: ClientApp, show_secrets: bool = False) -> dict:
    return {
        "id": app.id,
        "name": app.name,
        "api_key": app.api_key if show_secrets else _mask_secret(app.api_key),
        "webhook_secret": app.webhook_secret if show_secrets else _mask_secret(app.webhook_secret),
        "is_active": app.is_active,
        "callback_url": app.callback_url,
        "success_redirect_url": app.success_redirect_url,
        "failure_redirect_url": app.failure_redirect_url,
        "description": app.description,
        "created_at": app.created_at.isoformat() if app.created_at else None,
        "updated_at": app.updated_at.isoformat() if app.updated_at else None,
    }


def _serialize_gateway(gw: PaymentGateway) -> dict:
    return {
        "id": gw.id,
        "name": gw.name,
        "provider": gw.provider,
        "is_active": gw.is_active,
        "is_default": gw.is_default,
        "merchant_key": _mask_secret(gw.merchant_key),
        "api_key": _mask_secret(gw.api_key),
        "base_url": gw.base_url,
        "success_url": gw.success_url,
        "failure_url": gw.failure_url,
        "mode": gw.mode,
        "created_at": gw.created_at.isoformat() if gw.created_at else None,
        "updated_at": gw.updated_at.isoformat() if gw.updated_at else None,
    }


# ══════════════════════════════════════════════════════════════════════════
# CLIENT APPS CRUD
# ══════════════════════════════════════════════════════════════════════════

@router.get("/apps")
async def list_apps(db: AsyncSession = Depends(get_db)):
    """List all registered client apps."""
    result = await db.execute(
        select(ClientApp).order_by(ClientApp.created_at.desc())
    )
    apps = result.scalars().all()
    return {"apps": [_serialize_app(a) for a in apps], "total": len(apps)}


@router.post("/apps", status_code=201)
async def create_app(body: CreateAppRequest, db: AsyncSession = Depends(get_db)):
    """Register a new client app. Returns API key and webhook secret."""
    import secrets

    api_key = generate_api_key()
    webhook_secret = f"whsec_{secrets.token_urlsafe(32)}"

    app = ClientApp(
        name=body.name,
        api_key=api_key,
        webhook_secret=webhook_secret,
        callback_url=body.callback_url,
        success_redirect_url=body.success_redirect_url,
        failure_redirect_url=body.failure_redirect_url,
        description=body.description,
    )
    db.add(app)
    await db.commit()
    await db.refresh(app)

    # Show secrets only on creation
    return _serialize_app(app, show_secrets=True)


@router.put("/apps/{app_id}")
async def update_app(app_id: int, body: UpdateAppRequest, db: AsyncSession = Depends(get_db)):
    """Update a client app."""
    result = await db.execute(select(ClientApp).where(ClientApp.id == app_id))
    app = result.scalar_one_or_none()
    if not app:
        raise HTTPException(status_code=404, detail="App not found")

    for field, value in body.model_dump(exclude_unset=True).items():
        setattr(app, field, value)

    await db.commit()
    await db.refresh(app)
    return _serialize_app(app)


@router.patch("/apps/{app_id}/rotate-key")
async def rotate_app_key(app_id: int, db: AsyncSession = Depends(get_db)):
    """Rotate API key for a client app. Returns the new key."""
    result = await db.execute(select(ClientApp).where(ClientApp.id == app_id))
    app = result.scalar_one_or_none()
    if not app:
        raise HTTPException(status_code=404, detail="App not found")

    app.api_key = generate_api_key()
    await db.commit()
    return {"id": app.id, "api_key": app.api_key}


@router.patch("/apps/{app_id}/rotate-webhook-secret")
async def rotate_webhook_secret(app_id: int, db: AsyncSession = Depends(get_db)):
    """Rotate webhook secret for a client app."""
    import secrets
    result = await db.execute(select(ClientApp).where(ClientApp.id == app_id))
    app = result.scalar_one_or_none()
    if not app:
        raise HTTPException(status_code=404, detail="App not found")

    app.webhook_secret = f"whsec_{secrets.token_urlsafe(32)}"
    await db.commit()
    return {"id": app.id, "webhook_secret": app.webhook_secret}


@router.delete("/apps/{app_id}")
async def delete_app(app_id: int, db: AsyncSession = Depends(get_db)):
    """Delete a client app."""
    result = await db.execute(select(ClientApp).where(ClientApp.id == app_id))
    app = result.scalar_one_or_none()
    if not app:
        raise HTTPException(status_code=404, detail="App not found")
    await db.delete(app)
    await db.commit()
    return {"deleted": True}


# ══════════════════════════════════════════════════════════════════════════
# PAYMENT GATEWAYS CRUD (same pattern as ZTunnel admin)
# ══════════════════════════════════════════════════════════════════════════

@router.get("/payment-gateways")
async def list_gateways(db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(PaymentGateway).order_by(PaymentGateway.created_at.desc())
    )
    gateways = result.scalars().all()
    return {"gateways": [_serialize_gateway(gw) for gw in gateways], "total": len(gateways)}


@router.post("/payment-gateways", status_code=201)
async def create_gateway(body: CreateGatewayRequest, db: AsyncSession = Depends(get_db)):
    if body.provider not in ("payu", "cashfree", "custom"):
        raise HTTPException(status_code=400, detail="Provider must be payu, cashfree, or custom")

    if body.is_default:
        await db.execute(
            text("UPDATE payment_gateways SET is_default = false WHERE is_default = true")
        )

    gw = PaymentGateway(
        name=body.name,
        provider=body.provider,
        is_active=body.is_active,
        is_default=body.is_default,
        merchant_key=body.merchant_key,
        merchant_salt=body.merchant_salt,
        api_key=body.api_key,
        api_secret=body.api_secret,
        base_url=body.base_url,
        success_url=body.success_url,
        failure_url=body.failure_url,
        mode=body.mode,
    )
    db.add(gw)
    await db.commit()
    await db.refresh(gw)
    return _serialize_gateway(gw)


@router.put("/payment-gateways/{gateway_id}")
async def update_gateway(
    gateway_id: int, body: UpdateGatewayRequest, db: AsyncSession = Depends(get_db)
):
    result = await db.execute(
        select(PaymentGateway).where(PaymentGateway.id == gateway_id)
    )
    gw = result.scalar_one_or_none()
    if not gw:
        raise HTTPException(status_code=404, detail="Gateway not found")

    if body.is_default:
        await db.execute(
            text("UPDATE payment_gateways SET is_default = false WHERE is_default = true")
        )

    for field, value in body.model_dump(exclude_unset=True).items():
        setattr(gw, field, value)

    await db.commit()
    await db.refresh(gw)
    return _serialize_gateway(gw)


@router.patch("/payment-gateways/{gateway_id}/toggle")
async def toggle_gateway(gateway_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(PaymentGateway).where(PaymentGateway.id == gateway_id)
    )
    gw = result.scalar_one_or_none()
    if not gw:
        raise HTTPException(status_code=404, detail="Gateway not found")
    gw.is_active = not gw.is_active
    await db.commit()
    return {"id": gw.id, "is_active": gw.is_active}


@router.patch("/payment-gateways/{gateway_id}/set-default")
async def set_default_gateway(gateway_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(PaymentGateway).where(PaymentGateway.id == gateway_id)
    )
    gw = result.scalar_one_or_none()
    if not gw:
        raise HTTPException(status_code=404, detail="Gateway not found")
    if not gw.is_active:
        raise HTTPException(status_code=400, detail="Cannot set inactive gateway as default")

    await db.execute(
        text("UPDATE payment_gateways SET is_default = false WHERE is_default = true")
    )
    gw.is_default = True
    await db.commit()
    return {"id": gw.id, "is_default": True}


@router.delete("/payment-gateways/{gateway_id}")
async def delete_gateway(gateway_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(PaymentGateway).where(PaymentGateway.id == gateway_id)
    )
    gw = result.scalar_one_or_none()
    if not gw:
        raise HTTPException(status_code=404, detail="Gateway not found")
    if gw.is_default:
        raise HTTPException(status_code=400, detail="Cannot delete the default gateway")
    await db.delete(gw)
    await db.commit()
    return {"deleted": True}


# ══════════════════════════════════════════════════════════════════════════
# TRANSACTIONS (read-only view of all payments across all apps)
# ══════════════════════════════════════════════════════════════════════════

@router.get("/transactions")
async def list_transactions(
    app_id: Optional[int] = None,
    status: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
):
    """List all transactions with optional filters."""
    query = select(Payment)
    count_query = select(func.count(Payment.id))

    if app_id:
        query = query.where(Payment.app_id == app_id)
        count_query = count_query.where(Payment.app_id == app_id)
    if status:
        query = query.where(Payment.status == status)
        count_query = count_query.where(Payment.status == status)

    total_result = await db.execute(count_query)
    total = total_result.scalar()

    query = query.order_by(Payment.created_at.desc()).limit(min(limit, 200)).offset(offset)
    result = await db.execute(query)
    payments = result.scalars().all()

    return {
        "transactions": [
            {
                "id": p.id,
                "app_id": p.app_id,
                "txn_id": p.txn_id,
                "amount": p.amount,
                "currency": p.currency,
                "status": p.status,
                "product_info": p.product_info,
                "customer_name": p.customer_name,
                "customer_email": p.customer_email,
                "gateway_provider": p.gateway_provider,
                "gateway_txn_id": p.gateway_txn_id,
                "payment_mode": p.payment_mode,
                "extra_data": p.extra_data,
                "created_at": p.created_at.isoformat() if p.created_at else None,
                "completed_at": p.completed_at.isoformat() if p.completed_at else None,
            }
            for p in payments
        ],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/dashboard")
async def admin_dashboard(db: AsyncSession = Depends(get_db)):
    """Quick stats for the admin dashboard."""
    # Total apps
    apps_result = await db.execute(select(func.count(ClientApp.id)))
    total_apps = apps_result.scalar()

    # Total transactions by status
    for s in ("pending", "success", "failure"):
        count_result = await db.execute(
            select(func.count(Payment.id)).where(Payment.status == s)
        )
        locals()[f"total_{s}"] = count_result.scalar()

    # Total revenue
    revenue_result = await db.execute(
        select(func.coalesce(func.sum(Payment.amount), 0)).where(Payment.status == "success")
    )
    total_revenue = revenue_result.scalar()

    # Active gateways
    gw_result = await db.execute(
        select(func.count(PaymentGateway.id)).where(PaymentGateway.is_active == True)
    )
    active_gateways = gw_result.scalar()

    return {
        "total_apps": total_apps,
        "active_gateways": active_gateways,
        "total_transactions": {
            "pending": locals().get("total_pending", 0),
            "success": locals().get("total_success", 0),
            "failure": locals().get("total_failure", 0),
        },
        "total_revenue_inr": float(total_revenue),
    }
