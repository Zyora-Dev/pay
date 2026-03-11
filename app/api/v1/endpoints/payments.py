"""
Zyora Pay - Payment Endpoints
Client apps call these to initiate and verify payments.
"""
import json
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Security
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import api_key_header
from app.models.client_app import ClientApp
from app.services import payment as payment_service

router = APIRouter(prefix="/payments", tags=["Payments"])


# ── Schemas ──────────────────────────────────────────────────────────────

class InitiatePaymentRequest(BaseModel):
    amount: float
    product_info: str
    customer_name: str
    customer_email: str
    customer_phone: str = ""
    customer_id: str = ""
    extra_data: Optional[str] = None  # JSON string — passed back in webhook


class PaymentStatusResponse(BaseModel):
    txn_id: str
    status: str
    amount: float
    currency: str
    product_info: str
    gateway_provider: Optional[str]
    gateway_txn_id: Optional[str]
    payment_mode: Optional[str]
    created_at: str
    completed_at: Optional[str]


# ── Dependencies ─────────────────────────────────────────────────────────

async def get_client_app(
    api_key: str = Security(api_key_header),
    db: AsyncSession = Depends(get_db),
) -> ClientApp:
    """Authenticate client app via X-API-Key header."""
    if not api_key:
        raise HTTPException(status_code=401, detail="Missing X-API-Key header")
    app = await payment_service.get_app_by_api_key(db, api_key)
    if not app:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return app


# ── Endpoints ────────────────────────────────────────────────────────────

@router.post("/initiate")
async def initiate_payment(
    body: InitiatePaymentRequest,
    app: ClientApp = Depends(get_client_app),
    db: AsyncSession = Depends(get_db),
):
    """Initiate a payment. Returns gateway-specific params for the frontend form."""
    if body.amount < 1:
        raise HTTPException(status_code=400, detail="Minimum amount is ₹1")
    if body.amount > 1000000:
        raise HTTPException(status_code=400, detail="Maximum amount is ₹10,00,000")

    try:
        params = await payment_service.initiate_payment(
            db=db,
            app=app,
            amount=body.amount,
            product_info=body.product_info,
            customer_name=body.customer_name,
            customer_email=body.customer_email,
            customer_phone=body.customer_phone,
            customer_id=body.customer_id,
            metadata=body.extra_data,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    return {"payment_params": params}


@router.post("/verify")
async def verify_payment_post(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Gateway callback (POST) — PayU/Custom redirect here after payment.
    Verifies hash, updates payment, webhooks the client app, redirects user's browser.
    """
    raw_body = (await request.body()).decode("utf-8")
    hdrs = {k.lower(): v for k, v in request.headers.items()}

    content_type = hdrs.get("content-type", "")
    if "application/x-www-form-urlencoded" in content_type or "multipart/form-data" in content_type:
        form_data = await request.form()
        callback_data = dict(form_data)
    else:
        try:
            callback_data = await request.json()
        except Exception:
            callback_data = {}

    payment = await payment_service.verify_payment(
        db, callback_data, raw_body=raw_body, headers=hdrs
    )

    if not payment:
        return RedirectResponse(url="https://zyora.cloud?payment=error", status_code=303)

    # Load the client app to get redirect URLs and send webhook
    app_result = await db.execute(
        select(ClientApp).where(ClientApp.id == payment.app_id)
    )
    app = app_result.scalar_one_or_none()

    if app:
        # Send webhook callback to the client app
        await payment_service.send_webhook_callback(app, payment)

        # Redirect user's browser back to the client app
        if payment.status == "success":
            redirect_url = f"{app.success_redirect_url}?txn_id={payment.txn_id}&status=success&amount={payment.amount}"
        else:
            redirect_url = f"{app.failure_redirect_url}?txn_id={payment.txn_id}&status=failure"
        return RedirectResponse(url=redirect_url, status_code=303)

    return RedirectResponse(url="https://zyora.cloud?payment=error", status_code=303)


@router.get("/verify")
async def verify_payment_get(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Gateway callback (GET) — Cashfree return URL redirect."""
    callback_data = dict(request.query_params)

    payment = await payment_service.verify_payment(db, callback_data)

    if not payment:
        return RedirectResponse(url="https://zyora.cloud?payment=error", status_code=303)

    app_result = await db.execute(
        select(ClientApp).where(ClientApp.id == payment.app_id)
    )
    app = app_result.scalar_one_or_none()

    if app:
        await payment_service.send_webhook_callback(app, payment)

        if payment.status == "success":
            redirect_url = f"{app.success_redirect_url}?txn_id={payment.txn_id}&status=success&amount={payment.amount}"
        else:
            redirect_url = f"{app.failure_redirect_url}?txn_id={payment.txn_id}&status=failure"
        return RedirectResponse(url=redirect_url, status_code=303)

    return RedirectResponse(url="https://zyora.cloud?payment=error", status_code=303)


@router.post("/cashfree-webhook")
async def cashfree_webhook(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Cashfree server-to-server webhook."""
    raw_body = (await request.body()).decode("utf-8")
    hdrs = {k.lower(): v for k, v in request.headers.items()}

    try:
        callback_data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid body")

    event_data = callback_data.get("data", {})
    order_data = event_data.get("order", {})
    if order_data.get("order_id"):
        callback_data["order_id"] = order_data["order_id"]

    payment = await payment_service.verify_payment(
        db, callback_data, raw_body=raw_body, headers=hdrs
    )

    if payment:
        # Send webhook to client app
        app_result = await db.execute(
            select(ClientApp).where(ClientApp.id == payment.app_id)
        )
        app = app_result.scalar_one_or_none()
        if app:
            await payment_service.send_webhook_callback(app, payment)
        return {"status": "ok"}

    raise HTTPException(status_code=404, detail="Payment not found")


@router.get("/status/{txn_id}")
async def get_payment_status(
    txn_id: str,
    app: ClientApp = Depends(get_client_app),
    db: AsyncSession = Depends(get_db),
):
    """Check the status of a payment by txn_id."""
    payment = await payment_service.get_payment_by_txn(db, txn_id)
    if not payment or payment.app_id != app.id:
        raise HTTPException(status_code=404, detail="Payment not found")

    return {
        "txn_id": payment.txn_id,
        "status": payment.status,
        "amount": payment.amount,
        "currency": payment.currency,
        "product_info": payment.product_info,
        "gateway_provider": payment.gateway_provider,
        "gateway_txn_id": payment.gateway_txn_id,
        "payment_mode": payment.payment_mode,
        "extra_data": payment.extra_data,
        "created_at": payment.created_at.isoformat() if payment.created_at else None,
        "completed_at": payment.completed_at.isoformat() if payment.completed_at else None,
    }
