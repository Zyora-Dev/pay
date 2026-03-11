"""
Zyora Pay - Multi-Gateway Payment Service
Centralized payment processing for all Zyora apps.
Supports PayU, Cashfree (PG v3 API), and Custom gateways.
"""
import hashlib
import hmac
import base64
import json
import uuid
from datetime import datetime, timezone
from typing import Optional

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.payment import Payment
from app.models.payment_gateway import PaymentGateway
from app.models.client_app import ClientApp
from app.core.security import generate_webhook_signature


def generate_txn_id() -> str:
    return f"ZP{uuid.uuid4().hex[:12].upper()}"


async def get_default_gateway(db: AsyncSession) -> Optional[PaymentGateway]:
    result = await db.execute(
        select(PaymentGateway).where(
            PaymentGateway.is_active == True,
            PaymentGateway.is_default == True,
        )
    )
    return result.scalar_one_or_none()


async def get_app_by_api_key(db: AsyncSession, api_key: str) -> Optional[ClientApp]:
    result = await db.execute(
        select(ClientApp).where(
            ClientApp.api_key == api_key,
            ClientApp.is_active == True,
        )
    )
    return result.scalar_one_or_none()


# ── PayU ────────────────────────────────────────────────────────────────

def _payu_generate_hash(gateway: PaymentGateway, params: dict) -> str:
    hash_string = (
        f"{gateway.merchant_key}|{params['txnid']}|{params['amount']}|"
        f"{params['productinfo']}|{params['firstname']}|{params['email']}|"
        f"||||||||||{gateway.merchant_salt}"
    )
    return hashlib.sha512(hash_string.encode("utf-8")).hexdigest().lower()


def _payu_verify_hash(gateway: PaymentGateway, params: dict) -> bool:
    reverse_hash_string = (
        f"{gateway.merchant_salt}|{params.get('status', '')}|"
        f"||||||||||"
        f"{params.get('email', '')}|{params.get('firstname', '')}|"
        f"{params.get('productinfo', '')}|{params.get('amount', '')}|"
        f"{params.get('txnid', '')}|{gateway.merchant_key}"
    )
    expected = hashlib.sha512(reverse_hash_string.encode("utf-8")).hexdigest().lower()
    return expected == params.get("hash", "")


def _payu_build_params(
    gateway: PaymentGateway,
    txn_id: str,
    amount: str,
    product_info: str,
    customer_name: str,
    customer_email: str,
    customer_phone: str,
) -> dict:
    params = {
        "key": gateway.merchant_key,
        "txnid": txn_id,
        "amount": amount,
        "productinfo": product_info,
        "firstname": customer_name,
        "email": customer_email,
        "phone": customer_phone,
        "surl": gateway.success_url,
        "furl": gateway.failure_url,
    }
    params["hash"] = _payu_generate_hash(gateway, params)
    params["action"] = f"{gateway.base_url}/_payment"
    return params


# ── Cashfree PG v3 API ──────────────────────────────────────────────────

CASHFREE_API_VERSION = "2022-09-01"


async def _cashfree_create_order(
    gateway: PaymentGateway,
    txn_id: str,
    amount: str,
    product_info: str,
    customer_name: str,
    customer_email: str,
    customer_phone: str,
    customer_id: str,
) -> dict:
    url = f"{gateway.base_url.rstrip('/')}/pg/orders"

    payload = {
        "order_id": txn_id,
        "order_amount": float(amount),
        "order_currency": "INR",
        "order_note": product_info,
        "customer_details": {
            "customer_id": customer_id,
            "customer_name": customer_name,
            "customer_email": customer_email,
            "customer_phone": customer_phone or "9999999999",
        },
        "order_meta": {
            "return_url": gateway.success_url + "?order_id={order_id}",
            "notify_url": gateway.failure_url,
        },
    }

    headers = {
        "x-client-id": gateway.api_key,
        "x-client-secret": gateway.api_secret,
        "x-api-version": CASHFREE_API_VERSION,
        "Content-Type": "application/json",
    }

    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.post(url, json=payload, headers=headers)
        resp.raise_for_status()
        data = resp.json()

    return {
        "order_id": txn_id,
        "payment_session_id": data.get("payment_session_id", ""),
        "cf_order_id": data.get("cf_order_id"),
        "order_status": data.get("order_status", "ACTIVE"),
        "action": f"{gateway.base_url.rstrip('/')}/pg/orders/sessions/{data.get('payment_session_id', '')}",
        "environment": "sandbox" if "sandbox" in gateway.base_url else "production",
    }


def _cashfree_verify_webhook(gateway: PaymentGateway, signature: str, raw_body: str, timestamp: str) -> bool:
    if not gateway.api_secret or not signature:
        return False
    sign_data = timestamp + raw_body
    computed = hmac.new(
        gateway.api_secret.encode("utf-8"),
        sign_data.encode("utf-8"),
        hashlib.sha256,
    ).digest()
    computed_signature = base64.b64encode(computed).decode("utf-8")
    return hmac.compare_digest(computed_signature, signature)


async def _cashfree_fetch_order(gateway: PaymentGateway, order_id: str) -> dict:
    url = f"{gateway.base_url.rstrip('/')}/pg/orders/{order_id}"
    headers = {
        "x-client-id": gateway.api_key,
        "x-client-secret": gateway.api_secret,
        "x-api-version": CASHFREE_API_VERSION,
    }
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.get(url, headers=headers)
        resp.raise_for_status()
        return resp.json()


# ── Custom ──────────────────────────────────────────────────────────────

def _custom_build_params(
    gateway: PaymentGateway,
    txn_id: str,
    amount: str,
    product_info: str,
    customer_name: str,
    customer_email: str,
) -> dict:
    return {
        "api_key": gateway.api_key,
        "order_id": txn_id,
        "amount": amount,
        "currency": "INR",
        "description": product_info,
        "customer_name": customer_name,
        "customer_email": customer_email,
        "success_url": gateway.success_url,
        "failure_url": gateway.failure_url,
        "action": gateway.base_url,
    }


def _custom_verify(gateway: PaymentGateway, params: dict) -> bool:
    received_signature = params.get("signature", "")
    payload = params.get("payload", "")
    if not gateway.api_secret or not received_signature:
        return True
    computed = hmac.new(
        gateway.api_secret.encode("utf-8"),
        payload.encode("utf-8") if isinstance(payload, str) else str(payload).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(computed, received_signature)


# ── Gateway-agnostic interface ──────────────────────────────────────────

async def initiate_payment(
    db: AsyncSession,
    app: ClientApp,
    amount: float,
    product_info: str,
    customer_name: str,
    customer_email: str,
    customer_phone: str = "",
    customer_id: str = "",
    metadata: Optional[str] = None,
) -> dict:
    """Create a pending payment and return gateway-specific form params."""
    gateway = await get_default_gateway(db)
    if not gateway:
        raise ValueError("No active payment gateway configured.")

    txn_id = generate_txn_id()
    amount_str = f"{amount:.2f}"

    payment = Payment(
        app_id=app.id,
        txn_id=txn_id,
        amount=amount,
        product_info=product_info,
        customer_name=customer_name,
        customer_email=customer_email,
        customer_phone=customer_phone,
        extra_data=metadata,
        status="pending",
        gateway_id=gateway.id,
        gateway_provider=gateway.provider,
    )
    db.add(payment)
    await db.commit()

    if gateway.provider == "payu":
        params = _payu_build_params(
            gateway, txn_id, amount_str, product_info,
            customer_name, customer_email, customer_phone,
        )
    elif gateway.provider == "cashfree":
        params = await _cashfree_create_order(
            gateway, txn_id, amount_str, product_info,
            customer_name, customer_email, customer_phone,
            customer_id or f"app_{app.id}_cust",
        )
    elif gateway.provider == "custom":
        params = _custom_build_params(
            gateway, txn_id, amount_str, product_info,
            customer_name, customer_email,
        )
    else:
        raise ValueError(f"Unsupported gateway provider: {gateway.provider}")

    params["provider"] = gateway.provider
    params["gateway_name"] = gateway.name
    params["txn_id"] = txn_id
    return params


async def verify_payment(
    db: AsyncSession,
    callback_data: dict,
    raw_body: str = "",
    headers: Optional[dict] = None,
) -> Optional[Payment]:
    """Verify gateway callback and update payment status."""
    txn_id = (
        callback_data.get("txnid")
        or callback_data.get("order_id")
        or callback_data.get("orderId", "")
    )

    result = await db.execute(
        select(Payment).where(Payment.txn_id == txn_id)
    )
    payment = result.scalar_one_or_none()
    if not payment:
        return None

    if payment.status in ("success", "failure"):
        return payment

    gateway = None
    if payment.gateway_id:
        gw_result = await db.execute(
            select(PaymentGateway).where(PaymentGateway.id == payment.gateway_id)
        )
        gateway = gw_result.scalar_one_or_none()

    provider = payment.gateway_provider or "payu"
    is_success = False
    gateway_ref = ""
    mode = ""

    if provider == "payu" and gateway:
        if not _payu_verify_hash(gateway, callback_data):
            payment.status = "failure"
            await db.commit()
            return payment
        is_success = callback_data.get("status", "").lower() == "success"
        gateway_ref = callback_data.get("mihpayid", "")
        mode = callback_data.get("mode", "")

    elif provider == "cashfree" and gateway:
        hdrs = headers or {}
        webhook_sig = hdrs.get("x-webhook-signature", "")
        webhook_ts = hdrs.get("x-webhook-timestamp", "")

        if webhook_sig and raw_body:
            if not _cashfree_verify_webhook(gateway, webhook_sig, raw_body, webhook_ts):
                payment.status = "failure"
                await db.commit()
                return payment
            body_data = json.loads(raw_body) if isinstance(raw_body, str) else raw_body
            event_data = body_data.get("data", {})
            order_data = event_data.get("order", {})
            payment_data = event_data.get("payment", {})
            is_success = order_data.get("order_status") == "PAID"
            gateway_ref = str(payment_data.get("cf_payment_id", ""))
            mode = payment_data.get("payment_group", "")
        else:
            try:
                order_data = await _cashfree_fetch_order(gateway, txn_id)
                is_success = order_data.get("order_status") == "PAID"
                gateway_ref = str(order_data.get("cf_order_id", ""))
            except Exception:
                payment.status = "failure"
                await db.commit()
                return payment

    elif provider == "custom" and gateway:
        if not _custom_verify(gateway, callback_data):
            payment.status = "failure"
            await db.commit()
            return payment
        status_raw = callback_data.get("status", "")
        is_success = status_raw.lower() == "success"
        gateway_ref = callback_data.get("reference_id", "")
        mode = callback_data.get("payment_mode", "")
    else:
        is_success = callback_data.get("status", "").lower() == "success"

    if is_success:
        payment.status = "success"
        payment.gateway_txn_id = gateway_ref
        payment.payment_mode = mode
        payment.completed_at = datetime.now(timezone.utc)
    else:
        payment.status = "failure"
        payment.completed_at = datetime.now(timezone.utc)

    await db.commit()
    return payment


async def send_webhook_callback(app: ClientApp, payment: Payment) -> bool:
    """POST payment result to the client app's callback_url."""
    payload = json.dumps({
        "txn_id": payment.txn_id,
        "status": payment.status,
        "amount": payment.amount,
        "currency": payment.currency,
        "product_info": payment.product_info,
        "customer_email": payment.customer_email,
        "gateway_provider": payment.gateway_provider,
        "gateway_txn_id": payment.gateway_txn_id,
        "payment_mode": payment.payment_mode,
        "extra_data": payment.extra_data,
        "completed_at": payment.completed_at.isoformat() if payment.completed_at else None,
    }, default=str)

    signature = generate_webhook_signature(payload, app.webhook_secret)

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(
                app.callback_url,
                content=payload,
                headers={
                    "Content-Type": "application/json",
                    "X-Zyora-Pay-Signature": signature,
                    "X-Zyora-Pay-Txn-Id": payment.txn_id,
                },
            )
            return resp.status_code < 400
    except Exception:
        return False


async def get_payment_by_txn(db: AsyncSession, txn_id: str) -> Optional[Payment]:
    result = await db.execute(
        select(Payment).where(Payment.txn_id == txn_id)
    )
    return result.scalar_one_or_none()
