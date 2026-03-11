"""
Zyora Pay - Payment Gateway Model
Identical to ZTunnel's gateway model — supports PayU, Cashfree, Custom.
"""
from datetime import datetime
from typing import Optional
from sqlalchemy import String, DateTime, Boolean, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class PaymentGateway(Base):
    """Configurable payment gateway (PayU, Cashfree, Custom)."""

    __tablename__ = "payment_gateways"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    provider: Mapped[str] = mapped_column(String(30), nullable=False)  # payu, cashfree, custom
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_default: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Credentials
    merchant_key: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    merchant_salt: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    api_key: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    api_secret: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Gateway-specific config
    base_url: Mapped[str] = mapped_column(String(500), default="", nullable=False)
    # success/failure URLs point back to pay.zyora.cloud/v1/payments/verify
    success_url: Mapped[str] = mapped_column(String(500), default="", nullable=False)
    failure_url: Mapped[str] = mapped_column(String(500), default="", nullable=False)
    mode: Mapped[str] = mapped_column(String(20), default="test", nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    def __repr__(self) -> str:
        return f"<PaymentGateway(id={self.id}, name={self.name}, provider={self.provider})>"
