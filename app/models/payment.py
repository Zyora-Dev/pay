"""
Zyora Pay - Payment Model
"""
from datetime import datetime
from typing import Optional
from sqlalchemy import String, DateTime, Float, Integer, ForeignKey, Index, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class Payment(Base):
    """Payment transaction record."""

    __tablename__ = "payments"
    __table_args__ = (
        Index("ix_payments_app_status", "app_id", "status"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)

    # Multi-tenant: which client app initiated this payment
    app_id: Mapped[int] = mapped_column(Integer, ForeignKey("client_apps.id"), nullable=False, index=True)

    # Transaction
    txn_id: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    amount: Mapped[float] = mapped_column(Float, nullable=False)
    currency: Mapped[str] = mapped_column(String(10), default="INR", nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="pending", nullable=False)  # pending, success, failure

    # What the payment is for (passed by the client app)
    product_info: Mapped[str] = mapped_column(String(200), nullable=False)

    # Customer details (passed by the client app)
    customer_name: Mapped[str] = mapped_column(String(200), nullable=False)
    customer_email: Mapped[str] = mapped_column(String(200), nullable=False)
    customer_phone: Mapped[str] = mapped_column(String(20), default="", nullable=False)

    # Arbitrary metadata from the client app (JSON string)
    extra_data: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Gateway info
    gateway_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("payment_gateways.id", ondelete="SET NULL"), nullable=True
    )
    gateway_provider: Mapped[Optional[str]] = mapped_column(String(30), nullable=True)
    gateway_txn_id: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    payment_mode: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    app = relationship("ClientApp", backref="payments")

    def __repr__(self) -> str:
        return f"<Payment(id={self.id}, txn={self.txn_id}, status={self.status})>"
