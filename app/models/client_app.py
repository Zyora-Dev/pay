"""
Zyora Pay - Client App Model (multi-tenancy)
"""
from datetime import datetime
from typing import Optional
from sqlalchemy import String, DateTime, Boolean, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class ClientApp(Base):
    """A registered client application that uses Zyora Pay."""

    __tablename__ = "client_apps"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    api_key: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Where to POST webhook callbacks after payment verification
    callback_url: Mapped[str] = mapped_column(String(500), nullable=False)

    # Where to redirect the user's browser after payment
    success_redirect_url: Mapped[str] = mapped_column(String(500), nullable=False)
    failure_redirect_url: Mapped[str] = mapped_column(String(500), nullable=False)

    # Webhook secret for this app (HMAC key for signing callbacks)
    webhook_secret: Mapped[str] = mapped_column(String(200), nullable=False)

    # Optional metadata
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    def __repr__(self) -> str:
        return f"<ClientApp(id={self.id}, name={self.name})>"
