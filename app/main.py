"""
Zyora Pay - Centralized Payment Service
Deploy at pay.zyora.cloud
"""
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.core.database import init_db, close_db
from app.api.v1.endpoints import payments, admin


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: create tables if they don't exist
    await init_db()
    yield
    # Shutdown
    await close_db()


app = FastAPI(
    title="Zyora Pay",
    description="Centralized multi-tenant payment service for Zyora apps",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in settings.CORS_ORIGINS.split(",") if o.strip()],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept", "X-API-Key", "X-Admin-Secret"],
)

# Mount routers under /v1
app.include_router(payments.router, prefix="/v1")
app.include_router(admin.router, prefix="/v1")


@app.get("/")
async def root():
    return {
        "service": "Zyora Pay",
        "version": "1.0.0",
        "docs": "/docs",
    }


@app.get("/health")
async def health():
    return {"status": "ok"}
