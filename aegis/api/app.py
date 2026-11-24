"""
FastAPI application factory for AegisGateway.
"""

from contextlib import asynccontextmanager
import httpx
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from aegis.core.config import AegisConfig, load_config
from aegis.core.audit import AuditLogger
from aegis.api.router import create_api_router


def create_app(config: AegisConfig | None = None) -> FastAPI:
    cfg = config or load_config()
    audit_logger = AuditLogger(cfg.audit_log_path)
    http_client = httpx.AsyncClient(timeout=60.0)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        yield
        await http_client.aclose()

    app = FastAPI(
        title="AegisGateway",
        description="Autonomous Enterprise Security Gateway & DLP Proxy for LLM Applications",
        version="1.0.0",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    router = create_api_router(cfg, audit_logger, http_client)
    app.include_router(router)

    return app
