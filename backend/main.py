import os
import sys

# Ensure project root is in path for clean imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from backend.config import get_settings
from backend.database.company_db import init_company_db
from backend.database.security_db import init_security_db
from backend.database.seed import seed_company_data
from backend.routers import query, dashboard, logs, portal
from backend.utils.logger import get_logger

settings = get_settings()
logger = get_logger("main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # ── Startup ──────────────────────────────────────────
    logger.info("Initializing databases...")
    os.makedirs("./data", exist_ok=True)
    await init_company_db()
    await init_security_db()
    await seed_company_data()
    logger.info("Databases ready.")
    logger.info(f"App running at http://localhost:{settings.app_port}")
    yield
    # ── Shutdown ─────────────────────────────────────────
    logger.info("Shutting down.")


app = FastAPI(
    title="SQL Threat Detection System",
    description="LLM-Based Intelligent SQL Injection & Insider Threat Detection",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS — allow frontend JS to call API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── API Routers ───────────────────────────────────────────
app.include_router(query.router)
app.include_router(dashboard.router)
app.include_router(logs.router)
app.include_router(portal.router)

# ── Static Frontend Files ─────────────────────────────────
frontend_path = os.path.join(os.path.dirname(__file__), "..", "frontend")
app.mount("/static", StaticFiles(directory=os.path.join(frontend_path, "static")), name="static")


@app.get("/", include_in_schema=False)
async def serve_index():
    return FileResponse(os.path.join(frontend_path, "index.html"))


@app.get("/dashboard", include_in_schema=False)
async def serve_dashboard():
    return FileResponse(os.path.join(frontend_path, "dashboard.html"))


@app.get("/logs", include_in_schema=False)
async def serve_logs():
    return FileResponse(os.path.join(frontend_path, "logs.html"))


@app.get("/portal", include_in_schema=False)
async def serve_portal():
    return FileResponse(os.path.join(frontend_path, "portal.html"))


@app.get("/attacker", include_in_schema=False)
async def serve_attacker():
    return FileResponse(os.path.join(frontend_path, "attacker.html"))


@app.get("/health")
async def health():
    return {"status": "ok", "model": settings.groq_model}