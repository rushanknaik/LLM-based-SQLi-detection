import aiosqlite
import re
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional

from backend.detection.engine import HybridDetectionEngine
from backend.config import get_settings
from backend.utils.logger import get_logger

router = APIRouter(prefix="/api/portal", tags=["portal"])
engine = HybridDetectionEngine()
settings = get_settings()
logger = get_logger("portal_router")

# ── Request schemas ────────────────────────────────────

class PortalQueryRequest(BaseModel):
    query: str
    username: str
    user_role: str
    session_id: str


# ── Allowed tables and columns for safe execution ─────
# Only these are ever executed on company DB — prevents
# the demo itself from being exploited

ALLOWED_TABLES = {"users", "employees", "orders", "transactions"}

SAFE_READONLY_PATTERN = re.compile(
    r"^\s*(select)\s+", re.IGNORECASE
)


def is_safe_to_execute(query: str) -> bool:
    """Only allow SELECT statements on known tables for actual execution."""
    return bool(SAFE_READONLY_PATTERN.match(query.strip()))


async def log_to_security_db(session_id, username, user_role, query, result: dict):
    """Write detection result to security log."""
    try:
        async with aiosqlite.connect(settings.security_db_path) as db:
            await db.execute("""
                INSERT INTO query_logs
                (session_id, user_role, query, query_normalized, label, attack_type,
                 risk_score, detection_source, explanation, role_multiplier, flagged)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                session_id, user_role, query,
                result.get("query_normalized", ""),
                result["label"], result["attack_type"],
                result["risk_score"], result["detection_source"],
                result["explanation"], result["role_multiplier"],
                1 if result["flagged"] else 0
            ))
            await db.commit()
    except Exception as e:
        logger.error(f"Security log write failed: {e}")


# ── Endpoints ──────────────────────────────────────────

@router.get("/profile/{username}")
async def get_profile(username: str):
    """Fetch a single employee's non-sensitive profile."""
    async with aiosqlite.connect(settings.company_db_path) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("""
            SELECT u.id, u.username, u.email, u.role,
                   e.full_name, e.department, e.position, e.hire_date
            FROM users u
            LEFT JOIN employees e ON e.user_id = u.id
            WHERE u.username = ?
        """, (username,)) as cur:
            row = await cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="User not found")
            return dict(row)


@router.get("/directory")
async def get_directory(dept: Optional[str] = None):
    """Fetch employee directory — name, department, position only."""
    async with aiosqlite.connect(settings.company_db_path) as db:
        db.row_factory = aiosqlite.Row
        if dept and dept != "all":
            async with db.execute("""
                SELECT e.full_name, e.department, e.position, u.email
                FROM employees e
                JOIN users u ON u.id = e.user_id
                WHERE e.department = ?
                ORDER BY e.full_name
            """, (dept,)) as cur:
                rows = await cur.fetchall()
        else:
            async with db.execute("""
                SELECT e.full_name, e.department, e.position, u.email
                FROM employees e
                JOIN users u ON u.id = e.user_id
                ORDER BY e.department, e.full_name
            """) as cur:
                rows = await cur.fetchall()
        return [dict(r) for r in rows]


@router.get("/orders/{user_id}")
async def get_orders(user_id: int):
    """Fetch orders for a specific customer."""
    async with aiosqlite.connect(settings.company_db_path) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("""
            SELECT id, product_name, quantity, total_amount, status, order_date
            FROM orders
            WHERE customer_id = ?
            ORDER BY order_date DESC
        """, (user_id,)) as cur:
            rows = await cur.fetchall()
            return [dict(r) for r in rows]


@router.get("/departments")
async def get_departments():
    """List all unique departments."""
    async with aiosqlite.connect(settings.company_db_path) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT DISTINCT department FROM employees ORDER BY department"
        ) as cur:
            rows = await cur.fetchall()
            return [r["department"] for r in rows]


@router.post("/query")
async def run_portal_query(req: PortalQueryRequest):
    """
    Core interceptor endpoint.
    1. Run detection engine on the query
    2. Log result to security DB
    3. If benign → execute on company DB and return results
    4. If threat → block and return access denied
    """
    logger.info(f"Portal query from {req.username} ({req.user_role}): {req.query[:60]}...")

    # ── Step 1: Run detection ──────────────────────────
    detection = await engine.analyze(req.query, req.user_role)

    # ── Step 2: Log to security DB ─────────────────────
    await log_to_security_db(
        req.session_id, req.username, req.user_role,
        req.query, detection
    )

    # ── Step 3: Block if flagged ───────────────────────
    if detection["flagged"]:
        return {
            "blocked": True,
            "label": detection["label"],
            "attack_type": detection["attack_type"],
            "risk_score": detection["risk_score"],
            "explanation": detection["explanation"],
            "results": None,
            "columns": None,
            "message": f"⚠️ Query blocked by security system — {detection['attack_type'].replace('_', ' ').title()}"
        }

    # ── Step 4: Execute if safe ────────────────────────
    if not is_safe_to_execute(req.query):
        return {
            "blocked": True,
            "label": "blocked",
            "attack_type": "non_select_query",
            "risk_score": 0.5,
            "explanation": "Only SELECT queries are permitted in this portal.",
            "results": None,
            "columns": None,
            "message": "Only SELECT queries are allowed in the employee portal."
        }

    try:
        async with aiosqlite.connect(settings.company_db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(req.query) as cur:
                rows = await cur.fetchmany(100)  # Cap at 100 rows
                if not rows:
                    return {
                        "blocked": False,
                        "label": detection["label"],
                        "risk_score": detection["risk_score"],
                        "results": [],
                        "columns": [],
                        "row_count": 0,
                        "message": "Query returned no results."
                    }
                columns = list(rows[0].keys())
                results = [dict(r) for r in rows]
                return {
                    "blocked": False,
                    "label": detection["label"],
                    "risk_score": detection["risk_score"],
                    "results": results,
                    "columns": columns,
                    "row_count": len(results),
                    "message": f"Returned {len(results)} row(s)."
                }
    except Exception as e:
        return {
            "blocked": False,
            "label": "error",
            "attack_type": "query_error",
            "risk_score": 0.0,
            "explanation": str(e),
            "results": None,
            "columns": None,
            "message": f"Query error: {str(e)}"
        }