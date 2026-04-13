from fastapi import APIRouter
import aiosqlite
from backend.config import get_settings
from backend.utils.logger import get_logger

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])
settings = get_settings()
logger = get_logger("dashboard_router")


@router.get("/stats")
async def get_stats():
    """Overall aggregate counts for the stat cards."""
    async with aiosqlite.connect(settings.security_db_path) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("""
            SELECT
                COUNT(*) as total_queries,
                SUM(CASE WHEN label='benign' THEN 1 ELSE 0 END) as benign_count,
                SUM(CASE WHEN label='sqli' THEN 1 ELSE 0 END) as sqli_count,
                SUM(CASE WHEN label='insider' THEN 1 ELSE 0 END) as insider_count,
                SUM(CASE WHEN risk_score >= 0.8 THEN 1 ELSE 0 END) as high_risk_count,
                ROUND(AVG(risk_score), 3) as avg_risk_score
            FROM query_logs
        """) as cur:
            row = await cur.fetchone()
            return dict(row) if row else {
                "total_queries": 0, "benign_count": 0, "sqli_count": 0,
                "insider_count": 0, "high_risk_count": 0, "avg_risk_score": 0.0
            }


@router.get("/timeline")
async def get_timeline():
    """Hourly attack counts for the last 24 hours."""
    async with aiosqlite.connect(settings.security_db_path) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("""
            SELECT
                strftime('%H:00', timestamp) as hour,
                SUM(CASE WHEN label='sqli' THEN 1 ELSE 0 END) as sqli,
                SUM(CASE WHEN label='insider' THEN 1 ELSE 0 END) as insider,
                SUM(CASE WHEN label='benign' THEN 1 ELSE 0 END) as benign
            FROM query_logs
            WHERE timestamp >= datetime('now', '-24 hours')
            GROUP BY strftime('%H', timestamp)
            ORDER BY hour ASC
        """) as cur:
            rows = await cur.fetchall()
            return [dict(r) for r in rows]


@router.get("/threat-distribution")
async def get_threat_distribution():
    """Counts per label for the donut chart."""
    async with aiosqlite.connect(settings.security_db_path) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("""
            SELECT label, COUNT(*) as count
            FROM query_logs
            GROUP BY label
        """) as cur:
            rows = await cur.fetchall()
            return [dict(r) for r in rows]


@router.get("/heatmap")
async def get_heatmap():
    """Risk heatmap: role × attack_type counts."""
    async with aiosqlite.connect(settings.security_db_path) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("""
            SELECT user_role, attack_type, COUNT(*) as count
            FROM query_logs
            WHERE label != 'benign' AND attack_type != 'none'
            GROUP BY user_role, attack_type
            ORDER BY count DESC
        """) as cur:
            rows = await cur.fetchall()
            return [dict(r) for r in rows]


@router.get("/recent-flags")
async def get_recent_flags(limit: int = 10):
    """Most recent flagged queries for the alert feed."""
    async with aiosqlite.connect(settings.security_db_path) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("""
            SELECT id, timestamp, user_role, query, label, attack_type, risk_score, explanation
            FROM query_logs
            WHERE flagged = 1
            ORDER BY timestamp DESC
            LIMIT ?
        """, (limit,)) as cur:
            rows = await cur.fetchall()
            return [dict(r) for r in rows]


@router.get("/role-stats")
async def get_role_stats():
    """Per-role aggregate stats."""
    async with aiosqlite.connect(settings.security_db_path) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("""
            SELECT
                user_role,
                COUNT(*) as total,
                SUM(CASE WHEN label != 'benign' THEN 1 ELSE 0 END) as attacks,
                ROUND(AVG(risk_score), 3) as avg_risk
            FROM query_logs
            GROUP BY user_role
        """) as cur:
            rows = await cur.fetchall()
            return [dict(r) for r in rows]