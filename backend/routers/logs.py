from fastapi import APIRouter, Query
import aiosqlite
from backend.config import get_settings

router = APIRouter(prefix="/api/logs", tags=["logs"])
settings = get_settings()


@router.get("")
async def get_logs(
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=20, ge=1, le=100),
    role: str = Query(default="all"),
    label: str = Query(default="all"),
    flagged_only: bool = Query(default=False),
):
    offset = (page - 1) * per_page
    filters = []
    params = []

    if role != "all":
        filters.append("user_role = ?")
        params.append(role)
    if label != "all":
        filters.append("label = ?")
        params.append(label)
    if flagged_only:
        filters.append("flagged = 1")

    where = ("WHERE " + " AND ".join(filters)) if filters else ""

    async with aiosqlite.connect(settings.security_db_path) as db:
        db.row_factory = aiosqlite.Row

        async with db.execute(
            f"SELECT COUNT(*) FROM query_logs {where}", params
        ) as cur:
            total = (await cur.fetchone())[0]

        async with db.execute(
            f"""SELECT id, session_id, user_role, query, label, attack_type,
                       risk_score, detection_source, explanation, flagged, timestamp
                FROM query_logs {where}
                ORDER BY timestamp DESC
                LIMIT ? OFFSET ?""",
            params + [per_page, offset]
        ) as cur:
            rows = await cur.fetchall()

        return {
            "total": total,
            "page": page,
            "per_page": per_page,
            "total_pages": (total + per_page - 1) // per_page,
            "logs": [dict(r) for r in rows]
        }


@router.get("/{log_id}")
async def get_log(log_id: int):
    async with aiosqlite.connect(settings.security_db_path) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM query_logs WHERE id = ?", (log_id,)
        ) as cur:
            row = await cur.fetchone()
            if not row:
                from fastapi import HTTPException
                raise HTTPException(status_code=404, detail="Log entry not found")
            return dict(row)