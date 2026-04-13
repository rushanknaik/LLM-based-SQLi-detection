from fastapi import APIRouter, HTTPException
from backend.database.schemas import QueryRequest, QueryResponse, DetectionResult
from backend.detection.engine import HybridDetectionEngine
from backend.database.security_db import get_security_db
from backend.utils.logger import get_logger
import aiosqlite
from backend.config import get_settings
from datetime import date

router = APIRouter(prefix="/api/query", tags=["query"])
engine = HybridDetectionEngine()
logger = get_logger("query_router")
settings = get_settings()


async def update_stats(db: aiosqlite.Connection, label: str, risk_score: float, user_role: str):
    today = date.today().isoformat()

    # Upsert daily detection stats
    await db.execute("""
        INSERT INTO detection_stats (stat_date, total_queries, benign_count, sqli_count,
            insider_count, avg_risk_score, high_risk_count)
        VALUES (?, 1,
            CASE WHEN ? = 'benign' THEN 1 ELSE 0 END,
            CASE WHEN ? = 'sqli' THEN 1 ELSE 0 END,
            CASE WHEN ? = 'insider' THEN 1 ELSE 0 END,
            ?, CASE WHEN ? >= 0.8 THEN 1 ELSE 0 END)
        ON CONFLICT(stat_date) DO UPDATE SET
            total_queries = total_queries + 1,
            benign_count = benign_count + CASE WHEN ? = 'benign' THEN 1 ELSE 0 END,
            sqli_count = sqli_count + CASE WHEN ? = 'sqli' THEN 1 ELSE 0 END,
            insider_count = insider_count + CASE WHEN ? = 'insider' THEN 1 ELSE 0 END,
            avg_risk_score = (avg_risk_score * (total_queries - 1) + ?) / total_queries,
            high_risk_count = high_risk_count + CASE WHEN ? >= 0.8 THEN 1 ELSE 0 END
    """, (today, label, label, label, risk_score, risk_score,
          label, label, label, risk_score, risk_score))

    # Upsert role stats
    await db.execute("""
        INSERT INTO role_stats (user_role, stat_date, query_count, attack_count, avg_risk_score)
        VALUES (?, ?, 1,
            CASE WHEN ? != 'benign' THEN 1 ELSE 0 END, ?)
        ON CONFLICT(user_role, stat_date) DO UPDATE SET
            query_count = query_count + 1,
            attack_count = attack_count + CASE WHEN ? != 'benign' THEN 1 ELSE 0 END,
            avg_risk_score = (avg_risk_score * (query_count - 1) + ?) / query_count
    """, (user_role, today, label, risk_score, label, risk_score))


@router.post("/analyze", response_model=QueryResponse)
async def analyze_query(req: QueryRequest):
    logger.info(f"Analyzing query from role={req.user_role} session={req.session_id[:8]}...")

    try:
        result = await engine.analyze(req.query, req.user_role)
    except Exception as e:
        logger.error(f"Detection engine error: {e}")
        raise HTTPException(status_code=500, detail=f"Detection engine error: {str(e)}")

    log_id = None
    try:
        async with aiosqlite.connect(settings.security_db_path) as db:
            cursor = await db.execute("""
                INSERT INTO query_logs
                (session_id, user_role, query, query_normalized, label, attack_type,
                 risk_score, detection_source, explanation, role_multiplier, flagged)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                req.session_id, req.user_role, req.query,
                result.get("query_normalized", ""),
                result["label"], result["attack_type"],
                result["risk_score"], result["detection_source"],
                result["explanation"], result["role_multiplier"],
                1 if result["flagged"] else 0
            ))
            log_id = cursor.lastrowid
            await update_stats(db, result["label"], result["risk_score"], req.user_role)
            await db.commit()
    except Exception as e:
        logger.error(f"DB logging error: {e}")

    return QueryResponse(
        success=True,
        result=DetectionResult(
            label=result["label"],
            attack_type=result["attack_type"],
            risk_score=result["risk_score"],
            detection_source=result["detection_source"],
            explanation=result["explanation"],
            flagged=result["flagged"],
            role_multiplier=result["role_multiplier"],
        ),
        log_id=log_id
    )