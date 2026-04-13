import aiosqlite
import os
from backend.config import get_settings

settings = get_settings()

SECURITY_SCHEMA = """
CREATE TABLE IF NOT EXISTS query_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT,
    user_role TEXT NOT NULL,
    query TEXT NOT NULL,
    query_normalized TEXT,
    label TEXT NOT NULL,
    attack_type TEXT,
    risk_score REAL,
    detection_source TEXT,
    explanation TEXT,
    role_multiplier REAL DEFAULT 1.0,
    flagged INTEGER DEFAULT 0,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS detection_stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    stat_date DATE UNIQUE,
    total_queries INTEGER DEFAULT 0,
    benign_count INTEGER DEFAULT 0,
    sqli_count INTEGER DEFAULT 0,
    insider_count INTEGER DEFAULT 0,
    avg_risk_score REAL DEFAULT 0.0,
    high_risk_count INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS role_stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_role TEXT NOT NULL,
    stat_date DATE NOT NULL,
    query_count INTEGER DEFAULT 0,
    attack_count INTEGER DEFAULT 0,
    avg_risk_score REAL DEFAULT 0.0,
    UNIQUE(user_role, stat_date)
);
"""


async def init_security_db():
    os.makedirs(os.path.dirname(settings.security_db_path), exist_ok=True)
    async with aiosqlite.connect(settings.security_db_path) as db:
        await db.executescript(SECURITY_SCHEMA)
        await db.commit()


async def get_security_db():
    async with aiosqlite.connect(settings.security_db_path) as db:
        db.row_factory = aiosqlite.Row
        yield db