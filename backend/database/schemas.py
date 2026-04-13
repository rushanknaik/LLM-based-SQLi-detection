from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime


class QueryRequest(BaseModel):
    query: str = Field(..., min_length=1, max_length=2000)
    user_role: str = Field(..., pattern="^(employee|admin|outsider)$")
    session_id: str = Field(..., min_length=1)


class DetectionResult(BaseModel):
    label: str
    attack_type: str
    risk_score: float
    detection_source: str
    explanation: str
    flagged: bool
    role_multiplier: float


class QueryResponse(BaseModel):
    success: bool
    result: DetectionResult
    log_id: Optional[int] = None


class LogEntry(BaseModel):
    id: int
    session_id: Optional[str]
    user_role: str
    query: str
    label: str
    attack_type: Optional[str]
    risk_score: float
    detection_source: Optional[str]
    explanation: Optional[str]
    flagged: int
    timestamp: str


class DashboardStats(BaseModel):
    total_queries: int
    benign_count: int
    sqli_count: int
    insider_count: int
    high_risk_count: int
    avg_risk_score: float


class TimelinePoint(BaseModel):
    hour: str
    sqli: int
    insider: int
    benign: int


class HeatmapCell(BaseModel):
    role: str
    attack_type: str
    count: int


class RecentFlag(BaseModel):
    id: int
    timestamp: str
    user_role: str
    query: str
    label: str
    risk_score: float