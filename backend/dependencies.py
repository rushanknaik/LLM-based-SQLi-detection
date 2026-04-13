from backend.config import get_settings

settings = get_settings()


def get_risk_threshold() -> float:
    return settings.risk_flag_threshold