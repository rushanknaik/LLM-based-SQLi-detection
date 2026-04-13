import re
from backend.detection.rule_engine import run_rule_engine
from backend.detection.llm_classifier import classify_with_llm
from backend.detection.risk_scorer import aggregate_risk
from backend.config import get_settings

settings = get_settings()

# Roles that have elevated trust — if rule engine finds nothing,
# we do NOT let the LLM escalate to insider for these roles
TRUSTED_ROLES = {"admin"}


def normalize_query(query: str) -> str:
    q = query.strip()
    q = re.sub(r'\s+', ' ', q)
    q = re.sub(r'\\n|\\t|\\r', ' ', q)
    return q


class HybridDetectionEngine:

    async def analyze(self, query: str, user_role: str) -> dict:
        normalized = normalize_query(query)

        # Layer 1: Role-aware rule engine
        rule_match = run_rule_engine(normalized, user_role)

        llm_result = None

        if rule_match is None:
            # Rule engine found nothing (either truly benign, or rule was
            # intentionally skipped because of role exemption)
            if user_role in TRUSTED_ROLES:
                # Admin + no rule fired = trust it as benign.
                # Do NOT call LLM — it will hallucinate insider threat.
                pass
            else:
                # Non-admin with no rule match — ask LLM
                llm_result = await classify_with_llm(normalized, user_role)

                # Safety check: if LLM says insider but role is admin, override
                if llm_result and llm_result["label"] == "insider" and user_role in TRUSTED_ROLES:
                    llm_result["label"] = "benign"
                    llm_result["risk_score"] = 0.1
                    llm_result["reason"] = "Admin role — legitimate elevated access"

        elif rule_match.confidence < 0.90:
            # Low-confidence rule match — cross-check with LLM
            llm_result = await classify_with_llm(normalized, user_role)

            # Same admin safety check
            if llm_result and llm_result["label"] == "insider" and user_role in TRUSTED_ROLES:
                llm_result["label"] = "benign"
                llm_result["risk_score"] = 0.1
                llm_result["reason"] = "Admin role — legitimate elevated access"

        # Layer 3: Risk aggregation
        result = aggregate_risk(rule_match, llm_result, user_role)
        result["query_normalized"] = normalized
        result["flagged"] = result["risk_score"] >= settings.risk_flag_threshold

        return result