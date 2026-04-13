from typing import Optional
from backend.detection.rule_engine import RuleMatch

ROLE_RISK_MULTIPLIERS = {
    "outsider": 1.35,  # External actor accessing DB is inherently high-risk
    "employee": 1.00,  # Baseline
    "admin":    0.75,  # Admins have legitimate elevated access
}


def aggregate_risk(
    rule_match: Optional[RuleMatch],
    llm_result: Optional[dict],
    user_role: str
) -> dict:
    """
    Combine rule engine and LLM outputs into a final weighted risk assessment.
    Applies role-based multiplier to reflect contextual risk.
    """
    role_multiplier = ROLE_RISK_MULTIPLIERS.get(user_role, 1.0)

    if rule_match and rule_match.confidence >= 0.90:
        # High-confidence rule hit: trust it directly, LLM is supplementary
        base_score = rule_match.confidence
        label = rule_match.label
        attack_type = rule_match.attack_type
        explanation = rule_match.explanation
        detection_source = "rule_engine"

        # If LLM also ran and disagrees significantly, note it but keep rule
        if llm_result and llm_result["label"] != label:
            explanation += f" (LLM suggested: {llm_result['label']})"

    elif rule_match and llm_result:
        # Both fired: weighted blend — LLM carries more semantic weight
        base_score = (rule_match.confidence * 0.35) + (llm_result["risk_score"] * 0.65)
        label = llm_result["label"]  # LLM label takes precedence
        attack_type = llm_result.get("attack_type", rule_match.attack_type)
        explanation = llm_result.get("reason", rule_match.explanation)
        detection_source = "hybrid"

    elif llm_result:
        # Only LLM fired (rule engine found nothing)
        base_score = llm_result["risk_score"]
        label = llm_result["label"]
        attack_type = llm_result.get("attack_type", "unknown")
        explanation = llm_result.get("reason", "LLM classification")
        detection_source = "llm"

    else:
        # Nothing fired — benign default
        base_score = 0.05
        label = "benign"
        attack_type = "none"
        explanation = "No threats detected by rule engine or LLM"
        detection_source = "default"

    # Apply role multiplier and cap at 1.0
    final_score = min(round(base_score * role_multiplier, 3), 1.0)

    return {
        "label": label,
        "attack_type": attack_type,
        "risk_score": final_score,
        "detection_source": detection_source,
        "explanation": explanation,
        "role_multiplier": role_multiplier,
    }