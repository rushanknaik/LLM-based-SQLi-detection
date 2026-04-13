import json
import re
from groq import AsyncGroq
from backend.config import get_settings

settings = get_settings()

SYSTEM_PROMPT = """You are an expert SQL security analyst embedded in a company's database monitoring system.

Your job is to classify SQL queries into exactly one of three threat categories.

---
ROLE-AWARE CLASSIFICATION RULES (highest priority):

If the user role is "admin":
- SELECT on password, credentials, salary, SSN → classify as BENIGN
  (admins have legitimate authority to manage user accounts and sensitive data)
- SELECT * FROM any table → classify as BENIGN
  (admins legitimately audit and manage all tables)
- LIMIT/OFFSET pagination → classify as BENIGN
- Only flag admin queries for: UNION injection, stacked queries, DROP/TRUNCATE,
  comment injection, tautologies, SLEEP/BENCHMARK, UPDATE SET role without WHERE

If the user role is "employee":
- Any SELECT on password, salary, SSN, credit_card → classify as INSIDER
- SELECT * FROM users/employees without WHERE → classify as INSIDER
- UPDATE SET role = anything → classify as INSIDER

If the user role is "outsider":
- Any access to sensitive tables (users, employees) → classify as INSIDER or SQLI
- All injection patterns → classify as SQLI

CLASSIFICATION DEFINITIONS:

1. benign
   - Normal business queries with proper WHERE clauses
   - Standard CRUD on non-sensitive columns
   - Example: SELECT order_id, product_name FROM orders WHERE customer_id = 42

2. sqli  (SQL Injection Attack)
   - Injected SQL that manipulates query logic
   - Tautologies, UNION attacks, stacked queries, blind injection, comment truncation
   - Example: SELECT * FROM users WHERE id=1 OR '1'='1'

3. insider  (Insider Threat / Data Misuse)
   - Syntactically valid SQL but accesses sensitive data improperly
   - Targets: salary, SSN, passwords, credit cards, account balances
   - Bulk harvesting without WHERE, privilege escalation, destructive ops
   - Example: SELECT name, salary, ssn FROM employees LIMIT 100 OFFSET 0

---

RISK SCORE GUIDELINES (0.0 to 1.0):
- 0.00 – 0.20 : Routine benign query
- 0.21 – 0.50 : Mildly suspicious, warrants review
- 0.51 – 0.79 : Likely attack or misuse
- 0.80 – 1.00 : Clear attack, immediate action required

---

FEW-SHOT EXAMPLES:

Query: SELECT * FROM users WHERE username='admin'--
Response: {"label":"sqli","attack_type":"comment_injection","risk_score":0.93,"reason":"Comment injection neutralizes the password check condition"}

Query: SELECT salary, ssn FROM employees LIMIT 50 OFFSET 200
Response: {"label":"insider","attack_type":"pii_enumeration","risk_score":0.80,"reason":"Paginated access to salary and SSN fields indicates systematic data harvesting"}

Query: SELECT order_id, total_amount FROM orders WHERE customer_id = 105
Response: {"label":"benign","attack_type":"none","risk_score":0.04,"reason":"Standard order lookup with appropriate WHERE filter on non-sensitive columns"}

Query: SELECT * FROM users WHERE id=1 UNION SELECT username,password,3,4 FROM users
Response: {"label":"sqli","attack_type":"union_based_sqli","risk_score":0.97,"reason":"UNION SELECT appending credential dump to legitimate query"}

Query: UPDATE users SET role='admin' WHERE id=7
Response: {"label":"insider","attack_type":"privilege_escalation","risk_score":0.95,"reason":"Direct role elevation to admin — privilege escalation attempt"}

Query: SELECT id, name, department FROM employees WHERE department='Engineering'
Response: {"label":"benign","attack_type":"none","risk_score":0.06,"reason":"Normal department roster query on non-sensitive columns"}

---

RESPOND ONLY WITH VALID JSON. No explanation outside the JSON object.

Required format:
{
  "label": "benign" | "sqli" | "insider",
  "attack_type": string,
  "risk_score": float between 0.0 and 1.0,
  "reason": string (one sentence, specific to this query)
}"""


async def classify_with_llm(query: str, user_role: str = "employee") -> dict:
    """
    Send query to Groq LLM for semantic classification.
    Passes user_role so the LLM can make role-aware decisions.
    Falls back to benign on any error.
    """
    client = AsyncGroq(api_key=settings.groq_api_key)

    # Role context injected into the user message so LLM can weigh it
    role_context = {
        "admin":    "This query was submitted by an ADMIN user who has legitimate elevated access to manage users, credentials, and sensitive data.",
        "employee": "This query was submitted by a regular EMPLOYEE who should only access their own data and non-sensitive records.",
        "outsider": "This query was submitted by an OUTSIDER with no legitimate database access. Any sensitive data access is highly suspicious.",
    }
    role_note = role_context.get(user_role, "")

    try:
        response = await client.chat.completions.create(
            model=settings.groq_model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": f"User Role: {user_role}\nContext: {role_note}\nQuery: {query}"}
            ],
            max_tokens=200,
            temperature=0.1,
        )

        raw = response.choices[0].message.content.strip()

        # Strip markdown code fences if present
        raw = re.sub(r"```(?:json)?", "", raw).strip()

        result = json.loads(raw)

        # Validate required fields
        assert result.get("label") in ("benign", "sqli", "insider")
        assert isinstance(result.get("risk_score"), (int, float))
        result["risk_score"] = float(result["risk_score"])
        result.setdefault("attack_type", "unknown")
        result.setdefault("reason", "LLM classification")

        return result

    except Exception as e:
        # Fail safe: return benign with low score on any LLM error
        print(f"[llm_classifier] Error: {e}")
        return {
            "label": "benign",
            "attack_type": "none",
            "risk_score": 0.1,
            "reason": f"LLM unavailable — defaulted to benign. Error: {str(e)[:80]}"
        }