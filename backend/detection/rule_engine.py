import re
from dataclasses import dataclass
from typing import Optional, Set


@dataclass
class RuleMatch:
    matched: bool
    label: str
    attack_type: str
    confidence: float
    rule_name: str
    explanation: str


SQLI_RULES = [
    (r"or\s+['\"]?1['\"]?\s*=\s*['\"]?1",
     "tautology_injection", 0.97,
     "Classic OR 1=1 tautology — always-true condition to bypass authentication"),

    (r"or\s+['\"]?[a-z]['\"]?\s*=\s*['\"]?[a-z]",
     "tautology_injection", 0.93,
     "String tautology injection (e.g. 'a'='a') to force always-true evaluation"),

    (r"union\s+(all\s+)?select",
     "union_based_sqli", 0.97,
     "UNION SELECT injection — attempts to append attacker-controlled query results"),

    (r";\s*(drop|insert|update|delete|create|alter|truncate)\s?",
     "stacked_query_sqli", 0.98,
     "Stacked query injection — multiple statements to execute destructive SQL"),

    (r"(sleep|benchmark)\s*\(\s*\d+",
     "blind_time_sqli", 0.96,
     "Time-based blind SQLi — uses deliberate delay to infer database responses"),

    (r"waitfor\s+delay\s*['\"]",
     "blind_time_sqli", 0.96,
     "WAITFOR DELAY (MSSQL) — time-based blind injection technique"),

    (r"(and|or)\s+\d+\s*=\s*\d+",
     "boolean_blind_sqli", 0.87,
     "Boolean-based blind SQLi — infers data by testing true/false conditions"),

    (r"extractvalue\s*\(|updatexml\s*\(",
     "error_based_sqli", 0.95,
     "Error-based SQLi — forces database error to leak information"),

    (r"--\s*$",
     "comment_injection", 0.82,
     "SQL comment injection — truncates the original query to bypass conditions"),

    (r"/\*.*?\*/",
     "comment_injection", 0.80,
     "Inline comment injection — used to obfuscate or break up SQL keywords"),

    (r"#\s*$",
     "comment_injection", 0.78,
     "MySQL hash comment injection — equivalent to -- in MySQL"),

    (r"0x[0-9a-f]{4,}",
     "hex_encoding_sqli", 0.85,
     "Hex-encoded payload — attempts to bypass string-based filters"),

    (r"char\s*\(\s*\d+(\s*,\s*\d+)*\s*\)",
     "char_encoding_sqli", 0.82,
     "CHAR() encoding — obfuscates string literals to evade detection"),

    (r"convert\s*\(.+using\s+\w+\)",
     "encoding_evasion_sqli", 0.84,
     "CONVERT with charset — encoding manipulation to evade filters"),

    (r"into\s+(outfile|dumpfile)\s*['\"]",
     "data_export_sqli", 0.99,
     "INTO OUTFILE/DUMPFILE — attempts to write query results to filesystem"),

    (r"load_file\s*\(",
     "file_read_sqli", 0.95,
     "LOAD_FILE() — attempts to read server filesystem via SQL"),

    (r"information_schema\.(tables|columns|schemata)",
     "schema_enumeration_sqli", 0.90,
     "information_schema access — attacker mapping database structure"),

    (r"xp_cmdshell|exec\s+master",
     "os_command_sqli", 0.99,
     "xp_cmdshell / EXEC MASTER — OS command execution via SQL (critical)"),
]


# Format: (pattern, attack_type, confidence, explanation, exempt_roles)
# exempt_roles: roles for which this rule does NOT fire
# Empty set = fires for ALL roles with no exceptions

INSIDER_RULES = [
    (r"select\b.*\b(password|passwd|pwd|password_hash|secret)\b",
     "credential_access", 0.95,
     "Query selecting password/credential fields — high-risk credential harvesting",
     {"admin"}),

    (r"select\b.*\b(salary|compensation|wage|pay_grade)\b",
     "salary_exfiltration", 0.85,
     "Query targeting salary/compensation fields — potential financial data exfiltration",
     {"admin"}),

    (r"select\b.*\b(ssn|social_security|national_id|tax_id)\b",
     "pii_access", 0.95,
     "Query targeting SSN/national ID — sensitive PII exfiltration",
     {"admin"}),

    (r"select\b.*\b(credit_card|card_number|cvv|card_expiry)\b",
     "financial_data_access", 0.97,
     "Query targeting payment card data — PCI-DSS regulated data access",
     set()),

    (r"select\b.*\b(account_number|account_id|balance|routing_number)\b",
     "financial_enumeration", 0.82,
     "Query enumerating financial account details — potential fraud enablement",
     {"admin"}),

    (r"update\s+\w+\s+set\s+(role|is_admin|permission|access_level)\s*=",
     "privilege_escalation", 0.98,
     "UPDATE setting role/admin flag — privilege escalation attempt",
     set()),

    (r"grant\s+(all|select|insert|update|delete|execute)",
     "privilege_grant", 0.95,
     "GRANT statement — unauthorized privilege assignment",
     set()),

    (r"select\s+\*\s+from\s+(users|employees|customers|accounts|staff)\b",
     "bulk_user_data_access", 0.82,
     "SELECT * on sensitive table — bulk user data harvesting without filter",
     {"admin"}),

    (r"delete\s+from\s+\w+\s*;?\s*$",
     "bulk_delete", 0.98,
     "DELETE without WHERE clause — destructive bulk delete operation",
     set()),

    (r"update\s+\w+\s+set\s+(?!.*\bwhere\b)",
     "bulk_update", 0.91,
     "UPDATE without WHERE clause — modifies all rows in the table",
     set()),

    (r"limit\s+\d{2,}\s+offset\s+\d+",
     "enumeration_behavior", 0.72,
     "Paginated bulk access (LIMIT n OFFSET m) — systematic data harvesting pattern",
     {"admin"}),

    (r"select\b.*\bfrom\s+(employees|users)\b(?!.*\bwhere\b)",
     "unrestricted_table_scan", 0.80,
     "Full table scan without WHERE — accesses all records in sensitive table",
     {"admin"}),

    (r"select\b.*\b(dob|date_of_birth|birth_date|age)\b",
     "demographic_pii_access", 0.75,
     "Query accessing date of birth — demographic PII access",
     {"admin"}),

    (r"select\b.*\b(phone|mobile|address|zip|postal)\b.*\bfrom\s+(users|employees|customers)\b",
     "contact_pii_access", 0.73,
     "Query harvesting contact PII from user tables",
     {"admin"}),

    (r"(drop|truncate)\s+table\s+\w+",
     "destructive_ddl", 0.99,
     "DROP/TRUNCATE TABLE — destructive schema operation, likely sabotage",
     set()),
]


def run_rule_engine(query: str, user_role: str = "employee") -> Optional[RuleMatch]:
    """
    Role-aware rule engine.
    Insider rules skip evaluation if user_role is in that rule's exempt_roles set.
    SQLi rules always fire regardless of role.
    """
    q = query.lower().strip()
    matches = []

    for pattern, attack_type, confidence, explanation in SQLI_RULES:
        if re.search(pattern, q):
            matches.append(RuleMatch(
                matched=True,
                label="sqli",
                attack_type=attack_type,
                confidence=confidence,
                rule_name=pattern,
                explanation=explanation
            ))

    for pattern, attack_type, confidence, explanation, exempt_roles in INSIDER_RULES:
        if re.search(pattern, q):
            if user_role in exempt_roles:
                continue  # This role is exempt — skip rule
            matches.append(RuleMatch(
                matched=True,
                label="insider",
                attack_type=attack_type,
                confidence=confidence,
                rule_name=pattern,
                explanation=explanation
            ))

    if not matches:
        return None

    return max(matches, key=lambda m: m.confidence)