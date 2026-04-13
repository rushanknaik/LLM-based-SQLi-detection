import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.detection.rule_engine import run_rule_engine

# ── SQLi Tests ─────────────────────────────────────────
def test_tautology():
    r = run_rule_engine("SELECT * FROM users WHERE id=1 OR '1'='1'")
    assert r is not None
    assert r.label == "sqli"
    assert r.attack_type == "tautology_injection"

def test_union_select():
    r = run_rule_engine("SELECT * FROM users UNION SELECT username,password,3,4 FROM users")
    assert r is not None
    assert r.label == "sqli"
    assert r.attack_type == "union_based_sqli"

def test_comment_injection():
    r = run_rule_engine("SELECT * FROM users WHERE username='admin'--")
    assert r is not None
    assert r.label == "sqli"

def test_stacked_query():
    r = run_rule_engine("SELECT * FROM users; DROP TABLE users;")
    assert r is not None
    assert r.label == "sqli"
    assert r.attack_type == "stacked_query_sqli"

def test_sleep_injection():
    r = run_rule_engine("SELECT * FROM users WHERE id=1 AND SLEEP(5)")
    assert r is not None
    assert r.label == "sqli"
    assert r.attack_type == "blind_time_sqli"

def test_outfile():
    r = run_rule_engine("SELECT * FROM users INTO OUTFILE '/tmp/out.txt'")
    assert r is not None
    assert r.label == "sqli"
    assert r.attack_type == "data_export_sqli"

# ── Insider Tests ──────────────────────────────────────
def test_salary_access():
    r = run_rule_engine("SELECT name, salary FROM employees")
    assert r is not None
    assert r.label == "insider"
    assert r.attack_type == "salary_exfiltration"

def test_credential_harvest():
    r = run_rule_engine("SELECT username, password FROM users")
    assert r is not None
    assert r.label == "insider"
    assert r.attack_type == "credential_access"

def test_privilege_escalation():
    r = run_rule_engine("UPDATE users SET role='admin' WHERE id=7")
    assert r is not None
    assert r.label == "insider"
    assert r.attack_type == "privilege_escalation"

def test_bulk_delete():
    r = run_rule_engine("DELETE FROM transactions")
    assert r is not None
    assert r.label == "insider"
    assert r.attack_type == "bulk_delete"

def test_ssn_access():
    r = run_rule_engine("SELECT name, ssn FROM employees LIMIT 100 OFFSET 0")
    assert r is not None
    assert r.label == "insider"
    assert r.attack_type == "pii_access"

# ── Benign Tests ───────────────────────────────────────
def test_benign_select():
    r = run_rule_engine("SELECT id, name FROM employees WHERE department = 'Engineering'")
    assert r is None   # No rule should fire for benign query

def test_benign_order():
    r = run_rule_engine("SELECT order_id, total_amount FROM orders WHERE customer_id = 42")
    assert r is None

def test_benign_insert():
    r = run_rule_engine("INSERT INTO orders (product_name, quantity) VALUES ('Laptop', 1)")
    assert r is None


if __name__ == "__main__":
    tests = [
        test_tautology, test_union_select, test_comment_injection,
        test_stacked_query, test_sleep_injection, test_outfile,
        test_salary_access, test_credential_harvest, test_privilege_escalation,
        test_bulk_delete, test_ssn_access,
        test_benign_select, test_benign_order, test_benign_insert,
    ]
    passed = failed = 0
    for t in tests:
        try:
            t()
            print(f"  ✅ {t.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"  ❌ {t.__name__} — {e}")
            failed += 1

    print(f"\n{passed} passed, {failed} failed out of {len(tests)} tests")