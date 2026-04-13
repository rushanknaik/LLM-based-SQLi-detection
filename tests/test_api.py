"""
Basic API smoke tests.
Run with: python tests/test_api.py  (requires the server to be running on port 8000)
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import urllib.request
import json

BASE = "http://localhost:8000"


def post(path, payload):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        f"{BASE}{path}",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        return json.loads(resp.read())


def get(path):
    with urllib.request.urlopen(f"{BASE}{path}", timeout=10) as resp:
        return json.loads(resp.read())


def test_health():
    r = get("/health")
    assert r["status"] == "ok"
    print("  ✅ /health")


def test_analyze_benign():
    r = post("/api/query/analyze", {
        "query": "SELECT id, name FROM employees WHERE department='Engineering'",
        "user_role": "employee",
        "session_id": "test-session-001"
    })
    assert r["success"]
    assert r["result"]["label"] == "benign"
    assert r["result"]["risk_score"] < 0.6
    print("  ✅ analyze benign query")


def test_analyze_sqli():
    r = post("/api/query/analyze", {
        "query": "SELECT * FROM users WHERE id=1 OR '1'='1'",
        "user_role": "outsider",
        "session_id": "test-session-002"
    })
    assert r["success"]
    assert r["result"]["label"] == "sqli"
    assert r["result"]["flagged"] is True
    print("  ✅ analyze sqli query")


def test_analyze_insider():
    r = post("/api/query/analyze", {
        "query": "SELECT name, salary, ssn FROM employees LIMIT 100 OFFSET 0",
        "user_role": "employee",
        "session_id": "test-session-003"
    })
    assert r["success"]
    assert r["result"]["label"] == "insider"
    assert r["result"]["flagged"] is True
    print("  ✅ analyze insider query")


def test_role_multiplier_outsider():
    r = post("/api/query/analyze", {
        "query": "SELECT salary FROM employees",
        "user_role": "outsider",
        "session_id": "test-session-004"
    })
    assert r["result"]["role_multiplier"] == 1.35
    print("  ✅ outsider role multiplier = 1.35")


def test_dashboard_stats():
    r = get("/api/dashboard/stats")
    assert "total_queries" in r
    assert "sqli_count" in r
    print("  ✅ dashboard stats")


def test_logs():
    r = get("/api/logs?page=1&per_page=5")
    assert "logs" in r
    assert "total" in r
    print("  ✅ logs endpoint")


if __name__ == "__main__":
    tests = [
        test_health,
        test_analyze_benign,
        test_analyze_sqli,
        test_analyze_insider,
        test_role_multiplier_outsider,
        test_dashboard_stats,
        test_logs,
    ]
    passed = failed = 0
    print("\n── Running API Tests ──────────────────────────────")
    print("   (make sure server is running: uvicorn backend.main:app --reload)\n")
    for t in tests:
        try:
            t()
            passed += 1
        except Exception as e:
            print(f"  ❌ {t.__name__} — {e}")
            failed += 1

    print(f"\n{passed} passed, {failed} failed out of {len(tests)} tests")