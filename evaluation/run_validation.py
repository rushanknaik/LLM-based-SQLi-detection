"""
Batch validation script.
Runs the hybrid detection engine against test.csv and prints metrics.

Usage:
    python evaluation/run_validation.py

Requires:
    - .env with GROQ_API_KEY
    - dataset/v1.0/test.csv  with columns: query, label, attack_type
"""
import sys, os, csv, asyncio, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv()

from backend.detection.engine import HybridDetectionEngine
from evaluation.metrics import print_report

TEST_CSV = os.path.join(os.path.dirname(__file__), "..", "dataset", "v1.0", "test.csv")
ROLE     = "employee"    # Default role for batch evaluation
DELAY    = 0.3           # Seconds between LLM calls to avoid rate limiting
MAX_ROWS = 200           # Set to None to run all rows


async def run():
    if not os.path.exists(TEST_CSV):
        print(f"[ERROR] Test CSV not found: {TEST_CSV}")
        print("  Create dataset/v1.0/test.csv with columns: query, label, attack_type")
        return

    engine = HybridDetectionEngine()
    y_true, y_pred = [], []
    errors = 0

    with open(TEST_CSV, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    if MAX_ROWS:
        rows = rows[:MAX_ROWS]

    print(f"\n── Running validation on {len(rows)} queries ──────────────")

    for i, row in enumerate(rows):
        query      = row.get("query", "").strip()
        true_label = row.get("label", "").strip().lower()

        if not query or not true_label:
            continue

        try:
            result = await engine.analyze(query, ROLE)
            pred_label = result["label"]
            y_true.append(true_label)
            y_pred.append(pred_label)

            status = "✅" if pred_label == true_label else "❌"
            if (i + 1) % 10 == 0 or pred_label != true_label:
                print(f"  [{i+1:>4}/{len(rows)}] {status} true={true_label:<10} pred={pred_label:<10} risk={result['risk_score']:.3f}")

            await asyncio.sleep(DELAY)

        except Exception as e:
            print(f"  [ERROR] row {i+1}: {e}")
            errors += 1

    print(f"\nCompleted. {errors} errors encountered.")
    print_report(y_true, y_pred)


if __name__ == "__main__":
    asyncio.run(run())