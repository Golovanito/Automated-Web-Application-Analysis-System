import argparse
import datetime
import json
import os, sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from awsas.tests.runner import run_tests
from awsas.generator.claude_client import ClaudeClient

judge = ClaudeClient(api_key=os.environ.get("ANTHROPIC_API_KEY"), model="claude-sonnet-4-5-20250929")

TARGET_URL = "http://127.0.0.1:4280/vulnerabilities/sqli/"    
PAYLOADS_FILE = "data/payloads_2.json"  
TIMEOUT = 10 


def main():
    if not os.path.exists(PAYLOADS_FILE):
        print(f"[ERROR] Brak pliku payloadów: {PAYLOADS_FILE}")
        return

    with open(PAYLOADS_FILE, "r", encoding="utf-8") as f:
        payload_spec = json.load(f)

    results = run_tests(TARGET_URL, payload_spec, timeout=TIMEOUT, dvwa_login_data={
        "username": "admin",
        "password": "password",
        "security": "low"
    },
    judge_client=judge,
    judge_on_fail=True,)

    ts = datetime.datetime.utcnow().isoformat().replace(":", "-")
    out_path = f"data/payload_results_{ts}.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    print(json.dumps(results, indent=2, ensure_ascii=False))
    print(f"\n[✓] Wyniki testów zapisane do pliku: {out_path}")


if __name__ == "__main__":
    main()