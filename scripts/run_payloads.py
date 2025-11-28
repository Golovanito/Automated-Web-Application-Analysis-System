import argparse
import datetime
import json
import os, sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from awsas.tests.runner import run_tests

TARGET_URL = "http://localhost:3000/"     
PAYLOADS_FILE = "data/payloads.json"  
TIMEOUT = 10 


def main():
    if not os.path.exists(PAYLOADS_FILE):
        print(f"[ERROR] Brak pliku payloadów: {PAYLOADS_FILE}")
        return

    # 1) wczytaj payloady
    with open(PAYLOADS_FILE, "r", encoding="utf-8") as f:
        payload_spec = json.load(f)

    # 2) odpal testy
    results = run_tests(TARGET_URL, payload_spec, timeout=TIMEOUT)

    # 3) zapisz wyniki do pliku
    ts = datetime.datetime.utcnow().isoformat().replace(":", "-")
    out_path = f"data/payload_results_{ts}.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    # 4) wypisz trochę info na konsolę
    print(json.dumps(results, indent=2, ensure_ascii=False))
    print(f"\n[✓] Wyniki testów zapisane do pliku: {out_path}")


if __name__ == "__main__":
    main()