import json
import os, sys
from datetime import datetime
from typing import List, Dict, Any

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
DB_PATH = "data/cve_store.db"                 
FINGERPRINT_JSON = "data/fingerprint.json"
OUTPUT_JSON = "data/matcher_result.json"      

from awsas.cve.matcher import match_components_to_cves
from awsas.cve.store import CVEStore


def load_components_from_fingerprint(fp_path: str) -> List[Dict[str, Any]]:
    """Wczytuje komponenty z pliku fingerprint.json"""
    with open(fp_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    comps = []
    for c in data.get("components", []):
        if isinstance(c, dict) and c.get("name"):
            comps.append({
                "name": c.get("name").strip(),
                "version": (c.get("version") or "").strip()
            })
    return comps


def ensure_db(db_path: str):
    """Sprawdza, czy baza istnieje i nie jest pusta."""
    if not os.path.exists(db_path):
        raise FileNotFoundError(f"❌ Nie znaleziono bazy CVE: {db_path}")
    store = CVEStore(db_path)
    try:
        total = store.count()
    finally:
        store.close()
    if total == 0:
        raise RuntimeError(f"❌ Baza '{db_path}' jest pusta (COUNT=0). Zasiej CVE zanim uruchomisz test.")
    print(f"✅ Załadowano bazę CVE ({total} rekordów).")


def print_summary(results: Dict[str, List[Dict[str, Any]]], limit: int = 10):
    """Ładne podsumowanie w konsoli."""
    print("\n=== PODSUMOWANIE ===")
    if not results:
        print("Brak dopasowań CVE.")
        return
    for comp_key, items in results.items():
        print(f"\n[{comp_key}] (Top {min(limit, len(items))})")
        for it in items[:limit]:
            cve_id = it.get("cve_id", "?")
            score = it.get("score", "?")
            vstat = it.get("version_status", "unknown")
            desc = (it.get("description") or "").strip().replace("\n", " ")
            if len(desc) > 120:
                desc = desc[:117] + "..."
            print(f" - {cve_id} | score={score} | status={vstat} | {desc}")


def save_to_json(results: Dict[str, Any], output_path: str):
    """Zapisuje wynik matchera do pliku JSON z timestampem."""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    payload = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "db_path": DB_PATH,
        "fingerprint_file": FINGERPRINT_JSON,
        "results": results
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
    print(f"\n💾 Zapisano wynik matchera do pliku: {output_path}")


def main():
    ensure_db(DB_PATH)

    if not os.path.exists(FINGERPRINT_JSON):
        raise FileNotFoundError(f"❌ Nie znaleziono pliku fingerprintu: {FINGERPRINT_JSON}")
    components = load_components_from_fingerprint(FINGERPRINT_JSON)
    if not components:
        print("[WARN] Brak komponentów w fingerprintcie. Kończę.")
        return

    print("\n=== KOMPONENTY DO DOPASOWANIA ===")
    for c in components:
        print(f" - {c['name']}: {c.get('version') or '(brak wersji)'}")

    print("\n⏳ Uruchamianie matchera...")
    results = match_components_to_cves(
        components=components,
        db_path=DB_PATH,
        limit_per_component=10,
    )

    print_summary(results, limit=10)
    save_to_json(results, OUTPUT_JSON)


if __name__ == "__main__":
    main()