import json, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from awsas.fingerprint.detector import FingerprintDetector
from awsas.cve.matcher import match_components_to_cves
from awsas.generator.payloads import generate_test_payloads

DB_PATH = "data/cve_store.db"


def main():
    url = "https://boscaiola.eu"

    det = FingerprintDetector()
    profile = det.analyze(url)

    components = [
        {"name": c.name, "version": c.version}
        for c in profile.components
    ]

    cve_matches = match_components_to_cves(components, db_path=DB_PATH, limit_per_component=10)

    payload_spec = generate_test_payloads(profile, cve_matches)

    print(json.dumps(payload_spec, indent=2, ensure_ascii=False))

    import datetime
    ts = datetime.datetime.utcnow().isoformat().replace(":", "-")
    out_path = f"payloads_{ts}.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload_spec, f, indent=2, ensure_ascii=False)

    print(f"\n[✓] Payload zapisany do pliku: {out_path}")


if __name__ == "__main__":
    main()