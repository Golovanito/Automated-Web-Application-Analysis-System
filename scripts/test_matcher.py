import json
import sys, os
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from awsas.cve.matcher import match_components_to_cves  

def main():
    db_path = "data/cve_store.db"
    profile_path = Path("data/fingerprint.json")
    if not profile_path.exists():
        print("[!] fingerprint profile not found:", profile_path)
        return

    profile = json.loads(profile_path.read_text(encoding="utf-8"))

    components = profile.get("components") or []


    coerced = []
    for c in components:
        if not isinstance(c, dict):
            continue
        name = c.get("name") or c.get("component") or None
        version = c.get("version") or None
        if name:
            coerced.append({"name": name, "version": version})

    if not coerced:
        print("[!] No components found in profile['components']. Nothing to match.")
        return

    results = match_components_to_cves(
        coerced,
        db_path=db_path,
        limit_per_component=1000
    )

    out_path = Path("data/matcher_output.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps({"components": coerced, "results": results}, indent=2, ensure_ascii=False), encoding="utf-8")

    for comp in coerced:
        name = comp["name"]
        hits = results.get(name, []) or results.get(comp.get("name"), [])
        print(f"\n=== {name} ({comp.get('version')}) -> {len(hits)} hits ===")
        for h in hits[:5]:
            print(f"- {h.get('cve_id')} score={h.get('score'):.2f} | { (h.get('description') or '')[:80] }")

    print("\n[+] Wrote results to", out_path)

if __name__ == "__main__":
    main()