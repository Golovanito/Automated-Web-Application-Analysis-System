import json
from typing import List, Dict, Any
from .store import CVEStore
from .versioning import assess_version_against_cve


def json_safe_extract_cve_id(item: Dict[str, Any]) -> str:

    # ID CVE różnych formatów: 1.1 i 2.0
    if not isinstance(item, dict):
        return "<unknown>"

    cve = item.get("cve", item)

    # NVD 1.1
    meta = cve.get("CVE_data_meta")
    if isinstance(meta, dict) and "ID" in meta:
        return str(meta["ID"])

    # NVD 2.0
    if "id" in cve:
        return str(cve["id"])

    # fallback
    return (
        str(cve.get("cve_id"))
        or str(cve.get("CVE"))  # na wszelki
        or str(cve.get("ID"))
        or "<unknown>"
    )


def json_safe_extract_description(item: Dict[str, Any]) -> str:
  
    # Wyciąga opis CVE
    if not isinstance(item, dict):
        return ""

    cve = item.get("cve", item)

    # NVD 1.1
    desc = cve.get("description")
    if isinstance(desc, dict):
        data = desc.get("description_data")
        if isinstance(data, list) and data:
            val = data[0].get("value")
            if isinstance(val, str):
                return val

        if "value" in desc and isinstance(desc["value"], str):
            return desc["value"]

    # NVD 2.0
    if "descriptions" in cve and isinstance(cve["descriptions"], list):
        # prefer EN
        for d in cve["descriptions"]:
            if (
                isinstance(d, dict)
                and d.get("lang", "").lower().startswith("en")
                and isinstance(d.get("value"), str)
            ):
                return d["value"]
        # jak nie ma EN, bierz pierwszy sensowny
        for d in cve["descriptions"]:
            if isinstance(d, dict) and isinstance(d.get("value"), str):
                return d["value"]

    return ""


def match_components_to_cves(
    components: List[Dict[str, Any]],
    db_path: str,
    limit_per_component: int = 10,
) -> Dict[str, List[Dict[str, Any]]]:
    
    store = CVEStore(db_path)
    results: Dict[str, List[Dict[str, Any]]] = {}

    try:
        for comp in components:
            name = (comp.get("name") or "").strip()
            if not name:
                continue

            version = (comp.get("version") or "").strip()
            key = f"{name} {version}" if version else name

            # pobierz więcej hitów, potem przytnij
            raw_hits = store.search_by_text(name, limit=limit_per_component * 5)

            matches: List[Dict[str, Any]] = []
            name_l = name.lower()

            for hit in raw_hits:
                # upewnij się, że mamy dict
                if not isinstance(hit, dict):
                    try:
                        hit = json.loads(hit)
                    except Exception:
                        continue

                full_json_str = json.dumps(hit).lower()
                desc = json_safe_extract_description(hit)
                desc_l = desc.lower()

                # --- 1) bazowe dopasowanie po nazwie ---
                score = 0.0

                # nazwa występuje gdzieś w rekordzie JSON (klucze, wartości, itp.)
                if name_l in full_json_str:
                    score += 0.3

                # nazwa występuje w opisie (czytelny sygnał)
                if name_l in desc_l:
                    score += 0.3

                # --- 2) kontekst wersji (assess_version_against_cve) ---
                version_status = "unknown"
                if version:
                    version_status = assess_version_against_cve(version, hit)

                    if version_status == "vulnerable":
                        # twardy dowód: wersja w zakresie podatności
                        score += 0.35
                    elif version_status == "maybe_vulnerable":
                        # coś pasuje, ale nie do końca
                        score += 0.15
                    elif version_status == "not_vulnerable":
                        # to CVE nie dotyczy tej wersji → pomijamy
                        continue

                    # --- 3) fallback: wersja jako zwykły tekst ---
                    # jeśli nadal nie mamy pewności, ale numer wersji pojawia się w JSON-ie,
                    if version_status in ("unknown", "maybe_vulnerable"):
                        if version.lower() in full_json_str:
                            score += 0.1

                # przycięcie do [0,1]
                score = max(0.0, min(1.0, score))

                # odfiltruj totalne śmieci
                if score < 0.3:
                    continue

                matches.append(
                    {
                        "cve_id": json_safe_extract_cve_id(hit),
                        "description": desc,
                        "score": round(score, 2),
                        "version_status": version_status,
                    }
                )

            # sortujemy po score i przycinamy do limitu
            matches.sort(key=lambda m: m["score"], reverse=True)
            results[key] = matches[:limit_per_component]

    finally:
        store.close()

    return results