import json
from typing import List, Dict, Any
from .store import CVEStore
from .versioning import assess_version_against_cve, extract_version_ranges_from_cve

COMPONENT_CPE_PREFIXES: Dict[str, List[str]] = {
    "php": ["cpe:2.3:a:php:php"],
    "apache": ["cpe:2.3:a:apache:http_server"],
    "nginx": ["cpe:2.3:a:nginx:nginx"],
    "jquery": ["cpe:2.3:a:jquery:jquery"],
    "wordpress": ["cpe:2.3:a:wordpress:wordpress"],
    "joomla": ["cpe:2.3:a:joomla:joomla"],
    "mysql": ["cpe:2.3:a:oracle:mysql"],
    "postgresql": ["cpe:2.3:a:postgresql:postgresql"],
}


def json_safe_extract_cve_id(item: Dict[str, Any]) -> str:
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

    return (
        str(cve.get("cve_id"))
        or str(cve.get("CVE"))
        or str(cve.get("ID"))
        or "<unknown>"
    )

def json_safe_extract_description(item: Dict[str, Any]) -> str:
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
        # if no EN language
        for d in cve["descriptions"]:
            if isinstance(d, dict) and isinstance(d.get("value"), str):
                return d["value"]

    return ""

def _cve_has_matching_cpe(cve_item: Dict[str, Any], component_name: str) -> bool:
    # true only when CPE starts with one of COMPONENT_CPE_PREFIXES
    if not component_name:
        return True

    prefixes = COMPONENT_CPE_PREFIXES.get(component_name.lower())
    if not prefixes:
        return True

    ranges = extract_version_ranges_from_cve(cve_item)
    if not ranges:
        return False

    for r in ranges:
        cpe_uri = r.get("cpe_uri")
        if not cpe_uri:
            continue
        for pref in prefixes:
            if isinstance(cpe_uri, str) and cpe_uri.startswith(pref):
                return True

    return False


def match_components_to_cves(
    components: List[Dict[str, Any]],
    db_path: str,
    limit_per_component: int = 10,
    min_score: float = 0.3,
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

            raw_hits = store.search_by_text(name, limit=limit_per_component * 5)
            if not raw_hits:
                continue

            matches: List[Dict[str, Any]] = []
            name_l = name.lower()
            version_l = version.lower() if version else ""

            for hit in raw_hits:
                if not isinstance(hit, dict):
                    try:
                        hit = json.loads(hit)
                    except Exception:
                        continue

                if not _cve_has_matching_cpe(hit, name):
                    continue

                full_json_str = json.dumps(hit).lower()
                desc = json_safe_extract_description(hit)
                desc_l = desc.lower()

                score = 0.0

                if name_l in full_json_str:
                    score += 0.3

                if name_l in desc_l:
                    score += 0.3

                version_status = "unknown"
                if version:
                    prefixes = COMPONENT_CPE_PREFIXES.get(name.lower()) or []
                    version_status = assess_version_against_cve(version, hit, allowed_cpe_prefixes=prefixes)
                    if version_status == "vulnerable":
                        score += 0.35
                    # elif version_status == "maybe_vulnerable":
                        # score += 0.15
                    elif version_status == "not_vulnerable":
                        continue

                    if version_status in ("unknown", "maybe_vulnerable"):
                        if version_l and version_l in full_json_str:
                            score += 0.1

                score = max(0.0, min(1.0, score))

                if score < min_score:
                    continue

                matches.append(
                    {
                        "cve_id": json_safe_extract_cve_id(hit),
                        "description": desc,
                        "score": round(score, 2),
                        "version_status": version_status,
                    }
                )

            if matches:
                matches.sort(key=lambda m: m["score"], reverse=True)
                results[key] = matches[:limit_per_component]

    finally:
        store.close()

    return results