import re
from typing import Any, Dict, List, Optional, Tuple

def _normalize_version(ver: str) -> Tuple[int, ...]:
    # Parser wersji
    if not ver:
        return ()
    ver = ver.strip()
    # odetnij wszystko po pierwszej spacji / '-' / '+'
    for sep in (" ", "-", "+"):
        if sep in ver:
            ver = ver.split(sep, 1)[0]
    parts = []
    for p in ver.split("."):
        if not p:
            break
        if not p.isdigit():
            # jak coś dziwnego, przerywamy na tym miejscu
            break
        parts.append(int(p))
    return tuple(parts)

def _cmp_versions(a: str, b: str) -> int:
    # Porownanie wersji
    ta = _normalize_version(a)
    tb = _normalize_version(b)
    # porównujemy "klockami"
    for x, y in zip(ta, tb):
        if x < y:
            return -1
        if x > y:
            return 1
    # jeśli do tego miejsca są równe, dłuższa wygrywa
    if len(ta) < len(tb):
        return -1
    if len(ta) > len(tb):
        return 1
    return 0

def extract_version_from_cpe23uri(cpe23: str) -> Optional[str]:
    if not cpe23 or not isinstance(cpe23, str):
        return None
    parts = cpe23.split(":")
    # zabezpieczenie: oczekujemy przynajmniej 6 pól
    if len(parts) >= 6:
        ver = parts[5]
        if ver and ver not in ("*", "-"):
            return ver
    return None


def extract_version_ranges_from_cve(cve_item: Dict[str, Any]) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []

    # 1) jeśli mamy podklucz "cve", pracujemy na nim
    root = cve_item.get("cve", cve_item)

    def _extract_from_nodes(nodes: Any):
        if not isinstance(nodes, list):
            return
        for node in nodes:
            if not isinstance(node, dict):
                continue

            # cpe_match (stare) vs cpeMatch (nowe)
            matches = node.get("cpe_match") or node.get("cpeMatch")
            if isinstance(matches, list):
                for m in matches:
                    if not isinstance(m, dict):
                        continue

                    # cpe URI: cpe23Uri (stare) lub criteria (nowe API)
                    cpe_uri = m.get("cpe23Uri") or m.get("cpe23uri") or m.get("criteria") or m.get("cpe")
                    vsi  = m.get("versionStartIncluding")
                    vsex = m.get("versionStartExcluding")
                    vei  = m.get("versionEndIncluding")
                    vee  = m.get("versionEndExcluding")

                    if vsi or vsex or vei or vee:
                        results.append({
                            "type": "range",
                            "start": vsex or vsi,
                            "start_including": bool(vsi),
                            "end": vei or vee,
                            "end_including": bool(vei),
                            "cpe_uri": cpe_uri,
                        })
                    else:
                        ver = extract_version_from_cpe23uri(cpe_uri)
                        if ver:
                            results.append({"type": "exact", "version": ver, "cpe_uri": cpe_uri})

            # children (stare drzewo konfiguracji)
            children = node.get("children")
            if isinstance(children, list):
                for ch in children:
                    if isinstance(ch, dict):
                        _extract_from_nodes([ch])

    cfg = root.get("configurations")
    # NVD 2.0: configurations to LISTA bloków
    if isinstance(cfg, list):
        for block in cfg:
            if isinstance(block, dict):
                _extract_from_nodes(block.get("nodes"))
    # starszy styl: dict z "nodes"
    elif isinstance(cfg, dict):
        _extract_from_nodes(cfg.get("nodes"))

    return results


def assess_version_against_cve(detected_version: str, cve_item: Dict[str, Any]) -> str:
    if not detected_version:
        return "unknown"

    ranges = extract_version_ranges_from_cve(cve_item)
    if not ranges:
        return "unknown"

    status = "unknown"

    for r in ranges:
        if r.get("type") == "exact":
            v = r.get("version")
            if not v:
                continue
            cmp_res = _cmp_versions(detected_version, v)
            if cmp_res == 0:
                return "vulnerable"
            # exact mismatch nic nie wnosi – idziemy dalej

        elif r.get("type") == "range":
            start = r.get("start")
            end = r.get("end")
            inc_start = r.get("start_including", False)
            inc_end = r.get("end_including", False)

            ok_lower = True
            ok_upper = True

            if start:
                cmp_low = _cmp_versions(detected_version, start)
                if inc_start:
                    ok_lower = cmp_low >= 0
                else:
                    ok_lower = cmp_low > 0

            if end:
                cmp_high = _cmp_versions(detected_version, end)
                if inc_end:
                    ok_upper = cmp_high <= 0
                else:
                    ok_upper = cmp_high < 0

            if ok_lower and ok_upper:
                # idealne trafienie w zakres
                return "vulnerable"

            # jeśli mamy jakąś częściową informację o patchowaniu:
            if end:
                cmp_high = _cmp_versions(detected_version, end)
                # wersja wyższa niż wersja "końca podatności"
                if cmp_high > 0 and not inc_end:
                    status = "not_vulnerable"

    return status