import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

@dataclass
class Evidence:
    type: str
    value: str
    weight: float

@dataclass
class ComponentMatch:
    name: str
    version: Optional[str]
    score: float
    evidence: List[Evidence] = field(default_factory=list)

# (opcjonalnie) słownik faviconów → komponent
FAVICON_MAP: Dict[str, tuple[str, float]] = {
    # "sha1hash": ("phpMyAdmin", 0.95),
}

COOKIE_HINTS = {
    "PHPSESSID": ("PHP", None, 0.6),
    "JSESSIONID": ("Java", None, 0.6),
    "laravel_session": ("Laravel", None, 0.7),
    "csrftoken": ("Django", None, 0.7),
    "wordpress_logged_in": ("WordPress", None, 0.9),
}

def detect_components(
    headers: Dict[str, str],
    cookies: List[str],
    scripts: List[str],
    meta: Dict[str, str],
    favicon_hash: Optional[str],
    tls_issuer: Optional[str],
) -> List[ComponentMatch]:

    matches: List[ComponentMatch] = []

    # 1) meta generator (najsilniejszy)
    gen = meta.get("generator")
    if gen:
        parts = gen.split()
        name = parts[0]
        version = parts[1] if len(parts) > 1 else None
        ev = Evidence("meta_generator", gen, 1.0)
        matches.append(ComponentMatch(name=name, version=version, score=1.0, evidence=[ev]))

    # 2) cookies
    for c in cookies:
        if c in COOKIE_HINTS:
            name, version, w = COOKIE_HINTS[c]
            ev = Evidence("cookie", c, w)
            _append_match(matches, name, version, w, ev)

    # 3) Server header
    server = headers.get("Server")
    if server:
        srv = server.split("/")[0]
        ev = Evidence("server_header", server, 0.3)
        _append_match(matches, srv, None, 0.3, ev)

    # 4) scripts heuristics (np. jQuery)
    for s in scripts:
        if "jquery" in s.lower():
            m = re.search(r"jquery[-\.]?(\d+\.\d+(\.\d+)?)", s, re.IGNORECASE)
            ver = m.group(1) if m else None
            ev = Evidence("script", s, 0.8)
            _append_match(matches, "jQuery", ver, 0.8, ev)

    # 5) favicon hash
    if favicon_hash and favicon_hash in FAVICON_MAP:
        name, w = FAVICON_MAP[favicon_hash]
        ev = Evidence("favicon_hash", favicon_hash, w)
        _append_match(matches, name, None, w, ev)

    # 6) TLS issuer – sygnał słaby, czasem pomocniczy
    if tls_issuer:
        ev = Evidence("tls_issuer", tls_issuer, 0.2)
        _append_match(matches, "TLS-Issuer", None, 0.2, ev)

    # deduplikacja i scalanie
    combined: Dict[str, ComponentMatch] = {}
    for m in matches:
        key = m.name.lower()
        if key in combined:
            ex = combined[key]
            ex.evidence.extend(m.evidence)
            ex.score = min(1.0, max(ex.score, m.score))
            if not ex.version and m.version:
                ex.version = m.version
        else:
            combined[key] = m
    return list(combined.values())


def _append_match(matches: List[ComponentMatch], name: str, version: Optional[str], weight: float, ev: Evidence):
    found = next((m for m in matches if m.name.lower() == name.lower()), None)
    if found:
        found.evidence.append(ev)
        found.score = min(1.0, found.score + weight * 0.5)
        if not found.version and version:
            found.version = version
    else:
        matches.append(ComponentMatch(name=name, version=version, score=weight, evidence=[ev]))


def compute_confidence(components: List[ComponentMatch], headers: Dict[str, str], cookies: List[str], favicon_hash: Optional[str]) -> float:
    """Prosty agregator pewności 0..1."""
    if not components:
        base = 0.0
        if headers.get("Server"): base += 0.2
        if cookies: base += 0.2
        if favicon_hash: base += 0.3
        return min(1.0, base)

    scores = [c.score for c in components]
    avg = sum(scores) / len(scores)
    evidence_count = sum(len(c.evidence) for c in components)
    bonus = min(0.2, 0.02 * evidence_count)
    return round(min(1.0, avg + bonus), 3)