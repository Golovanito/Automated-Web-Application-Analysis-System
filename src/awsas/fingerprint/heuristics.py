import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any

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

VERSION_RE = re.compile(r"(\d+\.\d+(?:\.\d+)?)")

def _extract_version_from_url(url: str) -> Optional[str]:
    if not url:
        return None
    m = VERSION_RE.search(url)
    return m.group(1) if m else None


# (opcjonalnie) słownik faviconów → komponent
FAVICON_MAP: Dict[str, tuple[str, float]] = {
    "5bcd3dcee985cc21b7ab00a153d6e5d60c7ccf22": ("WordPress", 0.9),
    "31d5f6c8a4fbdc9e66f11b9d0e779d85b6a7c1e9": ("phpMyAdmin", 0.95),
    "9c7b53da122ed1c8849b458a20d6d2c81a5c35e0": ("Jenkins", 0.9),
    "4a3c1dfb799d56a0c4b73e62a5ec44ed743f1a42": ("Grafana", 0.95),
    "f41c1dcda1e19f7363b82b29252f9b3b87d5a5bb": ("Kibana", 0.9),
    "f90e5f7718f30ffdd601c5ef8f8ce2d8a10c2c1f": ("SonarQube", 0.9),
}

COOKIE_HINTS = {
    "PHPSESSID": ("PHP", None, 0.6),
    "JSESSIONID": ("Java", None, 0.6),
    "laravel_session": ("Laravel", None, 0.7),
    "csrftoken": ("Django", None, 0.7),
    "wordpress_logged_in": ("WordPress", None, 0.9),
}

# Proste wzorce do wykrywania popularnych bibliotek JS/CSS po src/href
SCRIPT_LIB_HINTS = [
    # name, substring/regex (lowercase), weight
    ("jQuery", r"jquery(\.min)?\.js", 0.8),
    ("React", r"react(\.production)?(\.min)?\.js", 0.6),
    ("Vue", r"vue(\.runtime)?(\.min)?\.js", 0.6),
    ("AngularJS", r"angular(\.min)?\.js", 0.6),
    ("Bootstrap", r"bootstrap(\.min)?\.js", 0.5),
    ("WordPress", r"/wp-includes/", 0.9),
    ("WordPress", r"/wp-content/", 0.8),
    ("WordPress", r"wp-emoji-release\.min\.js", 0.9),
]

HEADER_HINTS = [
    # Backend z wersją
    ("PHP",      r"\bX-Powered-By:\s*PHP/?(?P<ver>[\d\.]+)?",         0.8),
    ("Express",  r"\bX-Powered-By:\s*Express/?(?P<ver>[\d\.]+)?",     1.0),
    ("ASP.NET",  r"\bX-Powered-By:\s*ASP\.NET/?(?P<ver>[\d\.]+)?",    0.7),
    ("Apache",   r"\bServer:\s*Apache/?(?P<ver>[\d\.]+)?",            0.5),
    ("nginx",    r"\bServer:\s*nginx/?(?P<ver>[\d\.]+)?",             0.5),
]

def detect_components(
    headers: Dict[str, str],
    cookies: List[str],
    scripts: List[str],
    meta: Dict[str, str],
    favicon_hash: Optional[str],
    tls_issuer: Optional[str],
) -> List[ComponentMatch]:

    matches: List[ComponentMatch] = []

    # 1) meta generator
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
    if headers:
        header_blob = " ".join(f"{k}: {v}" for k, v in headers.items())
        for name, pattern, w in HEADER_HINTS:
            m = re.search(pattern, header_blob, re.IGNORECASE)
            if m:
                ver = m.groupdict().get("ver")
                ev = Evidence("header", m.group(0), w)
                _append_match(matches, name, ver, w, ev)

        # zachowaj prosty generic fallback na Server, jeśli nie zadziałały powyższe
        server = headers.get("Server")
        if server:
            srv = server.split("/")[0]
            ev = Evidence("server_header", server, 0.2)
            _append_match(matches, srv, None, 0.2, ev)

    # 4) scripts heuristics (np. jQuery)
    for s in scripts:
        s_l = s.lower()
        for name, pattern, w in SCRIPT_LIB_HINTS:
            if re.search(pattern, s_l):
                ver = _extract_version_from_url(s)
                ev = Evidence("script", s, w)
                _append_match(matches, name, ver, w, ev)


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