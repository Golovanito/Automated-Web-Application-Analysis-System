import json
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional

import requests

from .http_probe import (
    safe_request,
    parse_html,
    fetch_favicon_hash,
    fetch_tls_info,
    probe_common_endpoints,
)
from .heuristics import ComponentMatch, Evidence, compute_confidence, detect_components


@dataclass
class TargetProfile:
    url: str
    final_url: Optional[str] = None
    http_status: Optional[int] = None
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: List[str] = field(default_factory=list)
    favicon_hash: Optional[str] = None
    scripts: List[str] = field(default_factory=list)
    css: List[str] = field(default_factory=list)
    meta: Dict[str, str] = field(default_factory=dict)
    tls: Dict[str, str] = field(default_factory=dict)
    common_endpoints: Dict[str, int] = field(default_factory=dict)
    components: List[ComponentMatch] = field(default_factory=list)
    confidence_score: float = 0.0
    raw_html: Optional[str] = None

    def to_dict(self):
        d = asdict(self)
        # Evidence → dict
        for comp in d.get("components", []):
            comp["evidence"] = [
                {"type": e["type"], "value": e["value"], "weight": e["weight"]}
                for e in comp["evidence"]
            ]
        return d


class FingerprintDetector:
    def __init__(self, user_agent: Optional[str] = None, timeout: int = 10):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": user_agent or "awsas-fp/1.0 FingerprintDetector"
        })

    def analyze(self, url: str) -> TargetProfile:
        profile = TargetProfile(url=url)

        # 1) HEAD
        head = safe_request(self.session, "HEAD", url, timeout=self.timeout)
        if head is not None:
            profile.headers = {k: v for k, v in head.headers.items()}
            profile.http_status = head.status_code
            profile.final_url = head.url
            profile.cookies = list(head.cookies.keys())

        # 2) GET
        get = safe_request(self.session, "GET", url, timeout=self.timeout)
        if get is None:
            return profile
        profile.final_url = get.url
        profile.http_status = get.status_code
        profile.headers.update({k: v for k, v in get.headers.items()})
        profile.cookies = list({*profile.cookies, *list(get.cookies.keys())})
        profile.raw_html = get.text[:200000]

        # 3) Parse HTML
        scripts, css, meta = parse_html(get.text)
        profile.scripts, profile.css, profile.meta = scripts, css, meta

        # 4) Favicon
        profile.favicon_hash = fetch_favicon_hash(self.session, profile.final_url, get.text, timeout=self.timeout)

        # 5) TLS
        profile.tls = fetch_tls_info(profile.final_url)

        # 6) Common endpoints
        profile.common_endpoints = probe_common_endpoints(self.session, profile.final_url)

        # 7) Heuristics → components
        tls_issuer = profile.tls.get("issuer")
        profile.components = detect_components(
            headers=profile.headers,
            cookies=profile.cookies,
            scripts=profile.scripts,
            meta=profile.meta,
            favicon_hash=profile.favicon_hash,
            tls_issuer=tls_issuer,
        )

        # 8) Confidence
        profile.confidence_score = compute_confidence(profile.components, profile.headers, profile.cookies, profile.favicon_hash)

        return profile


# uruchomienie z linii komend (opcjonalnie)
if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("url")
    args = p.parse_args()

    det = FingerprintDetector()
    prof = det.analyze(args.url)
    print(json.dumps(prof.to_dict(), indent=2, ensure_ascii=False))