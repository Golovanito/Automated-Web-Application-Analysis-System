import json
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional, Any
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urlunparse

import requests

from .http_probe import (
    safe_request,
    parse_html,
    extract_forms,
    extract_paths,
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
    forms: List[Dict[str, Any]] = field(default_factory=list)
    discovered_paths: List[str] = field(default_factory=list)
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
    def __init__(
        self,
        user_agent: Optional[str] = None,
        timeout: int = 10,
        dvwa_login_data: Optional[Dict[str, str]] = None,
    ):
        self.timeout = timeout
        self.session = requests.Session()
        self.dvwa_login_data = dvwa_login_data or {}
        self.session.headers.update({
            "User-Agent": user_agent or "awsas-fp/1.0 FingerprintDetector"
        })

    # helpers to login in DVWA

    def _dvwa_login(self, base_url: str) -> bool:
        login_url = base_url.rstrip("/") + "/login.php"

        r = self.session.get(login_url, timeout=self.timeout, allow_redirects=True)
        token = None
        try:
            soup = BeautifulSoup(r.text, "html.parser")
            hidden = soup.find("input", {"name": "user_token"})
            if hidden and hidden.get("value"):
                token = hidden["value"]
        except Exception:
            pass

        data = {
            "username": self.dvwa_login_data.get("username", "admin"),
            "password": self.dvwa_login_data.get("password", "password"),
            "Login": "Login",
        }
        if token:
            data["user_token"] = token

        r2 = self.session.post(login_url, data=data, timeout=self.timeout, allow_redirects=True)

        test = self.session.get(base_url, timeout=self.timeout, allow_redirects=True)
        logged_in = "login.php" not in test.url

    def _dvwa_set_security(self, base_url: str, level: str = "low") -> None:
        url = base_url.rstrip("/") + "/security.php"
        data = {
            "security": level,
            "seclev_submit": "Submit"
        }
        r = self.session.post(url, data=data, timeout=self.timeout, allow_redirects=True)
        # print(f"DVWA security set to {level}, status={getattr(r, 'status_code', '?')}")

    def analyze(self, url: str) -> TargetProfile:
        profile = TargetProfile(url=url)


        parsed = urlparse(url)
        base_root = urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))

        if self.dvwa_login_data:
            try:
                self._dvwa_login(base_root)
                self._dvwa_set_security(base_root, self.dvwa_login_data.get("security", "low"))
            except Exception as e:
                print("DVWA login failed with exception:", e)

        head = safe_request(self.session, "HEAD", url, timeout=self.timeout)
        if head is not None:
            profile.headers = {k: v for k, v in head.headers.items()}
            profile.http_status = head.status_code
            profile.final_url = head.url
            profile.cookies = list(head.cookies.keys())

        get = safe_request(self.session, "GET", url, timeout=self.timeout)
        if get is None:
            return profile
        profile.final_url = get.url
        profile.http_status = get.status_code
        profile.headers.update({k: v for k, v in get.headers.items()})
        profile.cookies = list({*profile.cookies, *list(get.cookies.keys())})
        profile.raw_html = get.text[:200000]

        scripts, css, meta = parse_html(get.text)
        profile.scripts, profile.css, profile.meta = scripts, css, meta

        profile.forms = extract_forms(get.text)

        profile.favicon_hash = fetch_favicon_hash(
            self.session, profile.final_url, get.text, timeout=self.timeout
        )

        profile.tls = fetch_tls_info(profile.final_url)

        profile.common_endpoints = probe_common_endpoints(
            self.session, profile.final_url
        )

        profile.discovered_paths = extract_paths(
            get.text, profile.final_url or url
        )

        tls_issuer = profile.tls.get("issuer")
        profile.components = detect_components(
            headers=profile.headers,
            cookies=profile.cookies,
            scripts=profile.scripts,
            meta=profile.meta,
            favicon_hash=profile.favicon_hash,
            tls_issuer=tls_issuer,
        )

        profile.confidence_score = compute_confidence(
            profile.components, profile.headers, profile.cookies, profile.favicon_hash
        )

        return profile


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("url")
    args = p.parse_args()

    det = FingerprintDetector()
    prof = det.analyze(args.url)
    print(json.dumps(prof.to_dict(), indent=2, ensure_ascii=False))