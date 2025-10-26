# Test - raczej uzyje wersji modularnej

import hashlib
import json
import socket
import ssl
import time
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional, Tuple

import requests
from bs4 import BeautifulSoup


# Data structures

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
        # Convert dataclasses to serializable dict
        d = asdict(self)
        # simplify Evidence objects
        for comp in d.get("components", []):
            comp["evidence"] = [
                {"type": e["type"], "value": e["value"], "weight": e["weight"]}
                for e in comp["evidence"]
            ]
        return d


# Helper units

COMMON_ENDPOINTS = ["/admin", "/login", "/server-status", "/api/version", "/robots.txt"]


def sha1_bytes(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()


def safe_request(session: requests.Session, method: str, url: str, timeout: int = 10, **kwargs):
    try:
        resp = session.request(method, url, timeout=timeout, allow_redirects=True, **kwargs)
        return resp
    except Exception as e:
        return None


def fetch_tls_info(hostname: str, port: int = 443, timeout: float = 5.0) -> Dict[str, str]:
    info = {}
    try:
        ctx = ssl.create_default_context()
        # do not verify to still get peer cert even if invalid
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                # cert is a dict
                subject = cert.get("subject", ())
                issuer = cert.get("issuer", ())
                not_before = cert.get("notBefore")
                not_after = cert.get("notAfter")
                # Simplify subject/issuer
                def flatten_name(x):
                    parts = []
                    for t in x:
                        for k, v in t:
                            parts.append(f"{k}={v}")
                    return ", ".join(parts)

                info["subject"] = flatten_name(subject) if subject else ""
                info["issuer"] = flatten_name(issuer) if issuer else ""
                if not_before:
                    info["not_before"] = not_before
                if not_after:
                    info["not_after"] = not_after
                # include raw cert serial if present
                serial = cert.get("serialNumber")
                if serial:
                    info["serial"] = serial
    except Exception as e:
        # keep info empty or partial
        info["error"] = str(e)
    return info


# Fingerprint detector

class FingerprintDetector:
    def __init__(self, user_agent: Optional[str] = None, timeout: int = 10):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": user_agent
                or "awsas-fp/1.0 (+https://example.local) FingerprintDetector"
            }
        )

    def analyze(self, url: str, use_headless: bool = False) -> TargetProfile:
        """
        Analyze target URL and return TargetProfile
        - use_headless: reserved; if True and Playwright installed, will render the page with JS
        """
        profile = TargetProfile(url=url)

        # HEAD request to get quick headers
        head = safe_request(self.session, "HEAD", url, timeout=self.timeout)
        if head is not None:
            profile.headers = {k: v for k, v in head.headers.items()}
            profile.http_status = head.status_code
            profile.final_url = head.url
            profile.cookies = list(head.cookies.keys())
        else:
            # sometimes server blocks HEAD; proceed with GET
            pass

        # GET request (HTML)
        get = safe_request(self.session, "GET", url, timeout=self.timeout)
        if get is None:
            # unreachable or timed out
            profile.http_status = None
            return profile

        profile.final_url = get.url
        profile.http_status = get.status_code
        profile.headers = {**profile.headers, **{k: v for k, v in get.headers.items()}}
        # cookies from GET
        profile.cookies = list({*profile.cookies, *list(get.cookies.keys())})
        profile.raw_html = get.text[:200000]  # cap size stored

        # parse HTML for scripts, css, meta
        try:
            soup = BeautifulSoup(get.text, "html.parser")
            # scripts
            scripts = []
            for s in soup.find_all("script", src=True):
                scripts.append(s["src"])
            profile.scripts = scripts

            # css
            css = []
            for l in soup.find_all("link", rel=True):
                rel = l.get("rel")
                if isinstance(rel, list) and "stylesheet" in rel:
                    href = l.get("href")
                    if href:
                        css.append(href)
            profile.css = css

            # meta tags
            metas = {}
            for m in soup.find_all("meta"):
                name = m.get("name") or m.get("property") or m.get("http-equiv")
                content = m.get("content")
                if name and content:
                    metas[name.lower()] = content
            profile.meta = metas
        except Exception:
            # parsing error -> leave lists empty
            pass

        # fetch favicon
        favicon_hash = None
        try:
            # attempt to locate favicon: common locations or link rel
            favicon_url = None
            soup = BeautifulSoup(get.text, "html.parser")
            icon_link = soup.find("link", rel=lambda x: x and "icon" in x.lower())
            if icon_link and icon_link.get("href"):
                href = icon_link["href"]
                if href.startswith("http"):
                    favicon_url = href
                else:
                    # build absolute
                    favicon_url = requests.compat.urljoin(profile.final_url, href)
            else:
                # fallback default at /favicon.ico
                base = requests.compat.urljoin(profile.final_url, "/favicon.ico")
                favicon_url = base

            fav_resp = safe_request(self.session, "GET", favicon_url, timeout=self.timeout)
            if fav_resp is not None and fav_resp.status_code == 200:
                favicon_hash = sha1_bytes(fav_resp.content)
                profile.favicon_hash = favicon_hash
        except Exception:
            pass

        # TLS cert info (extract hostname from URL)
        try:
            parsed = requests.utils.urlparse(profile.final_url or url)
            hostname = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            if parsed.scheme == "https":
                tls_info = fetch_tls_info(hostname, port)
                profile.tls = tls_info
        except Exception:
            pass

        # common endpoints probing (HEAD to reduce side effects)
        ce = {}
        for ep in COMMON_ENDPOINTS:
            try:
                full = requests.compat.urljoin(profile.final_url, ep)
                r = safe_request(self.session, "HEAD", full, timeout=5)
                if r is None:
                    ce[ep] = -1
                else:
                    ce[ep] = r.status_code
            except Exception:
                ce[ep] = -1
        profile.common_endpoints = ce

        # simple component detection heuristics (rule-based)
        profile.components = self._detect_components(profile)

        # compute confidence score (aggregate)
        profile.confidence_score = self._compute_confidence(profile)

        return profile

    def _detect_components(self, profile: TargetProfile) -> List[ComponentMatch]:
        """
        Very simple rule-based detection:
        - look for meta generator
        - look for known script patterns
        - cookie names
        - server header
        - favicon hash (would require local dictionary; here we check examples)
        """
        matches: List[ComponentMatch] = []

        evidence: List[Evidence] = []

        # meta generator
        gen = profile.meta.get("generator")
        if gen:
            # e.g. "WordPress 5.8.1"
            parts = gen.split()
            name = parts[0]
            version = parts[1] if len(parts) > 1 else None
            ev = Evidence(type="meta_generator", value=gen, weight=1.0)
            cm = ComponentMatch(name=name, version=version, score=1.0, evidence=[ev])
            matches.append(cm)

        # cookie hints
        cookie_map = {
            "PHPSESSID": ("PHP", None, 0.6),
            "JSESSIONID": ("Java", None, 0.6),
            "laravel_session": ("Laravel", None, 0.7),
            "csrftoken": ("Django", None, 0.7),
            "wordpress_logged_in": ("WordPress", None, 0.9),
        }
        for c in profile.cookies:
            if c in cookie_map:
                name, version, weight = cookie_map[c]
                ev = Evidence(type="cookie", value=c, weight=weight)
                # try to append to existing component evidence
                found = next((m for m in matches if m.name.lower() == name.lower()), None)
                if found:
                    found.evidence.append(ev)
                    found.score = min(1.0, found.score + weight * 0.5)
                else:
                    matches.append(ComponentMatch(name=name, version=version, score=weight, evidence=[ev]))

        # server header
        server = profile.headers.get("Server")
        if server:
            # basic normalization
            srv = server.split("/")[0]
            ev = Evidence(type="server_header", value=server, weight=0.3)
            found = next((m for m in matches if m.name.lower() == srv.lower()), None)
            if found:
                found.evidence.append(ev)
                found.score = min(1.0, found.score + 0.3)
            else:
                matches.append(ComponentMatch(name=srv, version=None, score=0.3, evidence=[ev]))

        # scripts heuristics (example jQuery)
        for s in profile.scripts:
            if "jquery" in s.lower():
                # try to parse version from filename
                import re

                m = re.search(r"jquery[-\.]?(\d+\.\d+(\.\d+)?)", s, re.IGNORECASE)
                ver = m.group(1) if m else None
                ev = Evidence(type="script", value=s, weight=0.8)
                found = next((m for m in matches if m.name.lower() == "jquery"), None)
                if found:
                    found.evidence.append(ev)
                    found.score = min(1.0, found.score + 0.8)
                else:
                    matches.append(ComponentMatch(name="jQuery", version=ver, score=0.8, evidence=[ev]))

        # favicon examples (very small sample)
        favicon_map = {
            # example hash -> (name, weight)
            # 'd0f7f3...': ('phpMyAdmin', 0.95),
        }
        if profile.favicon_hash and profile.favicon_hash in favicon_map:
            name, weight = favicon_map[profile.favicon_hash]
            ev = Evidence(type="favicon_hash", value=profile.favicon_hash, weight=weight)
            matches.append(ComponentMatch(name=name, version=None, score=weight, evidence=[ev]))

        # TLS issuer hints (e.g. Let's Encrypt shows issuer)
        issuer = profile.tls.get("issuer", "")
        if "Let's Encrypt" in issuer or "Let's Encrypt" in profile.tls.get("issuer", ""):
            ev = Evidence(type="tls_issuer", value=issuer, weight=0.2)
            matches.append(ComponentMatch(name="LetsEncrypt", version=None, score=0.2, evidence=[ev]))

        # normalize names and combine duplicates (merge same name)
        combined: Dict[str, ComponentMatch] = {}
        for m in matches:
            key = m.name.lower()
            if key in combined:
                existing = combined[key]
                # merge evidence and take max version if present
                existing.evidence.extend(m.evidence)
                existing.score = min(1.0, max(existing.score, m.score))
                if not existing.version and m.version:
                    existing.version = m.version
            else:
                combined[key] = m
        return list(combined.values())

    def _compute_confidence(self, profile: TargetProfile) -> float:
        """
        Simple aggregator: average of component scores weighted by evidence count,
        plus bonuses for strong evidence (meta_generator, favicon).
        Result normalized to 0..1
        """
        comp_scores = [c.score for c in profile.components] if profile.components else []
        if not comp_scores:
            # fallback: use header/cookie hints
            base = 0.0
            if profile.headers.get("Server"):
                base += 0.2
            if profile.cookies:
                base += 0.2
            if profile.favicon_hash:
                base += 0.3
            return min(1.0, base)

        avg = sum(comp_scores) / len(comp_scores)
        # evidence richness bonus
        evidence_count = sum(len(c.evidence) for c in profile.components)
        bonus = min(0.2, 0.02 * evidence_count)
        score = min(1.0, avg + bonus)
        return round(score, 3)


# Test
if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser()
    p.add_argument("url", help="Target URL to fingerprint")
    p.add_argument("--headless", action="store_true", help="Use headless browser for JS rendering (optional)")
    args = p.parse_args()

    det = FingerprintDetector()
    prof = det.analyze(args.url, use_headless=args.headless)
    print(json.dumps(prof.to_dict(), indent=2, ensure_ascii=False))