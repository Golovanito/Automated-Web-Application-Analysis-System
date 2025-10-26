import hashlib
import socket
import ssl
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup


def sha1_bytes(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()


def safe_request(session: requests.Session, method: str, url: str, timeout: int = 10, **kwargs):
    try:
        return session.request(method, url, timeout=timeout, allow_redirects=True, **kwargs)
    except Exception:
        return None


def parse_html(html: str) -> Tuple[List[str], List[str], Dict[str, str]]:
    """Zwraca (scripts, css, meta) z podanego HTML-a."""
    scripts, css, metas = [], [], {}
    try:
        soup = BeautifulSoup(html, "html.parser")
        # scripts
        for s in soup.find_all("script", src=True):
            scripts.append(s["src"])
        # css
        for l in soup.find_all("link", rel=True):
            rel = l.get("rel")
            if isinstance(rel, list) and "stylesheet" in rel:
                href = l.get("href")
                if href:
                    css.append(href)
        # meta
        for m in soup.find_all("meta"):
            name = m.get("name") or m.get("property") or m.get("http-equiv")
            content = m.get("content")
            if name and content:
                metas[name.lower()] = content
    except Exception:
        pass
    return scripts, css, metas


def discover_favicon_url(final_url: str, html: Optional[str]) -> str:
    """Znajduje URL do favicona: <link rel='icon'> albo /favicon.ico."""
    favicon_url = urljoin(final_url, "/favicon.ico")
    if not html:
        return favicon_url
    try:
        soup = BeautifulSoup(html, "html.parser")
        icon_link = soup.find("link", rel=lambda x: x and "icon" in x.lower())
        if icon_link and icon_link.get("href"):
            href = icon_link["href"]
            favicon_url = href if href.startswith("http") else urljoin(final_url, href)
    except Exception:
        pass
    return favicon_url


def fetch_favicon_hash(session: requests.Session, final_url: str, html: Optional[str], timeout: int = 10) -> Optional[str]:
    try:
        fav_url = discover_favicon_url(final_url, html)
        r = safe_request(session, "GET", fav_url, timeout=timeout)
        if r is not None and r.status_code == 200 and r.content:
            return sha1_bytes(r.content)
    except Exception:
        pass
    return None


def fetch_tls_info(url: str, timeout: float = 5.0) -> Dict[str, str]:
    """Pobiera podstawowe info TLS (tylko dla https)."""
    info: Dict[str, str] = {}
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        return info
    hostname = parsed.hostname
    port = parsed.port or 443
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                def flatten_name(x):
                    parts = []
                    for t in x or ():
                        for k, v in t:
                            parts.append(f"{k}={v}")
                    return ", ".join(parts)

                info["subject"] = flatten_name(cert.get("subject"))
                info["issuer"] = flatten_name(cert.get("issuer"))
                if cert.get("notBefore"): info["not_before"] = cert["notBefore"]
                if cert.get("notAfter"):  info["not_after"]  = cert["notAfter"]
                if cert.get("serialNumber"): info["serial"] = cert["serialNumber"]
    except Exception as e:
        info["error"] = str(e)
    return info


COMMON_ENDPOINTS = ["/admin", "/login", "/server-status", "/api/version", "/robots.txt"]

def probe_common_endpoints(session: requests.Session, base_url: str, timeout: int = 5) -> Dict[str, int]:
    results: Dict[str, int] = {}
    for ep in COMMON_ENDPOINTS:
        full = urljoin(base_url, ep)
        r = safe_request(session, "HEAD", full, timeout=timeout)
        results[ep] = r.status_code if r is not None else -1
    return results