import hashlib
import socket
import ssl
from typing import Dict, List, Optional, Tuple, Any
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
    # Zwraca (scripts, css, meta) z podanego HTML-a
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

def extract_forms(html: str) -> List[Dict[str, Any]]:
    forms: List[Dict[str, Any]] = []
    try:
        soup = BeautifulSoup(html, "html.parser")

        # 1) Prawdziwe formularze <form>...</form>
        for f in soup.find_all("form"):
            form_info: Dict[str, Any] = {
                "kind": "form",  # normalny formularz
                "action": f.get("action") or "",
                "method": (f.get("method") or "GET").upper(),
                "inputs": [],
            }
            for inp in f.find_all(["input", "textarea", "select"]):
                form_info["inputs"].append({
                    "name": inp.get("name"),
                    "type": inp.get("type") or inp.name,
                    "id": inp.get("id"),
                    "placeholder": inp.get("placeholder"),
                })
            forms.append(form_info)

        # 2) "Sierotki" – inputy poza jakimkolwiek <form>
        orphan_inputs: List[Dict[str, Any]] = []
        for inp in soup.find_all(["input", "textarea", "select"]):
            if inp.find_parent("form"):
                continue  # już zebrane wyżej

            orphan_inputs.append({
                "name": inp.get("name"),
                "type": inp.get("type") or inp.name,
                "id": inp.get("id"),
                "placeholder": inp.get("placeholder"),
            })

        if orphan_inputs:
            forms.append(
                {
                    "kind": "orphan_inputs",
                    "action": "",
                    "method": "GET",  # domyślnie, bo nie wiemy co robi JS
                    "inputs": orphan_inputs,
                }
            )

    except Exception:
        pass

    return forms


def extract_paths(html: str, base_url: str) -> List[str]:
    paths: set[str] = set()
    try:
        soup = BeautifulSoup(html, "html.parser")
        # <a href="...">
        for a in soup.find_all("a", href=True):
            href = a["href"]
            paths.add(href)
        # <script src="..."> i <link href="...">
        for tag in soup.find_all(["script", "link"], src=True):
            paths.add(tag.get("src"))
        for tag in soup.find_all("link", href=True):
            paths.add(tag.get("href"))

    except Exception:
        pass

    cleaned: set[str] = set()
    base = urlparse(base_url)

    for p in paths:
        if not p:
            continue
        # ignorujemy absolutne zewnętrzne (inne hosty)
        full = urljoin(base_url, p)
        parsed = urlparse(full)
        if parsed.netloc != base.netloc:
            continue
        # interesuje nas tylko path + ewentualny fragment api
        cleaned.add(parsed.path)

    return sorted(cleaned)


def discover_favicon_url(final_url: str, html: Optional[str]) -> str:
    #Znajduje URL do favicona: <link rel='icon'> albo /favicon.ico.
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
    # Pobiera podstawowe info TLS (tylko dla https). 
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


COMMON_ENDPOINTS = ["/admin", "/login", "/server-status", "/api/version", "/robots.txt", "/signin", "/logout", "/register"]

def probe_common_endpoints(session: requests.Session, base_url: str, timeout: int = 5) -> Dict[str, int]:
    results: Dict[str, int] = {}
    for ep in COMMON_ENDPOINTS:
        full = urljoin(base_url, ep)
        r = safe_request(session, "HEAD", full, timeout=timeout)
        results[ep] = r.status_code if r is not None else -1
    return results