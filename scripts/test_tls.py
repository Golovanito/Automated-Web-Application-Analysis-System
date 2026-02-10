import hashlib
import socket
import ssl
from typing import Dict, List, Optional, Tuple, Any
from urllib.parse import urljoin, urlparse


def fetch_tls_info(url: str, timeout: float = 5.0) -> Dict[str, str]:
    info: Dict[str, str] = {}
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        return info
    hostname = parsed.hostname
    port = parsed.port or 443
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
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

print(fetch_tls_info("https://boscaiola.eu"))