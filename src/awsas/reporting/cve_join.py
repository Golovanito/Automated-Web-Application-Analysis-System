from __future__ import annotations
from typing import Dict, List, Any
from .models import Finding

SKIP_KEYWORDS = (
    "sql injection",
    "xss",
    "csrf",
    "lfi",
    "rfi",
    "directory traversal",
    "command injection",
    "open redirect",
    "ssrf",
    "xxe",
    "idor",
)


def attach_cves(findings: List[Finding], cve_matches: Dict[str, List[Dict[str, Any]]]) -> None:
    if not cve_matches:
        return

    for f in findings:
        title_l = (f.title or "").lower()
        if any(k in title_l for k in SKIP_KEYWORDS):
            continue

        hits: List[Dict[str, Any]] = []
        for comp_key, comp_hits in cve_matches.items():
            if not comp_key:
                continue
            if comp_key.lower() in title_l:
                hits.extend((comp_hits or [])[:5])

        # sanitize
        out = []
        for h in hits[:5]:
            out.append(
                {
                    "cve_id": h.get("cve_id"),
                    "score": h.get("score"),
                    "version_status": h.get("version_status"),
                    "description": (h.get("description") or "")[:240],
                }
            )
        f.related_cves = out