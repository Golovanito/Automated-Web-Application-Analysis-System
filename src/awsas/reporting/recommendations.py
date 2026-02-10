from __future__ import annotations
import json
import re
from typing import List, Dict, Any
from .models import Finding

SYSTEM = (
    "You are a cybersecurity expert writing remediation recommendations.\n"
    "Return ONLY valid JSON (no markdown).\n"
    "Schema: { \"recommendations\": [\"...\"] }\n"
)

FALLBACK_BULLET_RE = re.compile(r"^\s*(?:-|\*|\d+\.)\s+(.+)$")


def _strip_fences(raw: str) -> str:
    raw = raw.strip()
    raw = re.sub(r"^```[a-zA-Z0-9]*\s*", "", raw)
    raw = re.sub(r"\s*```$", "", raw).strip()
    return raw


def build_user_payload(f: Finding, environment: Dict[str, Any]) -> str:
    data = {
        "finding": {
            "title": f.title,
            "risk_level": f.risk_level,
            "url": f.url,
            "method": f.method,
            "verdict": f.verdict,
            "http_status": f.http_status,
            "evidence_snippet": (f.evidence_snippet or "")[:800],
            "notes": (f.notes or "")[:500],
            "related_cves": [
                {
                    "cve_id": c.get("cve_id"),
                    "score": c.get("score"),
                    "version_status": c.get("version_status"),
                    "description": (c.get("description") or "")[:200],
                }
                for c in (f.related_cves or [])[:5]
            ],
        },
        "environment": environment,
        "rules": [
            "Give 4–6 practical, actionable remediation steps.",
            "Each step should be 1–2 sentences.",
            "Do not mention DVWA, labs, pentest tools, or 'as an AI'.",
            "Do not suggest disabling security mechanisms.",
            "Prefer code-level + config-level fixes (validation, encoding, parameterized queries, allowlists).",
            "If CVEs exist, include upgrade/patch guidance (vendor-agnostic if possible).",
        ],
    }
    return json.dumps(data, ensure_ascii=False)


def _fallback_parse_list(raw: str) -> List[str]:
    lines = (raw or "").splitlines()
    out: List[str] = []
    for ln in lines:
        m = FALLBACK_BULLET_RE.match(ln)
        if m:
            item = m.group(1).strip()
            if item:
                out.append(item)
    return out[:8]


def generate_recommendations_for_finding(llm_client, f: Finding, environment: Dict[str, Any]) -> List[str]:
    blocks = [
        {"role": "system", "content": [{"type": "input_text", "text": SYSTEM}]},
        {"role": "user", "content": [{"type": "input_text", "text": build_user_payload(f, environment)}]},
    ]

    raw = llm_client.generate(blocks)
    raw = _strip_fences(raw)

    try:
        obj = json.loads(raw)
        recs = obj.get("recommendations") or []
        clean = [str(x).strip() for x in recs if str(x).strip()]
        return clean[:8]
    except Exception:
        # fallback: spróbuj wyłuskać listę
        fb = _fallback_parse_list(raw)
        return fb