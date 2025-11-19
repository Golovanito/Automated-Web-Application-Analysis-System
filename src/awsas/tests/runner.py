from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

import requests


@dataclass
class TestResult:
    id: str
    target_component: Optional[str]
    related_cve: Optional[str]
    risk_level: Optional[str]

    url: str
    method: str

    ok: bool
    http_status: Optional[int]
    error: Optional[str]
    indicator_found: bool

    response_snippet: Optional[str]
    notes: str = ""


def run_tests(
    base_url: str,
    payload_spec: Dict[str, Any],
    timeout: int = 10,
) -> Dict[str, Any]:
    tests = payload_spec.get("tests") or []
    if not isinstance(tests, list):
        raise ValueError("payload_spec['tests'] musi być listą")

    session = requests.Session()
    results: List[TestResult] = []

    for t in tests:
        t_id = t.get("id") or "<no-id>"
        comp = t.get("target_component")
        cve = t.get("related_cve")
        risk = t.get("risk_level")

        req = t.get("http_request") or {}
        method = (req.get("method") or "GET").upper()
        path = req.get("path") or "/"
        headers = req.get("headers") or {}
        body = req.get("body")

        expected_indicator = (t.get("expected_indicator") or "").strip()

        full_url = urljoin(base_url, path)

        http_status: Optional[int] = None
        indicator_found = False
        error: Optional[str] = None
        snippet: Optional[str] = None
        ok = False

        try:
            resp = session.request(
                method=method,
                url=full_url,
                headers=headers,
                data=body if isinstance(body, (str, bytes)) else None,
                timeout=timeout,
                allow_redirects=True,
            )
            http_status = resp.status_code
            text = resp.text or ""
            snippet = text[:2000]

            if expected_indicator:
                indicator_found = expected_indicator in text
                ok = indicator_found
            else:
                # Jeśli nie zdefiniowano indicatora, traktuj test jako „wykonany”,
                # ale niekoniecznie pozytywny/negatywny.
                ok = http_status is not None and http_status < 500
        except Exception as e:
            error = str(e)
            ok = False

        results.append(
            TestResult(
                id=t_id,
                target_component=comp,
                related_cve=cve,
                risk_level=risk,
                url=full_url,
                method=method,
                ok=ok,
                http_status=http_status,
                error=error,
                indicator_found=indicator_found,
                response_snippet=snippet,
            )
        )

    return {
        "base_url": base_url,
        "tests_count": len(results),
        "results": [asdict(r) for r in results],
    }