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
        check_indicator = (t.get("check_indicator") or "").strip()
        check_regex = (t.get("check_regex") or "").strip()
        expected_status = t.get("expected_status")  # może być int lub None

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

            # --- SPRAWDZANIE STATUSU ---
            status_ok = True
            if isinstance(expected_status, int):
                status_ok = (http_status == expected_status)

            # --- SPRAWDZANIE TREŚCI ---
            text_ok = True
            indicator_found = False

            # 1) regex ma pierwszeństwo
            if check_regex:
                try:
                    import re
                    if re.search(check_regex, text):
                        indicator_found = True
                        text_ok = True
                    else:
                        text_ok = False
                except re.error:
                    # jak regex zły – traktujemy jak brak dopasowania
                    text_ok = False

            # 2) prosty substring
            elif check_indicator:
                indicator_found = check_indicator in text
                text_ok = indicator_found

            # 3) fallback: krótki expected_indicator jako substring
            elif expected_indicator and len(expected_indicator) < 120:
                indicator_found = expected_indicator in text
                text_ok = indicator_found

            # 4) jeśli nie mamy żadnego checka – test tylko „wykonany”
            else:
                text_ok = True  # nie wiemy, więc nie psujemy wyniku

            ok = status_ok and text_ok

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