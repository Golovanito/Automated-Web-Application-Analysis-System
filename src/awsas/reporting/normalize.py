from __future__ import annotations
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from .models import Finding, Report

def _risk_key(r: str) -> str:
    r = (r or "").lower().strip()
    return r if r in ("high", "medium", "low") else "unknown"


def verdict_from_testresult(tr: Dict[str, Any]) -> str:
    if tr.get("ok") is True:
        return "pass"
    notes = (tr.get("notes") or "").lower()
    if "inconclusive" in notes:
        return "inconclusive"
    return "fail"


def normalize_results(run_output: Dict[str, Any]) -> List[Finding]:
    findings: List[Finding] = []
    for r in run_output.get("results", []) or []:
        findings.append(
            Finding(
                test_id=r.get("id", "") or "",
                title=r.get("target_component") or r.get("id", "") or "Finding",
                risk_level=_risk_key(r.get("risk_level") or "unknown"),
                url=r.get("url", "") or "",
                method=(r.get("method") or "GET").upper(),
                verdict=verdict_from_testresult(r),
                http_status=r.get("http_status"),
                evidence_snippet=((r.get("response_snippet") or "")[:900]).strip(),
                notes=(r.get("notes") or "").strip(),
            )
        )
    return findings


def build_report(
    run_output: Dict[str, Any],
    cve_matches: Optional[Dict[str, List[Dict[str, Any]]]] = None,
    environment: Optional[Dict[str, Any]] = None,
) -> Report:
    findings = normalize_results(run_output)

    totals = {"pass": 0, "fail": 0, "inconclusive": 0}
    risk = {"high": 0, "medium": 0, "low": 0, "unknown": 0}

    for f in findings:
        totals[f.verdict] = totals.get(f.verdict, 0) + 1
        rk = _risk_key(f.risk_level)
        risk[rk] = risk.get(rk, 0) + 1

    return Report(
        target=run_output.get("base_url") or "",
        generated_at=datetime.now(timezone.utc).isoformat(),
        totals=totals,
        risk_breakdown=risk,
        findings=findings,
        raw_results=run_output,
        cve_matches=cve_matches or {},
        environment=environment or {},
    )