from __future__ import annotations
from typing import Dict, Any, Optional
from .models import Report
from .normalize import build_report
from .cve_join import attach_cves
from .recommendations import generate_recommendations_for_finding


def make_report(
    run_output: Dict[str, Any],
    cve_matches: Optional[Dict[str, Any]] = None,
    environment: Optional[Dict[str, Any]] = None,
    llm_client=None,
    use_llm: bool = True,
) -> Report:
    report = build_report(run_output, cve_matches=cve_matches or {}, environment=environment or {})

    attach_cves(report.findings, report.cve_matches)

    if use_llm and llm_client is not None:
        for f in report.findings:
            if f.verdict == "pass" and f.risk_level in ("high", "medium"):
                f.recommendations = generate_recommendations_for_finding(llm_client, f, report.environment)

    return report