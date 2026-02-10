from __future__ import annotations

import json
import os, sys
from pathlib import Path
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

RUNNER_RESULTS_JSON = Path("data/payloads_result.json")  
CVE_MATCHES_JSON    = Path("data/matcher_output.json")   
OUT_DIR             = Path("reports_test")              

from awsas.reporting.models import Finding, Report
from awsas.reporting.normalize import normalize_results
from awsas.reporting.cve_join import attach_cves
from awsas.reporting.html import render_html
from awsas.reporting.recommendations import generate_recommendations_for_finding

from awsas.generator.claude_client import ClaudeClient


def load_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"Brak pliku: {path.resolve()}")
    return json.loads(path.read_text(encoding="utf-8"))


def build_environment(run_output: Dict[str, Any], cve_matches: Dict[str, Any]) -> Dict[str, Any]:
    """
    'environment' = kontekst dla LLM, żeby rekomendacje były sensowne.
    Minimalnie: target, wykryte komponenty (jeśli masz), + CVE keys.
    Możesz tu dorzucić np. fingerprint summary, OS, frameworki, itd.
    """
    return {
        "target": run_output.get("base_url"),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "cve_components": list((cve_matches or {}).keys())[:50],
    }


def compute_totals(findings: List[Finding], run_output: Dict[str, Any]) -> Dict[str, Any]:
    verdict_counts = {"pass": 0, "fail": 0, "inconclusive": 0}
    risk_counts = {"high": 0, "medium": 0, "low": 0, "unknown": 0}

    for f in findings:
        v = (f.verdict or "unknown").lower().strip()
        if v not in verdict_counts:
            v = "inconclusive"
        verdict_counts[v] += 1

        r = (f.risk_level or "unknown").lower().strip()
        if r not in risk_counts:
            r = "unknown"
        risk_counts[r] += 1

    return {
        "tests_total": int(run_output.get("tests_count") or len(run_output.get("results") or [])),
        "findings_total": len(findings),
        "verdicts": verdict_counts,
        "risk_breakdown": risk_counts,
    }


def make_llm_client() -> Optional[Any]:
    """
    Wersja “plug&play”: jak masz CLAUDE_API_KEY i model, to odpala LLM.
    Jak nie masz – skip.
    """
    claude_key = os.getenv("CLAUDE_API_KEY")
    claude_model = os.getenv("CLAUDE_MODEL", "claude-sonnet-4-5-20250929")

    if claude_key:
        return ClaudeClient(api_key=claude_key, model=claude_model)

    return None


def main() -> None:
    run_output = load_json(RUNNER_RESULTS_JSON)
    matcher_output = load_json(CVE_MATCHES_JSON)
    cve_matches = (matcher_output or {}).get("results", {})

    findings: List[Finding] = normalize_results(run_output)

    attach_cves(findings, cve_matches)

    env = build_environment(run_output, cve_matches)
    llm = make_llm_client()

    if llm is None:
        print("LLM: brak klucza (CLAUDE_API_KEY / OPENAI_API_KEY) -> pomijam generowanie rekomendacji.")
    else:
        print("LLM: generuję rekomendacje dla PASS + (high/medium)...")
        for f in findings:
            if f.verdict == "pass" and f.risk_level in ("high", "medium"):
                recs = generate_recommendations_for_finding(llm, f, env)
                f.recommendations = recs

    totals = compute_totals(findings, run_output)
    report = Report(
        target=str(run_output.get("base_url") or ""),
        generated_at=datetime.now(timezone.utc).isoformat(),
        totals={
            "tests_total": totals["tests_total"],
            "findings_total": totals["findings_total"],
            "passed": totals["verdicts"]["pass"],
            "failed": totals["verdicts"]["fail"],
            "inconclusive": totals["verdicts"]["inconclusive"],
        },
        risk_breakdown=totals["risk_breakdown"],
        findings=findings,
        raw_results=run_output,
        cve_matches=cve_matches,
    )

    html = render_html(report)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out_json = OUT_DIR / "report.test.json"
    out_html = OUT_DIR / "report.test.html"

    out_json.write_text(
        json.dumps(
            {
                "target": report.target,
                "generated_at": report.generated_at,
                "totals": report.totals,
                "risk_breakdown": report.risk_breakdown,
                "cve_matches": report.cve_matches,
                "findings": [f.__dict__ for f in report.findings],
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    out_html.write_text(html, encoding="utf-8")

    print(f"OK: zapisano {out_json.resolve()}")
    print(f"OK: zapisano {out_html.resolve()}")


if __name__ == "__main__":
    main()