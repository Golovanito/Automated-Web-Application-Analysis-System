# from __future__ import annotations
import json
import os
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone

from awsas.fingerprint.detector import FingerprintDetector, TargetProfile
from awsas.cve.matcher import match_components_to_cves
from awsas.generator.payloads import generate_test_payloads
from awsas.tests.runner import run_tests
from awsas.reporting.pipeline import make_report
from awsas.reporting.writer import write_report
from awsas.generator.claude_client import ClaudeClient

def _json_dump(path: Path, obj: Any) -> None:
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")

def _components_for_matcher(profile: TargetProfile) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for c in (profile.components or []):
        out.append(
            {
                "name": getattr(c, "name", None),
                "version": getattr(c, "version", None),
                "score": getattr(c, "score", None),
            }
        )
    return out


def _build_environment(profile: TargetProfile, cve_matches: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": {
            "url": profile.url,
            "final_url": profile.final_url,
            "http_status": profile.http_status,
        },
        "components": _components_for_matcher(profile)[:50],
        "common_endpoints": profile.common_endpoints,
        "tls": profile.tls,
        "cve_keys": list((cve_matches or {}).keys())[:100],
    }

def run_full_pipeline(
    target_url: str,
    cve_db_path: str,
    out_dir: str = "runs/full",
    fingerprint_timeout: int = 10,
    dvwa_login_data: Optional[Dict[str, str]] = {
        "username": os.getenv("DVWA_USER", "admin"),
        "password": os.getenv("DVWA_PASS", "password"),
        "security": os.getenv("DVWA_SEC", "low"),
    },
    use_judge: bool = False,
) -> Dict[str, str]:
    # fingerprint -> matcher -> generator -> executor -> reporting -> save
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    # before - export CLAUDE_API_KEY="api_key" - in terminal
    gen_api_key = os.getenv("CLAUDE_API_KEY") or os.getenv("OPENAI_API_KEY")
    gen_model = os.getenv("CLAUDE_MODEL")

    rep_llm_client = None
    rep_api_key = os.getenv("CLAUDE_API_KEY")
    rep_model = os.getenv("CLAUDE_MODEL", "claude-sonnet-4-5-20250929")
    if rep_api_key:
        rep_llm_client = ClaudeClient(api_key=rep_api_key, model=rep_model)

    judge_client = None
    if use_judge and rep_api_key:
        judge_client = ClaudeClient(api_key=rep_api_key, model=rep_model)

    # fingerprint
    det = FingerprintDetector(timeout=fingerprint_timeout, dvwa_login_data=dvwa_login_data)
    profile = det.analyze(target_url)
    _json_dump(out / "fingerprint.json", profile.to_dict())

    # matcher
    components = _components_for_matcher(profile)
    cve_matches = match_components_to_cves(
        components=components,
        db_path=cve_db_path,
        limit_per_component=10,
        min_score=0.3,
    )

    cve_matches_filtered: Dict[str, List[Dict[str, Any]]] = {}
    for k, hits in (cve_matches or {}).items():
        good = [h for h in (hits or []) if (h.get("version_status") in ("vulnerable", "maybe_vulnerable"))]
        if good:
            cve_matches_filtered[k] = good
    cve_matches = cve_matches_filtered

    _json_dump(out / "cve_matches.json", cve_matches)

    # payloads generator
    payload_spec = generate_test_payloads(
        profile=profile,
        cve_matches=cve_matches,
        api_key=gen_api_key,
        model=gen_model,
    )
    _json_dump(out / "payload_spec.json", payload_spec)

    # executor
    run_output = run_tests(
        base_url=target_url,
        payload_spec=payload_spec,
        timeout=10,
        dvwa_login_data=dvwa_login_data,
        judge_client=judge_client,
        judge_on_fail=True,
        max_judge_calls=10,
    )
    _json_dump(out / "run_output.json", run_output)

    # reporting
    environment = _build_environment(profile, cve_matches)

    report = make_report(
        run_output=run_output,
        cve_matches=cve_matches,
        environment=environment,
        llm_client=rep_llm_client,   # rekomendacje w raporcie (opcjonalnie)
        use_llm=True,
    )

    # save
    paths = write_report(report, out_dir=str(out), basename="report")

    return paths


if __name__ == "__main__":
    PROJECT_ROOT = Path(__file__).resolve().parents[3]
    # provide a db source path and url of tested webapp
    DEFAULT_CVE_DB = PROJECT_ROOT / "data" / "cve_store.db"
    TARGET_URL = os.getenv("AWSAS_TARGET_URL", "http://127.0.0.1:4280/vulnerabilities/sqli/")
    CVE_DB_PATH = os.getenv("AWSAS_CVE_DB", str(DEFAULT_CVE_DB))
    OUT_DIR = os.getenv("AWSAS_OUT_DIR", "runs/full_last")

    # credentials to test on DVWA app
    DVWA = {
        "username": os.getenv("DVWA_USER", "admin"),
        "password": os.getenv("DVWA_PASS", "password"),
        "security": os.getenv("DVWA_SEC", "low"),
    }

    paths = run_full_pipeline(
        target_url=TARGET_URL,
        cve_db_path=CVE_DB_PATH,
        out_dir=OUT_DIR,
        fingerprint_timeout=10,
        dvwa_login_data=DVWA,
        use_judge=True,
    )
    print("OK:", paths)