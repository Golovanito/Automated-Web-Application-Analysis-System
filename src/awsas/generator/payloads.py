from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any, Dict, List, Optional

from awsas.fingerprint.detector import TargetProfile
from awsas.cve.matcher import match_components_to_cves
from .openai_client import OpenAIPayloadGenerator
from .claude_client import ClaudeClient



def summarize_analysis(profile: TargetProfile, cve_matches: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
    components_summary: List[Dict[str, Any]] = []
    for comp in profile.components:
        components_summary.append(
            {
                "name": comp.name,
                "version": comp.version,
                "confidence": comp.score,
            }
        )

    cve_summary: Dict[str, List[Dict[str, Any]]] = {}
    for comp_key, hits in cve_matches.items():
        top_hits = []
        for h in hits[:5]:  # nie katujemy modelu 200 CVE na raz
            top_hits.append(
                {
                    "cve_id": h.get("cve_id"),
                    "score": h.get("score"),
                    "version_status": h.get("version_status"),
                    "description": (h.get("description") or "")[:400],
                }
            )
        cve_summary[comp_key] = top_hits

    html_snippet = (profile.raw_html or "")[:4000]

    forms_summary: List[Dict[str, Any]] = []
    for form in getattr(profile, "forms", []):
        forms_summary.append(
            {
                "method": form.get("method"),
                "action": form.get("action"),
                "inputs": [
                    {
                        "name": inp.get("name"),
                        "type": inp.get("type"),
                    }
                    for inp in form.get("inputs", [])[:20]  # max 20 pól na formularz
                ],
            }
        )
        if len(forms_summary) >= 20:  # max 20 formularzy
            break

    discovered_paths = profile.discovered_paths[:100] if profile.discovered_paths else []


    summary: Dict[str, Any] = {
        "target": {
            "url": profile.url,
            "final_url": profile.final_url,
            "http_status": profile.http_status,
        },
        "detected_components": components_summary,
        "tls": profile.tls,
        "common_endpoints": profile.common_endpoints,
        "cve_matches": cve_summary,

        "html_snippet": html_snippet,
        "forms": forms_summary,
        "discovered_paths": discovered_paths,
    }
    return summary


def build_openai_input(summary: Dict[str, Any]) -> List[Dict[str, Any]]:
    summary_json = json.dumps(summary, indent=2, ensure_ascii=False)

    system_prompt = (
        "You are a security assistant that helps generate NON-DESTRUCTIVE security test cases.\n"
        "You ONLY generate payloads and HTTP requests that can be safely used to VERIFY potential vulnerabilities\n"
        "on systems that the user is authorized to test.\n"
        "Do NOT generate guidance for data exfiltration, privilege escalation, or persistence.\n"
        "Prefer read-only requests, simple proof-of-concept checks, and clearly label each test.\n\n"
        "The output MUST be a single valid JSON object with the following shape, and nothing else:\n"
        "{\n"
        '  "tests": [\n'
        "    {\n"
        '      "id": string,\n'
        '      "target_component": string,\n'
        '      "related_cve": string | null,\n'
        '      "risk_level": "low" | "medium" | "high",\n'
        '      "description": string,\n'
        '      "http_request": {\n'
        '        "method": "GET" | "POST" | "HEAD" | "OPTIONS",\n'
        '        "path": string,\n'
        '        "headers": {string: string},\n'
        '        "body": string | null\n'
        "      },\n"
        '      "expected_indicator": string,\n'
        '      "check_indicator": string | null,\n'
        '      "check_regex": string | null,\n'
        '      "expected_status": int | null\n'
        "    }\n"
        "  ]\n"
        "}\n\n"
        "Semantics:\n"
        "- expected_indicator: human-readable description of what a positive result looks like (for reports).\n"
        "- check_indicator: a SHORT literal substring to search for in the HTTP response body for PASS.\n"
        "  Example: \"alert('jq-xss')\", \"<title>Apache Status</title>\", \"PHP Version\".\n"
        "- check_regex: OPTIONAL simple regex to match in the response body (use only if substring is not enough).\n"
        "- expected_status: OPTIONAL HTTP status code that indicates a positive result (e.g. 200, 403).\n\n"
        "Rules:\n"
        "- At least one of check_indicator, check_regex, expected_status MUST be non-null for each test.\n"
        "- check_indicator MUST be a short, concrete string that can reasonably appear verbatim in the response.\n"
        "- Do NOT put long explanations into check_indicator or check_regex – explanations go into expected_indicator.\n"
        "- Do NOT include any explanatory prose outside of the JSON. The entire response must be valid JSON.\n"
    )

    user_prompt = (
        "Below is the result of an automated security analysis of a web application.\n"
        "Based on these findings, generate a small set (3–10) of safe security test cases\n"
        "that can help verify whether the suspected vulnerabilities are actually present.\n"
        "Focus on issues that are likely relevant given the components and CVE candidates.\n\n"
        "=== ANALYSIS SUMMARY (JSON) ===\n"
        f"{summary_json}\n"
    )

    return [
        {
            "role": "system",
            "content": [
                {
                    "type": "input_text",
                    "text": system_prompt,
                }
            ],
        },
        {
            "role": "user",
            "content": [
                {
                    "type": "input_text",
                    "text": user_prompt,
                }
            ],
        },
    ]

def _strip_markdown_fence(raw: str) -> str:
    raw = raw.strip()
    # zaczyna się od ``` coś
    if raw.startswith("```"):
        # utnij pierwszą linię z ```json albo ``` 
        first_nl = raw.find("\n")
        if first_nl != -1:
            raw = raw[first_nl + 1 :]
        # utnij końcowe ```
        if raw.endswith("```"):
            raw = raw[: -3]
    return raw.strip()

def generate_test_payloads(
    profile: TargetProfile,
    cve_matches: Dict[str, List[Dict[str, Any]]],
    api_key: Optional[str] = None,
    model: Optional[str] = None,
    # model: str = "openai/gpt-4o",
) -> Dict[str, Any]:
    summary = summarize_analysis(profile, cve_matches)
    input_blocks = build_openai_input(summary)

    # client = OpenAIPayloadGenerator(api_key=api_key, model=model)
    client = ClaudeClient(api_key=api_key, model=model)
    raw = client.generate(input_blocks)

    cleaned = _strip_markdown_fence(raw)

    try:
        return json.loads(cleaned)
    except Exception:
        # Jak model zwróci coś nie-JSON (np. dopisze komentarz),
        # nie rozwalamy programu – użytkownik dostanie raw output.
        return {"raw_output": raw}