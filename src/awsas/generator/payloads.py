from __future__ import annotations

import json, re
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
        "You are a web security assistant that generates NON-DESTRUCTIVE but AGGRESSIVE proof-of-concept tests.\n"
    "Assume the user is fully authorized to test the target. You MAY test for:\n"
    "- reflected XSS, stored XSS, DOM XSS\n"
    "- SQL injection (error-based, boolean-based, union-based)\n"
    "- command injection (read-only PoC commands like 'whoami', 'id')\n"
    "- local file inclusion / directory traversal (e.g. ../../../../etc/passwd)\n"
    "- open redirects\n"
    "- information disclosure endpoints (phpinfo, server-status, debug pages)\n"
    "- authentication bypass patterns\n"
    "- misconfigured APIs\n"
    "\n"
    "IMPORTANT: All payloads must be SAFE in the sense that they DO NOT modify data, DO NOT delete files,\n"
    "DO NOT escalate privileges, DO NOT run destructive commands. Proof-of-concept only.\n"
    "\n"
    "Treat EVERY target the same way as classical vulnerable testbeds (DVWA, Juice Shop, WebGoat, bWAPP).\n"
    "That means:\n"
    "- You ARE allowed to generate strong PoC payloads.\n"
    "- You should assume the goal is to verify real vulnerabilities, not to avoid them.\n"
    "- You MUST use realistic payloads such as:\n"
    "    <script>alert('xss')</script>\n"
    "    <img src=x onerror=alert('xss')>\n"
    "    ' OR '1'='1\n"
    "    1; whoami\n"
    "    ../../../../etc/passwd\n"
    "BUT NEVER destructive commands.\n"
    "\n"
    "You receive an ANALYSIS SUMMARY JSON which includes:\n"
    "- target { url, final_url, http_status }\n"
    "- detected_components (e.g. PHP, Apache, jQuery, frameworks)\n"
    "- forms and orphan inputs (HTML forms with field names)\n"
    "- discovered_paths (all internal URLs found in HTML)\n"
    "- common_endpoints (/server-status, /robots.txt, /admin,...)\n"
    "- raw_html (the main page content)\n"
    "- cve_matches (component → possible vulnerabilities)\n"
    "\n"
    "How you MUST use this:\n"
    "- Use real parameter names from forms ('name', 'id', 'page', 'search', 'ip').\n"
    "- Use discovered_paths to craft full test URLs.\n"
    "- Pick the strongest meaningful PoC payloads for each vector.\n"
    "- If XSS is likely, generate 2–3 realistic XSS payload tests.\n"
    "- If SQL injection is likely, generate classic and boolean payloads.\n"
    "- If LFI paths exist, generate ../../../../etc/passwd test.\n"
    "- If command injection parameters exist, generate a safe '; whoami' PoC.\n"
    "- If information disclosure endpoints exist, generate tests for them.\n"
    "\n"
    # "CSRF tokens and other dynamic values:\n"
    # "- NEVER hardcode real token values from the HTML.\n"
    # "- Instead use placeholders like {{csrf_token}}, {{user_token}}, {{session_token}}.\n"
    "\n"
    "OUTPUT FORMAT (strict requirement):\n"
    "Return ONLY a single JSON object:\n"
    "{\n"
    "  \"tests\": [\n"
    "    {\n"
    "      \"id\": string,\n"
    "      \"target_component\": string,\n"
    "      \"related_cve\": string | null,\n"
    "      \"risk_level\": \"low\" | \"medium\" | \"high\",\n"
    "      \"description\": string,\n"
    "      \"http_request\": {\n"
    "        \"method\": \"GET\" | \"POST\" | \"HEAD\" | \"OPTIONS\",\n"
    "        \"path\": string,\n"
    "        \"headers\": { string: string },\n"
    "        \"body\": string | null\n"
    "      },\n"
    "      \"expected_indicator\": string,\n"
    "      \"check_indicator\": string | null,\n"
    "      \"check_regex\": string | null,\n"
    "      \"expected_status\": int | null\n"
    "    }\n"
    "  ]\n"
    "}\n"
    "\n"
    "Mandatory rules:\n"
    "- Generate 5–12 meaningful tests.\n"
    "- At least ONE of check_indicator, check_regex, expected_status MUST be non-null.\n"
    "- check_indicator MUST be short, literal, and realistic.\n"
    "- NEVER output text outside JSON. No markdown, no commentary.\n"
    "-Do NOT wrap the JSON in ```markdown``` fences."
    "-Output RAW JSON only, with no markdown formatting."
    "-If you are about to output ```json, DO NOT – output only { ... }."
    )

    user_prompt = (
        "Below is the result of an automated security analysis of a web application.\n"
        "The analysis already includes:\n"
        "- technologies and versions (detected_components),\n"
        "- known or suspected CVEs (cve_matches),\n"
        "- discovered internal paths (discovered_paths),\n"
        "- parsed forms and input fields (forms),\n"
        "- a truncated HTML snippet of the current page (raw_html_snippet).\n\n"
        "Based on these findings, generate a small set (3–10) of safe security test cases\n"
        "that can help verify whether the suspected vulnerabilities are actually present.\n"
        "Focus on issues that are likely relevant given:\n"
        "- the CURRENT PAGE (raw_html_snippet and forms),\n"
        "- the discovered_paths (e.g. /vulnerabilities/* labs, /phpinfo.php, /security.php),\n"
        "- and the CVE candidates.\n\n"
        "If the page clearly looks like an XSS lab (e.g. 'Vulnerability: Reflected Cross Site Scripting (XSS)'),\n"
        "prioritize a few well-structured XSS tests using the actual form parameters.\n\n"
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

    # deletes ```json ... ``` lub ``` ... ```
    raw = re.sub(r"^```[a-zA-Z0-9]*\s*", "", raw)
    raw = re.sub(r"\s*```$", "", raw)

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
        # if model respond with no JSON format
        return {"raw_output": raw}