from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any, Dict, List, Optional

from awsas.fingerprint.detector import TargetProfile
from awsas.cve.matcher import match_components_to_cves
from .openai_client import OpenAIPayloadGenerator


def summarize_analysis(profile: TargetProfile, cve_matches: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
    """
    Robi zwarty, tekstowy summary dla modelu:
    - podstawowe info o celu,
    - wykryte komponenty,
    - najistotniejsze CVE (ID, status wersji, krótki opis).
    """
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
    }
    return summary


def build_openai_input(summary: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Buduje input dla Responses API:
    - blok system: zasady (bezpieczne payloady, testy tylko do weryfikacji, bez destrukcji)
    - blok user: JSON z wynikami analizy + prośba o konkretne payloady testowe.
    """
    summary_json = json.dumps(summary, indent=2, ensure_ascii=False)

    system_prompt = (
        "You are a security assistant that helps generate NON-DESTRUCTIVE security test cases.\n"
        "You ONLY generate payloads and HTTP requests that can be safely used to VERIFY potential vulnerabilities\n"
        "on systems that the user is authorized to test.\n"
        "Do NOT generate guidance for data exfiltration, privilege escalation, or persistence.\n"
        "Prefer read-only requests, simple proof-of-concept checks, and clearly label each test.\n"
        "The output must be structured as JSON with the following shape:\n"
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
        '      "expected_indicator": string\n'
        "    }\n"
        "  ]\n"
        "}\n"
        "Do not include any explanatory prose outside of the JSON."
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


def generate_test_payloads(
    profile: TargetProfile,
    cve_matches: Dict[str, List[Dict[str, Any]]],
    api_key: Optional[str] = None,
    model: str = "gpt-5.1",
    # model: str = "openai/gpt-4o",
) -> Dict[str, Any]:
    """
    High-level:
    - bierze profil fingerprintu + wyniki matchera CVE,
    - robi summary,
    - buduje input pod OpenAI,
    - zwraca sparsowany JSON z testami.

    W razie błędu parsowania JSON zwraca dict z jednym kluczem 'raw_output'.
    """
    summary = summarize_analysis(profile, cve_matches)
    input_blocks = build_openai_input(summary)

    client = OpenAIPayloadGenerator(api_key=api_key, model=model)
    raw = client.generate(input_blocks)

    try:
        return json.loads(raw)
    except Exception:
        # Jak model zwróci coś nie-JSON (np. dopisze komentarz),
        # nie rozwalamy programu – użytkownik dostanie raw output.
        return {"raw_output": raw}