from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any


@dataclass
class Finding:
    test_id: str
    title: str
    risk_level: str               # low/medium/high/unknown
    url: str
    method: str
    verdict: str                  # pass/fail/inconclusive
    http_status: Optional[int]
    evidence_snippet: str
    notes: str = ""
    related_cves: List[Dict[str, Any]] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


@dataclass
class Report:
    target: str
    generated_at: str
    totals: Dict[str, int]
    risk_breakdown: Dict[str, int]
    findings: List[Finding]
    raw_results: Dict[str, Any]
    cve_matches: Dict[str, List[Dict[str, Any]]] = field(default_factory=dict)
    environment: Dict[str, Any] = field(default_factory=dict)