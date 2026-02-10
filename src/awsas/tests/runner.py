from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse, urlunparse, urlencode, urlsplit, urlunsplit, parse_qsl
from bs4 import BeautifulSoup
import re, json
import requests, time


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


def dvwa_login(
    session: requests.Session,
    base_url: str,
    username: str = "admin",
    password: str = "password",
    timeout: int = 10,
) -> bool:
    # DVWA login
    login_url = base_url.rstrip("/") + "/login.php"

    r = session.get(login_url, timeout=timeout, allow_redirects=True)

    token = None
    try:
        soup = BeautifulSoup(r.text, "html.parser")
        hidden = soup.find("input", {"name": "user_token"})
        if hidden and hidden.get("value"):
            token = hidden["value"]
    except Exception:
        pass

    data = {
        "username": username,
        "password": password,
        "Login": "Login",
    }
    if token:
        data["user_token"] = token

    session.post(login_url, data=data, timeout=timeout, allow_redirects=True)

    test = session.get(base_url, timeout=timeout, allow_redirects=True)
    logged_in = "login.php" not in test.url
    return logged_in


def dvwa_set_security(
    session: requests.Session,
    base_url: str,
    level: str = "low",
    timeout: int = 10,
) -> None:
    url = base_url.rstrip("/") + "/security.php"
    data = {
        "security": level,
        "seclev_submit": "Submit",
    }
    session.post(url, data=data, timeout=timeout, allow_redirects=True)

def extract_focus_snippet(html: str, limit: int = 8000) -> str:
    if not html:
        return ""

    try:
        soup = BeautifulSoup(html, "html.parser")

        # delete script/style – noise
        for tag in soup(["script", "style", "noscript"]):
            tag.decompose()

        # prefered content
        candidates = []
        for sel in [
            {"id": "main_body"},
            {"id": "content"},
            {"id": "main"},
            {"id": "container"},
        ]:
            hit = soup.find(attrs=sel)
            if hit:
                candidates.append(hit)

        if not candidates and soup.body:
            candidates = [soup.body]

        text = ""
        for c in candidates:
            text = c.get_text("\n", strip=True)
            if len(text) > 200:
                break

        if not text:
            text = soup.get_text("\n", strip=True)

        text = text[:limit]
        return text
    except Exception:
        return (html or "")[:limit]
    
_SUSPICIOUS_RE = re.compile(
    r"('|\bOR\b|\bAND\b|--|/\*|\*/|<script|onerror=|;|\bUNION\b|\bSELECT\b|\bSLEEP\b|\.\./|\bWAITFOR\b|\bxp_|%27|%3C)",
    re.IGNORECASE,
)

def _choose_baseline_value(param: str, val: str) -> str:
    p = (param or "").lower()
    if p in ("id", "uid", "user", "userid"):
        return "1"
    if p in ("name", "q", "query", "search"):
        return "test"
    if p in ("ip", "host", "addr"):
        return "127.0.0.1"
    if p in ("page", "file", "path"):
        return "index.php"
    # tokenów nie ruszamy
    if "token" in p:
        return val
    # default
    return "test"

def build_baseline_from_spec(method: str, path: str, body: Optional[str]) -> tuple[str, Optional[str]]:
    parts = urlsplit(path)
    q = parse_qsl(parts.query, keep_blank_values=True)

    new_q = []
    for k, v in q:
        if _SUSPICIOUS_RE.search(v or ""):
            new_q.append((k, _choose_baseline_value(k, v)))
        else:
            if v and len(v) > 50:
                new_q.append((k, _choose_baseline_value(k, v)))
            else:
                new_q.append((k, v))

    baseline_query = urlencode(new_q, doseq=True)
    baseline_path = urlunsplit((parts.scheme, parts.netloc, parts.path, baseline_query, parts.fragment))
    if baseline_path.startswith("//"):  # czasem urlsplit tak zwróci
        baseline_path = parts.path + (("?" + baseline_query) if baseline_query else "")

    baseline_body = body
    if method.upper() in ("POST", "PUT", "PATCH") and body and isinstance(body, str):
        if "=" in body and "&" in body:
            bq = parse_qsl(body, keep_blank_values=True)
            new_bq = []
            for k, v in bq:
                if _SUSPICIOUS_RE.search(v or ""):
                    new_bq.append((k, _choose_baseline_value(k, v)))
                else:
                    if v and len(v) > 80:
                        new_bq.append((k, _choose_baseline_value(k, v)))
                    else:
                        new_bq.append((k, v))
            baseline_body = urlencode(new_bq, doseq=True)

    return baseline_path, baseline_body

def compute_diff_features(baseline_text: str, attack_text: str) -> Dict[str, Any]:
    def count(s: str, needle: str) -> int:
        return s.lower().count(needle.lower()) if (s and needle) else 0

    feats = {
        "len_baseline": len(baseline_text or ""),
        "len_attack": len(attack_text or ""),
        "delta_len": (len(attack_text or "") - len(baseline_text or "")),
        "count_first_name_base": count(baseline_text, "First name:"),
        "count_first_name_attack": count(attack_text, "First name:"),
        "count_surname_base": count(baseline_text, "Surname:"),
        "count_surname_attack": count(attack_text, "Surname:"),
        "has_sql_error_attack": bool(re.search(r"(SQL syntax|mysql_fetch|mysqli_fetch|Warning.*mysql|syntax error)", attack_text or "", re.I)),
        "has_sql_error_base": bool(re.search(r"(SQL syntax|mysql_fetch|mysqli_fetch|Warning.*mysql|syntax error)", baseline_text or "", re.I)),
    }
    return feats

def heuristic_verdict(test_spec: Dict[str, Any], diff: Dict[str, Any], elapsed_ms_base: float, elapsed_ms_attack: float) -> tuple[str, float, list[str]]:
    target = (test_spec.get("target_component") or "").lower()
    path = ((test_spec.get("http_request") or {}).get("path") or "")
    body = ((test_spec.get("http_request") or {}).get("body") or "")
    blob = f"{path} {body}".lower()

    reasons = []

    # time-based SQLi
    if "sleep(" in blob or "waitfor" in blob:
        delta = elapsed_ms_attack - elapsed_ms_base
        reasons.append(f"timing delta_ms={delta:.0f} (base={elapsed_ms_base:.0f}, attack={elapsed_ms_attack:.0f})")
        if delta > 3000:
            return "pass", 0.9, reasons
        return "inconclusive", 0.6, reasons

    # error-based SQLi
    if "error" in target or "error-based" in target or "sql injection - error" in target:
        if diff["has_sql_error_attack"] and not diff["has_sql_error_base"]:
            reasons.append("SQL error present in attack but not in baseline")
            return "pass", 0.9, reasons
        return "inconclusive", 0.6, reasons

    # boolean-based SQLi
    if "boolean" in target or "or '1'='1" in blob or "or 1=1" in blob:
        base_n = diff["count_first_name_base"] + diff["count_surname_base"]
        att_n = diff["count_first_name_attack"] + diff["count_surname_attack"]
        reasons.append(f"record markers base={base_n} attack={att_n}")
        if att_n > base_n and att_n >= 2:
            return "pass", 0.9, reasons
        return "inconclusive", 0.6, reasons

    # XSS reflected
    if "xss" in target:
        payload = (test_spec.get("expected_indicator") or "").strip()
        if payload and payload[:40].lower() in (diff and ""):
            reasons.append("payload fragment appears in response")
            return "pass", 0.75, reasons
        return "inconclusive", 0.5, reasons

    return "inconclusive", 0.5, ["no matching heuristic rule"]

def evaluate_response(
    expected_status: Any,
    check_regex: str,
    check_indicator: str,
    expected_indicator: str,
    http_status: Optional[int],
    text: str,
) -> tuple[bool, bool, bool, bool]:
    status_ok = True
    if isinstance(expected_status, int) and http_status is not None:
        status_ok = (http_status == expected_status)

    text_ok = True
    indicator_found = False

    if check_regex:
        try:
            if re.search(check_regex, text, flags=re.IGNORECASE | re.DOTALL):
                indicator_found = True
                text_ok = True
            else:
                text_ok = False
        except re.error:
            text_ok = False

    elif check_indicator:
        indicator_found = (check_indicator in text)
        text_ok = indicator_found

    elif expected_indicator and len(expected_indicator) < 120:
        indicator_found = (expected_indicator in text)
        text_ok = indicator_found

    else:
        text_ok = True

    return (status_ok and text_ok), indicator_found, status_ok, text_ok


def llm_judge_result(
    client: Any,
    test_spec: Dict[str, Any],
    baseline: Dict[str, Any],
    attack: Dict[str, Any],
    diff: Dict[str, Any],
) -> Dict[str, Any]:
    system_prompt = (
        "You are a security test RESULT JUDGE.\n"
        "You do NOT generate new attacks.\n"
        "You MUST compare BASELINE vs ATTACK response.\n"
        "Do NOT decide based on page title/branding alone.\n"
        "Decide PASS only if there is evidence the payload changed behavior consistent with the test.\n"
        "You MAY suggest ONLY detector changes: check_regex/check_indicator/expected_status.\n"
        "Return ONLY RAW JSON, no markdown.\n"
        "Schema:\n"
        "{\n"
        "  \"verdict\": \"pass\"|\"fail\"|\"inconclusive\",\n"
        "  \"confidence\": 0.0,\n"
        "  \"evidence\": [\"...\"],\n"
        "  \"suggested_detector_update\": {\n"
        "     \"check_indicator\": string|null,\n"
        "     \"check_regex\": string|null,\n"
        "     \"expected_status\": int|null\n"
        "  },\n"
        "  \"notes\": \"\"\n"
        "}\n"
    )

    payload = {
        "test_spec": test_spec,
        "diff_features": diff,
        "baseline": {
            "http_status": baseline.get("http_status"),
            "final_url": baseline.get("final_url"),
            "snippet": baseline.get("snippet"),
            "elapsed_ms": baseline.get("elapsed_ms"),
        },
        "attack": {
            "http_status": attack.get("http_status"),
            "final_url": attack.get("final_url"),
            "snippet": attack.get("snippet"),
            "elapsed_ms": attack.get("elapsed_ms"),
        },
    }

    input_blocks = [
        {"role": "system", "content": [{"type": "input_text", "text": system_prompt}]},
        {"role": "user", "content": [{"type": "input_text", "text": json.dumps(payload, ensure_ascii=False)}]},
    ]

    raw = client.generate(input_blocks)
    raw_clean = raw.strip()
    raw_clean = re.sub(r"^```[a-zA-Z0-9]*\s*", "", raw_clean)
    raw_clean = re.sub(r"\s*```$", "", raw_clean).strip()

    try:
        return json.loads(raw_clean)
    except Exception:
        return {"raw_output": raw}


def run_tests(
    base_url: str,
    payload_spec: Dict[str, Any],
    timeout: int = 10,
    dvwa_login_data: Optional[Dict[str, str]] = None,
    judge_client: Optional[Any] = None,
    judge_on_fail: bool = True,
    max_judge_calls: int = 10
) -> Dict[str, Any]:
    tests = payload_spec.get("tests") or []
    if not isinstance(tests, list):
        raise ValueError("payload_spec['tests'] musi być listą")

    session = requests.Session()

    parsed = urlparse(base_url)
    base_root = urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))

    if dvwa_login_data:
        ok = dvwa_login(
            session,
            base_root,
            username=dvwa_login_data.get("username", "admin"),
            password=dvwa_login_data.get("password", "password"),
            timeout=timeout,
        )
        if ok:
            dvwa_set_security(
                session,
                base_root,
                level=dvwa_login_data.get("security", "low"),
                timeout=timeout,
            )

    

    results: List[TestResult] = []

    judge_calls = 0

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

        notes = ""

        try:
            baseline_path, baseline_body = build_baseline_from_spec(method, path, body)
            baseline_url = urljoin(base_url, baseline_path)

            t0 = time.perf_counter()
            resp_base = session.request(
                method=method,
                url=baseline_url,
                headers=headers,
                data=baseline_body if isinstance(baseline_body, (str, bytes)) else None,
                timeout=timeout,
                allow_redirects=True,
            )
            t1 = time.perf_counter()

            base_status = resp_base.status_code
            base_html = resp_base.text or ""
            base_snippet = extract_focus_snippet(base_html, limit=8000)
            base_elapsed_ms = (t1 - t0) * 1000.0

            t2 = time.perf_counter()
            resp = session.request(
                method=method,
                url=full_url,
                headers=headers,
                data=body if isinstance(body, (str, bytes)) else None,
                timeout=timeout,
                allow_redirects=True,
            )
            t3 = time.perf_counter()

            http_status = resp.status_code
            text = resp.text or ""
            snippet = extract_focus_snippet(text, limit=8000)
            attack_elapsed_ms = (t3 - t2) * 1000.0

            ok, indicator_found, status_ok, text_ok = evaluate_response(
                expected_status=expected_status,
                check_regex=check_regex,
                check_indicator=check_indicator,
                expected_indicator=expected_indicator,
                http_status=http_status,
                text=text,
            )

            diff = compute_diff_features(base_snippet, snippet)
            h_verdict, h_conf, h_reasons = heuristic_verdict(t, diff, base_elapsed_ms, attack_elapsed_ms)

            if (not ok) and h_verdict == "pass":
                ok = True
                indicator_found = True
                notes = f"heuristic=pass conf={h_conf} reasons={h_reasons[:2]}"

            if (not ok) and judge_client is not None and judge_on_fail and judge_calls < max_judge_calls:
                judge_calls += 1

                judge_out = llm_judge_result(
                    client=judge_client,
                    test_spec=t,
                    baseline={
                        "http_status": base_status,
                        "final_url": str(resp_base.url),
                        "snippet": base_snippet,
                        "elapsed_ms": base_elapsed_ms,
                    },
                    attack={
                        "http_status": http_status,
                        "final_url": str(resp.url),
                        "snippet": snippet,
                        "elapsed_ms": attack_elapsed_ms,
                    },
                    diff=diff,
                )

                upd = (judge_out or {}).get("suggested_detector_update") or {}
                new_expected_status = upd.get("expected_status", expected_status)
                new_check_regex = (upd.get("check_regex", check_regex) or "").strip()
                new_check_indicator = (upd.get("check_indicator", check_indicator) or "").strip()

                ok2, indicator_found2, _, _ = evaluate_response(
                    expected_status=new_expected_status,
                    check_regex=new_check_regex,
                    check_indicator=new_check_indicator,
                    expected_indicator=expected_indicator,
                    http_status=http_status,
                    text=text,
                )

                verdict = (judge_out or {}).get("verdict")
                conf = (judge_out or {}).get("confidence")
                evidence = (judge_out or {}).get("evidence") or []

                if verdict == "pass" and ok2:
                    ok = True
                    indicator_found = indicator_found2

                notes = (
                    f"heuristic={h_verdict} hconf={h_conf} "
                    f"judge_verdict={verdict} confidence={conf} "
                    f"detector_updated={bool(upd)} evidence={evidence[:2]}"
                )

            if ok and not notes:
                notes = f"status_ok={status_ok} text_ok={text_ok} (hard checks)"

        except Exception as e:
            error = str(e)
            ok = False
            notes = notes or ""

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
                notes=notes
            )
        )

    return {
        "base_url": base_url,
        "tests_count": len(results),
        "results": [asdict(r) for r in results],
    }