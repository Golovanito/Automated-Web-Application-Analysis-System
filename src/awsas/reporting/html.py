from __future__ import annotations
from html import escape
from .models import Report


def render_html(report: Report) -> str:
    cve_blocks = []
    for comp, hits in (report.cve_matches or {}).items():
        if not hits:
            continue
        items = "".join(
            f"<li><b>{escape(h.get('cve_id') or '')}</b> "
            f"(score: {escape(str(h.get('score')))}, status: {escape(str(h.get('version_status')))}): "
            f"{escape((h.get('description') or '')[:180])}</li>"
            for h in (hits or [])[:5]
        )
        cve_blocks.append(
            f"""
            <div style="border:1px solid #eee;border-radius:12px;padding:10px;margin:10px 0;">
              <b>{escape(comp)}</b>
              <ul style="margin:8px 0 0 18px;">{items}</ul>
            </div>
            """
        )

    rows = []
    for f in report.findings:
        badge = f.verdict.upper()
        risk = (f.risk_level or "unknown").upper()

        recs_html = ""
        if f.recommendations:
            recs_html = "<div style='margin-top:10px;'><b>Recommendations:</b><ul style='margin:8px 0 0 18px;'>" + \
                "".join(f"<li>{escape(x)}</li>" for x in f.recommendations) + "</ul></div>"

        related_cves_html = ""
        if f.related_cves:
            li = "".join(
                f"<li><b>{escape(x.get('cve_id') or '')}</b> "
                f"(score: {escape(str(x.get('score')))}; {escape(str(x.get('version_status')))}): "
                f"{escape((x.get('description') or '')[:160])}</li>"
                for x in f.related_cves[:5]
            )
            related_cves_html = f"<div style='margin-top:10px;'><b>Related CVEs:</b><ul style='margin:8px 0 0 18px;'>{li}</ul></div>"

        rows.append(
            f"""
            <div style="border:1px solid #ddd;border-radius:14px;padding:14px;margin:14px 0;">
              <div style="display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap;">
                <div><b>{escape(f.title)}</b></div>
                <div>
                  <span style="padding:4px 10px;border-radius:999px;border:1px solid #ccc;font-size:12px;">{escape(risk)}</span>
                  <span style="padding:4px 10px;border-radius:999px;border:1px solid #ccc;font-size:12px;margin-left:6px;">{escape(badge)}</span>
                </div>
              </div>

              <div style="margin-top:8px;font-size:13px;">
                <div><b>Test ID:</b> {escape(f.test_id)}</div>
                <div><b>Request:</b> {escape(f.method)} {escape(f.url)}</div>
                <div><b>HTTP status:</b> {escape(str(f.http_status))}</div>
              </div>

              <details style="margin-top:10px;">
                <summary style="cursor:pointer;"><b>Evidence snippet</b></summary>
                <pre style="white-space:pre-wrap;background:#fafafa;border:1px solid #eee;border-radius:10px;padding:10px;margin-top:8px;">{escape(f.evidence_snippet or '')}</pre>
              </details>

              {"<div style='margin-top:10px;'><b>Notes:</b> " + escape(f.notes) + "</div>" if f.notes else ""}

              {related_cves_html}
              {recs_html}
            </div>
            """
        )

    totals = report.totals or {}
    risk = report.risk_breakdown or {}

    html = f"""
    <!doctype html>
    <html>
    <head>
      <meta charset="utf-8"/>
      <title>Security Report</title>
      <meta name="viewport" content="width=device-width, initial-scale=1"/>
    </head>
    <body style="font-family:Arial, sans-serif; max-width: 980px; margin: 24px auto; padding: 0 14px;">
      <h1 style="margin-bottom:6px;">Security Report</h1>
      <div style="color:#555;margin-bottom:18px;">
        <div><b>Target:</b> {escape(report.target)}</div>
        <div><b>Generated at:</b> {escape(report.generated_at)}</div>
      </div>

      <div style="display:flex; gap:14px; flex-wrap:wrap; margin-bottom:18px;">
        <div style="border:1px solid #eee;border-radius:12px;padding:12px;min-width:220px;">
          <b>Totals</b>
          <ul style="margin:8px 0 0 18px;">
            <li>pass: {escape(str(totals.get("pass", 0)))}</li>
            <li>fail: {escape(str(totals.get("fail", 0)))}</li>
            <li>inconclusive: {escape(str(totals.get("inconclusive", 0)))}</li>
          </ul>
        </div>
        <div style="border:1px solid #eee;border-radius:12px;padding:12px;min-width:220px;">
          <b>Risk breakdown</b>
          <ul style="margin:8px 0 0 18px;">
            <li>high: {escape(str(risk.get("high", 0)))}</li>
            <li>medium: {escape(str(risk.get("medium", 0)))}</li>
            <li>low: {escape(str(risk.get("low", 0)))}</li>
            <li>unknown: {escape(str(risk.get("unknown", 0)))}</li>
          </ul>
        </div>
      </div>

      <h2>CVE matches (from fingerprinting)</h2>
      {''.join(cve_blocks) if cve_blocks else '<i>No CVE matches provided.</i>'}

      <h2 style="margin-top:22px;">Findings</h2>
      {''.join(rows) if rows else '<i>No findings.</i>'}

      <hr style="margin:26px 0; border:none; border-top:1px solid #eee;" />
      <details>
        <summary style="cursor:pointer;"><b>Raw results (debug)</b></summary>
        <pre style="white-space:pre-wrap;background:#fafafa;border:1px solid #eee;border-radius:10px;padding:10px;margin-top:8px;">{escape(str(report.raw_results)[:20000])}</pre>
      </details>
    </body>
    </html>
    """
    return html