from __future__ import annotations
import json
from pathlib import Path
from dataclasses import asdict
from typing import Dict
from .models import Report
from .html import render_html


def write_report(report: Report, out_dir: str = "reports", basename: str = "report") -> Dict[str, str]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    json_path = out / f"{basename}.json"
    html_path = out / f"{basename}.html"

    json_path.write_text(json.dumps(asdict(report), ensure_ascii=False, indent=2), encoding="utf-8")
    html_path.write_text(render_html(report), encoding="utf-8")

    return {"json": str(json_path), "html": str(html_path)}