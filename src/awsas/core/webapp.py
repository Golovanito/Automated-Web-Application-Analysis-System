from __future__ import annotations

import json
import os
import threading
import time
import traceback
import uuid
import io
import contextlib
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.templating import Jinja2Templates

PROJECT_ROOT = Path(__file__).resolve().parents[3]
DATA_DIR = PROJECT_ROOT / "data"
CVE_DB_PATH = DATA_DIR / "cve_store.db"
RUNS_DIR = PROJECT_ROOT / "runs"
TEMPLATES_DIR = PROJECT_ROOT / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

RUNS_DIR.mkdir(parents=True, exist_ok=True)

app = FastAPI(title="AWSAS Web UI", version="0.1")

_RUN_STATE: Dict[str, Dict[str, Any]] = {}
_RUN_LOCK = threading.Lock()


def _now_ms() -> int:
    return int(time.time() * 1000)


def _safe_json(obj: Any) -> Any:
    if is_dataclass(obj):
        return asdict(obj)
    if isinstance(obj, Path):
        return str(obj)
    if isinstance(obj, dict):
        return {str(k): _safe_json(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_safe_json(x) for x in obj]
    if isinstance(obj, (set, frozenset)):
        return [_safe_json(x) for x in obj]
    return obj


def _write_status(run_dir: Path, state: Dict[str, Any]) -> None:
    (run_dir / "status.json").write_text(
        json.dumps(_safe_json(state), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

class _LogSink(io.TextIOBase):
    def __init__(self, run_id: str, run_dir: Path, set_state_func, max_lines: int = 4000):
        self.run_id = run_id
        self.run_dir = run_dir
        self.set_state = set_state_func
        self.max_lines = max_lines
        self._buf = ""

    def write(self, s: str) -> int:
        if not s:
            return 0
        self._buf += s

        lines = self._buf.splitlines(True)
        keep = []
        out_lines = []
        for part in lines:
            if part.endswith("\n"):
                out_lines.append(part.rstrip("\n"))
            else:
                keep.append(part)
        self._buf = "".join(keep)

        if out_lines:
            with _RUN_LOCK:
                st = _RUN_STATE.get(self.run_id, {})
                logs = list(st.get("logs") or [])
                logs.extend(out_lines)
                if len(logs) > self.max_lines:
                    logs = logs[-self.max_lines:]
                st["logs"] = logs
                _RUN_STATE[self.run_id] = st
                _write_status(self.run_dir, st)

        return len(s)

    def flush(self) -> None:
        return


def _list_files(run_dir: Path) -> Dict[str, str]:
    if not run_dir.exists():
        return {}

    files = {}
    for p in sorted(run_dir.rglob("*")):
        if p.is_file():
            rel = p.relative_to(run_dir).as_posix()
            files[rel] = rel
    return files


def _call_run_full_pipeline(target_url: str, run_dir: Path) -> Dict[str, Any]:
    import inspect

    claude_key = os.getenv("CLAUDE_API_KEY")
    if not claude_key:
        raise RuntimeError("Missing CLAUDE_API_KEY in environment variables.")

    claude_model = os.getenv("CLAUDE_MODEL", "claude-sonnet-4-5-20250929")

    from awsas.generator.claude_client import ClaudeClient
    llm_client = ClaudeClient(api_key=claude_key, model=claude_model)

    from awsas.core.pipeline import run_full_pipeline  # noqa

    sig = inspect.signature(run_full_pipeline)
    kwargs: Dict[str, Any] = {}

    kwargs["target_url"] = target_url

    for name in ("out_dir", "output_dir", "run_dir", "reports_dir"):
        if name in sig.parameters:
            kwargs[name] = str(run_dir)
            break

    for name in ("db_path", "cve_db_path", "cve_store_path", "cve_db"):
        if name in sig.parameters:
            kwargs[name] = str(CVE_DB_PATH)
            break

    for name in ("llm_client", "client", "claude_client"):
        if name in sig.parameters:
            kwargs[name] = llm_client
            break

    for name in ("use_llm", "enable_llm"):
        if name in sig.parameters:
            kwargs[name] = True
            break

    for name in ("use_judge", "judge_on_fail", "enable_judge"):
        if name in sig.parameters:
            kwargs[name] = True
            break

    result = run_full_pipeline(**kwargs)
    return _safe_json(result)


def _runner_thread(run_id: str, target_url: str) -> None:
    run_dir = RUNS_DIR / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    def set_state(**patch: Any) -> None:
        with _RUN_LOCK:
            st = _RUN_STATE.get(run_id, {})
            st.update(patch)
            _RUN_STATE[run_id] = st
            _write_status(run_dir, st)

    def append_log(line: str) -> None:
        with _RUN_LOCK:
            st = _RUN_STATE.get(run_id, {})
            logs = list(st.get("logs") or [])
            logs.append(line)
            st["logs"] = logs
            _RUN_STATE[run_id] = st
            _write_status(run_dir, st)

    set_state(
        run_id=run_id,
        target_url=target_url,
        status="running",
        stage="starting",
        started_at_ms=_now_ms(),
        finished_at_ms=None,
        error=None,
        output=None,
        files={},
        logs=[],
    )

    try:
        set_state(stage="pipeline")
        append_log("Start pipeline...")

        sink = _LogSink(run_id, run_dir, set_state)

        import contextlib
        with contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
            output = _call_run_full_pipeline(target_url, run_dir)

        files = _list_files(run_dir)

        report_html = None
        cand = run_dir / "report.html"
        if cand.exists():
            report_html = "report.html"
        else:
            htmls = sorted([p.relative_to(run_dir).as_posix() for p in run_dir.rglob("*.html")])
            if htmls:
                report_html = htmls[0]

        append_log("Done.")
        set_state(
            status="done",
            stage="done",
            finished_at_ms=_now_ms(),
            output=output,
            files=files,
            report_html=report_html,
        )
    except Exception as e:
        tb = traceback.format_exc()
        set_state(
            status="error",
            stage="error",
            finished_at_ms=_now_ms(),
            error=str(e),
            traceback=tb,
            files=_list_files(run_dir),
            logs=_RUN_STATE[run_id]["logs"] + [f"ERROR: {e}"],
        )

def _db_ready() -> bool:
    try:
        return CVE_DB_PATH.exists() and CVE_DB_PATH.is_file() and CVE_DB_PATH.stat().st_size > 0
    except Exception:
        return False
    
@app.get("/api/system")
def system_status() -> JSONResponse:
    return JSONResponse(
        {
            "cve_db_path": CVE_DB_PATH.as_posix(),
            "cve_db_exists": CVE_DB_PATH.exists(),
            "cve_db_ready": _db_ready(),
            "cve_db_size_bytes": (CVE_DB_PATH.stat().st_size if CVE_DB_PATH.exists() else 0),
            "model_name": "Claude Sonnet 4.5",
        }
    )


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    db_ready = _db_ready()
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "cve_db_path": CVE_DB_PATH.as_posix(),
            "model_name": "Claude Sonnet 4.5",
            "cve_db_ready": db_ready,
            "cve_db_exists": CVE_DB_PATH.exists(),
            "cve_db_size_mb": round((CVE_DB_PATH.stat().st_size / (1024 * 1024)), 1) if CVE_DB_PATH.exists() else 0.0,
        },
    )


@app.post("/api/runs")
def start_run(payload: Dict[str, Any]) -> JSONResponse:
    url = (payload.get("url") or "").strip()
    if not url:
        raise HTTPException(status_code=400, detail="Missing 'url'.")

    if not _db_ready():
        raise HTTPException(
            status_code=409,
            detail=(
                "CVE database is missing. Build it first (data/cve_store.db). "
                "Tip: run the DB builder container or script, then refresh the page."
            ),
        )

    run_id = uuid.uuid4().hex[:12]
    with _RUN_LOCK:
        _RUN_STATE[run_id] = {
            "run_id": run_id,
            "target_url": url,
            "status": "queued",
            "stage": "queued",
            "started_at_ms": _now_ms(),
            "finished_at_ms": None,
            "error": None,
            "output": None,
            "files": {},
            "logs": ["Queued."],
        }

    t = threading.Thread(target=_runner_thread, args=(run_id, url), daemon=True)
    t.start()
    return JSONResponse({"run_id": run_id})


@app.get("/api/runs/{run_id}")
def get_run(run_id: str) -> JSONResponse:
    run_dir = RUNS_DIR / run_id
    with _RUN_LOCK:
        st = _RUN_STATE.get(run_id)

    if st is None:
        status_file = run_dir / "status.json"
        if status_file.exists():
            st = json.loads(status_file.read_text(encoding="utf-8"))
        else:
            raise HTTPException(status_code=404, detail="Run not found.")

    st["files"] = _list_files(run_dir)

    return JSONResponse(st)


@app.get("/api/runs/{run_id}/report")
def open_report(run_id: str, file: str = "report.html") -> FileResponse:
    run_dir = RUNS_DIR / run_id
    target = (run_dir / file).resolve()

    if not str(target).startswith(str(run_dir.resolve())):
        raise HTTPException(status_code=400, detail="Invalid path.")

    if not target.exists():
        raise HTTPException(status_code=404, detail="Report not found.")

    return FileResponse(str(target), media_type="text/html")


@app.get("/api/runs/{run_id}/files/{rel_path:path}")
def download_file(run_id: str, rel_path: str) -> FileResponse:
    run_dir = RUNS_DIR / run_id
    target = (run_dir / rel_path).resolve()

    if not str(target).startswith(str(run_dir.resolve())):
        raise HTTPException(status_code=400, detail="Invalid path.")

    if not target.exists() or not target.is_file():
        raise HTTPException(status_code=404, detail="File not found.")

    return FileResponse(str(target), filename=Path(rel_path).name)


# python -m awsas.core.webapp
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("awsas.core.webapp:app", host="0.0.0.0", port=8000, reload=True)