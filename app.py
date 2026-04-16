import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

import yaml
from fastapi import BackgroundTasks, FastAPI, HTTPException, Request

from netaiops.executor import (
    complete_execution_for_request_id,
    create_execution_for_request_id,
    dispatch_execution_for_request_id,
    fail_execution_for_request_id,
    get_execution_by_request_id,
    get_latest_execution,
    update_execution_results_for_request_id,
)
from netaiops.logger import setup_logger
from netaiops.request_summary import get_request_summary
from netaiops.review_builder import (
    generate_review_for_request_id,
    get_latest_review,
    get_review_by_request_id,
)
from netaiops.normalizers import normalize_alertmanager, normalize_elastic
from netaiops.plan_builder import (
    confirm_plan_for_request_id,
    generate_plan_for_request_id,
    get_latest_plan,
    get_plan_by_request_id,
)
from netaiops.processor import process_event_async

BASE_DIR = Path("/opt/netaiops-webhook")
DATA_DIR = BASE_DIR / "data"
RAW_DIR = DATA_DIR / "raw"
NORMALIZED_DIR = DATA_DIR / "normalized"
ANALYSIS_DIR = DATA_DIR / "analysis"
PLAN_DIR = DATA_DIR / "plans"
EXECUTION_DIR = DATA_DIR / "execution"
REVIEW_DIR = DATA_DIR / "reviews"
CONFIG_FILE = BASE_DIR / "config.yaml"

RAW_DIR.mkdir(parents=True, exist_ok=True)
NORMALIZED_DIR.mkdir(parents=True, exist_ok=True)
ANALYSIS_DIR.mkdir(parents=True, exist_ok=True)
PLAN_DIR.mkdir(parents=True, exist_ok=True)
EXECUTION_DIR.mkdir(parents=True, exist_ok=True)
REVIEW_DIR.mkdir(parents=True, exist_ok=True)

logger = setup_logger()
app = FastAPI(title="NetAIOps Webhook", version="3.0-a")


def load_config() -> dict:
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    return {}


CONFIG = load_config()


def load_version() -> str:
    version_file = BASE_DIR / "VERSION"
    if version_file.exists():
        return version_file.read_text(encoding="utf-8").strip()
    return "3.0.0-v3"


APP_VERSION = load_version()


def now_utc_str() -> str:
    return datetime.now(timezone.utc).isoformat()


def file_ts() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S_%f") + "_" + uuid.uuid4().hex[:8]


def safe_write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def persist_events(source: str, raw_payload: dict, normalized_events: list) -> dict:
    request_id = file_ts()
    raw_file = RAW_DIR / f"{source}_{request_id}.json"
    normalized_file = NORMALIZED_DIR / f"{source}_{request_id}.json"

    safe_write_json(raw_file, raw_payload)
    safe_write_json(
        normalized_file,
        {
            "request_id": request_id,
            "source": source,
            "event_count": len(normalized_events),
            "events": normalized_events,
            "created_at": now_utc_str(),
        },
    )

    return {
        "request_id": request_id,
        "raw_file": str(raw_file),
        "normalized_file": str(normalized_file),
        "event_count": len(normalized_events),
    }


def read_json_file(path: Path) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def latest_analysis_file() -> Path:
    files = sorted(ANALYSIS_DIR.glob("*.analysis.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not files:
        raise FileNotFoundError("no analysis files found")
    return files[0]


def analysis_file_by_request_id(request_id: str) -> Path:
    files = list(ANALYSIS_DIR.glob(f"*_{request_id}.analysis.json"))
    if not files:
        raise FileNotFoundError(f"analysis file not found for request_id={request_id}")
    return files[0]


def normalized_file_by_request_id(request_id: str) -> Path:
    files = list(NORMALIZED_DIR.glob(f"*_{request_id}.json"))
    if not files:
        raise FileNotFoundError(f"normalized file not found for request_id={request_id}")
    return files[0]


@app.get("/health")
async def health() -> dict:
    return {
        "status": "ok",
        "service": "netaiops-webhook",
        "version": APP_VERSION,
        "time": now_utc_str(),
    }


@app.get("/request/{request_id}/summary")
async def get_request_summary_api(request_id: str) -> dict:
    try:
        data = get_request_summary(request_id)
        return {
            "status": "ok",
            "data": data,
        }
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@app.get("/analysis/latest")
async def get_latest_analysis() -> dict:
    try:
        path = latest_analysis_file()
        data = read_json_file(path)
        return {
            "status": "ok",
            "file": str(path),
            "data": data,
        }
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@app.get("/analysis/{request_id}")
async def get_analysis_by_request_id(request_id: str) -> dict:
    try:
        path = analysis_file_by_request_id(request_id)
        data = read_json_file(path)
        return {
            "status": "ok",
            "file": str(path),
            "data": data,
        }
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@app.post("/analysis/replay/{request_id}")
async def replay_analysis(request_id: str, background_tasks: BackgroundTasks) -> dict:
    try:
        normalized_path = normalized_file_by_request_id(request_id)
        normalized_data = read_json_file(normalized_path)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))

    source = normalized_data.get("source", "")
    events = normalized_data.get("events", [])

    if not source:
        raise HTTPException(status_code=400, detail="normalized file missing source")
    if not isinstance(events, list) or not events:
        raise HTTPException(status_code=400, detail="normalized file missing events")

    replay_request_id = file_ts()
    logger.info(
        "replay analysis original_request_id=%s replay_request_id=%s source=%s event_count=%s",
        request_id,
        replay_request_id,
        source,
        len(events),
    )

    for event in events:
        background_tasks.add_task(process_event_async, source, replay_request_id, event, CONFIG)

    return {
        "status": "accepted",
        "action": "replay_analysis",
        "original_request_id": request_id,
        "replay_request_id": replay_request_id,
        "source": source,
        "event_count": len(events),
    }


@app.get("/plan/latest")
async def get_latest_plan_api() -> dict:
    try:
        result = get_latest_plan()
        return {
            "status": "ok",
            "file": result["plan_file"],
            "data": result["plan_data"],
        }
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@app.get("/plan/{request_id}")
async def get_plan_by_request_id_api(request_id: str) -> dict:
    try:
        result = get_plan_by_request_id(request_id)
        return {
            "status": "ok",
            "file": result["plan_file"],
            "data": result["plan_data"],
        }
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@app.post("/plan/generate/{request_id}")
async def generate_plan_api(request_id: str) -> dict:
    try:
        result = generate_plan_for_request_id(request_id)
        return {
            "status": "ok",
            "action": "generate_plan",
            "request_id": request_id,
            "file": result["plan_file"],
            "data": result["plan_data"],
        }
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/plan/confirm/{request_id}")
async def confirm_plan_api(request_id: str) -> dict:
    try:
        result = confirm_plan_for_request_id(request_id)
        return {
            "status": "ok",
            "action": "confirm_plan",
            "request_id": request_id,
            "file": result["plan_file"],
            "data": result["plan_data"],
        }
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/plan/execute/{request_id}")
async def execute_plan_api(request_id: str) -> dict:
    try:
        result = create_execution_for_request_id(request_id)
        return {
            "status": "ok",
            "action": "create_execution",
            "request_id": request_id,
            "file": result["execution_file"],
            "data": result["execution_data"],
        }
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/execution/dispatch/{request_id}")
async def dispatch_execution_api(request_id: str) -> dict:
    try:
        result = dispatch_execution_for_request_id(request_id)
        return {
            "status": "ok",
            "action": "dispatch_execution",
            "request_id": request_id,
            "file": result["execution_file"],
            "data": result["execution_data"],
        }
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/execution/complete/{request_id}")
async def complete_execution_api(request_id: str) -> dict:
    try:
        result = complete_execution_for_request_id(request_id)
        return {
            "status": "ok",
            "action": "complete_execution",
            "request_id": request_id,
            "file": result["execution_file"],
            "data": result["execution_data"],
        }
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/execution/fail/{request_id}")
async def fail_execution_api(request_id: str, request: Request) -> dict:
    try:
        payload = await request.json()
    except Exception:
        payload = {}

    message = payload.get("message", "execution failed")

    try:
        result = fail_execution_for_request_id(request_id, message)
        return {
            "status": "ok",
            "action": "fail_execution",
            "request_id": request_id,
            "file": result["execution_file"],
            "data": result["execution_data"],
        }
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/execution/result/{request_id}")
async def update_execution_result_api(request_id: str, request: Request) -> dict:
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="invalid json payload")

    command_results = payload.get("command_results", [])
    if not isinstance(command_results, list):
        raise HTTPException(status_code=400, detail="command_results must be a list")

    try:
        result = update_execution_results_for_request_id(request_id, command_results)
        return {
            "status": "ok",
            "action": "update_execution_result",
            "request_id": request_id,
            "file": result["execution_file"],
            "data": result["execution_data"],
        }
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/execution/latest")
async def get_latest_execution_api() -> dict:
    try:
        result = get_latest_execution()
        return {
            "status": "ok",
            "file": result["execution_file"],
            "data": result["execution_data"],
        }
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@app.get("/execution/{request_id}")
async def get_execution_by_request_id_api(request_id: str) -> dict:
    try:
        result = get_execution_by_request_id(request_id)
        return {
            "status": "ok",
            "file": result["execution_file"],
            "data": result["execution_data"],
        }
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@app.get("/review/latest")
async def get_latest_review_api() -> dict:
    try:
        result = get_latest_review()
        return {
            "status": "ok",
            "file": result["review_file"],
            "data": result["review_data"],
        }
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@app.get("/review/{request_id}")
async def get_review_by_request_id_api(request_id: str) -> dict:
    try:
        result = get_review_by_request_id(request_id)
        return {
            "status": "ok",
            "file": result["review_file"],
            "data": result["review_data"],
        }
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@app.post("/review/generate/{request_id}")
async def generate_review_api(request_id: str) -> dict:
    try:
        result = generate_review_for_request_id(request_id)
        return {
            "status": "ok",
            "action": "generate_review",
            "request_id": request_id,
            "file": result["review_file"],
            "data": result["review_data"],
        }
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/webhook/alertmanager")
async def webhook_alertmanager(request: Request, background_tasks: BackgroundTasks) -> dict:
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="invalid json payload")

    normalized_events = normalize_alertmanager(payload)
    persist_result = persist_events("alertmanager", payload, normalized_events)
    request_id = persist_result["request_id"]

    logger.info(
        "received alertmanager webhook request_id=%s event_count=%s",
        request_id,
        len(normalized_events),
    )

    for event in normalized_events:
        background_tasks.add_task(process_event_async, "alertmanager", request_id, event, CONFIG)

    return {
        "status": "accepted",
        "source": "alertmanager",
        "request_id": request_id,
        "event_count": len(normalized_events),
    }


@app.post("/webhook/elastic")
async def webhook_elastic(request: Request, background_tasks: BackgroundTasks) -> dict:
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="invalid json payload")

    normalized_events = normalize_elastic(payload)
    persist_result = persist_events("elastic", payload, normalized_events)
    request_id = persist_result["request_id"]

    logger.info(
        "received elastic webhook request_id=%s event_count=%s",
        request_id,
        len(normalized_events),
    )

    for event in normalized_events:
        background_tasks.add_task(process_event_async, "elastic", request_id, event, CONFIG)

    return {
        "status": "accepted",
        "source": "elastic",
        "request_id": request_id,
        "event_count": len(normalized_events),
    }


# =========================
# v4 routes
# =========================

@app.post("/v4/pipeline/run/{request_id}")
def v4_pipeline_run(request_id: str):
    from netaiops.pipeline import run_pipeline_for_request_id

    result = run_pipeline_for_request_id(
        request_id=request_id,
        auto_confirm=True,
        auto_dispatch=True,
    )

    return {
        "status": "ok",
        "stage": "v4_pipeline_run",
        "request_id": request_id,
        "result": result,
    }


@app.post("/v4/execution/result/{request_id}")
def v4_execution_result(request_id: str, payload: dict):
    from netaiops.execution_callback import handle_execution_result_callback
    from netaiops.review_builder import generate_review_for_request_id
    from netaiops.request_summary import get_request_summary
    from netaiops.notifier import send_notification

    callback_result = handle_execution_result_callback(request_id, payload)
    review_result = generate_review_for_request_id(request_id)
    summary = get_request_summary(request_id)
    notify_result = send_notification(request_id)

    return {
        "status": "ok",
        "stage": "v4_execution_result",
        "request_id": request_id,
        "callback_result": callback_result,
        "review_result": review_result,
        "summary": summary,
        "notify_result": notify_result,
    }


@app.get("/v4/request/{request_id}/summary")
def v4_request_summary(request_id: str):
    from netaiops.request_summary import get_request_summary

    return {
        "status": "ok",
        "request_id": request_id,
        "summary": get_request_summary(request_id),
    }


@app.get("/v4/dispatch/{request_id}")
def v4_dispatch_record(request_id: str):
    from netaiops.dispatcher import get_dispatch_record

    return {
        "status": "ok",
        "request_id": request_id,
        "dispatch": get_dispatch_record(request_id),
    }


@app.post("/v4/internal/auto-pipeline/{request_id}")
def v4_internal_auto_pipeline(request_id: str):
    from netaiops.pipeline import run_pipeline_safe

    result = run_pipeline_safe(
        request_id=request_id,
        auto_confirm=True,
        auto_dispatch=True,
    )

    return {
        "status": "ok" if result.get("ok") else "error",
        "stage": "v4_internal_auto_pipeline",
        "request_id": request_id,
        "result": result,
    }
