import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

import yaml
from fastapi import BackgroundTasks, FastAPI, HTTPException, Request

from netaiops.logger import setup_logger
from netaiops.processor import process_event_async
from netaiops.normalizers import normalize_alertmanager, normalize_elastic


BASE_DIR = Path("/opt/netaiops-webhook")
DATA_DIR = BASE_DIR / "data"
RAW_DIR = DATA_DIR / "raw"
NORMALIZED_DIR = DATA_DIR / "normalized"
ANALYSIS_DIR = DATA_DIR / "analysis"
CONFIG_FILE = BASE_DIR / "config.yaml"

RAW_DIR.mkdir(parents=True, exist_ok=True)
NORMALIZED_DIR.mkdir(parents=True, exist_ok=True)
ANALYSIS_DIR.mkdir(parents=True, exist_ok=True)

logger = setup_logger()

app = FastAPI(title="NetAIOps Webhook", version="2.0-c")


def load_config() -> dict:
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    return {}


CONFIG = load_config()


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
        "version": "2.0-c",
        "time": now_utc_str(),
    }


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
