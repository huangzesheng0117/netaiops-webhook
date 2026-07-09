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
from netaiops.execution_parser_enricher import enrich_callback_execution_result
from netaiops.investigation_state import (
    build_and_persist_investigation_session,
    build_persist_session_with_notify_result,
)
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
from netaiops.light_alert_formatter import build_light_notifications
from netaiops.dongdong_card_sender import send_universal_card
from netaiops.governance.api import router as governance_router

BASE_DIR = Path("/opt/netaiops-webhook")
DATA_DIR = BASE_DIR / "data"
RAW_DIR = DATA_DIR / "raw"
NORMALIZED_DIR = DATA_DIR / "normalized"
ANALYSIS_DIR = DATA_DIR / "analysis"
PLAN_DIR = DATA_DIR / "plans"
EXECUTION_DIR = DATA_DIR / "execution"
REVIEW_DIR = DATA_DIR / "reviews"
LIGHT_ALERT_DIR = DATA_DIR / "light_alerts"
LIGHT_ALERT_RAW_DIR = LIGHT_ALERT_DIR / "raw"
LIGHT_ALERT_NOTIFY_DIR = LIGHT_ALERT_DIR / "notify"
CONFIG_FILE = BASE_DIR / "config.yaml"

RAW_DIR.mkdir(parents=True, exist_ok=True)
NORMALIZED_DIR.mkdir(parents=True, exist_ok=True)
ANALYSIS_DIR.mkdir(parents=True, exist_ok=True)
PLAN_DIR.mkdir(parents=True, exist_ok=True)
EXECUTION_DIR.mkdir(parents=True, exist_ok=True)
REVIEW_DIR.mkdir(parents=True, exist_ok=True)
LIGHT_ALERT_RAW_DIR.mkdir(parents=True, exist_ok=True)
LIGHT_ALERT_NOTIFY_DIR.mkdir(parents=True, exist_ok=True)

logger = setup_logger()
app = FastAPI(title="NetAIOps Webhook", version="3.0-a")
app.include_router(governance_router)


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


def _v10_build_evidence_detail_after_review(request_id: str, stage: str = "pipeline_after_review") -> dict:
    """Build Evidence Hub detail as a non-blocking v10 sidecar."""
    try:
        from netaiops.evidence_hub.integration import build_evidence_detail_safe

        return build_evidence_detail_safe(
            request_id=request_id,
            base_dir=BASE_DIR,
            config=CONFIG,
            stage=stage,
            logger=logger,
            overwrite=True,
        )
    except Exception as exc:
        try:
            logger.exception(
                "v10 evidence hub integration failed request_id=%s stage=%s: %r",
                request_id,
                stage,
                exc,
            )
        except Exception:
            pass
        return {
            "ok": False,
            "status": "error",
            "stage": stage,
            "request_id": request_id,
            "enabled": True,
            "error": f"{type(exc).__name__}: {exc}",
        }


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




# =========================


# =========================
# v10 Evidence Hub List / Search API
# 只读扫描 data/evidence_hub/requests/ 下的 summary/meta 索引。
# 不触发设备命令、不发送咚咚、不修改原始 data。
# =========================


@app.get("/evidence")
async def list_evidence_api(
    limit: int = 50,
    offset: int = 0,
    device_ip: str = "",
    family: str = "",
    hostname: str = "",
    request_id: str = "",
    q: str = "",
) -> dict:
    from netaiops.evidence_hub.list_api import get_evidence_list

    try:
        return get_evidence_list(
            base_dir=BASE_DIR,
            limit=limit,
            offset=offset,
            device_ip=device_ip,
            family=family,
            hostname=hostname,
            request_id=request_id,
            q=q,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

# v10 Evidence Hub Detail API
# 只读查询 data/evidence_hub/requests/<request_id>/ 下的结构化证据。
# 不触发设备命令、不发送咚咚、不修改原始 data。
# =========================


def _v10_evidence_api_response(func, request_id: str):
    try:
        return func(request_id, base_dir=BASE_DIR)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@app.get("/evidence/{request_id}/summary")
async def get_evidence_summary_api(request_id: str) -> dict:
    from netaiops.evidence_hub.detail_api import get_evidence_summary

    return _v10_evidence_api_response(get_evidence_summary, request_id)


@app.get("/evidence/{request_id}/raw")
async def get_evidence_raw_api(request_id: str) -> dict:
    from netaiops.evidence_hub.detail_api import get_evidence_section

    try:
        return get_evidence_section(request_id, "raw", base_dir=BASE_DIR)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@app.get("/evidence/{request_id}/metrics")
async def get_evidence_metrics_api(request_id: str) -> dict:
    from netaiops.evidence_hub.detail_api import get_evidence_metrics

    return _v10_evidence_api_response(get_evidence_metrics, request_id)


@app.get("/evidence/{request_id}/device")
async def get_evidence_device_api(request_id: str) -> dict:
    from netaiops.evidence_hub.detail_api import get_evidence_device

    return _v10_evidence_api_response(get_evidence_device, request_id)


@app.get("/evidence/{request_id}/review")
async def get_evidence_review_api(request_id: str) -> dict:
    from netaiops.evidence_hub.detail_api import get_evidence_review

    return _v10_evidence_api_response(get_evidence_review, request_id)


@app.get("/evidence/{request_id}")
async def get_evidence_detail_api(request_id: str) -> dict:
    from netaiops.evidence_hub.detail_api import get_evidence_detail

    return _v10_evidence_api_response(get_evidence_detail, request_id)

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
        try:
            from netaiops.log_command_hard_error_normalizer import normalize_log_command_false_hard_errors
            payload = normalize_log_command_false_hard_errors(payload)
        except Exception:
            pass
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
        evidence_detail_result = _v10_build_evidence_detail_after_review(
            request_id,
            stage="review_generate_api",
        )
        return {
            "status": "ok",
            "action": "generate_review",
            "request_id": request_id,
            "file": result["review_file"],
            "data": result["review_data"],
            "evidence_detail_result": evidence_detail_result,
        }
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


# =========================
# Light alert routes
# 独立轻量链路：Alertmanager -> Webhook -> 咚咚服务号通用卡片
# 注意：该链路不进入原 /webhook/alertmanager AI 分析主链路。
# =========================

def send_light_alert_card_task(lite_request_id: str, notify_index: int, title: str, detail: str) -> None:
    result_file = LIGHT_ALERT_NOTIFY_DIR / f"alertmanager_{lite_request_id}_{notify_index:03d}.send_result.json"

    try:
        send_result = send_universal_card(title=title, detail=detail)
    except Exception as exc:
        send_result = {
            "ok": False,
            "error": repr(exc),
            "title": title,
            "lite_request_id": lite_request_id,
            "index": notify_index,
        }

    safe_write_json(
        result_file,
        {
            "lite_request_id": lite_request_id,
            "index": notify_index,
            "title": title,
            "send_result": send_result,
            "created_at": now_utc_str(),
        },
    )

    if send_result.get("ok"):
        logger.info(
            "light alert card sent lite_request_id=%s index=%s title=%s",
            lite_request_id,
            notify_index,
            title,
        )
    else:
        logger.error(
            "light alert card send failed lite_request_id=%s index=%s title=%s result=%s",
            lite_request_id,
            notify_index,
            title,
            send_result,
        )



# Light alert mirror rate limit helpers

def light_alert_mirror_get_alerts(payload: dict) -> list:
    alerts = payload.get("alerts")
    if isinstance(alerts, list):
        return [item for item in alerts if isinstance(item, dict)]

    data = payload.get("data")
    if isinstance(data, dict) and isinstance(data.get("alerts"), list):
        return [item for item in data.get("alerts") if isinstance(item, dict)]

    if isinstance(payload.get("labels"), dict) or isinstance(payload.get("annotations"), dict):
        return [payload]

    return []


def light_alert_mirror_rate_key(payload: dict, item: dict) -> str:
    import hashlib
    import json

    labels = item.get("labels") if isinstance(item.get("labels"), dict) else {}
    annotations = item.get("annotations") if isinstance(item.get("annotations"), dict) else {}
    alerts = light_alert_mirror_get_alerts(payload)

    try:
        index = int(item.get("index", 0))
    except Exception:
        index = 0

    source_alert = alerts[index] if 0 <= index < len(alerts) else {}
    source_labels = source_alert.get("labels") if isinstance(source_alert.get("labels"), dict) else {}
    source_annotations = source_alert.get("annotations") if isinstance(source_alert.get("annotations"), dict) else {}

    fingerprint = (
        source_alert.get("fingerprint")
        or labels.get("fingerprint")
        or source_labels.get("fingerprint")
        or item.get("fingerprint")
    )
    if fingerprint:
        return f"fingerprint:{fingerprint}"

    merged_labels = {}
    merged_labels.update(source_labels)
    merged_labels.update(labels)

    key_source = {
        "alertname": merged_labels.get("alertname") or item.get("alert_name") or "",
        "ip": merged_labels.get("ip") or merged_labels.get("device_ip") or merged_labels.get("instance") or "",
        "sysName": merged_labels.get("sysName") or merged_labels.get("hostname") or "",
        "ifName": merged_labels.get("ifName") or "",
        "test_id": merged_labels.get("test_id") or "",
        "interfaces": annotations.get("interfaces") or source_annotations.get("interfaces") or "",
        "object_label": annotations.get("object_label") or source_annotations.get("object_label") or "",
        "object_key": annotations.get("object_label_key") or source_annotations.get("object_label_key") or "",
    }

    raw = json.dumps(key_source, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    return f"fallback:{digest}"


def light_alert_mirror_should_send(payload: dict, item: dict, throttle_seconds: int = 3600) -> tuple:
    import json
    import time

    status = (item.get("status") or "").strip().lower()
    key = light_alert_mirror_rate_key(payload, item)

    state_dir = LIGHT_ALERT_DIR / "state"
    state_dir.mkdir(parents=True, exist_ok=True)
    state_file = state_dir / "mirror_rate_limit.json"

    state = {}
    if state_file.exists():
        try:
            state = json.loads(state_file.read_text(encoding="utf-8"))
            if not isinstance(state, dict):
                state = {}
        except Exception:
            state = {}

    # resolved 表示当前告警生命周期结束：
    # 1. resolved 本身不限流，必须允许发送；
    # 2. 同时清除该 fingerprint 的 firing 限流记录，避免恢复后再次 firing 被旧状态挡掉。
    if status == "resolved":
        had_entry = key in state
        removed_entry = state.pop(key, None)
        if had_entry:
            safe_write_json(state_file, state)
            logger.info(
                "light alert mirror resolved cleared firing throttle key=%s title=%s",
                key,
                item.get("title", ""),
            )
        return True, {
            "limited": False,
            "reason": "resolved_cleared_firing_throttle" if had_entry else "resolved_no_existing_firing_throttle",
            "status": status,
            "key": key,
            "cleared_firing_throttle": had_entry,
            "removed_entry": removed_entry,
            "throttle_seconds": throttle_seconds,
            "title": item.get("title", ""),
        }

    if status != "firing":
        return True, {
            "limited": False,
            "reason": "status_not_firing",
            "status": status,
            "key": key,
            "throttle_seconds": throttle_seconds,
        }

    now_ts = time.time()

    entry = state.get(key)
    last_sent_at = 0.0
    if isinstance(entry, dict):
        try:
            last_sent_at = float(entry.get("last_sent_at", 0))
        except Exception:
            last_sent_at = 0.0

    if last_sent_at and now_ts - last_sent_at < throttle_seconds:
        remaining = int(throttle_seconds - (now_ts - last_sent_at))
        return False, {
            "limited": True,
            "reason": "firing_throttled",
            "status": status,
            "key": key,
            "remaining_seconds": remaining,
            "last_sent_at": last_sent_at,
            "last_sent_at_utc": entry.get("last_sent_at_utc") if isinstance(entry, dict) else "",
            "throttle_seconds": throttle_seconds,
            "title": item.get("title", ""),
        }

    cutoff = now_ts - 7 * 24 * 3600
    cleaned = {}
    for k, v in state.items():
        if not isinstance(v, dict):
            continue
        try:
            ts = float(v.get("last_sent_at", 0))
        except Exception:
            ts = 0
        if ts >= cutoff:
            cleaned[k] = v

    cleaned[key] = {
        "last_sent_at": now_ts,
        "last_sent_at_utc": now_utc_str(),
        "title": item.get("title", ""),
        "alert_name": item.get("alert_name", ""),
        "status": status,
        "throttle_seconds": throttle_seconds,
    }
    safe_write_json(state_file, cleaned)

    return True, {
        "limited": False,
        "reason": "firing_first_or_expired",
        "status": status,
        "key": key,
        "throttle_seconds": throttle_seconds,
        "title": item.get("title", ""),
    }

def mirror_light_alert_payload_task(payload: dict) -> None:
    try:
        result = build_light_notifications(payload)
        original_lite_request_id = result.get("lite_request_id", "unknown")
        lite_request_id = f"mirror_{original_lite_request_id}"
        result["lite_request_id"] = lite_request_id
        result["source"] = "mirror_from_webhook_alertmanager"
        result["mirror_rate_limit_policy"] = {
            "firing_throttle_seconds": 3600,
            "resolved_throttled": False,
            "scope": "mirror_from_/webhook/alertmanager_only",
        }

        raw_file = LIGHT_ALERT_RAW_DIR / f"alertmanager_{lite_request_id}.json"
        notify_file = LIGHT_ALERT_NOTIFY_DIR / f"alertmanager_{lite_request_id}.notifications.json"

        safe_write_json(
            raw_file,
            {
                "lite_request_id": lite_request_id,
                "source": "mirror_from_webhook_alertmanager",
                "payload": payload,
                "created_at": now_utc_str(),
            },
        )

        sent_count = 0
        throttled_count = 0
        rate_limit_decisions = []

        for item in result.get("notifications", []):
            should_send, decision = light_alert_mirror_should_send(payload, item, throttle_seconds=3600)
            decision["index"] = item.get("index")
            decision["title"] = item.get("title")
            decision["alert_name"] = item.get("alert_name")
            rate_limit_decisions.append(decision)

            if not should_send:
                throttled_count += 1
                logger.info(
                    "light alert mirror suppressed by rate limit lite_request_id=%s index=%s key=%s remaining_seconds=%s title=%s",
                    lite_request_id,
                    item.get("index"),
                    decision.get("key"),
                    decision.get("remaining_seconds"),
                    item.get("title"),
                )
                continue

            send_light_alert_card_task(
                lite_request_id,
                int(item.get("index", 0)),
                item.get("title", ""),
                item.get("detail", ""),
            )
            sent_count += 1

        result["mirror_rate_limit_decisions"] = rate_limit_decisions
        result["mirror_sent_count"] = sent_count
        result["mirror_throttled_count"] = throttled_count
        safe_write_json(notify_file, result)

        logger.info(
            "mirrored alertmanager payload to light card lite_request_id=%s alert_count=%s notification_count=%s sent_count=%s throttled_count=%s skipped_count=%s",
            lite_request_id,
            result.get("alert_count"),
            result.get("notification_count"),
            sent_count,
            throttled_count,
            result.get("skipped_count"),
        )

    except Exception as exc:
        logger.exception("mirror alertmanager payload to light card failed: %r", exc)



@app.post("/light-alert/alertmanager")
async def light_alert_alertmanager(request: Request, background_tasks: BackgroundTasks) -> dict:
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="invalid json payload")

    result = build_light_notifications(payload)
    lite_request_id = result["lite_request_id"]

    raw_file = LIGHT_ALERT_RAW_DIR / f"alertmanager_{lite_request_id}.json"
    notify_file = LIGHT_ALERT_NOTIFY_DIR / f"alertmanager_{lite_request_id}.notifications.json"

    safe_write_json(
        raw_file,
        {
            "lite_request_id": lite_request_id,
            "source": "alertmanager_light",
            "payload": payload,
            "created_at": now_utc_str(),
        },
    )

    # Batch 14.1：直接轻量入口复用 mirror 已验证的共享限流状态。
    # firing：同一 key 3600 秒内仅调度发送一次。
    # resolved：始终允许发送，并清除对应 firing 状态。
    # pending：仍由 build_light_notifications() 跳过。
    sent_count = 0
    throttled_count = 0
    rate_limit_decisions = []

    for item in result.get("notifications", []):
        should_send, decision = light_alert_mirror_should_send(
            payload,
            item,
            throttle_seconds=3600,
        )
        decision["index"] = item.get("index")
        decision["title"] = item.get("title")
        decision["alert_name"] = item.get("alert_name")
        rate_limit_decisions.append(decision)

        if not should_send:
            throttled_count += 1
            logger.info(
                "direct light alert suppressed by rate limit lite_request_id=%s index=%s key=%s remaining_seconds=%s title=%s",
                lite_request_id,
                item.get("index"),
                decision.get("key"),
                decision.get("remaining_seconds"),
                item.get("title"),
            )
            continue

        background_tasks.add_task(
            send_light_alert_card_task,
            lite_request_id,
            int(item.get("index", 0)),
            item.get("title", ""),
            item.get("detail", ""),
        )
        sent_count += 1

    result["source"] = "alertmanager_light"
    result["direct_rate_limit_policy"] = {
        "firing_throttle_seconds": 3600,
        "resolved_throttled": False,
        "state_file": str(LIGHT_ALERT_DIR / "state" / "mirror_rate_limit.json"),
        "state_scope": "shared_by_direct_and_mirror_light_alert_paths",
        "scope": "direct_/light-alert/alertmanager",
    }
    result["rate_limit_decisions"] = rate_limit_decisions
    result["sent_count"] = sent_count
    result["throttled_count"] = throttled_count

    # 必须在限流决策完成后再写通知记录，确保运行时文件可审计。
    safe_write_json(notify_file, result)

    logger.info(
        "received light alertmanager webhook lite_request_id=%s alert_count=%s notification_count=%s sent_count=%s throttled_count=%s skipped_count=%s",
        lite_request_id,
        result.get("alert_count"),
        result.get("notification_count"),
        sent_count,
        throttled_count,
        result.get("skipped_count"),
    )

    return {
        "status": "accepted",
        "source": "alertmanager_light",
        "lite_request_id": lite_request_id,
        "alert_count": result.get("alert_count"),
        # notification_count 保持兼容：表示 formatter 生成的候选通知数。
        "notification_count": result.get("notification_count"),
        "sent_count": sent_count,
        "throttled_count": throttled_count,
        "skipped_count": result.get("skipped_count"),
        "rate_limit_decisions": rate_limit_decisions,
        "raw_file": str(raw_file),
        "notify_file": str(notify_file),
    }


@app.post("/webhook/alertmanager")
async def webhook_alertmanager(request: Request, background_tasks: BackgroundTasks) -> dict:
    try:
        payload = await request.json()
        background_tasks.add_task(mirror_light_alert_payload_task, payload)
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
    parser_enrich_result = {
        "ok": False,
        "enabled": True,
        "stage": "v6.2",
        "error": "",
    }
    try:
        parser_enrich_result = enrich_callback_execution_result(callback_result)
    except Exception as exc:
        # v6.2 Parser enrichment 是旁路结构化能力，不能影响原 callback/review/notify 主链路。
        parser_enrich_result = {
            "ok": False,
            "enabled": True,
            "stage": "v6.2",
            "error": str(exc),
        }

    review_result = generate_review_for_request_id(request_id)
    evidence_detail_result = _v10_build_evidence_detail_after_review(
        request_id,
        stage="v4_execution_result_after_review",
    )
    summary = get_request_summary(request_id)
    notify_result = send_notification(request_id)

    investigation_result = {
        "ok": False,
        "enabled": True,
        "stage": "v6.1",
        "error": "",
    }
    try:
        investigation_session, investigation_file = build_persist_session_with_notify_result(
            request_id=request_id,
            notify_result=notify_result,
            base_dir=BASE_DIR,
        )
        investigation_result = {
            "ok": True,
            "enabled": True,
            "stage": "v6.1",
            "session_file": str(investigation_file),
            "session_status": investigation_session.get("session_status"),
            "timeline_count": len(investigation_session.get("timeline") or []),
        }
    except Exception as exc:
        # Investigation Session 是 v6.1 旁路审计能力，不能影响原 v4/v5 回调主链路。
        investigation_result = {
            "ok": False,
            "enabled": True,
            "stage": "v6.1",
            "error": str(exc),
        }

    interface_error_delta_schedule_result = {
        "ok": True,
        "enabled": True,
        "stage": "v7.9",
        "scheduled": False,
        "reason": "not_evaluated",
    }
    try:
        from netaiops.interface_error_delta import maybe_schedule_from_callback
        interface_error_delta_schedule_result = maybe_schedule_from_callback(
            request_id=request_id,
            callback_result=callback_result,
            base_dir=BASE_DIR,
        )
    except Exception as exc:
        interface_error_delta_schedule_result = {
            "ok": False,
            "enabled": True,
            "stage": "v7.9",
            "scheduled": False,
            "error": str(exc),
        }

    return {
        "status": "ok",
        "stage": "v4_execution_result",
        "request_id": request_id,
        "callback_result": callback_result,
        "parser_enrich_result": parser_enrich_result,
        "review_result": review_result,
        "summary": summary,
        "notify_result": notify_result,
        "investigation_result": investigation_result,
        "interface_error_delta_schedule_result": interface_error_delta_schedule_result,
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




# ===== light mirror resolved inside v5 skip helper begin =====
def _light_mirror_is_resolved_alert_for_v5_skip(alert: dict) -> bool:
    if not isinstance(alert, dict):
        return False

    labels = alert.get("labels") if isinstance(alert.get("labels"), dict) else {}
    annotations = alert.get("annotations") if isinstance(alert.get("annotations"), dict) else {}

    status = (
        str(alert.get("status") or "")
        or str(labels.get("status") or "")
        or str(annotations.get("status") or "")
    ).strip().lower()

    restored = (
        str(alert.get("restored") or "")
        or str(labels.get("restored") or "")
        or str(annotations.get("restored") or "")
    ).strip().lower()

    if status in {"resolved", "resolve", "restored"}:
        return True
    if restored in {"true", "1", "yes", "y"}:
        return True
    return False


def _light_mirror_extract_resolved_payload_for_v5_skip(payload: dict) -> dict:
    if not isinstance(payload, dict):
        return {}

    alerts = payload.get("alerts")
    if isinstance(alerts, list):
        resolved_alerts = [item for item in alerts if _light_mirror_is_resolved_alert_for_v5_skip(item)]
        if not resolved_alerts:
            return {}

        copied = dict(payload)
        copied["alerts"] = resolved_alerts
        copied["status"] = "resolved"
        copied["source"] = "resolved_mirrored_inside_v5_skip"
        return copied

    if _light_mirror_is_resolved_alert_for_v5_skip(payload):
        copied = dict(payload)
        copied["status"] = "resolved"
        copied["source"] = "resolved_mirrored_inside_v5_skip"
        return copied

    return {}


def mirror_resolved_alerts_to_light_from_v5_skip(payload: dict) -> None:
    try:
        import threading

        resolved_payload = _light_mirror_extract_resolved_payload_for_v5_skip(payload)
        if not resolved_payload:
            return

        thread = threading.Thread(
            target=mirror_light_alert_payload_task,
            args=(resolved_payload,),
            daemon=True,
        )
        thread.start()
        logger.info(
            "scheduled resolved alert payload to light mirror inside v5 skip middleware alert_count=%s",
            len(resolved_payload.get("alerts", [])) if isinstance(resolved_payload.get("alerts"), list) else 1,
        )
    except Exception as exc:
        logger.exception("failed to schedule resolved alert payload inside v5 skip middleware: %r", exc)
# ===== light mirror resolved inside v5 skip helper end =====

# ===== v5 skip resolved alertmanager/prometheus alerts begin =====
# Resolved 恢复告警不进入分析流程：
# 1. 全 resolved payload：直接返回 skipped。
# 2. mixed payload：只保留 firing alerts，丢弃 resolved alerts 后继续进入原 webhook 流程。
# 3. 非 webhook 路径不受影响。

try:
    import json as _v5sr_json
    from starlette.requests import Request as _V5SRRequest
    from starlette.responses import JSONResponse as _V5SRJSONResponse

    from netaiops.alert_status_filter import filter_firing_alerts as _v5sr_filter_firing_alerts

    if not getattr(app.state, "v5_skip_resolved_alerts_enabled", False):
        app.state.v5_skip_resolved_alerts_enabled = True

        @app.middleware("http")
        async def v5_skip_resolved_alerts_middleware(request: _V5SRRequest, call_next):
            path = request.url.path or ""

            # 只处理 webhook 告警入口，避免影响 health / summary / query 等接口。
            if request.method.upper() == "POST" and "/webhook/" in path:
                body = await request.body()

                try:
                    payload = _v5sr_json.loads(body.decode("utf-8", errors="replace") or "{}")
                    # light mirror resolved inside v5 skip call
                    try:
                        mirror_resolved_alerts_to_light_from_v5_skip(payload)
                    except Exception as exc:
                        logger.exception("mirror resolved payload inside v5 skip failed: %r", exc)
                except Exception:
                    async def receive_original():
                        return {
                            "type": "http.request",
                            "body": body,
                            "more_body": False,
                        }

                    request = _V5SRRequest(request.scope, receive_original)
                    return await call_next(request)

                action, filtered_payload, meta = _v5sr_filter_firing_alerts(payload)

                if action == "skip_resolved":
                    return _V5SRJSONResponse(
                        {
                            "status": "skipped",
                            "reason": "resolved_alert_ignored",
                            "message": "resolved alert payload ignored; no analysis will be triggered",
                            "analysis_skipped": True,
                            "mcp_skipped": True,
                            "notify_skipped": True,
                            "path": path,
                            "filter_meta": meta,
                        }
                    )

                if action == "pass_filtered":
                    body = _v5sr_json.dumps(filtered_payload, ensure_ascii=False).encode("utf-8")

                async def receive_filtered():
                    return {
                        "type": "http.request",
                        "body": body,
                        "more_body": False,
                    }

                request = _V5SRRequest(request.scope, receive_filtered)

            return await call_next(request)

except Exception as _v5sr_exc:
    # 不因中间件注册失败影响主服务启动。
    try:
        print("WARN: v5 skip resolved alerts middleware init failed:", _v5sr_exc)
    except Exception:
        pass
# ===== v5 skip resolved alertmanager/prometheus alerts end =====



# ===== v6.1 investigation session APIs begin =====
@app.get("/v6/investigation/{request_id}")
def v6_get_investigation_session(request_id: str, build: bool = True):
    try:
        if build:
            session, session_file = build_and_persist_investigation_session(
                request_id=request_id,
                base_dir=BASE_DIR,
            )
        else:
            from netaiops.investigation_state import build_investigation_session
            session = build_investigation_session(
                request_id=request_id,
                base_dir=BASE_DIR,
            )
            session_file = BASE_DIR / "data" / "investigation" / f"{request_id}.investigation.session.json"

        return {
            "status": "ok",
            "stage": "v6.1_investigation_session",
            "request_id": request_id,
            "session_file": str(session_file),
            "session": session,
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/v6/investigation/{request_id}/build")
def v6_build_investigation_session(request_id: str):
    try:
        session, session_file = build_and_persist_investigation_session(
            request_id=request_id,
            base_dir=BASE_DIR,
        )
        return {
            "status": "ok",
            "stage": "v6.1_investigation_session_build",
            "request_id": request_id,
            "session_file": str(session_file),
            "session_status": session.get("session_status"),
            "timeline_count": len(session.get("timeline") or []),
            "session": session,
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
# ===== v6.1 investigation session APIs end =====



# ===== v6.4 skill runtime APIs begin =====
@app.get("/v6/skills/runtime")
def v6_skill_runtime_index():
    try:
        from netaiops.skill_runtime_api import build_runtime_index_response
        return build_runtime_index_response(BASE_DIR)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/v6/skills/runtime/validate")
def v6_skill_runtime_validate():
    try:
        from netaiops.skill_runtime_api import build_runtime_validate_response
        return build_runtime_validate_response(BASE_DIR)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/v6/skills/runtime/family/{family}")
def v6_skill_runtime_by_family(family: str, levels: str = "metadata"):
    try:
        from netaiops.skill_runtime_api import build_runtime_family_response
        return build_runtime_family_response(
            family=family,
            base_dir=BASE_DIR,
            levels=levels,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/v6/skills/runtime/skill/{skill_name}")
def v6_skill_runtime_by_skill(skill_name: str, levels: str = "metadata"):
    try:
        from netaiops.skill_runtime_api import build_runtime_skill_response
        return build_runtime_skill_response(
            skill_name=skill_name,
            base_dir=BASE_DIR,
            levels=levels,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
# ===== v6.4 skill runtime APIs end =====



# ===== v6.5 adaptive evidence APIs begin =====
@app.get("/v6/adaptive/plan/{request_id}")
def v6_adaptive_plan(request_id: str, include_candidates: bool = True):
    try:
        from netaiops.adaptive_evidence_api import build_adaptive_plan_response
        return build_adaptive_plan_response(
            request_id=request_id,
            base_dir=BASE_DIR,
            include_candidates=include_candidates,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/v6/adaptive/simulate/missing-facts")
def v6_adaptive_simulate_missing_facts(include_candidates: bool = True, strict: bool = True):
    try:
        from netaiops.adaptive_evidence_api import build_missing_facts_simulation_response
        return build_missing_facts_simulation_response(
            base_dir=BASE_DIR,
            include_candidates=include_candidates,
            strict=strict,
        )
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
# ===== v6.5 adaptive evidence APIs end =====

# ===== v7.1 incident memory APIs begin =====
@app.get("/v7/memory/incidents")
def v7_memory_incidents(
    family: str = "",
    hostname: str = "",
    interface: str = "",
    q: str = "",
    days: int = 0,
    limit: int = 20,
    rebuild: bool = False,
    rebuild_limit: int = 0,
):
    try:
        from netaiops.memory_api import build_incidents_response
        return build_incidents_response(
            base_dir=BASE_DIR,
            family=family,
            hostname=hostname,
            interface=interface,
            q=q,
            days=days,
            limit=limit,
            rebuild=rebuild,
            rebuild_limit=rebuild_limit,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/v7/memory/incidents/{request_id}")
def v7_memory_incident_detail(request_id: str, build: bool = True, write: bool = True):
    try:
        from netaiops.memory_api import build_incident_detail_response
        return build_incident_detail_response(
            request_id=request_id,
            base_dir=BASE_DIR,
            build=build,
            write=write,
        )
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
# ===== v7.1 incident memory APIs end =====

# ===== v7.2 relation engine APIs begin =====
@app.get("/v7/relations/incidents")
def v7_relation_incidents(
    family: str = "",
    hostname: str = "",
    interface: str = "",
    relation_type: str = "",
    min_score: int = 0,
    limit: int = 20,
    rebuild: bool = False,
    rebuild_limit: int = 0,
):
    try:
        from netaiops.relation_api import build_relations_response
        return build_relations_response(
            base_dir=BASE_DIR,
            family=family,
            hostname=hostname,
            interface=interface,
            relation_type=relation_type,
            min_score=min_score,
            limit=limit,
            rebuild=rebuild,
            rebuild_limit=rebuild_limit,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/v7/relations/rebuild")
def v7_relation_rebuild(limit: int = 0):
    try:
        from netaiops.relation_api import build_relation_rebuild_response
        return build_relation_rebuild_response(
            base_dir=BASE_DIR,
            limit=limit,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/v7/relations/incidents/{request_id}")
def v7_relation_incident_detail(
    request_id: str,
    rebuild: bool = False,
    rebuild_limit: int = 0,
):
    try:
        from netaiops.relation_api import build_relation_detail_response
        return build_relation_detail_response(
            request_id=request_id,
            base_dir=BASE_DIR,
            rebuild=rebuild,
            rebuild_limit=rebuild_limit,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
# ===== v7.2 relation engine APIs end =====

# ===== v7.3 skill proposal APIs begin =====
@app.get("/v7/skill-proposals")
def v7_skill_proposals(
    family: str = "",
    proposal_type: str = "",
    verdict: str = "",
    min_score: int = 0,
    limit: int = 20,
    rebuild: bool = False,
    limit_clusters: int = 0,
):
    try:
        from netaiops.skill_proposal_api import query_skill_proposals_response
        return query_skill_proposals_response(
            base_dir=BASE_DIR,
            family=family,
            proposal_type=proposal_type,
            verdict=verdict,
            min_score=min_score,
            limit=limit,
            rebuild=rebuild,
            limit_clusters=limit_clusters,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/v7/skill-proposals/rebuild")
def v7_skill_proposals_rebuild(
    limit_clusters: int = 0,
    rebuild_relations: bool = False,
):
    try:
        from netaiops.skill_proposal_api import build_skill_proposals_response
        return build_skill_proposals_response(
            base_dir=BASE_DIR,
            limit_clusters=limit_clusters,
            rebuild_relations=rebuild_relations,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/v7/skill-proposals/{proposal_id}")
def v7_skill_proposal_detail(proposal_id: str):
    try:
        from netaiops.skill_proposal_api import skill_proposal_detail_response
        return skill_proposal_detail_response(
            proposal_id=proposal_id,
            base_dir=BASE_DIR,
        )
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
# ===== v7.3 skill proposal APIs end =====

# ===== v7.4 skill proposal review APIs begin =====
@app.get("/v7/skill-proposal-reviews/summary")
def v7_skill_proposal_review_summary():
    try:
        from netaiops.skill_proposal_review_api import review_summary_response
        return review_summary_response(base_dir=BASE_DIR)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/v7/skill-proposal-reviews/pending")
def v7_skill_proposal_review_pending(min_score: int = 0, limit: int = 20):
    try:
        from netaiops.skill_proposal_review_api import pending_reviews_response
        return pending_reviews_response(
            base_dir=BASE_DIR,
            min_score=min_score,
            limit=limit,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/v7/skill-proposal-reviews")
def v7_skill_proposal_reviews(
    proposal_id: str = "",
    decision: str = "",
    reviewer: str = "",
    family: str = "",
    limit: int = 20,
):
    try:
        from netaiops.skill_proposal_review_api import query_reviews_response
        return query_reviews_response(
            base_dir=BASE_DIR,
            proposal_id=proposal_id,
            decision=decision,
            reviewer=reviewer,
            family=family,
            limit=limit,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/v7/skill-proposal-reviews/{proposal_id}")
def v7_skill_proposal_review_status(proposal_id: str):
    try:
        from netaiops.skill_proposal_review_api import proposal_review_status_response
        return proposal_review_status_response(
            proposal_id=proposal_id,
            base_dir=BASE_DIR,
        )
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/v7/skill-proposal-reviews/{proposal_id}")
def v7_skill_proposal_review_create(
    proposal_id: str,
    decision: str,
    reviewer: str = "manual_reviewer",
    comment: str = "",
    next_action: str = "",
):
    try:
        from netaiops.skill_proposal_review_api import create_review_response
        return create_review_response(
            proposal_id=proposal_id,
            decision=decision,
            reviewer=reviewer,
            comment=comment,
            next_action=next_action,
            base_dir=BASE_DIR,
        )
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
# ===== v7.4 skill proposal review APIs end =====

# ===== v7.5 skill draft APIs begin =====
@app.get("/v7/skill-drafts")
def v7_skill_drafts(
    family: str = "",
    proposal_id: str = "",
    limit: int = 20,
):
    try:
        from netaiops.skill_draft_api import query_skill_drafts_response
        return query_skill_drafts_response(
            base_dir=BASE_DIR,
            family=family,
            proposal_id=proposal_id,
            limit=limit,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/v7/skill-drafts/rebuild")
def v7_skill_drafts_rebuild(proposal_id: str = ""):
    try:
        from netaiops.skill_draft_api import build_skill_drafts_response
        return build_skill_drafts_response(
            base_dir=BASE_DIR,
            proposal_id=proposal_id,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/v7/skill-drafts/{draft_id}")
def v7_skill_draft_detail(draft_id: str):
    try:
        from netaiops.skill_draft_api import skill_draft_detail_response
        return skill_draft_detail_response(
            draft_id=draft_id,
            base_dir=BASE_DIR,
        )
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
# ===== v7.5 skill draft APIs end =====

# ===== v7.6 learning report APIs begin =====
@app.get("/v7/learning/report")
def v7_learning_report(rebuild: bool = False):
    try:
        from netaiops.learning_report_api import latest_learning_report_response
        return latest_learning_report_response(
            base_dir=BASE_DIR,
            rebuild=rebuild,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/v7/learning/reports/rebuild")
def v7_learning_reports_rebuild():
    try:
        from netaiops.learning_report_api import build_learning_report_response
        return build_learning_report_response(base_dir=BASE_DIR)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/v7/learning/reports")
def v7_learning_reports(limit: int = 20):
    try:
        from netaiops.learning_report_api import list_learning_reports_response
        return list_learning_reports_response(
            base_dir=BASE_DIR,
            limit=limit,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/v7/learning/reports/{report_id}")
def v7_learning_report_detail(report_id: str):
    try:
        from netaiops.learning_report_api import learning_report_detail_response
        return learning_report_detail_response(
            report_id=report_id,
            base_dir=BASE_DIR,
        )
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
# ===== v7.6 learning report APIs end =====

# ===== v7.7 release audit APIs begin =====
@app.get("/v7/release/audit")
def v7_release_audit(write: bool = False):
    try:
        from netaiops.v7_release_audit_api import v7_release_audit_response
        return v7_release_audit_response(
            base_dir=BASE_DIR,
            write=write,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
# ===== v7.7 release audit APIs end =====

# ===== v7.9 interface error delta APIs begin =====
@app.get("/v7/interface-error-delta")
def v7_interface_error_delta_list(limit: int = 20):
    try:
        from netaiops.interface_error_delta import list_delta_results
        rows = list_delta_results(base_dir=BASE_DIR, limit=limit)
        return {
            "status": "ok",
            "stage": "v7.9_interface_error_delta_recheck",
            "count": len(rows),
            "records": rows,
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/v7/interface-error-delta/{request_id}")
def v7_interface_error_delta_detail(request_id: str):
    try:
        from netaiops.interface_error_delta import read_delta_result
        return {
            "status": "ok",
            "stage": "v7.9_interface_error_delta_recheck",
            "request_id": request_id,
            "data": read_delta_result(request_id, base_dir=BASE_DIR),
        }
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/v7/interface-error-delta/{request_id}/run")
def v7_interface_error_delta_run(request_id: str, delay_seconds: int = 0):
    try:
        from netaiops.interface_error_delta import run_delta_check
        result = run_delta_check(
            request_id=request_id,
            base_dir=BASE_DIR,
            delay_seconds=delay_seconds,
            execute=True,
        )
        return {
            "status": "ok",
            "stage": "v7.9_interface_error_delta_recheck",
            "request_id": request_id,
            "data": result,
        }
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
# ===== v7.9 interface error delta APIs end =====

# ===== v7.10 LLM resilience APIs begin =====
@app.get("/v7/llm/health")
def v7_llm_health(include_models: bool = False, chat_smoke: bool = False):
    try:
        from netaiops.llm_client import check_llm_health

        return {
            "status": "ok",
            "stage": "v7.10_llm_resilience",
            "data": check_llm_health(
                CONFIG,
                include_models=include_models,
                chat_smoke=chat_smoke,
            ),
        }
    except Exception as exc:
        return {
            "status": "error",
            "stage": "v7.10_llm_resilience",
            "error": str(exc),
        }
# ===== v7.10 LLM resilience APIs end =====

# =========================

# =========================
# v10 Evidence Hub Minimal Frontend UI
# 只读展示 data/evidence_hub/requests/ 下的结构化证据。
# 不触发设备命令、不发送咚咚、不修改原始 data。
# =========================


@app.get("/evidence-ui")
async def evidence_ui_index_api(
    limit: int = 50,
    offset: int = 0,
    device_ip: str = "",
    family: str = "",
    hostname: str = "",
    request_id: str = "",
    q: str = "",
):
    from fastapi.responses import HTMLResponse
    from netaiops.evidence_hub.ui_api import build_evidence_index_html

    try:
        html = build_evidence_index_html(
            base_dir=BASE_DIR,
            limit=limit,
            offset=offset,
            device_ip=device_ip,
            family=family,
            hostname=hostname,
            request_id=request_id,
            q=q,
        )
        return HTMLResponse(content=html)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/evidence-ui/{request_id}")
async def evidence_ui_detail_api(request_id: str):
    from fastapi.responses import HTMLResponse
    from netaiops.evidence_hub.ui_api import build_evidence_detail_html

    try:
        html = build_evidence_detail_html(request_id, base_dir=BASE_DIR)
        return HTMLResponse(content=html)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

# End v10 Evidence Hub Minimal Frontend UI
