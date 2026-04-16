import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict
from urllib import request


BASE_DIR = Path("/opt/netaiops-webhook")
DATA_DIR = BASE_DIR / "data"
CALLBACK_DIR = DATA_DIR / "callback"


def now_utc_str() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def post_execution_result(
    webhook_base_url: str,
    request_id: str,
    payload: Dict[str, Any],
    timeout: int = 15,
) -> Dict[str, Any]:
    url = f"{webhook_base_url.rstrip('/')}/v4/execution/result/{request_id}"

    local_record = {
        "request_id": request_id,
        "callback_url": url,
        "payload": payload,
        "submitted_at": now_utc_str(),
    }
    safe_write_json(CALLBACK_DIR / f"{request_id}.callback.request.json", local_record)

    body = json.dumps(payload).encode("utf-8")
    req = request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    with request.urlopen(req, timeout=timeout) as resp:
        response_text = resp.read().decode("utf-8", errors="replace")
        status_code = resp.getcode()

    response_data = {
        "request_id": request_id,
        "status_code": status_code,
        "response_text": response_text,
        "callback_url": url,
        "received_at": now_utc_str(),
    }
    safe_write_json(CALLBACK_DIR / f"{request_id}.callback.response.json", response_data)

    return response_data
