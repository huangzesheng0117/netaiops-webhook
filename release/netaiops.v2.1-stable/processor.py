import json
import os
from datetime import datetime, timezone

from netaiops.prompts import PROMPT_VERSION, build_analysis_prompt
from netaiops.llm_client import call_llm
from netaiops.logger import setup_logger


logger = setup_logger()


def classify_error(exc: Exception) -> str:
    msg = str(exc).lower()

    if "timed out" in msg or "timeout" in msg:
        return "timeout"
    if "401" in msg or "403" in msg or "unauthorized" in msg or "forbidden" in msg:
        return "auth_error"
    if "404" in msg:
        return "not_found"
    if "429" in msg or "rate limit" in msg:
        return "rate_limit"
    if "json" in msg and "parse" in msg:
        return "json_parse_error"
    if "connection" in msg or "connect" in msg:
        return "connection_error"

    return "unknown_error"


def process_event_async(source: str, request_id: str, event: dict, config: dict | None = None) -> None:
    config = config or {}
    llm_cfg = config.get("llm", {}) or {}
    analysis_cfg = config.get("analysis", {}) or {}

    save_prompt = bool(analysis_cfg.get("save_prompt", True))
    save_result = bool(analysis_cfg.get("save_result", True))

    analysis_dir = "/opt/netaiops-webhook/data/analysis"
    os.makedirs(analysis_dir, exist_ok=True)

    prompt = build_analysis_prompt(event)

    output = {
        "request_id": request_id,
        "source": source,
        "analysis_status": "unknown",
        "model": "",
        "prompt_version": PROMPT_VERSION,
        "llm_enabled": bool(llm_cfg.get("enabled", False)),
        "llm_provider": llm_cfg.get("provider", ""),
        "llm_model_requested": llm_cfg.get("model", ""),
        "error_type": "",
        "event": event,
        "created_at": datetime.now(timezone.utc).isoformat()
    }

    if save_prompt:
        output["prompt"] = prompt

    try:
        llm_result = call_llm(prompt, config=config)
        output["analysis_status"] = "success"
        output["model"] = llm_result.get("model", "unknown")
        if save_result:
            output["result"] = llm_result.get("analysis", {})
        logger.info("analysis success request_id=%s source=%s", request_id, source)
    except Exception as exc:
        output["analysis_status"] = "failed"
        output["error_type"] = classify_error(exc)
        if save_result:
            output["result"] = {
                "error": str(exc)
            }
        logger.exception("analysis failed request_id=%s source=%s", request_id, source)

    filename = f"{source}_{request_id}.analysis.json"
    filepath = os.path.join(analysis_dir, filename)

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2)

    logger.info("analysis file saved path=%s", filepath)
