import json
import os
from datetime import datetime, timezone

from netaiops.llm_client import call_llm
from netaiops.logger import setup_logger
from netaiops.prompts import PROMPT_VERSION, build_analysis_prompt


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


def maybe_run_v4_pipeline(request_id: str, config: dict | None = None) -> dict | None:
    config = config or {}
    pipeline_cfg = config.get("pipeline", {}) or {}

    enabled = bool(pipeline_cfg.get("enabled", False))
    auto_confirm = bool(pipeline_cfg.get("auto_confirm", True))
    auto_dispatch = bool(pipeline_cfg.get("auto_dispatch", True))

    if not enabled:
        logger.info("v4 pipeline disabled request_id=%s", request_id)
        return None

    try:
        from netaiops.pipeline import run_pipeline_safe

        result = run_pipeline_safe(
            request_id=request_id,
            auto_confirm=auto_confirm,
            auto_dispatch=auto_dispatch,
        )

        if result.get("ok"):
            logger.info(
                "v4 pipeline completed request_id=%s auto_confirm=%s auto_dispatch=%s",
                request_id,
                auto_confirm,
                auto_dispatch,
            )
        else:
            logger.error(
                "v4 pipeline failed request_id=%s error=%s",
                request_id,
                result.get("error"),
            )

        return result
    except Exception as exc:
        logger.exception("unexpected v4 pipeline error request_id=%s", request_id)
        return {
            "ok": False,
            "request_id": request_id,
            "result": None,
            "error": str(exc),
        }


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
        "created_at": datetime.now(timezone.utc).isoformat(),
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

    if output.get("analysis_status") == "success":
        pipeline_result = maybe_run_v4_pipeline(request_id, config=config)

        pipeline_meta_path = os.path.join(
            analysis_dir,
            f"{source}_{request_id}.pipeline.json",
        )
        with open(pipeline_meta_path, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "request_id": request_id,
                    "source": source,
                    "pipeline_result": pipeline_result,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                },
                f,
                ensure_ascii=False,
                indent=2,
            )

        logger.info("pipeline metadata saved path=%s", pipeline_meta_path)
