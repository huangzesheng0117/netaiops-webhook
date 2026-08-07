from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Mapping

from agent_runner.callback_client import post_execution_result


BASE_DIR = Path("/opt/netaiops-webhook")
CALLBACK_DIR = BASE_DIR / "data" / "callback"
EXECUTION_DIR = BASE_DIR / "data" / "execution"
REVIEW_DIR = BASE_DIR / "data" / "reviews"
INTERNAL_WEBHOOK_BASE_URL = "http://127.0.0.1:18080"

DEVICE_EVIDENCE_BLOCK_REASONS = {
    "vendor_not_supported",
    "device_ip_missing",
    "plan_not_readonly_only",
    "guard_not_all_readonly",
    "classification_not_allow_auto_execute",
    "command_count_exceeded",
    "playbook_not_readonly_only",
    "playbook_auto_execute_disabled",
    "interface_target_missing",
    "interface_target_invalid",
    "interface_command_invalid",
}
SUPPRESS_DELIVERY_REASONS = {
    "cooldown_duplicate_alert",
    "same_device_active_dispatch_limit",
}


def now_utc_str() -> str:
    return datetime.now(timezone.utc).isoformat()


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def policy_reasons(plan_data: Mapping[str, Any]) -> list[str]:
    policy = _mapping(plan_data.get("policy_result"))
    return [
        _text(item)
        for item in (policy.get("reasons") or [])
        if _text(item)
    ]


def should_run_blocked_safe_delivery(
    plan_data: Mapping[str, Any],
) -> Dict[str, Any]:
    policy = _mapping(plan_data.get("policy_result"))
    reasons = policy_reasons(plan_data)
    reason_set = set(reasons)

    suppressed = sorted(reason_set & SUPPRESS_DELIVERY_REASONS)
    eligible = sorted(reason_set & DEVICE_EVIDENCE_BLOCK_REASONS)

    if policy.get("auto_confirm_allowed") is True:
        return {
            "eligible": False,
            "reason": "policy_allows_normal_execution",
            "policy_reasons": reasons,
            "device_block_reasons": [],
            "suppressed_reasons": [],
        }
    if suppressed:
        return {
            "eligible": False,
            "reason": "delivery_suppressed_by_alert_throttle",
            "policy_reasons": reasons,
            "device_block_reasons": eligible,
            "suppressed_reasons": suppressed,
        }
    if not eligible:
        return {
            "eligible": False,
            "reason": "no_supported_device_evidence_block_reason",
            "policy_reasons": reasons,
            "device_block_reasons": [],
            "suppressed_reasons": [],
        }

    return {
        "eligible": True,
        "reason": "device_evidence_blocked_continue_downstream",
        "policy_reasons": reasons,
        "device_block_reasons": eligible,
        "suppressed_reasons": [],
    }


def build_blocked_safe_callback_payload(
    request_id: str,
    plan_data: Mapping[str, Any],
    decision: Mapping[str, Any],
) -> Dict[str, Any]:
    return {
        "request_id": request_id,
        "runner_mode": "blocked_safe",
        "target_scope": dict(_mapping(plan_data.get("target_scope"))),
        "classification": dict(
            _mapping(plan_data.get("classification"))
        ),
        "playbook": dict(_mapping(plan_data.get("playbook"))),
        "family_result": dict(
            _mapping(plan_data.get("family_result"))
        ),
        "capability_plan": dict(
            _mapping(plan_data.get("capability_plan"))
        ),
        "execution_source": _text(plan_data.get("execution_source")),
        "readonly_only": plan_data.get("readonly_only"),
        "policy_result": dict(
            _mapping(plan_data.get("policy_result"))
        ),
        "precheck_result": {
            "stop": True,
            "status": "blocked_safe",
            "reason": decision.get("reason"),
            "policy_reasons": decision.get("policy_reasons") or [],
        },
        "guard_result": dict(
            _mapping(plan_data.get("guard_result"))
        ),
        "interface_target_guard": dict(
            _mapping(plan_data.get("interface_target_guard"))
        ),
        "command_results": [],
        "blocked_safe": {
            "active": True,
            "status": "device_evidence_not_executed",
            "reason": decision.get("reason"),
            "reason_codes": decision.get("device_block_reasons") or [],
            "policy_reasons": decision.get("policy_reasons") or [],
            "message": (
                "设备取证因安全门禁未执行；继续使用已有告警和指标证据"
                "生成降级Review与通知。"
            ),
        },
        "completed_at": now_utc_str(),
        "source_dispatch_file": "",
    }


def _terminal_artifacts_exist(
    request_id: str,
    *,
    base_dir: Path,
) -> bool:
    callback_dir = base_dir / "data" / "callback"
    execution_dir = base_dir / "data" / "execution"
    review_dir = base_dir / "data" / "reviews"
    patterns = (
        callback_dir / f"{request_id}.callback.response.json",
        execution_dir / f"*_{request_id}.execution.json",
        review_dir / f"*_{request_id}.review.json",
    )
    return any(
        bool(list(path.parent.glob(path.name)))
        for path in patterns
    )


def _safe_write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(dict(payload), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def run_blocked_safe_delivery(
    request_id: str,
    plan_data: Mapping[str, Any],
    *,
    base_dir: Path = BASE_DIR,
    callback_sender: Callable[..., Dict[str, Any]] = post_execution_result,
    webhook_base_url: str = INTERNAL_WEBHOOK_BASE_URL,
) -> Dict[str, Any]:
    decision = should_run_blocked_safe_delivery(plan_data)
    result: Dict[str, Any] = {
        "request_id": request_id,
        "eligible": bool(decision.get("eligible")),
        "invoked": False,
        "decision": decision,
        "callback_result": None,
        "error": "",
    }

    if not decision.get("eligible"):
        return result
    if _terminal_artifacts_exist(request_id, base_dir=Path(base_dir)):
        result["decision"] = {
            **decision,
            "eligible": False,
            "reason": "terminal_artifacts_already_exist",
        }
        return result

    payload = build_blocked_safe_callback_payload(
        request_id,
        plan_data,
        decision,
    )
    audit_path = (
        Path(base_dir)
        / "data"
        / "callback"
        / f"{request_id}.blocked_safe.delivery.json"
    )
    _safe_write_json(
        audit_path,
        {
            "request_id": request_id,
            "decision": decision,
            "payload_summary": {
                "runner_mode": payload.get("runner_mode"),
                "blocked_safe": payload.get("blocked_safe"),
                "command_count": len(payload.get("command_results") or []),
            },
            "created_at": now_utc_str(),
        },
    )

    try:
        callback_result = callback_sender(
            webhook_base_url=webhook_base_url,
            request_id=request_id,
            payload=payload,
            timeout=30,
        )
        result["invoked"] = True
        result["callback_result"] = callback_result
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"

    _safe_write_json(
        audit_path,
        {
            "request_id": request_id,
            "decision": decision,
            "invoked": result["invoked"],
            "callback_result": result["callback_result"],
            "error": result["error"],
            "finished_at": now_utc_str(),
        },
    )
    return result
