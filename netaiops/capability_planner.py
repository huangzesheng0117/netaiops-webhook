import json
import os
import urllib.request
from pathlib import Path
from typing import Any, Dict, List

import yaml

from netaiops.capability_registry import CAPABILITY_REGISTRY


BASE_DIR = Path("/opt/netaiops-webhook")
CONFIG_FILE = BASE_DIR / "config.yaml"


def safe_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def load_config() -> Dict[str, Any]:
    if not CONFIG_FILE.exists():
        return {}
    try:
        return yaml.safe_load(CONFIG_FILE.read_text(encoding="utf-8")) or {}
    except Exception:
        return {}


def get_planner_config() -> Dict[str, Any]:
    cfg = load_config()
    planner = cfg.get("capability_planner", {}) or {}
    llm = cfg.get("llm", {}) or {}

    enabled = bool(planner.get("enabled", False))

    base_url = safe_text(planner.get("base_url")) or safe_text(llm.get("base_url"))
    model = safe_text(planner.get("model")) or safe_text(llm.get("model"))
    api_key_env = safe_text(planner.get("api_key_env")) or safe_text(llm.get("api_key_env")) or "NETAIOPS_LLM_API_KEY"

    families_enabled = planner.get("families_enabled", []) or []
    if isinstance(families_enabled, str):
        families_enabled = [x.strip() for x in families_enabled.split(",") if x.strip()]

    return {
        "enabled": enabled,
        "provider": safe_text(planner.get("provider")) or safe_text(llm.get("provider")) or "openai_compatible",
        "base_url": base_url.rstrip("/"),
        "model": model,
        "api_key_env": api_key_env,
        "timeout": int(planner.get("timeout", 45)),
        "temperature": float(planner.get("temperature", 0.1)),
        "max_tokens": int(planner.get("max_tokens", 800)),
        "families_enabled": families_enabled,
        "fallback_on_error": bool(planner.get("fallback_on_error", True)),
    }


def required_args_satisfied(capability: str, arguments: Dict[str, Any]) -> bool:
    meta = CAPABILITY_REGISTRY.get(capability, {}) or {}
    required_args = meta.get("required_args", []) or []

    for arg_name in required_args:
        if not safe_text(arguments.get(arg_name)):
            return False

    return True


def build_allowed_capabilities(capability_plan: Dict[str, Any]) -> List[Dict[str, Any]]:
    selected = capability_plan.get("selected_capabilities", []) or []

    allowed: List[Dict[str, Any]] = []
    seen = set()

    for item in selected:
        capability = safe_text(item.get("capability"))
        if not capability or capability in seen:
            continue

        meta = CAPABILITY_REGISTRY.get(capability, {}) or {}
        if not meta:
            continue

        if not bool(meta.get("readonly", True)):
            continue

        arguments = item.get("arguments", {}) or {}
        if not required_args_satisfied(capability, arguments):
            continue

        allowed.append(
            {
                "capability": capability,
                "order": item.get("order", len(allowed) + 1),
                "required_args": meta.get("required_args", []) or [],
                "judge_profile": meta.get("judge_profile", "network_cli_generic"),
                "reason": item.get("reason", "family_default"),
            }
        )
        seen.add(capability)

    return allowed


def build_planner_prompt(
    event: Dict[str, Any],
    family_result: Dict[str, Any],
    capability_plan: Dict[str, Any],
    allowed_capabilities: List[Dict[str, Any]],
) -> str:
    prompt_obj = {
        "role": "network_readonly_capability_planner",
        "task": "Select readonly diagnostic capabilities. Do not generate device commands.",
        "rules": [
            "Only choose capabilities from allowed_capabilities.",
            "Do not invent new capability names.",
            "Do not choose write or config-changing actions.",
            "Prefer the smallest useful set of capabilities.",
            "Return JSON only.",
        ],
        "event": {
            "source": event.get("source", ""),
            "status": event.get("status", ""),
            "severity": event.get("severity", ""),
            "vendor": event.get("vendor", ""),
            "platform": event.get("platform", ""),
            "hostname": event.get("hostname", ""),
            "device_ip": event.get("device_ip", ""),
            "alarm_type": event.get("alarm_type") or event.get("event_type") or "",
            "interface": event.get("interface", ""),
            "peer_ip": event.get("peer_ip", ""),
            "raw_text": event.get("raw_text", ""),
            "if_alias": event.get("if_alias") or event.get("ifAlias") or "",
            "job": event.get("job", ""),
        },
        "family_result": {
            "family": family_result.get("family", ""),
            "target_kind": family_result.get("target_kind", ""),
            "auto_execute_allowed": family_result.get("auto_execute_allowed", False),
            "legacy_playbook_type": family_result.get("legacy_playbook_type", ""),
        },
        "default_capability_order": [
            item.get("capability") for item in (capability_plan.get("selected_capabilities", []) or [])
        ],
        "allowed_capabilities": allowed_capabilities,
        "expected_json_schema": {
            "selected_capabilities": [
                {
                    "capability": "one capability from allowed_capabilities",
                    "reason": "why this capability is needed",
                }
            ],
            "planner_reason": "overall reasoning summary",
            "need_prometheus": True,
            "need_elastic": False,
            "stop_condition": "when enough evidence has been collected",
        },
    }

    return json.dumps(prompt_obj, ensure_ascii=False, indent=2)


def call_openai_compatible_chat(cfg: Dict[str, Any], prompt: str) -> Dict[str, Any]:
    base_url = safe_text(cfg.get("base_url"))
    model = safe_text(cfg.get("model"))
    api_key_env = safe_text(cfg.get("api_key_env"))
    api_key = os.getenv(api_key_env, "")

    if not base_url:
        raise ValueError("capability_planner base_url is empty")
    if not model:
        raise ValueError("capability_planner model is empty")

    url = f"{base_url}/chat/completions"

    payload = {
        "model": model,
        "temperature": float(cfg.get("temperature", 0.1)),
        "max_tokens": int(cfg.get("max_tokens", 800)),
        "messages": [
            {
                "role": "system",
                "content": "You are a network operations readonly diagnostic capability planner. Return JSON only.",
            },
            {
                "role": "user",
                "content": prompt,
            },
        ],
    }

    headers = {
        "Content-Type": "application/json",
    }

    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    req = urllib.request.Request(
        url,
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers=headers,
        method="POST",
    )

    with urllib.request.urlopen(req, timeout=int(cfg.get("timeout", 45))) as resp:
        data = json.loads(resp.read().decode("utf-8", errors="replace"))

    content = ""
    choices = data.get("choices", []) or []
    if choices:
        content = ((choices[0].get("message") or {}).get("content")) or ""

    content = content.strip()
    if content.startswith("```"):
        content = content.strip("`")
        if content.lower().startswith("json"):
            content = content[4:].strip()

    return json.loads(content)


def validate_llm_selection(
    llm_result: Dict[str, Any],
    capability_plan: Dict[str, Any],
) -> Dict[str, Any]:
    original_items = capability_plan.get("selected_capabilities", []) or []
    original_by_name = {}

    for item in original_items:
        capability = safe_text(item.get("capability"))
        if capability:
            original_by_name[capability] = item

    selected_raw = llm_result.get("selected_capabilities", []) or []
    selected_items: List[Dict[str, Any]] = []
    invalid_items: List[Dict[str, Any]] = []
    seen = set()

    order = 1

    for raw in selected_raw:
        if isinstance(raw, str):
            capability = raw
            reason = "llm_selected"
        elif isinstance(raw, dict):
            capability = safe_text(raw.get("capability"))
            reason = safe_text(raw.get("reason")) or "llm_selected"
        else:
            continue

        if not capability:
            continue

        if capability in seen:
            continue

        if capability not in original_by_name:
            invalid_items.append(
                {
                    "capability": capability,
                    "reason": "not_in_allowed_default_plan",
                }
            )
            continue

        item = dict(original_by_name[capability])
        item["order"] = order
        item["reason"] = reason
        item["planner_selected"] = True

        selected_items.append(item)
        seen.add(capability)
        order += 1

    return {
        "selected_items": selected_items,
        "invalid_items": invalid_items,
    }


def attach_planner_metadata(
    capability_plan: Dict[str, Any],
    planner: Dict[str, Any],
) -> Dict[str, Any]:
    out = dict(capability_plan or {})
    out["planner"] = planner
    return out


def fallback_capability_plan(
    capability_plan: Dict[str, Any],
    reason: str,
    error: str = "",
) -> Dict[str, Any]:
    return attach_planner_metadata(
        capability_plan,
        {
            "enabled": False,
            "mode": "default_registry",
            "used_llm": False,
            "fallback": True,
            "reason": reason,
            "error": error,
        },
    )


def refine_capability_plan(
    event: Dict[str, Any],
    family_result: Dict[str, Any],
    capability_plan: Dict[str, Any],
) -> Dict[str, Any]:
    cfg = get_planner_config()
    family = safe_text(family_result.get("family"))

    if not cfg.get("enabled"):
        return fallback_capability_plan(capability_plan, "planner_disabled")

    families_enabled = cfg.get("families_enabled", []) or []
    if families_enabled and family not in families_enabled:
        return fallback_capability_plan(capability_plan, "family_not_enabled")

    allowed_capabilities = build_allowed_capabilities(capability_plan)
    if not allowed_capabilities:
        return fallback_capability_plan(capability_plan, "no_allowed_capabilities")

    prompt = build_planner_prompt(event, family_result, capability_plan, allowed_capabilities)

    try:
        llm_result = call_openai_compatible_chat(cfg, prompt)
        validated = validate_llm_selection(llm_result, capability_plan)

        selected_items = validated.get("selected_items", [])
        invalid_items = validated.get("invalid_items", [])

        if not selected_items:
            return attach_planner_metadata(
                capability_plan,
                {
                    "enabled": True,
                    "mode": "llm_capability_planner",
                    "used_llm": True,
                    "fallback": True,
                    "reason": "llm_selected_no_valid_capabilities",
                    "invalid_items": invalid_items,
                    "raw_result": llm_result,
                },
            )

        out = dict(capability_plan)
        out["selected_capabilities"] = selected_items
        out["readonly_only"] = all(item.get("readonly", True) for item in selected_items)
        out["planner"] = {
            "enabled": True,
            "mode": "llm_capability_planner",
            "used_llm": True,
            "fallback": False,
            "planner_reason": safe_text(llm_result.get("planner_reason")),
            "need_prometheus": bool(llm_result.get("need_prometheus", False)),
            "need_elastic": bool(llm_result.get("need_elastic", False)),
            "stop_condition": safe_text(llm_result.get("stop_condition")),
            "invalid_items": invalid_items,
            "allowed_capabilities": allowed_capabilities,
        }
        return out

    except Exception as e:
        if cfg.get("fallback_on_error", True):
            return fallback_capability_plan(capability_plan, "planner_error_fallback", str(e))
        raise
