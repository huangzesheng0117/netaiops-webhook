import json
from pathlib import Path
from typing import Any, Dict, List, Optional


BASE_DIR = Path("/opt/netaiops-webhook")
DATA_DIR = BASE_DIR / "data"
ANALYSIS_DIR = DATA_DIR / "analysis"
PLAN_DIR = DATA_DIR / "plans"
EXECUTION_DIR = DATA_DIR / "execution"
REVIEW_DIR = DATA_DIR / "reviews"


def read_json_file(path: Path) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def find_optional_file(directory: Path, request_id: str, suffix: str) -> Optional[Path]:
    files = list(directory.glob(f"*_{request_id}.{suffix}"))
    return files[0] if files else None


def safe_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def shorten_text(text: Any, limit: int = 200) -> str:
    value = safe_text(text).replace("\r", " ").replace("\n", " ")
    value = " ".join(value.split())
    if len(value) <= limit:
        return value
    return value[: limit - 3] + "..."


def _family_from_plan(plan_data: Dict[str, Any]) -> str:
    family_result = (plan_data or {}).get("family_result", {}) or {}
    classification = (plan_data or {}).get("classification", {}) or {}

    for value in [
        family_result.get("family"),
        classification.get("family"),
        classification.get("playbook_type"),
        ((plan_data or {}).get("playbook", {}) or {}).get("playbook_id"),
    ]:
        text = safe_text(value)
        if text:
            return text

    return ""


def _capability_preview(plan_data: Dict[str, Any], limit: int = 5) -> List[str]:
    capability_plan = (plan_data or {}).get("capability_plan", {}) or {}
    selected = capability_plan.get("selected_capabilities", []) or []

    preview: List[str] = []
    for item in selected[:limit]:
        capability = safe_text((item or {}).get("capability"))
        if capability:
            preview.append(capability)

    return preview


def _execution_stats(execution_data: Dict[str, Any], review_data: Dict[str, Any]) -> Dict[str, Any]:
    exec_stats = (execution_data or {}).get("stats", {}) or {}
    review_stats = (review_data or {}).get("stats", {}) or {}

    hard_error_count = review_stats.get("hard_error_count")
    if hard_error_count is None:
        hard_error_count = 0

    return {
        "raw": exec_stats,
        "command_total": review_stats.get("command_total"),
        "command_completed": review_stats.get("command_completed"),
        "command_failed": review_stats.get("command_failed"),
        "command_partial": review_stats.get("command_partial"),
        "hard_error_count": hard_error_count,
    }


def _review_preview(review_data: Dict[str, Any], limit: int = 3) -> Dict[str, Any]:
    key_findings = (review_data or {}).get("key_findings", []) or []
    recommendations = (review_data or {}).get("recommendations", []) or []

    return {
        "key_findings_preview": key_findings[:limit],
        "recommendations_preview": recommendations[:limit],
    }


def build_request_summary(request_id: str) -> Dict:
    analysis_file = find_optional_file(ANALYSIS_DIR, request_id, "analysis.json")
    plan_file = find_optional_file(PLAN_DIR, request_id, "plan.json")
    execution_file = find_optional_file(EXECUTION_DIR, request_id, "execution.json")
    review_file = find_optional_file(REVIEW_DIR, request_id, "review.json")

    analysis_data = read_json_file(analysis_file) if analysis_file else None
    plan_data = read_json_file(plan_file) if plan_file else None
    execution_data = read_json_file(execution_file) if execution_file else None
    review_data = read_json_file(review_file) if review_file else None

    family = _family_from_plan(plan_data or {})
    capability_preview = _capability_preview(plan_data or {})
    execution_stats = _execution_stats(execution_data or {}, review_data or {})
    review_preview = _review_preview(review_data or {})

    return {
        "request_id": request_id,
        "analysis": {
            "exists": bool(analysis_file),
            "file": str(analysis_file) if analysis_file else None,
            "status": (analysis_data or {}).get("analysis_status"),
            "summary": ((analysis_data or {}).get("result", {}) or {}).get("summary"),
            "confidence": ((analysis_data or {}).get("result", {}) or {}).get("confidence"),
        },
        "plan": {
            "exists": bool(plan_file),
            "file": str(plan_file) if plan_file else None,
            "status": (plan_data or {}).get("plan_status"),
            "readonly_only": (plan_data or {}).get("readonly_only"),
            "execution_source": (plan_data or {}).get("execution_source"),
            "auto_confirm_recommended": (plan_data or {}).get("auto_confirm_recommended"),
            "playbook": (plan_data or {}).get("playbook"),
            "policy_result": (plan_data or {}).get("policy_result"),
            "family": family,
            "capability_plan_mode": ((plan_data or {}).get("capability_plan", {}) or {}).get("mode"),
            "capability_count": len((((plan_data or {}).get("capability_plan", {}) or {}).get("selected_capabilities", [])) or []),
            "capability_preview": capability_preview,
        },
        "execution": {
            "exists": bool(execution_file),
            "file": str(execution_file) if execution_file else None,
            "status": (execution_data or {}).get("execution_status"),
            "mode": (execution_data or {}).get("execution_mode"),
            "stats": execution_stats,
        },
        "review": {
            "exists": bool(review_file),
            "file": str(review_file) if review_file else None,
            "status": (review_data or {}).get("review_status"),
            "conclusion": (review_data or {}).get("conclusion"),
            "recommendations": (review_data or {}).get("recommendations"),
            "family": (review_data or {}).get("family"),
            "preview": review_preview,
        },
        "quick_view": {
            "family": family or safe_text((review_data or {}).get("family")),
            "execution_source": safe_text((plan_data or {}).get("execution_source")),
            "capability_count": len(capability_preview),
            "hard_error_count": execution_stats.get("hard_error_count", 0),
            "review_status": safe_text((review_data or {}).get("review_status")),
            "review_conclusion_short": shorten_text((review_data or {}).get("conclusion"), 120),
        },
    }


def get_request_summary(request_id: str) -> Dict:
    return build_request_summary(request_id)
