import json
from pathlib import Path
from typing import Dict


BASE_DIR = Path("/opt/netaiops-webhook")
DATA_DIR = BASE_DIR / "data"
ANALYSIS_DIR = DATA_DIR / "analysis"
PLAN_DIR = DATA_DIR / "plans"
EXECUTION_DIR = DATA_DIR / "execution"
REVIEW_DIR = DATA_DIR / "reviews"


def read_json_file(path: Path) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def find_optional_file(directory: Path, request_id: str, suffix: str):
    files = list(directory.glob(f"*_{request_id}.{suffix}"))
    return files[0] if files else None


def build_request_summary(request_id: str) -> Dict:
    analysis_file = find_optional_file(ANALYSIS_DIR, request_id, "analysis.json")
    plan_file = find_optional_file(PLAN_DIR, request_id, "plan.json")
    execution_file = find_optional_file(EXECUTION_DIR, request_id, "execution.json")
    review_file = find_optional_file(REVIEW_DIR, request_id, "review.json")

    analysis_data = read_json_file(analysis_file) if analysis_file else None
    plan_data = read_json_file(plan_file) if plan_file else None
    execution_data = read_json_file(execution_file) if execution_file else None
    review_data = read_json_file(review_file) if review_file else None

    return {
        "request_id": request_id,
        "analysis": {
            "exists": bool(analysis_file),
            "file": str(analysis_file) if analysis_file else None,
            "status": (analysis_data or {}).get("analysis_status"),
            "summary": ((analysis_data or {}).get("result", {}) or {}).get("summary"),
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
        },
        "execution": {
            "exists": bool(execution_file),
            "file": str(execution_file) if execution_file else None,
            "status": (execution_data or {}).get("execution_status"),
            "mode": (execution_data or {}).get("execution_mode"),
            "stats": (execution_data or {}).get("stats"),
        },
        "review": {
            "exists": bool(review_file),
            "file": str(review_file) if review_file else None,
            "status": (review_data or {}).get("review_status"),
            "conclusion": (review_data or {}).get("conclusion"),
            "recommendations": (review_data or {}).get("recommendations"),
        },
    }


def get_request_summary(request_id: str) -> Dict:
    return build_request_summary(request_id)
