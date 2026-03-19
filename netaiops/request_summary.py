import json
from pathlib import Path


BASE_DIR = Path("/opt/netaiops-webhook")
DATA_DIR = BASE_DIR / "data"
ANALYSIS_DIR = DATA_DIR / "analysis"
PLAN_DIR = DATA_DIR / "plans"
EXECUTION_DIR = DATA_DIR / "execution"
REVIEW_DIR = DATA_DIR / "reviews"


def read_json_file(path: Path) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def find_single_file(directory: Path, pattern: str) -> Path | None:
    files = list(directory.glob(pattern))
    if not files:
        return None
    return files[0]


def get_request_summary(request_id: str) -> dict:
    analysis_path = find_single_file(ANALYSIS_DIR, f"*_{request_id}.analysis.json")
    plan_path = find_single_file(PLAN_DIR, f"*_{request_id}.plan.json")
    execution_path = find_single_file(EXECUTION_DIR, f"*_{request_id}.execution.json")
    review_path = find_single_file(REVIEW_DIR, f"*_{request_id}.review.json")

    if not any([analysis_path, plan_path, execution_path, review_path]):
        raise FileNotFoundError(f"no records found for request_id={request_id}")

    analysis_data = read_json_file(analysis_path) if analysis_path else None
    plan_data = read_json_file(plan_path) if plan_path else None
    execution_data = read_json_file(execution_path) if execution_path else None
    review_data = read_json_file(review_path) if review_path else None

    return {
        "request_id": request_id,
        "analysis": {
            "exists": analysis_data is not None,
            "file": str(analysis_path) if analysis_path else None,
            "status": analysis_data.get("analysis_status") if analysis_data else None,
            "summary": ((analysis_data or {}).get("result") or {}).get("summary") if analysis_data else None,
            "recommended_next_step": ((analysis_data or {}).get("result") or {}).get("recommended_next_step") if analysis_data else None,
        },
        "plan": {
            "exists": plan_data is not None,
            "file": str(plan_path) if plan_path else None,
            "status": plan_data.get("plan_status") if plan_data else None,
            "readonly_only": plan_data.get("readonly_only") if plan_data else None,
            "requires_confirmation": plan_data.get("requires_confirmation") if plan_data else None,
            "command_count": len((plan_data or {}).get("execution_candidates", []) or []) if plan_data else 0,
        },
        "execution": {
            "exists": execution_data is not None,
            "file": str(execution_path) if execution_path else None,
            "status": execution_data.get("execution_status") if execution_data else None,
            "command_count": len((execution_data or {}).get("commands", []) or []) if execution_data else 0,
            "dispatched_at": execution_data.get("dispatched_at") if execution_data else None,
            "completed_at": execution_data.get("completed_at") if execution_data else None,
        },
        "review": {
            "exists": review_data is not None,
            "file": str(review_path) if review_path else None,
            "status": review_data.get("review_status") if review_data else None,
            "summary": review_data.get("summary") if review_data else None,
            "next_steps": review_data.get("next_steps") if review_data else None,
        },
    }
