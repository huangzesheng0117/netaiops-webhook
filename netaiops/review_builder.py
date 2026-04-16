import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List


BASE_DIR = Path("/opt/netaiops-webhook")
DATA_DIR = BASE_DIR / "data"
EXECUTION_DIR = DATA_DIR / "execution"
REVIEW_DIR = DATA_DIR / "reviews"


def now_utc_str() -> str:
    return datetime.now(timezone.utc).isoformat()


def read_json_file(path: Path) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def safe_write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def execution_file_by_request_id(request_id: str) -> Path:
    files = list(EXECUTION_DIR.glob(f"*_{request_id}.execution.json"))
    if not files:
        raise FileNotFoundError(f"execution file not found for request_id={request_id}")
    return files[0]


def review_file_by_request_id(request_id: str) -> Path:
    files = list(REVIEW_DIR.glob(f"*_{request_id}.review.json"))
    if files:
        return files[0]

    execution_path = execution_file_by_request_id(request_id)
    source = execution_path.name.split("_", 1)[0]
    return REVIEW_DIR / f"{source}_{request_id}.review.json"


def extract_key_findings(command_results: List[Dict[str, Any]]) -> List[str]:
    findings = []

    for item in command_results:
        cmd = item.get("command", "")
        status = item.get("dispatch_status", "")
        output = item.get("output", "")

        if status == "completed":
            findings.append(f"Command completed successfully: {cmd}")
        else:
            findings.append(f"Command status={status}: {cmd}")

        if output:
            short_output = str(output).strip().replace("\n", " ")
            if len(short_output) > 160:
                short_output = short_output[:160] + "..."
            findings.append(f"Output snippet: {short_output}")

    return findings[:10]


def build_recommendations(execution_data: Dict[str, Any]) -> List[str]:
    classification = execution_data.get("classification", {}) or {}
    playbook = execution_data.get("playbook", {}) or {}
    execution_status = execution_data.get("execution_status", "")

    playbook_id = playbook.get("playbook_id", "")
    playbook_type = classification.get("playbook_type", "")

    recommendations = []

    if execution_status == "completed":
        recommendations.append("Review collected evidence and correlate with alarm timeline.")
    else:
        recommendations.append("Investigate failed or partial commands before drawing conclusions.")

    if playbook_id == "huawei_bgp_neighbor_down" or playbook_type == "bgp_neighbor_down":
        recommendations.append("Check BGP peer reachability and peer state transition history.")
        recommendations.append("Compare routing state and interface health on both ends.")

    elif playbook_id == "huawei_ospf_neighbor_down" or playbook_type == "ospf_neighbor_down":
        recommendations.append("Check OSPF adjacency state, interface status, and log timeline.")
        recommendations.append("Verify whether routing changes align with adjacency loss.")

    elif playbook_id == "huawei_interface_flap" or playbook_type == "interface_flap":
        recommendations.append("Check interface error counters, optics, and recent flap logs.")
        recommendations.append("Verify peer side stability and physical link quality.")

    elif playbook_id == "f5_pool_member_down" or playbook_type == "f5_pool_member_down":
        recommendations.append("Check pool member monitor state and backend reachability.")
        recommendations.append("Verify application-side health and recent connection behavior.")

    else:
        recommendations.append("Review command outputs and refine the playbook if needed.")

    return recommendations[:6]


def build_review_from_execution_data(execution_data: Dict[str, Any]) -> Dict[str, Any]:
    request_id = execution_data.get("request_id", "")
    command_results = execution_data.get("command_results", []) or []
    stats = execution_data.get("stats", {}) or {}

    execution_status = execution_data.get("execution_status", "")
    if execution_status == "completed":
        review_status = "completed"
        conclusion = "Readonly evidence collection completed successfully."
    elif execution_status == "partial":
        review_status = "partial"
        conclusion = "Readonly evidence collection partially completed."
    else:
        review_status = "needs_attention"
        conclusion = "Evidence collection failed or requires manual attention."

    review = {
        "request_id": request_id,
        "review_id": f"review_{uuid.uuid4().hex[:12]}",
        "review_status": review_status,
        "conclusion": conclusion,
        "execution_status": execution_status,
        "target_scope": execution_data.get("target_scope", {}),
        "classification": execution_data.get("classification", {}),
        "playbook": execution_data.get("playbook", {}),
        "stats": stats,
        "key_findings": extract_key_findings(command_results),
        "recommendations": build_recommendations(execution_data),
        "generated_at": now_utc_str(),
        "source_execution_file": "",
    }
    return review


def generate_review_for_request_id(request_id: str) -> Dict[str, Any]:
    execution_path = execution_file_by_request_id(request_id)
    execution_data = read_json_file(execution_path)

    review = build_review_from_execution_data(execution_data)
    review["source_execution_file"] = str(execution_path)

    review_path = review_file_by_request_id(request_id)
    safe_write_json(review_path, review)

    return {
        "review_file": str(review_path),
        "review_data": review,
    }


def get_review_by_request_id(request_id: str) -> Dict[str, Any]:
    review_path = review_file_by_request_id(request_id)
    if not review_path.exists():
        raise FileNotFoundError(f"review file not found for request_id={request_id}")

    return {
        "review_file": str(review_path),
        "review_data": read_json_file(review_path),
    }


def get_latest_review() -> Dict[str, Any]:
    files = sorted(REVIEW_DIR.glob("*.review.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not files:
        raise FileNotFoundError("no review files found")

    path = files[0]
    return {
        "review_file": str(path),
        "review_data": read_json_file(path),
    }
