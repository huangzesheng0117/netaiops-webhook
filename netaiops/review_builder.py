import json
from datetime import datetime, timezone
from pathlib import Path


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
    if not files:
        raise FileNotFoundError(f"review file not found for request_id={request_id}")
    return files[0]


def latest_review_file() -> Path:
    files = sorted(REVIEW_DIR.glob("*.review.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not files:
        raise FileNotFoundError("no review files found")
    return files[0]


def build_review_from_execution(execution: dict) -> dict:
    commands = execution.get("commands", []) or []
    target_scope = execution.get("target_scope", {}) or {}

    completed = []
    failed = []
    pending = []

    evidence = []

    for item in commands:
        entry = {
            "order": item.get("order"),
            "command": item.get("command"),
            "dispatch_status": item.get("dispatch_status"),
            "output": item.get("output"),
            "error": item.get("error"),
        }

        status = item.get("dispatch_status")
        if status == "completed":
            completed.append(entry)
            if item.get("output"):
                evidence.append(
                    {
                        "order": item.get("order"),
                        "command": item.get("command"),
                        "finding": item.get("output"),
                    }
                )
        elif status == "failed":
            failed.append(entry)
        else:
            pending.append(entry)

    if failed:
        review_status = "needs_attention"
    elif pending:
        review_status = "partial"
    else:
        review_status = "completed"

    conclusion_parts = []

    if completed:
        conclusion_parts.append(f"已完成 {len(completed)} 条取证命令。")
    if failed:
        conclusion_parts.append(f"有 {len(failed)} 条命令执行失败。")
    if pending:
        conclusion_parts.append(f"仍有 {len(pending)} 条命令未完成。")

    if evidence:
        first_finding = evidence[0].get("finding", "")
        if first_finding:
            conclusion_parts.append(f"关键发现：{first_finding}")

    conclusion = " ".join(conclusion_parts).strip()
    if not conclusion:
        conclusion = "暂无明确执行结论。"

    next_steps = []

    for item in failed:
        cmd = item.get("command", "")
        err = item.get("error", "")
        next_steps.append(f"重新检查命令执行失败原因：{cmd}；错误：{err}")

    if not next_steps and evidence:
        next_steps.append("根据已回传证据，建议进入二次根因分析。")

    if not next_steps:
        next_steps.append("补充执行结果后再生成 review。")

    review = {
        "request_id": execution.get("request_id"),
        "execution_id": execution.get("execution_id"),
        "source": execution.get("source"),
        "review_status": review_status,
        "target_scope": target_scope,
        "execution_status": execution.get("execution_status"),
        "summary": conclusion,
        "evidence": evidence,
        "completed_commands": completed,
        "failed_commands": failed,
        "pending_commands": pending,
        "next_steps": next_steps,
        "execution_file": "",
        "generated_at": now_utc_str(),
    }
    return review


def generate_review_for_request_id(request_id: str) -> dict:
    execution_path = execution_file_by_request_id(request_id)
    execution = read_json_file(execution_path)

    review = build_review_from_execution(execution)
    review["execution_file"] = str(execution_path)

    source = execution.get("source", "unknown")
    review_path = REVIEW_DIR / f"{source}_{request_id}.review.json"
    safe_write_json(review_path, review)

    return {
        "review_file": str(review_path),
        "review_data": review,
    }


def get_review_by_request_id(request_id: str) -> dict:
    path = review_file_by_request_id(request_id)
    return {
        "review_file": str(path),
        "review_data": read_json_file(path),
    }


def get_latest_review() -> dict:
    path = latest_review_file()
    return {
        "review_file": str(path),
        "review_data": read_json_file(path),
    }
