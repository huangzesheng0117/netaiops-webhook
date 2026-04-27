import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from netaiops.evidence_facts import build_interface_evidence_summary


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


def safe_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def shorten_text(text: str, limit: int = 180) -> str:
    text = safe_text(text).replace("\r", " ").replace("\n", " ")
    text = " ".join(text.split())
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def extract_output_text(value: Any) -> str:
    if value is None:
        return ""

    if isinstance(value, dict):
        structured = value.get("structuredContent") or {}
        result = structured.get("result")
        if result:
            return safe_text(result)

        nested_output = value.get("output")
        if nested_output:
            return extract_output_text(nested_output)

        content = value.get("content") or []
        if isinstance(content, list):
            parts: List[str] = []
            for item in content:
                if isinstance(item, dict):
                    txt = safe_text(item.get("text"))
                    if txt:
                        parts.append(txt)
            if parts:
                return "\n".join(parts)

        return safe_text(value)

    if isinstance(value, list):
        parts = [extract_output_text(item) for item in value]
        parts = [x for x in parts if x]
        return "\n".join(parts)

    text = safe_text(value)
    if not text:
        return ""

    try:
        parsed = json.loads(text)
        return extract_output_text(parsed)
    except Exception:
        return text


def get_family(execution_data: Dict[str, Any]) -> str:
    family_result = execution_data.get("family_result", {}) or {}
    classification = execution_data.get("classification", {}) or {}
    playbook = execution_data.get("playbook", {}) or {}

    for value in [
        family_result.get("family"),
        classification.get("family"),
        classification.get("playbook_type"),
        playbook.get("playbook_id"),
    ]:
        text = safe_text(value)
        if text:
            return text

    return "generic_network_readonly"


def collect_command_stats(command_results: List[Dict[str, Any]]) -> Dict[str, int]:
    total = len(command_results)
    completed = 0
    failed = 0
    partial = 0
    hard_error = 0

    for item in command_results:
        status = safe_text(item.get("dispatch_status")).lower()
        judge = item.get("judge", {}) if isinstance(item.get("judge"), dict) else {}
        if status == "completed":
            completed += 1
        elif status == "failed":
            failed += 1
        elif status == "partial":
            partial += 1

        if bool(judge.get("hard_error", False)):
            hard_error += 1

    return {
        "total": total,
        "completed": completed,
        "failed": failed,
        "partial": partial,
        "hard_error": hard_error,
    }


def build_conclusion(execution_data: Dict[str, Any], stats: Dict[str, int], family: str) -> Dict[str, str]:
    execution_status = safe_text(execution_data.get("execution_status")).lower()
    hard_error_count = stats.get("hard_error", 0)
    failed_count = stats.get("failed", 0)
    completed_count = stats.get("completed", 0)
    total = stats.get("total", 0)

    if total == 0:
        return {
            "review_status": "needs_attention",
            "conclusion": "未采集到有效执行结果，当前无法形成可靠结论。",
        }

    if hard_error_count > 0:
        return {
            "review_status": "needs_attention",
            "conclusion": f"本次证据采集中存在 {hard_error_count} 条设备侧硬错误，需优先核对平台命令映射或设备侧可执行性后再判断故障结论。",
        }

    if execution_status == "completed" and completed_count == total:
        if family in ("bgp_neighbor_down", "routing_neighbor_down"):
            conclusion = "关键信息采集完成，可继续围绕邻居状态、路由可达性和链路侧证据判断原因。"
        elif family == "ospf_neighbor_down":
            conclusion = "关键信息采集完成，可继续围绕邻接状态、接口状态和日志时间线判断原因。"
        elif family in ("interface_or_link_traffic_drop", "interface_or_link_utilization_high", "interface_packet_loss_or_discards_high", "interface_status_or_flap"):
            conclusion = "接口侧关键信息采集完成，可继续结合流量、错包、聚合和日志判断链路异常类型。"
        elif family == "f5_pool_member_down":
            conclusion = "F5 侧关键信息采集完成，可继续围绕 pool/member 状态与后端可达性判断原因。"
        else:
            conclusion = "只读证据采集完成，可以继续结合输出内容进行人工复核与结论归纳。"

        return {
            "review_status": "completed",
            "conclusion": conclusion,
        }

    if completed_count > 0 and (failed_count > 0 or execution_status == "partial"):
        return {
            "review_status": "partial",
            "conclusion": "部分关键证据已采集完成，但仍存在失败或未完成项，当前结论需保留不确定性。",
        }

    return {
        "review_status": "needs_attention",
        "conclusion": "本次证据采集失败或有效结果不足，建议先处理执行异常后再继续分析。",
    }


def extract_key_findings(command_results: List[Dict[str, Any]]) -> List[str]:
    findings: List[str] = []

    for item in command_results:
        capability = safe_text(item.get("capability"))
        command = safe_text(item.get("command"))
        status = safe_text(item.get("dispatch_status"))
        judge = item.get("judge", {}) if isinstance(item.get("judge"), dict) else {}
        hard_error = bool(judge.get("hard_error", False))
        matched_rule_id = safe_text(judge.get("matched_rule_id"))
        matched_text = safe_text(judge.get("matched_text"))

        display = capability if capability else command
        if capability and command:
            display = f"{capability} -> {command}"

        if hard_error:
            detail = []
            if matched_rule_id:
                detail.append(f"规则={matched_rule_id}")
            if matched_text:
                detail.append(f"命中={matched_text}")
            detail_text = "；".join(detail) if detail else "设备返回硬错误"
            findings.append(f"{display} 执行失败，设备返回硬错误：{detail_text}")
            continue

        output_text = shorten_text(extract_output_text(item.get("output")), 160)
        error_text = shorten_text(safe_text(item.get("error")), 160)

        if status == "completed":
            if output_text:
                findings.append(f"{display} 执行成功，返回要点：{output_text}")
            else:
                findings.append(f"{display} 执行成功。")
        elif status == "partial":
            if output_text:
                findings.append(f"{display} 部分完成，返回要点：{output_text}")
            else:
                findings.append(f"{display} 部分完成。")
        else:
            if error_text:
                findings.append(f"{display} 执行失败，报错：{error_text}")
            elif output_text:
                findings.append(f"{display} 执行失败，返回要点：{output_text}")
            else:
                findings.append(f"{display} 执行失败。")

    return findings[:10]


def build_recommendations(execution_data: Dict[str, Any], stats: Dict[str, int], family: str) -> List[str]:
    recommendations: List[str] = []

    if stats.get("hard_error", 0) > 0:
        recommendations.append("优先核对 capability 与平台命令映射是否正确，并确认当前设备平台类型识别是否准确。")
        recommendations.append("结合硬错误命中规则，检查是否存在厂商命令差异、对象不存在或权限不足。")

    if family in ("bgp_neighbor_down", "routing_neighbor_down"):
        recommendations.append("继续核查对端邻居状态、路由可达性以及链路两端是否存在同步异常。")
        recommendations.append("对照近期网络变更、BGP/BFD 配置调整和链路事件时间线。")
    elif family == "ospf_neighbor_down":
        recommendations.append("继续核查 OSPF 邻接状态、接口状态与 Hello/Dead 定时相关配置。")
        recommendations.append("对照近期路由策略或接口配置变更，确认是否存在邻接重建失败。")
    elif family in ("interface_or_link_traffic_drop", "interface_or_link_utilization_high", "interface_packet_loss_or_discards_high", "interface_status_or_flap"):
        recommendations.append("继续核查接口错包、物理层状态、聚合成员一致性及对端端口健康情况。")
        recommendations.append("结合日志时间线确认是否存在接口抖动、模块异常或链路切换。")
    elif family == "device_cpu_high":
        recommendations.append("继续核查高 CPU 是否由异常流量、控制面事件或日志抖动引起。")
    elif family == "device_memory_high":
        recommendations.append("继续核查内存占用变化趋势及是否存在异常进程或会话堆积。")
    elif family == "f5_pool_member_down":
        recommendations.append("继续核查 pool member 监控状态、后端服务可达性及应用健康检查结果。")
    else:
        recommendations.append("结合已采集输出继续人工复核，并评估是否需要补充更多诊断命令。")

    if stats.get("failed", 0) > 0 and stats.get("hard_error", 0) == 0:
        recommendations.append("对失败命令逐条复核执行环境、参数对象和设备可达性，再继续形成最终结论。")

    deduped: List[str] = []
    for item in recommendations:
        text = safe_text(item)
        if text and text not in deduped:
            deduped.append(text)

    return deduped[:6]


def build_review_from_execution_data(execution_data: Dict[str, Any]) -> Dict[str, Any]:
    request_id = execution_data.get("request_id", "")
    command_results = execution_data.get("command_results", []) or []
    execution_status = execution_data.get("execution_status", "") or ""
    family = get_family(execution_data)

    stats = execution_data.get("stats", {}) or {}
    derived_stats = collect_command_stats(command_results)
    merged_stats = {
        **stats,
        "command_total": derived_stats.get("total", 0),
        "command_completed": derived_stats.get("completed", 0),
        "command_failed": derived_stats.get("failed", 0),
        "command_partial": derived_stats.get("partial", 0),
        "hard_error_count": derived_stats.get("hard_error", 0),
    }

    conclusion_bundle = build_conclusion(execution_data, derived_stats, family)

    evidence_summary = build_interface_evidence_summary(execution_data)

    review = {
        "request_id": request_id,
        "review_id": f"review_{uuid.uuid4().hex[:12]}",
        "review_status": conclusion_bundle["review_status"],
        "conclusion": evidence_summary.get("conclusion") or conclusion_bundle["conclusion"],
        "execution_status": execution_status,
        "family": family,
        "evidence_summary": evidence_summary,
        "target_scope": execution_data.get("target_scope", {}),
        "classification": execution_data.get("classification", {}),
        "family_result": execution_data.get("family_result", {}),
        "playbook": execution_data.get("playbook", {}),
        "execution_source": execution_data.get("execution_source", ""),
        "capability_plan": execution_data.get("capability_plan", {}),
        "stats": merged_stats,
        "key_findings": (evidence_summary.get("key_findings") or []) + extract_key_findings(command_results),
        "recommendations": (evidence_summary.get("recommendations") or []) + build_recommendations(execution_data, derived_stats, family),
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
