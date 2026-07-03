from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple


DEFAULT_CONFIG_PATH = "/opt/netaiops-webhook/config/ai_analysis_dongdong.env"
ALLOWED_TEMPLATES = {"default", "white", "blue", "purple", "green", "grey", "red", "orange"}


@dataclass(frozen=True)
class AiAnalysisCardConfig:
    card_api_url: str
    service_account: str
    service_token: str
    appid: str
    group_id: str
    card_type: str = "networkAiAnalysisCard"
    card_template: str = "default"
    card_need_refresh: bool = False
    card_expire: str = "2099-01-01"
    timeout: int = 10


def _text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _bool(value: Any, default: bool = False) -> bool:
    text = _text(value).lower()
    if not text:
        return default
    if text in {"1", "true", "yes", "y", "on"}:
        return True
    if text in {"0", "false", "no", "n", "off"}:
        return False
    return default


def _int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _truncate(value: Any, limit: int) -> str:
    text = _text(value)
    if len(text) <= limit:
        return text
    return text[: max(1, limit - 1)].rstrip() + "…"


def load_env_file(path: str = DEFAULT_CONFIG_PATH) -> Dict[str, str]:
    target = Path(path)
    if not target.is_file():
        raise FileNotFoundError(f"AI card config file not found: {target}")

    result: Dict[str, str] = {}
    for raw in target.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        result[key.strip()] = value.strip().strip('"').strip("'")
    return result


def load_ai_card_config(path: str = DEFAULT_CONFIG_PATH) -> AiAnalysisCardConfig:
    env = load_env_file(path)
    required = (
        "AI_DONGDONG_CARD_API_URL",
        "AI_DONGDONG_SERVICE_ACCOUNT",
        "AI_DONGDONG_SERVICE_TOKEN",
        "AI_DONGDONG_APPID",
        "AI_DONGDONG_GROUP_ID",
    )
    missing = [key for key in required if not _text(env.get(key))]
    if missing:
        raise ValueError(f"missing AI card config: {missing}")

    token = _text(env["AI_DONGDONG_SERVICE_TOKEN"])
    if token.upper() in {"REPLACE_ME", "CHANGE_ME", "TODO"}:
        raise ValueError("AI_DONGDONG_SERVICE_TOKEN is still a placeholder")

    template = _text(env.get("AI_DONGDONG_CARD_TEMPLATE")) or "default"
    if template not in ALLOWED_TEMPLATES:
        template = "default"

    return AiAnalysisCardConfig(
        card_api_url=_text(env["AI_DONGDONG_CARD_API_URL"]),
        service_account=_text(env["AI_DONGDONG_SERVICE_ACCOUNT"]),
        service_token=token,
        appid=_text(env["AI_DONGDONG_APPID"]),
        group_id=_text(env["AI_DONGDONG_GROUP_ID"]),
        card_type=_text(env.get("AI_DONGDONG_CARD_TYPE")) or "networkAiAnalysisCard",
        card_template=template,
        card_need_refresh=_bool(env.get("AI_DONGDONG_CARD_NEED_REFRESH"), False),
        card_expire=_text(env.get("AI_DONGDONG_CARD_EXPIRE")) or "2099-01-01",
        timeout=max(1, _int(env.get("AI_DONGDONG_TIMEOUT"), 10)),
    )


def redacted_config(config: AiAnalysisCardConfig) -> Dict[str, Any]:
    token = config.service_token or ""
    return {
        "card_api_url": config.card_api_url,
        "service_account": config.service_account,
        "service_token": "***REDACTED***",
        "service_token_length": len(token),
        "appid": config.appid,
        "group_id": config.group_id,
        "card_type": config.card_type,
        "card_template": config.card_template,
        "card_need_refresh": config.card_need_refresh,
        "card_expire": config.card_expire,
        "timeout": config.timeout,
    }


def _prefix(label: Any) -> str:
    text = _text(label).rstrip(":：").strip() or "内容"
    return f"{text}："


def _max_lines(label: str, value: str) -> int:
    if label in {"当前判断", "告警内容"}:
        return 5
    if label in {"处理建议", "证据摘要"}:
        return 4
    if len(value) > 100:
        return 4
    if len(value) > 60:
        return 3
    if len(value) > 30:
        return 2
    return 1


def _row(label: str, value: str) -> Dict[str, Any]:
    return {
        "tag": "div",
        "fields": [
            {
                "is_short": False,
                "text": {
                    "tag": "plain_text",
                    "prefix": _prefix(label),
                    "content": _text(value) or "-",
                    "type": "detail",
                    "max_lines": _max_lines(label, value),
                },
            }
        ],
    }


def _iter_rows(fields: Iterable[Mapping[str, Any]]) -> Iterable[Dict[str, Any]]:
    for item in fields:
        label = _text(item.get("label"))
        value = _text(item.get("value"))
        if not label or not value or label == "详情链接":
            continue

        lines = [
            line.strip()
            for line in value.replace("\r\n", "\n").replace("\r", "\n").split("\n")
            if line.strip()
        ]
        if not lines:
            continue

        if label == "处理建议":
            # Keep all recommendations in one card field so the label is rendered once.
            yield _row("处理建议", "\n".join(lines))
        else:
            yield _row(label, "；".join(lines))

def _detail_url(card: Mapping[str, Any]) -> str:
    for item in card.get("fields") or []:
        if not isinstance(item, Mapping):
            continue
        if _text(item.get("label")) == "详情链接":
            value = _text(item.get("value"))
            if value.startswith("http://") or value.startswith("https://"):
                return value
    return ""


def _action(detail_url: str) -> Optional[Dict[str, Any]]:
    if not detail_url:
        return None
    return {
        "tag": "action",
        "actions": [
            {
                "is_short": False,
                "text": {"tag": "plain_text", "content": "查看完整证据"},
                "type": "default",
                "handle": {
                    "url": {
                        "url_key": "",
                        "common_url": detail_url,
                        "android_url": {"type": "sysH5", "link": detail_url},
                        "ios_url": {"type": "sysH5", "link": detail_url},
                        "pc_url": {"type": "default", "link": detail_url},
                    }
                },
            }
        ],
    }


def build_api_card_detail(card: Mapping[str, Any], config: AiAnalysisCardConfig) -> Dict[str, Any]:
    if not isinstance(card, Mapping):
        raise ValueError("card must be a mapping")
    fields = card.get("fields") or []
    if not isinstance(fields, list):
        raise ValueError("card.fields must be a list")

    elements: List[Dict[str, Any]] = list(_iter_rows(fields))
    detail_url = _detail_url(card)
    action = _action(detail_url)
    if action:
        elements.append({"tag": "hr"})
        elements.append(action)
    if not elements:
        elements.append(_row("告警内容", "未生成卡片字段"))

    title = _truncate(card.get("title") or "NetAIOps 告警分析", 45)
    header_template = _text((card.get("header") or {}).get("template")) or config.card_template
    if header_template not in ALLOWED_TEMPLATES:
        header_template = config.card_template

    return {
        "config": {
            "expire": config.card_expire,
            "appId": config.appid,
            "needRefresh": config.card_need_refresh,
        },
        "header": {
            "title": {"tag": "plain_text", "content": title},
            "template": header_template,
        },
        "elements": elements,
    }


def build_ai_card_request_payload(card: Mapping[str, Any], config: AiAnalysisCardConfig) -> Dict[str, Any]:
    title = _truncate(card.get("title") or "NetAIOps 告警分析", 45)
    detail = build_api_card_detail(card, config)
    return {
        "appId": config.appid,
        "toGroupId": config.group_id,
        "msgType": "universalCard",
        "title": title,
        "testFlag": False,
        "detail": json.dumps(detail, ensure_ascii=False, separators=(",", ":")),
        "cardType": config.card_type,
    }


def parse_success(response_text: str, http_code: int) -> Tuple[bool, str, str]:
    try:
        payload = json.loads(response_text) if response_text else {}
    except json.JSONDecodeError:
        return False, "", "non_json_response"

    business_code = _text(payload.get("code"))
    business_msg = _text(payload.get("msg", payload.get("message", "")))
    if not str(http_code).startswith("2"):
        return False, business_code, business_msg
    if business_code in {"0", "200", "000000", "success"}:
        return True, business_code, business_msg
    if business_msg.lower() == "success" or business_msg == "成功":
        return True, business_code, business_msg
    return False, business_code, business_msg


def send_ai_analysis_card(
    card: Mapping[str, Any],
    *,
    config: Optional[AiAnalysisCardConfig] = None,
    config_path: str = DEFAULT_CONFIG_PATH,
) -> Dict[str, Any]:
    resolved_config = config or load_ai_card_config(config_path)
    payload = build_ai_card_request_payload(card, resolved_config)
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

    request = urllib.request.Request(
        resolved_config.card_api_url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json; charset=UTF-8",
            "Authorization": "Basic Og==",
            "account": resolved_config.service_account,
            "token": resolved_config.service_token,
            "User-Agent": "netaiops-ai-analysis-card/1.0",
        },
    )

    http_code = 0
    response_text = ""
    error = ""
    try:
        with urllib.request.urlopen(request, timeout=resolved_config.timeout) as response:
            http_code = int(response.status)
            response_text = response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        http_code = int(exc.code)
        response_text = exc.read().decode("utf-8", errors="replace")
        error = str(exc)
    except Exception as exc:
        error = repr(exc)

    ok, business_code, business_msg = parse_success(response_text, http_code)
    return {
        "ok": ok,
        "sent": ok,
        "transport": "universal_card",
        "http_code": http_code,
        "business_code": business_code,
        "business_msg": business_msg,
        "response_text": response_text,
        "error": error,
        "group_id": resolved_config.group_id,
        "appid": resolved_config.appid,
        "card_type": resolved_config.card_type,
        "payload_preview": {
            "appId": payload.get("appId"),
            "toGroupId": payload.get("toGroupId"),
            "msgType": payload.get("msgType"),
            "title": payload.get("title"),
            "cardType": payload.get("cardType"),
        },
    }
