from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ===== light alert card template helper begin =====
def _light_alert_card_header_template(title: str = '', detail: str = '') -> str:
    title_text = str(title or '')
    title_lower = title_text.lower()

    # 最高优先级：标题中已经明确恢复/Resolved，则使用浅蓝色。
    if '[恢复]' in title_text or '[resolved]' in title_lower:
        return 'blue'

    # 标题中已经明确告警/Firing，则保持默认色；不要再被描述中的 resolved 字样误导。
    if '[告警]' in title_text or '[firing]' in title_lower or '[alert]' in title_lower:
        return 'default'

    # 标题无法判断时，只解析“告警状态”这一行；不扫描告警描述或 detail 任意位置。
    for raw_line in str(detail or '').splitlines():
        line = raw_line.strip()
        lower_line = line.lower()
        if not line:
            continue

        is_status_line = False
        status_value = ''

        for sep in ('：', ':'):
            if sep in line:
                key, value = line.split(sep, 1)
                key = key.strip().lower()
                if key in {'告警状态', '状态', 'status', 'alert status', 'alert_status'}:
                    is_status_line = True
                    status_value = value.strip().lower()
                break

        if not is_status_line:
            continue

        if status_value.startswith('resolved') or status_value.startswith('restore') or status_value.startswith('恢复'):
            return 'blue'
        if status_value.startswith('firing') or status_value.startswith('alert') or status_value.startswith('告警'):
            return 'default'

    return 'default'
# ===== light alert card template helper end =====



DEFAULT_CONFIG_PATH = "/opt/netaiops-webhook/config/light_alert_dongdong.env"


@dataclass
class DongdongCardConfig:
    card_api_url: str
    service_account: str
    service_token: str
    appid: str
    group_id: str
    card_type: str = "networkAlertCard"
    card_template: str = "default"
    card_need_refresh: bool = False
    card_expire: str = "2099-01-01"
    timeout: int = 10


def safe_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def load_env_file(path: str = DEFAULT_CONFIG_PATH) -> Dict[str, str]:
    env_path = Path(path)
    if not env_path.exists():
        raise FileNotFoundError(f"config file not found: {path}")

    data: Dict[str, str] = {}
    for raw in env_path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        data[key.strip()] = value.strip().strip('"').strip("'")
    return data


def load_card_config(path: str = DEFAULT_CONFIG_PATH) -> DongdongCardConfig:
    env = load_env_file(path)

    required = [
        "DONGDONG_CARD_API_URL",
        "DONGDONG_SERVICE_ACCOUNT",
        "DONGDONG_SERVICE_TOKEN",
        "DONGDONG_APPID",
        "DONGDONG_GROUP_ID",
    ]
    missing = [key for key in required if not env.get(key)]
    if missing:
        raise ValueError(f"missing dongdong card config: {missing}")

    need_refresh_raw = env.get("DONGDONG_CARD_NEED_REFRESH", "false").lower()
    timeout_raw = env.get("DONGDONG_TIMEOUT", "10")
    template = env.get("DONGDONG_CARD_TEMPLATE", "default") or "default"
    allowed_templates = {"default", "white", "blue", "purple", "green", "grey", "red", "orange"}
    if template not in allowed_templates:
        template = "default"

    return DongdongCardConfig(
        card_api_url=env["DONGDONG_CARD_API_URL"],
        service_account=env["DONGDONG_SERVICE_ACCOUNT"],
        service_token=env["DONGDONG_SERVICE_TOKEN"],
        appid=env["DONGDONG_APPID"],
        group_id=env["DONGDONG_GROUP_ID"],
        card_type=env.get("DONGDONG_CARD_TYPE", "networkAlertCard") or "networkAlertCard",
        card_template=template,
        card_need_refresh=need_refresh_raw in {"1", "true", "yes", "y", "on"},
        card_expire=env.get("DONGDONG_CARD_EXPIRE", "2099-01-01") or "2099-01-01",
        timeout=int(timeout_raw),
    )


def redacted_config(config: DongdongCardConfig) -> Dict[str, Any]:
    token = config.service_token or ""
    return {
        "card_api_url": config.card_api_url,
        "service_account": config.service_account,
        "service_token": "***REDACTED***",
        "service_token_length": len(token),
        "service_token_prefix": token[:6] if token else "",
        "service_token_suffix": token[-6:] if token else "",
        "appid": config.appid,
        "group_id": config.group_id,
        "card_type": config.card_type,
        "card_template": config.card_template,
        "card_need_refresh": config.card_need_refresh,
        "card_expire": config.card_expire,
        "timeout": config.timeout,
    }


def normalize_prefix(prefix: str) -> str:
    text = safe_text(prefix)
    if not text:
        return "内容："
    text = text.rstrip(":：").strip()
    return f"{text}："


def split_detail_line(line: str) -> Tuple[str, str]:
    text = safe_text(line)
    if not text:
        return "", ""

    if ":" in text:
        key, value = text.split(":", 1)
        return normalize_prefix(key), safe_text(value)

    if "：" in text:
        key, value = text.split("：", 1)
        return normalize_prefix(key), safe_text(value)

    return "内容：", text


def max_lines_for(prefix: str, content: str) -> int:
    prefix_text = safe_text(prefix)
    content_text = safe_text(content)

    if "告警描述" in prefix_text:
        return 3
    if "错误" in prefix_text or "失败" in prefix_text:
        return 4
    if "接口" in prefix_text:
        return 3
    if "监测对象" in prefix_text or "目标地址" in prefix_text:
        return 2
    if len(content_text) > 80:
        return 3
    if len(content_text) > 40:
        return 2
    return 1


def card_field(prefix: str, content: Any, max_lines: int = 2) -> Dict[str, Any]:
    return {
        "is_short": False,
        "text": {
            "tag": "plain_text",
            "prefix": normalize_prefix(prefix),
            "content": safe_text(content) or "-",
            "type": "detail",
            "max_lines": max_lines,
        },
    }


def card_row(prefix: str, content: Any, max_lines: int = 2) -> Dict[str, Any]:
    return {
        "tag": "div",
        "fields": [
            card_field(prefix, content, max_lines),
        ],
    }


def build_card_detail(title: str, detail: str, config: DongdongCardConfig) -> Dict[str, Any]:
    elements: List[Dict[str, Any]] = []

    for line in (detail or "").splitlines():
        prefix, content = split_detail_line(line)
        if not prefix:
            continue
        elements.append(card_row(prefix, content, max_lines_for(prefix, content)))

    if not elements:
        elements.append(card_row("告警内容：", "-", 1))

    return {
        "config": {
            "appId": config.appid,
            "needRefresh": config.card_need_refresh,
            "expire": config.card_expire,
        },
        "header": {
            "template": _light_alert_card_header_template(title, detail),
            "title": {
                "tag": "plain_text",
                "content": title,
            },
        },
        "elements": elements,
    }


def build_universal_card_payload(title: str, detail: str, config: DongdongCardConfig) -> Dict[str, Any]:
    card_detail = build_card_detail(title=title, detail=detail, config=config)

    return {
        "appId": config.appid,
        "toGroupId": config.group_id,
        "msgType": "universalCard",
        "title": title,
        "testFlag": False,
        "detail": json.dumps(card_detail, ensure_ascii=False, separators=(",", ":")),
        "cardType": config.card_type,
    }


def parse_success(response_text: str, http_code: int) -> Tuple[bool, str, str]:
    business_code = ""
    business_msg = ""

    try:
        data = json.loads(response_text) if response_text else {}
        business_code = safe_text(data.get("code"))
        business_msg = safe_text(data.get("msg", data.get("message", "")))
    except Exception:
        return False, business_code, "non_json_response"

    if not str(http_code).startswith("2"):
        return False, business_code, business_msg
    if business_code in {"0", "200", "000000", "success"}:
        return True, business_code, business_msg
    if business_msg.lower() == "success" or business_msg == "成功":
        return True, business_code, business_msg

    return False, business_code, business_msg


def send_universal_card(
    title: str,
    detail: str,
    config: Optional[DongdongCardConfig] = None,
    config_path: str = DEFAULT_CONFIG_PATH,
) -> Dict[str, Any]:
    config = config or load_card_config(config_path)
    payload = build_universal_card_payload(title=title, detail=detail, config=config)
    card_detail_obj = json.loads(payload["detail"])
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

    req = urllib.request.Request(
        config.card_api_url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json; charset=UTF-8",
            "Authorization": "Basic Og==",
            "account": config.service_account,
            "token": config.service_token,
            "User-Agent": "netaiops-light-alert-dongdong-card/1.0",
        },
    )

    http_code = 0
    response_text = ""
    error = ""

    try:
        with urllib.request.urlopen(req, timeout=config.timeout) as resp:
            http_code = resp.status
            response_text = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        http_code = exc.code
        response_text = exc.read().decode("utf-8", errors="replace")
        error = str(exc)
    except Exception as exc:
        error = repr(exc)

    business_ok, business_code, business_msg = parse_success(response_text, http_code)

    return {
        "ok": business_ok,
        "http_code": http_code,
        "business_code": business_code,
        "business_msg": business_msg,
        "response_text": response_text,
        "error": error,
        "title": title,
        "group_id": config.group_id,
        "payload_preview": {
            "appId": payload.get("appId"),
            "toGroupId": payload.get("toGroupId"),
            "msgType": payload.get("msgType"),
            "title": payload.get("title"),
            "cardType": payload.get("cardType"),
        },
        "card_detail_debug": card_detail_obj,
    }
