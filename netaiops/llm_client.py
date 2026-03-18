import json
import re

import httpx


def _mock_response(model: str = "mock-model") -> dict:
    return {
        "model": model,
        "analysis": {
            "summary": "mock analysis: 该告警已被接收并完成初步分析",
            "alarm_interpretation": "这是一个模拟分析结果，因为当前未启用真实大模型接口。",
            "possible_causes": [
                "监控对象状态异常",
                "阈值触发",
                "设备、链路或业务对象出现短时波动"
            ],
            "suggested_checks": [
                "确认告警对象的当前运行状态",
                "检查告警发生时间附近是否有变更",
                "核对最近5到15分钟相关监控指标或日志"
            ],
            "suggested_commands": [
                "show interface status",
                "show log",
                "show ip route"
            ],
            "risk_note": "当前为模拟分析结果，仅用于验证处理链路。",
            "confidence": "low"
        }
    }


def _extract_json_text(text: str) -> str:
    if not text:
        raise ValueError("empty model response text")

    text = text.strip()

    fenced = re.search(r"```json\s*(\{.*\})\s*```", text, re.DOTALL | re.IGNORECASE)
    if fenced:
        return fenced.group(1)

    fenced_generic = re.search(r"```\s*(\{.*\})\s*```", text, re.DOTALL)
    if fenced_generic:
        return fenced_generic.group(1)

    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        return text[start:end + 1]

    raise ValueError("no json object found in model response")


def call_llm(prompt: str, config: dict | None = None) -> dict:
    config = config or {}
    llm_cfg = config.get("llm", {}) or {}

    enabled = llm_cfg.get("enabled", False)
    if not enabled:
        return _mock_response()

    provider = llm_cfg.get("provider", "openai_compatible")
    if provider != "openai_compatible":
        raise ValueError(f"unsupported llm provider: {provider}")

    base_url = str(llm_cfg.get("base_url", "")).rstrip("/")
    api_key = str(llm_cfg.get("api_key", ""))
    model = str(llm_cfg.get("model", ""))
    timeout = int(llm_cfg.get("timeout", 60))
    verify_ssl = bool(llm_cfg.get("verify_ssl", True))
    temperature = llm_cfg.get("temperature", 0.2)
    max_tokens = int(llm_cfg.get("max_tokens", 1200))

    if not base_url:
        raise ValueError("llm.base_url is empty")
    if not model:
        raise ValueError("llm.model is empty")

    url = f"{base_url}/chat/completions"

    headers = {
        "Content-Type": "application/json"
    }
    if api_key and api_key != "YOUR_API_KEY":
        headers["Authorization"] = f"Bearer {api_key}"

    payload = {
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": "你是资深网络运维告警分析助手。必须严格按要求输出 JSON。"
            },
            {
                "role": "user",
                "content": prompt
            }
        ],
        "temperature": temperature,
        "max_tokens": max_tokens
    }

    with httpx.Client(timeout=timeout, verify=verify_ssl) as client:
        response = client.post(url, headers=headers, json=payload)
        response.raise_for_status()
        data = response.json()

    try:
        content = data["choices"][0]["message"]["content"]
    except Exception as exc:
        raise ValueError(f"unexpected llm response format: {data}") from exc

    json_text = _extract_json_text(content)

    try:
        analysis = json.loads(json_text)
    except Exception as exc:
        raise ValueError(f"failed to parse model json: {json_text}") from exc

    return {
        "model": data.get("model", model),
        "analysis": analysis
    }
