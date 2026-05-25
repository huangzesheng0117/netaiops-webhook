import json
import os
import re
import time
from typing import Any

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
                "设备、链路或业务对象出现短时波动",
            ],
            "suggested_checks": [
                "确认告警对象的当前运行状态",
                "检查告警发生时间附近是否有变更",
                "核对最近5到15分钟相关监控指标或日志",
            ],
            "suggested_commands": [
                "show interface status",
                "show log",
                "show ip route",
            ],
            "risk_note": "当前为模拟分析结果，仅用于验证处理链路。",
            "confidence": "low",
        },
        "llm_metadata": {
            "enabled": False,
            "provider": "mock",
            "call_status": "mock",
            "parse_status": "mock",
        },
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


def _as_bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "on"}
    return bool(value)


def _as_int(value: Any, default: int) -> int:
    try:
        if value is None or value == "":
            return default
        return int(value)
    except Exception:
        return default


def _as_float(value: Any, default: float) -> float:
    try:
        if value is None or value == "":
            return default
        return float(value)
    except Exception:
        return default


def _short_error(exc: Exception, limit: int = 240) -> str:
    text = str(exc).replace("\n", " ").strip()
    if len(text) > limit:
        return text[:limit] + "..."
    return text


def _preview(text: str, limit: int = 500) -> str:
    text = (text or "").replace("\r", " ").strip()
    if len(text) > limit:
        return text[:limit] + "..."
    return text


def _resolve_api_key(llm_cfg: dict) -> str:
    direct = str(llm_cfg.get("api_key", "") or "")
    if direct and direct != "YOUR_API_KEY":
        return direct

    env_name = str(llm_cfg.get("api_key_env", "") or "").strip()
    if env_name:
        return os.environ.get(env_name, "")

    return ""


def _normalize_base_url(base_url: str) -> str:
    base = str(base_url or "").strip().rstrip("/")
    if base.endswith("/chat/completions"):
        base = base[: -len("/chat/completions")]
    if base.endswith("/models"):
        base = base[: -len("/models")]
    return base.rstrip("/")


def _chat_url(base_url: str) -> str:
    base = _normalize_base_url(base_url)
    return f"{base}/chat/completions"


def _models_url(base_url: str) -> str:
    base = _normalize_base_url(base_url)
    return f"{base}/models"


def _build_endpoint_configs(llm_cfg: dict) -> list[dict]:
    endpoints: list[dict] = []

    raw_endpoints = llm_cfg.get("endpoints") or llm_cfg.get("base_urls") or []
    if isinstance(raw_endpoints, (str, dict)):
        raw_endpoints = [raw_endpoints]

    for idx, item in enumerate(raw_endpoints):
        if isinstance(item, str):
            base_url = item
            name = f"endpoint_{idx + 1}"
            timeout = llm_cfg.get("timeout", 60)
            verify_ssl = llm_cfg.get("verify_ssl", True)
        elif isinstance(item, dict):
            base_url = item.get("base_url") or item.get("url") or ""
            name = item.get("name") or item.get("type") or f"endpoint_{idx + 1}"
            timeout = item.get("timeout", llm_cfg.get("timeout", 60))
            verify_ssl = item.get("verify_ssl", llm_cfg.get("verify_ssl", True))
        else:
            continue

        base_url = _normalize_base_url(str(base_url))
        if base_url:
            endpoints.append(
                {
                    "name": str(name),
                    "base_url": base_url,
                    "timeout": _as_int(timeout, _as_int(llm_cfg.get("timeout"), 60)),
                    "verify_ssl": _as_bool(verify_ssl, True),
                }
            )

    base_url = _normalize_base_url(str(llm_cfg.get("base_url", "") or ""))
    if base_url and not any(x.get("base_url") == base_url for x in endpoints):
        endpoints.insert(
            0,
            {
                "name": "primary",
                "base_url": base_url,
                "timeout": _as_int(llm_cfg.get("timeout"), 60),
                "verify_ssl": _as_bool(llm_cfg.get("verify_ssl"), True),
            },
        )

    return endpoints


def _build_timeout(timeout_seconds: int, llm_cfg: dict) -> httpx.Timeout:
    connect_timeout = _as_float(llm_cfg.get("connect_timeout"), min(10.0, float(timeout_seconds)))
    read_timeout = _as_float(llm_cfg.get("read_timeout"), float(timeout_seconds))
    write_timeout = _as_float(llm_cfg.get("write_timeout"), float(timeout_seconds))
    pool_timeout = _as_float(llm_cfg.get("pool_timeout"), min(10.0, float(timeout_seconds)))
    return httpx.Timeout(
        timeout=float(timeout_seconds),
        connect=connect_timeout,
        read=read_timeout,
        write=write_timeout,
        pool=pool_timeout,
    )


def _build_headers(api_key: str, llm_cfg: dict) -> dict:
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    extra_headers = llm_cfg.get("headers") or {}
    if isinstance(extra_headers, dict):
        for key, value in extra_headers.items():
            if key and value is not None and str(key).lower() != "authorization":
                headers[str(key)] = str(value)

    return headers


def _build_payload(prompt: str, model: str, llm_cfg: dict) -> dict:
    payload = {
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": "你是资深网络运维告警分析助手。必须严格按要求输出 JSON。",
            },
            {
                "role": "user",
                "content": prompt,
            },
        ],
        "temperature": llm_cfg.get("temperature", 0.2),
        "max_tokens": _as_int(llm_cfg.get("max_tokens"), 1200),
        "stream": False,
    }

    channel_names = llm_cfg.get("channel_names")
    if channel_names:
        if isinstance(channel_names, str):
            payload["channel_names"] = [channel_names]
        elif isinstance(channel_names, list):
            payload["channel_names"] = [str(x) for x in channel_names if str(x).strip()]

    extra_body = llm_cfg.get("extra_body") or {}
    if isinstance(extra_body, dict):
        blocked = {"model", "messages", "stream"}
        for key, value in extra_body.items():
            if key not in blocked:
                payload[key] = value

    return payload


def _fallback_analysis(reason: str, model: str, metadata: dict) -> dict:
    return {
        "model": model or metadata.get("configured_model", ""),
        "analysis": {
            "summary": f"LLM 分析未能生成标准结构化结果：{reason}",
            "alarm_interpretation": "本次告警的 LLM 调用或 JSON 解析未完全成功。系统已保留结构化降级结果，后续 family/capability/MCP 取证链路仍可继续工作。",
            "possible_causes": [
                "LLM 网关请求失败、超时或返回异常",
                "模型返回内容不是合法 JSON",
                "模型输出被截断或包含额外说明文本",
            ],
            "suggested_checks": [
                "检查 LLM 网关连通性和模型可用性",
                "检查本次 analysis 文件中的 llm_metadata",
                "必要时通过 tools/check_llm_connection.py 做模型连通性预检",
            ],
            "suggested_commands": [],
            "risk_note": "这是 LLM 降级结果，不代表网络故障已经完成根因判断。",
            "confidence": "low",
        },
        "llm_metadata": metadata,
    }


def call_llm(prompt: str, config: dict | None = None) -> dict:
    config = config or {}
    llm_cfg = config.get("llm", {}) or {}

    enabled = _as_bool(llm_cfg.get("enabled"), False)
    if not enabled:
        return _mock_response()

    provider = llm_cfg.get("provider", "openai_compatible")
    if provider != "openai_compatible":
        raise ValueError(f"unsupported llm provider: {provider}")

    model = str(llm_cfg.get("model", "") or "").strip()
    if not model:
        raise ValueError("llm.model is empty")

    endpoints = _build_endpoint_configs(llm_cfg)
    if not endpoints:
        raise ValueError("llm.base_url or llm.endpoints is empty")

    api_key = _resolve_api_key(llm_cfg)
    headers = _build_headers(api_key, llm_cfg)
    payload = _build_payload(prompt, model, llm_cfg)

    retry = max(0, _as_int(llm_cfg.get("retry", llm_cfg.get("retries", 1)), 1))
    metadata_base = {
        "enabled": True,
        "provider": provider,
        "configured_model": model,
        "endpoint_count": len(endpoints),
        "max_attempts_per_endpoint": retry + 1,
        "call_status": "unknown",
        "parse_status": "not_started",
        "errors": [],
    }

    total_attempts = 0
    last_metadata = dict(metadata_base)

    for endpoint_index, endpoint in enumerate(endpoints):
        timeout_seconds = _as_int(endpoint.get("timeout"), _as_int(llm_cfg.get("timeout"), 60))
        verify_ssl = _as_bool(endpoint.get("verify_ssl"), _as_bool(llm_cfg.get("verify_ssl"), True))

        for attempt in range(retry + 1):
            total_attempts += 1
            started = time.monotonic()
            metadata = dict(metadata_base)
            metadata.update(
                {
                    "endpoint_index": endpoint_index,
                    "endpoint_name": endpoint.get("name", f"endpoint_{endpoint_index + 1}"),
                    "attempt_index": attempt,
                    "total_attempts": total_attempts,
                    "timeout": timeout_seconds,
                    "verify_ssl": verify_ssl,
                }
            )

            try:
                with httpx.Client(timeout=_build_timeout(timeout_seconds, llm_cfg), verify=verify_ssl) as client:
                    response = client.post(_chat_url(endpoint["base_url"]), headers=headers, json=payload)

                latency_ms = int((time.monotonic() - started) * 1000)
                metadata["latency_ms"] = latency_ms
                metadata["status_code"] = response.status_code
                metadata["channel_name"] = response.headers.get("X-Channel-Name", "")
                response.raise_for_status()
                data = response.json()

                usage = data.get("usage")
                if isinstance(usage, dict):
                    metadata["usage"] = usage

                choice = (data.get("choices") or [{}])[0]
                metadata["finish_reason"] = choice.get("finish_reason", "")

                try:
                    content = choice["message"]["content"]
                except Exception as exc:
                    metadata["call_status"] = "success"
                    metadata["parse_status"] = "unexpected_response_format"
                    metadata["errors"] = [f"unexpected llm response format: {_short_error(exc)}"]
                    metadata["raw_response_preview"] = _preview(json.dumps(data, ensure_ascii=False))
                    return _fallback_analysis("unexpected_response_format", data.get("model", model), metadata)

                try:
                    json_text = _extract_json_text(content)
                    analysis = json.loads(json_text)
                    if not isinstance(analysis, dict):
                        analysis = {
                            "summary": "LLM 返回了合法 JSON，但顶层不是对象。",
                            "raw_analysis": analysis,
                            "confidence": "low",
                        }

                    metadata["call_status"] = "success"
                    metadata["parse_status"] = "ok"
                    return {
                        "model": data.get("model", model),
                        "analysis": analysis,
                        "llm_metadata": metadata,
                    }
                except Exception as exc:
                    metadata["call_status"] = "success"
                    metadata["parse_status"] = "json_parse_failed"
                    metadata["errors"] = [f"failed to parse model json: {_short_error(exc)}"]
                    metadata["raw_content_preview"] = _preview(content)
                    return _fallback_analysis("json_parse_failed", data.get("model", model), metadata)

            except Exception as exc:
                latency_ms = int((time.monotonic() - started) * 1000)
                error_text = _short_error(exc)
                metadata["latency_ms"] = latency_ms
                metadata["call_status"] = "failed"
                metadata["parse_status"] = "not_started"
                metadata["errors"] = [error_text]
                last_metadata = metadata

    final_metadata = dict(last_metadata)
    final_metadata["call_status"] = "failed"
    final_metadata["parse_status"] = "not_started"
    final_metadata["total_attempts"] = total_attempts
    return _fallback_analysis("llm_call_failed", model, final_metadata)


def check_llm_health(
    config: dict | None = None,
    include_models: bool = False,
    chat_smoke: bool = False,
) -> dict:
    config = config or {}
    llm_cfg = config.get("llm", {}) or {}

    enabled = _as_bool(llm_cfg.get("enabled"), False)
    provider = llm_cfg.get("provider", "openai_compatible")
    model = str(llm_cfg.get("model", "") or "").strip()
    endpoints = _build_endpoint_configs(llm_cfg)
    api_key = _resolve_api_key(llm_cfg)
    headers = _build_headers(api_key, llm_cfg)

    result = {
        "enabled": enabled,
        "provider": provider,
        "configured_model": model,
        "endpoint_count": len(endpoints),
        "include_models": include_models,
        "chat_smoke": chat_smoke,
        "endpoints": [],
    }

    if not enabled:
        result["overall_status"] = "disabled"
        return result

    if provider != "openai_compatible":
        result["overall_status"] = "unsupported_provider"
        result["error"] = f"unsupported llm provider: {provider}"
        return result

    if not model:
        result["overall_status"] = "missing_model"
        return result

    if not endpoints:
        result["overall_status"] = "missing_endpoint"
        return result

    ok_any = False

    for endpoint_index, endpoint in enumerate(endpoints):
        timeout_seconds = _as_int(endpoint.get("timeout"), _as_int(llm_cfg.get("timeout"), 60))
        verify_ssl = _as_bool(endpoint.get("verify_ssl"), _as_bool(llm_cfg.get("verify_ssl"), True))

        item = {
            "endpoint_index": endpoint_index,
            "endpoint_name": endpoint.get("name", f"endpoint_{endpoint_index + 1}"),
            "timeout": timeout_seconds,
            "verify_ssl": verify_ssl,
            "models_status": "skipped",
            "chat_status": "skipped",
        }

        try:
            with httpx.Client(timeout=_build_timeout(timeout_seconds, llm_cfg), verify=verify_ssl) as client:
                if include_models:
                    started = time.monotonic()
                    resp = client.get(_models_url(endpoint["base_url"]), headers=headers)
                    item["models_latency_ms"] = int((time.monotonic() - started) * 1000)
                    item["models_status_code"] = resp.status_code
                    item["models_channel_name"] = resp.headers.get("X-Channel-Name", "")
                    resp.raise_for_status()
                    models_data = resp.json()
                    ids = []
                    for obj in models_data.get("data", []):
                        if isinstance(obj, dict) and obj.get("id"):
                            ids.append(str(obj["id"]))
                    item["models_status"] = "ok"
                    item["model_count"] = len(ids)
                    item["configured_model_found"] = model in ids if ids else None

                if chat_smoke:
                    started = time.monotonic()
                    smoke_payload = _build_payload(
                        "请只输出一个 JSON 对象：{\"summary\":\"ok\",\"confidence\":\"high\"}",
                        model,
                        {**llm_cfg, "max_tokens": 128, "temperature": 0},
                    )
                    resp = client.post(_chat_url(endpoint["base_url"]), headers=headers, json=smoke_payload)
                    item["chat_latency_ms"] = int((time.monotonic() - started) * 1000)
                    item["chat_status_code"] = resp.status_code
                    item["chat_channel_name"] = resp.headers.get("X-Channel-Name", "")
                    resp.raise_for_status()
                    data = resp.json()
                    content = data["choices"][0]["message"]["content"]
                    _extract_json_text(content)
                    item["chat_status"] = "ok"

            if (not include_models or item["models_status"] == "ok") and (not chat_smoke or item["chat_status"] == "ok"):
                ok_any = True

        except Exception as exc:
            item["error"] = _short_error(exc)
            if include_models and item["models_status"] == "skipped":
                item["models_status"] = "failed"
            if chat_smoke and item["chat_status"] == "skipped":
                item["chat_status"] = "failed"

        result["endpoints"].append(item)

    result["overall_status"] = "ok" if ok_any else "failed"
    return result
