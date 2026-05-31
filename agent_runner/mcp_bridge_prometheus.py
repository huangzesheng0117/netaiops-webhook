#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetAIOps v8 Prometheus MCP Bridge POC.

职责：
- 优先尝试通过 Prometheus MCP SSE 调用 execute_query / execute_range_query。
- MCP 不可用、工具调用失败、参数不兼容时，fallback 到 Victoria/Prometheus HTTP API。
- 本模块只做只读查询封装，不做业务根因判断，不修改 Prometheus/Grafana/设备配置。

说明：
- 当前 venv 中可能没有官方 mcp Python SDK。
- 为了避免第二批就强依赖 pip 安装，本文件内置一个最小 SSE JSON-RPC MCP 客户端。
- 后续如果确认官方 SDK 安装稳定，可以再替换为 SDK 实现。
"""

from __future__ import annotations

import json
import queue
import threading
import time
import urllib.parse
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests
import yaml

try:
    from netaiops.prometheus_http_client import PrometheusHttpClient
except Exception:
    # 兼容从仓库根目录外直接执行的场景。
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from netaiops.prometheus_http_client import PrometheusHttpClient


DEFAULT_PROTOCOL_VERSION = "2024-11-05"


def load_config(config_path: str = "config.yaml") -> Dict[str, Any]:
    p = Path(config_path)
    if not p.exists():
        return {}
    return yaml.safe_load(p.read_text(encoding="utf-8")) or {}


class MinimalSseMcpClient:
    """
    最小 MCP SSE JSON-RPC 客户端。

    流程：
    1. GET /sse，读取 event:endpoint，得到 /messages/?session_id=...
    2. POST JSON-RPC initialize 到 messages endpoint。
    3. POST notifications/initialized。
    4. POST tools/list 或 tools/call。
    5. 从 SSE 流中读取对应 id 的响应。
    """

    def __init__(self, sse_url: str, timeout: int = 15) -> None:
        self.sse_url = sse_url
        self.timeout = int(timeout or 15)
        self.session = requests.Session()
        self._resp: Optional[requests.Response] = None
        self._reader_thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._endpoint_ready = threading.Event()
        self._endpoint: Optional[str] = None
        self._messages: "queue.Queue[Dict[str, Any]]" = queue.Queue()
        self._next_id = 1
        self._initialized = False

    def __enter__(self) -> "MinimalSseMcpClient":
        self.open()
        self.initialize()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def open(self) -> None:
        headers = {"Accept": "text/event-stream"}
        self._resp = self.session.get(
            self.sse_url,
            headers=headers,
            stream=True,
            timeout=(3, self.timeout),
        )
        if self._resp.status_code != 200:
            raise RuntimeError(f"SSE open failed: HTTP {self._resp.status_code} {self._resp.text[:200]}")

        self._reader_thread = threading.Thread(target=self._reader_loop, daemon=True)
        self._reader_thread.start()

        if not self._endpoint_ready.wait(timeout=min(self.timeout, 10)):
            raise RuntimeError("SSE endpoint event not received")

    def close(self) -> None:
        self._stop.set()
        try:
            if self._resp is not None:
                self._resp.close()
        except Exception:
            pass
        try:
            self.session.close()
        except Exception:
            pass

    def initialize(self) -> Dict[str, Any]:
        if self._initialized:
            return {"ok": True, "already_initialized": True}

        result = self.request(
            "initialize",
            {
                "protocolVersion": DEFAULT_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {
                    "name": "netaiops-webhook-prometheus-bridge",
                    "version": "v8-poc",
                },
            },
        )
        self.notify("notifications/initialized", {})
        self._initialized = True
        return result

    def list_tools(self) -> Dict[str, Any]:
        return self.request("tools/list", {})

    def call_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        return self.request(
            "tools/call",
            {
                "name": name,
                "arguments": arguments,
            },
        )

    def request(self, method: str, params: Dict[str, Any]) -> Dict[str, Any]:
        msg_id = self._next_id
        self._next_id += 1

        payload = {
            "jsonrpc": "2.0",
            "id": msg_id,
            "method": method,
            "params": params,
        }
        self._post_json(payload)

        deadline = time.time() + self.timeout
        while time.time() < deadline:
            remaining = max(0.2, deadline - time.time())
            try:
                msg = self._messages.get(timeout=min(remaining, 1))
            except queue.Empty:
                continue

            if msg.get("id") == msg_id:
                if "error" in msg:
                    raise RuntimeError(json.dumps(msg.get("error"), ensure_ascii=False))
                return msg.get("result", {})

        raise TimeoutError(f"MCP request timeout: method={method} id={msg_id}")

    def notify(self, method: str, params: Dict[str, Any]) -> None:
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
        }
        self._post_json(payload)

    def _post_json(self, payload: Dict[str, Any]) -> None:
        if not self._endpoint:
            raise RuntimeError("MCP messages endpoint is not ready")

        url = urllib.parse.urljoin(self.sse_url, self._endpoint)
        resp = self.session.post(
            url,
            data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            timeout=(3, self.timeout),
        )
        if resp.status_code not in (200, 202):
            raise RuntimeError(f"MCP POST failed: HTTP {resp.status_code} {resp.text[:300]}")

    def _reader_loop(self) -> None:
        event_name: Optional[str] = None
        data_lines: List[str] = []

        def flush_event() -> None:
            nonlocal event_name, data_lines
            if not data_lines:
                event_name = None
                data_lines = []
                return

            data = "\n".join(data_lines).strip()
            ev = event_name or "message"

            if ev == "endpoint":
                self._endpoint = data
                self._endpoint_ready.set()
            else:
                try:
                    obj = json.loads(data)
                    if isinstance(obj, dict):
                        self._messages.put(obj)
                except Exception:
                    self._messages.put({
                        "jsonrpc": "2.0",
                        "method": "non_json_event",
                        "params": {
                            "event": ev,
                            "data": data[:1000],
                        },
                    })

            event_name = None
            data_lines = []

        try:
            assert self._resp is not None
            for raw in self._resp.iter_lines(decode_unicode=True):
                if self._stop.is_set():
                    break
                if raw is None:
                    continue

                line = raw.rstrip("\r")
                if line == "":
                    flush_event()
                    continue
                if line.startswith(":"):
                    continue
                if line.startswith("event:"):
                    event_name = line[len("event:"):].strip()
                    continue
                if line.startswith("data:"):
                    data_lines.append(line[len("data:"):].strip())
                    continue
        except Exception as e:
            self._messages.put({
                "jsonrpc": "2.0",
                "method": "reader_error",
                "params": {
                    "error": f"{type(e).__name__}: {e}",
                },
            })


class PrometheusBridge:
    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        self.config = config or load_config()
        self.prom_mcp_cfg = self.config.get("prometheus_mcp") or {}
        self.prom_direct_cfg = self.config.get("prometheus_direct") or {}

        self.enabled = bool(self.prom_mcp_cfg.get("enabled", False))
        self.sse_url = self.prom_mcp_cfg.get("sse_url") or ""
        self.backend_url = self.prom_mcp_cfg.get("backend_url") or ""
        self.timeout = int(self.prom_mcp_cfg.get("timeout_seconds") or 15)

        fallback_cfg = self.prom_mcp_cfg.get("fallback_http_api") or {}
        self.fallback_enabled = bool(fallback_cfg.get("enabled", True))
        self.fallback_url = fallback_cfg.get("url") or self.backend_url

        self.http_client = PrometheusHttpClient(
            base_url=self.fallback_url,
            timeout=self.timeout,
        ) if self.fallback_url else None

    @classmethod
    def from_config(cls, config_path: str = "config.yaml") -> "PrometheusBridge":
        return cls(load_config(config_path))

    def summary(self) -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "sse_url": self.sse_url,
            "backend_url": self.backend_url,
            "timeout_seconds": self.timeout,
            "fallback_enabled": self.fallback_enabled,
            "fallback_url": self.fallback_url,
        }

    def list_tools(self) -> Dict[str, Any]:
        started = time.time()
        try:
            self._ensure_mcp_ready()
            with MinimalSseMcpClient(self.sse_url, timeout=self.timeout) as client:
                result = client.list_tools()
            return {
                "ok": True,
                "source": "prometheus_mcp",
                "elapsed_ms": int((time.time() - started) * 1000),
                "result": result,
                "error": None,
            }
        except Exception as e:
            return {
                "ok": False,
                "source": "prometheus_mcp",
                "elapsed_ms": int((time.time() - started) * 1000),
                "result": None,
                "error": f"{type(e).__name__}: {e}",
            }

    def execute_query(self, query: str, ts: Optional[float] = None) -> Dict[str, Any]:
        tool_args: Dict[str, Any] = {"query": query}
        if ts is not None:
            tool_args["time"] = ts

        mcp_result, mcp_error = self._try_mcp_tool("execute_query", tool_args)
        if mcp_result is not None:
            return {
                "ok": True,
                "source": "prometheus_mcp",
                "backend": self.backend_url,
                "query": query,
                "query_type": "instant",
                "fallback_used": False,
                "mcp_result": mcp_result,
                "error": None,
            }

        if self.fallback_enabled and self.http_client is not None:
            fallback = self.http_client.query(query=query, ts=ts)
            fallback["fallback_used"] = True
            fallback["mcp_error"] = mcp_error
            return fallback

        return {
            "ok": False,
            "source": "prometheus_mcp",
            "backend": self.backend_url,
            "query": query,
            "query_type": "instant",
            "fallback_used": False,
            "mcp_result": None,
            "error": mcp_error or "mcp_unavailable_and_fallback_disabled",
        }

    def execute_range_query(self, query: str, start: float, end: float, step: str = "60s") -> Dict[str, Any]:
        # Prometheus MCP 的 execute_range_query schema 要求 start/end/step 均为 string。
        # 这里统一转成字符串，避免 Pydantic 校验失败。
        tool_args = {
            "query": query,
            "start": str(start),
            "end": str(end),
            "step": str(step),
        }

        mcp_result, mcp_error = self._try_mcp_tool("execute_range_query", tool_args)
        if mcp_result is not None:
            return {
                "ok": True,
                "source": "prometheus_mcp",
                "backend": self.backend_url,
                "query": query,
                "query_type": "range",
                "start": start,
                "end": end,
                "step": step,
                "fallback_used": False,
                "mcp_result": mcp_result,
                "error": None,
            }

        if self.fallback_enabled and self.http_client is not None:
            fallback = self.http_client.query_range(query=query, start=start, end=end, step=step)
            fallback["fallback_used"] = True
            fallback["mcp_error"] = mcp_error
            return fallback

        return {
            "ok": False,
            "source": "prometheus_mcp",
            "backend": self.backend_url,
            "query": query,
            "query_type": "range",
            "start": start,
            "end": end,
            "step": step,
            "fallback_used": False,
            "mcp_result": None,
            "error": mcp_error or "mcp_unavailable_and_fallback_disabled",
        }

    def _try_mcp_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        started = time.time()
        try:
            self._ensure_mcp_ready()
            with MinimalSseMcpClient(self.sse_url, timeout=self.timeout) as client:
                result = client.call_tool(tool_name, arguments)

            elapsed_ms = int((time.time() - started) * 1000)

            if isinstance(result, dict):
                result["_netaiops_elapsed_ms"] = elapsed_ms

                # MCP 工具调用可能返回 JSON-RPC 成功，但工具自身 isError=true。
                # 这种情况必须视为失败，不能让上层误判为 Prometheus 取证成功。
                if result.get("isError") is True:
                    content = result.get("content") or []
                    err_text = None
                    if content and isinstance(content, list):
                        first = content[0]
                        if isinstance(first, dict):
                            err_text = first.get("text")
                    if not err_text:
                        err_text = json.dumps(result, ensure_ascii=False, default=str)[:800]
                    return None, f"mcp_tool_error: {err_text}"

                return result, None

            return None, f"mcp_tool_invalid_result: {type(result).__name__}"
        except Exception as e:
            return None, f"{type(e).__name__}: {e}"

    def _ensure_mcp_ready(self) -> None:
        if not self.enabled:
            raise RuntimeError("prometheus_mcp disabled in config.yaml")
        if not self.sse_url:
            raise RuntimeError("prometheus_mcp.sse_url is empty")
