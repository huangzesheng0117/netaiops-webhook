#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetAIOps v8 Prometheus HTTP API fallback client.

职责：
- 作为 Prometheus MCP 不可用时的 HTTP API 兜底查询客户端。
- 只使用 Prometheus/VictoriaMetrics 只读接口：
  /api/v1/query
  /api/v1/query_range
- 不负责业务判断，业务判断后续交给 window_analyzer/evidence 层。
"""

from __future__ import annotations

import time
from typing import Any, Dict, Optional

import requests


class PrometheusHttpClient:
    def __init__(self, base_url: str, timeout: int = 15) -> None:
        self.base_url = (base_url or "").rstrip("/")
        self.timeout = int(timeout or 15)

    def query(self, query: str, ts: Optional[float] = None) -> Dict[str, Any]:
        params: Dict[str, Any] = {"query": query}
        if ts is not None:
            params["time"] = ts
        return self._get("/api/v1/query", params=params, query_type="instant", query=query)

    def query_range(self, query: str, start: float, end: float, step: str = "60s") -> Dict[str, Any]:
        params: Dict[str, Any] = {
            "query": query,
            "start": start,
            "end": end,
            "step": step,
        }
        return self._get("/api/v1/query_range", params=params, query_type="range", query=query)

    def _get(self, path: str, params: Dict[str, Any], query_type: str, query: str) -> Dict[str, Any]:
        url = self.base_url + path
        started = time.time()
        try:
            resp = requests.get(
                url,
                params=params,
                timeout=self.timeout,
            )
            elapsed_ms = int((time.time() - started) * 1000)
            text = resp.text
            try:
                data = resp.json()
            except Exception:
                data = None

            ok = bool(
                resp.status_code == 200
                and isinstance(data, dict)
                and data.get("status") == "success"
            )
            result = ((data or {}).get("data") or {}).get("result") if isinstance(data, dict) else None

            return {
                "ok": ok,
                "source": "prometheus_http_api",
                "backend": "victoria_or_prometheus",
                "url": url,
                "query": query,
                "query_type": query_type,
                "status_code": resp.status_code,
                "elapsed_ms": elapsed_ms,
                "result_count": len(result or []),
                "data": data,
                "error": None if ok else self._build_error(resp.status_code, data, text),
            }
        except Exception as e:
            elapsed_ms = int((time.time() - started) * 1000)
            return {
                "ok": False,
                "source": "prometheus_http_api",
                "backend": "victoria_or_prometheus",
                "url": url,
                "query": query,
                "query_type": query_type,
                "elapsed_ms": elapsed_ms,
                "result_count": 0,
                "data": None,
                "error": f"{type(e).__name__}: {e}",
            }

    @staticmethod
    def _build_error(status_code: int, data: Any, text: str) -> str:
        if isinstance(data, dict):
            if data.get("error"):
                return f"http_{status_code}: {data.get('errorType') or ''} {data.get('error')}"
            return f"http_{status_code}: prometheus status={data.get('status')}"
        return f"http_{status_code}: {text[:300]}"
