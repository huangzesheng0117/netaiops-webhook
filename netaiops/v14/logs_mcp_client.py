"""Strict read-only Streamable-HTTP MCP client for Logs Evidence.

No arbitrary Elasticsearch DSL/index/URL/credential fields are accepted by the
public collection request. Real network use remains gated by higher-level
runtime configuration and is disabled during W1 offline verification.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Mapping

import httpx

from .logs_contracts import EXPECTED_LOG_TOOLS, LogsCollectionRequest, LogsCollectionResult


class LogsMcpError(RuntimeError):
    pass


class LogsMcpContractError(LogsMcpError):
    pass


class LogsMcpTransportError(LogsMcpError):
    def __init__(self, message: str, *, safe_to_retry: bool = False) -> None:
        super().__init__(message)
        self.safe_to_retry = bool(safe_to_retry)


@dataclass(frozen=True)
class ToolContractSummary:
    names: tuple[str, ...]
    exact_match: bool


class StreamableHttpMcpTransport:
    def __init__(
        self,
        url: str,
        *,
        timeout_seconds: float = 15.0,
        protocol_version: str = "2025-06-18",
        client: httpx.Client | None = None,
    ) -> None:
        if not url.startswith(("http://", "https://")):
            raise ValueError("MCP URL must use http or https")
        self.url = url
        self.timeout_seconds = float(timeout_seconds)
        self.protocol_version = protocol_version
        self._owned_client = client is None
        timeout = httpx.Timeout(
            self.timeout_seconds,
            connect=min(5.0, self.timeout_seconds),
            write=min(10.0, self.timeout_seconds),
            pool=min(5.0, self.timeout_seconds),
        )
        self.client = client or httpx.Client(
            timeout=timeout,
            trust_env=False,
        )
        self.session_id: str | None = None
        self.initialized = False
        self._next_id = 1

    def close(self) -> None:
        if self._owned_client:
            self.client.close()

    def __enter__(self) -> "StreamableHttpMcpTransport":
        self.initialize()
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()

    def initialize(self) -> Mapping[str, Any]:
        if self.initialized:
            return {"already_initialized": True}
        result = self.request(
            "initialize",
            {
                "protocolVersion": self.protocol_version,
                "capabilities": {},
                "clientInfo": {"name": "netaiops-webhook-logs", "version": "v14-w1"},
            },
        )
        negotiated = str(result.get("protocolVersion") or self.protocol_version)
        self.protocol_version = negotiated
        self.notify("notifications/initialized", {})
        self.initialized = True
        return result

    def list_tools(self) -> Mapping[str, Any]:
        self._require_initialized()
        return self.request("tools/list", {})

    def call_tool(self, name: str, arguments: Mapping[str, Any]) -> Mapping[str, Any]:
        self._require_initialized()
        return self.request("tools/call", {"name": name, "arguments": dict(arguments)})

    def request(self, method: str, params: Mapping[str, Any]) -> Mapping[str, Any]:
        request_id = self._next_id
        self._next_id += 1
        payload = {"jsonrpc": "2.0", "id": request_id, "method": method, "params": dict(params)}
        response = self._post(payload)
        message = self._decode_response(response, request_id)
        if "error" in message:
            raise LogsMcpTransportError("MCP JSON-RPC error: " + json.dumps(message["error"], sort_keys=True)[:800])
        result = message.get("result", {})
        if not isinstance(result, Mapping):
            raise LogsMcpContractError("MCP result must be an object")
        return result

    def notify(self, method: str, params: Mapping[str, Any]) -> None:
        payload = {"jsonrpc": "2.0", "method": method, "params": dict(params)}
        response = self._post(payload)
        if response.content:
            self._decode_response(response, None)

    def _post(self, payload: Mapping[str, Any]) -> httpx.Response:
        headers = {
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
        }
        if payload.get("method") != "initialize":
            headers["MCP-Protocol-Version"] = self.protocol_version
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        try:
            response = self.client.post(self.url, json=dict(payload), headers=headers)
        except (httpx.ConnectError, httpx.ConnectTimeout, httpx.PoolTimeout) as exc:
            raise LogsMcpTransportError(
                f"MCP connection failed before a response: {type(exc).__name__}",
                safe_to_retry=True,
            ) from exc
        except httpx.HTTPError as exc:
            # Read/write/protocol failures may happen after the request reached the server.
            # Treat them as ambiguous and never automatically retry the same phase.
            raise LogsMcpTransportError(
                f"MCP HTTP transport failed: {type(exc).__name__}",
                safe_to_retry=False,
            ) from exc
        if response.status_code >= 400:
            raise LogsMcpTransportError(
                f"MCP HTTP status {response.status_code}",
                safe_to_retry=False,
            )
        session = response.headers.get("Mcp-Session-Id")
        if session:
            self.session_id = session
        return response

    @staticmethod
    def _decode_response(response: httpx.Response, request_id: int | None) -> Mapping[str, Any]:
        if not response.content:
            return {}
        content_type = response.headers.get("content-type", "").lower()
        if "application/json" in content_type:
            obj = response.json()
            if not isinstance(obj, Mapping):
                raise LogsMcpContractError("MCP JSON response must be an object")
            if request_id is not None and obj.get("id") != request_id:
                raise LogsMcpContractError("MCP JSON response id mismatch")
            return obj
        text = response.text
        if "text/event-stream" in content_type or text.lstrip().startswith(("event:", "data:")):
            candidates: list[Mapping[str, Any]] = []
            for block in text.replace("\r\n", "\n").split("\n\n"):
                data_lines = [line[5:].strip() for line in block.splitlines() if line.startswith("data:")]
                if not data_lines:
                    continue
                try:
                    obj = json.loads("\n".join(data_lines))
                except json.JSONDecodeError:
                    continue
                if isinstance(obj, Mapping):
                    candidates.append(obj)
            if request_id is None and candidates:
                return candidates[-1]
            for item in candidates:
                if item.get("id") == request_id:
                    return item
            raise LogsMcpContractError("SSE response did not contain matching request id")
        try:
            obj = response.json()
        except Exception as exc:
            raise LogsMcpContractError("unsupported MCP response content type") from exc
        if not isinstance(obj, Mapping):
            raise LogsMcpContractError("MCP response must be an object")
        if request_id is not None and obj.get("id") != request_id:
            raise LogsMcpContractError("MCP JSON fallback response id mismatch")
        return obj

    def _require_initialized(self) -> None:
        if not self.initialized:
            raise LogsMcpTransportError("MCP transport is not initialized")


class LogsMcpClient:
    def __init__(self, transport: StreamableHttpMcpTransport) -> None:
        self.transport = transport

    def validate_tools(self) -> ToolContractSummary:
        payload = self.transport.list_tools()
        tools = payload.get("tools", [])
        if not isinstance(tools, list):
            raise LogsMcpContractError("tools/list result must contain a tools array")
        names: list[str] = []
        for item in tools:
            if not isinstance(item, Mapping) or not isinstance(item.get("name"), str):
                raise LogsMcpContractError("each tools/list item must have a string name")
            names.append(item["name"])
        actual = frozenset(names)
        exact = actual == EXPECTED_LOG_TOOLS and len(names) == len(EXPECTED_LOG_TOOLS)
        if not exact:
            raise LogsMcpContractError(
                f"tools/list drift: expected={sorted(EXPECTED_LOG_TOOLS)} actual={sorted(actual)} count={len(names)}"
            )
        collect = next(item for item in tools if item.get("name") == "collect_log_evidence")
        schema = collect.get("inputSchema")
        if not isinstance(schema, Mapping):
            raise LogsMcpContractError("collect_log_evidence inputSchema missing")
        properties = schema.get("properties")
        if not isinstance(properties, Mapping):
            raise LogsMcpContractError("collect_log_evidence inputSchema.properties missing")
        if schema.get("additionalProperties") is not False:
            raise LogsMcpContractError("collect_log_evidence must reject additional properties")
        expected_fields = {
            "profile_id",
            "incident_time",
            "window_before_minutes",
            "window_after_minutes",
            "phase",
            "device_ip",
            "device_name",
            "event_code",
            "severity",
            "keywords",
            "max_raw_samples",
        }
        actual_fields = set(properties)
        forbidden = {
            "cluster", "index", "index_pattern", "url", "api_key", "secret",
            "raw_dsl", "query_dsl", "body", "script", "runtime_mappings",
        } & actual_fields
        if actual_fields != expected_fields or forbidden:
            raise LogsMcpContractError(
                "collect_log_evidence schema drift: "
                f"expected={sorted(expected_fields)} actual={sorted(actual_fields)} "
                f"forbidden={sorted(forbidden)}"
            )
        annotations = collect.get("annotations")
        if not isinstance(annotations, Mapping):
            raise LogsMcpContractError("collect_log_evidence annotations missing")
        if (
            annotations.get("readOnlyHint") is not True
            or annotations.get("destructiveHint") is not False
            or annotations.get("idempotentHint") is not True
            or annotations.get("openWorldHint") is not False
        ):
            raise LogsMcpContractError(
                "collect_log_evidence read-only/idempotent annotations drift"
            )
        return ToolContractSummary(names=tuple(sorted(names)), exact_match=True)

    def collect_log_evidence(self, request: LogsCollectionRequest) -> LogsCollectionResult:
        result = self.transport.call_tool("collect_log_evidence", request.tool_arguments())
        if result.get("isError") is True:
            raise LogsMcpTransportError("collect_log_evidence returned isError=true")
        structured = result.get("structuredContent")
        if isinstance(structured, Mapping):
            payload: Any = structured
        else:
            payload = None
            content = result.get("content")
            if isinstance(content, list):
                for item in content:
                    if isinstance(item, Mapping) and item.get("type") == "text" and isinstance(item.get("text"), str):
                        try:
                            parsed = json.loads(item["text"])
                        except json.JSONDecodeError:
                            continue
                        if isinstance(parsed, Mapping):
                            payload = parsed
                            break
            if payload is None and isinstance(result, Mapping) and "status" in result:
                payload = result
        if not isinstance(payload, Mapping):
            raise LogsMcpContractError("collect_log_evidence did not return structured JSON output")
        parsed = LogsCollectionResult.model_validate(payload)
        if parsed.profile_id != request.profile_id:
            raise LogsMcpContractError("response profile_id does not match request")
        if parsed.phase != request.phase:
            raise LogsMcpContractError("response phase does not match request")
        if parsed.incident_time != request.incident_time:
            raise LogsMcpContractError("response incident_time does not match request")
        expected_start = request.incident_time - timedelta(
            minutes=request.window_before_minutes
        )
        expected_end = request.incident_time + timedelta(
            minutes=request.window_after_minutes
        )
        if (
            parsed.query_window.start_time != expected_start
            or parsed.query_window.end_time != expected_end
        ):
            raise LogsMcpContractError(
                "response query_window does not match requested incident window"
            )
        return parsed
