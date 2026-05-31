#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetAIOps v8 Prometheus metric mapping loader.

职责：
- 加载 config/prometheus_metrics.yaml。
- 根据 profile/query_name 生成 PromQL 候选列表。
- 只做模板渲染，不负责执行查询和业务判断。
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


_VAR_RE = re.compile(r"{{\s*([a-zA-Z0-9_]+)\s*}}")


class PrometheusMetricMapping:
    def __init__(self, mapping_path: str = "config/prometheus_metrics.yaml") -> None:
        self.mapping_path = Path(mapping_path)
        if not self.mapping_path.exists():
            raise FileNotFoundError(f"metric mapping file not found: {self.mapping_path}")
        self.raw = yaml.safe_load(self.mapping_path.read_text(encoding="utf-8")) or {}
        self.defaults = self.raw.get("defaults") or {}
        self.profiles = self.raw.get("profiles") or {}

    def list_profiles(self) -> List[str]:
        return sorted(self.profiles.keys())

    def get_profile(self, profile: str) -> Dict[str, Any]:
        item = self.profiles.get(profile)
        if not isinstance(item, dict):
            raise KeyError(f"profile not found: {profile}")
        return item

    def list_queries(self, profile: str) -> List[str]:
        item = self.get_profile(profile)
        queries = item.get("queries") or {}
        return sorted(queries.keys())

    def get_query_config(self, profile: str, query_name: str) -> Dict[str, Any]:
        item = self.get_profile(profile)
        queries = item.get("queries") or {}
        q = queries.get(query_name)
        if not isinstance(q, dict):
            raise KeyError(f"query not found: profile={profile} query={query_name}")
        return q

    def render_candidates(self, profile: str, query_name: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        q = self.get_query_config(profile, query_name)

        if q.get("promql"):
            templates = [q["promql"]]
        else:
            templates = q.get("promql_candidates") or []

        result: List[Dict[str, Any]] = []
        for idx, template in enumerate(templates):
            rendered, missing = render_template(str(template), context)
            result.append({
                "index": idx,
                "profile": profile,
                "query_name": query_name,
                "promql": rendered,
                "template": template,
                "missing_variables": missing,
                "unit": q.get("unit"),
                "direction": q.get("direction"),
            })
        return result


def normalize_context(context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    ctx = dict(context or {})

    aliases = {
        "if_name": ["if_name", "ifName", "interface", "interface_name", "object_name"],
        "device_ip": ["device_ip", "ip", "instance"],
        "hostname": ["hostname", "sysName", "device_name"],
        "job": ["job"],
    }

    for canonical, keys in aliases.items():
        if ctx.get(canonical):
            continue
        for key in keys:
            if ctx.get(key):
                ctx[canonical] = ctx[key]
                break

    return ctx


def render_template(template: str, context: Dict[str, Any]) -> tuple[str, List[str]]:
    ctx = normalize_context(context)
    missing: List[str] = []

    def repl(match: re.Match[str]) -> str:
        key = match.group(1)
        value = ctx.get(key)
        if value is None or value == "":
            missing.append(key)
            return ""
        return str(value).replace("\\", "\\\\").replace('"', '\\"')

    rendered = _VAR_RE.sub(repl, template)
    return rendered, sorted(set(missing))


if __name__ == "__main__":
    mapping = PrometheusMetricMapping()
    print("profiles:", mapping.list_profiles())
