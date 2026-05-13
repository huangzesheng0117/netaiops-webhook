#!/usr/bin/env python3
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List

try:
    import yaml
except Exception as exc:
    raise SystemExit(f"ERROR: PyYAML is required: {exc}")

BASE_DIR = Path("/opt/netaiops-webhook")
DEFAULT_RULE_FILES = [
    BASE_DIR / "rules.txt",
    BASE_DIR / "input" / "rules.txt",
    BASE_DIR / "input" / "prometheus_rules.txt",
]

OUTPUT_FILE = BASE_DIR / "config" / "interface_groups.yaml"


def safe_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def iter_rules(obj: Any) -> Iterable[Dict[str, Any]]:
    if isinstance(obj, dict):
        if isinstance(obj.get("rules"), list):
            for item in obj["rules"]:
                if isinstance(item, dict):
                    yield item

        for value in obj.values():
            yield from iter_rules(value)

    elif isinstance(obj, list):
        for item in obj:
            yield from iter_rules(item)


def load_rules(path: Path) -> List[Dict[str, Any]]:
    text = path.read_text(encoding="utf-8", errors="replace")

    try:
        data = json.loads(text)
    except Exception as exc:
        raise SystemExit(f"ERROR: failed to parse rules json: {path}: {exc}")

    return list(iter_rules(data))


def extract_ip(query: str) -> str:
    m = re.search(r'ip\s*=~\s*"([^"]+)"', query)
    if not m:
        return ""

    value = m.group(1).strip()

    # 只处理确定的单 IP，避免 10.(192|187) 这类正则被错误配置成具体设备。
    if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", value):
        return value

    return ""


def extract_ifnames(query: str) -> List[str]:
    patterns = [
        r'ifName\s*=~\s*"([^"]+\|[^"]+)"',
        r"ifName\s*=~\s*'([^']+\|[^']+)'",
        r'ifDescr\s*=~\s*"([^"]+\|[^"]+)"',
        r"ifDescr\s*=~\s*'([^']+\|[^']+)'",
    ]

    for pattern in patterns:
        m = re.search(pattern, query, flags=re.IGNORECASE)
        if not m:
            continue

        expr = m.group(1).strip()
        result = []
        seen = set()

        for item in expr.split("|"):
            item = item.strip().strip('"').strip("'")
            if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_\-./]+", item):
                continue
            if item in seen:
                continue
            seen.add(item)
            result.append(item)

        if len(result) >= 2:
            return result

    return []


def clean_description(value: str) -> str:
    value = safe_text(value)
    value = value.replace("{{$labels.sysName}}", "").strip()
    value = re.sub(r"\s+", " ", value)
    return value


def base_keywords(name: str, description: str) -> List[str]:
    name = safe_text(name)
    description = clean_description(description)

    candidates = [
        name,
        description,
    ]

    # 去掉“超过80%”后半段，保留线路名称主体，方便匹配真实告警文本。
    for text in (name, description):
        text = clean_description(text)

        for sep in ("超过80%", "利用率超过80%", "-入向", "-出向"):
            if sep in text:
                candidates.append(text.split(sep)[0].strip())

        # SH8-CTC利用率-入向 -> SH8-CTC
        short = re.sub(r"利用率.*$", "", text).strip("_- ")
        if short and short != text:
            candidates.append(short)

        # SH8互联网线路_CTC_300M_利用率超过80%-入向 -> SH8互联网线路_CTC_300M
        m = re.search(r"(.+?_\d+[MG]?)_?利用率", text)
        if m:
            candidates.append(m.group(1).strip())

    result = []
    seen = set()

    for item in candidates:
        item = clean_description(item)
        if not item:
            continue
        if len(item) < 4:
            continue
        if item in seen:
            continue
        seen.add(item)
        result.append(item)

    return result


def normalize_group_name(name: str, device_ip: str, interfaces: List[str]) -> str:
    raw = safe_text(name) or f"{device_ip}_{'_'.join(interfaces)}"
    raw = raw.replace("利用率-入向", "")
    raw = raw.replace("利用率-出向", "")
    raw = raw.replace("利用率", "")
    raw = re.sub(r"[^A-Za-z0-9_\-\u4e00-\u9fff]+", "_", raw)
    raw = raw.strip("_-")
    return raw or f"{device_ip}_{'_'.join(interfaces)}"


def build_groups(rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    merged: Dict[tuple, Dict[str, Any]] = {}

    for rule in rules:
        name = safe_text(rule.get("name"))
        query = safe_text(rule.get("query"))
        annotations = rule.get("annotations") if isinstance(rule.get("annotations"), dict) else {}
        description = clean_description(annotations.get("description"))

        text_for_family = f"{name} {description} {query}"

        if "利用率" not in text_for_family:
            continue

        if "ifName" not in query and "ifDescr" not in query:
            continue

        interfaces = extract_ifnames(query)
        if len(interfaces) < 2:
            continue

        device_ip = extract_ip(query)

        # 没有确定单 IP 的规则先不生成 interface group，避免把泛规则错误绑定。
        if not device_ip:
            continue

        key = (device_ip, tuple(interfaces))

        if key not in merged:
            merged[key] = {
                "name": normalize_group_name(name, device_ip, interfaces),
                "description": description or name,
                "device_ip": device_ip,
                "match_keywords": [],
                "interfaces": interfaces,
                "source_rules": [],
            }

        group = merged[key]
        group["source_rules"].append(name)

        for keyword in base_keywords(name, description):
            if keyword not in group["match_keywords"]:
                group["match_keywords"].append(keyword)

    groups = list(merged.values())

    groups.sort(key=lambda x: (x.get("device_ip", ""), x.get("name", "")))

    return groups


def main() -> None:
    rule_file = None

    for path in DEFAULT_RULE_FILES:
        if path.exists():
            rule_file = path
            break

    if not rule_file:
        raise SystemExit(
            "ERROR: rules file not found. Expected one of: "
            + ", ".join(str(x) for x in DEFAULT_RULE_FILES)
        )

    rules = load_rules(rule_file)
    groups = build_groups(rules)

    if not groups:
        raise SystemExit("ERROR: no multi-interface utilization groups found from rules")

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    data = {
        "interface_groups": groups,
    }

    OUTPUT_FILE.write_text(
        yaml.safe_dump(data, allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )

    print("RULE_FILE =", rule_file)
    print("OUTPUT_FILE =", OUTPUT_FILE)
    print("GROUP_COUNT =", len(groups))

    for group in groups:
        print(
            "GROUP:",
            group.get("name"),
            group.get("device_ip"),
            ",".join(group.get("interfaces", [])),
            "keywords=" + " | ".join(group.get("match_keywords", [])[:4]),
        )

    print("BUILD_INTERFACE_GROUPS_FROM_RULES_CHECK=PASS")


if __name__ == "__main__":
    main()
