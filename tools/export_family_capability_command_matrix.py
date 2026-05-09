#!/usr/bin/env python3
import inspect
import json
import re
import sys
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple
from xml.sax.saxutils import escape, quoteattr

BASE_DIR = Path("/opt/netaiops-webhook")
OUTPUT_FILE = BASE_DIR / "docs" / "webhook_v5_family_capability_command_matrix.xlsx"

sys.path.insert(0, str(BASE_DIR))


def safe_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list, tuple, set)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value).strip()


def to_plain(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: to_plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [to_plain(x) for x in value]
    if hasattr(value, "__dict__"):
        return {k: to_plain(v) for k, v in value.__dict__.items() if not k.startswith("_")}
    return value


def get_meta_value(meta: Any, *keys: str, default: Any = "") -> Any:
    meta = to_plain(meta)
    if isinstance(meta, dict):
        for key in keys:
            if key in meta:
                return meta.get(key)
    return default


def normalize_capability_item(item: Any) -> Dict[str, Any]:
    item = to_plain(item)
    if isinstance(item, str):
        return {"capability": item}
    if isinstance(item, dict):
        return item
    return {"capability": safe_text(item)}


def discover_family_names() -> List[str]:
    known = {
        "interface_or_link_utilization_high",
        "interface_or_link_traffic_drop",
        "interface_packet_loss_or_discards_high",
        "interface_status_or_flap",
        "interface_flap",
        "bgp_neighbor_down",
        "ospf_neighbor_down",
        "routing_neighbor_down",
        "device_cpu_high",
        "device_memory_high",
        "f5_pool_member_down",
        "generic_network_readonly",
    }

    try:
        import netaiops.family_registry as fr

        for name, value in vars(fr).items():
            if name.startswith("_"):
                continue

            value = to_plain(value)

            if isinstance(value, dict):
                for key, item in value.items():
                    if isinstance(key, str) and (
                        "_" in key
                        and any(x in key for x in ["interface", "bgp", "ospf", "device", "memory", "cpu", "f5", "routing", "generic"])
                    ):
                        known.add(key)

                    if isinstance(item, dict):
                        fam = safe_text(item.get("family") or item.get("name") or item.get("id"))
                        if fam:
                            known.add(fam)

            if isinstance(value, list):
                for item in value:
                    if isinstance(item, str) and "_" in item:
                        known.add(item)
                    elif isinstance(item, dict):
                        fam = safe_text(item.get("family") or item.get("name") or item.get("id"))
                        if fam:
                            known.add(fam)

            if isinstance(value, set):
                for item in value:
                    if isinstance(item, str) and "_" in item:
                        known.add(item)

    except Exception:
        pass

    return sorted(x for x in known if x)


def sample_event_for_family(family: str) -> Dict[str, Any]:
    event = {
        "source": "alertmanager",
        "status": "firing",
        "severity": "critical",
        "vendor": "CISCO",
        "platform": "cisco_nxos",
        "os_family": "ACI",
        "job": "SW-CISCO-ACI-SAMPLE",
        "device_ip": "192.0.2.10",
        "hostname": "SAMPLE-SW01",
        "instance": "192.0.2.10",
        "family": family,
        "playbook_type_hint": family,
        "alarm_type": family,
        "object_type": "interface",
        "interface": "Ethernet1/1",
        "ifName": "Ethernet1/1",
        "if_alias": "To_SAMPLE_PEER",
        "peer_ip": "10.1.1.1",
        "vrf": "default",
        "pool": "/Common/test_pool",
        "pool_name": "/Common/test_pool",
        "pool_member": "10.1.1.10:80",
        "member": "10.1.1.10:80",
        "virtual_server": "/Common/test_vs",
        "raw_text": family,
    }

    if family.startswith("bgp"):
        event.update(
            {
                "vendor": "HUAWEI",
                "platform": "huawei_vrp",
                "os_family": "VRP",
                "object_type": "neighbor",
                "peer_ip": "10.1.1.1",
                "alarm_type": "BGP邻居Down",
                "raw_text": "BGP neighbor 10.1.1.1 down",
            }
        )

    if family.startswith("ospf") or family.startswith("routing"):
        event.update(
            {
                "vendor": "H3C",
                "platform": "h3c_comware",
                "os_family": "Comware",
                "object_type": "neighbor",
                "peer_ip": "10.1.1.1",
                "alarm_type": "OSPF邻居Down",
                "raw_text": "OSPF neighbor down",
            }
        )

    if family == "device_cpu_high":
        event.update(
            {
                "object_type": "device",
                "alarm_type": "CPU使用率高",
                "raw_text": "device cpu high",
            }
        )

    if family == "device_memory_high":
        event.update(
            {
                "object_type": "device",
                "alarm_type": "内存使用率高",
                "raw_text": "device memory high",
            }
        )

    if family == "f5_pool_member_down":
        event.update(
            {
                "vendor": "F5",
                "platform": "f5_tmsh",
                "os_family": "F5",
                "object_type": "pool_member",
                "alarm_type": "F5 pool member down",
                "raw_text": "F5 pool member down",
            }
        )

    return event


def load_core_modules():
    import netaiops.family_registry as family_registry
    import netaiops.capability_registry as capability_registry
    import netaiops.platform_command_matrix as platform_command_matrix

    return family_registry, capability_registry, platform_command_matrix


def get_capability_registry(capability_registry_module) -> Dict[str, Any]:
    for name in ("CAPABILITY_REGISTRY", "CAPABILITIES", "CAPABILITY_DEFINITIONS"):
        value = getattr(capability_registry_module, name, None)
        if isinstance(value, dict):
            return value
    return {}


def get_platform_command_matrix(platform_command_matrix_module) -> Dict[str, Dict[str, str]]:
    value = getattr(platform_command_matrix_module, "PLATFORM_COMMAND_MATRIX", None)
    if isinstance(value, dict):
        return value
    return {}


def get_platform_aliases(platform_command_matrix_module) -> Dict[str, str]:
    value = getattr(platform_command_matrix_module, "PLATFORM_ALIASES", None)
    if isinstance(value, dict):
        return value
    return {}


def build_family_plan(family_registry_module, capability_registry_module, family: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    event = sample_event_for_family(family)

    classify_family = getattr(family_registry_module, "classify_family", None)
    build_capability_plan = getattr(capability_registry_module, "build_capability_plan", None)

    family_result = {
        "family": family,
        "target_kind": "",
        "auto_execute_allowed": "",
        "legacy_playbook_type": family,
    }

    if callable(classify_family):
        try:
            result = classify_family(event)
            if isinstance(result, dict):
                family_result.update(result)
        except Exception as e:
            family_result["classify_error"] = str(e)

    capability_plan = {
        "selected_capabilities": [],
        "readonly_only": "",
        "plan_source": "",
    }

    if callable(build_capability_plan):
        try:
            result = build_capability_plan(event, family_result)
            if isinstance(result, dict):
                capability_plan.update(result)
        except Exception as e:
            capability_plan["build_error"] = str(e)

    return family_result, capability_plan


class SafeFormatDict(dict):
    def __missing__(self, key):
        return "{" + key + "}"


DEFAULT_ARGS = SafeFormatDict(
    {
        "interface": "Ethernet1/1",
        "peer_ip": "10.1.1.1",
        "vrf": "default",
        "pool": "/Common/test_pool",
        "pool_name": "/Common/test_pool",
        "pool_member": "10.1.1.10:80",
        "member": "10.1.1.10:80",
        "virtual_server": "/Common/test_vs",
        "device_ip": "192.0.2.10",
        "hostname": "SAMPLE-SW01",
    }
)


def render_sample_command(template: str, arguments: Dict[str, Any]) -> str:
    args = SafeFormatDict(DEFAULT_ARGS)
    args.update({k: safe_text(v) for k, v in (arguments or {}).items() if safe_text(v)})
    try:
        return template.format_map(args)
    except Exception:
        try:
            return template.format(**args)
        except Exception:
            return template


def family_platform_scope(family: str, platforms: List[str]) -> List[str]:
    if family == "f5_pool_member_down":
        return [p for p in platforms if p == "f5_tmsh"] or platforms

    if family in ("device_cpu_high", "device_memory_high"):
        return [p for p in platforms if p != "f5_tmsh"] + ([p for p in platforms if p == "f5_tmsh"])

    return [p for p in platforms if p != "f5_tmsh"]


def col_letter(n: int) -> str:
    s = ""
    while n:
        n, r = divmod(n - 1, 26)
        s = chr(65 + r) + s
    return s


def cell_ref(row: int, col: int) -> str:
    return f"{col_letter(col)}{row}"


def sheet_name_safe(name: str) -> str:
    name = re.sub(r"[:\\/?*\[\]]", "_", name)
    return name[:31] or "Sheet"


def estimate_width(rows: List[List[Any]], col_idx: int) -> float:
    max_len = 8
    for row in rows[:300]:
        if col_idx < len(row):
            value = safe_text(row[col_idx])
            visual_len = 0
            for ch in value:
                visual_len += 2 if ord(ch) > 127 else 1
            max_len = max(max_len, min(60, visual_len))
    return max(10, min(55, max_len + 2))


def sheet_xml(rows: List[List[Any]], sheet_index: int) -> str:
    row_count = len(rows)
    col_count = max((len(r) for r in rows), default=1)
    last_ref = f"{col_letter(col_count)}{max(row_count, 1)}"

    cols_xml = ["<cols>"]
    for c in range(1, col_count + 1):
        width = estimate_width(rows, c - 1)
        cols_xml.append(f'<col min="{c}" max="{c}" width="{width:.1f}" customWidth="1"/>')
    cols_xml.append("</cols>")

    sheet_data = ["<sheetData>"]
    for r_idx, row in enumerate(rows, start=1):
        height = 22 if r_idx == 1 else 18
        sheet_data.append(f'<row r="{r_idx}" ht="{height}" customHeight="1">')
        for c_idx in range(1, col_count + 1):
            value = row[c_idx - 1] if c_idx - 1 < len(row) else ""
            ref = cell_ref(r_idx, c_idx)
            style = 1 if r_idx == 1 else 0

            if isinstance(value, (int, float)) and not isinstance(value, bool):
                sheet_data.append(f'<c r="{ref}" s="{style}"><v>{value}</v></c>')
            else:
                text = escape(safe_text(value))
                sheet_data.append(f'<c r="{ref}" t="inlineStr" s="{style}"><is><t xml:space="preserve">{text}</t></is></c>')
        sheet_data.append("</row>")
    sheet_data.append("</sheetData>")

    freeze = ""
    if row_count > 1:
        freeze = (
            '<sheetViews><sheetView workbookViewId="0">'
            '<pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/>'
            '</sheetView></sheetViews>'
        )
    else:
        freeze = '<sheetViews><sheetView workbookViewId="0"/></sheetViews>'

    autofilter = f'<autoFilter ref="A1:{last_ref}"/>' if row_count > 1 and col_count > 0 else ""

    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        f"{freeze}"
        f"{''.join(cols_xml)}"
        f"{''.join(sheet_data)}"
        f"{autofilter}"
        "</worksheet>"
    )


def workbook_xml(sheet_names: List[str]) -> str:
    sheets = []
    for idx, name in enumerate(sheet_names, start=1):
        sheets.append(f'<sheet name={quoteattr(name)} sheetId="{idx}" r:id="rId{idx}"/>')
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        "<sheets>"
        + "".join(sheets)
        + "</sheets></workbook>"
    )


def workbook_rels_xml(sheet_count: int) -> str:
    rels = []
    for idx in range(1, sheet_count + 1):
        rels.append(
            f'<Relationship Id="rId{idx}" '
            'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" '
            f'Target="worksheets/sheet{idx}.xml"/>'
        )
    rels.append(
        f'<Relationship Id="rId{sheet_count + 1}" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" '
        'Target="styles.xml"/>'
    )
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        + "".join(rels)
        + "</Relationships>"
    )


def root_rels_xml() -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
        "</Relationships>"
    )


def content_types_xml(sheet_count: int) -> str:
    overrides = [
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>',
        '<Default Extension="xml" ContentType="application/xml"/>',
        '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>',
        '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>',
    ]
    for idx in range(1, sheet_count + 1):
        overrides.append(
            f'<Override PartName="/xl/worksheets/sheet{idx}.xml" '
            'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        )
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        + "".join(overrides)
        + "</Types>"
    )


def styles_xml() -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        '<fonts count="2">'
        '<font><sz val="11"/><name val="Calibri"/></font>'
        '<font><b/><sz val="11"/><color rgb="FFFFFFFF"/><name val="Calibri"/></font>'
        '</fonts>'
        '<fills count="3">'
        '<fill><patternFill patternType="none"/></fill>'
        '<fill><patternFill patternType="gray125"/></fill>'
        '<fill><patternFill patternType="solid"><fgColor rgb="FF1F4E78"/><bgColor indexed="64"/></patternFill></fill>'
        '</fills>'
        '<borders count="2">'
        '<border><left/><right/><top/><bottom/><diagonal/></border>'
        '<border><left style="thin"/><right style="thin"/><top style="thin"/><bottom style="thin"/><diagonal/></border>'
        '</borders>'
        '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
        '<cellXfs count="2">'
        '<xf numFmtId="0" fontId="0" fillId="0" borderId="1" xfId="0"><alignment vertical="top" wrapText="1"/></xf>'
        '<xf numFmtId="0" fontId="1" fillId="2" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1"><alignment horizontal="center" vertical="center" wrapText="1"/></xf>'
        '</cellXfs>'
        '<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>'
        '</styleSheet>'
    )


def save_xlsx(sheets: List[Tuple[str, List[List[Any]]]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    sheet_names = [sheet_name_safe(name) for name, _ in sheets]

    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", content_types_xml(len(sheets)))
        z.writestr("_rels/.rels", root_rels_xml())
        z.writestr("xl/workbook.xml", workbook_xml(sheet_names))
        z.writestr("xl/_rels/workbook.xml.rels", workbook_rels_xml(len(sheets)))
        z.writestr("xl/styles.xml", styles_xml())

        for idx, (_, rows) in enumerate(sheets, start=1):
            z.writestr(f"xl/worksheets/sheet{idx}.xml", sheet_xml(rows, idx))


def main() -> None:
    family_registry_module, capability_registry_module, platform_command_matrix_module = load_core_modules()

    capability_registry = get_capability_registry(capability_registry_module)
    platform_matrix = get_platform_command_matrix(platform_command_matrix_module)
    platform_aliases = get_platform_aliases(platform_command_matrix_module)

    family_names = discover_family_names()
    platform_names = sorted(platform_matrix.keys())

    family_plans: Dict[str, Dict[str, Any]] = {}
    for family in family_names:
        family_result, capability_plan = build_family_plan(
            family_registry_module,
            capability_registry_module,
            family,
        )
        family_plans[family] = {
            "family_result": family_result,
            "capability_plan": capability_plan,
        }

    readme_rows = [
        ["项目", "内容"],
        ["导出时间", datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
        ["导出路径", str(OUTPUT_FILE)],
        ["说明", "本表基于当前 /opt/netaiops-webhook 最新代码动态导出。"],
        ["核心链路", "family_registry -> capability_registry -> platform_command_matrix -> execution_candidates"],
        ["Sheet说明", "告警家族能力：每类告警默认选择哪些 capability。"],
        ["Sheet说明", "能力注册表：每个 capability 的元数据。"],
        ["Sheet说明", "平台命令矩阵：每个平台下 capability 到命令模板的映射。"],
        ["Sheet说明", "家族平台命令：每类告警在不同平台上最终会渲染出的命令模板和示例命令。"],
        ["Sheet说明", "缺口和建议：当前平台命令覆盖缺口，后续可逐项修复。"],
    ]

    family_rows = [
        [
            "family",
            "target_kind",
            "auto_execute_allowed",
            "legacy_playbook_type",
            "plan_source",
            "order",
            "capability",
            "readonly",
            "judge_profile",
            "required_args",
            "arguments",
            "reason",
        ]
    ]

    for family in family_names:
        family_result = family_plans[family]["family_result"]
        capability_plan = family_plans[family]["capability_plan"]
        selected = capability_plan.get("selected_capabilities", []) or []

        if not selected:
            family_rows.append(
                [
                    family,
                    family_result.get("target_kind", ""),
                    family_result.get("auto_execute_allowed", ""),
                    family_result.get("legacy_playbook_type", ""),
                    capability_plan.get("plan_source", ""),
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    capability_plan.get("build_error") or family_result.get("classify_error") or "无默认 capability",
                ]
            )
            continue

        for idx, raw_item in enumerate(selected, start=1):
            item = normalize_capability_item(raw_item)
            cap = safe_text(item.get("capability"))
            meta = capability_registry.get(cap, {}) or {}

            family_rows.append(
                [
                    family,
                    family_result.get("target_kind", ""),
                    family_result.get("auto_execute_allowed", ""),
                    family_result.get("legacy_playbook_type", ""),
                    capability_plan.get("plan_source", ""),
                    item.get("order", idx),
                    cap,
                    item.get("readonly", get_meta_value(meta, "readonly", default="")),
                    item.get("judge_profile", get_meta_value(meta, "judge_profile", default="")),
                    safe_text(get_meta_value(meta, "required_args", default=item.get("required_args", ""))),
                    safe_text(item.get("arguments", "")),
                    safe_text(item.get("reason", "")),
                ]
            )

    capability_rows = [
        [
            "capability",
            "description",
            "readonly",
            "required_args",
            "judge_profile",
            "risk",
            "category",
            "tags",
            "raw_meta",
        ]
    ]

    for cap in sorted(capability_registry.keys()):
        meta = to_plain(capability_registry.get(cap, {}) or {})
        capability_rows.append(
            [
                cap,
                get_meta_value(meta, "description", "desc", "summary", default=""),
                get_meta_value(meta, "readonly", default=""),
                safe_text(get_meta_value(meta, "required_args", default="")),
                get_meta_value(meta, "judge_profile", default=""),
                get_meta_value(meta, "risk", default=""),
                get_meta_value(meta, "category", default=""),
                safe_text(get_meta_value(meta, "tags", default="")),
                safe_text(meta),
            ]
        )

    platform_rows = [
        [
            "platform",
            "capability",
            "command_template",
            "sample_command",
            "coverage",
        ]
    ]

    for platform in platform_names:
        command_map = platform_matrix.get(platform, {}) or {}
        for cap in sorted(command_map.keys()):
            template = safe_text(command_map.get(cap))
            platform_rows.append(
                [
                    platform,
                    cap,
                    template,
                    render_sample_command(template, DEFAULT_ARGS),
                    "covered",
                ]
            )

    family_platform_rows = [
        [
            "family",
            "platform",
            "order",
            "capability",
            "command_template",
            "sample_command",
            "readonly",
            "judge_profile",
            "required_args",
            "arguments",
            "coverage",
        ]
    ]

    gap_rows = [
        [
            "family",
            "platform",
            "capability",
            "gap_type",
            "suggested_action",
        ]
    ]

    for family in family_names:
        selected = family_plans[family]["capability_plan"].get("selected_capabilities", []) or []
        scoped_platforms = family_platform_scope(family, platform_names)

        for raw_item in selected:
            item = normalize_capability_item(raw_item)
            cap = safe_text(item.get("capability"))
            if not cap:
                continue

            meta = capability_registry.get(cap, {}) or {}
            arguments = SafeFormatDict(DEFAULT_ARGS)
            arguments.update({k: safe_text(v) for k, v in (item.get("arguments", {}) or {}).items() if safe_text(v)})

            for platform in scoped_platforms:
                command_map = platform_matrix.get(platform, {}) or {}
                template = safe_text(command_map.get(cap))
                coverage = "covered" if template else "missing"

                family_platform_rows.append(
                    [
                        family,
                        platform,
                        item.get("order", ""),
                        cap,
                        template,
                        render_sample_command(template, arguments) if template else "",
                        item.get("readonly", get_meta_value(meta, "readonly", default="")),
                        item.get("judge_profile", get_meta_value(meta, "judge_profile", default="")),
                        safe_text(get_meta_value(meta, "required_args", default=item.get("required_args", ""))),
                        safe_text(item.get("arguments", "")),
                        coverage,
                    ]
                )

                if not template:
                    gap_rows.append(
                        [
                            family,
                            platform,
                            cap,
                            "platform_command_missing",
                            f"在 netaiops/platform_command_matrix.py 中为 {platform}.{cap} 补充命令模板。",
                        ]
                    )

    if len(gap_rows) == 1:
        gap_rows.append(["无", "无", "无", "no_gap_detected", "当前已覆盖导出的 family/platform/capability 组合。"])

    alias_rows = [["alias", "platform"]]
    for alias, platform in sorted(platform_aliases.items()):
        alias_rows.append([alias, platform])

    sheets = [
        ("说明", readme_rows),
        ("告警家族能力", family_rows),
        ("能力注册表", capability_rows),
        ("平台命令矩阵", platform_rows),
        ("家族平台命令", family_platform_rows),
        ("缺口和建议", gap_rows),
        ("平台别名", alias_rows),
    ]

    save_xlsx(sheets, OUTPUT_FILE)

    print("EXPORT_XLSX_OK")
    print("output =", OUTPUT_FILE)
    print("family_count =", len(family_names))
    print("capability_count =", len(capability_registry))
    print("platform_count =", len(platform_names))
    print("family_platform_command_rows =", len(family_platform_rows) - 1)
    print("gap_count =", len(gap_rows) - 1)


if __name__ == "__main__":
    main()
