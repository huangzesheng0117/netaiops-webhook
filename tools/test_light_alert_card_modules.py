import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from netaiops.light_alert_formatter import build_light_notifications
from netaiops.dongdong_card_sender import (
    build_universal_card_payload,
    load_card_config,
    redacted_config,
)


def assert_contains(text: str, expected: str) -> None:
    if expected not in text:
        raise AssertionError(f"missing {expected!r} in:\n{text}")


def main() -> None:
    payload = {
        "status": "firing",
        "commonLabels": {
            "group": "netdev",
            "severity": "critical",
        },
        "alerts": [
            {
                "status": "firing",
                "labels": {
                    "alertname": "F5活跃连接数突增",
                    "ip": "10.187.251.97",
                    "sysName": "SH8-F5-LTM01",
                },
                "annotations": {
                    "description": "F5活跃连接数突增测试",
                    "value_name": "当前活跃连接数",
                    "current_value": "100001",
                    "value_unit": "",
                    "for_duration": "0m",
                },
            },
            {
                "status": "firing",
                "labels": {
                    "alertname": "SH8-GDS利用率-入向",
                    "sysName": "SH8-Internet-SW01",
                },
                "annotations": {
                    "description": "SH8互联网线路_GDS_300M_入向利用率超过80%",
                    "direction": "入向",
                    "device_ip": "10.192.251.95",
                    "interfaces": "Te1/0/1, Te2/0/1",
                    "bandwidth_mbps": "300",
                    "value_name": "当前流量",
                    "current_value": "256.32",
                    "value_unit": "Mbps",
                    "for_duration": "0m",
                },
            },
            {
                "status": "resolved",
                "labels": {
                    "alertname": "BGP邻居状态",
                    "ip": "10.187.251.97",
                    "bgpPeerRemoteAddr": "10.1.1.1",
                },
                "annotations": {
                    "description": "思科交换机BGP邻居状态异常",
                    "object_label": "邻居地址",
                    "object_label_key": "bgpPeerRemoteAddr",
                    "for_duration": "1m",
                },
            },
            {
                "status": "pending",
                "labels": {
                    "alertname": "pending测试",
                    "ip": "10.1.1.1",
                },
                "annotations": {
                    "description": "pending测试不发送",
                    "for_duration": "1m",
                },
            },
        ],
    }

    result = build_light_notifications(payload)
    assert result["alert_count"] == 4
    assert result["notification_count"] == 3
    assert result["skipped_count"] == 1

    first = result["notifications"][0]
    assert first["title"] == "[network][告警] F5活跃连接数突增"
    assert_contains(first["detail"], "告警状态: firing")
    assert_contains(first["detail"], "告警描述: F5活跃连接数突增测试")
    assert_contains(first["detail"], "设备IP: 10.187.251.97")
    assert_contains(first["detail"], "设备名称: SH8-F5-LTM01")
    assert_contains(first["detail"], "当前活跃连接数: 100001")
    assert_contains(first["detail"], "持续时间: 0m")

    second = result["notifications"][1]
    assert_contains(second["detail"], "方向: 入向")
    assert_contains(second["detail"], "设备IP: 10.192.251.95")
    assert_contains(second["detail"], "接口: Te1/0/1, Te2/0/1")
    assert_contains(second["detail"], "链路带宽: 300 Mbps")
    assert_contains(second["detail"], "当前流量: 256.32 Mbps")

    third = result["notifications"][2]
    assert third["title"] == "[network][恢复] BGP邻居状态"
    assert_contains(third["detail"], "邻居地址: 10.1.1.1")

    cfg = load_card_config()
    redacted = redacted_config(cfg)
    assert redacted["service_token"] == "***REDACTED***"
    assert redacted["appid"] == "D619"
    assert redacted["group_id"] == "62800"

    card_payload = build_universal_card_payload(first["title"], first["detail"], cfg)
    detail = json.loads(card_payload["detail"])
    elements = detail.get("elements", [])

    assert card_payload["msgType"] == "universalCard"
    assert card_payload["toGroupId"] == "62800"
    assert card_payload["cardType"] == "networkAlertCard"
    assert detail["header"]["template"] == cfg.card_template
    assert "cardType" not in detail["config"]
    assert len(elements) >= 5

    first_element = elements[0]
    assert first_element["tag"] == "div"
    assert "fields" in first_element
    assert "text" not in first_element
    assert len(first_element["fields"]) == 1

    first_text = first_element["fields"][0]["text"]
    assert first_text["tag"] == "plain_text"
    assert first_text["prefix"] == "告警状态："
    assert first_text["content"] == "firing"
    assert first_text["type"] == "detail"
    assert first_text["max_lines"] == 1

    assert all(item.get("tag") == "div" for item in elements)
    assert all("fields" in item and len(item["fields"]) == 1 for item in elements)
    assert all((item["fields"][0]["text"]["tag"] == "plain_text") for item in elements)

    print("[OK] light alert formatter + Gatus-compatible dongdong card sender tests passed")
    print("----- redacted config -----")
    print(json.dumps(redacted, ensure_ascii=False, indent=2))
    print("----- sample title -----")
    print(first["title"])
    print("----- sample detail -----")
    print(first["detail"])
    print("----- sample card detail structure -----")
    print(json.dumps({
        "config": detail.get("config"),
        "header": detail.get("header"),
        "elements_count": len(elements),
        "first_element": first_element,
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
