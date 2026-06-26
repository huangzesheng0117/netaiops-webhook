import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import json
import sys
from pathlib import Path

from netaiops.light_alert_formatter import build_light_notifications
from netaiops.dongdong_card_sender import build_universal_card_payload, load_card_config


def main() -> None:
    if len(sys.argv) != 2:
        print("usage: python tools/preview_light_alert_card.py <alertmanager_payload.json>")
        raise SystemExit(2)

    payload_file = Path(sys.argv[1])
    payload = json.loads(payload_file.read_text(encoding="utf-8"))
    result = build_light_notifications(payload)
    cfg = load_card_config()

    print(json.dumps({
        "lite_request_id": result["lite_request_id"],
        "alert_count": result["alert_count"],
        "notification_count": result["notification_count"],
        "skipped_count": result["skipped_count"],
        "skipped": result["skipped"],
    }, ensure_ascii=False, indent=2))

    for item in result["notifications"]:
        card_payload = build_universal_card_payload(item["title"], item["detail"], cfg)
        detail = json.loads(card_payload["detail"])

        print("\n" + "=" * 80)
        print(item["title"])
        print()
        print(item["detail"])
        print()
        print("card_payload_preview:")
        print(json.dumps({
            "appId": card_payload.get("appId"),
            "toGroupId": card_payload.get("toGroupId"),
            "msgType": card_payload.get("msgType"),
            "cardType": card_payload.get("cardType"),
            "detail_header": detail.get("header"),
            "detail_elements_count": len(detail.get("elements", [])),
        }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
