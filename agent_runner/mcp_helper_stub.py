#!/opt/netaiops-webhook/venv/bin/python
import json
import sys

payload = json.load(sys.stdin)

device_name = payload.get("device_name", "")
command = payload.get("command", "")
tool_name = payload.get("tool_name", "")

print(
    json.dumps(
        {
            "ok": True,
            "tool_name": tool_name,
            "device_name": device_name,
            "command": command,
            "output": f"[MCP HELPER STUB] {tool_name} on {device_name}: {command}",
        },
        ensure_ascii=False,
    )
)
