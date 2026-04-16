#!/opt/netaiops-webhook/venv/bin/python
import json
import sys

payload = json.load(sys.stdin)
command = payload.get("command", "")
target_scope = payload.get("target_scope", {}) or {}
device_ip = target_scope.get("device_ip", "")
hostname = target_scope.get("hostname", "")

print(
    json.dumps(
        {
            "ok": True,
            "device_ip": device_ip,
            "hostname": hostname,
            "command": command,
            "output": f"[MCP WRAPPER STUB] executed on {hostname or device_ip}: {command}",
        },
        ensure_ascii=False,
    )
)
