#!/opt/netaiops-webhook/venv/bin/python
# -*- coding: utf-8 -*-

import json
import os
import subprocess
import sys
from pathlib import Path


def build_helper_cmd():
    helper_cmd = os.getenv("MCP_HELPER_CMD", "").strip()
    if not helper_cmd:
        raise RuntimeError("MCP_HELPER_CMD is not set")

    helper_path = Path(helper_cmd)
    if helper_path.exists():
        if os.access(str(helper_path), os.X_OK):
            return [str(helper_path)]
        return [sys.executable, str(helper_path)]

    return [helper_cmd]


def main():
    payload = json.load(sys.stdin)
    helper_cmd = build_helper_cmd()

    proc = subprocess.run(
        helper_cmd,
        input=json.dumps(payload, ensure_ascii=False),
        text=True,
        capture_output=True,
        timeout=int(os.getenv("MCP_TIMEOUT", "60")),
    )

    stdout = (proc.stdout or "").strip()
    stderr = (proc.stderr or "").strip()

    if proc.returncode != 0:
        print(
            json.dumps(
                {
                    "ok": False,
                    "error": f"helper returncode={proc.returncode}",
                    "stderr": stderr,
                    "stdout": stdout,
                },
                ensure_ascii=False,
            )
        )
        sys.exit(proc.returncode or 1)

    try:
        helper_result = json.loads(stdout) if stdout else {}
    except Exception:
        print(
            json.dumps(
                {
                    "ok": False,
                    "error": "helper output is not valid json",
                    "stdout": stdout,
                },
                ensure_ascii=False,
            )
        )
        sys.exit(2)

    print(json.dumps(helper_result, ensure_ascii=False))

    if not helper_result.get("ok", False):
        sys.exit(2)

    sys.exit(0)


if __name__ == "__main__":
    main()
