from pathlib import Path
from typing import Any, Dict

import yaml


BASE_DIR = Path("/opt/netaiops-webhook")
CONFIG_FILE = BASE_DIR / "config.yaml"


def load_config() -> Dict[str, Any]:
    if not CONFIG_FILE.exists():
        return {}
    with open(CONFIG_FILE, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def get_external_base_url() -> str:
    cfg = load_config()
    return str(cfg.get("external_base_url", "http://127.0.0.1:18080")).rstrip("/")


def get_notify_config() -> Dict[str, Any]:
    cfg = load_config()
    return cfg.get("notify", {}) or {}


def get_notify_settings() -> dict:
    return get_notify_config()
