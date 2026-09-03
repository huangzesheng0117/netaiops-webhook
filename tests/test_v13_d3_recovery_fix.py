from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from netaiops.v13.d3_recovery_canary import (
    D3RecoveryCanaryError,
    validate_original_failed_attempt,
)
from netaiops.v13.real_owner_adapters import (
    D3RealAdapterError,
    bind_d3_netmiko_helper,
    d3_netmiko_runtime_contract,
    resolve_d3_netmiko_helper,
)


class D3RuntimeRecoveryFixTests(unittest.TestCase):
    def _helper(self, root: Path) -> Path:
        path = root / "bridge_helper.py"
        path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
        return path

    def test_service_helper_is_bound_when_shell_is_missing(self):
        with tempfile.TemporaryDirectory() as td:
            helper = self._helper(Path(td))
            old = os.environ.pop("MCP_HELPER_CMD", None)
            try:
                with patch(
                    "netaiops.v13.real_owner_adapters._systemd_service_environment",
                    return_value={"MCP_HELPER_CMD": str(helper)},
                ):
                    with bind_d3_netmiko_helper() as bound:
                        self.assertEqual(bound, helper.resolve())
                        self.assertEqual(os.environ.get("MCP_HELPER_CMD"), str(helper.resolve()))
                    self.assertIsNone(os.environ.get("MCP_HELPER_CMD"))
            finally:
                if old is not None:
                    os.environ["MCP_HELPER_CMD"] = old

    def test_service_helper_is_authoritative_over_shell(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "svc").mkdir()
            service_helper = self._helper(root / "svc")
            (root / "shell").mkdir()
            shell_helper = self._helper(root / "shell")
            old = os.environ.get("MCP_HELPER_CMD")
            os.environ["MCP_HELPER_CMD"] = str(shell_helper)
            try:
                with patch(
                    "netaiops.v13.real_owner_adapters._systemd_service_environment",
                    return_value={"MCP_HELPER_CMD": str(service_helper)},
                ):
                    self.assertEqual(resolve_d3_netmiko_helper(), service_helper.resolve())
            finally:
                if old is None:
                    os.environ.pop("MCP_HELPER_CMD", None)
                else:
                    os.environ["MCP_HELPER_CMD"] = old

    def test_missing_helper_is_blocked(self):
        old = os.environ.pop("MCP_HELPER_CMD", None)
        try:
            with patch(
                "netaiops.v13.real_owner_adapters._systemd_service_environment",
                return_value={},
            ):
                with self.assertRaises(D3RealAdapterError):
                    resolve_d3_netmiko_helper()
        finally:
            if old is not None:
                os.environ["MCP_HELPER_CMD"] = old

    def test_non_executable_helper_is_blocked(self):
        with tempfile.TemporaryDirectory() as td:
            helper = Path(td) / "helper.py"
            helper.write_text("print('x')\n", encoding="utf-8")
            helper.chmod(stat.S_IRUSR | stat.S_IWUSR)
            with patch(
                "netaiops.v13.real_owner_adapters._systemd_service_environment",
                return_value={"MCP_HELPER_CMD": str(helper)},
            ):
                with self.assertRaises(D3RealAdapterError):
                    resolve_d3_netmiko_helper()

    def test_runtime_contract_reports_sha_without_executing_helper(self):
        with tempfile.TemporaryDirectory() as td:
            helper = self._helper(Path(td))
            with patch(
                "netaiops.v13.real_owner_adapters._systemd_service_environment",
                return_value={"MCP_HELPER_CMD": str(helper)},
            ):
                contract = d3_netmiko_runtime_contract()
            self.assertTrue(contract["helper_exists"])
            self.assertTrue(contract["helper_executable"])
            self.assertEqual(len(contract["helper_sha256"]), 64)

    def test_original_failed_attempt_binding(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            family = "interface_status_or_flap"
            rid = "v13d3-test-original"
            state = root / "data/v13/d3_canary_state" / f"{family}.json"
            state.parent.mkdir(parents=True)
            state.write_text(json.dumps({
                "family": family,
                "request_id": rid,
                "state": "failed_or_ambiguous",
                "automatic_retry_allowed": False,
            }), encoding="utf-8")
            cp = root / "data/v13/capability_checkpoints" / rid
            cp.mkdir(parents=True)
            (cp / "m.json").write_text(json.dumps({
                "source": "metrics", "status": "success", "attempts": 1,
                "terminal": True, "envelope": {"status": "success", "facts": {"prometheus_mcp_called": True}},
            }), encoding="utf-8")
            (cp / "d.json").write_text(json.dumps({
                "source": "device", "status": "failed", "attempts": 1,
                "terminal": True, "envelope": {"status": "failed", "reason": "netmiko_mcp_command_failed", "facts": {"netmiko_mcp_called": True}},
            }), encoding="utf-8")
            fr = root / "data/evidence_hub/requests" / rid / "v13"
            fr.mkdir(parents=True)
            for source in ("metrics", "device"):
                (fr / f"{source}_owner_fence.json").write_text(json.dumps({
                    "active": True,
                    "external_call_already_attempted": True,
                    "legacy_action": "skip_duplicate",
                }), encoding="utf-8")
            result = validate_original_failed_attempt(root, family)
            self.assertEqual(result["original_request_id"], rid)
            self.assertEqual(result["metrics_status"], "success")
            self.assertEqual(result["device_status"], "failed")

    def test_original_success_state_cannot_be_recovery_source(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            family = "interface_status_or_flap"
            state = root / "data/v13/d3_canary_state" / f"{family}.json"
            state.parent.mkdir(parents=True)
            state.write_text(json.dumps({
                "family": family,
                "request_id": "v13d3-test",
                "state": "sentinel_completed",
                "automatic_retry_allowed": False,
            }), encoding="utf-8")
            with self.assertRaises(D3RecoveryCanaryError):
                validate_original_failed_attempt(root, family)


if __name__ == "__main__":
    unittest.main()
