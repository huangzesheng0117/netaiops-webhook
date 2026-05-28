---
name: cisco_device_reachability_down
version: v6.3.0
family: cisco_device_reachability_down
description: Cisco device up metric abnormal analysis with ping, SSH and health inspection sequence.
risk_level: readonly
stage: v6.3
---

# cisco_device_reachability_down

## Scope

This Skill handles Prometheus `up` reachability alerts for Cisco devices.

## Mandatory diagnosis sequence

1. First check whether the management IP is reachable by ping from the NetAIOps execution side.
2. If ping fails, stop device-side CLI analysis and conclude that the device may be powered off, crashed, management path interrupted, HA switched, or monitoring path interrupted.
3. If ping succeeds, attempt SSH login.
4. If SSH login fails, stop deeper CLI analysis and conclude that the device management plane, AAA, SSH service, access policy, or high CPU/memory pressure may be abnormal.
5. Only if SSH login succeeds, run a lightweight readonly health inspection.

## Lightweight health inspection focus

- CPU and memory pressure
- management interface state
- recent management, login, reload, up/down, CPU or memory logs
- HA / cluster state when applicable
- routing protocol state when applicable
- Prometheus up metric and scrape window

## Runtime boundary

Only readonly evidence collection is allowed. Do not execute config, set, clear, delete, reboot, shutdown, reload, save, commit, debug-enable or other state-changing operations.

## Output requirement

The final review must explicitly show:

- management IP ping result
- SSH login result
- whether analysis stopped early because ping or SSH failed
- CPU / memory / management interface / HA / routing / log evidence if SSH succeeded
- current judgement: device down, management path issue, SSH/management-plane issue, recovered, transient, or inconclusive
