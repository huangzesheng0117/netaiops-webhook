---
name: interface_down_or_oper_status
version: v9.1.0-cisco-interface-down
family: interface_down_or_oper_status
description: Cisco interface down or operational status abnormal analysis skill with Prometheus historical evidence and readonly CLI evidence.
risk_level: readonly
stage: v9
---

# interface_down_or_oper_status

## Scope

This Skill is used for Cisco interface Down, port Down and operational status abnormal alerts.

Covered examples:

- 非ACI端口状态
- Leaf-Spine互联端口状态
- BorderLeaf端口状态
- Spine端口状态
- 接口状态异常
- 端口状态异常
- 接口 Down / 端口 Down
- 互联网线路接口 Down / 互联网链路端口 Down

## Investigation goal

The goal is not to assume hardware failure immediately. The platform must first classify the interface state, then correlate Prometheus history and readonly device evidence.

The final judgement should answer:

1. Is the interface currently still down or abnormal?
2. Was the alert a sustained issue, a transient flap, or already recovered?
3. Is the state administratively down, physical down, protocol down, err-disabled, suspended/notconnect/inactive, or STP/VLAN related?
4. Is there evidence of optic, physical error, link flap, Port-channel/LACP/vPC, VLAN/STP, or module issue?
5. Which follow-up should be done manually?

## Overall logic

### 1. Confirm what kind of Down it is

Do not change configuration at this stage.

Classify the state:

| State | Meaning | Priority |
| --- | --- | --- |
| administratively down | manually shutdown or configuration disabled | check config and change record |
| down/down or notconnect | physical layer is not up | optic, fiber/cable, peer port, speed/FEC |
| up/down | physical layer up but protocol down | encapsulation, keepalive, L2/L3 mode, Port-channel, sub-interface |
| err-disabled | protection mechanism disabled the port | BPDU Guard, UDLD, link-flap, port-security, invalid gbic/sfp |
| suspended / inactive / individual | common on Nexus or bundle member | Port-channel, LACP, vPC, VLAN consistency |
| link-flap | repeated up/down | physical link, optic, peer, speed negotiation, STP/LACP |

### 2. Identify the interface type

Different interface types have different evidence priorities:

- Physical L3 interface: IP, carrier, speed/FEC, peer.
- Access port: VLAN, STP, err-disable, endpoint or downstream switch.
- Trunk port: trunk state, allowed VLAN, native VLAN, STP, peer trunk.
- Port-channel member: LACP/PAgP, member consistency, speed, trunk, vPC.
- SVI/Vlan interface: VLAN existence, active member and autostate.
- Sub-interface: parent state and encapsulation.
- Optical port: transceiver present, Rx/Tx power, DOM alarms, fiber and peer optics.
- Nexus fabric/FEX/vPC port: vPC, FEX, fabric uplink and pinning.

### 3. Classify the failure direction

| Direction | Evidence |
| --- | --- |
| administrative shutdown | admin down, running-config contains shutdown |
| physical layer | down/down, notconnect, no light, CRC/FCS, optic abnormal |
| peer side | local no receive light, expected peer port down/shutdown/misconfigured |
| err-disable | err-disabled status and reason |
| speed/FEC/duplex | speed mismatch, negotiation failure, FEC mismatch |
| Port-channel/LACP | member suspended, individual, not bundled |
| vPC | vPC consistency, peer-link or member issue |
| VLAN/STP | VLAN missing, blocked, BPDU Guard, Root Guard, Loop Guard |
| link flap | logs show repeated up/down, carrier transition increases |
| hardware/module | transceiver absent/unsupported, DOM alarms, linecard/module alarm |

## Prometheus evidence requirement

For interface Down/status alerts, Prometheus evidence is mandatory when labels are available.

The preferred profile is `interface_down_status`.

Required labels:

- device_ip
- if_name / interface / ifName

Query intent:

- `oper_status`: historical ifOperStatus window, used to decide whether the port was continuously down, flapped, recovered, or has no data.
- `in_bps` / `out_bps`: traffic trend before and after alert, used to detect whether business traffic really disappeared.
- `in_errors_delta`: error trend during the window, used as supporting physical-layer evidence.

Prometheus failure must not block CLI evidence. If Prometheus has no data, the notification must clearly state the reason and conclusion boundary.

## First-wave command policy

The default Cisco playbook uses no more than 14 readonly commands. It is optimized for Nexus/NX-OS production simulation objects.

The first wave should quickly classify the issue. Do not run every second-level command automatically.

Default exclusions:

- Do not run `show version` by default.
- Do not run CDP and LLDP together by default.
- Do not run deep LACP/vPC consistency commands by default.
- Do not run peer-side commands automatically.
- Do not run any recovery or configuration command.

Useful manual follow-ups when needed:

- CDP/LLDP neighbor detail to confirm peer.
- LACP neighbor and vPC consistency when bundle/vPC issue is suspected.
- Peer-side interface check.
- FEC/speed/platform-specific transceiver compatibility checks.

## Runtime boundary

Only readonly commands are allowed.

Forbidden operations include:

- configure terminal / conf t
- interface configuration
- shutdown / no shutdown
- clear
- reload / reboot / reset
- copy / write / save
- delete / erase / format
- debug

## DingTalk notification expectation

Use the v8 standard DingTalk template.

The final notification should include:

1. Initial judgement based on alert object and Prometheus window.
2. Alert meaning analysis.
3. Command execution overview: total/success/failed, successful command list and failed command list.
4. Command analysis: aggregate findings by state/config/log/error/optic/VLAN/STP/Port-channel/vPC/module dimensions.
5. Overall execution judgement: active, recovered/transient, physical suspected, config/admin suspected, bundle/vPC suspected, VLAN/STP suspected, or inconclusive.
6. Suggestions: manual follow-up steps.

Do not expose internal orchestration wording in DingTalk:

- 第一批
- 第二批
- 第一波
- 第二波
- stage-1
- stage-2

Do not paste large raw CLI output unless strictly necessary.
