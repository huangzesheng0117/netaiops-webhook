---
name: routing_neighbor_down
version: v6.4.0-bfd-enhanced
family: routing_neighbor_down
description: Enhanced Cisco routing neighbor down analysis skill for BGP, OSPF, ISIS and BFD alerts.
risk_level: readonly
stage: v8
---

# routing_neighbor_down

## Scope

This Skill handles routing neighbor abnormal alerts, especially:

- BGP neighbor down
- OSPF neighbor down
- ISIS adjacency abnormal
- BFD neighbor down

## BFD investigation goal

When a BFD Neighbor Down alert is received, the platform should not only check `show bfd neighbors`.
It should correlate:

1. BFD session state and down reason.
2. BFD clients and registered upper-layer protocols.
3. Route and ARP to the peer.
4. L3 interface, physical interface, errors, transceiver, port-channel and vPC evidence.
5. BGP/OSPF/ISIS upper-layer neighbor state.
6. Recent BFD/routing/interface logs.
7. Control-plane / CoPP / BFD redirect evidence when available.

## BFD analysis logic

- If BFD is still Down/AdminDown, treat the issue as active.
- If BFD is Up but recent logs show down/up, treat it as recovered or transient.
- If the carrying interface is down, flapping, or has CRC/error/discard growth, treat BFD down as a result of transport/interface issue.
- If route or ARP to the peer is missing, focus on basic L3 reachability before BFD itself.
- If Tx count increases but Rx count does not, suspect peer-side, ACL, path drop, or CoPP.
- If the down reason is `Control Detection Time Expired`, check packet loss, CoPP, ACL and overly aggressive timers.
- If the down reason is `Echo Function Failed`, check BFD echo, SVI/vPC path, asymmetric forwarding and platform limitations.
- If the down reason is `Neighbor Signaled Session Down`, prioritize peer-side checks.
- If BGP/OSPF/ISIS is also down, the routing control plane is impacted; if not, the BFD issue may be isolated or transient.

## Runtime boundary

Only readonly commands are allowed.

Forbidden operations include:

- configure terminal
- shutdown / no shutdown
- clear
- reload
- copy / delete / erase
- debug

## Notification expectation

The final review should include:

- affected device and peer
- BFD session state
- BFD down reason if available
- carrying interface status
- route / ARP to peer
- upper-layer protocol impact
- recent logs
- failed commands if any
- whether this is likely transport issue, peer-side issue, CoPP/ACL issue, echo/vPC limitation, configuration mismatch, transient recovery, or inconclusive


## BGP neighbor abnormal investigation

### Scope

This section handles BGP neighbor down, BGP peer abnormal, BGP flap and BGP Established-but-prefix-abnormal scenarios.

### First-wave investigation goal

The first wave must answer these questions:

1. Is the BGP peer Established, Idle, Active, Connect, OpenSent, OpenConfirm, or prefix-abnormal?
2. What is the Last reset reason?
3. Are there BGP/BFD/interface logs around the alert time?
4. Is BGP configuration consistent with expectation?
5. Is there a valid RIB/FIB path to the peer?
6. Is the outgoing interface healthy?
7. Is BFD directly triggering BGP down?
8. Are advertised/accepted routes abnormal?

### Default first-wave command count

The default BGP playbook executes no more than 15 readonly commands.

### Human-readable analysis expectations

Use the standard DingTalk notification template:

1. Initial judgement.
2. Alert meaning analysis.
3. Command execution overview. Only show total/success/failed command counts and list failed commands. Do not list all successful commands here.
4. Key evidence results. Each command should be explained as `command: human-readable finding`.
5. Process summary.
6. Suggestions.

Do not paste raw CLI output into DingTalk unless strictly necessary.

### Common judgement rules

- Idle / Active / Connect: check route to peer, source address, TCP/179, ACL/firewall and peer-side listener.
- OpenSent / OpenConfirm: check remote-as, router-id, password, capability, address-family and keepalive negotiation.
- Established with prefix 0 or missing routes: check address-family activation, route-map, prefix-list, filter-list, maximum-prefix, next-hop and advertised/received routes.
- Hold timer expired: check packet loss, interface errors, BFD, CPU/control-plane and peer-side health.
- BFD adjacency down: follow BFD evidence first.
- Wrong AS: remote-as mismatch or peer AS changed.
- BGP identifier wrong: router-id duplicate or invalid.
- Maximum-prefix exceeded: neighbor may have been automatically shut down.
- Interface flap or CRC/errors: BGP down is likely secondary to transport issue.
- RIB/FIB mismatch: check next-hop reachability, RIB failure and forwarding installation.

### Second-wave or manual checks

The following checks are useful but should not be in the default auto-executed first wave unless explicitly required:

- ping peer with expected source.
- telnet peer TCP/179.
- route-map / prefix-list / AS-path deep inspection.
- specific business prefix BGP/RIB/FIB consistency.
- CPU / memory / control-plane deep checks.

## DingTalk notification policy for routing neighbor alerts

Internal command orchestration may have discovery commands and optional follow-up commands.
However, the DingTalk message must present a unified analysis.

Do not expose these internal terms in DingTalk:

- 第一批
- 第二批
- 第一波
- 第二波
- stage-1
- stage-2

The final notification should use:

1. Initial judgement.
2. Alert meaning analysis.
3. Command execution overview.
4. Command analysis.
5. Overall execution judgement.
6. Suggestions.

For BGP alerts, do not assume the original alert always contains an interface.
If the alert only contains peer IP and VRF, use peer/VRF based evidence first.
If the interface can be inferred internally, merge interface evidence into the unified analysis.
If the interface cannot be uniquely inferred, state the uncertainty in the overall judgement.

## BGP physical-interface out-of-scope policy

For BGP neighbor abnormal alerts, the default auto-executed playbook does not run physical interface commands.

Excluded from the BGP default playbook:

- show interface <interface>
- show interface <interface> counters errors
- show running-config interface <interface>
- show port-channel summary
- optics / transceiver checks

Reason:

Physical interface down, CRC/error/discard, optic power and port-channel member failures are covered by dedicated physical-interface alert categories.
The BGP playbook should focus on BGP state, peer detail, reset reason, BGP/BFD logs, BGP configuration, RIB/FIB reachability, BFD trigger and route exchange.

DingTalk notification should not ask the BGP playbook to infer the physical interface by default.
If BGP evidence suggests a lower-layer issue, the message should recommend correlating with physical-interface alerts or running the dedicated interface playbook.
