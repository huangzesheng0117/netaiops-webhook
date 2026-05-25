---
name: routing_neighbor_down
version: v6.3.0
family: routing_neighbor_down
description: Cisco routing neighbor down analysis skill for BGP, OSPF and BFD alerts.
risk_level: readonly
stage: v6.3
---

# routing_neighbor_down

## Scope

This Skill is generated from Cisco Prometheus rule semantics and is used for routing neighbor state alerts.

Covered alert names:

- BGP邻居状态
- OSPF邻居状态
- BFD邻居状态

## Investigation goal

Confirm whether the routing neighbor issue is still active, identify the affected protocol and peer, and correlate device CLI evidence with Prometheus alert windows and recent protocol logs.

## Protocol-specific focus

### BGP

Focus on:

- peer IP
- peer state
- established / idle / active / connect
- route count
- hold timer
- recent neighbor reset logs
- underlay or transport reachability

### OSPF

Focus on:

- neighbor ID
- interface
- area
- FULL / 2-Way / ExStart / Down state
- recent adjacency logs
- interface MTU, network type or authentication hints when available

### BFD

Focus on:

- BFD session state
- local and remote discriminator
- associated upper-layer protocol
- flap count or recent down logs
- transport path and peer reachability

## Runtime boundary

Only readonly tools are allowed. This Skill must not execute configuration, clearing, reload, delete, copy, commit or debug operations.

## Evidence expectation

The final review should clearly show:

- alert name and routing protocol
- device hostname and device IP
- peer IP or neighbor ID when available
- readonly MCP commands executed
- current neighbor state
- recent protocol logs
- Prometheus window state when available
- whether the issue is still active, recovered, transient, or inconclusive
- next recommended action
