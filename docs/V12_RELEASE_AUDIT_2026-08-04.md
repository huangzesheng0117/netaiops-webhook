# NetAIOps Webhook v12 Release Audit

> 生成时间：2026-08-04T08:40:03.880590+00:00
> Release Audit：PASS

## 发布基线

```text
version=12.0.0-v12-controlled-multi-agent
mode=primary
fail_open_to_legacy=true
notifications_use_v12=false
logs_enabled=false
knowledge_enabled=false
```

## Primary Family

```text
interface_status_or_flap
interface_or_link_utilization_high
interface_traffic_anomaly
```

其他 Family 固定 fallback legacy。

## 测试

```text
all_v12_tests=818
all_v12_returncode=0
full_repository_tests=1367
full_repository_returncode=0
historical_failures=0
new_failures=0
```

## 运行时入口

```text
/health=200
/evidence?limit=1=200
/evidence-ui=200
/governance/health=200
/governance-ui=200
/agent/health=200
/agent-ui=200
```

## 外部调用与通知边界

```text
Release Audit synthetic GLM calls=0
Release Audit synthetic Prometheus MCP calls=0
Release Audit synthetic Netmiko MCP calls=0
Release Audit synthetic notifications=0
Evidence MCP calls=0
OPS ES API calls=0
Analytics MCP calls=0
FastMCP calls=0

Approved primary request budget:
Prometheus MCP<=1
Netmiko MCP<=1
GLM RCA<=1
v12 notification=0
```

## 审计结果

```text
problems=[]
warnings=[]
release_audit=PASS
```
