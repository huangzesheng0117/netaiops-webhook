# NetAIOps Webhook v8 Prometheus MCP Release Notes

## 版本定位

v8 的核心目标是为 NetAIOps Webhook 增加 Prometheus 历史指标证据能力，使平台不只依赖设备当前 show 命令，还可以通过 Prometheus query_range 获取告警时间窗口内的趋势数据。

## 核心能力

- 新增 Prometheus MCP Bridge。
- 新增 Prometheus HTTP API fallback。
- 新增 Prometheus metric mapping。
- 新增 Prometheus window analyzer。
- 新增 Prometheus evidence v8 统一入口。
- 新增 Prometheus runtime sidecar。
- playbook 支持 prometheus_evidence_first 元数据。
- plan / pipeline / review / notification 主链路接入 Prometheus evidence。
- 咚咚通知展示 Prometheus窗口证据。
- 支持真实 Alertmanager 仿真告警端到端验证。

## 当前已验证场景

### Cisco 接口流量突降 / 突增 / 利用率类

当前流量类 PromQL 使用 1min 精度：

rate(ifHCInOctets{ip="<device_ip>", ifName="<if_name>"}[1m]) * 8
rate(ifHCOutOctets{ip="<device_ip>", ifName="<if_name>"}[1m]) * 8

说明：

- 现网 SNMP 采集频率为 1min，因此 PromQL rate window 使用 [1m]。
- 查询 step 为 60s。
- 默认查询窗口为过去 15 分钟。
- 默认对比值为当前采样点向前偏移 5 分钟后最接近的采样点。
- 流量类告警不再默认查询 oper_status。
- oper_status 只应在接口状态 down/up 类告警中使用。

## 当前生产验证结论

- webhook 服务健康检查正常。
- Prometheus MCP 查询链路正常。
- Prometheus evidence 可落盘到 data/prometheus_evidence/。
- 咚咚通知可以展示 Prometheus窗口证据。
- 已通过 V8 仿真告警验证 Alertmanager -> Webhook -> Prometheus MCP -> Review -> Notification 链路。

## 安全与兼容策略

- Prometheus 查询失败不得阻断原有 CLI 取证链路。
- HTTP API fallback 作为 Prometheus MCP 不可用时的兜底路径。
- runtime sidecar 只对声明 prometheus_evidence_first.enabled=true 的 playbook 生效。
- 敏感配置、runtime 数据、日志、备份目录不得提交到 GitHub。

## 后续建议

- 继续扩展接口错包 / 丢包 / CRC 的 Prometheus 增量证据。
- 继续扩展 F5 / FortiGate / Hillstone 会话数、连接数、CPU、内存类 Prometheus 证据。
- 后续可增加 Grafana dashboard deeplink，便于值班人员从咚咚跳转查看曲线。
