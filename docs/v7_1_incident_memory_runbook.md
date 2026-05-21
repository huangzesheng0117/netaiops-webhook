# NetAIOps webhook v7.1 Incident Memory Runbook

v7.1 是 Hermes-style Learning Ops 的第一步：从既有 request_id 产物中抽取长期 incident_memory，用于后续 relation_engine、skill proposal 和 learning report。

## 安全边界

- 不影响 v5/v6 生产主链路。
- 不执行任何设备命令。
- 不保存明文设备 IP、密码、Token、Webhook Secret、MCP Server URL 或完整 inventory。
- 设备 IP 只保存 device_ip_hash。

## 常用命令

python tools/build_incident_memory.py --rid <request_id> --write

python tools/build_incident_memory.py --all --limit 100 --write

python tools/query_incident_memory.py --family interface_or_link_utilization_high --limit 20 --summary

curl -s 'http://127.0.0.1:18080/v7/memory/incidents?limit=20' | python -m json.tool

curl -s 'http://127.0.0.1:18080/v7/memory/incidents/<request_id>' | python -m json.tool

## 验收标准

- data/memory/incidents.jsonl 可生成。
- 单条 memory 不包含明文 IPv4 和敏感关键词。
- 可按 family、hostname、interface 查询。
- python -m unittest tests.test_memory_store -v 通过。
