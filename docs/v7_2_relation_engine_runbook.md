# NetAIOps webhook v7.2 Relation Engine Runbook

v7.2 基于 v7.1 incident_memory 构建告警关联关系，用于识别相似告警、重复告警、同一设备/接口/线路的反复问题。

## 安全边界

- 只读取 data/memory/incidents.jsonl。
- 不访问设备，不执行 MCP/Netmiko 命令。
- 不保存明文设备 IP，只使用 device_ip_hash。
- 结果写入 data/memory/incident_relations.json。

## 关联评分维度

- same_family
- same_hostname
- same_device_hash
- same_interface
- same_circuit_alias
- same_direction
- same_alarm_type
- same_alarm_bandwidth
- near_time_2h / near_time_24h / near_time_7d
- similar_utilization

## 常用命令

python tools/build_incident_memory.py --all --limit 100 --write

python tools/build_incident_relations.py --limit 100 --summary

python tools/query_incident_relations.py --min-score 60 --summary

python tools/query_incident_relations.py --rid <request_id> --summary

curl -s 'http://127.0.0.1:18080/v7/relations/incidents?limit=10&min_score=60' | python -m json.tool

curl -s 'http://127.0.0.1:18080/v7/relations/incidents/<request_id>' | python -m json.tool

## 验收标准

- data/memory/incident_relations.json 可生成。
- strong_recurrence 能识别同 family、同设备、同接口、同线路的重复告警。
- python -m unittest tests.test_relation_engine -v 通过。
- bash tools/regress_v7_2.sh 通过。
