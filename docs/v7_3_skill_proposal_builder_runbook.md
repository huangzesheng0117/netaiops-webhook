# NetAIOps webhook v7.3 Skill Proposal Builder Runbook

v7.3 基于 v7.1 incident_memory 和 v7.2 relation_engine 自动生成候选 Skill Proposal。

## 定位

v7.3 不生成正式 Skill，不修改 skills/ 目录，不改变生产执行链路。它只回答一个问题：

某一类重复告警/重复经验，是否值得被沉淀为新 Skill 或既有 Skill 的增强项？

## 复用价值评分维度

- recurrence：同一签名重复出现次数
- execution_quality：历史取证命令完成质量
- parser_coverage：是否已有结构化 parsed facts
- business_signal：是否存在明确业务阈值或高利用率信号
- specificity：family、设备、接口、线路、方向是否足够具体
- novelty：是否已有相关 Skill，决定新增或增强

## 安全边界

- 只读取 incident_memory 和 relation_graph。
- 不执行 MCP/Netmiko。
- 不保存明文设备 IP、密码、Token。
- 生成的 proposal 必须 manual_review_required=true。
- auto_merge_enabled 必须为 false。
- writes_formal_skill 必须为 false。

## 常用命令

python tools/build_skill_proposals.py --summary --validate-safety

python tools/query_skill_proposals.py --summary --min-score 60

python tools/query_skill_proposals.py --proposal-id <proposal_id> --validate-safety

curl -s 'http://127.0.0.1:18080/v7/skill-proposals?limit=10&min_score=60' | python -m json.tool

curl -s -X POST 'http://127.0.0.1:18080/v7/skill-proposals/rebuild?limit_clusters=20' | python -m json.tool

curl -s 'http://127.0.0.1:18080/v7/skill-proposals/<proposal_id>' | python -m json.tool

## 验收标准

- data/skill_proposals/proposals.jsonl 可生成。
- 至少可以从重复告警 cluster 生成 draft_review_required proposal。
- proposal 不包含明文 IPv4 和敏感关键词。
- 不会自动写入 skills/ 正式目录。
- bash tools/regress_v7_3.sh 通过。
