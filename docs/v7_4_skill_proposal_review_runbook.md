# NetAIOps webhook v7.4 Skill Proposal Review Gate Runbook

v7.4 为 v7.3 生成的 Skill Proposal 增加人工复核门控。

## 定位

- v7.3 只生成候选 proposal。
- v7.4 记录人工 review 决策。
- v7.4 不自动创建正式 Skill，不写入 skills/ 目录。

## 允许的决策

- approve：通过，允许后续进入 Skill 草稿阶段。
- reject：拒绝，不再继续。
- defer：暂缓观察。
- needs_more_evidence：证据不足，需要补充样例或事实。

## 常用命令

python tools/review_skill_proposal.py --pending --min-score 50

python tools/review_skill_proposal.py --proposal-id <proposal_id>

python tools/review_skill_proposal.py --proposal-id <proposal_id> --decision approve --reviewer hzs --comment "approve for draft"

python tools/review_skill_proposal.py --reviews --proposal-id <proposal_id>

python tools/review_skill_proposal.py --summary

## 安全边界

- 只写 data/skill_proposal_reviews。
- 不写 skills/。
- 不执行 MCP/Netmiko。
- 不自动 merge。
