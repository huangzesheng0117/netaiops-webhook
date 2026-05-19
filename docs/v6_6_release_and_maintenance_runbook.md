# NetAIOps webhook v6.6 发布与维护收尾手册

## 1. 阶段定位

当前阶段：v6.6。

v6.6 的目标是固化 v6.1 到 v6.5 的回归、发布、回滚和维护体系。

v6.6 不新增生产执行能力，不改变 MCP 主执行链路，不启用自适应取证真实执行。

## 2. v6 当前能力边界

v6 当前已经完成以下阶段：

- v6.1：Investigation Session 与受控调查状态机
- v6.2：Tool / Parser 体系
- v6.3：NetAIOps Skill 库
- v6.4：Skill Runtime 渐进加载
- v6.5：Skill 约束下的自适应取证 dry-run
- v6.6：回归、发布和维护体系固化

当前 v6.5 adaptive evidence 仍是 dry-run：

    dispatch_enabled: false
    adaptive_execution_enabled: false
    dry_run_only: true
    readonly_only: true

## 3. 全量回归入口

执行 v6 全量回归：

    cd /opt/netaiops-webhook
    source venv/bin/activate
    bash tools/regress_v6_all.sh

指定 request_id：

    RID=<request_id> bash tools/regress_v6_all.sh

全量回归会依次执行：

- compileall
- v6 release precheck
- v6.1 regression
- v6.2 regression
- v6.3 regression
- v6.4 regression
- v6.5 regression
- /health 检查
- 生成 docs/v6_6_release_snapshot.json

## 4. 发布前检查

发布前执行：

    python tools/v6_release_precheck.py --rid <request_id>

生成快照：

    python tools/v6_release_precheck.py --rid <request_id> --write docs/v6_6_release_snapshot.json

必须满足：

    verdict: pass
    violations: []
    health.ok: true

允许存在：

    git working tree has uncommitted changes

因为当前 v6 改造阶段尚未统一提交 Git。

## 5. 验收关键词

v6.6 第一批验收时重点看：

    Ran 86 tests
    OK

    "verdict": "pass"
    "stage": "v6.6"
    "violations": []

    v6.1 regression PASS
    v6.2 regression PASS
    v6.3 regression PASS
    v6.4 regression PASS
    v6.5 regression PASS

    v6.6 all regression PASS
    status: ok

## 6. 回滚建议

如果 v6.6 后续发布前发现异常，优先使用以下策略：

1. 不提交当前工作区。
2. 使用 backup/ 中对应时间戳文件恢复单个文件。
3. 如果需要整体回退，使用 Git 当前 main 分支作为基线。
4. 恢复后执行：

       python -m compileall -q app.py netaiops tools tests agent_runner
       curl -sf http://127.0.0.1:18080/health | python -m json.tool
       bash tools/regress_v6_5.sh

5. 确认服务正常后再继续处理。

## 7. 生产维护注意事项

当前 v6 的新增能力以旁路审计、结构化解析、Skill 约束和 dry-run 规划为主。

生产维护时重点关注：

- /health 是否正常
- v6 investigation API 是否能返回 session
- execution 文件是否仍能 parsed
- evidence_facts 是否 parsed-first
- skill binding 是否 violations=[]
- adaptive plan 是否 dispatch_enabled=false
- adaptive API 是否只返回 dry-run plan
- data/、logs/、backup/、config.yaml、venv/ 等敏感或运行时目录不要提交 Git

## 8. 下一批建议

v6.6 第二批建议做：

- 生成 v6 release notes
- 生成 Git 提交前 diff 审计脚本
- 检查 .gitignore 是否覆盖运行时与敏感文件
- 输出最终提交建议
