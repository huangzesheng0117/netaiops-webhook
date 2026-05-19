# NetAIOps webhook v6 提交前检查清单

## 1. 必须通过的回归

提交前必须执行：

```bash
cd /opt/netaiops-webhook
source venv/bin/activate
bash tools/regress_v6_all.sh
```

必须看到：

```text
v6.1 regression PASS
v6.2 regression PASS
v6.3 regression PASS
v6.4 regression PASS
v6.5 regression PASS
v6.6 all regression PASS
```

## 2. 必须通过的 Git 审计

执行：

```bash
python tools/v6_git_audit.py --write docs/v6_6_git_audit_report.json
```

必须看到：

```text
"verdict": "pass"
"violations": []
```

## 3. 不应提交的内容

不得提交以下内容：

- config.yaml
- data/
- logs/
- backup/
- venv/
- .env
- 设备账号密码
- API Key
- Webhook Secret
- MCP Server URL
- Prometheus 真实地址
- 设备 inventory 明细
- UCS、zip、tar.gz 等备份包

## 4. 允许存在的 warning

允许存在：

```text
git working tree has uncommitted changes
```

因为最终提交前本来就会存在大量新增文件。

也允许存在 Skill Binding 文本扫描类 warning，例如：

```text
capability not found in current registry text scan
```

前提是：

```text
violations: []
verdict: pass
```

## 5. 建议提交前人工查看

```bash
git diff --stat
git status --short
git diff -- README_STATUS.md
git diff -- app.py
git diff -- netaiops/
git diff -- tools/
git diff -- tests/
git diff -- docs/
```

## 6. 建议提交命令

确认无异常后再执行：

```bash
git add README_STATUS.md app.py docs netaiops skills tests tools
git status --short
git commit -m "feat: complete NetAIOps webhook v6 investigation, parser, skill and adaptive dry-run framework"
```

是否 push 远端，需要在生产环境确认后再决定。
