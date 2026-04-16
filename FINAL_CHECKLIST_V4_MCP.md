# NetAIOps webhook v4 + MCP 最终联调检查清单

## 一、编排层
- [x] webhook 服务正常启动
- [x] /health 返回正常
- [x] /v4/request/{request_id}/summary 可查询
- [x] 手工 plan 可落盘
- [x] dispatch 可生成

## 二、MCP helper 层
- [x] /opt/netaiops-mcp-helper/bridge_helper.py 存在
- [x] discover_tools.py 可列出远端工具
- [x] get_network_device_list 可返回真实设备
- [x] send_command_and_get_output 可单独执行成功

## 三、Runner 层
- [x] run_runner_mcp.sh 可执行
- [x] mcp backend 返回 completed
- [x] callback 文件生成成功

## 四、回写与复盘层
- [x] run_callback.sh 可执行
- [x] execution 文件生成成功
- [x] review 文件生成成功
- [x] summary 显示 execution.mode=mcp
- [x] summary 显示 execution.status=completed

## 五、上线前风险控制
- [x] 只使用 readonly show 命令
- [ ] 先只接真实存在的 inventory 设备
- [x] 先只做单设备场景
- [ ] 先只做少量 playbook
- [x] callback 和 runner 均保留日志

## 六、输出层准备
- [x] notification payload 可生成
- [x] notification 文本可预览
- [x] 查询链接使用 external_base_url
- [x] analysis_summary 为空时不显示 None
- [x] 通知触发时机限定为最终 execution/review 阶段
- [ ] 咚咚发送脚本已接入
