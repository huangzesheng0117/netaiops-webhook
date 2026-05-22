# NetAIOps Webhook

NetAIOps Webhook 是一个面向网络运维告警场景的 AI 告警分析平台。平台接收来自 Alertmanager、Elastic 等系统的 Webhook 告警，将原始告警标准化后，结合 LLM 分析、告警家族识别、能力规划、只读取证、结果判错、证据提炼和通知生成，输出面向网络工程师可直接使用的告警分析结论。

当前主线已经演进到 V7。本文档只描述当前版本的最终能力，不展开 V1 到 V7 各阶段的中间建设态。

## 一、项目定位

本项目的目标不是简单地把告警转发给大模型，而是把网络告警处理拆成一条可控、可回归、可审计的工程化流水线：

```text
告警接入
  -> 原始告警落盘
  -> 标准化
  -> LLM 初步分析
  -> 告警家族识别
  -> 能力规划
  -> 多厂商命令生成
  -> 安全策略校验
  -> MCP/Netmiko 只读取证
  -> 执行结果判错
  -> 证据事实提炼
  -> Prometheus / 历史窗口补充
  -> Review 汇总
  -> 通知发送
  -> V6/V7 调查、Skill、学习侧车能力
```

平台强调以下原则：

- **只读优先**：自动执行链路只允许只读类网络命令，不做配置变更。
- **证据优先**：结论尽量基于设备输出、Prometheus 窗口数据、历史分析记录等证据。
- **可回放**：原始告警、标准化结果、分析结果、执行结果、Review 均按 request_id 落盘。
- **可回归**：核心模块配套单元测试和版本回归脚本。
- **可扩展**：通过 family、capability、command matrix、tool、parser、skill 等分层能力持续扩展。
- **生产可维护**：系统行为透明，保留运行记录和审计入口，便于后续排障。

## 二、当前核心能力

### 1. 多来源告警接入

当前平台支持接收并处理以下类型的告警输入：

| 来源 | 说明 |
|---|---|
| Alertmanager | Prometheus 告警 Webhook，支持 firing / resolved 状态识别 |
| Elastic / Kibana | 日志类告警 Webhook，支持常见网络日志事件标准化 |
| 测试样例 | testdata 中保留典型告警样例，用于本地回归和功能验证 |

平台会对原始 payload 进行落盘，生成 request_id，并在后续分析、执行、Review、通知中持续使用该 request_id 进行关联。

### 2. 告警标准化与状态过滤

标准化层负责把不同来源的 payload 转换成统一结构，包括：

- 告警来源
- 告警名称
- 告警状态
- 设备标识
- 设备平台
- 接口名称
- 标签信息
- 原始描述
- 时间信息

对于 Alertmanager 的 resolved 告警，平台会跳过重分析流程，避免对已经恢复的告警重复执行取证。

### 3. LLM 分析与结构化落盘

LLM 不直接控制执行链路，而是作为分析能力的一部分参与：

- 对告警内容进行初步分析
- 提取可能的故障对象
- 给出初步影响判断
- 生成排查建议
- 将分析结果结构化保存到本地数据目录

LLM 结果会和后续 family registry、capability registry、platform command matrix、MCP 取证结果共同组成最终 Review，不作为唯一判断依据。

### 4. 告警家族识别

平台通过 family registry 对告警进行家族归类。当前覆盖的典型类型包括：

| 告警家族 | 示例 |
|---|---|
| 接口状态异常 | interface down、link flap |
| 接口流量异常 | 带宽利用率高、流量突增、流量突降 |
| 接口错包/丢包 | input errors、CRC、drops、discards |
| BGP 邻居异常 | BGP neighbor down |
| OSPF 邻居异常 | OSPF neighbor down |
| 设备资源异常 | CPU、内存、会话、连接数异常 |
| F5 / DNS / HA 类异常 | F5 连接数、DNS 解析、HA 状态 |
| 光功率异常 | NX-OS transceiver Rx/Tx power abnormal |
| 通用日志异常 | 来自 Elastic 的网络日志告警 |

家族识别结果会影响后续的命令选择、证据提炼和通知模板。

### 5. 能力规划与多厂商命令矩阵

平台不会把所有告警都套用同一组命令，而是根据告警家族、设备平台、接口类型、告警方向和当前上下文规划需要执行的只读能力。

核心概念包括：

| 概念 | 作用 |
|---|---|
| family_registry | 判断告警属于哪一类问题 |
| capability_registry | 根据告警类型规划需要调查的能力 |
| platform_command_matrix | 根据平台和能力渲染具体命令 |
| safety_policy | 对命令进行只读安全校验 |
| agent_runner | 调用 MCP helper 执行只读命令 |

当前已重点区分 Cisco IOS-XE、NX-OS、ACI 等平台的命令差异，避免把某个平台不支持的命令错误下发到设备。

### 6. MCP / Netmiko 只读取证

平台通过 MCP helper 调用 Netmiko 对网络设备执行只读命令。Webhook 主服务不直接承载设备登录逻辑，而是通过 agent_runner 与 MCP helper 解耦。

典型链路如下：

```text
Webhook 主服务
  -> agent_runner
  -> MCP bridge
  -> MCP helper
  -> Netmiko
  -> 网络设备只读命令
  -> 命令输出回传
  -> execution_callback
```

这种方式把控制面和执行面分离，便于后续扩展更多工具或数据源。

### 7. 执行结果判错与证据事实提炼

平台会对 MCP 返回结果进行判错和事实提炼，而不是简单地把命令输出原文塞进通知。

当前支持的处理包括：

- 判断命令成功、失败、部分成功。
- 识别平台不支持命令、参数错误、连接异常。
- 从 show interface 输出中提取接口状态、速率、错包、丢包、CRC 等事实。
- 从 transceiver 输出中提取 Tx/Rx 光功率和阈值。
- 对接口错包类告警进行二次计数器复查。
- 将事实转化成更适合通知展示的摘要。

### 8. Prometheus 窗口证据

对于部分指标型告警，平台支持补充 Prometheus 窗口证据，用于判断：

- 是否为持续异常。
- 是否为瞬时尖峰。
- 告警后是否已经恢复。
- 当前设备 show 输出与历史指标是否一致。

这让告警分析不只依赖某一刻的设备输出，而是能结合时间窗口进行判断。

### 9. Review 与通知生成

最终 Review 会综合标准化告警、LLM 初步分析、告警家族、能力规划、MCP 执行结果、取证事实、Prometheus 窗口证据以及 V6/V7 增强上下文，生成可读性更强的分析结论，并通过通知模块发送到下游 IM 平台。

通知内容重点关注：

- 告警对象
- 当前状态
- 执行了哪些命令
- 成功/失败/部分成功情况
- 关键证据事实
- 初步判断
- 建议动作

## 三、V6 / V7 增强能力

V2 到 V5 构成了平台的主体链路：告警接入、标准化、LLM 分析、执行规划、MCP 取证、证据提炼和通知。V6 和 V7 主要是在这个地基上增强调查过程控制、Skill 体系和学习侧车能力。

### 1. V6：受控调查与 Skill Runtime

V6 引入了更工程化的调查模型：

| 能力 | 说明 |
|---|---|
| Investigation Session | 为一次告警调查建立受控状态 |
| Tool / Parser 体系 | 将工具执行和输出解析拆分成可扩展模块 |
| Skill Registry | 将可复用网络分析经验沉淀为 Skill |
| Skill Runtime | 在受控条件下加载和运行 Skill |
| Adaptive Evidence | 根据告警上下文规划补充取证 |
| Release / Maintenance Runbook | 固化回归、发布和维护流程 |

V6 的定位不是替代 V2 到 V5，而是让原有链路更可控、更模块化。

### 2. V7：学习侧车与经验沉淀

V7 参考 Hermes 类思想，引入学习侧车能力，但不让系统自动修改生产逻辑。当前 V7 重点包括：

| 能力 | 说明 |
|---|---|
| Incident Memory | 保存历史告警处理记录 |
| Relation Engine | 识别告警之间的关联关系 |
| Skill Proposal Builder | 从高价值案例中生成 Skill 候选 |
| Skill Proposal Review | 对候选 Skill 进行人工可审查管理 |
| Skill Draft Builder | 生成可读、可审查的 Skill 草案 |
| Learning Report | 输出学习报告和沉淀摘要 |
| Release Audit | 对版本发布和运行状态进行审计 |
| Interface Error Delta Recheck | 对接口错包类告警进行延迟二次复查 |

V7 的关键原则是：**只做建议、沉淀和辅助判断，不绕过人工审查直接改变生产分析策略。**

## 四、典型处理链路

### 1. 接口流量异常

```text
Alertmanager 告警
  -> 标准化为接口流量异常
  -> family_registry 识别为接口利用率/流量类问题
  -> capability_registry 规划接口状态、速率、错误计数器等能力
  -> command matrix 渲染对应平台命令
  -> MCP 只读取证
  -> 提取接口速率、带宽、错误、丢弃等事实
  -> 结合 Prometheus 窗口证据
  -> 生成 Review 和通知
```

### 2. 接口错包异常

```text
接口错包告警
  -> 首次 MCP 取证获取当前 counter
  -> 记录 baseline
  -> 延迟触发二次 counter recheck
  -> 比较前后 counter 是否继续增长
  -> 判断 still_increasing / not_increasing / unknown
  -> 在后续 Review 中补充二次取证结论
```

### 3. NX-OS 光功率异常

```text
光功率告警
  -> 识别为 optical_power_abnormal
  -> 提取接口对象
  -> 规划 show interface transceiver details
  -> 解析 Tx/Rx power、warning、alarm threshold
  -> 判断正常、预警或告警
  -> 输出光模块/光纤/对端方向的处理建议
```

## 五、项目结构

```text
.
├── app.py                         # FastAPI 主入口
├── agent_runner/                  # MCP 执行侧 runner
├── netaiops/                      # 核心业务模块
│   ├── normalizers.py             # 告警标准化
│   ├── processor.py               # 主处理流程
│   ├── family_registry.py         # 告警家族识别
│   ├── capability_registry.py     # 能力规划
│   ├── platform_command_matrix.py # 平台命令矩阵
│   ├── safety_policy.py           # 只读安全策略
│   ├── output_judger.py           # 执行结果判错
│   ├── family_evidence.py         # 家族化证据提炼
│   ├── prometheus_evidence.py     # Prometheus 窗口证据
│   ├── review_builder.py          # Review 汇总
│   ├── notification_payload.py    # 通知内容组装
│   ├── notifier.py                # 通知发送
│   ├── investigation_*            # V6 调查状态机
│   ├── skill_*                    # V6/V7 Skill 体系
│   ├── memory_*                   # V7 事件记忆
│   ├── relation_*                 # V7 关联分析
│   ├── learning_report*           # V7 学习报告
│   └── interface_error_delta.py   # V7 接口错包二次复查
├── playbooks/                     # 告警处理 playbook
├── skills/                        # 网络 Skill
├── tools/                         # 构建、验证、回归、维护工具
├── tests/                         # 单元测试
├── testdata/                      # 回归样例
├── docs/                          # 版本说明、运行手册、审计材料
├── config/                        # 非敏感配置片段
├── config.example.yaml            # 示例配置
├── VERSION                        # 版本标识
└── README_STATUS.md               # 历史状态说明
```

生产环境中还会存在以下运行时目录，这些目录通常不进入 Git 仓库：

```text
data/     # request、raw、normalized、analysis、execution、review、memory 等运行数据
logs/     # 服务日志
venv/     # Python 虚拟环境
backup/   # 本地维护备份
```

## 六、配置说明

仓库中提供 `config.example.yaml` 作为配置样例。生产环境通常使用本地 `config.yaml` 或环境变量注入敏感信息。

敏感信息不应提交到 GitHub，包括但不限于：

- LLM API Key
- MCP Server URL
- 设备账号密码
- IM Webhook 地址
- Prometheus 内部地址
- 内部设备 IP 清单
- Token、Secret、Cookie

建议将真实配置放在生产环境本地，并通过 `.gitignore` 排除。

## 七、运行方式

开发或测试环境可以使用：

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python -m compileall -q app.py netaiops agent_runner tools tests
```

生产环境通常使用 systemd 托管 uvicorn 服务，入口为：

```text
uvicorn app:app --host 0.0.0.0 --port 18080
```

健康检查：

```bash
curl -sf http://127.0.0.1:18080/health | python -m json.tool
```

## 八、常用验证命令

编译检查：

```bash
python -m compileall -q app.py netaiops agent_runner tools tests
```

核心回归：

```bash
bash tools/regress_v7_all.sh
bash tools/regress_v6_all.sh
```

接口错包二次复查查询：

```bash
curl -s "http://127.0.0.1:18080/v7/interface-error-delta?limit=5" | python -m json.tool
```

本地测试 Webhook：

```bash
./test_webhook.sh testdata/alertmanager/interface_down.json
```

## 九、关键 API 示例

| API | 作用 |
|---|---|
| `/health` | 服务健康检查 |
| `/webhook` | Webhook 告警接入 |
| `/callback/execution` | 执行结果回调 |
| `/v7/memory/incidents` | V7 事件记忆查询 |
| `/v7/relations/incidents` | V7 告警关联查询 |
| `/v7/skill-proposals` | V7 Skill 候选查询 |
| `/v7/skill-proposal-reviews` | V7 Skill 候选复核 |
| `/v7/skill-drafts` | V7 Skill 草案查询 |
| `/v7/learning/report` | V7 学习报告 |
| `/v7/release/audit` | V7 发布审计 |
| `/v7/interface-error-delta` | 接口错包二次复查结果 |

## 十、安全边界

本项目在设计上遵循以下安全边界：

1. 自动取证只执行只读命令。
2. 命令执行前经过 safety policy 校验。
3. Webhook 主服务与 MCP 执行侧解耦。
4. 生产敏感配置不进入 Git 仓库。
5. V7 学习侧车不自动修改生产策略。
6. Skill 候选需要人工审查后再进入可用能力库。
7. 回归测试通过后再提交和发布。

## 十一、维护建议

日常维护建议优先关注：

- `systemctl status netaiops-webhook`
- `/health` 健康检查
- `logs/` 服务日志
- `data/` 下按 request_id 落盘的分析链路
- MCP helper 连接状态
- LLM 调用状态
- Prometheus 查询状态
- 通知发送结果
- `tools/regress_v7_all.sh`
- `tools/regress_v6_all.sh`

对于新增告警类型，推荐按以下顺序扩展：

```text
family_registry
  -> capability_registry
  -> platform_command_matrix
  -> safety_policy
  -> parser / family_evidence
  -> review / notification
  -> tests
  -> regression
```

## 十二、当前版本定位

当前版本可以理解为：

```text
V2-V5：平台主链路与生产地基
V6：受控调查、Tool/Parser、Skill Runtime、Adaptive Evidence
V7：Incident Memory、Relation Engine、Skill Proposal、Learning Report、Release Audit、二次复查侧车
```

README 只描述当前最终能力，不保留历史建设过程中的中间实现说明。更细的版本文档和运行手册见 `docs/` 目录。
