# output_judger 判错规则说明

## 1. 作用

output_judger 用于避免“设备命令实际上失败，但系统误判为 completed”的情况。

很多设备或 wrapper 会把错误信息放在 stdout 中，即使进程返回码正常，也不能直接认为命令成功。

## 2. 当前可识别的硬错误

包括但不限于：

- Invalid command
- Incorrect command
- Ambiguous command
- Incomplete command
- Unknown command
- Syntax Error
- bash: xxx command not found
- no device named
- authentication failed
- permission denied
- validation error
- traceback
- timeout

## 3. 不应误判为失败的内容

以下内容可能是正常设备输出里的计数项，不应直接判定为命令失败：

- CRC
- input error
- output error
- discard
- drops
- error packets

这些应该进入 evidence_facts，而不是作为 command hard error。

## 4. 状态语义

completed：

命令执行完成，未命中硬错误规则。

failed：

命令执行失败，或设备输出命中硬错误规则。

partial：

部分命令成功，部分命令失败。

## 5. 与 review 的关系

如果 command_results 中存在 hard_error：

- review 不应直接给 completed 正向结论。
- 应提示先修复命令、平台矩阵、设备映射或权限问题。

如果所有命令均 completed：

- review 可以继续做 facts 提炼和综合判断。
