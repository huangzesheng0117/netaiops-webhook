import json

PROMPT_VERSION = "v2.0"


def build_analysis_prompt(event: dict) -> str:
    event_text = json.dumps(event, ensure_ascii=False, indent=2)

    prompt = f"""
你是一名资深网络运维告警分析助手。

你的职责：
1. 根据输入的标准化告警事件进行分析
2. 只做分析，不执行任何变更
3. 不要假设你已经登录设备
4. 输出必须是 JSON
5. 如果信息不足，也要给出合理的排查建议

请基于下面的告警事件进行分析：

{event_text}

请严格输出如下 JSON 结构，不要输出额外说明文字：

{{
  "summary": "一句话总结告警含义",
  "alarm_interpretation": "你对告警的理解",
  "possible_causes": [
    "可能原因1",
    "可能原因2"
  ],
  "suggested_checks": [
    "建议检查项1",
    "建议检查项2"
  ],
  "suggested_commands": [
    "show命令1",
    "show命令2"
  ],
  "risk_note": "风险提示",
  "confidence": "high/medium/low"
}}
""".strip()

    return prompt
