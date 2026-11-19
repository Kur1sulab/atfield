"""心之壁的 AI 层：云 / 本地模型接入 + 出网脱敏 + 研判建议。

对外只暴露一个入口类 AI（由 Core 持有），其余是内部实现。

模块
    provider  协议客户端（openai 兼容 / anthropic）+ 凭据解析 + 预设
    redact    出网脱敏网关（任何字节离开本机前必过）
    judge     研判逻辑 + 输出白名单 + 预算 + 建议流水

不变量（改这个包之前先读一遍）
    · AI 进程无特权，不执行 pfctl / 不删文件 / 不改策略，只写 suggestions.jsonl
    · AI 只吃 Finding 的结构化摘要，不吃原始流量与文件内容
    · 出网默认强制脱敏；端点是回环地址也不例外（网关背后仍是云端）
    · 任何 AI 失败都收敛成 error 建议，主流水线不受影响
    · 凭据原文不落日志、不落审计、不进界面，只出现指纹
"""
from __future__ import annotations

from .judge import ACTION_WHITELIST, AI, VERDICT_CN, VERDICTS
from .provider import (PRESETS, AIError, Client, Reply, apply_preset,
                       load_secret, parse_json_reply, resolve_key, save_secret)
from .redact import is_loopback_url, mask_key, redact_obj, redact_text

__all__ = [
    "AI", "Client", "Reply", "AIError", "PRESETS", "apply_preset",
    "VERDICTS", "VERDICT_CN", "ACTION_WHITELIST",
    "redact_obj", "redact_text", "is_loopback_url", "mask_key",
    "resolve_key", "load_secret", "save_secret", "parse_json_reply",
]
