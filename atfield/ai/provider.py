"""云 AI 客户端：一套接口吃掉 OpenAI 兼容协议与 Anthropic 协议。

为什么自己写 HTTP 而不引 SDK
    1) 这个产品的运行时依赖只有 psutil / yaml，塞一个 openai SDK 进来等于
       把「装不上就起不来」的风险引进来。
    2) 需要精确控制「发出了什么字节」。SDK 会自己加重试、自己加 header、
       自己把 request 打进日志——而我们的红线是「出网内容必须可审计」。
    3) 只要 chat/completions 这一个动作，函数调用与流式都能用 urllib 拼出来。

支持的后端
    openai      OpenAI / DeepSeek / Kimi / GLM / Qwen / vLLM / Ollama / 任何
                自称 OpenAI 兼容的网关。路径 {base}/chat/completions
    anthropic   Claude 原生协议。路径 {base}/v1/messages（base 不带 /v1）

magpie 网关
    本机 127.0.0.1:3425/v1，key 固定 magpie，背后是 160+ 个云端模型的路由组。
    实测：基础对话 1.2s、json_object 结构化输出可用、function calling 可用、
    SSE 流式可用。所以它被做成内置预设，一键切换团队/模型。

凭据怎么放（三条，优先级从高到低）
    1) config.yaml 的 ai.api_key        —— 不推荐，配置文件会进备份
    2) 环境变量 ai.api_key_env（默认 ATFIELD_AI_KEY）
    3) ~/.atfield/secrets/ai.json       —— 推荐，权限 600，不进 git 不进日志

    无论哪条来，进日志/审计/界面时一律只出现 mask_key() 的指纹，
    原文不落任何持久化介质。这是硬约束，代码里没有任何打印原文的分支。
"""
from __future__ import annotations

import json
import os
import socket
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from . import redact

# 预算：单次请求的输出上限，防止模型话痨把响应体撑爆
HARD_MAX_TOKENS = 2048


class AIError(Exception):
    """带分类的失败。kind 用于界面提示与审计归因，不做异常栈外泄。"""

    def __init__(self, kind: str, message: str, http_status: int = 0):
        super().__init__(message)
        self.kind = kind            # auth | rate_limit | timeout | network | bad_response | disabled | not_configured
        self.http_status = http_status

    def to_dict(self) -> Dict[str, Any]:
        return {"kind": self.kind, "error": str(self),
                "http_status": self.http_status}


@dataclass
class Reply:
    text: str
    model: str = ""
    latency_ms: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    redactions: Dict[str, int] = field(default_factory=dict)
    raw_finish: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"text": self.text, "model": self.model,
                "latency_ms": self.latency_ms,
                "prompt_tokens": self.prompt_tokens,
                "completion_tokens": self.completion_tokens,
                "redactions": self.redactions,
                "finish_reason": self.raw_finish}


# ---------------------------------------------------------------- 预设

PRESETS: Dict[str, Dict[str, Any]] = {
    # 本机 magpie 网关：一个端点聚合 160+ 云端模型，key 固定
    "magpie": {
        "provider": "openai",
        "base_url": "http://127.0.0.1:3425/v1",
        "model": "group/daily",
        "api_key": "magpie",
        "note": "本机 magpie 网关，聚合 workbuddy / trae / opencode-go 等云端模型；"
                "group/daily 自动选当前额度可用的最强模型",
    },
    "deepseek": {
        "provider": "openai",
        "base_url": "https://api.deepseek.com/v1",
        "model": "deepseek-chat",
        "api_key_env": "DEEPSEEK_API_KEY",
        "note": "DeepSeek 官方",
    },
    "kimi": {
        "provider": "openai",
        "base_url": "https://api.moonshot.cn/v1",
        "model": "kimi-k2-0905-preview",
        "api_key_env": "MOONSHOT_API_KEY",
        "note": "Moonshot / Kimi",
    },
    "qwen": {
        "provider": "openai",
        "base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1",
        "model": "qwen-plus",
        "api_key_env": "DASHSCOPE_API_KEY",
        "note": "阿里云百炼（OpenAI 兼容模式）",
    },
    "ollama": {
        "provider": "openai",
        "base_url": "http://127.0.0.1:11434/v1",
        "model": "qwen3:8b",
        "api_key": "ollama",
        "note": "本地 Ollama，数据不出本机",
    },
    "anthropic": {
        "provider": "anthropic",
        "base_url": "https://api.anthropic.com",
        "model": "claude-sonnet-4-5",
        "api_key_env": "ANTHROPIC_API_KEY",
        "note": "Claude 原生协议",
    },
}


def apply_preset(cfg: Dict[str, Any], name: str) -> Dict[str, Any]:
    """把预设合并进 ai 配置块（原地改，返回改后的块）。"""
    p = PRESETS.get(name)
    if not p:
        return cfg
    for k, v in p.items():
        if k in ("note",):
            continue
        cfg[k] = v
    cfg["preset"] = name
    return cfg


# ---------------------------------------------------------------- 凭据

def _secrets_path() -> str:
    data_dir = os.environ.get("ATFIELD_DATA_DIR") or os.path.join(
        os.path.expanduser("~"), ".atfield")
    return os.path.join(data_dir, "secrets", "ai.json")


def load_secret() -> str:
    """从 secrets 文件读 key。文件权限必须是 600，否则拒绝读取。"""
    path = _secrets_path()
    if not os.path.isfile(path):
        return ""
    try:
        st = os.stat(path)
        if st.st_mode & 0o077:
            return ""      # 权限过宽，宁可不用也不读
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return str(data.get("api_key") or "")
    except Exception:
        return ""


def save_secret(key: str) -> Dict[str, Any]:
    """写入 key 到 600 的 secrets 文件。返回结果不含明文。"""
    path = _secrets_path()
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump({"api_key": key, "updated_at": time.time()}, fh)
        os.replace(tmp, path)
        os.chmod(path, 0o600)
        return {"ok": True, "path": path, "fingerprint": redact.mask_key(key)}
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def resolve_key(cfg: Dict[str, Any]) -> Tuple[str, str]:
    """返回 (key, 来源)。来源用于界面显示，不暴露 key 本身。"""
    direct = str(cfg.get("api_key") or "").strip()
    if direct:
        return direct, "config"
    env_name = str(cfg.get("api_key_env") or "").strip()
    if env_name:
        val = os.environ.get(env_name, "").strip()
        if val:
            return val, f"env:{env_name}"
    val = load_secret()
    if val:
        return val, "secrets_file"
    return "", "none"


# ---------------------------------------------------------------- 客户端

class Client:
    """一次构造，多次调用。线程安全（无共享可变状态）。"""

    def __init__(self, cfg: Dict[str, Any]):
        self.cfg = cfg or {}
        self.provider = str(self.cfg.get("provider") or "openai").lower()
        self.base_url = str(self.cfg.get("base_url") or "").rstrip("/")
        self.model = str(self.cfg.get("model") or "")
        self.timeout = float(self.cfg.get("timeout") or 30)
        self.max_tokens = min(int(self.cfg.get("max_tokens") or 900), HARD_MAX_TOKENS)
        self.temperature = float(
            self.cfg.get("temperature") if self.cfg.get("temperature") is not None else 0.2)
        self.key, self.key_source = resolve_key(self.cfg)

    # ---------- 状态 ----------
    def status(self) -> Dict[str, Any]:
        """不联网的配置自检。"""
        problems: List[str] = []
        if not self.base_url:
            problems.append("base_url 为空")
        if not self.model:
            problems.append("model 为空")
        if not self.key and self.provider != "anthropic" or (not self.key and self.provider == "anthropic"):
            if not self.key:
                problems.append("没有可用凭据（config / 环境变量 / secrets 文件均为空）")
        if self.provider not in ("openai", "anthropic"):
            problems.append(f"不支持的 provider: {self.provider}")
        return {
            "ready": not problems,
            "problems": problems,
            "provider": self.provider,
            "base_url": self.base_url,
            "model": self.model,
            "endpoint": self._endpoint(),
            "key_present": bool(self.key),
            "key_source": self.key_source,
            "key_fingerprint": redact.mask_key(self.key),
            "timeout": self.timeout,
            "max_tokens": self.max_tokens,
        }

    def _endpoint(self) -> str:
        if self.provider == "anthropic":
            base = self.base_url
            if base.endswith("/v1"):
                base = base[:-3]
            return base + "/v1/messages"
        return self.base_url + "/chat/completions"

    # ---------- 出网 ----------
    def chat(self, messages: List[Dict[str, str]], *,
             json_mode: bool = False,
             do_redact: Optional[bool] = None,
             max_tokens: Optional[int] = None) -> Reply:
        """发一轮对话。do_redact 默认跟随配置 ai.redact（默认 True）。"""
        if not self.key:
            raise AIError("not_configured", "缺少 API 凭据")
        if not self.base_url or not self.model:
            raise AIError("not_configured", "base_url 或 model 未配置")

        if do_redact is None:
            do_redact = bool(self.cfg.get("redact", True))

        # 脱敏在本地完成，之后 payload 里只剩占位符
        counts: Dict[str, int] = {}
        out_msgs = messages
        if do_redact:
            out_msgs, counts = redact.redact_obj(messages)

        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": out_msgs,
            "max_tokens": min(max_tokens or self.max_tokens, HARD_MAX_TOKENS),
            "temperature": self.temperature,
        }
        if json_mode and self.provider == "openai":
            payload["response_format"] = {"type": "json_object"}

        headers = {"Content-Type": "application/json"}
        if self.provider == "anthropic":
            headers["x-api-key"] = self.key
            headers["anthropic-version"] = "2023-06-01"
            # anthropic 要求 system 单独提出来
            sys_parts = [m["content"] for m in out_msgs if m.get("role") == "system"]
            rest = [m for m in out_msgs if m.get("role") != "system"]
            payload = {
                "model": self.model,
                "max_tokens": payload["max_tokens"],
                "temperature": self.temperature,
                "messages": rest,
            }
            if sys_parts:
                payload["system"] = "\n\n".join(sys_parts)
        else:
            headers["Authorization"] = "Bearer " + self.key

        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(self._endpoint(), data=body, method="POST")
        for k, v in headers.items():
            req.add_header(k, v)

        t0 = time.time()
        try:
            ctx = ssl.create_default_context()
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                raw = resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            detail = ""
            try:
                detail = exc.read().decode("utf-8", "replace")[:400]
            except Exception:
                pass
            kind = {401: "auth", 403: "auth", 429: "rate_limit"}.get(exc.code, "bad_response")
            if exc.code >= 500:
                kind = "network"
            # 上游错误体可能回显 key（部分网关会把 Authorization 打回来），再脱一次
            detail, _ = redact.redact_text(detail)
            raise AIError(kind, f"HTTP {exc.code}: {detail}".strip(), exc.code) from None
        except socket.timeout:
            raise AIError("timeout", f"请求超时（{self.timeout:.0f}s）") from None
        except urllib.error.URLError as exc:
            reason = str(getattr(exc, "reason", exc))
            kind = "timeout" if "timed out" in reason.lower() else "network"
            raise AIError(kind, f"连接失败: {reason}") from None
        except Exception as exc:
            raise AIError("network", f"{type(exc).__name__}: {exc}") from None

        latency = int((time.time() - t0) * 1000)
        return self._parse(raw, latency, counts)

    def _parse(self, raw: str, latency: int, counts: Dict[str, int]) -> Reply:
        try:
            data = json.loads(raw)
        except Exception:
            raise AIError("bad_response", "响应不是合法 JSON") from None

        if isinstance(data, dict) and data.get("error"):
            err = data["error"]
            msg = err.get("message") if isinstance(err, dict) else str(err)
            msg, _ = redact.redact_text(str(msg)[:400])
            raise AIError("bad_response", f"上游错误: {msg}")

        text = ""
        finish = ""
        usage: Dict[str, Any] = {}
        if self.provider == "anthropic":
            blocks = data.get("content") or []
            text = "".join(b.get("text", "") for b in blocks if isinstance(b, dict))
            finish = str(data.get("stop_reason") or "")
            u = data.get("usage") or {}
            usage = {"prompt_tokens": u.get("input_tokens", 0),
                     "completion_tokens": u.get("output_tokens", 0)}
        else:
            choices = data.get("choices") or []
            if not choices:
                raise AIError("bad_response", "响应里没有 choices")
            msg = choices[0].get("message") or {}
            text = msg.get("content") or ""
            if not text and msg.get("reasoning_content"):
                text = msg["reasoning_content"]
            finish = str(choices[0].get("finish_reason") or "")
            u = data.get("usage") or {}
            usage = {"prompt_tokens": u.get("prompt_tokens", 0),
                     "completion_tokens": u.get("completion_tokens", 0)}

        return Reply(text=str(text).strip(), model=str(data.get("model") or self.model),
                     latency_ms=latency,
                     prompt_tokens=int(usage.get("prompt_tokens") or 0),
                     completion_tokens=int(usage.get("completion_tokens") or 0),
                     redactions=counts, raw_finish=finish)

    # ---------- 连通性 ----------
    def ping(self) -> Dict[str, Any]:
        """真发一条最小请求，验证端到端可用。"""
        t0 = time.time()
        try:
            r = self.chat([{"role": "user", "content": "回复两个字：在线"}],
                          max_tokens=16)
            return {"ok": True, "latency_ms": r.latency_ms, "model": r.model,
                    "reply": r.text[:40], "usage": {
                        "prompt_tokens": r.prompt_tokens,
                        "completion_tokens": r.completion_tokens},
                    "redactions": r.redactions}
        except AIError as exc:
            out = {"ok": False, "latency_ms": int((time.time() - t0) * 1000)}
            out.update(exc.to_dict())
            return out
        except Exception as exc:
            return {"ok": False, "kind": "internal",
                    "error": f"{type(exc).__name__}: {exc}",
                    "latency_ms": int((time.time() - t0) * 1000)}


def parse_json_reply(text: str) -> Optional[Dict[str, Any]]:
    """从模型回复里抠出 JSON 对象。容忍 ```json 围栏与前后废话。"""
    if not text:
        return None
    s = text.strip()
    for fence in ("```json", "```JSON", "```"):
        if s.startswith(fence):
            s = s[len(fence):]
            break
    if s.endswith("```"):
        s = s[:-3]
    s = s.strip()
    try:
        obj = json.loads(s)
        return obj if isinstance(obj, dict) else None
    except Exception:
        pass
    # 退一步：找第一个 { 到最后一个 }
    i, j = s.find("{"), s.rfind("}")
    if 0 <= i < j:
        try:
            obj = json.loads(s[i:j + 1])
            return obj if isinstance(obj, dict) else None
        except Exception:
            return None
    return None
