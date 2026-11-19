"""凭据静态暴露盘点 —— 只读扫描本机散落的明文 key / token / 私钥 / 含口令配置。

为什么单独一层：EDR 看得见「谁读了 ~/.ssh/id_rsa」，但看不见「这台机器上
本来就躺着一份 0644 的私钥、一份没进 .gitignore 的 .env」。后者不需要攻击者
做任何事就已经是暴露面，属于「静态暴露」而不是「行为检测」，所以这里单独
成层，只做盘点、不做处置。

三条硬约束（任何改动都不得放宽）

1. 只读
   只以 "r" 打开、只 os.walk/stat。不写、不删、不改权限、不上传。
   `test_credscan.ReadOnlyGuarantee` 会对源码做禁用词检查，防止后续维护
   顺手加个「自动修复权限」把这一层变成写操作。

2. 输出强制脱敏
   任何返回字段都不得包含完整凭据：`prefix` 只给前 6 位、`length` 给长度、
   `fingerprint` 给 sha256 前 12 位（不可逆，仅用于跨文件去重）。
   长度 ≤ 6 的凭据连前缀都不给（否则「前 6 位」就是全文）。
   保留位数只能从配置往小调，上限写死 MASK_KEEP_MAX=6。

3. 不把自己算成风险
   `tests/`、`fixtures/`、`*.sample`、`*.example`、本模块源码、data_dir
   一律排除；行内 `atfield:allow-cred` / `credscan:ignore` 可逐行豁免。
"""

from __future__ import annotations

import fnmatch
import hashlib
import os
import re
import time
from typing import Any, Dict, List, Optional, Tuple

MASK_KEEP_MAX = 6
FINGERPRINT_LEN = 12
PREVIEW_MAX = 120
SELF_PATH = os.path.abspath(__file__)

# ---------------------------------------------------------------- 扫描面
# 常规项目/家目录里的凭据落点；不存在的目录直接跳过，不会报错。
DEFAULT_ROOTS: List[str] = [
    os.path.join("~", ".ssh"),
    os.path.join("~", ".aws"),
    os.path.join("~", ".config"),
    os.path.join("~", ".docker"),
    os.path.join("~", ".kube"),
    os.path.join("~", ".npmrc"),
    os.path.join("~", ".netrc"),
    os.path.join("~", "Desktop"),
    os.path.join("~", "Documents"),
    os.path.join("~", "Downloads"),
    os.path.join("~", "code"),
    os.path.join("~", "projects"),
    os.path.join("~", "workspace"),
    os.path.join("~", "dev"),
    os.path.join("~", "aegis"),
    "~",                      # 兜底：家目录本体（靠下面的排除表剪掉缓存/系统区）
]

# 目录名整除（walk 时直接剪枝，不进目录）
EXCLUDE_DIR_NAMES = {
    ".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv",
    "site-packages", "dist-packages", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    ".tox", ".next", ".nuxt", "dist", "build", ".cache", "cache", "Caches", "Keychains",
    ".Trash", ".DocumentRevisions-V100", ".Spotlight-V100", ".fseventsd",
    "photoslibrary", ".npm", ".yarn", "DerivedData", "Pods", "vendor",
    "logs", "log", ".gradle", ".idea",
}

# 绝对路径前缀整除（系统区、自己的数据区；不读、不报）
EXCLUDE_PATH_PREFIXES = (
    "/System", "/Library", "/usr", "/bin", "/sbin", "/private/var", "/private/etc",
    "/Applications", "/Volumes", "/cores", "/dev",
)

# 只扫「像配置/凭据/脚本」的文件，避免把整个磁盘的二进制都读一遍
TEXT_EXTS = {
    ".env", ".ini", ".cfg", ".conf", ".config", ".yaml", ".yml", ".json", ".toml",
    ".properties", ".sh", ".zsh", ".bash", ".fish", ".pem", ".key", ".ovpn",
    ".netrc", ".npmrc", ".pypirc", ".htpasswd", ".txt", ".md", ".xml", ".sql",
    ".py", ".rb", ".php", ".js", ".ts", ".go", ".java", ".rs", ".bak", ".old",
}
NAME_HINTS = {
    "credentials", "config", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    ".netrc", ".npmrc", ".pypirc", ".git-credentials", ".htpasswd",
    "secrets.yml", "secrets.yaml", "settings.py", "credentials.json",
    "service-account.json", ".env.local", ".env.production", ".env.development",
}

# 自身与已知安全区：扫自身仓库时不能把自己的测试样本/正则源码当命中
DEFAULT_WHITELIST: List[str] = [
    "*/tests/*", "*/test/*", "*/fixtures/*", "*/fixture/*", "*/docs/*",
    "*/examples/*", "*/samples/*", "*_test.py", "test_*.py", "conftest.py",
    "*.example", "*.sample", "*.template", "*.tpl", "*.dist", "*.md.example",
    "*credscan_selftest*", "*mock_smtp*",
]
INLINE_ALLOW = ("atfield:allow-cred", "credscan:ignore", "allowlist secret",
                "pragma: allowlist", "fake-credential-for-test")

# 明显是占位符的值：不是凭据，报出来只会制造噪声（噪声会让人关掉扫描）
PLACEHOLDER_VALUES = {
    "", "none", "null", "true", "false", "yes", "no", "test", "demo", "dummy",
    "example", "placeholder", "changeme", "change_me", "change-me", "password",
    "secret", "token", "todo", "fixme", "xxx", "xxxx", "xxxxx", "******", "***",
    "...", "-", "0", "1", "n/a", "na", "unset", "empty", "redacted",
}
PLACEHOLDER_PREFIX = ("${", "{{", "%(", "<", "$", "your_", "your-", "yourkey",
                      "sk-your", "replace", "insert", "env:", "os.environ",
                      "process.env", "getenv(", "***", "xxx", "\u2026")

# ---------------------------------------------------------------- 规则表
# group：取第几个捕获组作为凭据本体（0 = 整个匹配）
RULES: List[Dict[str, Any]] = [
    {"kind": "aws_access_key", "cn": "AWS Access Key ID", "severity": "high", "group": 1,
     "rx": re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b")},
    {"kind": "aws_secret_key", "cn": "AWS Secret Access Key", "severity": "critical", "group": 1,
     "rx": re.compile(r"(?i)aws_?secret_?access_?key\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})")},
    {"kind": "github_token", "cn": "GitHub Token", "severity": "critical", "group": 1,
     "rx": re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{30,255}|github_pat_[A-Za-z0-9_]{22,255})\b")},
    {"kind": "slack_token", "cn": "Slack Token", "severity": "high", "group": 1,
     "rx": re.compile(r"\b(xox[baprs]-[A-Za-z0-9-]{10,})")},
    {"kind": "anthropic_key", "cn": "Anthropic API Key", "severity": "critical", "group": 1,
     "rx": re.compile(r"\b(sk-ant-[A-Za-z0-9_\-]{20,})")},
    {"kind": "openai_key", "cn": "OpenAI 风格 API Key", "severity": "critical", "group": 1,
     "rx": re.compile(r"\b(sk-(?:proj-)?[A-Za-z0-9_\-]{20,})")},
    {"kind": "google_api_key", "cn": "Google API Key", "severity": "high", "group": 1,
     "rx": re.compile(r"\b(AIza[0-9A-Za-z_\-]{35})")},
    {"kind": "stripe_key", "cn": "Stripe Live Key", "severity": "critical", "group": 1,
     "rx": re.compile(r"\b((?:sk|rk)_live_[0-9A-Za-z]{16,})")},
    {"kind": "jwt", "cn": "JWT", "severity": "medium", "group": 0,
     "rx": re.compile(r"\b(eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,})")},
    {"kind": "db_url_password", "cn": "连接串内嵌口令", "severity": "high", "group": 1,
     "rx": re.compile(r"(?i)\b(?:mysql|mariadb|postgres(?:ql)?|mongodb(?:\+srv)?|redis|amqp)"
                      r"://[^\s:@/'\"]+:([^\s@/'\"]{4,})@")},
    {"kind": "private_key", "cn": "私钥块", "severity": "critical", "group": 0,
     "rx": re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY(?: BLOCK)?-----")},
    {"kind": "generic_secret", "cn": "配置里的明文口令/密钥", "severity": "medium", "group": 2,
     "rx": re.compile(r"""(?i)(?:^|[^A-Za-z0-9_.-])"""
                      r"""([A-Za-z0-9_.-]*(?:password|passwd|pwd|secret|token|api[_-]?key"""
                      r"""|access[_-]?key|private[_-]?key|client[_-]?secret|auth[_-]?token)"""
                      r"""[A-Za-z0-9_.-]*)\s*[:=]\s*["']?([^\s"'#,;]{8,})""")},
]
RULE_BY_KIND = {r["kind"]: r for r in RULES}
_SEV_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


# ---------------------------------------------------------------- 脱敏
def mask(value: str, keep: int = MASK_KEEP_MAX) -> Dict[str, Any]:
    """把凭据变成可安全落日志的形状：前 keep 位 + 长度，其余一律不给。

    keep 上限写死 6：配置只能调小不能调大。长度 ≤ keep 时连前缀都不给——
    否则「前 6 位」对 6 位长的口令就是全文。
    """
    n = len(value or "")
    k = max(0, min(int(keep), MASK_KEEP_MAX))
    if n == 0:
        return {"prefix": "", "length": 0, "masked": "（空）"}
    if n <= k:
        return {"prefix": "", "length": n, "masked": f"**（{n} 位，过短不显示）"}
    head = value[:k]
    return {"prefix": head, "length": n, "masked": f"{head}\u2026（{n} 位）"}


def fingerprint(value: str) -> str:
    """不可逆指纹：同一凭据在不同文件里出现时可关联，但无法还原。"""
    if not value:
        return ""
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:FINGERPRINT_LEN]


def _looks_placeholder(value: str) -> bool:
    v = (value or "").strip().strip("\"'")
    low = v.lower()
    if low in PLACEHOLDER_VALUES:
        return True
    if low.startswith(PLACEHOLDER_PREFIX):
        return True
    if len(set(low)) <= 1:
        return True
    # 明显是说明文字而不是密钥
    if any(t in low for t in ("example", "placeholder", "your_", "xxxx", "<", "change_me")):
        return True
    return False


# ---------------------------------------------------------------- 白名单
class Whitelist:
    """路径 glob + 行内标记 + 自身排除。

    `tests/` 默认在名单里：扫自身仓库时，测试里造的假 key 不是风险，
    把它报出来会让整个能力一上线就满屏噪声（噪声=功能被关掉）。
    """

    def __init__(self, extra: Optional[List[str]] = None, enabled: bool = True):
        self.enabled = bool(enabled)
        self.patterns = list(DEFAULT_WHITELIST) + [str(p) for p in (extra or []) if p]

    def path_allowed(self, path: str) -> bool:
        if not self.enabled:
            return False
        p = os.path.abspath(path)
        if p == SELF_PATH:
            return True
        for pat in self.patterns:
            if fnmatch.fnmatch(p, pat) or fnmatch.fnmatch(os.path.basename(p), pat):
                return True
            # 目录型 pattern（*/tests/*）也要能命中 tests 目录本身下的相对路径
            if pat.endswith("/*") and fnmatch.fnmatch(p, pat[:-2] + "/*"):
                return True
        return False

    @staticmethod
    def line_allowed(line: str) -> bool:
        low = (line or "").lower()
        return any(mark in low for mark in INLINE_ALLOW)


# ---------------------------------------------------------------- 扫描器
class Scanner:
    def __init__(self, cfg: Optional[Dict[str, Any]] = None):
        c = (cfg or {}).get("credscan") or {}
        self.cfg = cfg or {}
        self.data_dir = os.path.abspath(
            (cfg or {}).get("data_dir") or os.path.expanduser("~/.atfield"))
        self.roots: List[str] = [str(x) for x in (c.get("roots") or []) if str(x).strip()]
        self.max_files = max(1, int(c.get("max_files", 3000) or 3000))
        self.max_bytes = max(4096, int(c.get("max_bytes", 256 * 1024) or 256 * 1024))
        self.max_seconds = max(1.0, float(c.get("max_seconds", 15.0) or 15.0))
        self.min_severity = str(c.get("min_severity") or "low").lower()
        self.keep = max(0, min(int(c.get("mask_keep", MASK_KEEP_MAX) or MASK_KEEP_MAX),
                               MASK_KEEP_MAX))
        self.whitelist = Whitelist(c.get("whitelist") or [], c.get("whitelist_enabled", True))
        self.extra_exclude = [os.path.abspath(os.path.expanduser(str(x)))
                              for x in (c.get("exclude") or []) if str(x).strip()]
        self.enabled = bool(c.get("enabled", True))
        self.last: Dict[str, Any] = {}

    # ---------- 根目录 ----------
    def resolve_roots(self, roots: Optional[List[str]] = None) -> List[str]:
        explicit = bool(roots)
        raw = roots or self.roots or DEFAULT_ROOTS
        out: List[str] = []
        seen = set()
        for r in raw:
            p = os.path.abspath(os.path.expanduser(str(r)))
            if p in seen:
                continue
            seen.add(p)
            if os.path.isdir(p) and not self._excluded_dir(p):
                out.append(p)
        if not out and not explicit:
            home = os.path.abspath(os.path.expanduser("~"))
            if os.path.isdir(home):
                out.append(home)
        return out

    def _excluded_dir(self, path: str) -> bool:
        p = os.path.abspath(path)
        if p == self.data_dir or p.startswith(self.data_dir + os.sep):
            return True
        for pre in EXCLUDE_PATH_PREFIXES:
            if p == pre or p.startswith(pre + os.sep):
                return True
        for pre in self.extra_exclude:
            if p == pre or p.startswith(pre + os.sep):
                return True
        return os.path.basename(p) in EXCLUDE_DIR_NAMES

    def _interesting(self, path: str) -> bool:
        name = os.path.basename(path)
        low = name.lower()
        if low.endswith((".min.js", ".min.css", ".map", ".lock", ".svg")):
            return False        # 压缩产物/锁文件里 "token:" 是语法噪声，不是凭据
        if low.startswith(".env"):
            return True
        if name in NAME_HINTS or low in NAME_HINTS:
            return True
        ext = os.path.splitext(name)[1].lower()
        return ext in TEXT_EXTS

    # ---------- 单文件 ----------
    def _mode(self, st: os.stat_result) -> str:
        return format(st.st_mode & 0o777, "04o")

    def scan_text(self, text: str, path: str = "<mem>", mode: str = "") -> List[Dict[str, Any]]:
        """扫描一段文本（测试与 CLI 都走这里），返回已脱敏的命中列表。"""
        hits: List[Dict[str, Any]] = []
        for lineno, line in enumerate((text or "").splitlines(), start=1):
            if not line.strip():
                continue
            if Whitelist.line_allowed(line):
                continue
            line_hits: List[Tuple[Dict[str, Any], str]] = []
            for rule in RULES:
                for m in rule["rx"].finditer(line):
                    try:
                        val = m.group(rule.get("group", 0)) or ""
                    except Exception:
                        val = m.group(0) or ""
                    val = val.strip().strip("\"'")
                    if not val:
                        continue
                    if rule["kind"] != "private_key" and _looks_placeholder(val):
                        continue
                    line_hits.append((rule, val))
            if not line_hits:
                continue
            # 具体规则命中时丢掉同行的泛化命中，避免一条密钥报两次
            specific = [h for h in line_hits if h[0]["kind"] != "generic_secret"]
            if specific:
                line_hits = specific
            seen_kind = set()
            for rule, val in line_hits:
                if (rule["kind"], val) in seen_kind:
                    continue
                seen_kind.add((rule["kind"], val))
                hits.append(self._hit(path, lineno, rule, val, mode))
        return hits

    def _hit(self, path: str, lineno: int, rule: Dict[str, Any], value: str,
             mode: str) -> Dict[str, Any]:
        risks: List[str] = []
        sev = rule["severity"]
        if rule["kind"] == "private_key":
            # 私钥只报「这里有一个私钥块」，不取样内容、也不算指纹：
            # 否则所有私钥共享同一个「指纹」，会被误报成「同一凭据在多处出现」。
            m = {"prefix": "", "length": 0, "masked": "私钥块（内容不取样）"}
            fp = ""
        else:
            m = mask(value, self.keep)
            fp = fingerprint(value)
        if mode:
            bits = int(mode, 8) if re.fullmatch(r"[0-7]{3,4}", mode) else 0
            if rule["kind"] == "private_key" and bits & 0o077:
                risks.append(f"私钥文件权限 {mode}：组/其他用户可读，应收到 0600")
                sev = "critical"
            elif bits & 0o004:
                risks.append(f"文件权限 {mode}：同机任何账号可读")
            elif bits & 0o040:
                risks.append(f"文件权限 {mode}：同组账号可读")
        if rule["kind"] in ("generic_secret", "db_url_password") and mode:
            risks.append("口令以明文形式落在配置/脚本里，应改为环境变量或钥匙串引用")
        return {
            "path": path,
            "line": lineno,
            "kind": rule["kind"],
            "kind_cn": rule["cn"],
            "severity": sev,
            "prefix": m["prefix"],
            "length": m["length"],
            "masked": m["masked"],
            "fingerprint": fp,
            "risks": risks,
        }

    def _read(self, path: str) -> Optional[str]:
        try:
            with open(path, "rb") as fh:
                raw = fh.read(self.max_bytes)
        except (OSError, PermissionError):
            return None
        if b"\x00" in raw[:4096]:
            return None
        return raw.decode("utf-8", "replace")

    # ---------- .gitignore 覆盖判定 ----------
    def _gitignore_covered(self, path: str) -> Optional[bool]:
        """返回 True=被忽略 / False=未被忽略 / None=不在 git 仓库里。"""
        cur = os.path.dirname(os.path.abspath(path))
        for _ in range(10):
            if os.path.isdir(os.path.join(cur, ".git")) or os.path.isfile(os.path.join(cur, ".git")):
                rel = os.path.relpath(os.path.abspath(path), cur).replace(os.sep, "/")
                pats: List[str] = []
                try:
                    with open(os.path.join(cur, ".gitignore"), "r", encoding="utf-8",
                              errors="replace") as fh:
                        pats = [ln.strip() for ln in fh if ln.strip() and not ln.strip().startswith("#")]
                except OSError:
                    pats = []
                name = os.path.basename(path)
                for pat in pats:
                    neg = pat.startswith("!")
                    p = pat[1:] if neg else pat
                    p = p.lstrip("/")
                    if p.endswith("/"):
                        if rel.startswith(p):
                            return not neg
                        continue
                    if fnmatch.fnmatch(rel, p) or fnmatch.fnmatch(name, p) or rel == p:
                        return not neg
                return False
            parent = os.path.dirname(cur)
            if parent == cur:
                break
            cur = parent
        return None

    # ---------- 全盘 ----------
    def scan(self, roots: Optional[List[str]] = None, limit: int = 300,
             deadline_s: Optional[float] = None) -> Dict[str, Any]:
        t0 = time.time()
        deadline = t0 + float(deadline_s if deadline_s is not None else self.max_seconds)
        roots_used = self.resolve_roots(roots)
        if not roots_used:
            return {"ok": False, "error": "没有可扫描的目录（路径不存在或被排除表挡住）",
                    "roots": [], "hits": [], "totals": {"hits": 0}}
        hits: List[Dict[str, Any]] = []
        files = 0
        seen_files: set = set()
        root_set = {os.path.abspath(r) for r in roots_used}
        skipped = {"big": 0, "binary": 0, "unreadable": 0, "whitelisted": 0, "dirs": 0}
        truncated = False
        for root in roots_used:
            for dirpath, dirnames, filenames in os.walk(root, followlinks=False,
                                                         onerror=lambda e: None):
                dirnames[:] = sorted(d for d in dirnames if not self._excluded_dir(
                    os.path.join(dirpath, d)))
                # 已经作为独立根扫过的子目录不再二次进入（否则同一文件被扫两遍）
                dirnames[:] = [d for d in dirnames
                               if os.path.join(dirpath, d) not in root_set]
                if dirpath == root and self._excluded_dir(dirpath):
                    dirnames[:] = []
                    continue
                for name in sorted(filenames):
                    if files >= self.max_files or time.time() > deadline:
                        truncated = True
                        break
                    path = os.path.join(dirpath, name)
                    if self.whitelist.path_allowed(path):
                        skipped["whitelisted"] += 1
                        continue
                    if not self._interesting(path):
                        continue
                    try:
                        st = os.stat(path)
                    except OSError:
                        skipped["unreadable"] += 1
                        continue
                    if not os.path.isfile(path) or st.st_size == 0:
                        continue
                    real = os.path.realpath(path)
                    if real in seen_files:
                        continue          # 重叠根目录（~ 与 ~/.ssh 同时给）时不重复读
                    seen_files.add(real)
                    if st.st_size > self.max_bytes:
                        skipped["big"] += 1
                        continue
                    files += 1
                    text = self._read(path)
                    if text is None:
                        skipped["binary"] += 1
                        continue
                    mode = self._mode(st)
                    file_hits = self.scan_text(text, path, mode)
                    if not file_hits:
                        continue
                    # 单文件里几十处 "token=" 通常是模板/词表，不是几十个凭据：
                    # 只留最长的 3 条并注明折叠数量，避免一条真凭据被噪声淹掉。
                    gen = [h for h in file_hits if h["kind"] == "generic_secret"]
                    if len(gen) > 3:
                        keep = sorted(gen, key=lambda h: -h["length"])[:3]
                        for h in keep:
                            h["risks"].append(
                                f"该文件共 {len(gen)} 处同类明文，已折叠其余 {len(gen) - 3} 条")
                        file_hits = [h for h in file_hits if h["kind"] != "generic_secret"] + keep
                    # 含口令的配置文件 / .env 追加「提交泄漏」风险
                    base = os.path.basename(path).lower()
                    if base.startswith(".env") or base in ("credentials", ".npmrc", ".pypirc",
                                                           ".netrc", ".git-credentials"):
                        covered = self._gitignore_covered(path)
                        if covered is False:
                            for h in file_hits:
                                h["risks"].append("该文件未被 .gitignore 覆盖：一次 git add 就会进仓库")
                            file_hits = [dict(h, severity="high") for h in file_hits]
                    hits.extend(file_hits)
                if truncated:
                    break
            if truncated:
                break

        # 同一 (文件, 行, 类型, 前缀, 长度) 只留一条：宁可少报重复，也不要满屏同一条
        uniq: Dict[Tuple[str, int, str, str, int], Dict[str, Any]] = {}
        for h in hits:
            uniq[(h["path"], h["line"], h["kind"], h["prefix"], h["length"])] = h
        hits = list(uniq.values())

        # 同一凭据跨文件复用 → 追加风险（改一处没用，得全部轮换）
        by_fp: Dict[str, List[Dict[str, Any]]] = {}
        for h in hits:
            if h["fingerprint"]:
                by_fp.setdefault(h["fingerprint"], []).append(h)
        for fp, group in by_fp.items():
            if len(group) > 1:
                for h in group:
                    h["risks"].append(f"同一凭据在 {len(group)} 处出现：需整体轮换")

        sev_floor = _SEV_ORDER.get(self.min_severity, 1)
        hits = [h for h in hits if _SEV_ORDER.get(h["severity"], 0) >= sev_floor]
        hits.sort(key=lambda h: (-_SEV_ORDER.get(h["severity"], 0), h["path"], h["line"]))

        by_kind: Dict[str, int] = {}
        by_sev: Dict[str, int] = {}
        for h in hits:
            by_kind[h["kind"]] = by_kind.get(h["kind"], 0) + 1
            by_sev[h["severity"]] = by_sev.get(h["severity"], 0) + 1

        out = {
            "ok": True,
            "ts": t0,
            "elapsed_ms": int((time.time() - t0) * 1000),
            "roots": roots_used,
            "files_scanned": files,
            "skipped": skipped,
            "truncated": truncated,
            "hits": hits[:max(1, int(limit))],
            "totals": {
                "hits": len(hits),
                "files_with_hits": len({h["path"] for h in hits}),
                "unique_secrets": len(by_fp),
                "by_kind": by_kind,
                "by_severity": by_sev,
            },
            "redaction": {"keep": self.keep,
                          "policy": "只给前 6 位 + 长度；长度 ≤6 时不显示任何字符；"
                                    "另给 sha256 前 12 位指纹用于去重"},
            "readonly": True,
            "note": "静态盘点只报告「这里躺着凭据」，不代表已被读取；"
                    "要判断是否被读，看 AEG-030/031 的行为告警。",
        }
        self.last = {k: v for k, v in out.items() if k != "hits"}
        return out

    def status(self) -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "roots": self.roots or [os.path.expanduser(r) for r in DEFAULT_ROOTS],
            "max_files": self.max_files,
            "max_bytes": self.max_bytes,
            "max_seconds": self.max_seconds,
            "mask_keep": self.keep,
            "whitelist_enabled": self.whitelist.enabled,
            "whitelist": list(self.whitelist.patterns),
            "last": self.last,
        }
