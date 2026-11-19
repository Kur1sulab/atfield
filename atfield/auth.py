"""本机账号与 RBAC：控制台不再裸奔。

之前的形态是「只绑回环、无鉴权、单人用」——拿去做产品就不成立了：
一台 Mac 上多人共用、远程拍屏、浏览器插件、本机恶意进程都能直接读态势。

这里做最小可用的一层：
    账号     scrypt 存口令（salt 每账号独立），文件 0600
    角色     viewer 只看 / analyst 研判 / responder 处置 / admin 管一切
    会话     HttpOnly Cookie 令牌，内存态，重启即失效（配 ttl）
    防爆破   单账号失败计数 → 锁定窗口；失败与解锁都进审计链
    首启     自动生成随机口令的管理员，写到 INITIAL-ADMIN.txt 并在控制台打印

只做本地认证，不碰 SSO——SSO/OIDC 是下一步，接口位置留好了（see verify_login）。
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import threading
import time
from typing import Any, Dict, List, Optional

ROLES = ("admin", "responder", "analyst", "viewer")

ROLE_CAPS: Dict[str, set] = {
    "viewer": {"read"},
    "analyst": {"read", "triage"},
    "responder": {"read", "triage", "respond"},
    "admin": {"read", "triage", "respond", "admin"},
}

ROLE_CN = {"admin": "管理员", "responder": "响应处置", "analyst": "研判分析", "viewer": "只读"}

WEAK = {"password", "passw0rd!2", "123456789", "qwertyuiop", "p@ssw0rd123", "admin12345",
        "password123", "letmein123", "changeme123", "11111111111", "atfield123456"}

SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 14, 8, 1
SCRYPT_MAXMEM = 64 * 1024 * 1024


def _hash_pw(pw: str, salt: str, n: int = SCRYPT_N, r: int = SCRYPT_R, p: int = SCRYPT_P) -> str:
    dk = hashlib.scrypt(pw.encode("utf-8"), salt=bytes.fromhex(salt),
                        n=n, r=r, p=p, dklen=32, maxmem=SCRYPT_MAXMEM)
    return dk.hex()


def pw_problem(pw: str) -> str:
    """口令策略：长度优先，拒绝明显弱口令。强度不够就明确告诉用户哪里不行。"""
    if len(pw or "") < 10:
        return "口令至少 10 位"
    if pw.lower() in WEAK:
        return "该口令在常见弱口令表里"
    kinds = sum(1 for f in (any(c.islower() for c in pw), any(c.isupper() for c in pw),
                            any(c.isdigit() for c in pw),
                            any(not c.isalnum() for c in pw)) if f)
    if kinds < 2:
        return "口令需要至少两类字符（小写/大写/数字/符号）"
    return ""


def new_password(length: int = 18) -> str:
    """生成一次性初始口令：避开易混淆字符。"""
    alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*"
    return "".join(secrets.choice(alphabet) for _ in range(length))


class Auth:
    def __init__(self, cfg: Dict[str, Any]):
        acfg = (cfg.get("server") or {}).get("auth") or {}
        self.enabled = bool(acfg.get("enabled", True))
        self.session_ttl = int(acfg.get("session_ttl", 8 * 3600))
        self.max_fail = int(acfg.get("max_fail", 5))
        self.lock_seconds = int(acfg.get("lock_seconds", 300))
        self.allow_anon_read = bool(acfg.get("allow_anon_read", False))
        self.data_dir = cfg.get("data_dir") or os.path.expanduser("~/.atfield")
        os.makedirs(self.data_dir, exist_ok=True)
        self.path = os.path.join(self.data_dir, "users.json")
        self._lock = threading.RLock()
        self._sessions: Dict[str, Dict[str, Any]] = {}
        self.audit = None                     # 由 Core 注入
        self.bootstrap_pw = ""
        self._db = self._load()
        if self.enabled:
            self._ensure_admin()

    # ---------- 持久化 ----------
    def _load(self) -> Dict[str, Any]:
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                db = json.load(fh)
            if isinstance(db, dict) and isinstance(db.get("users"), dict):
                return db
        except Exception:
            pass
        return {"version": 1, "users": {}}

    def _save(self) -> None:
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self._db, fh, ensure_ascii=False, indent=2, sort_keys=True)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self.path)
        try:
            os.chmod(self.path, 0o600)
        except Exception:
            pass

    def _ensure_admin(self) -> None:
        with self._lock:
            if self._db["users"]:
                return
            pw = new_password(20)
            self._db["users"]["admin"] = self._mk_user(pw, "admin", must_change=True)
            self._save()
            self.bootstrap_pw = pw
            note = os.path.join(self.data_dir, "INITIAL-ADMIN.txt")
            try:
                fd = os.open(note, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    fh.write("心之壁 初始管理员账号（首次登录后请立即改口令，然后删除本文件）\n"
                             f"用户名: admin\n口令:   {pw}\n"
                             f"生成时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
                             "改口令：python3 atfieldd.py --passwd admin\n")
            except Exception:
                pass
            self._audit("user.bootstrap", actor="system", role="system",
                        target="admin", result="ok",
                        detail={"note": "已生成初始管理员口令，见 INITIAL-ADMIN.txt"})

    def _mk_user(self, pw: str, role: str, must_change: bool = False) -> Dict[str, Any]:
        salt = secrets.token_hex(16)
        return {"salt": salt, "hash": _hash_pw(pw, salt), "role": role,
                "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P,
                "created": time.time(),
                "created_cn": time.strftime("%Y-%m-%d %H:%M:%S"),
                "last_login": 0.0, "last_login_cn": "", "fails": 0,
                "locked_until": 0.0, "must_change": bool(must_change)}

    def set_audit(self, audit) -> None:
        self.audit = audit

    def _audit(self, action: str, actor: str, role: str, target: str,
               result: str, detail: Optional[Dict[str, Any]] = None) -> None:
        if self.audit is not None:
            try:
                self.audit.append(action, actor=actor, role=role, target=target,
                                  result=result, detail=detail or {})
            except Exception:
                pass

    # ---------- 用户管理 ----------
    def list_users(self) -> List[Dict[str, Any]]:
        out = []
        with self._lock:
            for name, u in sorted(self._db["users"].items()):
                out.append({
                    "user": name, "role": u.get("role"),
                    "role_cn": ROLE_CN.get(str(u.get("role")), u.get("role")),
                    "must_change": bool(u.get("must_change")),
                    "locked": float(u.get("locked_until") or 0) > time.time(),
                    "created_cn": u.get("created_cn", ""),
                    "last_login_cn": u.get("last_login_cn", ""),
                    "fails": int(u.get("fails") or 0),
                })
        return out

    def add_user(self, user: str, pw: str, role: str = "viewer",
                 actor: str = "system", actor_role: str = "system") -> Dict[str, Any]:
        user = (user or "").strip()
        if not user or len(user) > 32 or any(c in user for c in " :/\\\t\n"):
            return {"ok": False, "error": "用户名非法（1-32 位，不含空格与冒号/斜杠）"}
        if role not in ROLES:
            return {"ok": False, "error": f"角色只能是 {', '.join(ROLES)}"}
        bad = pw_problem(pw)
        if bad:
            return {"ok": False, "error": bad}
        with self._lock:
            if user in self._db["users"]:
                return {"ok": False, "error": "用户已存在"}
            self._db["users"][user] = self._mk_user(pw, role)
            self._save()
        self._audit("user.add", actor=actor, role=actor_role, target=user, result="ok",
                    detail={"role": role})
        return {"ok": True, "user": user, "role": role}

    def set_password(self, user: str, pw: str, actor: str = "system",
                     actor_role: str = "system", must_change: bool = False) -> Dict[str, Any]:
        bad = pw_problem(pw)
        if bad:
            return {"ok": False, "error": bad}
        with self._lock:
            u = self._db["users"].get(user)
            if not u:
                return {"ok": False, "error": "用户不存在"}
            salt = secrets.token_hex(16)
            u.update({"salt": salt, "hash": _hash_pw(pw, salt), "must_change": bool(must_change),
                      "fails": 0, "locked_until": 0.0})
            self._save()
        self._audit("user.passwd", actor=actor, role=actor_role, target=user, result="ok")
        return {"ok": True, "user": user}

    def set_role(self, user: str, role: str, actor: str = "system",
                 actor_role: str = "system") -> Dict[str, Any]:
        if role not in ROLES:
            return {"ok": False, "error": f"角色只能是 {', '.join(ROLES)}"}
        with self._lock:
            u = self._db["users"].get(user)
            if not u:
                return {"ok": False, "error": "用户不存在"}
            if u.get("role") == "admin" and role != "admin" and self._admin_count() <= 1:
                return {"ok": False, "error": "至少要保留一个管理员"}
            u["role"] = role
            self._save()
        self._audit("user.role", actor=actor, role=actor_role, target=user, result="ok",
                    detail={"role": role})
        return {"ok": True, "user": user, "role": role}

    def delete_user(self, user: str, actor: str = "system",
                    actor_role: str = "system") -> Dict[str, Any]:
        with self._lock:
            u = self._db["users"].get(user)
            if not u:
                return {"ok": False, "error": "用户不存在"}
            if u.get("role") == "admin" and self._admin_count() <= 1:
                return {"ok": False, "error": "至少要保留一个管理员"}
            self._db["users"].pop(user, None)
            self._save()
            for tok, s in list(self._sessions.items()):
                if s.get("user") == user:
                    self._sessions.pop(tok, None)
        self._audit("user.delete", actor=actor, role=actor_role, target=user, result="ok")
        return {"ok": True, "user": user}

    def _admin_count(self) -> int:
        return sum(1 for u in self._db["users"].values() if u.get("role") == "admin")

    # ---------- 登录 / 会话 ----------
    def login(self, user: str, pw: str, ip: str = "", ua: str = "") -> Dict[str, Any]:
        if not self.enabled:
            tok = secrets.token_urlsafe(24)
            with self._lock:
                self._sessions[tok] = {"user": "local", "role": "admin",
                                       "exp": time.time() + self.session_ttl,
                                       "ip": ip, "created": time.time()}
            return {"ok": True, "token": tok, "user": "local", "role": "admin",
                    "role_cn": "管理员（鉴权已关闭）", "must_change": False}
        user = (user or "").strip()
        with self._lock:
            u = self._db["users"].get(user)
            now = time.time()
            if u and float(u.get("locked_until") or 0) > now:
                left = int(float(u["locked_until"]) - now)
                self._audit("auth.login", actor=user, role="?", target=ip, result="locked",
                            detail={"理由": "账号锁定中", "剩余秒": left})
                return {"ok": False, "error": f"账号已锁定，{left} 秒后重试"}
            if not u:
                # 不区分「用户不存在」与「口令错误」，避免被用来枚举账号
                self._audit("auth.login", actor=user or "-", role="?", target=ip,
                            result="deny", detail={"理由": "账号或口令错误"})
                return {"ok": False, "error": "账号或口令错误"}
            calc = _hash_pw(pw or "", u["salt"], int(u.get("n") or SCRYPT_N),
                            int(u.get("r") or SCRYPT_R), int(u.get("p") or SCRYPT_P))
            if not secrets.compare_digest(calc, str(u.get("hash") or "")):
                u["fails"] = int(u.get("fails") or 0) + 1
                locked = u["fails"] >= self.max_fail
                if locked:
                    u["locked_until"] = now + self.lock_seconds
                    u["fails"] = 0
                self._save()
                self._audit("auth.login", actor=user, role=str(u.get("role")),
                            target=ip, result="deny",
                            detail={"理由": "口令错误", "连续失败": u.get("fails"),
                                    "已锁定": locked})
                msg = f"口令错误次数过多，账号锁定 {self.lock_seconds} 秒" if locked else "账号或口令错误"
                return {"ok": False, "error": msg, "locked": locked}
            u["fails"] = 0
            u["locked_until"] = 0.0
            u["last_login"] = now
            u["last_login_cn"] = time.strftime("%Y-%m-%d %H:%M:%S")
            self._save()
            tok = secrets.token_urlsafe(32)
            self._sessions[tok] = {"user": user, "role": str(u.get("role")),
                                   "exp": now + self.session_ttl, "ip": ip,
                                   "created": now}
        self._audit("auth.login", actor=user, role=str(u.get("role")), target=ip, result="ok",
                    detail={"界面": (ua or "")[:80]})
        return {"ok": True, "token": tok, "user": user, "role": u.get("role"),
                "role_cn": ROLE_CN.get(str(u.get("role")), ""),
                "must_change": bool(u.get("must_change"))}

    def session(self, token: str) -> Optional[Dict[str, Any]]:
        """令牌 → 会话。过期即清；关闭鉴权时给匿名管理员（本机单人模式）。"""
        now = time.time()
        with self._lock:
            if not self.enabled:
                return {"user": "local", "role": "admin", "exp": now + 60, "ip": "", "created": now}
            s = self._sessions.get(token or "")
            if not s:
                return None
            if float(s.get("exp") or 0) <= now:
                self._sessions.pop(token, None)
                return None
            return s

    def logout(self, token: str, ip: str = "") -> Dict[str, Any]:
        with self._lock:
            s = self._sessions.pop(token or "", None)
        if s:
            self._audit("auth.logout", actor=s.get("user"), role=str(s.get("role")),
                        target=ip, result="ok")
        return {"ok": True}

    def sweep_sessions(self) -> int:
        now = time.time()
        with self._lock:
            dead = [t for t, s in self._sessions.items() if float(s.get("exp") or 0) <= now]
            for t in dead:
                self._sessions.pop(t, None)
        return len(dead)

    # ---------- 授权 ----------
    @staticmethod
    def caps(role: str) -> set:
        return ROLE_CAPS.get(role, {"read"})

    @classmethod
    def can(cls, role: str, cap: str) -> bool:
        return cap in cls.caps(role)

    def status(self) -> Dict[str, Any]:
        with self._lock:
            users = self.list_users()
            return {
                "enabled": self.enabled,
                "users": len(users),
                "sessions": len(self._sessions),
                "session_ttl": self.session_ttl,
                "max_fail": self.max_fail,
                "lock_seconds": self.lock_seconds,
                "admins": sum(1 for u in self._db["users"].values() if u.get("role") == "admin"),
                "pending_change": sum(1 for u in self._db["users"].values()
                                      if u.get("must_change")),
                "roles": [{"role": r, "cn": ROLE_CN[r], "caps": sorted(ROLE_CAPS[r])}
                          for r in ROLES],
                "bootstrap_file": os.path.join(self.data_dir, "INITIAL-ADMIN.txt")
                if self.bootstrap_pw or os.path.isfile(os.path.join(self.data_dir,
                                                                    "INITIAL-ADMIN.txt")) else "",
            }
