"""报告导出：把当前态势渲染成可交付的 Markdown（可直接贴进工单/周报）。"""
from __future__ import annotations

import json
import time
from typing import Any, Dict, List

from . import __version__
from .model import SEVERITY_CN, STATUS_CN, iso


def _md_escape(s: Any) -> str:
    return str(s if s is not None else "").replace("|", "\\|").replace("\n", " ")


def build(core) -> str:
    ov = core.overview()
    st = core.store
    base = st.get_state("baseline") or {}
    procs = st.get_state("processes") or {}
    net = st.get_state("connections") or {}
    sess = st.get_state("sessions") or {}
    pers = st.get_state("persistence") or {}
    integ = st.get_state("integrity") or {}
    findings = st.snapshot_findings(500)
    incidents = st.snapshot_incidents(50)

    L: List[str] = []
    L.append("# 心之壁 终端态势报告")
    L.append("")
    L.append(f"- 生成时间：{ov['now']}")
    L.append(f"- 主机：`{ov['host']}`　用户：`{ov['user']}`　平台：{ov['platform']}")
    L.append(f"- 心之壁 版本：{__version__}　已运行：{ov['uptime'] // 60} 分钟（启动于 {ov['started_at']}）")
    L.append("")

    L.append("## 一、态势结论")
    L.append("")
    L.append(f"> {ov['verdict']}")
    L.append("")
    t = ov["threat"]
    L.append(f"- 风险指数 **{t['risk']} / 100（{t['level']}）**，1 小时内新增告警 {t['recent_1h']} 条")
    L.append(f"- 防护健康度 **{ov['health']['health']} / 100（{ov['health']['grade']}）**")
    L.append(f"- 累计事件 {ov['totals']['events']} 条，规则命中 {ov['totals']['findings']} 条，攻击链 {ov['totals']['incidents']} 条")
    L.append("")

    L.append("## 二、防护健康度分维度")
    L.append("")
    L.append("| 维度 | 得分 | 检查项 | 不合格 | 主要短板 |")
    L.append("|---|---|---|---|---|")
    for d in ov["health"]["dimensions"]:
        L.append(f"| {d['name']} | {d['score']} | {d['checks']} | {d['failed']} | {_md_escape(d['top_issue']) or '—'} |")
    L.append("")

    L.append("## 三、攻击链（按时间串起来的攻击叙事）")
    L.append("")
    if not incidents:
        L.append("暂无跨阶段攻击链命中。")
    for inc in incidents:
        L.append(f"### {inc['template_id']} {inc['title']}")
        L.append("")
        L.append(f"- 严重程度：**{inc['severity_cn']}**　评分：{inc['score']}")
        L.append(f"- 时间：{inc['first_time']} → {inc['last_time']}（持续 {inc['duration']}s）")
        L.append(f"- 归属：`{inc['actor']}`")
        L.append("")
        L.append("| 阶段 | 命中规则 | 证据 | 时间 |")
        L.append("|---|---|---|---|")
        for s in inc["stages"]:
            L.append(f"| {s['stage']} | {s['rule_id']} {_md_escape(s['rule_name'])} | "
                     f"{_md_escape((s['detail'] or '')[:110])} | {s['time']} |")
        L.append("")
        L.append(f"**判断**：{inc['summary']}")
        L.append("")
        L.append(f"**处置建议**：{inc['advice']}")
        L.append("")

    L.append("## 四、重大发现（高危及以上）")
    L.append("")
    serious = [f for f in findings if f.get("severity") in ("high", "critical")]
    if not serious:
        L.append("未发现高危及以上事件。")
    else:
        L.append("| 时间 | 等级 | 规则 | 对象 | 证据 |")
        L.append("|---|---|---|---|---|")
        for f in serious[:40]:
            ev = f.get("event") or {}
            obj = ev.get("process") or ev.get("path") or "-"
            L.append(f"| {f['time']} | {f['severity_cn']} | {f['rule_id']} {_md_escape(f['name'])} | "
                     f"`{_md_escape(obj)[:50]}` | {_md_escape((f.get('detail') or '')[:120])} |")
    L.append("")

    L.append("## 五、安全基线明细")
    L.append("")
    results = base.get("results") or []
    by_cat: Dict[str, List[dict]] = {}
    for r in results:
        by_cat.setdefault(r.get("category") or "其他", []).append(r)
    for cat, items in by_cat.items():
        L.append(f"### {cat}")
        L.append("")
        L.append("| 检查项 | 状态 | 证据 | 建议 |")
        L.append("|---|---|---|---|")
        for r in items:
            L.append(f"| {r['name']} | {STATUS_CN.get(r['status'], r['status'])} | "
                     f"{_md_escape((r.get('evidence') or '')[:110])} | {_md_escape((r.get('advice') or '—')[:110])} |")
        L.append("")

    L.append("## 六、终端资产与暴露面")
    L.append("")
    listeners = net.get("listeners") or []
    L.append(f"### 监听端口（{len(listeners)}）")
    L.append("")
    if listeners:
        L.append("| 地址 | 协议 | 进程 | 用户 |")
        L.append("|---|---|---|---|")
        for li in listeners[:40]:
            L.append(f"| {li.get('laddr')} | {li.get('type')} | {li.get('process')}({li.get('pid')}) | {li.get('user')} |")
    else:
        L.append("无监听端口数据（可能权限不足）。")
    L.append("")

    L.append(f"### 登录会话（{len(sess.get('active') or [])}）")
    L.append("")
    active = sess.get("active") or []
    if active:
        L.append("| 用户 | 终端 | 来源 | 开始 |")
        L.append("|---|---|---|---|")
        for s in active:
            L.append(f"| {s.get('user')} | {s.get('tty')} | {s.get('from') or '本地'} | {s.get('since')} |")
    else:
        L.append("无活动会话。")
    L.append("")

    sus = pers.get("suspicious") or []
    L.append(f"### 持久化项（共 {pers.get('count', 0)}，可疑 {len(sus)}）")
    L.append("")
    if sus:
        L.append("| Label | 路径 | 可疑点 |")
        L.append("|---|---|---|")
        for p in sus[:20]:
            L.append(f"| {_md_escape(p.get('label'))} | `{_md_escape(p.get('path'))}` | {_md_escape('; '.join(p.get('suspicious') or []))} |")
    else:
        L.append("未发现可疑持久化项。")
    L.append("")

    L.append("### 关键文件完整性")
    L.append("")
    files = integ.get("files") or []
    if files:
        L.append("| 文件 | 存在 | 可读 | SHA256(前16) |")
        L.append("|---|---|---|---|")
        for f in files[:30]:
            L.append(f"| `{_md_escape(f.get('path'))}` | {'是' if f.get('exists') else '否'} | "
                     f"{'是' if f.get('readable') else '否'} | `{f.get('digest') or '-'}` |")
    else:
        L.append("无完整性数据。")
    L.append("")

    L.append("## 七、遥测与采集器状态")
    L.append("")
    L.append("| 采集器 | 模式 | 状态 | 周期 | 运行次数 | 错误 | 备注 |")
    L.append("|---|---|---|---|---|---|---|")
    for c in ov["collectors"]:
        state = "运行中" if c.get("enabled") else ("不满足条件" if not c.get("available") else "已关闭")
        L.append(f"| {c['name']} | {c['mode']} | {state} | {c['interval'] or '流式'}s | "
                 f"{c.get('runs', 0)} | {c.get('errors', 0)} | {_md_escape((c.get('reason') or '')[:60])} |")
    L.append("")

    L.append("## 八、检测覆盖")
    L.append("")
    catalog = core.engine.catalog()
    mitre = sorted({m for r in catalog for m in r["mitre"]})
    L.append(f"- 内建规则 **{len(catalog)}** 条，攻击链模板 **{len(core.correlator.catalog())}** 条")
    L.append(f"- 覆盖 MITRE ATT&CK 技术：{', '.join(mitre)}")
    L.append("")

    L.append("## 九、响应动作审计")
    L.append("")
    acts = st.meta.get("actions") or []
    if acts:
        L.append("| 时间 | 动作 | 目标 | 结果 |")
        L.append("|---|---|---|---|")
        for a in acts[-30:]:
            L.append(f"| {a.get('time')} | {a.get('action')} | {_md_escape(a.get('target'))} | {_md_escape(a.get('result'))} |")
    else:
        L.append("本会话尚未执行任何响应动作。")
    L.append("")
    L.append("## 十、主动防御：诱饵（Canary）")
    L.append("")
    can = core.canary.status()
    L.append(f"当前部署诱饵 **{can.get('count', 0)}** 个，被触碰 **{can.get('trips', 0)}** 个。")
    L.append("")
    if can.get("items"):
        L.append("| 诱饵文件 | 说明 | 触碰次数 |")
        L.append("|---|---|---|")
        for it in can["items"][:20]:
            L.append(f"| `{_md_escape(it.get('path'))}` | {_md_escape(it.get('note'))} | {it.get('trips', 0)} |")
        L.append("")
    L.append("> 诱饵文件不会被任何正常业务访问，一旦被读取即按入侵事件处理；"
             "误报率显著低于行为规则。")
    L.append("")

    L.append("## 十一、行为基线（UEBA）与网络检测（NDR）")
    L.append("")
    u = core.ueba.status()
    L.append(f"- 行为基线：已知进程名 {u.get('known_processes', 0)} 个、已知可执行路径 "
             f"{u.get('known_exe', 0)} 个、已知外联地址 {u.get('known_remote', 0)} 个"
             f"（学习期：{'是' if u.get('learning') else '否'}，累计样本 {u.get('samples', 0)}）")
    nd = core.netintel.status()
    L.append(f"- 网络画像：观测目的地 {nd.get('destinations', 0)} 个，其中未解析域名 "
             f"{nd.get('unresolved', 0)} 个；疑似信标 **{nd.get('beacon_count', 0)}** 条")
    L.append("")
    if nd.get("beacons"):
        L.append("| 进程 | 目的地 | 平均间隔 | 波动 | 样本 |")
        L.append("|---|---|---|---|---|")
        for b in nd["beacons"][:10]:
            L.append(f"| {_md_escape(b.get('process'))} | {b.get('ip')}:{b.get('port')} | "
                     f"{b.get('interval_s')}s | {b.get('cv')} | {b.get('samples')} |")
        L.append("")
    if nd.get("flags"):
        L.append("| 类型 | 说明 | 等级 |")
        L.append("|---|---|---|")
        for fl in nd["flags"][:15]:
            L.append(f"| {fl.get('kind')} | {_md_escape((fl.get('text') or '')[:120])} | "
                     f"{SEVERITY_CN.get(fl.get('severity'), fl.get('severity'))} |")
        L.append("")

    L.append("## 十二、威胁情报（IOC）")
    L.append("")
    it = core.intel.stats()
    L.append(f"- 本地情报库：IP {it.get('ip', 0)} 条、域名 {it.get('domain', 0)} 条、"
             f"哈希 {it.get('hash', 0)} 条；内建风险类别 {it.get('builtin_categories', 0)} 条")
    L.append(f"- 库文件：`{it.get('path')}`")
    L.append("")
    L.append("> 内建的是**类别规则**（动态 DNS / 隧道服务 / 高滥用 TLD），不是编造的具体 IOC；"
             "具体 IOC 需由使用方从自有情报源导入。")
    L.append("")

    L.append("## 十三、SOAR 剧本与处置工单")
    L.append("")
    pb = core.playbooks.status()
    L.append(f"- 已加载剧本 **{pb.get('count', 0)}** 个，待人工确认动作 **{len(pb.get('pending') or [])}** 个，"
             f"本轮触发记录 **{len(pb.get('history') or [])}** 条")
    L.append("")
    if pb.get("items"):
        L.append("| 剧本 | 名称 | 触发条件 | 动作 | 需确认 |")
        L.append("|---|---|---|---|---|")
        for p in pb["items"]:
            L.append(f"| {p.get('id')} | {_md_escape(p.get('name'))} | "
                     f"`{json.dumps(p.get('when') or {}, ensure_ascii=False)}` | "
                     f"{', '.join(p.get('actions') or [])} | {'是' if p.get('require_confirm') else '否'} |")
        L.append("")
    tks = st.snapshot_tickets(30)
    L.append(f"### 工单（{len(tks)}）")
    L.append("")
    if tks:
        L.append("| 工单 | 标题 | 等级 | 状态 | 来源 | 创建 |")
        L.append("|---|---|---|---|---|---|")
        for tk in tks:
            L.append(f"| {tk['tid']} | {_md_escape(tk['title'])} | "
                     f"{SEVERITY_CN.get(tk['severity'], tk['severity'])} | {tk['status']} | "
                     f"{tk.get('source')} | {tk.get('created_cn')} |")
    else:
        L.append("暂无工单。")
    L.append("")

    L.append("## 十四、资产与软件清单")
    L.append("")
    inv = core.inventory.status()
    L.append(f"- 已登记应用 **{inv.get('apps', 0)}** 个；超过 18 个月未更新 {inv.get('stale_count', 0)} 个；"
             f"签名校验失败 {inv.get('unsigned_count', 0)} 个；远程控制类 {len(inv.get('remote') or [])} 个")
    L.append("")
    if inv.get("remote"):
        L.append("| 远程控制软件 | 版本 | 路径 |")
        L.append("|---|---|---|")
        for a in inv["remote"][:15]:
            L.append(f"| {_md_escape(a.get('name'))} | {_md_escape(a.get('version'))} | "
                     f"`{_md_escape(a.get('path'))}` |")
        L.append("")
    if inv.get("stale"):
        L.append("| 长期未更新 | 版本 | 最后修改 |")
        L.append("|---|---|---|")
        for a in inv["stale"][:15]:
            L.append(f"| {_md_escape(a.get('name'))} | {_md_escape(a.get('version'))} | {a.get('modified_cn')} |")
        L.append("")

    L.append("## 十五、合规矩阵（CIS / 等保三级）")
    L.append("")
    comp = core.compliance_state or {}
    for fw, sc in (comp.get("frameworks") or {}).items():
        L.append(f"- **{fw}**：得分 {sc.get('score')} / 100（通过 {sc.get('pass')}，"
                 f"不合格 {sc.get('fail')}，警告 {sc.get('warn')}，未判定 {sc.get('unknown')}）")
    L.append("")
    rows = comp.get("rows") or []
    if rows:
        L.append("| 条款 | 框架 | 要求 | 状态 |")
        L.append("|---|---|---|---|")
        for r in rows:
            mark = {"pass": "通过", "fail": "不合格", "warn": "警告",
                    "unknown": "未判定", "gap": "未覆盖"}.get(r["status"], r["status"])
            L.append(f"| {r['control']} | {r['framework']} | {_md_escape(r['title'])} | {mark} |")
        L.append("")
    L.append(f"> {comp.get('basis', '')}")
    L.append("")
    L.append("---")
    L.append("")
    L.append("*本报告由 心之壁 自动生成：所有数据来自本机实时采集，未做人工修饰；"
             "「未知」项表示当前权限不足以判定，不代表安全。*")
    return "\n".join(L)
