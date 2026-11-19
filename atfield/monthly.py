"""月度报告：给不登控制台的人看的那个东西。

安全产品最终要交的不是界面，是一份「这个月这台机器发生了什么、我们做了什么、
还有哪些没闭合」的纸。甲方安全负责人、等保测评、老板预算会都看这一份。

产出
    MD   给技术看、进知识库
    HTML 给邮件看（内联样式，邮件客户端不加载外部 CSS）
    落盘 ~/.atfield/exports/monthly/<YYYY-MM>/
投递
    config.yaml 里配 monthly.smtp 就用 SMTP 发；没配不报错，只落盘并在结果里说明原因，
    绝不假装发送成功。
"""
from __future__ import annotations

import html
import json
import os
import smtplib
import ssl
import time
from email.message import EmailMessage
from email.utils import formataddr, formatdate
from typing import Any, Dict, List, Optional

from . import __version__, scoring
from .model import SEVERITY_CN

SEV_ORDER = ["critical", "high", "medium", "low", "info"]


def _month_bounds(month: str) -> tuple:
    """'2026-11' → (起, 止) 时间戳；非法则退回本月。"""
    now = time.localtime()
    year, mon = now.tm_year, now.tm_mon
    try:
        if month:
            parts = str(month).split("-")
            year, mon = int(parts[0]), int(parts[1])
            if not 1 <= mon <= 12:
                raise ValueError
    except Exception:
        year, mon = now.tm_year, now.tm_mon
    start = time.mktime((year, mon, 1, 0, 0, 0, 0, 0, -1))
    if mon == 12:
        end = time.mktime((year + 1, 1, 1, 0, 0, 0, 0, 0, -1))
    else:
        end = time.mktime((year, mon + 1, 1, 0, 0, 0, 0, 0, -1))
    return start, end, f"{year:04d}-{mon:02d}"


def _top(counter: Dict[str, int], n: int = 8) -> List[Dict[str, Any]]:
    return [{"name": k, "count": v} for k, v in
            sorted(counter.items(), key=lambda kv: kv[1], reverse=True)[:n]]


def collect(core, month: str = "") -> Dict[str, Any]:
    """把一个月的数据从各引擎里捞出来，形成纯数据（渲染与投递都基于它）。"""
    st = core.store
    start, end, label = _month_bounds(month)
    findings = [f for f in st.snapshot_findings(100000)
                if start <= float(f.get("ts") or 0) < end]
    incidents = [i for i in st.snapshot_incidents(100000)
                 if start <= float(i.get("last_seen") or i.get("ts") or 0) < end]
    tickets = [t for t in st.snapshot_tickets(5000)
               if start <= float(t.get("created") or 0) < end]
    actions = [a for a in (st.meta.get("actions") or [])
               if start <= float(a.get("ts") or 0) < end]

    sev: Dict[str, int] = {s: 0 for s in SEV_ORDER}
    rules: Dict[str, int] = {}
    actors: Dict[str, int] = {}
    hours: Dict[str, int] = {}
    for f in findings:
        s = str(f.get("severity") or "info")
        sev[s] = sev.get(s, 0) + 1
        rid = str(f.get("rule_id") or "?")
        rules[rid] = rules.get(rid, 0) + 1
        act = str(f.get("actor") or "").strip() or "（未归属）"
        actors[act] = actors.get(act, 0) + 1
        h = time.strftime("%H", time.localtime(float(f.get("ts") or 0)))
        hours[h] = hours.get(h, 0) + 1

    open_t = [t for t in tickets if t.get("status") == "open"]
    ack_t = [t for t in tickets if t.get("status") == "ack"]
    closed_t = [t for t in tickets if t.get("status") == "closed"]
    mttr = 0.0
    if closed_t:
        spans = [max(0.0, float(t.get("updated") or t.get("created") or 0)
                     - float(t.get("created") or 0)) for t in closed_t]
        mttr = sum(spans) / len(spans) / 3600.0

    action_kinds: Dict[str, int] = {}
    for a in actions:
        k = str(a.get("action") or "?")
        action_kinds[k] = action_kinds.get(k, 0) + 1

    # 审计链：只取本月，且必带一次全链校验结论
    audit_rows: List[Dict[str, Any]] = []
    audit_verify: Dict[str, Any] = {}
    if getattr(core, "audit", None) is not None:
        try:
            audit_verify = core.audit.verify()
            for row in core.audit.tail(20000):
                if start <= float(row.get("ts") or 0) < end:
                    audit_rows.append(row)
        except Exception:
            audit_verify = {"ok": False, "issues": [{"type": "verify_failed"}]}
    actor_kinds: Dict[str, int] = {}
    for row in audit_rows:
        act = str(row.get("action") or "?")
        actor_kinds[act] = actor_kinds.get(act, 0) + 1

    try:
        posture = scoring.posture(st.get_state("baseline") or {})
    except Exception:
        posture = {}
    try:
        threat = scoring.threat(st.snapshot_findings(500), st.snapshot_incidents(50))
    except Exception:
        threat = {}
    intel_raw: Dict[str, Any] = {}
    if hasattr(core, "intel"):
        try:
            intel_raw = core.intel.stats()
        except Exception:
            intel_raw = {}
    canary_raw: Dict[str, Any] = {}
    if hasattr(core, "canary"):
        try:
            canary_raw = core.canary.status()
        except Exception:
            canary_raw = {}

    data = {
        "month": label,
        "range_cn": f"{time.strftime('%Y-%m-%d', time.localtime(start))} ~ "
                    f"{time.strftime('%Y-%m-%d', time.localtime(end - 1))}",
        "generated_cn": time.strftime("%Y-%m-%d %H:%M:%S"),
        "host": getattr(core, "host", ""),
        "version": __version__,
        "counts": {
            "findings": len(findings),
            "incidents": len(incidents),
            "tickets": len(tickets),
            "actions": len(actions),
            "audit": len(audit_rows),
        },
        "severity": sev,
        "top_rules": _top(rules, 10),
        "top_actors": _top(actors, 6),
        "hours": [{"hour": h, "count": hours.get(h, 0)} for h in
                  sorted(hours, key=lambda x: int(x))],
        "incidents": [{
            "title": i.get("title"), "severity": i.get("severity"),
            "severity_cn": SEVERITY_CN.get(str(i.get("severity")), i.get("severity")),
            "first": i.get("first_time") or "", "last": i.get("last_time") or "",
            "score": i.get("score"), "stages": len(i.get("stages") or []),
            "summary": (i.get("summary") or "")[:300],
        } for i in sorted(incidents, key=lambda x: float(x.get("score") or 0),
                          reverse=True)[:12]],
        "tickets": {
            "open": len(open_t), "ack": len(ack_t), "closed": len(closed_t),
            "mttr_hours": round(mttr, 1),
            "items": [{"tid": t.get("tid"), "title": t.get("title"),
                       "severity": t.get("severity"), "status": t.get("status"),
                       "created": t.get("created_cn"), "owner": t.get("owner") or ""}
                      for t in tickets[:15]],
        },
        "actions": {"total": len(actions), "kinds": _top(action_kinds, 8),
                    "items": [{"time": time.strftime("%m-%d %H:%M", time.localtime(
                        float(a.get("ts") or 0))),
                        "actor": a.get("actor"), "action": a.get("action"),
                        "target": str(a.get("target") or "")[:80],
                        "result": a.get("result")} for a in actions[:15]]},
        "audit": {
            "records": len(audit_rows),
            "verify": {"ok": bool(audit_verify.get("ok")),
                       "checked": audit_verify.get("checked"),
                       "anchor_state": audit_verify.get("anchor_state"),
                       "issue_count": audit_verify.get("issue_count"),
                       "issues": audit_verify.get("issues", [])[:5]},
            "kinds": _top(actor_kinds, 10),
        },
        "posture": {
            "health": (posture.get("health") if isinstance(posture, dict) else None),
            "grade": (posture.get("grade") if isinstance(posture, dict) else None),
            "dims": [{ "name": d.get("name"), "score": d.get("score"),
                       "failed": d.get("failed")}
                     for d in ((posture.get("dimensions") or []) if isinstance(posture, dict) else [])],
        },
        "threat": {"risk": (threat.get("risk") if isinstance(threat, dict) else None),
                   "level": (threat.get("level") if isinstance(threat, dict) else None)},
        "compliance": (core.compliance_state or st.get_state("compliance") or {}),
        "intel": {"domains": intel_raw.get("domain", 0), "ips": intel_raw.get("ip", 0),
                  "hashes": intel_raw.get("hash", 0)},
        "canary": {"deployed": canary_raw.get("count", 0),
                   "trips": canary_raw.get("trips", 0)},
    }
    data["advice"] = _advice(data)
    return data


def _advice(d: Dict[str, Any]) -> List[str]:
    """结论要能落地：按数据说话，不写空话。"""
    out: List[str] = []
    sev = d.get("severity") or {}
    crit = int(sev.get("critical") or 0)
    high = int(sev.get("high") or 0)
    if crit:
        out.append(f"本月有 {crit} 条严重告警，逐条确认是否已闭环；未闭环的严重项在下月报告中会被重复计入。")
    if high > 5:
        out.append(f"高危告警 {high} 条偏多，建议先按规则看 TOP 规则，把误报规则做抑制或调参，"
                   f"否则真实告警会被噪声淹没。")
    tk = d.get("tickets") or {}
    if int(tk.get("open") or 0) and not int(tk.get("closed") or 0):
        out.append("工单只有开没有关：处置闭环率是这类产品最容易被质疑的一项，本月没有任何闭环记录。")
    if not int(tk.get("mttr_hours") or 0) and int(tk.get("closed") or 0):
        out.append("工单平均闭环时长缺失，检查关闭工单时是否填了备注与状态。")
    audit = d.get("audit") or {}
    if not (audit.get("verify") or {}).get("ok"):
        out.append("审计链校验未通过！立即排查：日志文件被改动、被截断或锚点被替换，取证可信度已受影响。")
    elif not int(audit.get("records") or 0):
        out.append("本月审计链没有记录，说明控制台没有被操作过，或审计写入没有生效。")
    posture = d.get("posture") or {}
    dims = [x for x in (posture.get("dims") or []) if int(x.get("failed") or 0) > 0]
    if dims:
        worst = sorted(dims, key=lambda x: float(x.get("score") or 0))[0]
        out.append(f"防护健康度短板在「{worst.get('name')}」（{worst.get('failed')} 项不合格），"
                   f"优先修这一类，收益最大。")
    if not out:
        out.append("本月未见需要特别处置的问题；继续保持每周复核一次告警分布。")
    return out


# ---------------- 渲染 ----------------
def render_md(d: Dict[str, Any]) -> str:
    L: List[str] = []
    L.append(f"# 终端安全月度报告 · {d['month']}")
    L.append("")
    L.append(f"- 统计区间：{d['range_cn']}")
    L.append(f"- 主机：{d['host']}　产品版本：{d['version']}")
    L.append(f"- 生成时间：{d['generated_cn']}")
    L.append("")
    L.append("## 一、本月概览")
    L.append("")
    c = d["counts"]
    L.append("| 指标 | 数量 |")
    L.append("| --- | --- |")
    L.append(f"| 告警（规则命中） | {c['findings']} |")
    L.append(f"| 攻击链 | {c['incidents']} |")
    L.append(f"| 工单 | {c['tickets']} |")
    L.append(f"| 处置动作 | {c['actions']} |")
    L.append(f"| 审计记录 | {c['audit']} |")
    L.append("")
    sev = d["severity"]
    _sev_line = "　".join(f"{SEVERITY_CN.get(s, s)} {sev.get(s, 0)}"
                         for s in SEV_ORDER if sev.get(s))
    L.append("严重度分布：" + (_sev_line or "本月无告警"))
    L.append("")
    L.append("## 二、风险与防护健康度")
    L.append("")
    th = d.get("threat") or {}
    po = d.get("posture") or {}
    L.append(f"- 风险指数：{th.get('risk')}（{th.get('level')}）")
    L.append(f"- 防护健康度：{po.get('health')}（{po.get('grade')}）")
    for dim in po.get("dims") or []:
        if int(dim.get("failed") or 0) > 0:
            L.append(f"  - {dim.get('name')}：得分 {dim.get('score')}，不合格 {dim.get('failed')} 项")
    L.append("")
    L.append("## 三、TOP 告警规则")
    L.append("")
    if d["top_rules"]:
        L.append("| 规则 | 命中 |")
        L.append("| --- | --- |")
        for r in d["top_rules"]:
            L.append(f"| {r['name']} | {r['count']} |")
    else:
        L.append("本月无告警。")
    L.append("")
    L.append("## 四、攻击链")
    L.append("")
    if d["incidents"]:
        for i in d["incidents"]:
            L.append(f"- **[{i['severity_cn']}] {i['title']}**（{i['stages']} 阶段，"
                     f"评分 {i['score']}）　{i['first']} → {i['last']}")
            if i["summary"]:
                L.append(f"  - {i['summary']}")
    else:
        L.append("本月未形成多阶段攻击链。")
    L.append("")
    L.append("## 五、处置动作")
    L.append("")
    if d["actions"]["total"]:
        L.append("动作类型：" + "　".join(f"{k['name']} {k['count']}" for k in d["actions"]["kinds"]))
        L.append("")
        L.append("| 时间 | 操作人 | 动作 | 目标 | 结果 |")
        L.append("| --- | --- | --- | --- | --- |")
        for a in d["actions"]["items"]:
            L.append(f"| {a['time']} | {a['actor']} | {a['action']} | {a['target']} | {a['result']} |")
    else:
        L.append("本月无处置动作（未执行隔离/挂起/终止等）。")
    L.append("")
    L.append("## 六、工单与闭环")
    L.append("")
    tk = d["tickets"]
    L.append(f"- 打开 {tk['open']}　处理中 {tk['ack']}　已关闭 {tk['closed']}　"
             f"平均闭环 {tk['mttr_hours']} 小时")
    if tk["items"]:
        L.append("")
        L.append("| 工单 | 标题 | 严重度 | 状态 | 创建 | 负责人 |")
        L.append("| --- | --- | --- | --- | --- | --- |")
        for t in tk["items"]:
            L.append(f"| {t['tid']} | {t['title']} | {SEVERITY_CN.get(str(t['severity']), t['severity'])} "
                     f"| {t['status']} | {t['created']} | {t['owner'] or '—'} |")
    L.append("")
    L.append("## 七、合规与情报")
    L.append("")
    comp = d.get("compliance") or {}
    fr = comp.get("frameworks") or comp.get("scores") or {}
    if isinstance(fr, dict) and fr:
        for name, val in fr.items():
            if isinstance(val, dict):
                L.append(f"- {name}：{val.get('score', '—')} 分（{val.get('grade', '')}）")
    else:
        L.append("- 合规框架评分暂无数据（运行一次合规评估后写入）。")
    intel = d.get("intel") or {}
    if intel:
        L.append(f"- 情报库：域名 {intel.get('domains', 0)} 条 / IP {intel.get('ips', 0)} 条"
                 f" / 哈希 {intel.get('hashes', 0)} 条")
    canary = d.get("canary") or {}
    if canary:
        L.append(f"- 诱饵：部署 {canary.get('deployed', 0)} 个，本月触碰 {canary.get('trips', 0)} 个")
    L.append("")
    L.append("## 八、审计链")
    L.append("")
    av = d["audit"]["verify"]
    L.append(f"- 本月审计记录 {d['audit']['records']} 条")
    L.append(f"- 全链校验：{'通过' if av.get('ok') else '**未通过**'}　"
             f"校验条数 {av.get('checked')}　锚点状态 {av.get('anchor_state')}")
    if d["audit"]["kinds"]:
        L.append("- 动作分布：" + "　".join(f"{k['name']} {k['count']}" for k in d["audit"]["kinds"]))
    if av.get("issues"):
        L.append("- 问题：" + json.dumps(av["issues"], ensure_ascii=False))
    L.append("")
    L.append("## 九、结论与建议")
    L.append("")
    for i, line in enumerate(d.get("advice") or [], 1):
        L.append(f"{i}. {line}")
    L.append("")
    L.append("---")
    L.append(f"本报告由 心之壁 v{d['version']} 自动生成；原始数据保留在本机 "
             f"`~/.atfield`，可按时间线复核。")
    return "\n".join(L) + "\n"


def render_html(d: Dict[str, Any]) -> str:
    e = html.escape
    sev = d["severity"]
    rows_top = "".join(
        f"<tr><td style='padding:6px 10px;border-bottom:1px solid #eceff3'>{e(str(r['name']))}</td>"
        f"<td style='padding:6px 10px;border-bottom:1px solid #eceff3;text-align:right'>{r['count']}</td></tr>"
        for r in d["top_rules"]) or "<tr><td colspan='2' style='padding:8px 10px;color:#6b7280'>本月无告警</td></tr>"
    rows_inc = "".join(
        f"<tr><td style='padding:6px 10px;border-bottom:1px solid #eceff3'>{e(str(i['severity_cn']))}</td>"
        f"<td style='padding:6px 10px;border-bottom:1px solid #eceff3'>{e(str(i['title']))}</td>"
        f"<td style='padding:6px 10px;border-bottom:1px solid #eceff3;text-align:right'>{i['stages']}</td>"
        f"<td style='padding:6px 10px;border-bottom:1px solid #eceff3;text-align:right'>{i['score']}</td></tr>"
        for i in d["incidents"]) or "<tr><td colspan='4' style='padding:8px 10px;color:#6b7280'>本月未形成攻击链</td></tr>"
    tk = d["tickets"]
    av = d["audit"]["verify"]
    advice = "".join(f"<li style='margin:6px 0'>{e(x)}</li>" for x in d.get("advice") or [])
    chip = lambda s: ("#b42318" if s == "critical" else "#b54708" if s == "high"
                      else "#175cd3" if s == "medium" else "#475467") if True else "#475467"
    sev_chips = "".join(
        f"<span style='display:inline-block;margin:0 8px 8px 0;padding:4px 10px;border-radius:999px;"
        f"background:#f2f4f7;color:{chip(s)};font-size:13px'>{SEVERITY_CN.get(s, s)} {sev.get(s, 0)}</span>"
        for s in SEV_ORDER if sev.get(s))
    return f"""<!doctype html>
<html><body style="margin:0;padding:0;background:#f6f7f9;font-family:-apple-system,'PingFang SC','Helvetica Neue',Arial,sans-serif;color:#101828">
<div style="max-width:760px;margin:0 auto;padding:24px 16px">
  <div style="background:#0f172a;color:#fff;border-radius:14px;padding:22px 24px">
    <div style="font-size:13px;letter-spacing:2px;opacity:.7">心之壁 · 终端安全月报</div>
    <div style="font-size:24px;font-weight:600;margin-top:6px">{e(d['month'])}</div>
    <div style="font-size:13px;opacity:.75;margin-top:8px">{e(d['range_cn'])}　主机 {e(d['host'])}　v{e(d['version'])}</div>
  </div>

  <div style="background:#fff;border-radius:14px;padding:20px 22px;margin-top:14px">
    <div style="font-size:15px;font-weight:600;margin-bottom:12px">本月概览</div>
    <table style="width:100%;border-collapse:collapse;font-size:14px">
      <tr>
        <td style="padding:10px;background:#f8fafc;border-radius:10px;text-align:center">
          <div style="font-size:22px;font-weight:600">{d['counts']['findings']}</div>
          <div style="font-size:12px;color:#667085">告警</div></td>
        <td style="width:8px"></td>
        <td style="padding:10px;background:#f8fafc;border-radius:10px;text-align:center">
          <div style="font-size:22px;font-weight:600">{d['counts']['incidents']}</div>
          <div style="font-size:12px;color:#667085">攻击链</div></td>
        <td style="width:8px"></td>
        <td style="padding:10px;background:#f8fafc;border-radius:10px;text-align:center">
          <div style="font-size:22px;font-weight:600">{d['counts']['actions']}</div>
          <div style="font-size:12px;color:#667085">处置动作</div></td>
        <td style="width:8px"></td>
        <td style="padding:10px;background:#f8fafc;border-radius:10px;text-align:center">
          <div style="font-size:22px;font-weight:600">{d['counts']['audit']}</div>
          <div style="font-size:12px;color:#667085">审计记录</div></td>
      </tr>
    </table>
    <div style="margin-top:14px">{sev_chips}</div>
  </div>

  <div style="background:#fff;border-radius:14px;padding:20px 22px;margin-top:14px">
    <div style="font-size:15px;font-weight:600;margin-bottom:10px">风险与防护健康度</div>
    <div style="font-size:14px;line-height:1.9">
      风险指数 <b>{e(str((d.get('threat') or {}).get('risk')))}</b>　
      防护健康度 <b>{e(str((d.get('posture') or {}).get('health')))}</b>（{e(str((d.get('posture') or {}).get('grade')))}）
    </div>
  </div>

  <div style="background:#fff;border-radius:14px;padding:20px 22px;margin-top:14px">
    <div style="font-size:15px;font-weight:600;margin-bottom:10px">TOP 告警规则</div>
    <table style="width:100%;border-collapse:collapse;font-size:14px">{rows_top}</table>
  </div>

  <div style="background:#fff;border-radius:14px;padding:20px 22px;margin-top:14px">
    <div style="font-size:15px;font-weight:600;margin-bottom:10px">攻击链</div>
    <table style="width:100%;border-collapse:collapse;font-size:14px">
      <tr style="color:#667085;font-size:12px"><td style="padding:4px 10px">级别</td>
      <td style="padding:4px 10px">名称</td><td style="padding:4px 10px;text-align:right">阶段</td>
      <td style="padding:4px 10px;text-align:right">评分</td></tr>
      {rows_inc}
    </table>
  </div>

  <div style="background:#fff;border-radius:14px;padding:20px 22px;margin-top:14px">
    <div style="font-size:15px;font-weight:600;margin-bottom:10px">工单与审计链</div>
    <div style="font-size:14px;line-height:1.9">
      工单：打开 {tk['open']}　处理中 {tk['ack']}　已关闭 {tk['closed']}　平均闭环 {tk['mttr_hours']} 小时<br>
      审计链：本月 {d['audit']['records']} 条　全链校验
      <b style="color:{'#067647' if av.get('ok') else '#b42318'}">{'通过' if av.get('ok') else '未通过'}</b>
      　锚点 {e(str(av.get('anchor_state')))}
    </div>
  </div>

  <div style="background:#fff;border-radius:14px;padding:20px 22px;margin-top:14px">
    <div style="font-size:15px;font-weight:600;margin-bottom:8px">结论与建议</div>
    <ol style="font-size:14px;line-height:1.8;padding-left:20px;margin:0">{advice}</ol>
  </div>

  <div style="font-size:12px;color:#667085;text-align:center;padding:18px 0">
    由 心之壁 v{e(d['version'])} 自动生成 · {e(d['generated_cn'])} · 原始数据保留在本机 ~/.atfield
  </div>
</div></body></html>"""


def save(core, data: Dict[str, Any]) -> Dict[str, str]:
    out_dir = os.path.join(core.cfg.get("data_dir") or os.path.expanduser("~/.atfield"),
                           "exports", "monthly", data["month"])
    os.makedirs(out_dir, exist_ok=True)
    md_path = os.path.join(out_dir, f"心之壁-月报-{data['month']}.md")
    html_path = os.path.join(out_dir, f"心之壁-月报-{data['month']}.html")
    json_path = os.path.join(out_dir, f"心之壁-月报-{data['month']}.json")
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write(render_md(data))
    with open(html_path, "w", encoding="utf-8") as fh:
        fh.write(render_html(data))
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
    return {"md": md_path, "html": html_path, "json": json_path}


def deliver(core, data: Dict[str, Any], paths: Dict[str, str],
            send: bool = True) -> Dict[str, Any]:
    """按配置投递。没配 SMTP 就明确说没发，不假装。"""
    cfg = (core.cfg.get("monthly") or {}).get("smtp") or {}
    host = str(cfg.get("host") or "")
    # recipients / to 都认；单个字符串里逗号分隔多个地址也拆开
    raw_rcpts = cfg.get("recipients") or cfg.get("to") or []
    if isinstance(raw_rcpts, str):
        raw_rcpts = [raw_rcpts]
    recipients: List[str] = []
    for r in raw_rcpts:
        recipients.extend(x.strip() for x in str(r).split(",") if x.strip())
    if not send:
        return {"sent": False, "reason": "未要求投递（仅落盘）", "paths": paths}
    if not host or not recipients:
        return {"sent": False,
                "reason": "未配置 SMTP（config.yaml 的 monthly.smtp.host / recipients），报告已落盘",
                "paths": paths}
    port = int(cfg.get("port") or (465 if cfg.get("ssl") else 587))
    # sender / from 都认（README 里写的是 from，旧代码只认 sender，照文档配会丢发件人）
    sender = str(cfg.get("sender") or cfg.get("from") or cfg.get("user")
                 or "atfield@localhost")
    msg = EmailMessage()
    msg["Subject"] = f"心之壁 终端安全月报 · {data['month']} · {data['host']}"
    msg["From"] = formataddr(("心之壁", sender))
    msg["To"] = ", ".join(recipients)
    msg["Date"] = formatdate(localtime=True)
    msg.set_content(render_md(data))
    msg.add_alternative(render_html(data), subtype="html")
    try:
        with open(paths["html"], "rb") as fh:
            blob = fh.read()
        msg.add_attachment(blob, maintype="text", subtype="html",
                           filename=os.path.basename(paths["html"]))
    except Exception:
        pass
    try:
        ctx = ssl.create_default_context()
        if cfg.get("ssl"):
            with smtplib.SMTP_SSL(host, port, context=ctx, timeout=25) as srv:
                if cfg.get("user"):
                    srv.login(str(cfg["user"]), str(cfg.get("password") or ""))
                srv.send_message(msg)
        else:
            with smtplib.SMTP(host, port, timeout=25) as srv:
                srv.ehlo()
                # starttls 三态：显式 true 必须升级成功（失败即报错，不静默降级）；
                # 显式 false 跳过；缺省按服务器能力机会性升级——内网常见不带
                # STARTTLS 的明文中继，旧版缺省 True 对这类服务器必然投递失败。
                if "starttls" in cfg:
                    use_tls = bool(cfg.get("starttls"))
                else:
                    use_tls = srv.has_extn("starttls")
                if use_tls:
                    srv.starttls(context=ctx)
                    srv.ehlo()
                if cfg.get("user"):
                    srv.login(str(cfg["user"]), str(cfg.get("password") or ""))
                srv.send_message(msg)
    except Exception as exc:
        return {"sent": False, "reason": f"发送失败（{host}:{port}）：{exc}",
                "paths": paths, "recipients": recipients}
    return {"sent": True, "recipients": recipients, "paths": paths,
            "subject": msg["Subject"]}


def build(core, month: str = "", send: bool = False) -> Dict[str, Any]:
    data = collect(core, month)
    paths = save(core, data)
    out = deliver(core, data, paths, send=send)
    result = {"ok": True, "month": data["month"], "paths": paths,
              "delivery": out, "counts": data["counts"],
              "advice": data.get("advice")}
    if getattr(core, "audit", None) is not None:
        try:
            core.audit.append("monthly.report", actor="system", role="system",
                              target=data["month"], result="ok",
                              detail={"投递": out.get("sent"), "原因": out.get("reason", ""),
                                      "文件": os.path.basename(paths["md"])})
        except Exception:
            pass
    return result
