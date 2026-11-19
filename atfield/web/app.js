'use strict';

/* ============================================================
   心之壁 控制台
   数据来源：REST（/api/*）+ SSE（/api/stream，2s 推一次全量态势）
   ============================================================ */

const CN = {
  sev: { info: '信息', low: '低危', medium: '中危', high: '高危', critical: '严重' },
  st: { pass: '通过', warn: '警告', fail: '不合格', unknown: '未判定', gap: '未覆盖' },
  pb: { pending: '待确认', done: '已完成', rejected: '已驳回' },
  tk: { open: '待处理', ack: '处理中', closed: '已关闭' },
  tl: { event: '事件', finding: '告警', incident: '攻击链', action: '处置', ticket: '工单' },
  cat: { remote: '远程控制', browser: '浏览器', dev: '开发工具', security: '安全软件', vpn: '网络代理', other: '其他' },
  conf: { low: '低', medium: '中', high: '高' },
};

const S = {
  view: 'overview',
  o: null,          // overview 快照（SSE 推送）
  assets: null,
  cache: {},
  lastRender: 0,
};

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));

/* ---------------- 基础工具 ---------------- */
function esc(v) {
  return String(v == null ? '' : v).replace(/[&<>"']/g, c => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));
}
function clip(v, n = 64) {
  const s = String(v == null ? '' : v);
  const t = s.length > n ? s.slice(0, n) + '…' : s;
  return `<span class="clip" title="${esc(s)}">${esc(t)}</span>`;
}
function num(n) {
  if (n == null || n === '') return '0';
  return String(n).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
}
function tsStr(ts) {
  if (!ts) return '—';
  const d = new Date(Number(ts) * 1000);
  const p = x => String(x).padStart(2, '0');
  return `${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}
function sev(v) {
  const k = String(v || 'info');
  return `<span class="sev sev-${esc(k)}">${esc(CN.sev[k] || k)}</span>`;
}
function stBadge(v) {
  const k = String(v || 'unknown');
  return `<span class="st st-${k === 'gap' ? 'unknown' : esc(k)}">${esc(CN.st[k] || k)}</span>`;
}
function toast(msg, kind = 'ok') {
  const box = $('#toast');
  const d = document.createElement('div');
  d.className = kind;
  d.textContent = msg;
  box.appendChild(d);
  setTimeout(() => d.remove(), 4200);
}
async function API(path, opt) {
  const o = Object.assign({ headers: {} }, opt || {});
  const silent = !!o.noLoginRedirect;
  delete o.noLoginRedirect;
  o.headers['X-Requested-With'] = 'atfield';
  if (o.body && typeof o.body !== 'string') {
    o.body = JSON.stringify(o.body);
    o.headers['Content-Type'] = 'application/json';
  }
  const r = await fetch(path, o);
  const ct = r.headers.get('content-type') || '';
  if (!ct.includes('json')) {
    const t = await r.text();
    if (r.status === 401) {
      if (!silent) showLogin('登录状态已失效，请重新登录');
      throw new Error('未登录');
    }
    if (!r.ok) throw new Error(t.slice(0, 200) || ('HTTP ' + r.status));
    return t;
  }
  const j = await r.json();
  if (r.status === 401 && j && j.login_required) {
    if (!silent) showLogin(j.hint ? '首次登录口令文件：' + j.hint : '请登录');
    throw new Error(j.error || '未登录');
  }
  if (r.status === 403) throw new Error(j.error || '权限不足');
  if (j && j.ok === false && j.error) throw new Error(j.error);
  return j;
}
function table(cols, rows, opts = {}) {
  if (!rows || !rows.length) return `<div class="empty">${esc(opts.empty || '暂无数据')}</div>`;
  const head = cols.map(c => `<th>${esc(c.t)}</th>`).join('');
  const body = rows.map(r => `<tr>${cols.map((c, i) => `<td class="${c.c || ''}">${r[i] == null ? '' : r[i]}</td>`).join('')}</tr>`).join('');
  return `<div class="table-wrap"><table><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table></div>`;
}
function panel(title, body, opts = {}) {
  const tag = opts.tag ? `<span class="panel-tag ${opts.tagCls || ''}">${esc(opts.tag)}</span>` : '';
  return `<div class="glass panel ${opts.cls || ''}">
    <div class="panel-head"><h3>${esc(title)}</h3><span class="spacer"></span>${opts.actions || ''}${tag}</div>
    ${body}
  </div>`;
}
function kpi(label, val, sub, color, barPct) {
  return `<div class="glass kpi">
    <div class="kpi-label">${esc(label)}</div>
    <div class="kpi-val" style="color:${color || 'var(--text)'}">${val}</div>
    <div class="kpi-sub">${sub || ''}</div>
    ${barPct == null ? '' : `<div class="kpi-bar"><i style="width:${Math.max(2, Math.min(100, barPct))}%;background:${color || 'var(--mint)'}"></i></div>`}
  </div>`;
}
function donut(score, grade) {
  const r = 62, c = 2 * Math.PI * r;
  // 环用强调色、只有掉到 65 以下才转红：82 分标着「良好」却画个警示棕环，语义自相矛盾
  const col = score >= 65 ? 'var(--accent)' : 'var(--red)';
  const off = c * (1 - Math.max(0, Math.min(100, score)) / 100);
  return `<div class="donut">
    <svg viewBox="0 0 148 148">
      <circle class="dn-track" cx="74" cy="74" r="${r}" fill="none" stroke="var(--gauge-track)" stroke-width="9"/>
      <circle cx="74" cy="74" r="${r}" fill="none" stroke="${col}" stroke-width="9"
        stroke-linecap="round" stroke-dasharray="${c}" stroke-dashoffset="${off}"/>
    </svg>
    <div class="donut-c"><b style="color:${col}">${score.toFixed(0)}</b><span>${esc(grade || '')}</span></div>
  </div>`;
}
function dims(list) {
  return `<div class="dims">${(list || []).map(d => {
    const v = Number(d.score || 0);
    // 细条统一用强调色：长度本身就是信号，再叠三种颜色只会显得脏；
    // 等级用数字颜色表达（那是有足够像素承载颜色的地方）
    const numCol = v >= 85 ? 'var(--accent)' : v >= 65 ? 'var(--warn)' : 'var(--bad)';
    return `<div class="dim" title="${esc(d.desc || '')}${d.top_issue ? ' · 主要问题：' + d.top_issue : ''}">
      <div class="dim-name">${esc(d.name)}</div>
      <div class="dim-track"><i style="width:${v}%;background:var(--accent)"></i></div>
      <div class="dim-score" style="color:${numCol}">${v.toFixed(0)}</div>
    </div>`;
  }).join('')}</div>`;
}

/* ---------------- 顶部 / 侧栏 ---------------- */
function renderChrome(o) {
  if (!o) return;
  $('#host').textContent = o.host || '—';
  $('#meta').textContent = `${o.platform || ''} · ${o.user || ''} · 已运行 ${Math.floor((o.uptime || 0) / 60)} 分钟 · ${o.now || ''}`;
  const h = o.health || {}, t = o.threat || {};
  const hp = $('#pill-health');
  hp.className = 'pill lv-' + (h.health >= 85 ? 'calm' : h.health >= 65 ? 'medium' : 'critical');
  hp.textContent = `健康度 ${Number(h.health || 0).toFixed(0)} · ${h.grade || '—'}`;
  const tp = $('#pill-threat');
  tp.className = 'pill lv-' + (o.threat_color || 'calm');
  tp.textContent = `风险 ${Number(t.risk || 0).toFixed(0)} · ${t.level || '—'}`;
  if (o.version) {
    const v = $('#ver');
    v.textContent = 'v' + o.version;
    v.hidden = false;
    v.title = `${o.product || '心之壁'} ${o.version}`;
  }

  const coll = o.collectors || [];
  $('#collector-mini').innerHTML = coll.map(c => {
    const cls = !c.enabled ? 'off' : (c.available ? 'ok' : 'err');
    const tip = [c.reason || c.last_error || '', c.last_ms ? Math.round(c.last_ms) + 'ms' : '']
      .filter(Boolean).join(' · ');
    return `<div class="mini-row" title="${esc(tip)}">
      <span class="sq ${cls}"></span>
      <span class="nm">${esc(c.name)}</span>
      <span class="count-hint">${c.available ? 'ok' : 'n/a'}</span>
    </div>`;
  }).join('') || '<div class="empty">无采集器</div>';

  // 侧栏分组标题带上总路数——列表被限高后，仍然一眼知道有多少采集器
  const st = document.querySelector('.side-foot .side-title');
  if (st) st.textContent = `采集器状态 · ${coll.length} 路`;

  const f = o.fusion || {};
  $('#b-findings').textContent = num((o.top_findings || []).length);
  $('#b-ndr').textContent = num((f.ndr || {}).beacon_count || 0);
  $('#b-canary').textContent = num((f.canary || {}).trips || 0);
  $('#b-pending').textContent = num(((f.playbooks || {}).pending || []).length);
  $('#b-tickets').textContent = num(((f.tickets || []).filter(x => x.status !== 'closed') || []).length);
}

/* ---------------- 视图：态势总览 ---------------- */
function viewOverview() {
  const o = S.o;
  if (!o) return '<div class="empty">正在等待首个态势快照…</div>';
  const t = o.threat || {}, h = o.health || {}, tt = o.totals || {}, f = o.fusion || {};
  const beacons = (f.ndr || {}).beacon_count || 0;
  const canaryTrips = (f.canary || {}).trips || 0;
  const pending = ((f.playbooks || {}).pending || []).length;
  const inv = f.inventory || {};
  const comp = f.compliance || {};
  const fw = comp.frameworks || {};
  const cis = fw['CIS'] || {}, dj = fw['等保三级'] || {};

  return `
  <div class="kpis">
    ${kpi('风险度', `${Number(t.risk || 0).toFixed(0)}<small>${esc(t.level || '')}</small>`,
      `近 1 小时新增告警 ${num(t.recent_1h || 0)} 条`, 'var(--red)', t.risk)}
    ${kpi('健康度', `${Number(h.health || 0).toFixed(0)}<small>${esc(h.grade || '')}</small>`,
      `基线不合格 ${num(tt.baseline_fail || 0)} 项 · 警告 ${num(tt.baseline_warn || 0)} 项`, 'var(--mint)', h.health)}
    ${kpi('告警 / 攻击链', `${num(t.findings_total || 0)}<small>/${num(t.incidents_total || 0)}</small>`,
      `严重 ${num((t.by_severity || {}).critical || 0)} · 高危 ${num((t.by_severity || {}).high || 0)}`, 'var(--orange)')}
    ${kpi('信号聚合', `${num(beacons + canaryTrips)}<small>个信号</small>`,
      `信标 ${num(beacons)} · 诱饵触碰 ${num(canaryTrips)} · 待确认处置 ${num(pending)}`, 'var(--blue)')}
  </div>

  <div class="grid-2">
    ${panel('健康度构成', `<div class="posture-body">${donut(Number(h.health || 0), h.grade)}${dims(h.dimensions)}</div>`,
    { tag: '基线驱动', tagCls: 'mint' })}
    ${panel('态势结论', `<div class="verdict">${esc(verdictText(o.verdict))}</div>`, { tag: '自动生成' })}
  </div>

  <div class="grid-3">
    ${panel('行为基线 UEBA', miniRows([
      ['已知进程名', num((f.ueba || {}).known_processes || 0)],
      ['已知可执行路径', num((f.ueba || {}).known_exe || 0)],
      ['已知外联地址', num((f.ueba || {}).known_remote || 0)],
      ['状态', (f.ueba || {}).learning ? '学习中' : '已建立基线'],
    ]), { tag: '偏离即告警' })}
    ${panel('网络检测 NDR', miniRows([
      ['观测目的地', num((f.ndr || {}).destinations || 0)],
      ['未解析域名', num((f.ndr || {}).unresolved || 0)],
      ['疑似信标', num(beacons)],
      ['行为标记', num(((f.ndr || {}).flags || []).length)],
    ]), { tag: '主机侧 NDR' })}
    ${panel('诱饵 / 情报 / 剧本', miniRows([
      ['诱饵文件', `${num((f.canary || {}).count || 0)} 个（触碰 ${num(canaryTrips)}）`],
      ['情报条目', `${num((f.intel || {}).ip || 0)} IP / ${num((f.intel || {}).domain || 0)} 域名`],
      ['剧本', `${num((f.playbooks || {}).count || 0)} 个（待确认 ${num(pending)}）`],
      ['工单未关闭', num((f.tickets || []).filter(x => x.status !== 'closed').length)],
    ]), { tag: '主动防御' })}
  </div>

  <div class="grid-2">
    ${panel('攻击链叙事', chainList(o.recent_incidents || []), {
      actions: `<span class="panel-tag">${num((o.recent_incidents || []).length)}</span>`,
    })}
    ${panel('最近告警', `<div class="scroll-list">${miniFindings(o.top_findings || [])}</div>`, {
      actions: `<button class="btn sm" data-goto="findings">查看全部</button>`,
    })}
  </div>

  <div class="grid-3">
    ${panel('资产与软件', miniRows([
      ['已登记应用', num(inv.apps || 0)],
      ['长期未更新', num(inv.stale_count || 0)],
      ['签名异常', num(inv.unsigned_count || 0)],
      ['远程控制类', num((inv.remote || []).length)],
    ]), { actions: `<button class="btn sm" data-goto="inventory">明细</button>` })}
    ${panel('合规矩阵', miniRows([
      ['CIS 得分', `${Number(cis.score || 0).toFixed(0)} / 100`],
      ['CIS 不合格', num(cis.fail || 0)],
      ['等保三级得分', `${Number(dj.score || 0).toFixed(0)} / 100`],
      ['等保不合格', num(dj.fail || 0)],
    ]), { actions: `<button class="btn sm" data-goto="compliance">矩阵</button>` })}
    ${panel('终端与边界', miniRows([
      ['进程', num(tt.processes || 0)],
      ['活动连接', `${num(tt.connections || 0)}（公网 ${num(tt.public_connections || 0)}）`],
      ['监听端口', num(tt.listeners || 0)],
      ['常驻项', `${num(tt.persistence || 0)}（可疑 ${num(tt.persistence_suspicious || 0)}）`],
    ]), { actions: `<button class="btn sm" data-goto="telemetry">遥测</button>` })}
  </div>`;
}
function verdictText(v) {
  if (!v) return '暂无结论：等待首轮基线检查与遥测采集完成。';
  if (typeof v === 'string') return v;
  if (Array.isArray(v)) return v.join(' ');
  return Object.entries(v).map(([k, x]) => `${k}：${typeof x === 'object' ? JSON.stringify(x) : x}`).join('　');
}
function miniRows(rows) {
  return `<div class="kv">${rows.map(([k, v]) => `<div class="kv-row"><div class="k">${esc(k)}</div><div class="v">${esc(v)}</div></div>`).join('')}</div>`;
}
function chainList(list) {
  if (!list.length) return '<div class="empty">暂无攻击链：单点告警尚未满足时序关联条件</div>';
  return `<div class="chain-list">${list.map(i => `
    <div class="chain">
      <div class="chain-top">
        <span class="sev sev-${esc(i.severity || 'info')}">${esc(i.severity_cn || CN.sev[i.severity] || '')}</span>
        <span class="chain-title">${esc(i.template_id || '')} · ${esc(i.title || '')}</span>
        <span class="chain-meta">${esc(i.actor || '')}</span>
      </div>
      <div class="stages">${(i.stages || []).map((s, idx) => (
        `${idx ? '<span class="stage-arrow">→</span>' : ''}<span class="stage">${esc(s.stage || '')}</span>`
      )).join('')}</div>
    </div>`).join('')}</div>`;
}
function miniFindings(list) {
  if (!list.length) return '<div class="empty">暂无告警</div>';
  return `<div class="mini">${list.map(f => `
    <div class="mini-item">
      ${sev(f.severity)}
      <div class="mi-main">
        <div class="mi-name">${esc(f.name || f.rule_id || '')}</div>
        <div class="mi-sub">${esc(f.rule_id || '')} · ${esc((f.actor || '').toString())} · ${esc(f.detail || '')}</div>
      </div>
    </div>`).join('')}</div>`;
}

/* ---------------- 视图：告警与攻击链 ---------------- */
async function viewFindings() {
  const [fd, inc] = await Promise.all([API('/api/findings?limit=300'), API('/api/incidents?limit=50')]);
  const list = fd.findings || [];
  const rows = list.map(f => [
    `<span class="mono">${esc(tsStr((f.event || {}).ts || f.ts))}</span>`,
    sev(f.severity),
    `<span class="mono">${esc(f.rule_id || '')}</span>`,
    esc(f.name || ''),
    clip(f.actor, 22),
    clip(f.detail || '', 90),
    `<span class="mono">${esc((f.tags || []).join(','))}</span>`,
  ]);
  return `
  <div class="filters">
    <input type="text" id="f-q" placeholder="过滤规则 / 主体 / 详情">
    <select id="f-sev">
      <option value="">全部等级</option>
      <option value="critical">严重</option><option value="high">高危</option>
      <option value="medium">中危</option><option value="low">低危</option>
    </select>
    <span class="spacer"></span>
    <span class="count-hint">${num(list.length)} 条告警</span>
  </div>
  ${panel('攻击链', chainList(inc.incidents || []), { tag: '时序关联', tagCls: 'mint' })}
  ${panel('告警明细', `<div id="f-table">${table([
    { t: '时间', c: 'nowrap mono' }, { t: '等级' }, { t: '规则' }, { t: '名称' },
    { t: '主体' }, { t: '详情' }, { t: '标签', c: 'mono' },
  ], rows)}</div>`)}`;
}
function bindFindings() {
  const q = $('#f-q'), s = $('#f-sev');
  if (!q || !s) return;
  const apply = () => {
    const txt = q.value.trim().toLowerCase(), sv = s.value;
    $$('#f-table tbody tr').forEach(tr => {
      const hit = (!txt || tr.textContent.toLowerCase().includes(txt)) && (!sv || tr.children[1].textContent.trim() === CN.sev[sv]);
      tr.style.display = hit ? '' : 'none';
    });
  };
  q.addEventListener('input', apply);
  s.addEventListener('change', apply);
}

/* ---------------- 视图：取证时间线 ---------------- */
async function viewTimeline() {
  const d = await API('/api/timeline?limit=400');
  const rows = (d.timeline || []).map(r => [
    `<span class="mono">${esc(tsStr(r.ts))}</span>`,
    `<span class="st st-${r.type === 'finding' ? 'fail' : r.type === 'incident' ? 'warn' : 'unknown'}">${esc(CN.tl[r.type] || r.type)}</span>`,
    sev(r.severity),
    clip(r.title, 84),
    `<span class="mono">${esc(r.source || '')}</span>`,
    clip(r.actor, 20),
  ]);
  return panel('统一取证时间线', table([
    { t: '时间', c: 'nowrap' }, { t: '类型' }, { t: '等级' }, { t: '内容' }, { t: '来源' }, { t: '主体' },
  ], rows, { empty: '暂无时间线记录' }), {
    tag: '事件 / 告警 / 攻击链 / 处置 / 工单',
    actions: `<span class="count-hint">最近 ${num(rows.length)} 条</span>`,
  });
}

/* ---------------- 视图：终端遥测 ---------------- */
async function viewTelemetry() {
  const a = await API('/api/assets');
  S.assets = a;
  const p = a.processes || {}, c = a.connections || {}, se = a.sessions || {},
    pe = a.persistence || {}, ig = a.integrity || {}, sw = a.security_sw || {};

  const procRows = (p.rows || []).slice(0, 300).map(r => [
    `<span class="mono">${esc(r.pid)}</span>`, `<span class="mono">${esc(r.ppid)}</span>`,
    esc(r.name || ''), esc(r.user || ''), clip(r.exe || '', 70),
  ]);
  const connRows = (c.rows || []).slice(0, 300).map(r => [
    `<span class="mono">${esc(r.proto || '')}</span>`,
    `<span class="mono">${esc((r.laddr || '') + (r.lport ? ':' + r.lport : ''))}</span>`,
    `<span class="mono">${esc((r.raddr || '') + (r.rport ? ':' + r.rport : ''))}</span>`,
    esc(r.status || ''), clip(r.process || r.pname || '', 30),
    r.public ? '<span class="sev sev-high">公网</span>' : '',
  ]);
  const listenRows = (c.listeners || []).slice(0, 200).map(r => [
    `<span class="mono">${esc((r.laddr || '') + ':' + (r.lport || ''))}</span>`,
    clip(r.process || '', 34),
    r.risky ? `<span class="sev sev-${esc(r.risky_level || 'medium')}">${esc(r.risky || '')}</span>` : '',
  ]);
  const sessRows = (se.active || []).map(r => [
    esc(r.user || ''), `<span class="mono">${esc(r.tty || '')}</span>`,
    esc(r.from || ''), `<span class="mono">${esc(r.since || '')}</span>`,
    r.remote ? '<span class="sev sev-medium">远程</span>' : '本地',
  ]);
  const persRows = (pe.items || []).slice(0, 300).map(r => [
    clip(r.label || r.path, 34), clip(r.program || '', 60),
    esc(r.scope || ''), `<span class="mono">${esc(r.interval == null ? (r.run_at_load ? 'RunAtLoad' : '') : r.interval + 's')}</span>`,
    (r.suspicious || []).length ? `<span class="sev sev-high">${esc((r.suspicious || []).join('；'))}</span>` : '',
  ]);
  const cronRows = (pe.cron || []).map(r => [`<span class="mono">${clip(r.line, 110)}</span>`]);
  const igRows = (ig.files || []).map(r => [
    clip(r.path, 70), r.exists ? '存在' : '<span class="sev sev-high">缺失</span>',
    `<span class="mono">${esc(r.digest || '')}</span>`, r.readable ? '' : '<span class="sev sev-low">不可读</span>',
  ]);
  const swRows = (sw.items || []).map(r => [
    esc(r.label || ''), r.present ? '<span class="st st-pass">已安装</span>' : '<span class="st st-unknown">未检测到</span>',
  ]);

  const tab = (id, label, content) => `<button class="tab${id === 'processes' ? ' active' : ''}" data-tab="${id}">${label}</button>`;
  return `
  ${panel('终端活动', `
    <div class="tabs">
      ${tab('processes', `进程 ${num((p.rows || []).length)}`)}
      ${tab('conns', `连接 ${num((c.rows || []).length)}`)}
      ${tab('listen', `监听 ${num((c.listeners || []).length)}`)}
      ${tab('sessions', `会话 ${num((se.active || []).length)}`)}
      ${tab('persist', `常驻 ${num(pe.count || 0)}`)}
      ${tab('cron', `定时任务 ${num((pe.cron || []).length)}`)}
      ${tab('integrity', `完整性 ${num((ig.files || []).length)}`)}
      ${tab('av', '安全组件')}
    </div>
    <div class="tabpane active" data-pane="processes">${table([
      { t: 'PID', c: 'mono' }, { t: 'PPID', c: 'mono' }, { t: '进程' }, { t: '用户' }, { t: '可执行路径' },
    ], procRows, { empty: '无进程数据' })}${p.hidden && p.hidden.length ? `<div class="act-desc" style="margin-top:8px">隐藏进程交叉校验差异：${num(p.hidden.length)} 条（psutil 与 ps 视图不一致）</div>` : ''}</div>
    <div class="tabpane" data-pane="conns">${table([
      { t: '协议', c: 'mono' }, { t: '本地' }, { t: '远端' }, { t: '状态' }, { t: '进程' }, { t: '边界' },
    ], connRows, { empty: '无活动连接' })}</div>
    <div class="tabpane" data-pane="listen">${table([
      { t: '监听地址' }, { t: '进程' }, { t: '风险' },
    ], listenRows, { empty: '无监听端口' })}</div>
    <div class="tabpane" data-pane="sessions">${table([
      { t: '用户' }, { t: 'TTY' }, { t: '来源' }, { t: '登录时间' }, { t: '类型' },
    ], sessRows, { empty: '无活动会话' })}</div>
    <div class="tabpane" data-pane="persist">${table([
      { t: '标签' }, { t: '程序/命令' }, { t: '范围' }, { t: '触发' }, { t: '可疑点' },
    ], persRows, { empty: '无常驻项' })}</div>
    <div class="tabpane" data-pane="cron">${table([{ t: '定时任务行' }], cronRows, { empty: '无用户 crontab' })}</div>
    <div class="tabpane" data-pane="integrity">${table([
      { t: '文件' }, { t: '状态' }, { t: 'SHA-256 前缀', c: 'mono' }, { t: '可读性' },
    ], igRows, { empty: '未配置监控文件' })}</div>
    <div class="tabpane" data-pane="av">${table([{ t: '组件' }, { t: '状态' }], swRows, { empty: '无数据' })}</div>
  `, { tag: '非特权采集' })}`;
}
function bindTabs() {
  $$('.tab').forEach(b => b.addEventListener('click', () => {
    $$('.tab').forEach(x => x.classList.remove('active'));
    $$('.tabpane').forEach(x => x.classList.remove('active'));
    b.classList.add('active');
    const pane = $(`.tabpane[data-pane="${b.dataset.tab}"]`);
    if (pane) pane.classList.add('active');
  }));
}

/* ---------------- 视图：UEBA ---------------- */
async function viewUEBA() {
  const d = await API('/api/ueba');
  const s = d.status || {};
  const max = Math.max(1, ...(d.hourly || []).map(h => h.count));
  const bars = (d.hourly || []).map(h => `<div class="bar" style="height:${Math.max(2, (h.count / max) * 100)}%" title="${h.hour}:00 · ${h.count} 次观测"></div>`).join('');
  return `
  <div class="kpis">
    ${kpi('学习状态', s.learning ? '学习中' : '已建立基线', `已观测 ${num(s.samples || 0)} 次 · ${num(s.learn_elapsed || 0)} 秒`, 'var(--mint)')}
    ${kpi('已知进程名', num(s.known_processes || 0), '首次出现即偏离', 'var(--blue)')}
    ${kpi('已知可执行路径', num(s.known_exe || 0), '路径级基线', 'var(--blue)')}
    ${kpi('已知外联地址', num(s.known_remote || 0), '新目的地即记录', 'var(--orange)')}
  </div>
  ${panel('24 小时活动分布', `<div class="bars">${bars}</div>
    <div class="act-desc" style="margin-top:8px">低活跃时段（00:00-06:00）首次出现的非系统路径进程会被自动提升告警等级。</div>`,
    { actions: `<button class="btn sm danger" data-act="ueba-reset">重置基线</button>`, tag: `画像文件 ${s.path || ''}` })}
  <div class="grid-2">
    ${panel('已知进程（前 200）', `<div class="mini">${(d.top_processes || []).map(p => `<div class="mini-row"><span class="nm mono">${esc(p)}</span></div>`).join('') || '<div class="empty">暂无</div>'}</div>`)}
    ${panel('最近外联目的地', `<div class="mini">${(d.recent_destinations || []).map(ip => `<div class="mini-row"><span class="nm mono">${esc(ip)}</span></div>`).join('') || '<div class="empty">暂无外联记录</div>'}</div>`)}
  </div>`;
}

/* ---------------- 视图：NDR ---------------- */
async function viewNDR() {
  const d = await API('/api/ndr');
  const bRows = (d.beacons || []).map(b => [
    esc(b.process || ''), `<span class="mono">${esc(b.ip)}:${esc(b.port)}</span>`,
    esc(b.hostname || '未解析'), `<span class="mono">${esc(b.interval_s)}s</span>`,
    `<span class="mono">${esc(b.cv)}</span>`, num(b.samples), num(b.hits),
  ]);
  const fRows = (d.flags || []).map(f => [
    `<span class="mono">${esc(tsStr(f.ts))}</span>`, sev(f.severity),
    `<span class="mono">${esc(f.kind)}</span>`, esc(f.process || ''), clip(f.text, 96),
  ]);
  const dRows = (d.top_destinations || []).map(x => [
    `<span class="mono">${esc(x.ip)}</span>`, esc(x.hostname || '未解析'),
    num(x.count), `<span class="mono">${esc(Object.keys(x.ports || {}).join(','))}</span>`,
    clip(Object.keys(x.processes || {}).join(','), 40),
  ]);
  return `
  <div class="kpis">
    ${kpi('观测目的地', num(d.destinations || 0), '按进程/连接聚合', 'var(--blue)')}
    ${kpi('未解析域名', num(d.unresolved || 0), '直连 IP 的上游线索', 'var(--amber)')}
    ${kpi('疑似信标', num(d.beacon_count || 0), '间隔高度规律的外联', 'var(--red)')}
    ${kpi('行为标记', num((d.flags || []).length), '近期 NDR 判定', 'var(--orange)')}
  </div>
  ${panel('信标检测（C2 心跳特征）', table([
    { t: '进程' }, { t: '目的地' }, { t: '域名' }, { t: '平均间隔' }, { t: '波动系数' }, { t: '样本' }, { t: '命中轮次' },
  ], bRows, { empty: '暂未发现规律心跳（需要至少 5 个等间隔连接样本）' }),
    { tag: '间隔变异系数 < 0.18 触发' })}
  ${panel('网络行为标记', table([
    { t: '时间', c: 'nowrap' }, { t: '等级' }, { t: '类型' }, { t: '进程' }, { t: '说明' },
  ], fRows, { empty: '暂无标记' }))}
  ${panel('目的地画像（前 40）', table([
    { t: '地址' }, { t: '域名' }, { t: '连接次数' }, { t: '端口' }, { t: '进程' },
  ], dRows, { empty: '暂无数据' }))}`;
}

/* ---------------- 视图：诱饵 ---------------- */
async function viewCanary() {
  const d = await API('/api/canary');
  const rows = (d.items || []).map(i => [
    clip(i.path, 62), esc(i.note || ''),
    i.trips ? `<span class="sev sev-critical">${num(i.trips)}</span>` : '<span class="mono">0</span>',
    `<span class="mono">${esc(tsStr(i.deployed))}</span>`,
    i.last_trip ? `<span class="mono">${esc(tsStr(i.last_trip))}</span>` : '—',
  ]);
  return `
  <div class="kpis">
    ${kpi('已部署诱饵', num(d.count || 0), '真实文件绝不覆盖', 'var(--mint)')}
    ${kpi('被触碰', num(d.trips || 0), '触碰即按入侵处理', 'var(--red)')}
    ${kpi('监控方式', 'atime + 哈希', '非特权可用，root 可叠加实时打开事件', 'var(--blue)')}
    ${kpi('误报特征', '极低', '正常业务不会读取这些文件', 'var(--mint)')}
  </div>
  ${panel('诱饵清单', table([
    { t: '文件路径' }, { t: '伪装说明' }, { t: '触碰' }, { t: '部署时间' }, { t: '最近触碰' },
  ], rows, { empty: '尚未部署诱饵：点右上「部署诱饵」在家目录放置诱饵文件' }), {
    actions: `<button class="btn sm mint" data-act="canary-deploy">部署诱饵</button>
              <button class="btn sm danger" data-act="canary-undeploy">全部移除</button>`,
  })}
  ${panel('使用说明', `<div class="act-desc">
    诱饵是「零误报」信号源：放在 Documents / Desktop / .ssh 等位置，内容伪装成凭据、
    财务报表、运维记录。任何读取、改写、删除都会立刻产生 critical 告警并触发取证剧本。
    部署时只写入不存在的路径，不会覆盖你的真实文件；移除按钮只删自己部署的那些。
  </div>`)}`;
}

/* ---------------- 视图：威胁情报 ---------------- */
async function viewIntel() {
  const d = await API('/api/intel');
  const s = d.stats || {};
  const rows = (d.items || []).slice(0, 300).map(i => [
    `<span class="mono">${esc(i.kind)}</span>`, `<span class="mono">${esc(i.value)}</span>`,
    esc(CN.conf[i.confidence] || i.confidence || ''), esc(i.source || ''),
    clip(i.note || '', 60),
    `<button class="btn sm danger" data-act="intel-del" data-kind="${esc(i.kind)}" data-value="${esc(i.value)}">移除</button>`,
  ]);
  return `
  <div class="kpis">
    ${kpi('IP 情报', num(s.ip || 0), '命中即高危告警', 'var(--blue)')}
    ${kpi('域名情报', num(s.domain || 0), '支持精确 + 类别匹配', 'var(--blue)')}
    ${kpi('哈希情报', num(s.hash || 0), '可供完整性比对', 'var(--blue)')}
    ${kpi('内建风险类别', num(s.builtin_categories || 0), '动态 DNS / 隧道 / 高滥用 TLD', 'var(--amber)')}
  </div>
  ${panel('新增情报', `
    <div class="filters">
      <select id="intel-kind"><option value="ip">IP</option><option value="domain">域名</option><option value="hash">哈希</option></select>
      <input type="text" id="intel-value" placeholder="值，例如 203.0.113.9" style="min-width:240px">
      <input type="text" id="intel-note" placeholder="备注（可选）" style="min-width:180px">
      <button class="btn sm mint" data-act="intel-add">加入情报库</button>
    </div>
    <div class="act-desc" style="margin-top:10px">批量导入：每行 <span class="mono">类型,值,备注</span> 或纯值（自动判类型）。</div>
    <textarea id="intel-import" class="ta" placeholder="ip,203.0.113.9,示例：某次事件的 C2&#10;domain,example-bad.test"></textarea>
    <div class="act-row" style="margin-top:8px">
      <button class="btn sm" data-act="intel-import">导入文本</button>
      <span class="act-desc" style="margin:0">库文件：${esc(s.path || '')}</span>
    </div>`, { tag: '本地库' })}
  ${panel('情报条目', table([
    { t: '类型', c: 'mono' }, { t: '值' }, { t: '置信度' }, { t: '来源' }, { t: '备注' }, { t: '操作' },
  ], rows, { empty: '情报库为空：可导入自有情报，或直接使用内建风险类别匹配' }))}`;
}

/* ---------------- 视图：SOAR ---------------- */
async function viewPlaybooks() {
  const d = await API('/api/playbooks');
  const pbRows = (d.items || []).map(p => [
    `<span class="mono">${esc(p.id)}</span>`, esc(p.name || ''),
    `<span class="mono">${esc(JSON.stringify(p.when || {}))}</span>`,
    `<span class="mono">${esc((p.actions || []).join(' → '))}</span>`,
    p.require_confirm ? '<span class="sev sev-medium">需确认</span>' : '<span class="st st-pass">自动</span>',
    p.enabled ? '启用' : '<span class="st st-unknown">停用</span>',
  ]);
  const pending = (d.pending || []).map(r => `
    <div class="chain">
      <div class="chain-top">
        <span class="sev sev-${esc((r.trigger || {}).severity || 'medium')}">${esc((r.trigger || {}).severity_cn || '')}</span>
        <span class="chain-title">${esc(r.playbook)} · ${esc(r.name || '')}</span>
        <span class="chain-meta">${esc(r.time || '')}</span>
      </div>
      <div class="act-desc">触发规则 ${esc((r.trigger || {}).rule_id || '')} · 主体 ${esc((r.trigger || {}).actor || '')} · ${esc((r.trigger || {}).detail || '')}</div>
      <div class="act-row">
        <button class="btn sm mint" data-act="pb-confirm" data-run="${esc(r.run_id)}">确认执行</button>
        <button class="btn sm danger" data-act="pb-reject" data-run="${esc(r.run_id)}">驳回</button>
      </div>
    </div>`).join('');
  const histRows = (d.history || []).slice().reverse().slice(0, 60).map(r => [
    `<span class="mono">${esc(r.time || tsStr(r.ts))}</span>`, esc(r.playbook || ''), esc(r.name || ''),
    esc(r.incident || ''), `<span class="st st-${r.status === 'done' ? 'pass' : r.status === 'rejected' ? 'unknown' : 'warn'}">${esc(CN.pb[r.status] || r.status)}</span>`,
    clip((r.results || []).map(x => `${x.action}:${x.ok ? '成功' : '失败'}`).join('，'), 70),
  ]);
  return `
  ${panel('待确认动作', pending ? `<div class="chain-list">${pending}</div>` : '<div class="empty">没有待确认的处置动作</div>', {
    actions: `<button class="btn sm" data-act="pb-reload">重载剧本</button>`,
    tag: '人工审批门',
  })}
  ${panel('剧本清单', table([
    { t: 'ID' }, { t: '名称' }, { t: '触发条件' }, { t: '动作序列' }, { t: '执行方式' }, { t: '状态' },
  ], pbRows, { empty: '无剧本' }), {
    actions: (d.errors || []).length ? `<span class="panel-tag red">${esc(d.errors.join('；'))}</span>` : '',
    tag: 'YAML 声明式',
  })}
  ${panel('执行记录', table([
    { t: '时间', c: 'nowrap' }, { t: '剧本' }, { t: '名称' }, { t: '关联攻击链' }, { t: '状态' }, { t: '结果' },
  ], histRows, { empty: '暂无执行记录' }))}
  <div class="act-desc">剧本文件位于 <span class="mono">~/.atfield/playbooks/*.yaml</span>，改完点「重载剧本」立即生效；
  默认 require_confirm=true —— 处置可以建议，但动别人的进程要先留人工确认痕迹。</div>`;
}

/* ---------------- 视图：工单 ---------------- */
async function viewTickets() {
  const d = await API('/api/tickets?limit=200');
  const list = d.tickets || [];
  const rows = list.map(t => [
    `<span class="mono">${esc(t.tid)}</span>`, clip(t.title, 52), sev(t.severity),
    `<span class="st st-${t.status === 'closed' ? 'pass' : t.status === 'ack' ? 'warn' : 'fail'}">${esc(CN.tk[t.status] || t.status)}</span>`,
    esc(t.source || ''), `<span class="mono">${esc(t.created_cn || '')}</span>`,
    `<button class="btn sm" data-act="tk-ack" data-tid="${esc(t.tid)}">受理</button>
     <button class="btn sm" data-act="tk-close" data-tid="${esc(t.tid)}">关闭</button>
     <button class="btn sm" data-act="tk-note" data-tid="${esc(t.tid)}">备注</button>`,
  ]);
  return `
  ${panel('新建工单', `
    <div class="filters">
      <input type="text" id="tk-title" placeholder="标题" style="min-width:260px">
      <select id="tk-sev"><option value="medium">中危</option><option value="high">高危</option>
        <option value="critical">严重</option><option value="low">低危</option></select>
      <input type="text" id="tk-ref" placeholder="关联规则/对象" style="min-width:160px">
      <button class="btn sm mint" data-act="tk-new">创建</button>
    </div>`, { tag: '处置闭环' })}
  ${panel('工单列表', table([
    { t: '工单' }, { t: '标题' }, { t: '等级' }, { t: '状态' }, { t: '来源' }, { t: '创建时间' }, { t: '操作' },
  ], rows, { empty: '暂无工单：剧本触发或手工创建后出现在这里' }), { actions: `<span class="count-hint">${num(list.length)} 条</span>` })}`;
}

/* ---------------- 视图：资产软件 ---------------- */
async function viewInventory() {
  const d = await API('/api/inventory');
  if (d.scanning) {
    return panel('资产与软件清单', `<div class="empty">首次扫描已在后台开始，几秒后刷新本页即可看到结果。</div>`, {
      actions: `<button class="btn sm" data-act="refresh">刷新</button>`,
    });
  }
  const remoteRows = (d.remote || []).map(a => [
    esc(a.name || ''), `<span class="mono">${esc(a.version || '')}</span>`,
    esc(a.bundle_id || ''), clip(a.path, 52),
  ]);
  const staleRows = (d.stale || []).map(a => [
    esc(a.name || ''), `<span class="mono">${esc(a.version || '')}</span>`,
    `<span class="mono">${esc(a.modified_cn || '')}</span>`, `<span class="mono">${esc(a.age_days)} 天</span>`,
  ]);
  const secRows = (d.security_tools || []).map(a => [
    esc(a.name || ''), `<span class="mono">${esc(a.version || '')}</span>`, clip(a.path, 52),
  ]);
  const byCat = Object.entries(d.by_category || {}).map(([k, v]) => `${CN.cat[k] || k} ${v}`).join('　');
  return `
  <div class="kpis">
    ${kpi('已登记应用', num(d.apps || 0), byCat || '—', 'var(--mint)')}
    ${kpi('长期未更新', num(d.stale_count || 0), '超过 18 个月未变动（线索，非结论）', 'var(--amber)')}
    ${kpi('签名异常', num(d.unsigned_count || 0), 'codesign 校验失败', 'var(--red)')}
    ${kpi('远程控制软件', num((d.remote || []).length), '横向移动高频入口', 'var(--orange)')}
  </div>
  ${panel('远程控制类软件', table([
    { t: '名称' }, { t: '版本' }, { t: 'Bundle ID' }, { t: '路径' },
  ], remoteRows, { empty: '未检测到远程控制类应用' }), {
    actions: `<button class="btn sm" data-act="inv-scan">重新扫描</button>`,
    tag: '重点关注',
  })}
  <div class="grid-2">
    ${panel('长期未更新（前 60）', table([
      { t: '应用' }, { t: '版本' }, { t: '最后修改' }, { t: '距今' },
    ], staleRows, { empty: '无' }))}
    ${panel('安全类软件', table([
      { t: '应用' }, { t: '版本' }, { t: '路径' },
    ], secRows, { empty: '未检测到第三方安全软件（系统自带防护见基线视图）' }))}
  </div>
  <div class="act-desc">CVE 映射表已导入 ${num(d.cve_map_size || 0)} 个产品（可选）。版本老化只作为复核线索，不直接判定为漏洞。</div>`;
}

/* ---------------- 视图：合规 ---------------- */
async function viewCompliance() {
  let d = await API('/api/compliance');
  if (!d || !d.rows || !d.rows.length) d = await API('/api/compliance/rebuild', { method: 'POST', body: {} });
  const fw = d.frameworks || {};
  const cards = Object.entries(fw).map(([k, v]) => kpi(
    k, `${Number(v.score || 0).toFixed(0)}<small>分</small>`,
    `通过 ${v.pass} · 不合格 ${v.fail} · 警告 ${v.warn} · 未判定 ${v.unknown}`,
    v.score >= 85 ? 'var(--mint)' : v.score >= 60 ? 'var(--amber)' : 'var(--red)', v.score
  )).join('');
  const rows = (d.rows || []).map(r => [
    `<span class="mono">${esc(r.control)}</span>`, esc(r.framework), esc(r.title), stBadge(r.status),
    clip((r.evidence || []).map(e => `${e.id || ''} ${e.title || ''}`).join('；'), 62),
  ]);
  return `
  <div class="kpis">${cards}</div>
  ${panel('合规矩阵', table([
    { t: '条款' }, { t: '框架' }, { t: '要求' }, { t: '状态' }, { t: '对应检查项' },
  ], rows, { empty: '尚未生成：请先等待基线检查完成' }), {
    actions: `<button class="btn sm" data-act="comp-rebuild">重建矩阵</button>`,
    tag: esc(d.generated_cn || ''),
  })}
  <div class="act-desc">${esc(d.basis || '')}</div>`;
}

/* ---------------- 视图：基线 ---------------- */
async function viewBaseline() {
  const a = await API('/api/assets');
  const b = a.baseline || {};
  const res = b.results || [];
  const cats = {};
  res.forEach(r => { (cats[r.category] = cats[r.category] || []).push(r); });
  const blocks = Object.entries(cats).map(([cat, items]) => `
    <div class="cat-block">
      <div class="cat-title">${esc(cat)} · ${num(items.length)} 项</div>
      ${table([
        { t: '状态' }, { t: '检查项' }, { t: '证据' }, { t: '整改建议' },
      ], items.map(r => [
        stBadge(r.status), esc(r.name || r.id || ''),
        clip(r.evidence || '', 60), clip(r.advice || '', 70),
      ]))}
    </div>`).join('');
  const c = b.counts || {};
  return `
  <div class="kpis">
    ${kpi('通过', num(c.pass || 0), '配置符合基线', 'var(--mint)')}
    ${kpi('警告', num(c.warn || 0), '建议整改', 'var(--amber)')}
    ${kpi('不合格', num(c.fail || 0), '需立即处理', 'var(--red)')}
    ${kpi('未判定', num(c.unknown || 0), '权限不足或环境不支持', 'var(--blue)')}
  </div>
  ${panel('基线检查明细', blocks || '<div class="empty">基线检查尚未完成</div>', { tag: `共 ${res.length} 项` })}`;
}

/* ---------------- 视图：响应与审计 ---------------- */
async function viewResponse() {
  const [acts, tk, sup, fw] = await Promise.all([
    API('/api/actions'), API('/api/tickets?limit=20'), API('/api/suppress'),
    API('/api/firewall').catch(() => ({})),
  ]);
  const rows = (acts.actions || []).slice().reverse().slice(0, 120).map(a => [
    `<span class="mono">${esc(tsStr(a.ts))}</span>`, esc(a.actor || ''), esc(a.action || ''),
    clip(a.target || '', 40), clip(a.result || '', 50),
  ]);
  const sale = S.cache.selftest;
  return `
  <div class="act-grid">
    ${panel('进程处置', `
      <div class="act-desc">非 root 只能操作同用户进程；PID ≤ 1 与平台自身进程被硬拒绝。所有动作写入审计。</div>
      <div class="act-row">
        <input type="number" id="rp-pid" placeholder="PID" style="min-width:110px">
        <button class="btn sm danger" data-act="rp-terminate">终止</button>
        <button class="btn sm" data-act="rp-suspend">挂起</button>
        <button class="btn sm" data-act="rp-resume">恢复</button>
      </div>`, { tag: '受控' })}
    ${panel('主机防火墙', (() => {
      const f = fw || {};
      const tone = f.tone || 'off';
      const chips = (f.blocked || []).map(ip =>
        `<span class="fw-chip">${esc(ip)}<button data-act="fw-unblock" data-ip="${esc(ip)}" title="解封这个">×</button></span>`
      ).join('');
      return `
      <div class="fw-state">
        <span class="fw-lamp ${esc(tone)}"></span>
        <b>${esc(f.label || '未知')}</b>
        <span class="fw-meta">pf ${f.pf_enabled ? '已开启' : '未开启'}
          · anchor ${f.attached === true ? '已挂载' : '未挂载'}
          · ${num(f.count || 0)} 条阻断</span>
      </div>
      ${f.detail ? `<div class="fw-note">${esc(f.detail)}</div>` : ''}
      <div class="act-row">
        <input type="text" id="fw-ip" placeholder="IP 或 CIDR，如 203.0.113.9" style="min-width:210px">
        <input type="text" id="fw-why" placeholder="理由（会写进审计）" style="min-width:170px">
        <button class="btn sm danger" data-act="fw-block">阻断</button>
        <button class="btn sm" data-act="fw-unblock">解封</button>
      </div>
      ${chips ? `<div class="fw-chips">${chips}</div>`
              : '<div class="fw-empty">当前没有阻断目标</div>'}`;
    })(), { tag: (fw && fw.tone) === 'on' ? '在位' : ((fw && fw.tone) === 'warn' ? '待挂载' : '未启用') })}
    ${panel('边界与证据', `
      <div class="act-desc">封禁只生成可复核的命令（pfctl / 路由），不会静默改防火墙；证据导出会打包事件、告警、攻击链与审计。</div>
      <div class="act-row">
        <input type="text" id="rp-ip" placeholder="对端 IP" style="min-width:170px">
        <button class="btn sm" data-act="rp-block">生成封禁命令</button>
        <button class="btn sm mint" data-act="rp-export">导出证据包</button>
        <button class="btn sm" data-act="rp-selftest">运行自检</button>
      </div>
      <pre class="out" id="rp-out">等待操作…</pre>`, { tag: '只读优先' })}
  </div>
  ${panel('处置审计', table([
    { t: '时间', c: 'nowrap' }, { t: '操作者' }, { t: '动作' }, { t: '对象' }, { t: '结果' },
  ], rows, { empty: '暂无处置动作' }), { actions: `<span class="count-hint">${num((acts.actions || []).length)} 条</span>` })}
  ${panel('误报抑制', `
    <div class="act-desc">抑制必须留下依据：可指定规则 ID 与关键字（子串匹配详情/进程/路径/命令行）。
    已抑制 ${num(sup.suppressed_total || 0)} 次，规则 ${num(sup.count || 0)} 条。抑制不删证据，只不再重复告警。</div>
    <div class="filters">
      <input type="text" id="sup-rule" placeholder="规则 ID（可留空）" style="min-width:130px">
      <input type="text" id="sup-contains" placeholder="关键字，如某内部工具名" style="min-width:220px">
      <input type="text" id="sup-note" placeholder="依据/工单号" style="min-width:150px">
      <button class="btn sm" data-act="sup-add">添加抑制</button>
    </div>
    ${table([{ t: '规则' }, { t: '关键字' }, { t: '依据' }, { t: '操作' }],
    (sup.items || []).map((s, i) => [
      `<span class="mono">${esc(s.rule_id || '（全部规则）')}</span>`,
      clip(s.contains || '（同规则全抑制）', 40), clip(s.note || '', 40),
      `<button class="btn sm danger" data-act="sup-del" data-index="${i}">撤销</button>`,
    ]), { empty: '暂无抑制规则' })}`, { tag: esc(sup.path || '') })}
  ${sale ? panel('最近一次自检结果', `<pre class="out">${esc(JSON.stringify(sale, null, 2))}</pre>`, { tag: '合成事件' }) : ''}`;
}

/* ---------------- 视图：采集通道 ---------------- */
function viewCollectors() {
  const o = S.o || {}, coll = o.collectors || [];
  const rows = coll.map(c => [
    esc(c.name || ''), esc(c.mode || ''), `<span class="mono">${esc(c.interval == null ? '—' : c.interval + 's')}</span>`,
    c.enabled ? '<span class="st st-pass">启用</span>' : '<span class="st st-unknown">停用</span>',
    c.available ? '<span class="st st-pass">可用</span>' : '<span class="st st-fail">不可用</span>',
    num(c.runs || 0), num(c.errors || 0),
    clip(c.reason || c.last_error || '', 60),
    `<span class="mono">${c.last_ms ? c.last_ms.toFixed(1) + 'ms' : '—'}</span>`,
  ]);
  const tel = o.telemetry || {};
  const ls = tel.logstream || {}, pv = tel.privileged || {};
  return `
  ${panel('采集通道状态', table([
    { t: '通道' }, { t: '模式' }, { t: '周期' }, { t: '开关' }, { t: '可用性' }, { t: '轮次' }, { t: '错误' }, { t: '说明' }, { t: '耗时' },
  ], rows, { empty: '无采集器' }), { tag: `共 ${coll.length} 个` })}
  <div class="grid-2">
    ${panel('统一日志流', miniRows([
      ['状态', ls.available === false ? '不可用' : (ls.enabled === false ? '未启用' : '运行中')],
      ['已采集', num(ls.count || ls.lines || 0) + ' 条'],
      ['说明', ls.reason || ls.last_error || '订阅 macOS unified log'],
    ]), { tag: '非特权' })}
    ${panel('EndpointSecurity（root 增强）', miniRows([
      ['状态', pv.enabled ? '已启用' : '未启用'],
      ['原因', pv.reason || (tel.eslogger_root ? '已取得 root' : '需要 root 才能订阅 eslogger')],
      ['用途', '实时 exec/open/rename/kextload 等事件'],
    ]), { tag: '可选' })}
  </div>`;
}

/* ---------------- 认证（RBAC） ---------------- */
const AUTH = { user: null, role: '', caps: [], mustChange: false, ready: false };
const ROLE_CN = { admin: '管理员', responder: '响应处置', analyst: '研判分析', viewer: '只读' };
function can(cap) { return (AUTH.caps || []).indexOf(cap) >= 0; }

async function loadMe() {
  try {
    const me = await API('/api/auth/me', { noLoginRedirect: true });
    AUTH.user = me.user;
    AUTH.role = me.role || '';
    AUTH.caps = me.caps || [];
    AUTH.mustChange = !!me.must_change;
    AUTH.ready = true;
    paintUser();
    return true;
  } catch (e) {
    AUTH.ready = false;
    return false;
  }
}
function paintUser() {
  const el = $('#who');
  if (!el) return;
  // 账号区折成一个按钮 + 菜单：顶栏原来 8 个元素并排，太挤
  el.innerHTML =
    `<button class="who-btn" id="who-btn" aria-haspopup="menu" aria-expanded="false">` +
      `<span class="who-dot"></span><b>${esc(AUTH.user || '—')}</b>` +
      `<span class="who-role r-${esc(AUTH.role)}">${esc(ROLE_CN[AUTH.role] || AUTH.role)}</span>` +
      `<span class="who-caret" aria-hidden="true">▾</span>` +
    `</button>` +
    `<div class="who-menu" id="who-menu" role="menu" hidden>` +
      `<div class="who-menu-hd">${esc(AUTH.user || '—')} · ${esc(ROLE_CN[AUTH.role] || AUTH.role)}</div>` +
      `<button class="who-item" role="menuitem" data-act="gov-logout">退出登录</button>` +
    `</div>`;
  el.hidden = false;
}
function showLogin(msg) {
  const ov = $('#login');
  if (!ov) return;
  ov.hidden = false;
  const e = $('#login-err');
  if (e) e.textContent = msg || '';
  const u = $('#login-user');
  if (u && !u.value) setTimeout(() => u.focus(), 60);
}
function hideLogin() {
  const o = $('#login');
  if (o) o.hidden = true;
}
async function doLogin(ev) {
  if (ev) ev.preventDefault();
  const user = ($('#login-user').value || '').trim();
  const pw = $('#login-pass').value || '';
  const err = $('#login-err');
  err.textContent = '';
  if (!user || !pw) { err.textContent = '请输入账号与口令'; return; }
  const btn = $('#login-go');
  btn.disabled = true; btn.textContent = '验证中…';
  try {
    const r = await API('/api/auth/login', { method: 'POST', body: { user, password: pw }, noLoginRedirect: true });
    $('#login-pass').value = '';
    AUTH.user = r.user; AUTH.role = r.role; AUTH.caps = r.caps || [];
    AUTH.mustChange = !!r.must_change; AUTH.ready = true;
    paintUser();
    hideLogin();
    await boot(true);
    if (AUTH.mustChange) toast('当前仍是初始口令，请尽快在「治理与审计链」里改掉', 'err');
  } catch (e) {
    err.textContent = e.message || '登录失败';
  } finally {
    btn.disabled = false; btn.textContent = '登录';
  }
}
async function doLogout() {
  try { await API('/api/auth/logout', { method: 'POST', body: {} }); } catch (e) { /* 已失效也继续 */ }
  AUTH.user = null; AUTH.role = ''; AUTH.caps = []; AUTH.ready = false;
  const el = $('#who');
  if (el) el.hidden = true;
  if (sse) { try { sse.close(); } catch (e) {} sse = null; }
  S.o = null;
  showLogin('已退出登录');
}

/* ---------------- 视图：治理与审计链 ---------------- */
function govRowColor(ok) { return ok ? 'var(--mint)' : 'var(--red)'; }

async function viewGovernance() {
  let g = {}, a = { records: [], stats: {}, anchor: {} }, users = [], roles = [];
  try { g = await API('/api/governance'); } catch (e) { g = { error: e.message || String(e) }; }
  try { a = await API('/api/audit?limit=40'); } catch (e) { /* 保留空表 */ }
  if (can('admin')) {
    try { const u = await API('/api/users'); users = u.users || []; roles = u.roles || []; } catch (e) {}
  }
  const au = g.audit || {}, ga = g.auth || {}, up = g.updates || {}, ru = g.rules || {};
  const br = up.breaker || {};
  const vr = S.cache.auditVerify || null;
  const mw = S.cache.monthly || null;
  const recs = (a.records || []).slice().reverse();
  const packs = ru.packs || [];

  const kpis = `<div class="kpis">
    ${kpi('审计记录', num(au.records || 0), `分片 ${num(au.segments || 0)} · ${(au.bytes || 0) >= 1048576
      ? (au.bytes / 1048576).toFixed(1) + ' MB'
      : (au.bytes || 0) >= 1024 ? Math.round(au.bytes / 1024) + ' KB' : (au.bytes || 0) + ' B'}`,
      'var(--blue)')}
    ${kpi('账号', num(ga.users || 0), `管理员 ${num(ga.admins || 0)} · 在线会话 ${num(ga.sessions || 0)}`, 'var(--mint)')}
    ${kpi('检测规则', num(ru.total || 0), `外部规则包 ${num(packs.length)} 个`, 'var(--orange)')}
    ${kpi('更新通道', esc(up.installed_version || '—'),
      `熔断 ${br.open ? '已触发（剩 ' + Math.round((br.seconds_left || 0) / 60) + ' 分）' : '未触发'} · LKG ${esc(up.lkg_version || '无')}`,
      br.open ? 'var(--red)' : 'var(--mint)')}
  </div>`;

  const chain = `
    <div class="gov-line"><span>链头哈希</span><code class="hk">${esc((a.stats || {}).head || '—')}</code></div>
    <div class="gov-line"><span>保留策略</span><b>${num(au.retain_days || 0)} 天 / ${num(Math.round(au.retain_total_mb || 0))} MB</b></div>
    <div class="gov-line"><span>HMAC 锚点</span><b>${esc((a.anchor || {}).hash ? '已签名 ' + String((a.anchor || {}).hash).slice(0, 12) + '…' : '尚未生成')}</b></div>
    ${vr ? `<div class="gov-verdict ${vr.ok ? 'ok' : 'bad'}">
        ${vr.ok ? `链路完整：校验 ${num(vr.checked || 0)} 条记录，${num(vr.issue_count || 0)} 处异常`
                : `发现 ${num(vr.issue_count || 0)} 处异常：${esc(((vr.issues || [])[0] || {}).kind || '未知')}`}
        <i>${esc(vr.verified_at_cn || '')}</i></div>` : ''}
    <div class="gov-actions">
      <button class="btn sm" data-act="gov-verify">校验审计链</button>
      <a class="btn sm" href="/api/audit" target="_blank" rel="noreferrer">查看原始 JSON</a>
    </div>`;

  const recTable = table(
    [{ t: '时间' }, { t: '动作' }, { t: '操作者' }, { t: '目标', c: 'clip-cell' }, { t: '结果' }, { t: '哈希' }],
    recs.map(r => [
      esc(r.ts_cn || tsStr(r.ts)),
      `<b>${esc(r.action || '')}</b>`,
      `${esc(r.actor || '')}<span class="muted"> / ${esc(r.role || '')}</span>`,
      clip(r.target || '—', 42),
      ({ ok: '<span class="st st-pass">成功</span>',
         deny: '<span class="sev sev-high">拒绝</span>',
         blocked: '<span class="sev sev-medium">熔断拦截</span>',
         locked: '<span class="sev sev-medium">账号锁定</span>',
       })[r.result] || `<span class="st st-fail">${esc(r.result || '—')}</span>`,
      `<code class="hk">${esc(String(r.hash || '').slice(0, 10))}</code>`,
    ]), { empty: '还没有审计记录' });

  const upd = `
    <div class="gov-line"><span>当前版本</span><b>${esc(up.current_version || '—')}</b></div>
    <div class="gov-line"><span>已安装</span><b>${esc(up.installed_version || '—')} ${esc(up.installed_cn || '')}</b></div>
    <div class="gov-line"><span>最近可用（LKG）</span><b>${esc(up.lkg_version || '无')}</b></div>
    <div class="gov-line"><span>签名校验</span><b>${up.require_signature ? '强制' : '关闭'} · 指纹 ${esc(up.key_fingerprint || '—')}</b></div>
    <div class="gov-line"><span>受管目录</span><b>${(up.roots || []).map(esc).join(' / ') || '—'}</b></div>
    <div class="gov-line"><span>熔断器</span><b style="color:${govRowColor(!br.open)}">${br.open
      ? `已打开（连续失败 ${num(br.fail_count || 0)} 次，冷却 ${Math.round((br.seconds_left || 0) / 60)} 分）`
      : `关闭（阈值 ${num(br.threshold || 0)} 次 / 冷却 ${Math.round((br.cooldown_seconds || 0) / 3600)} 小时）`}</b></div>
    <div class="gov-actions">
      <button class="btn sm" data-act="gov-rules-reload">重载规则包</button>
      ${can('admin') ? `<button class="btn sm" data-act="gov-apply">应用更新包…</button>
        <button class="btn sm danger" data-act="gov-rollback">回滚到 LKG</button>
        <button class="btn sm" data-act="gov-breaker-reset">解除熔断</button>
        <button class="btn sm" data-act="gov-export">导出当前基线</button>` : '<span class="muted">更新与回滚需要管理员</span>'}
    </div>
    `;

  // 规则包拆成独立一张卡：塞在更新通道里会把右列拉到 400+，左列只有 190，版面空一半
  const packsHtml = packs.length
    ? `<div class="mini-rows">${packs.map(p => `<div class="mini-row">
        <span class="sq ${p.error ? 'err' : 'ok'}"></span>
        <span class="nm">${esc(p.pack || p.file || '包')}</span>
        <span class="count-hint">${num(p.rules || 0)} 条</span></div>`).join('')}</div>`
    : '<div class="empty">未加载外部规则包（~/.atfield/rules/*.yaml）</div>';

  const userPanel = can('admin') ? `
    ${table([{ t: '账号' }, { t: '角色' }, { t: '初口令' }, { t: '最近登录' }, { t: '操作' }],
    users.map(u => [
      `<b>${esc(u.user)}</b>`,
      `<span class="who-role r-${esc(u.role)}">${esc(ROLE_CN[u.role] || u.role)}</span>`,
      u.must_change ? '<span class="sev sev-medium">待修改</span>' : '<span class="muted">已改</span>',
      esc(u.last_login_cn || '—'),
      `<button class="btn sm" data-act="gov-user-passwd" data-user="${esc(u.user)}">改口令</button>
       <button class="btn sm" data-act="gov-user-role" data-user="${esc(u.user)}">改角色</button>
       <button class="btn sm danger" data-act="gov-user-del" data-user="${esc(u.user)}">删除</button>`,
    ]), { empty: '只有一个初始管理员' })}
    <div class="gov-form">
      <input id="nu-user" placeholder="新账号" spellcheck="false">
      <input id="nu-pass" type="password" placeholder="初始口令（≥12 位）">
      <select id="nu-role">${['viewer', 'analyst', 'responder', 'admin']
        .map(r => `<option value="${r}"${r === 'viewer' ? ' selected' : ''}>${ROLE_CN[r]}</option>`).join('')}</select>
      <button class="btn sm primary" data-act="gov-user-add">新增账号</button>
    </div>
    <div class="gov-note">角色能力：只读＝看板；研判分析＝+情报/抑制/工单；响应处置＝+终止进程/封禁；管理员＝+账号/更新/回滚/邮件。</div>`
    : `<div class="empty">账号管理需要管理员权限（当前：${esc(ROLE_CN[AUTH.role] || AUTH.role)}）</div>`;

  const monthly = `
    <div class="gov-actions">
      <button class="btn sm primary" data-act="gov-monthly-preview">生成预览</button>
      <button class="btn sm primary" data-act="gov-monthly-save">保存到磁盘</button>
      ${can('admin') ? '<button class="btn sm" data-act="gov-monthly-send">邮件投递</button>' : ''}
      <a class="btn sm" href="/api/monthly/file?fmt=html" download>下载 HTML</a>
      <a class="btn sm" href="/api/monthly/file?fmt=md" download>下载 Markdown</a>
    </div>
    ${mw ? `<div class="gov-line"><span>报告月份</span><b>${esc(mw.month || '')}（${esc(mw.range_cn || '')}）</b></div>
      <pre class="out gov-md">${esc((mw.markdown || '').slice(0, 4000))}</pre>` : '<div class="empty">点「生成预览」看本月月报</div>'}`;

  return `${kpis}
    <div class="grid-2">
      <div class="gov-col">
        ${panel('审计链完整性', chain, { tag: 'append-only', tagCls: 'mint' })}
        ${panel('外部规则包', packsHtml, { tag: `${num(packs.length)} 个包` })}
      </div>
      ${panel('更新通道与回滚', upd, { tag: '签名 + 健康探针', tagCls: 'mint' })}
    </div>
    ${panel('最近审计记录', recTable, { tag: '不可篡改哈希链' })}
    <div class="grid-2">
      ${panel('账号与角色（RBAC）', userPanel, { tag: can('admin') ? '可管理' : '只读' })}
      ${panel('月度报告', monthly, { tag: '等保审计材料' })}
    </div>`;
}

/* ---------------- 治理操作 ---------------- */
function bindGovernance() {
  document.addEventListener('submit', e => {
    if (e.target && e.target.id === 'login-form') doLogin(e);
  });
  document.addEventListener('click', async e => {
    const b = e.target.closest('[data-act]');
    if (!b) return;
    const act = b.dataset.act;
    if (!act || act.indexOf('gov-') !== 0) return;
    try {
      if (act === 'gov-logout') { await doLogout(); return; }
      if (act === 'gov-verify') {
        toast('正在校验审计链…');
        const r = await API('/api/audit/verify', { method: 'POST', body: {} });
        S.cache.auditVerify = r;
        toast(r.ok ? `链路完整，校验 ${r.checked} 条` : `发现 ${r.issue_count} 处异常`, r.ok ? 'ok' : 'err');
        render();
      } else if (act === 'gov-rules-reload') {
        const r = await API('/api/rules/reload', { method: 'POST', body: {} });
        toast(`已重载 ${r.rules} 条规则（外部 ${r.external }）`);
        render();
      } else if (act === 'gov-rollback') {
        if (!window.confirm('回滚会把规则与剧本恢复到上一个可用版本，继续？')) return;
        const r = await API('/api/updates/rollback', { method: 'POST', body: { reason: '控制台手工回滚' } });
        toast(r.ok ? `已回滚到 ${r.lkg_version || '上一版本'}` : (r.error || '回滚失败'), r.ok ? 'ok' : 'err');
        render();
      } else if (act === 'gov-breaker-reset') {
        await API('/api/updates/reset', { method: 'POST', body: {} });
        toast('熔断已解除');
        render();
      } else if (act === 'gov-apply') {
        const dir = window.prompt('更新包目录（含 manifest.json）');
        if (!dir) return;
        const r = await API('/api/updates/apply', { method: 'POST', body: { dir } });
        toast(r.ok ? `已应用 ${r.version || ''}` : (r.error || '应用失败'), r.ok ? 'ok' : 'err');
        render();
      } else if (act === 'gov-export') {
        const dest = window.prompt('导出目录', '');
        if (dest === null) return;
        const r = await API('/api/updates/export', { method: 'POST', body: { dest: dest || '' } });
        toast(r.ok ? `已导出基线到 ${r.path || dest}` : (r.error || '导出失败'), r.ok ? 'ok' : 'err');
      } else if (act === 'gov-user-add') {
        const user = ($('#nu-user').value || '').trim();
        const password = $('#nu-pass').value || '';
        const role = $('#nu-role').value;
        if (!user || !password) return toast('账号与口令都要填', 'err');
        const r = await API('/api/users/add', { method: 'POST', body: { user, password, role } });
        toast(r.ok ? `已创建 ${user}（${ROLE_CN[role]}）` : (r.error || '创建失败'), r.ok ? 'ok' : 'err');
        $('#nu-user').value = ''; $('#nu-pass').value = '';
        render();
      } else if (act === 'gov-user-passwd') {
        const user = b.dataset.user;
        const pw = window.prompt(`给 ${user} 设置新口令（≥12 位，含大小写与数字）`);
        if (!pw) return;
        const url = user === AUTH.user ? '/api/auth/passwd' : '/api/users/passwd';
        const r = await API(url, { method: 'POST', body: { user, password: pw } });
        toast(r.ok ? '口令已更新' : (r.error || '更新失败'), r.ok ? 'ok' : 'err');
        render();
      } else if (act === 'gov-user-role') {
        const user = b.dataset.user;
        const role = window.prompt(`给 ${user} 设置角色：admin / responder / analyst / viewer`);
        if (!role) return;
        const r = await API('/api/users/role', { method: 'POST', body: { user, role: role.trim() } });
        toast(r.ok ? `已设为 ${ROLE_CN[r.role] || r.role}` : (r.error || '修改失败'), r.ok ? 'ok' : 'err');
        render();
      } else if (act === 'gov-user-del') {
        const user = b.dataset.user;
        if (!window.confirm(`删除账号 ${user}？该账号在线会话会立即失效。`)) return;
        const r = await API('/api/users/delete', { method: 'POST', body: { user } });
        toast(r.ok ? `已删除 ${user}` : (r.error || '删除失败'), r.ok ? 'ok' : 'err');
        render();
      } else if (act === 'gov-monthly-preview') {
        const r = await API('/api/monthly');
        S.cache.monthly = { month: (r.data || {}).month, range_cn: (r.data || {}).range_cn, markdown: r.markdown };
        toast('已生成月报预览');
        render();
      } else if (act === 'gov-monthly-save' || act === 'gov-monthly-send') {
        const send = act === 'gov-monthly-send';
        const r = await API('/api/monthly', { method: 'POST', body: { month: '', send } });
        if (r.ok) {
          const p = (r.paths || {});
          toast(send
            ? (r.delivery && r.delivery.ok ? '已投递到 ' + (r.delivery.to || '收件人') : ('文件已生成，邮件未发：' + ((r.delivery || {}).reason || '未配置 SMTP')))
            : '已保存：' + (p.md || p.html || 'exports/monthly'));
        } else {
          toast(r.error || '生成失败', 'err');
        }
        render();
      }
    } catch (err) {
      toast(err.message || String(err), 'err');
    }
  });
}

/* ---------------- 路由与刷新 ---------------- */

/* ---------------- 视图：心之壁 ---------------- */
const WALL_ST = {
  sealed: { cls: 'seal',   cn: '守住', hint: '有策略覆盖，这段时间没观测到异常' },
  wave:   { cls: 'wave',   cn: '波动', hint: '被试探过，但挡住了' },
  breach: { cls: 'breach', cn: '穿透', hint: '已经发生真实越界' },
  quiet:  { cls: 'quiet',  cn: '静默', hint: '没观测到异常，也没有证据说守住了' },
};

// AI 的判定用同一套力场语言说出来，别让人在两种术语之间来回翻译
const JUDGE_VERDICT = {
  benign:     { cn: '力场未动', cls: 'seal',   hint: '这个行为没有越过任何边界' },
  suspicious: { cn: '力场波动', cls: 'wave',   hint: '边界被碰了一下，但还没破' },
  malicious:  { cn: '力场穿透', cls: 'breach', hint: '边界已经被越过' },
  uncertain:  { cn: '判读不明', cls: 'quiet',  hint: '模型给不出结论，需要人来定' },
};

/* 心之壁徽记：本体那个八角形。
   八边形的「边」就是墙本身——五条边界各占一圈 20% 的周长，
   守住是实弧、波动在闪、静默是细线、穿透则在这段墙上真的开个口子。
   只画 /api/barrier 已经算好的状态，不产生任何新数据。 */
function wallField(d) {
  const rows = (d.barriers || []).slice(0, 5);
  const sealed = rows.filter(b => b.state === 'sealed').length;
  const breached = Number(d.breached || 0);
  const cx = 60, cy = 60;

  // 平顶平底的八边形路径（顶点落在 22.5° + 45°k）
  const octPath = r => {
    let p = '';
    for (let i = 0; i < 8; i++) {
      const t = (22.5 + 45 * i) * Math.PI / 180;
      p += (i ? 'L' : 'M') + (cx + r * Math.cos(t)).toFixed(2) + ' ' +
           (cy + r * Math.sin(t)).toFixed(2);
    }
    return p + 'Z';
  };
  const octPts = r => {
    const a = [];
    for (let i = 0; i < 8; i++) {
      const t = (22.5 + 45 * i) * Math.PI / 180;
      a.push((cx + r * Math.cos(t)).toFixed(2) + ',' + (cy + r * Math.sin(t)).toFixed(2));
    }
    return a.join(' ');
  };
  const RING = octPath(50);
  const step = rows.length ? 100 / rows.length : 20;

  const arcs = rows.map((b, i) => {
    const st = WALL_ST[b.state] || WALL_ST.quiet;
    // 五块墙板：板间留 1.4% 的缝，端点因此都落在直边上，不会切在拐角错位
    const GAP = 1.4;
    const plate = step - GAP;
    const rest = (100 - plate).toFixed(2);
    // 破口：这块墙板自己从中间断开，缺口固定 6 单位
    const dash = b.state === 'breach'
      ? ((plate - 6) / 2).toFixed(2) + ' 6 ' + ((plate - 6) / 2).toFixed(2) + ' ' + rest
      : plate.toFixed(2) + ' ' + rest;
    const off = (-(step * i + GAP / 2)).toFixed(2);
    return `<path class="wf-arc ${st.cls}" d="${RING}" pathLength="100"`
         + ` stroke-dasharray="${dash}" stroke-dashoffset="${off}">`
         + `<title>${esc(b.cn)} · ${esc(st.cn)} · ${Number(b.score || 0)} 分`
         + `${b.state === 'breach' ? ' —— 这段墙已经开了口子' : ''}</title></path>`;
  }).join('');

  const solid = !breached && rows.length > 0 && sealed === rows.length;
  const cls = 'wall-field' + (breached ? ' is-breach' : (solid ? ' is-solid' : ''));
  const cap = breached ? '心之壁 · 破损' : (solid ? '心之壁 · 完整' : '心之壁 · 展开');
  // 点徽记跳到该看的那条：先看有没有被穿透的，没有就跳最弱
  const focus = rows.find(b => b.state === 'breach')
    || rows.slice().sort((a, b) => Number(a.score || 0) - Number(b.score || 0))[0] || {};
  const goto = esc(focus.key || d.weakest || '');
  const gotoCap = '点击定位到「' + esc(focus.cn || '') + '」';

  return `
  <div class="${cls}" data-goto="${goto}" role="button" tabindex="0"
       title="八边形的边就是墙，断口即穿透 · 点击定位到最需要看的那条边界">
    <svg viewBox="0 0 120 120" aria-hidden="true">
      <circle class="wf-halo" cx="60" cy="60" r="57"/>
      <polygon class="wf-veil" points="${octPts(41)}"/>
      ${arcs}
    </svg>
    <div class="wall-field-cap">${esc(cap)}</div>
    <div class="wall-field-hint">${gotoCap}</div>
  </div>`;
}

async function viewWall() {
  const d = await API('/api/barrier');
  const rows = d.barriers || [];
  const strength = Math.max(0, Math.min(100, Number(d.strength || 0)));
  const gradeCls = strength >= 80 ? 'seal' : strength >= 50 ? 'wave' : 'breach';

  // fid → 边界名，用来把 AI 判读归到对应那条墙上
  const fidWall = {};
  rows.forEach(b => (b.fids || []).forEach(f => { if (f) fidWall[f] = b.cn; }));

  let judgeBody = '';
  let cfgWarn = '';
  try {
    // 先看配置读到了没有：读失败时功能是静默关闭的，必须让人看见
    const st = await API('/api/ai/status').catch(() => ({}));
    if (st && st.config_error) {
      cfgWarn = `<div class="wall-warn">配置读取异常：${esc(st.config_error)}
        <span>（文件 ${esc(st.config_path || '—')}，本次运行使用默认值）</span></div>`;
    }
    const sg = await API('/api/ai/suggestions?limit=40');
    const list = (sg.suggestions || []).filter(x => x.kind !== 'ping' && x.verdict);
    if (!list.length) {
      judgeBody = st.enabled
        ? '<div class="empty">还没有判读记录。等有告警需要定性时，判读结果会出现在这里。</div>'
        : '<div class="empty">AI 判读未启用 —— 五条边界照常工作，判读只是可选的解释层，关掉不影响检测。</div>';
    } else {
      judgeBody = '<div class="judge-list">' + list.slice(0, 8).map(x => {
        const v = JUDGE_VERDICT[x.verdict] || JUDGE_VERDICT.uncertain;
        const wall = fidWall[x.fid] || '历史判读';
        const conf = Math.round(Number(x.confidence || 0) * 100);
        return `
        <div class="judge-item">
          <div class="judge-head">
            <span class="judge-wall" title="${fidWall[x.fid] ? '归属当前告警窗口' : '该告警已不在当前统计窗口内'}">${esc(wall)}</span>
            <span class="wall-st ${v.cls}" title="${esc(v.hint)}">${esc(v.cn)}</span>
            <span class="judge-conf">置信 ${conf}%</span>
            <span class="judge-meta">${esc(x.model || '')}${x.latency_ms ? ' · ' + Math.round(x.latency_ms) + 'ms' : ''}</span>
          </div>
          <div class="judge-reason">${esc(String(x.reason || '').slice(0, 220))}</div>
          <div class="judge-foot">仅判读，未执行任何动作${x.executed ? '（异常：executed=true）' : ''}</div>
        </div>`;
      }).join('') + '</div>';
    }
  } catch (e) {
    judgeBody = `<div class="empty">判读不可用：${esc(e.message || e)}</div>`;
  }

  const items = rows.map(b => {
    const st = WALL_ST[b.state] || WALL_ST.quiet;
    return `
    <div class="wall-item" data-bk="${esc(b.key || '')}">
      <div class="wall-head">
        <span class="wall-cn">${esc(b.cn)}</span>
        <span class="wall-st ${st.cls}" title="${esc(st.hint)}">${esc(st.cn)}</span>
        <span class="wall-foot">
          <span>试探 ${Number(b.waves || 0)}</span>
          <span>穿透 ${Number(b.breaches || 0)}</span>
          <span>守备 ${(b.rules || []).length}</span>
        </span>
        <span class="wall-score">${Number(b.score || 0)}</span>
      </div>
      <div class="wall-desc">${esc(b.desc || '')}</div>
      <div class="wall-meter ${st.cls}"><i style="width:${Math.max(2, Number(b.score || 0))}%"></i></div>
    </div>`;
  }).join('');

  return `
  ${panel('力场强度', `
    <div class="wall-hero">
      ${wallField(d)}
      <div class="wall-big ${gradeCls}">${strength}<em>${esc(d.grade_cn || '')}</em></div>
      <div class="wall-hero-meta">
        <div>最弱环节 · <b>${esc(d.weakest_cn || '—')}</b></div>
        <div>已观测边界 ${Number(d.observed || 0)}/5 · 已穿透 ${Number(d.breached || 0)} 条</div>
      </div>
    </div>
    <div class="wall-track ${gradeCls}"><i style="width:${strength}%"></i></div>`, {
    tag: '边界完整性',
  })}
  ${panel('五条边界', `<div class="wall-list">${items || '<div class="empty">暂无边界数据</div>'}</div>`, {
    actions: '<span class="panel-tag mint">按边界归位</span>',
    tag: '进程 · 文件 · 网络 · 凭据 · 信号',
  })}
  ${cfgWarn}
  ${panel('力场判读', judgeBody, {
    tag: 'AI 只定性，不动作',
    actions: '<span class="panel-tag mint">判读结果不改变边界状态</span>',
  })}
  ${panel('怎么读这张图', `
    <div class="kv">
      <div class="kv-row"><span class="k">心之壁</span><span class="v">每条边界还在不在。终端上的异常，本质都是某条边界被试探、或被穿透。</span></div>
      <div class="kv-row"><span class="k">守住 / 静默</span><span class="v">守住＝有规则覆盖且这阵子没异常；静默＝没观测到异常，但也没有证据说它守得住。两者不能混为一谈。</span></div>
      <div class="kv-row"><span class="k">穿透</span><span class="v">真实发生的越界：严重级命中，或高危且诱饵被实际踩中。</span></div>
      <div class="kv-row"><span class="k">力场强度</span><span class="v">五条边界得分的均值。<b>不是</b>概率，也不是健康分——它是「有几堵墙还立着」的摘要。</span></div>
      <div class="kv-row"><span class="k">不新增检测</span><span class="v">心之壁不装新引擎。它把已有的基线、完整性、NDR、UEBA、诱饵按「守的是哪条边界」重新归位，让漏在哪一眼看得到。</span></div>
    </div>`, { tag: '读法' })}`;
}

const VIEWS = {
  overview: () => viewOverview(),
  wall: viewWall,
  findings: viewFindings,
  timeline: viewTimeline,
  telemetry: viewTelemetry,
  ueba: viewUEBA,
  ndr: viewNDR,
  canary: viewCanary,
  intel: viewIntel,
  playbooks: viewPlaybooks,
  tickets: viewTickets,
  inventory: viewInventory,
  compliance: viewCompliance,
  baseline: viewBaseline,
  response: viewResponse,
  governance: viewGovernance,
  collectors: () => viewCollectors(),
};

async function render(view) {
  if (view) S.view = view;
  const fn = VIEWS[S.view];
  if (!fn) return;
  $$('.nav-item').forEach(b => b.classList.toggle('active', b.dataset.view === S.view));
  try {
    const html = await fn();
    const root = $('#root');
    root.innerHTML = html;
    bindTabs();
    if (S.view === 'findings') bindFindings();
  } catch (e) {
    $('#root').innerHTML = panel('加载失败', `<pre class="out">${esc(e.message || e)}</pre>`, { tagCls: 'red', tag: '错误' });
  }
}

/* ---------------- 事件绑定 ---------------- */
function bindChrome() {
  window.addEventListener('hashchange', () => {
    const v = (location.hash || '#overview').slice(1);
    if (v && VIEWS[v] && v !== S.view) render(v);
  });
  $('#nav').addEventListener('click', e => {
    const b = e.target.closest('.nav-item');
    if (!b) return;
    location.hash = b.dataset.view;
    render(b.dataset.view);
  });

  $('#btn-refresh').addEventListener('click', () => render());
  $('#btn-selftest').addEventListener('click', () => doSelftest());
  document.addEventListener('click', async e => {
    const goto = e.target.closest('[data-goto]');
    if (goto) { location.hash = goto.dataset.goto; render(goto.dataset.goto); return; }
    const b = e.target.closest('[data-act]');
    if (!b) return;
    const act = b.dataset.act;
    try {
      if (act === 'ueba-reset') { await API('/api/ueba/reset', { method: 'POST', body: {} }); toast('行为基线已重置，重新进入学习期'); render(); }
      else if (act === 'canary-deploy') { const r = await API('/api/canary/deploy', { method: 'POST', body: {} }); toast(r.detail || '已部署'); render(); }
      else if (act === 'canary-undeploy') { const r = await API('/api/canary/undeploy', { method: 'POST', body: {} }); toast(r.detail || '已移除'); render(); }
      else if (act === 'pb-reload') { const r = await API('/api/playbooks/reload', { method: 'POST', body: {} }); toast(`已加载 ${r.count} 个剧本`); render(); }
      else if (act === 'pb-confirm') { const r = await API('/api/playbook/confirm', { method: 'POST', body: { run_id: b.dataset.run } }); toast(r.ok ? '已执行处置动作' : (r.detail || '执行失败'), r.ok ? 'ok' : 'err'); render(); }
      else if (act === 'pb-reject') { const r = await API('/api/playbook/reject', { method: 'POST', body: { run_id: b.dataset.run } }); toast(r.detail || '已驳回'); render(); }
      else if (act === 'inv-scan') { await API('/api/inventory/scan', { method: 'POST', body: {} }); toast('后台扫描已启动'); setTimeout(() => render(), 2500); }
      else if (act === 'comp-rebuild') { await API('/api/compliance/rebuild', { method: 'POST', body: {} }); toast('合规矩阵已重建'); render(); }
      else if (act === 'intel-add') {
        const kind = $('#intel-kind').value, value = $('#intel-value').value.trim(), note = $('#intel-note').value.trim();
        if (!value) return toast('请填写情报值', 'err');
        const r = await API('/api/intel/add', { method: 'POST', body: { kind, value, note } });
        toast(r.detail || '已加入', r.ok ? 'ok' : 'err'); render();
      } else if (act === 'intel-import') {
        const text = $('#intel-import').value;
        if (!text.trim()) return toast('请粘贴情报内容', 'err');
        const r = await API('/api/intel/import', { method: 'POST', body: { text } });
        toast(`解析 ${r.rows} 行，导入 ${r.added} 条`); render();
      } else if (act === 'intel-del') {
        await API('/api/intel/remove', { method: 'POST', body: { kind: b.dataset.kind, value: b.dataset.value } });
        toast('已移除'); render();
      } else if (act === 'tk-new') {
        const title = $('#tk-title').value.trim();
        if (!title) return toast('请填写标题', 'err');
        await API('/api/ticket/new', { method: 'POST', body: { title, severity: $('#tk-sev').value, ref: $('#tk-ref').value } });
        toast('工单已创建'); render();
      } else if (act === 'tk-ack' || act === 'tk-close') {
        await API('/api/ticket/update', { method: 'POST', body: { tid: b.dataset.tid, status: act === 'tk-ack' ? 'ack' : 'closed' } });
        toast('状态已更新'); render();
      } else if (act === 'tk-note') {
        const note = window.prompt('备注内容');
        if (!note) return;
        await API('/api/ticket/update', { method: 'POST', body: { tid: b.dataset.tid, note } });
        toast('备注已记录'); render();
      } else if (act === 'rp-terminate' || act === 'rp-suspend' || act === 'rp-resume') {
        const pid = Number($('#rp-pid').value);
        if (!pid) return toast('请填写 PID', 'err');
        const map = { 'rp-terminate': 'terminate', 'rp-suspend': 'suspend', 'rp-resume': 'resume' };
        const r = await API('/api/respond', { method: 'POST', body: { action: map[act], pid } });
        out(JSON.stringify(r, null, 2)); toast(r.detail || (r.ok ? '已执行' : '未执行'), r.ok ? 'ok' : 'err');
      } else if (act === 'rp-block') {
        const ip = $('#rp-ip').value.trim();
        if (!ip) return toast('请填写对端 IP', 'err');
        const r = await API('/api/respond', { method: 'POST', body: { action: 'block', ip } });
        out(JSON.stringify(r, null, 2));
      } else if (act === 'fw-block' || act === 'fw-unblock') {
        const ip = (b.dataset.ip || ($('#fw-ip') && $('#fw-ip').value) || '').trim();
        if (!ip) return toast('请填写 IP 或 CIDR', 'err');
        const why = act === 'fw-block' ? (($('#fw-why') && $('#fw-why').value) || '').trim() : '';
        const r = await API('/api/firewall/' + (act === 'fw-block' ? 'block' : 'unblock'),
                            { method: 'POST', body: act === 'fw-block' ? { ip, reason: why } : { ip } });
        toast(r.ok ? (act === 'fw-block' ? '已下规则' : '已解封') : (r.detail || '失败'),
              r.ok ? 'ok' : 'err');
        render();
      } else if (act === 'rp-export') {
        const r = await API('/api/respond', { method: 'POST', body: { action: 'export' } });
        out(JSON.stringify(r, null, 2)); toast('证据包已导出');
      } else if (act === 'rp-selftest') { doSelftest(); }
      else if (act === 'sup-add') {
        const rule_id = $('#sup-rule').value.trim();
        const contains = $('#sup-contains').value.trim();
        const note = $('#sup-note').value.trim();
        if (!rule_id && !contains) return toast('至少填规则 ID 或关键字', 'err');
        const r = await API('/api/suppress/add', { method: 'POST', body: { rule_id, contains, note } });
        toast(r.ok ? `已添加抑制（共 ${r.count} 条）` : (r.detail || '失败'), r.ok ? 'ok' : 'err');
        render();
      } else if (act === 'sup-del') {
        await API('/api/suppress/remove', { method: 'POST', body: { index: Number(b.dataset.index) } });
        toast('已撤销抑制'); render();
      }
      else if (act === 'refresh') { render(); }
    } catch (err) {
      toast(err.message || String(err), 'err');
    }
  });
}
function out(txt) {
  const el = $('#rp-out');
  if (el) el.textContent = txt;
  else toast(txt.slice(0, 160));
}
async function doSelftest() {
  try {
    toast('正在跑自检…');
    const r = await API('/api/selftest', { method: 'POST', body: {} });
    S.cache.selftest = r;
    const n = (r.findings || []).length, m = (r.incidents || []).length;
    toast(`自检完成：命中 ${n} 条告警、${m} 条攻击链`, 'ok');
    if (S.view === 'response' || S.view === 'overview') render();
  } catch (e) {
    toast(e.message || String(e), 'err');
  }
}

/* ---------------- SSE ---------------- */
let sseTimer = null;
let sse = null;
function connectSSE() {
  if (sse) { try { sse.close(); } catch (e) {} sse = null; }
  const es = new EventSource('/api/stream');
  sse = es;
  es.onopen = () => {
    $('#sse-dot').className = 'cd live';
    $('#sse-txt').textContent = '实时通道已连接';
  };
  es.onerror = () => {
    $('#sse-dot').className = 'cd dead';
    $('#sse-txt').textContent = '实时通道断开，重连中…';
  };
  es.onmessage = ev => {
    let o;
    try { o = JSON.parse(ev.data); } catch { return; }
    S.o = o;
    renderChrome(o);
    if (S.view === 'overview' || S.view === 'collectors') {
      if (sseTimer) return;
      sseTimer = setTimeout(() => { sseTimer = null; render(); }, 1800);
    }
  };
}

/* ---------------- 主题与版本 ---------------- */
const THEMES = ['dark', 'dusk', 'light'];
function applyTheme(name) {
  const t = THEMES.indexOf(name) >= 0 ? name : 'light';
  document.documentElement.setAttribute('data-theme', t);
  try { localStorage.setItem('atfield.theme', t); } catch (e) { /* 隐私模式忽略 */ }
  $$('#theme-sw .tsw').forEach(b => b.classList.toggle('on', b.dataset.theme === t));
}
function initTheme() {
  let saved = null;
  try { saved = localStorage.getItem('atfield.theme'); } catch (e) {}
  applyTheme(saved || 'light');
  const sw = $('#theme-sw');
  if (sw) sw.addEventListener('click', e => {
    const b = e.target.closest('.tsw');
    if (b && b.dataset.theme) applyTheme(b.dataset.theme);
  });
}
async function loadVersion() {
  try {
    const v = await API('/api/version');
    const el = $('#ver');
    if (el && v && v.version) {
      el.textContent = 'v' + v.version;
      el.title = `${v.name || '心之壁'} v${v.version}${v.python ? ' · ' + v.python : ''}`;
      el.hidden = false;
    }
  } catch (e) { /* 版本号非关键路径 */ }
}

/* 徽记不是摆设：点它就跳到最需要看的那条边界 */
document.addEventListener('click', ev => {
  const f = ev.target.closest && ev.target.closest('.wall-field');
  if (!f) return;
  const key = f.getAttribute('data-goto');
  if (!key) return;
  const row = document.querySelector('.wall-item[data-bk="' + key + '"]');
  if (!row) return;
  row.scrollIntoView({ behavior: 'smooth', block: 'center' });
  row.classList.remove('wf-flash');
  void row.offsetWidth;                     // 重启动画
  row.classList.add('wf-flash');
  setTimeout(() => row.classList.remove('wf-flash'), 2600);
});
document.addEventListener('keydown', ev => {
  if (ev.key !== 'Enter' && ev.key !== ' ') return;
  const f = ev.target.closest && ev.target.closest('.wall-field');
  if (!f) return;
  ev.preventDefault();
  f.click();
});

/* 账号菜单：点按钮开合，点外面或 Esc 关闭（一次绑定，重渲染不失效） */
document.addEventListener('click', ev => {
  const btn = ev.target.closest && ev.target.closest('#who-btn');
  const menu = document.getElementById('who-menu');
  if (!menu) return;
  if (btn) {
    const open = menu.hidden;
    menu.hidden = !open;
    btn.setAttribute('aria-expanded', String(open));
    return;
  }
  if (!ev.target.closest || !ev.target.closest('.who-menu')) {
    menu.hidden = true;
    const b = document.getElementById('who-btn');
    if (b) b.setAttribute('aria-expanded', 'false');
  }
});
document.addEventListener('keydown', ev => {
  if (ev.key !== 'Escape') return;
  const menu = document.getElementById('who-menu');
  const b = document.getElementById('who-btn');
  if (menu && !menu.hidden) { menu.hidden = true; if (b) { b.setAttribute('aria-expanded', 'false'); b.focus(); } }
});

/* ---------------- 启动 ---------------- */
async function boot(relogin) {
  initTheme();
  if (!boot._bound) {
    bindChrome();
    bindGovernance();
    boot._bound = true;
  }
  const authed = await loadMe();
  if (!authed) {
    showLogin();
    return;
  }
  hideLogin();
  loadVersion();
  const start = (location.hash || '#overview').slice(1);
  render(VIEWS[start] ? start : 'overview');
  if (!sse) connectSSE();          // 登录后也要接上实时通道
  if (!boot._timer) {
    boot._timer = setInterval(() => {
      const ae = document.activeElement;
      const typing = ae && (ae.tagName === 'INPUT' || ae.tagName === 'TEXTAREA');
      if (!typing && S.view !== 'overview' && S.view !== 'collectors' && S.view !== 'governance') render();
      else if (S.view === 'governance' && !typing) render();
    }, 12000);
  }
}
document.addEventListener('DOMContentLoaded', () => boot());
