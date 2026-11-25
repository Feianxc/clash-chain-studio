// Chain Studio · 图形化所见即所得前端控制器

const ui = {
  tab: 'canvas',            // canvas | android | nodes | rules
  deviceView: 'windows',    // windows | android-daily | android-dedicated
  simScenario: 'claude',    // claude | chatgpt | google | game | domestic | mobile-browser | udp-guard
  phonePreviewMode: 'daily', // daily | dedicated
  drawer: null,             // null | 'hop' | 'exit' | 'import-sub' | 'add-exit' | 'edit-exit' | 'benchmark'
  editingExitId: null,
  nodeSearch: '',
  expertSubtab: 'win-diff',
  dirty: false,
  bootstrap: null,
  preview: null,
  adbDevices: null,
  adbPackages: null,
  adbInspect: null,
  hygieneAudit: null,
  hygieneCaches: null,
  hygieneBusy: false
};

const SCENARIOS = [
  { id: 'claude', icon: '🤖', label: 'Claude / Anthropic' },
  { id: 'chatgpt', icon: '✨', label: 'ChatGPT / OpenAI' },
  { id: 'google', icon: '🔍', label: 'Google / 登录' },
  { id: 'game', icon: '🎮', label: '原神 / 鸣潮更新' },
  { id: 'domestic', icon: '🇨🇳', label: '百度 / 国内网站' },
  { id: 'mobile-browser', icon: '🌐', label: '手机 Chrome / X 浏览器' },
  { id: 'udp-guard', icon: '🛡️', label: '受保护 App 的 UDP' }
];

function esc(v) {
  return String(v ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function fmtTime(iso) {
  if (!iso) return '未测';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return String(iso);
  return d.toLocaleString('zh-CN', { hour12: false, month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' });
}

function toast(msg, kind = 'info') {
  const el = document.createElement('div');
  el.className = `toast ${kind}`;
  el.textContent = msg;
  document.getElementById('toastStack').appendChild(el);
  setTimeout(() => el.remove(), 3400);
}

async function api(url, opts = {}) {
  const res = await fetch(url, {
    headers: { 'Content-Type': 'application/json', ...(opts.headers || {}) },
    ...opts
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    if (res.status === 404 && url.startsWith('/api/hygiene')) {
      throw new Error('后台服务仍是旧版本，请重新双击 Start-ChainStudio.cmd（现已支持自动重启更新）后再体检');
    }
    throw new Error(data.error || `请求失败 (${res.status})`);
  }
  return data;
}

function activeCtx() {
  const state = ui.bootstrap?.state;
  if (!state) return {};
  const sub = state.subscriptions.find(s => s.id === state.activeBinding.subscriptionId) || state.subscriptions[0];
  const exit = state.staticExits.find(e => e.id === state.activeBinding.staticExitId) || state.staticExits[0];
  const preset = state.rulePresets.find(p => p.id === state.activeBinding.rulePresetId) || state.rulePresets[0];
  const primaryHop = state.activeBinding.primaryFirstHop || state.activeBinding.selectedFirstHops?.[0] || '未选择第一跳';
  return { state, sub, exit, preset, primaryHop };
}

async function refresh(withPreview = false) {
  ui.bootstrap = await api('/api/bootstrap');
  renderTopChrome();
  renderMainView();
  if (ui.drawer) renderDrawerContent();
  if (withPreview || ui.tab === 'rules' || ui.tab === 'android') {
    api('/api/preview').then(prev => {
      ui.preview = prev;
      if (ui.tab === 'rules' || ui.tab === 'android') renderMainView();
    }).catch(() => {});
  }
}

function renderTopChrome() {
  document.querySelectorAll('.seg-btn').forEach(b => {
    b.classList.toggle('active', b.dataset.tab === ui.tab);
  });

  const v = ui.bootstrap?.preview?.validation;
  const dot = document.getElementById('topStatusDot');
  const pendingDot = document.getElementById('pendingDot');
  const banner = document.getElementById('bannerSlot');

  pendingDot.classList.toggle('hidden', !ui.dirty);

  if (!v) {
    dot.className = 'status-dot dot-neutral';
    banner.classList.add('hidden');
  } else if (!v.valid) {
    dot.className = 'status-dot dot-danger';
    dot.title = `有 ${v.errors.length} 项配置冲突`;
    banner.classList.remove('hidden');
    banner.innerHTML = `<div class="banner-inner danger"><span><strong>配置冲突：</strong>${esc(v.errors[0])}</span><button class="btn btn-secondary btn-sm" id="btnBannerFix">去修复</button></div>`;
    document.getElementById('btnBannerFix')?.addEventListener('click', () => switchTab('nodes'));
  } else if (v.warnings?.length) {
    dot.className = 'status-dot dot-warn';
    dot.title = v.warnings[0];
    banner.classList.remove('hidden');
    banner.innerHTML = `<div class="banner-inner warn"><span>${esc(v.warnings[0])}</span><button class="btn btn-secondary btn-sm" id="btnBannerImport">从本机 Clash Verge 导入</button></div>`;
    document.getElementById('btnBannerImport')?.addEventListener('click', () => runImportClashVerge());
  } else {
    dot.className = 'status-dot dot-ok';
    dot.title = '校验通过';
    banner.classList.add('hidden');
  }
}

function renderMainView() {
  const root = document.getElementById('viewRoot');
  if (!ui.bootstrap) return;
  if (ui.tab === 'canvas') renderCanvasView(root);
  else if (ui.tab === 'android') renderAndroidView(root);
  else if (ui.tab === 'nodes') renderNodesView(root);
  else if (ui.tab === 'hygiene') renderHygieneView(root);
  else if (ui.tab === 'rules') renderRulesView(root);
}

// =========================================================
// 路由模拟器判定（实时反映当前设备视图 + 规则开关）
// =========================================================
function evaluateScenario(scenarioId, deviceView, ctx) {
  const { primaryHop, exit, preset } = ctx;
  const expectedIp = exit?.expectedIp || '-';
  const isWin = deviceView === 'windows';
  const isDed = deviceView === 'android-dedicated';

  switch (scenarioId) {
    case 'claude':
      return {
        lane: 'chain',
        text: `命中受保护规则 → 经「${primaryHop}」转至「${exit?.name}」→ 固定出口 ${expectedIp}`
      };
    case 'chatgpt':
      return {
        lane: 'chain',
        text: `命中 AI 保护规则 → 走静态住宅链，出口始终锁定 ${expectedIp}`
      };
    case 'google':
      return {
        lane: 'chain',
        text: `优先于国内直连命中 Google 规则（含 google.cn）→ 走静态链 ${expectedIp}`
      };
    case 'game': {
      const enabledCount = (preset.gameDirectRules || []).filter(r => r.enabled).length;
      return enabledCount > 0
        ? { lane: 'direct', text: `命中游戏直连通道（${enabledCount} 条规则生效）→ 本地高速直连，零静态流量消耗` }
        : { lane: 'chain', text: '游戏直连规则已关闭 → 将按默认分流处理' };
    }
    case 'domestic':
      return {
        lane: 'direct',
        text: '命中 GEOSITE,cn / GEOIP,CN → 国内网站直接连接，不经过任何代理'
      };
    case 'mobile-browser':
      if (isWin) {
        return { lane: 'direct', text: '电脑普通浏览器按域名分流：国内网站直连，海外网站走静态链（BitBrowser 专用口 17902 强制全走链）' };
      }
      if (isDed) {
        const count = (preset.androidBrowserApps || []).filter(a => a.enabled).length;
        return {
          lane: 'chain',
          text: `手机【专用版】生效：已接管 ${count} 个浏览器整应用走静态链 ${expectedIp}（含国内检测页同出口）`
        };
      }
      return {
        lane: 'direct',
        text: '手机【日常版】生效：普通浏览器不强制整应用走链，国内网页直连、海外网页走静态链'
      };
    case 'udp-guard':
      return {
        lane: 'block',
        text: isWin
          ? '静态末跳为 TCP 通道，剩余 UDP 统一 REJECT 拦截，杜绝绕过代理泄漏真实 IP'
          : '受保护手机 App 的 UDP 优先于国内直连被 REJECT 拦截，彻底避免回落直连'
      };
    default:
      return { lane: 'chain', text: `经「${primaryHop}」→ 静态出口 ${expectedIp}` };
  }
}

function wireSvg(kind, dimmed = false) {
  const cls = kind === 'direct' ? 'wire-direct' : (kind === 'block' ? 'wire-block' : 'wire-chain');
  const dimCls = dimmed ? 'wire-dim' : '';
  const strokeColor = kind === 'direct' ? 'var(--direct)' : (kind === 'block' ? 'var(--warn)' : 'var(--chain)');
  return `
    <svg viewBox="0 0 54 24" aria-hidden="true">
      <line x1="2" y1="12" x2="46" y2="12" class="wire-base ${dimCls}" />
      <line x1="2" y1="12" x2="46" y2="12" class="wire-flow ${cls} ${dimCls}" />
      <path d="M41 6.5 L49 12 L41 17.5" fill="none" stroke="${dimmed ? 'var(--border-strong)' : strokeColor}" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" style="opacity:${dimmed ? 0.35 : 1}" />
    </svg>
  `;
}

// =========================================================
// 视图 1：图形化链路总控画布（WYSIWYG 核心）
// =========================================================
function renderCanvasView(root) {
  const ctx = activeCtx();
  const { state, sub, exit, preset, primaryHop } = ctx;
  const winEnv = ui.bootstrap.windowsEnv;
  const isWin = ui.deviceView === 'windows';
  const isDaily = ui.deviceView === 'android-daily';
  const isDed = ui.deviceView === 'android-dedicated';

  const latestProbe = state.probeHistory.find(p => p.target === (isWin ? 'windows' : 'android')) || null;
  const observedIp = latestProbe?.ruleProbe?.observedIp || null;
  const latency = latestProbe?.ruleProbe?.meanSec ? `${latestProbe.ruleProbe.meanSec}s` : null;

  const sim = evaluateScenario(ui.simScenario, ui.deviceView, ctx);
  const chainActive = sim.lane === 'chain';
  const directActive = sim.lane === 'direct';
  const blockActive = sim.lane === 'block';

  const srcChainTitle = isWin
    ? 'AI / 海外 / BitBrowser'
    : (isDed ? 'Claude / GoLogin + 浏览器' : 'Claude / GoLogin / 海外');
  const srcChainSub = isWin
    ? `分流 :${preset.windowsOptions.mixedPort} · 专用 :${preset.windowsOptions.relayPort}`
    : (isDed ? `全保护 · GoLogin :${preset.androidOptions.dedicatedListenerPort}` : `日常分流 · GoLogin :${preset.androidOptions.dedicatedListenerPort}`);

  const srcDirectTitle = isWin ? '国内网站 & 游戏更新' : '国内 App & 网页';
  const srcDirectSub = isWin ? '米哈游 / 鸣潮 / 无限暖暖' : (isDaily ? '微信 / 百度 / 普通浏览器国内' : '非接管国内 App 直连');

  const protoLabel = isWin
    ? `${(exit?.windowsProtocol || 'http').toUpperCase()} + IPv4 Relay`
    : `${(exit?.androidProtocol || 'socks5').toUpperCase()} · UDP关`;

  const shortcutMeta = [
    { id: 'claude-env', emoji: '🇺🇸', label: 'Claude 美国环境', sub: '美中时区 · en-US' },
    { id: 'china-env', emoji: '🇨🇳', label: '中国日常环境', sub: '北京时间 · 退出检查' },
    { id: 'claude-desktop', emoji: '🖥️', label: 'Claude Desktop', sub: '校验静态 IP 后启动' },
    { id: 'claude-code', emoji: '⌨️', label: 'Claude Code', sub: '独立 CLI 静态通道' }
  ];

  root.innerHTML = `
    <section class="stage-card">
      <!-- 顶部设备切换栏 -->
      <div class="stage-toolbar">
        <div class="device-pills" role="tablist">
          <button class="device-pill ${isWin ? 'active' : ''}" data-dev="windows">🖥️ 电脑 Windows</button>
          <button class="device-pill ${isDaily ? 'active' : ''}" data-dev="android-daily">📱 手机日常 Daily</button>
          <button class="device-pill ${isDed ? 'active' : ''}" data-dev="android-dedicated">📱 手机专用 Dedicated</button>
        </div>
        <div class="row">
          ${isWin
            ? `<span class="tag tag-neutral">TUN ${preset.windowsOptions.tunEnable ? '开启' : '关闭'}</span>
               <button class="sim-chip ${winEnv.relayHealth.status === 'pass' ? 'active-direct' : ''}" id="btnToggleRelay" title="内置 IPv4 DoH Relay (17902 → 17901)">
                 ${winEnv.relayHealth.status === 'pass' ? '● Relay 运行中' : '▶ 启动 IPv4 Relay'}
               </button>`
            : `<span class="tag tag-chain">同源同步版本 ${esc(state.deviceBindings.android.dailyVersion || '待生成')}</span>`}
          <button class="btn btn-ghost btn-sm" id="btnCanvasImport">从本机导入</button>
        </div>
      </div>

      <!-- 图形化双车道拓扑画布 -->
      <div class="topology-stage">
        <div class="topo-diagram">
          <!-- 上车道：链式代理通道 -->
          <div class="t-node pos-src-chain ${chainActive ? 'lit-chain' : (blockActive ? 'lit-block' : 'dimmed')}">
            <div class="t-node-head">
              <div class="t-icon ${blockActive ? 'warn' : 'chain'}">${blockActive ? '🛡️' : '⚡'}</div>
              <span class="tag ${blockActive ? 'tag-warn' : 'tag-chain'}">${blockActive ? '拦截 UDP' : '走静态链'}</span>
            </div>
            <div>
              <div class="t-kicker">流量入口</div>
              <div class="t-title" title="${esc(srcChainTitle)}">${esc(srcChainTitle)}</div>
              <div class="t-sub mono">${esc(srcChainSub)}</div>
            </div>
          </div>

          <div class="lane-link pos-link-1">${wireSvg(blockActive ? 'block' : 'chain', !chainActive && !blockActive)}</div>

          <!-- 可直接点击替换：第一跳 -->
          <div class="t-node interactive pos-hop ${chainActive ? 'lit-chain' : 'dimmed'}" id="nodeClickHop" title="点击直接更换第一跳或订阅">
            <div class="t-node-head">
              <div class="t-icon chain">✈️</div>
              <span class="t-action-hint">点击换跳 ▾</span>
            </div>
            <div>
              <div class="t-kicker">第一跳 · ${esc(sub?.name || '未选订阅')}</div>
              <div class="t-title" title="${esc(primaryHop)}">${esc(primaryHop)}</div>
              <div class="t-sub">备选组共 ${state.activeBinding.selectedFirstHops.length} 个叶子节点</div>
            </div>
          </div>

          <div class="lane-link pos-link-2">${wireSvg('chain', !chainActive)}</div>

          <!-- 可直接点击替换：静态出口 -->
          <div class="t-node interactive pos-exit ${chainActive ? 'lit-chain' : 'dimmed'}" id="nodeClickExit" title="点击直接更换静态出口 IP">
            <div class="t-node-head">
              <div class="t-icon chain">🛡️</div>
              <span class="t-action-hint">点击换 IP ▾</span>
            </div>
            <div>
              <div class="t-kicker">静态出口 · ${esc(exit?.region || 'US')}</div>
              <div class="t-title" title="${esc(exit?.name || '')}">${esc(exit?.name || '未配置静态出口')}</div>
              <div class="t-sub mono">${esc(protoLabel)} · ${exit?.hasCredentials ? '🔒已加密' : '待填凭据'}</div>
            </div>
          </div>

          <div class="lane-link pos-link-3">${wireSvg('chain', !chainActive)}</div>

          <!-- 最终实测公网 IP -->
          <div class="t-node interactive pos-pubip ${chainActive ? 'lit-chain' : 'dimmed'}" id="nodeClickProbe" title="点击立即实测当前出口 IP">
            <div class="t-node-head">
              <div class="t-icon ${latestProbe?.status === 'pass' ? 'direct' : (exit?.isSample ? 'warn' : 'neutral')}">🌐</div>
              <span class="tag ${latestProbe?.status === 'pass' ? 'tag-direct' : (exit?.isSample ? 'tag-warn' : (latestProbe?.status === 'fail' ? 'tag-danger' : 'tag-neutral'))}">
                ${latestProbe?.status === 'pass'
                  ? `已核验 ${latency || ''}`
                  : (exit?.isSample ? '待导入本机' : (latestProbe?.status === 'fail' ? 'IP 不符' : '点击探测'))}
              </span>
            </div>
            <div>
              <div class="t-kicker">最终公网出口</div>
              <div class="t-title mono">${esc(observedIp || exit?.expectedIp || '-')}</div>
              <div class="t-sub">${observedIp
                ? (exit?.isSample ? '当前还是示例预期IP，请点导入' : `实测于 ${fmtTime(latestProbe.checkedAt)}`)
                : `预期 IP · 点击实测`}</div>
            </div>
          </div>

          <!-- 下车道：本地高速直连通道 -->
          <div class="t-node pos-src-direct ${directActive ? 'lit-direct' : 'dimmed'}">
            <div class="t-node-head">
              <div class="t-icon direct">🏠</div>
              <span class="tag tag-direct">本地直连</span>
            </div>
            <div>
              <div class="t-kicker">免代理流量</div>
              <div class="t-title">${esc(srcDirectTitle)}</div>
              <div class="t-sub">${esc(srcDirectSub)}</div>
            </div>
          </div>

          <div class="lane-link pos-link-d1">${wireSvg('direct', !directActive)}</div>

          <div class="t-node interactive pos-direct-mid ${directActive ? 'lit-direct' : 'dimmed'}" id="nodeClickRules">
            <div class="t-node-head">
              <div class="row">
                <div class="t-icon direct">⚡</div>
                <div>
                  <div class="t-title">DIRECT 直连快车道</div>
                  <div class="t-sub">不经过机场第一跳，不消耗静态住宅流量，点击管理游戏与国内规则</div>
                </div>
              </div>
              <span class="tag tag-direct">${(preset.gameDirectRules || []).filter(r => r.enabled).length} 条游戏规则</span>
            </div>
          </div>

          <div class="lane-link pos-link-d2">${wireSvg('direct', !directActive)}</div>

          <div class="t-node pos-direct-end ${directActive ? 'lit-direct' : 'dimmed'}">
            <div class="t-node-head">
              <div class="t-icon direct">🇨🇳</div>
              <span class="tag tag-direct">宽带直出</span>
            </div>
            <div>
              <div class="t-kicker">最终连接</div>
              <div class="t-title">国内本地网络</div>
              <div class="t-sub">满速下载与低延迟</div>
            </div>
          </div>
        </div>
      </div>

      <!-- 交互式路由模拟器（所见即所得） -->
      <div class="sim-bar">
        <div class="sim-row">
          <span class="sim-label">点一下试试看怎么走：</span>
          ${SCENARIOS.map(sc => {
            const active = ui.simScenario === sc.id;
            const activeCls = active ? `active-${sim.lane}` : '';
            return `<button class="sim-chip ${activeCls}" data-sim="${sc.id}">${sc.icon} ${esc(sc.label)}</button>`;
          }).join('')}
        </div>
        <div class="sim-verdict ${sim.lane}">
          <span><strong>${sim.lane === 'direct' ? '🟢 直连路径：' : (sim.lane === 'block' ? '🛡️ 安全阻断：' : '🔵 静态链路径：')}</strong>${esc(sim.text)}</span>
          ${!isWin ? `<button class="btn btn-secondary btn-sm" id="btnSimJumpAndroid">去配置手机端 →</button>` : ''}
        </div>
      </div>
    </section>

    <!-- 底部 4 个原有快捷入口 -->
    <section>
      <div class="row" style="margin-bottom:10px;padding:0 4px;">
        <strong style="font-size:13.5px;">电脑快捷入口</strong>
        <span class="sub-text">${winEnv.environmentMode ? `当前系统模式：${esc(winEnv.environmentMode.mode)} (${esc(winEnv.environmentMode.timeZone)})` : '保留原有 4 个脚本的互斥锁与出口守卫'}</span>
      </div>
      <div class="dock-grid">
        ${shortcutMeta.map(sc => {
          const found = winEnv.shortcuts?.find(x => x.id === sc.id)?.exists;
          return `
            <button class="dock-tile" data-launch="${sc.id}" title="${found ? '点击启动' : '路径未就绪，可在规则与备份页设置路径'}">
              <span class="dock-emoji">${sc.emoji}</span>
              <div style="min-width:0;">
                <div class="dock-title">${esc(sc.label)}</div>
                <div class="dock-sub">${found ? esc(sc.sub) : '待配置本机路径'}</div>
              </div>
            </button>
          `;
        }).join('')}
      </div>
    </section>
  `;

  root.querySelectorAll('.device-pill').forEach(btn => {
    btn.addEventListener('click', () => {
      ui.deviceView = btn.dataset.dev;
      renderCanvasView(root);
    });
  });

  root.querySelectorAll('.sim-chip').forEach(btn => {
    btn.addEventListener('click', () => {
      ui.simScenario = btn.dataset.sim;
      renderCanvasView(root);
    });
  });

  document.getElementById('nodeClickHop')?.addEventListener('click', () => openDrawer('hop'));
  document.getElementById('nodeClickExit')?.addEventListener('click', () => openDrawer('exit'));
  document.getElementById('nodeClickProbe')?.addEventListener('click', () => {
    if (isWin) runWindowsProbe();
    else switchTab('android');
  });
  document.getElementById('nodeClickRules')?.addEventListener('click', () => switchTab('rules'));
  document.getElementById('btnCanvasImport')?.addEventListener('click', () => runImportClashVerge());
  document.getElementById('btnToggleRelay')?.addEventListener('click', async () => {
    try {
      const running = winEnv.relayHealth.status === 'pass';
      if (running) {
        const res = await api('/api/relay/stop', { method: 'POST' });
        toast(res.stopped ? '已停止内置 IPv4 Relay' : 'Relay 由外部守护进程运行中，请通过系统计划任务管理', 'info');
      } else {
        toast('正在启动内置 IPv4 Relay...');
        const res = await api('/api/relay/start', { method: 'POST' });
        toast(`IPv4 Relay 已就绪 (127.0.0.1:${res.listenPort})`, 'ok');
      }
      await refresh();
    } catch (err) { toast(err.message, 'error'); }
  });
  document.getElementById('btnSimJumpAndroid')?.addEventListener('click', () => switchTab('android'));

  root.querySelectorAll('[data-launch]').forEach(btn => {
    btn.addEventListener('click', async () => {
      try {
        const res = await api('/api/launcher/run', { method: 'POST', body: JSON.stringify({ action: btn.dataset.launch }) });
        toast(`已启动入口 (PID ${res.pid})`, 'ok');
      } catch (err) {
        toast(err.message, 'error');
      }
    });
  });
}

// =========================================================
// 视图 2：手机 Clash Meta 所见即所得配置台
// =========================================================
function renderAndroidView(root) {
  const { state, exit, preset, primaryHop } = activeCtx();
  const andOpts = preset.androidOptions;
  const isDed = ui.phonePreviewMode === 'dedicated';
  const latestVer = state.versions[0] || null;
  const devices = ui.adbDevices?.devices || [];
  const authDev = devices.find(d => d.authorized);
  const pkgs = ui.adbPackages?.packages || null;

  const appIcon = (pkg) => {
    if (pkg.includes('claude')) return '🤖';
    if (pkg.includes('gologin')) return '🦊';
    if (pkg.includes('xbrowser')) return '⚡';
    if (pkg.includes('chrome')) return '🌐';
    if (pkg.includes('emmx')) return '🧭';
    return '📱';
  };

  root.innerHTML = `
    <div class="phone-layout">
      <!-- 左侧：所见即所得手机模拟视图 -->
      <aside class="phone-frame">
        <div class="phone-notch" aria-hidden="true"></div>

        <div class="phone-mode-switch">
          <button class="phone-mode-btn ${!isDed ? 'active' : ''}" data-pmode="daily">日常版 Daily</button>
          <button class="phone-mode-btn ${isDed ? 'active' : ''}" data-pmode="dedicated">专用版 Dedicated</button>
        </div>

        <div class="phone-route-pill">
          <div style="font-weight:650;">当前静态链路线</div>
          <div class="mono" style="font-size:11.5px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${esc(primaryHop)} → ${esc(exit?.expectedIp || '-')}</div>
          <div style="font-size:11px;opacity:.85;">SOCKS5 · GoLogin 专用口 :${andOpts.dedicatedListenerPort}</div>
        </div>

        <div>
          <div class="row" style="justify-content:space-between;margin-bottom:8px;">
            <span style="font-size:12px;font-weight:650;color:var(--ink-2);">点击 App 卡片实时开关规则</span>
            <span class="tag ${isDed ? 'tag-chain' : 'tag-direct'}">${isDed ? '浏览器全静链' : '浏览器按规则分流'}</span>
          </div>

          <div class="phone-app-grid">
            ${preset.androidCoreApps.map((app, i) => `
              <button class="phone-app-tile ${app.enabled ? 'route-chain' : ''}" data-toggle-core="${i}" title="${esc(app.packageName)}">
                <div class="app-tile-top">
                  <span class="app-badge">${appIcon(app.packageName)}</span>
                  ${pkgs ? `<span class="tag ${pkgs[app.packageName] ? 'tag-direct' : 'tag-neutral'}">${pkgs[app.packageName] ? '已装' : '未装'}</span>` : ''}
                </div>
                <div class="app-name">${esc(app.label)}</div>
                <div class="app-state" style="color:${app.enabled ? 'var(--chain)' : 'var(--ink-3)'}">
                  ${app.enabled ? '🔵 静态链 · 禁UDP' : '已关闭保护'}
                </div>
              </button>
            `).join('')}

            ${preset.androidBrowserApps.map((app, i) => {
              const forcedChain = isDed && app.enabled;
              return `
                <button class="phone-app-tile ${forcedChain ? 'route-chain' : 'route-direct'}" data-toggle-browser="${i}" title="${esc(app.packageName)}">
                  <div class="app-tile-top">
                    <span class="app-badge">${appIcon(app.packageName)}</span>
                    ${pkgs ? `<span class="tag ${pkgs[app.packageName] ? 'tag-direct' : 'tag-neutral'}">${pkgs[app.packageName] ? '已装' : '未装'}</span>` : ''}
                  </div>
                  <div class="app-name">${esc(app.label)}</div>
                  <div class="app-state" style="color:${forcedChain ? 'var(--chain)' : 'var(--direct)'}">
                    ${isDed
                      ? (app.enabled ? '🔵 专用静链 · 禁UDP' : '🟢 已排除(走分流)')
                      : '🟢 国内直连 / 海外走链'}
                  </div>
                </button>
              `;
            }).join('')}
          </div>
        </div>

        <!-- 移动数据 DNS 一键切换 -->
        <div class="toggle-row" style="margin-top:2px;">
          <div>
            <div style="font-size:12.5px;font-weight:650;">移动数据稳态 DNS</div>
            <div style="font-size:11px;color:var(--ink-2);">Clash 7874 + 节点域名策略</div>
          </div>
          <label class="switch">
            <input type="checkbox" id="chkPhoneDns7874" ${andOpts.mobileDnsMode === 'local-clash-7874' ? 'checked' : ''} />
            <span class="slider"></span>
          </label>
        </div>
      </aside>

      <!-- 右侧：极简三步同步向导 -->
      <div class="step-stack">
        <section class="card">
          <div class="card-head">
            <div>
              <h2 class="card-title"><span class="step-badge">1</span>同步生成手机双配置 YAML</h2>
              <p class="sub-text">两份文件始终基于同一订阅与静态出口生成，版本严格对齐</p>
            </div>
            <button class="btn btn-primary btn-sm" id="btnAndroidGenNow">立即生成双配置</button>
          </div>
          <div class="split-2">
            <div class="visual-card">
              <div class="visual-card-row">
                <strong>Daily-Static-Chain.yaml</strong>
                <span class="tag tag-direct">日常推荐</span>
              </div>
              <div class="sub-text">${ui.preview?.android?.daily?.ruleCount ?? '-'} 条规则 · 普通浏览器国内直连</div>
              <div class="row" style="margin-top:4px;">
                <a class="btn btn-secondary btn-sm" href="/api/download/${latestVer ? esc(latestVer.versionId) : 'latest'}/Daily-Static-Chain.yaml" ${latestVer ? '' : 'onclick="return false;" style="opacity:.45"'}>下载日常版</a>
                <button class="btn btn-ghost btn-sm btn-mark-active" data-prof="Daily-Static-Chain">标为已激活</button>
              </div>
            </div>
            <div class="visual-card">
              <div class="visual-card-row">
                <strong>Claude-GoLogin-Static.yaml</strong>
                <span class="tag tag-chain">浏览器专用</span>
              </div>
              <div class="sub-text">${ui.preview?.android?.dedicated?.ruleCount ?? '-'} 条规则 · 接管 ${preset.androidBrowserApps.filter(a => a.enabled).length} 个浏览器</div>
              <div class="row" style="margin-top:4px;">
                <a class="btn btn-secondary btn-sm" href="/api/download/${latestVer ? esc(latestVer.versionId) : 'latest'}/Claude-GoLogin-Static.yaml" ${latestVer ? '' : 'onclick="return false;" style="opacity:.45"'}>下载专用版</a>
                <button class="btn btn-ghost btn-sm btn-mark-active" data-prof="Claude-GoLogin-Static">标为已激活</button>
              </div>
            </div>
          </div>
        </section>

        <section class="card">
          <div class="card-head">
            <div>
              <h2 class="card-title"><span class="step-badge">2</span>一键推送到手机（ADB）</h2>
              <p class="sub-text">${authDev ? `已连接：${esc(authDev.model)} (${esc(authDev.serial)})` : '插上 USB 调试后点击扫描，或直接用上方按钮下载文件导入 Clash Meta'}</p>
            </div>
            <button class="btn btn-secondary btn-sm" id="btnAdbScan">扫描手机</button>
          </div>
          <div class="row">
            <button class="btn btn-secondary btn-sm" id="btnAdbPkg">核对手机已装 App</button>
            <button class="btn btn-chain btn-sm" id="btnAdbPush">推送双份 YAML 到手机 Download</button>
          </div>
        </section>

        <section class="card">
          <div class="card-head">
            <div>
              <h2 class="card-title"><span class="step-badge">3</span>只读探测双入口出口 IP</h2>
              <p class="sub-text">在手机激活配置后点此验收 7890（规则口）与 17990（GoLogin 口），结束后自动清除映射</p>
            </div>
            <button class="btn btn-secondary btn-sm" id="btnAdbInspect">开始只读探测</button>
          </div>
          <div class="field" style="max-width:340px;">
            <label>临时 Controller Secret（选填，用于读取 Core 当前第一跳）</label>
            <input type="password" id="inputAdbSecret" placeholder="无密码可留空" />
          </div>
          ${ui.adbInspect ? `
            <div class="sim-verdict ${ui.adbInspect.status === 'pass' ? 'direct' : 'block'}" style="margin-top:12px;">
              <div>
                <strong>探测结果：${esc(ui.adbInspect.status)}</strong>
                ${ui.adbInspect.error ? ` · ${esc(ui.adbInspect.error)}` : ''}
                ${ui.adbInspect.ruleProbe ? `<div class="mono" style="font-size:12px;">7890 规则口：${esc(ui.adbInspect.ruleProbe.observedIp || ui.adbInspect.ruleProbe.stage)} | 17990 GoLogin：${esc(ui.adbInspect.dedicatedProbe?.observedIp || ui.adbInspect.dedicatedProbe?.stage)}</div>` : ''}
              </div>
            </div>
          ` : ''}
        </section>
      </div>
    </div>
  `;

  root.querySelectorAll('[data-pmode]').forEach(btn => {
    btn.addEventListener('click', () => {
      ui.phonePreviewMode = btn.dataset.pmode;
      renderAndroidView(root);
    });
  });

  root.querySelectorAll('[data-toggle-core]').forEach(btn => {
    btn.addEventListener('click', async () => {
      const idx = Number(btn.dataset.toggleCore);
      const list = structuredClone(preset.androidCoreApps);
      list[idx].enabled = !list[idx].enabled;
      await patchRules({ androidCoreApps: list }, `${list[idx].label} ${list[idx].enabled ? '已开启静态保护' : '已暂停保护'}`);
    });
  });

  root.querySelectorAll('[data-toggle-browser]').forEach(btn => {
    btn.addEventListener('click', async () => {
      if (!isDed) {
        toast('日常版默认不接管普通浏览器；切到「专用版」即可点击开关', 'info');
        return;
      }
      const idx = Number(btn.dataset.toggleBrowser);
      const list = structuredClone(preset.androidBrowserApps);
      list[idx].enabled = !list[idx].enabled;
      await patchRules({ androidBrowserApps: list }, `专用版已${list[idx].enabled ? '接管' : '排除'} ${list[idx].label}`);
    });
  });

  document.getElementById('chkPhoneDns7874')?.addEventListener('change', async (e) => {
    const mode = e.target.checked ? 'local-clash-7874' : 'direct-cn';
    await patchRules({ androidOptions: { mobileDnsMode: mode } }, e.target.checked ? '已启用 7874 移动数据稳态 DNS' : '已切换为直连国内 DNS');
  });

  document.getElementById('btnAndroidGenNow')?.addEventListener('click', () => openApplyModal());

  root.querySelectorAll('.btn-mark-active').forEach(btn => {
    btn.addEventListener('click', async () => {
      const prof = btn.dataset.prof;
      const body = prof === 'Daily-Static-Chain'
        ? { activeProfile: prof, dailyStatus: 'activated' }
        : { activeProfile: prof, dedicatedStatus: 'activated' };
      await api('/api/android/status', { method: 'PUT', body: JSON.stringify(body) });
      toast(`已记录手机当前使用：${prof}`, 'ok');
      await refresh();
    });
  });

  document.getElementById('btnAdbScan')?.addEventListener('click', async () => {
    try {
      ui.adbDevices = await api('/api/adb/devices');
      toast(`发现 ${ui.adbDevices.devices.length} 台设备`, ui.adbDevices.devices.length ? 'ok' : 'info');
      renderAndroidView(root);
    } catch (err) { toast(err.message, 'error'); }
  });

  document.getElementById('btnAdbPkg')?.addEventListener('click', async () => {
    try {
      const serial = authDev?.serial || state.deviceBindings.android.deviceSerial;
      ui.adbPackages = await api('/api/adb/packages', { method: 'POST', body: JSON.stringify({ serial }) });
      if (ui.adbPackages.status === 'pass') toast('已同步手机 App 安装状态到左侧预览', 'ok');
      else toast(ui.adbPackages.error || '请先扫描并授权手机', 'error');
      renderAndroidView(root);
    } catch (err) { toast(err.message, 'error'); }
  });

  document.getElementById('btnAdbPush')?.addEventListener('click', async () => {
    try {
      const serial = authDev?.serial || state.deviceBindings.android.deviceSerial;
      const res = await api('/api/adb/push', { method: 'POST', body: JSON.stringify({ serial }) });
      toast(`已推送到 ${res.push.remoteDir}`, 'ok');
      await refresh();
    } catch (err) { toast(err.message, 'error'); }
  });

  document.getElementById('btnAdbInspect')?.addEventListener('click', async () => {
    try {
      toast('正在通过临时 ADB 转发探测 7890 & 17990...');
      const serial = authDev?.serial || state.deviceBindings.android.deviceSerial;
      const secret = document.getElementById('inputAdbSecret')?.value || '';
      const res = await api('/api/adb/inspect', {
        method: 'POST',
        body: JSON.stringify({ serial, secret, versionId: latestVer?.versionId })
      });
      ui.adbInspect = res.inspect;
      toast(`探测完成：${res.inspect.status}`, res.inspect.status === 'pass' ? 'ok' : 'error');
      await refresh();
    } catch (err) { toast(err.message, 'error'); }
  });
}

// =========================================================
// 视图 3：第一跳订阅 & 静态出口卡片墙（无表单堆砌）
// =========================================================
function renderNodesView(root) {
  const { state, sub, primaryHop } = activeCtx();
  const selSet = new Set(state.activeBinding.selectedFirstHops || []);
  const q = ui.nodeSearch.trim().toLowerCase();
  const visibleNodes = (sub?.nodes || []).filter(n => !q || n.name.toLowerCase().includes(q) || n.server.toLowerCase().includes(q));

  root.innerHTML = `
    <div class="split-2">
      <!-- 左：第一跳订阅与节点 -->
      <section class="card" style="display:flex;flex-direction:column;gap:14px;">
        <div class="card-head" style="margin-bottom:0;">
          <div>
            <h2 class="card-title">✈️ 第一跳订阅（国内中转）</h2>
            <p class="sub-text">随时换便宜订阅，点星标设首选、点卡片加入备选组</p>
          </div>
          <div class="row">
            <button class="btn btn-secondary btn-sm" id="btnOpenBench">⚡ 测速</button>
            <button class="btn btn-primary btn-sm" id="btnOpenImportSub">+ 导入订阅</button>
          </div>
        </div>

        <div class="row">
          ${state.subscriptions.map(item => `
            <button class="sim-chip ${item.id === state.activeBinding.subscriptionId ? 'active-chain' : ''}" data-pick-sub="${esc(item.id)}">
              ${esc(item.name)} <span style="opacity:.7">(${item.nodeCount})</span>
            </button>
          `).join('')}
        </div>

        <div class="row">
          <input type="text" id="nodesSearchInput" value="${esc(ui.nodeSearch)}" placeholder="搜索节点（台湾 / 香港 / 日本 / IEPL...）" class="grow" />
          ${sub?.hasUrl ? `<button class="btn btn-secondary btn-sm" id="btnRefreshActiveSub">刷新订阅</button>` : ''}
        </div>

        <div class="hop-grid" id="nodesHopGrid"></div>
      </section>

      <!-- 右：静态出口卡片墙 -->
      <section class="card" style="display:flex;flex-direction:column;gap:14px;">
        <div class="card-head" style="margin-bottom:0;">
          <div>
            <h2 class="card-title">🛡️ 静态出口 IP 档案</h2>
            <p class="sub-text">换 IP 只需点一下切换，密码本地加密永不外泄</p>
          </div>
          <button class="btn btn-primary btn-sm" id="btnOpenAddExit">+ 新增静态 IP</button>
        </div>

        <div style="display:flex;flex-direction:column;gap:10px;">
          ${state.staticExits.map(ex => {
            const active = ex.id === state.activeBinding.staticExitId;
            return `
              <div class="visual-card ${active ? 'selected' : ''}">
                <div class="visual-card-row">
                  <div>
                    <div class="row">
                      <strong>${esc(ex.name)}</strong>
                      ${active ? '<span class="tag tag-chain">使用中</span>' : ''}
                      ${ex.isSample ? '<span class="tag tag-warn">示例</span>' : ''}
                    </div>
                    <div class="mono" style="font-size:15px;font-weight:700;margin-top:4px;">${esc(ex.expectedIp)}</div>
                    <div class="sub-text">入口 <span class="mono">${esc(ex.server)}:${ex.port}</span> · ${esc(ex.region)} · ${ex.hasCredentials ? '🔒已存凭据' : '未填凭据'}</div>
                  </div>
                  <div class="row">
                    ${!active ? `<button class="btn btn-primary btn-sm btn-pick-exit" data-id="${esc(ex.id)}">切换</button>` : ''}
                    <button class="btn btn-secondary btn-sm btn-edit-exit" data-id="${esc(ex.id)}">编辑</button>
                  </div>
                </div>
              </div>
            `;
          }).join('')}
        </div>
      </section>
    </div>
  `;

  document.getElementById('btnOpenImportSub')?.addEventListener('click', () => openDrawer('import-sub'));
  document.getElementById('btnOpenBench')?.addEventListener('click', () => openDrawer('benchmark'));
  document.getElementById('btnOpenAddExit')?.addEventListener('click', () => { ui.editingExitId = null; openDrawer('add-exit'); });

  root.querySelectorAll('[data-pick-sub]').forEach(btn => {
    btn.addEventListener('click', () => patchBinding({ subscriptionId: btn.dataset.pickSub }, '已切换第一跳订阅'));
  });

  const renderHopGridOnly = () => {
    const grid = document.getElementById('nodesHopGrid');
    if (!grid) return;
    const kw = ui.nodeSearch.trim().toLowerCase();
    const filtered = (sub?.nodes || []).filter(n => !kw || n.name.toLowerCase().includes(kw) || n.server.toLowerCase().includes(kw));
    grid.innerHTML = filtered.length === 0
      ? '<div class="sub-text">没有匹配的节点</div>'
      : filtered.map(n => {
        const inGrp = selSet.has(n.name);
        const isPri = primaryHop === n.name;
        return `
          <div class="hop-item ${inGrp ? 'in-group' : ''} ${isPri ? 'is-primary' : ''}" data-toggle-hop="${esc(n.name)}">
            <div style="min-width:0;">
              <div style="font-size:13px;font-weight:620;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;" title="${esc(n.name)}">${esc(n.name)}</div>
              <div class="sub-text mono" style="font-size:11px;">${esc(n.type.toUpperCase())} · ${esc(n.server)}</div>
            </div>
            <button class="btn ${isPri ? 'btn-chain' : 'btn-ghost'} btn-sm btn-star-hop" data-star="${esc(n.name)}" title="设为首选第一跳">
              ${isPri ? '★ 首选' : '☆'}
            </button>
          </div>
        `;
      }).join('');

    grid.querySelectorAll('.btn-star-hop').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        patchBinding({ primaryFirstHop: btn.dataset.star }, `首选第一跳已设为 ${btn.dataset.star}`);
      });
    });
    grid.querySelectorAll('[data-toggle-hop]').forEach(card => {
      card.addEventListener('click', () => {
        const name = card.dataset.toggleHop;
        const set = new Set(state.activeBinding.selectedFirstHops || []);
        if (set.has(name)) set.delete(name); else set.add(name);
        patchBinding({ selectedFirstHops: [...set] }, set.has(name) ? `已加入备选：${name}` : `已移出备选：${name}`);
      });
    });
  };
  renderHopGridOnly();

  document.getElementById('nodesSearchInput')?.addEventListener('input', (e) => {
    ui.nodeSearch = e.target.value;
    renderHopGridOnly();
  });

  document.getElementById('btnRefreshActiveSub')?.addEventListener('click', async () => {
    try {
      toast('正在在线刷新订阅...');
      const res = await api(`/api/subscriptions/${encodeURIComponent(sub.id)}/refresh`, { method: 'POST' });
      toast(`已刷新（${res.nodeCount} 节点）`, 'ok');
      await refresh(true);
    } catch (err) { toast(err.message, 'error'); }
  });

  root.querySelectorAll('.btn-pick-exit').forEach(btn => {
    btn.addEventListener('click', () => patchBinding({ staticExitId: btn.dataset.id }, '已切换静态出口，请点击右上角「生成并应用」'));
  });

  root.querySelectorAll('.btn-edit-exit').forEach(btn => {
    btn.addEventListener('click', () => { ui.editingExitId = btn.dataset.id; openDrawer('edit-exit'); });
  });
}

// =========================================================
// 视图 3.5：🛡️ Claude 独立环境与防泄漏体检中心
// =========================================================
function renderHygieneView(root) {
  const { exit } = activeCtx();
  const audit = ui.hygieneAudit;
  const caches = audit?.caches || ui.hygieneCaches?.caches || [];
  const runningTargets = audit?.cards?.find(c => c.id === 'process-guard')?.runningTargets || ui.hygieneCaches?.runningTargets || [];

  const verdictCls = audit ? `verdict-${audit.verdict}` : '';
  const shieldIcon = !audit ? '🛡️' : (audit.verdict === 'pass' ? '✅' : (audit.verdict === 'fail' ? '⚠️' : '🔍'));
  const statusTag = (st) => {
    if (st === 'pass') return '<span class="tag tag-direct">pass · 通过</span>';
    if (st === 'fail') return '<span class="tag tag-danger">fail · 需修复</span>';
    if (st === 'blocked') return '<span class="tag tag-warn">blocked · 未读到</span>';
    return '<span class="tag tag-warn">partial · 留意</span>';
  };

  const checkers = audit?.externalCheckers || [
    { name: '本地 CheckCC (4317)', url: 'http://127.0.0.1:4317', note: '需先启动 CheckCC 本地服务' },
    { name: 'BrowserLeaks WebRTC', url: 'https://browserleaks.com/webrtc', note: '在 BitBrowser / GoLogin 内打开确认无本地 IP 泄漏' },
    { name: 'BrowserLeaks DNS', url: 'https://browserleaks.com/dns', note: '核对 DNS 归属与静态出口一致' },
    { name: 'IPInfo 画像', url: 'https://ipinfo.io', note: '核对 ASN、住宅属性与时区' }
  ];

  root.innerHTML = `
    <!-- 顶部综合就绪度横幅 -->
    <section class="hygiene-hero ${verdictCls}">
      <div class="row" style="gap:14px;">
        <div class="hygiene-shield">${shieldIcon}</div>
        <div>
          <h2 class="card-title" style="font-size:16.5px;">
            ${audit ? esc(audit.verdictLabel) : 'Claude 独立环境与防泄漏体检中心'}
          </h2>
          <p class="sub-text">
            ${audit
              ? `上次体检：${fmtTime(audit.checkedAt)} · 核验双口静态 IP、时区语言对齐、Desktop/CLI 守卫、IPv6/UDP 防泄漏与进程残留`
              : `一键检查「出口 IP、时区语言、远端 DNS、IPv6/UDP 防泄漏、客户端策略与进程残留」是否全部对齐当前静态出口 (${esc(exit?.expectedIp || '-')})`}
          </p>
        </div>
      </div>
      <div class="row">
        <button class="btn btn-primary" id="btnRunHygieneScan" ${ui.hygieneBusy ? 'disabled' : ''}>
          ${ui.hygieneBusy ? '正在全面体检...' : '🔍 一键全面体检'}
        </button>
      </div>
    </section>

    <!-- 5 维红绿灯体检卡片 -->
    ${audit ? `
      <section class="audit-grid">
        ${audit.cards.map(c => `
          <div class="audit-card st-${esc(c.status)}">
            <div class="visual-card-row">
              <strong style="font-size:13.5px;">${esc(c.title)}</strong>
              ${statusTag(c.status)}
            </div>
            <div style="font-size:13px;font-weight:580;">${esc(c.summary)}</div>
            <ul class="audit-list">
              ${(c.details || []).map(d => `<li>${esc(d)}</li>`).join('')}
            </ul>
            ${c.actionHint === 'claude-env' ? `
              <div style="margin-top:auto;padding-top:6px;">
                <button class="btn btn-chain btn-sm btn-fix-claude-env">🇺🇸 一键切换 Claude 美国环境</button>
              </div>
            ` : ''}
          </div>
        `).join('')}
      </section>
    ` : `
      <section class="card" style="text-align:center;padding:34px 20px;">
        <div style="font-size:28px;margin-bottom:8px;">🛡️</div>
        <div style="font-weight:650;margin-bottom:6px;">启动 Claude 或更换静态 IP 前，建议先做一次 5 维一致性体检</div>
        <p class="sub-text" style="max-width:560px;margin:0 auto 14px;">风控的核心不是频繁随机伪造指纹，而是让 <strong>静态住宅 IP、系统时区、语言、远端 DNS、WebRTC/UDP 阻断、独立浏览器 Profile</strong> 始终保持真实且稳定的坐标一致。</p>
        <button class="btn btn-chain" id="btnRunHygieneScanEmpty">立即开始体检</button>
      </section>
    `}

    <!-- 下半部分：安全渲染缓存清理 + 独立浏览器指纹与换 IP SOP -->
    <section class="split-2">
      <!-- 安全渲染缓存清理台 -->
      <div class="card" style="display:flex;flex-direction:column;gap:12px;">
        <div class="card-head" style="margin-bottom:0;">
          <div>
            <h2 class="card-title">🧹 安全渲染缓存清理（保留登录态）</h2>
            <p class="sub-text">仅清理白名单内的临时缓存，绝不删除 Cookie、登录凭据或 Claude Code Hooks</p>
          </div>
          <button class="btn btn-ghost btn-sm" id="btnRefreshCaches">刷新大小</button>
        </div>

        <div class="banner-inner warn" style="font-size:12px;">
          <span>💡 <strong>防误区提示：</strong>正常稳定使用的账号<strong>不要</strong>频繁清 Cookie 或重置指纹（固定设备画像更安全）；仅在切换新静态 IP、解决客户端卡顿或新建隔离账号时才清理临时渲染缓存。</span>
        </div>

        ${runningTargets.length > 0 ? `
          <div class="banner-inner danger" style="font-size:12px;">
            <span>检测到 ${runningTargets.length} 个相关进程仍在运行（${esc([...new Set(runningTargets.map(p => p.ProcessName))].join(', '))}），请先完全退出后再清理缓存。</span>
          </div>
        ` : ''}

        <div style="display:flex;flex-direction:column;gap:8px;">
          ${caches.length === 0 ? '<div class="sub-text">点击「刷新大小」或「一键全面体检」扫描本机可安全清理的临时渲染缓存。</div>' : caches.map(c => `
            <div class="toggle-row">
              <div style="min-width:0;">
                <div style="font-size:13px;font-weight:600;">${esc(c.label)}</div>
                <div class="sub-text">${esc(c.safeNote)} · 当前 <strong class="mono">${c.totalMB} MB</strong> (${c.totalFiles} 文件)</div>
              </div>
              <button class="btn btn-secondary btn-sm btn-clean-cache" data-cid="${esc(c.id)}" ${runningTargets.length > 0 || c.totalFiles === 0 ? 'disabled' : ''}>清理</button>
            </div>
          `).join('')}
        </div>
      </div>

      <!-- 指纹浏览器一致性清单 + 换 IP 标准 SOP -->
      <div class="card" style="display:flex;flex-direction:column;gap:12px;">
        <div class="card-head" style="margin-bottom:0;">
          <div>
            <h2 class="card-title">🧭 换静态 IP / 独立浏览器防风控 SOP</h2>
            <p class="sub-text">配合 BitBrowser (17902) 与手机 GoLogin (17990) 使用</p>
          </div>
        </div>

        <div style="display:flex;flex-direction:column;gap:7px;">
          <div class="sop-step"><span class="step-badge">1</span><div><strong>先退出再切换：</strong>更换静态 IP 或切回中国环境前，先彻底退出 Claude Desktop / CLI / 专用浏览器，避免旧进程缓存旧时区或长连接跨 IP 复用。</div></div>
          <div class="sop-step"><span class="step-badge">2</span><div><strong>固定单账号独立 Profile：</strong>BitBrowser 绑定 <code>127.0.0.1:17902</code>，手机 GoLogin 绑定 <code>127.0.0.1:17990</code>；WebRTC 设为 <strong>禁用 / Disable non-proxied UDP</strong>，时区与语言跟随静态 IP（如 <code>en-US</code> / <code>America/Chicago</code>），固定硬件指纹不随机跳动。</div></div>
          <div class="sop-step"><span class="step-badge">3</span><div><strong>切换后先体检再登录：</strong>点上方「一键全面体检」，确认 7897 / 17902 双口 IP 一致、时区一致、UDP/IPv6 防泄漏通过后再启动客户端。</div></div>
        </div>

        <div style="border-top:1px solid var(--border);padding-top:10px;">
          <div style="font-size:12px;font-weight:650;color:var(--ink-2);margin-bottom:7px;">复制链接到 BitBrowser / GoLogin 内核对（勿在日常浏览器测，第三方分数仅作参考）：</div>
          <div class="row">
            ${checkers.map(ch => `
              <button class="sim-chip btn-copy-url" data-url="${esc(ch.url)}" title="${esc(ch.note)}">📋 ${esc(ch.name)}</button>
            `).join('')}
          </div>
        </div>
      </div>
    </section>
  `;

  const triggerScan = async () => {
    ui.hygieneBusy = true;
    renderHygieneView(root);
    try {
      const res = await api('/api/hygiene/scan', { method: 'POST' });
      ui.hygieneAudit = res.audit;
      toast(`体检完成：${res.audit.verdictLabel}`, res.audit.verdict === 'pass' ? 'ok' : (res.audit.verdict === 'fail' ? 'error' : 'info'));
    } catch (err) {
      toast(err.message, 'error');
    } finally {
      ui.hygieneBusy = false;
      renderHygieneView(root);
    }
  };

  document.getElementById('btnRunHygieneScan')?.addEventListener('click', triggerScan);
  document.getElementById('btnRunHygieneScanEmpty')?.addEventListener('click', triggerScan);

  document.getElementById('btnRefreshCaches')?.addEventListener('click', async () => {
    try {
      ui.hygieneCaches = await api('/api/hygiene/caches');
      if (ui.hygieneAudit) ui.hygieneAudit.caches = ui.hygieneCaches.caches;
      toast('已刷新缓存大小', 'ok');
      renderHygieneView(root);
    } catch (err) { toast(err.message, 'error'); }
  });

  root.querySelectorAll('.btn-clean-cache').forEach(btn => {
    btn.addEventListener('click', async () => {
      if (!confirm('确认仅清理所选的渲染临时缓存？（不会删除登录 Cookie、账号状态或 Claude Code 配置）')) return;
      try {
        const res = await api('/api/hygiene/clean-cache', {
          method: 'POST',
          body: JSON.stringify({ confirm: true, targetIds: [btn.dataset.cid] })
        });
        if (ui.hygieneAudit) ui.hygieneAudit.caches = res.caches;
        ui.hygieneCaches = { ...(ui.hygieneCaches || {}), caches: res.caches };
        toast('已安全清理临时渲染缓存（登录态保留）', 'ok');
        renderHygieneView(root);
      } catch (err) { toast(err.message, 'error'); }
    });
  });

  root.querySelectorAll('.btn-fix-claude-env').forEach(btn => {
    btn.addEventListener('click', async () => {
      try {
        const res = await api('/api/launcher/run', { method: 'POST', body: JSON.stringify({ action: 'claude-env' }) });
        toast(`已触发「Claude 美国环境」切换 (PID ${res.pid})，完成后请重新体检`, 'ok');
      } catch (err) { toast(err.message, 'error'); }
    });
  });

  root.querySelectorAll('.btn-copy-url').forEach(btn => {
    btn.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(btn.dataset.url);
        toast(`已复制 ${btn.dataset.url}，请粘贴到专用浏览器内打开`, 'ok');
      } catch {
        toast(`请手动复制：${btn.dataset.url}`, 'info');
      }
    });
  });
}

// =========================================================
// 视图 4：规则开关、版本回滚与可折叠专家视图
// =========================================================
function renderRulesView(root) {
  const { state, preset } = activeCtx();
  const winOpts = preset.windowsOptions;
  const winBind = state.deviceBindings.windows;

  root.innerHTML = `
    <div class="split-2">
      <!-- 游戏直连与自定义规则 -->
      <section class="card" style="display:flex;flex-direction:column;gap:12px;">
        <div class="card-head" style="margin-bottom:0;">
          <div>
            <h2 class="card-title">🎮 游戏与国内直连开关</h2>
            <p class="sub-text">开启后直接走本地宽带，绝不消耗静态出口流量</p>
          </div>
          <span class="tag tag-direct">DIRECT</span>
        </div>
        ${preset.gameDirectRules.map((r, i) => `
          <div class="toggle-row">
            <div style="min-width:0;">
              <div style="font-size:13px;font-weight:600;">${esc(r.note || r.payload)}</div>
              <div class="sub-text mono" style="font-size:11px;overflow:hidden;text-overflow:ellipsis;">${esc(r.payload)}</div>
            </div>
            <label class="switch">
              <input type="checkbox" class="sw-game" data-i="${i}" ${r.enabled ? 'checked' : ''} />
              <span class="slider"></span>
            </label>
          </div>
        `).join('')}

        <div style="border-top:1px solid var(--border);padding-top:12px;">
          <div style="font-weight:650;font-size:13px;margin-bottom:8px;">➕ 自定义补充规则</div>
          ${preset.customRules.map((r, i) => `
            <div class="toggle-row" style="margin-bottom:6px;">
              <span class="mono" style="font-size:12px;">${esc(r.type)},${esc(r.payload)} → <strong>${esc(r.action)}</strong></span>
              <button class="btn btn-danger btn-sm btn-rm-custom" data-i="${i}">删</button>
            </div>
          `).join('')}
          <form id="formQuickRule" class="row">
            <select name="type" style="width:130px;">
              <option value="DOMAIN-SUFFIX">域名后缀</option>
              <option value="DOMAIN">精确域名</option>
              <option value="PROCESS-NAME">进程名</option>
            </select>
            <input type="text" name="payload" placeholder="例如 steamcontent.com" class="grow" required />
            <select name="action" style="width:92px;">
              <option value="DIRECT">直连</option>
              <option value="CHAIN">静态链</option>
              <option value="REJECT">拒绝</option>
            </select>
            <button type="submit" class="btn btn-secondary btn-sm">添加</button>
          </form>
        </div>
      </section>

      <!-- 版本历史与一键回滚 -->
      <section class="card" style="display:flex;flex-direction:column;gap:12px;">
        <div class="card-head" style="margin-bottom:0;">
          <div>
            <h2 class="card-title">🕒 版本记录与一键回滚</h2>
            <p class="sub-text">每次覆盖 Clash Verge 前都会自动存档，出问题秒级还原</p>
          </div>
          <a class="btn btn-secondary btn-sm" href="/api/report/export">导出脱敏报告</a>
        </div>

        ${state.versions.length === 0 ? '<div class="sub-text">尚未生成版本，点击右上角「生成并应用」即可创建首个版本。</div>' : state.versions.slice(0, 8).map(v => `
          <div class="visual-card">
            <div class="visual-card-row">
              <div>
                <div class="row">
                  <strong class="mono">${esc(v.versionId)}</strong>
                  <span class="tag ${v.windowsStatus === 'applied' ? 'tag-chain' : 'tag-neutral'}">Win: ${esc(v.windowsStatus)}</span>
                </div>
                <div class="sub-text">${esc(v.primaryFirstHop || '-')} → <span class="mono">${esc(v.expectedIp)}</span> · ${fmtTime(v.createdAt)}</div>
              </div>
              <div class="row">
                <a class="btn btn-ghost btn-sm" href="/api/download/${esc(v.versionId)}/Desktop-Static-Chain.yaml">通用桌面YAML</a>
                <a class="btn btn-ghost btn-sm" href="/api/download/${esc(v.versionId)}/Daily-Static-Chain.yaml">手机日常</a>
                <a class="btn btn-ghost btn-sm" href="/api/download/${esc(v.versionId)}/Claude-GoLogin-Static.yaml">手机专用</a>
                ${v.backupPath ? `<button class="btn btn-danger btn-sm btn-rb" data-ver="${esc(v.versionId)}">回滚</button>` : ''}
              </div>
            </div>
          </div>
        `).join('')}
      </section>
    </div>

    <!-- 折叠专家设置：日常不打扰，需要时全掌控 -->
    <section class="card">
      <details>
        <summary style="cursor:pointer;font-weight:650;font-size:14px;">⚙️ 高级设置与底层代码预览（端口、TUN / IPv6、本机路径、Script.js 差异）</summary>
        <div class="split-2" style="margin-top:16px;">
          <form id="formExpertWin" class="form-stack">
            <div class="form-2col">
              <div class="field"><label>分流端口</label><input type="number" name="mixedPort" value="${winOpts.mixedPort}" /></div>
              <div class="field"><label>Relay / 上游端口</label><div class="row"><input type="number" name="relayPort" value="${winOpts.relayPort}" style="width:90px;" /><input type="number" name="upstreamPort" value="${winOpts.upstreamPort}" style="width:90px;" /></div></div>
            </div>
            <div class="toggle-row"><span>Windows TUN 模式（默认关闭）</span><label class="switch"><input type="checkbox" name="tunEnable" ${winOpts.tunEnable ? 'checked' : ''} /><span class="slider"></span></label></div>
            <div class="toggle-row"><span>Windows IPv6（默认关闭）</span><label class="switch"><input type="checkbox" name="ipv6" ${winOpts.ipv6 ? 'checked' : ''} /><span class="slider"></span></label></div>
            <div class="field"><label>Clash Verge 配置目录</label><input type="text" name="clashVergeDir" value="${esc(winBind.clashVergeDir)}" /></div>
            <div class="field"><label>ClaudeLocal 启动器目录</label><input type="text" name="claudeLocalDir" value="${esc(winBind.claudeLocalDir)}" /></div>
            <div class="field"><label>环境切换脚本目录</label><input type="text" name="claudeEnvScriptsDir" value="${esc(winBind.claudeEnvScriptsDir)}" /></div>
            <div><button type="submit" class="btn btn-secondary btn-sm">保存高级设置</button></div>
          </form>

          <div class="form-stack">
            <div class="row">
              <button class="sim-chip ${ui.expertSubtab === 'win-diff' ? 'active-chain' : ''}" data-esub="win-diff">Script.js 差异</button>
              <button class="sim-chip ${ui.expertSubtab === 'and-diff' ? 'active-chain' : ''}" data-esub="and-diff">手机日常 vs 专用</button>
              <button class="sim-chip ${ui.expertSubtab === 'runtime' ? 'active-chain' : ''}" data-esub="runtime">共享运行时 JSON</button>
            </div>
            <div class="code-box" id="expertCodeBox">${renderExpertCode()}</div>
          </div>
        </div>
      </details>
    </section>
  `;

  root.querySelectorAll('.sw-game').forEach(chk => {
    chk.addEventListener('change', async () => {
      const list = structuredClone(preset.gameDirectRules);
      list[Number(chk.dataset.i)].enabled = chk.checked;
      await patchRules({ gameDirectRules: list }, '已更新游戏直连规则');
    });
  });

  root.querySelectorAll('.btn-rm-custom').forEach(btn => {
    btn.addEventListener('click', async () => {
      const list = preset.customRules.filter((_, idx) => idx !== Number(btn.dataset.i));
      await patchRules({ customRules: list }, '已删除规则');
    });
  });

  document.getElementById('formQuickRule')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    const list = [...preset.customRules, { id: `c-${Date.now()}`, type: fd.get('type'), payload: String(fd.get('payload')).trim(), action: fd.get('action'), scope: 'both', enabled: true }];
    await patchRules({ customRules: list }, '已添加自定义规则');
  });

  root.querySelectorAll('.btn-rb').forEach(btn => {
    btn.addEventListener('click', async () => {
      if (!confirm(`确定回滚 Clash Verge 到 ${btn.dataset.ver} 应用前的备份？`)) return;
      try {
        await api('/api/rollback', { method: 'POST', body: JSON.stringify({ versionId: btn.dataset.ver }) });
        toast('已回滚至应用前快照', 'ok');
        await refresh(true);
      } catch (err) { toast(err.message, 'error'); }
    });
  });

  document.getElementById('formExpertWin')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    try {
      await api('/api/rules', {
        method: 'PUT',
        body: JSON.stringify({
          windowsOptions: {
            mixedPort: Number(fd.get('mixedPort')),
            relayPort: Number(fd.get('relayPort')),
            upstreamPort: Number(fd.get('upstreamPort')),
            tunEnable: fd.get('tunEnable') === 'on',
            ipv6: fd.get('ipv6') === 'on'
          }
        })
      });
      await api('/api/device-paths', {
        method: 'PUT',
        body: JSON.stringify({
          clashVergeDir: fd.get('clashVergeDir'),
          claudeLocalDir: fd.get('claudeLocalDir'),
          claudeEnvScriptsDir: fd.get('claudeEnvScriptsDir')
        })
      });
      toast('高级设置已保存', 'ok');
      await refresh(true);
    } catch (err) { toast(err.message, 'error'); }
  });

  root.querySelectorAll('[data-esub]').forEach(btn => {
    btn.addEventListener('click', () => {
      ui.expertSubtab = btn.dataset.esub;
      root.querySelectorAll('[data-esub]').forEach(x => x.classList.remove('active-chain'));
      btn.classList.add('active-chain');
      document.getElementById('expertCodeBox').innerHTML = renderExpertCode();
    });
  });
}

function renderExpertCode() {
  const p = ui.preview;
  if (!p) return '加载中...';
  if (!p.valid) return esc(p.validation.errors.join('\n'));
  if (ui.expertSubtab === 'win-diff') return renderDiffLines(p.windows.diff);
  if (ui.expertSubtab === 'and-diff') return renderDiffLines(p.android.variantDiff);
  return esc(JSON.stringify(p.sharedRuntime, null, 2));
}

function renderDiffLines(diff) {
  if (!diff?.lines?.length) return '当前无差异';
  return diff.lines.map(l => `<span class="diff-line ${esc(l.type)}">${esc((l.prefix || '') + (l.type === 'skip' ? '' : ' ') + l.text)}</span>`).join('\n');
}

// =========================================================
// 右侧滑出式快速替换抽屉（点击画布节点直接呼出）
// =========================================================
function openDrawer(mode) {
  ui.drawer = mode;
  document.getElementById('drawerBackdrop').classList.remove('hidden');
  renderDrawerContent();
}

function closeDrawer() {
  ui.drawer = null;
  document.getElementById('drawerBackdrop').classList.add('hidden');
}

function renderDrawerContent() {
  const titleEl = document.getElementById('drawerTitle');
  const subEl = document.getElementById('drawerSubtitle');
  const bodyEl = document.getElementById('drawerBody');
  const { state, sub, primaryHop, preset } = activeCtx();

  if (ui.drawer === 'hop') {
    titleEl.textContent = '快速更换第一跳 / 订阅';
    subEl.textContent = '点选即刻更新画布，静态出口 IP 保持不变';
    const q = ui.nodeSearch.trim().toLowerCase();
    const nodes = (sub?.nodes || []).filter(n => !q || n.name.toLowerCase().includes(q));

    bodyEl.innerHTML = `
      <div class="row">
        <button class="btn btn-primary btn-sm" id="drBtnImport">+ 导入便宜新订阅</button>
        <button class="btn btn-secondary btn-sm" id="drBtnBench">⚡ 全链测速选最快</button>
      </div>
      <div class="field">
        <label>当前订阅源</label>
        <select id="drSubSelect">
          ${state.subscriptions.map(s => `<option value="${esc(s.id)}" ${s.id === state.activeBinding.subscriptionId ? 'selected' : ''}>${esc(s.name)} (${s.nodeCount} 节点)</option>`).join('')}
        </select>
      </div>
      <input type="text" id="drNodeSearch" value="${esc(ui.nodeSearch)}" placeholder="筛选节点名称..." />
      <div style="display:flex;flex-direction:column;gap:8px;">
        ${nodes.map(n => `
          <div class="hop-item ${n.name === primaryHop ? 'is-primary' : ''}" data-dr-hop="${esc(n.name)}">
            <div style="min-width:0;">
              <div style="font-weight:620;font-size:13px;">${esc(n.name)}</div>
              <div class="sub-text mono" style="font-size:11px;">${esc(n.type.toUpperCase())} · ${esc(n.server)}:${n.port}</div>
            </div>
            ${n.name === primaryHop ? '<span class="tag tag-chain">当前首选</span>' : '<span class="sub-text">点击选中</span>'}
          </div>
        `).join('')}
      </div>
    `;

    document.getElementById('drBtnImport')?.addEventListener('click', () => openDrawer('import-sub'));
    document.getElementById('drBtnBench')?.addEventListener('click', () => openDrawer('benchmark'));
    document.getElementById('drSubSelect')?.addEventListener('change', (e) => patchBinding({ subscriptionId: e.target.value }, '已切换第一跳订阅'));
    document.getElementById('drNodeSearch')?.addEventListener('input', (e) => {
      ui.nodeSearch = e.target.value;
      renderDrawerContent();
      const inp = document.getElementById('drNodeSearch');
      if (inp) { inp.focus(); inp.selectionStart = inp.selectionEnd = inp.value.length; }
    });
    bodyEl.querySelectorAll('[data-dr-hop]').forEach(el => {
      el.addEventListener('click', async () => {
        await patchBinding({ primaryFirstHop: el.dataset.drHop }, `第一跳已切换为 ${el.dataset.drHop}`);
      });
    });
    return;
  }

  if (ui.drawer === 'exit') {
    const lastWinProbe = state.probeHistory.find(p => p.target === 'windows' && p.ruleProbe?.observedIp);
    const observedIp = lastWinProbe?.ruleProbe?.observedIp || null;
    const activeExit = state.staticExits.find(e => e.id === state.activeBinding.staticExitId);
    titleEl.textContent = '快速更换静态出口 IP';
    subEl.textContent = '节点入口地址与预期公网 IP 可分开维护（支持网关转发型代理）';
    bodyEl.innerHTML = `
      <div class="row">
        <button class="btn btn-primary btn-sm" id="drBtnNewExit">+ 新增静态 IP</button>
        <button class="btn btn-secondary btn-sm" id="drBtnImportVerge">从本机 Clash Verge 导入</button>
      </div>
      ${observedIp && activeExit && observedIp !== activeExit.expectedIp ? `
        <div class="banner-inner warn" style="flex-direction:column;align-items:flex-start;gap:8px;">
          <span>最近实测公网出口为 <strong class="mono">${esc(observedIp)}</strong>（当前预期为 <span class="mono">${esc(activeExit.expectedIp)}</span>）</span>
          <button class="btn btn-secondary btn-sm" id="drBtnAdoptObservedIp">把实测 IP (${esc(observedIp)}) 设为预期公网 IP</button>
        </div>
      ` : ''}
      <div style="display:flex;flex-direction:column;gap:10px;">
        ${state.staticExits.map(ex => {
          const active = ex.id === state.activeBinding.staticExitId;
          return `
            <div class="visual-card ${active ? 'selected' : ''}" style="cursor:pointer;" data-dr-exit="${esc(ex.id)}">
              <div class="visual-card-row">
                <div>
                  <div class="row">
                    <strong>${esc(ex.name)}</strong>
                    ${ex.isSample ? '<span class="tag tag-warn">文档示例占位</span>' : ''}
                  </div>
                  <div class="mono" style="font-size:15px;font-weight:700;margin-top:2px;">${esc(ex.expectedIp)}</div>
                  <div class="sub-text">${esc(ex.region)} · 入口 ${esc(ex.server)}:${ex.port}</div>
                </div>
                <div class="row">
                  ${active ? '<span class="tag tag-chain">使用中</span>' : '<span class="btn btn-secondary btn-sm">选中</span>'}
                  <button class="btn btn-ghost btn-sm dr-edit-exit" data-id="${esc(ex.id)}">编辑</button>
                </div>
              </div>
            </div>
          `;
        }).join('')}
      </div>
    `;
    document.getElementById('drBtnNewExit')?.addEventListener('click', () => { ui.editingExitId = null; openDrawer('add-exit'); });
    document.getElementById('drBtnImportVerge')?.addEventListener('click', () => runImportClashVerge());
    document.getElementById('drBtnAdoptObservedIp')?.addEventListener('click', async () => {
      try {
        const info = lastWinProbe?.ruleProbe?.ipinfo;
        await api(`/api/static-exits/${encodeURIComponent(activeExit.id)}`, {
          method: 'PUT',
          body: JSON.stringify({
            expectedIp: observedIp,
            region: info?.country && info?.city ? `${info.country} / ${info.city}` : activeExit.region,
            timeZone: info?.timezone || activeExit.timeZone
          })
        });
        toast(`已将预期公网 IP 更新为 ${observedIp}`, 'ok');
        await refresh(true);
      } catch (err) { toast(err.message, 'error'); }
    });
    bodyEl.querySelectorAll('.dr-edit-exit').forEach(btn => {
      btn.addEventListener('click', (e) => { e.stopPropagation(); ui.editingExitId = btn.dataset.id; openDrawer('edit-exit'); });
    });
    bodyEl.querySelectorAll('[data-dr-exit]').forEach(card => {
      card.addEventListener('click', () => patchBinding({ staticExitId: card.dataset.drExit }, '已切换静态出口，请点击右上角「生成并应用」'));
    });
    return;
  }

  if (ui.drawer === 'import-sub') {
    titleEl.textContent = '导入新的第一跳订阅';
    subEl.textContent = '支持机场订阅链接、Clash YAML、Base64 或节点链接';
    bodyEl.innerHTML = `
      <form id="drFormUrl" class="form-stack">
        <div class="field"><label>订阅名称</label><input type="text" name="name" placeholder="例如：便宜机场线" required /></div>
        <div class="field"><label>订阅链接 (URL)</label><input type="url" name="url" placeholder="https://..." required /></div>
        <div class="field"><label>价格备注（选填）</label><input type="text" name="priceNote" placeholder="例如 ¥9.9/月 · 150GB" /></div>
        <button type="submit" class="btn btn-primary">通过链接拉取并启用</button>
      </form>
      <div style="text-align:center;color:var(--ink-3);font-size:12px;">— 或者直接粘贴 YAML / 节点文本 —</div>
      <form id="drFormYaml" class="form-stack">
        <div class="field"><label>名称</label><input type="text" name="name" placeholder="例如：本地节点快照" required /></div>
        <div class="field"><label>YAML 或 ss:// / trojan:// 文本</label><textarea name="content" rows="5" required></textarea></div>
        <button type="submit" class="btn btn-secondary">解析文本并启用</button>
      </form>
    `;
    document.getElementById('drFormUrl')?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const fd = new FormData(e.target);
      try {
        toast('正在拉取订阅...');
        const res = await api('/api/subscriptions/import-url', {
          method: 'POST',
          body: JSON.stringify({ name: fd.get('name'), url: fd.get('url'), priceNote: fd.get('priceNote') })
        });
        ui.dirty = true;
        toast(`导入成功：${res.subscription.nodeCount} 个叶子节点`, 'ok');
        closeDrawer();
        await refresh(true);
      } catch (err) { toast(err.message, 'error'); }
    });
    document.getElementById('drFormYaml')?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const fd = new FormData(e.target);
      try {
        const res = await api('/api/subscriptions/import-yaml', {
          method: 'POST',
          body: JSON.stringify({ name: fd.get('name'), content: fd.get('content') })
        });
        ui.dirty = true;
        toast(`解析成功：${res.subscription.nodeCount} 个叶子节点`, 'ok');
        closeDrawer();
        await refresh(true);
      } catch (err) { toast(err.message, 'error'); }
    });
    return;
  }

  if (ui.drawer === 'add-exit' || ui.drawer === 'edit-exit') {
    const editing = ui.drawer === 'edit-exit' ? state.staticExits.find(x => x.id === ui.editingExitId) : null;
    titleEl.textContent = editing ? '编辑静态出口 IP' : '新增静态出口 IP';
    subEl.textContent = '节点地址与预期公网 IP 独立维护，密码安全加密存储';
    bodyEl.innerHTML = `
      <form id="drFormExit" class="form-stack">
        <div class="form-2col">
          <div class="field"><label>名称</label><input type="text" name="name" value="${esc(editing?.name || '')}" placeholder="NodeMaven 美国 Dallas" required /></div>
          <div class="field"><label>地区</label><input type="text" name="region" value="${esc(editing?.region || 'US / Dallas')}" /></div>
        </div>
        <div class="form-2col">
          <div class="field"><label>节点连接地址 (Server)</label><input type="text" name="server" value="${esc(editing?.server || '')}" required /></div>
          <div class="field"><label>端口</label><input type="number" name="port" value="${esc(editing?.port || 5432)}" required /></div>
        </div>
        <div class="field"><label>预期公网出口 IP（用于防漂移校验）</label><input type="text" name="expectedIp" value="${esc(editing?.expectedIp || '')}" required /></div>
        <div class="form-2col">
          <div class="field"><label>Windows 协议</label><select name="windowsProtocol"><option value="http" ${(editing?.windowsProtocol || 'http') === 'http' ? 'selected' : ''}>HTTP (配合 IPv4 Relay)</option><option value="socks5" ${editing?.windowsProtocol === 'socks5' ? 'selected' : ''}>SOCKS5</option></select></div>
          <div class="field"><label>Android 协议</label><select name="androidProtocol"><option value="socks5" ${(editing?.androidProtocol || 'socks5') === 'socks5' ? 'selected' : ''}>SOCKS5 (推荐)</option><option value="http" ${editing?.androidProtocol === 'http' ? 'selected' : ''}>HTTP</option></select></div>
        </div>
        <div class="form-2col">
          <div class="field"><label>代理用户名（加密保存）</label><input type="text" name="username" placeholder="${editing?.hasCredentials ? '留空保持原值' : '填写用户名'}" /></div>
          <div class="field"><label>代理密码（加密保存）</label><input type="password" name="password" placeholder="${editing?.hasCredentials ? '留空保持原值' : '填写密码'}" /></div>
        </div>
        <button type="submit" class="btn btn-primary">${editing ? '保存修改' : '保存并立即切换为此出口'}</button>
      </form>
    `;
    document.getElementById('drFormExit')?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const fd = new FormData(e.target);
      const payload = {
        name: fd.get('name'),
        region: fd.get('region'),
        server: fd.get('server'),
        port: Number(fd.get('port')),
        expectedIp: fd.get('expectedIp'),
        windowsProtocol: fd.get('windowsProtocol'),
        androidProtocol: fd.get('androidProtocol'),
        username: fd.get('username') || undefined,
        password: fd.get('password') || undefined,
        activate: !editing
      };
      try {
        if (editing) await api(`/api/static-exits/${encodeURIComponent(editing.id)}`, { method: 'PUT', body: JSON.stringify(payload) });
        else await api('/api/static-exits', { method: 'POST', body: JSON.stringify(payload) });
        ui.dirty = true;
        toast(editing ? '静态出口已更新' : '已新增并切换静态出口', 'ok');
        closeDrawer();
        await refresh(true);
      } catch (err) { toast(err.message, 'error'); }
    });
    return;
  }

  if (ui.drawer === 'benchmark') {
    const last = state.benchmarks[0] || null;
    const ctrl = ui.bootstrap?.windowsEnv?.controller || {};
    titleEl.textContent = '⚡ 全链第一跳测速';
    subEl.textContent = '固定静态出口逐个测试第一跳，测完自动还原原节点';
    bodyEl.innerHTML = `
      <div class="visual-card ${ctrl.detected ? 'selected' : ''}">
        <div class="visual-card-row">
          <strong>${ctrl.detected ? '✅ 已自动连接 Clash Verge 控制器' : '⚠️ 未自动检测到运行中的 Mihomo 控制器'}</strong>
          <span class="tag ${ctrl.detected ? 'tag-direct' : 'tag-warn'}">${ctrl.detected ? (ctrl.transport === 'pipe' ? 'Named Pipe' : ctrl.transport.toUpperCase()) : '待连接'}</span>
        </div>
        <div class="sub-text">
          ${ctrl.detected
            ? `${esc(ctrl.label)}${ctrl.hasSecret ? ' · 密钥已自动读取' : ''} · 代理口 <span class="mono">${preset.windowsOptions.mixedPort}</span>`
            : '请确认 Clash Verge 正在运行，或展开下方高级选项手动填入 TCP Controller 地址'}
        </div>
        ${ctrl.detected ? `
          <div class="sub-text">
            策略组 <code>${esc(preset.windowsOptions.firstHopGroupName)}</code> 当前载入 <strong>${ctrl.liveCandidatesCount}</strong> 个候选节点${ctrl.liveFirstHopNow ? `（现用：${esc(ctrl.liveFirstHopNow)}）` : ''}
          </div>
        ` : ''}
      </div>

      ${ctrl.detected && ctrl.liveCandidatesCount <= 2 ? `
        <div class="banner-inner warn" style="font-size:12px;">
          <span>💡 当前策略组里只有 ${ctrl.liveCandidatesCount} 个候选节点；如果想测更多机场节点，先在「第一跳与出口」多勾选几个节点，点「生成并应用」写入并刷新 Clash Verge 后再来批量测速。</span>
        </div>
      ` : ''}

      <form id="drFormBench" class="form-stack">
        <details>
          <summary class="sub-text" style="cursor:pointer;">高级：手动覆盖其他 Controller 地址或测试端口（默认全自动无需填写）</summary>
          <div class="form-stack" style="margin-top:10px;">
            <div class="field"><label>自定义 Controller URL（留空即自动连接 Clash Verge）</label><input type="text" name="controllerUrl" placeholder="留空自动识别 Named Pipe / Unix Socket / TCP" /></div>
            <div class="form-2col">
              <div class="field"><label>自定义 Secret（留空自动读取）</label><input type="password" name="secret" placeholder="留空自动读取" /></div>
              <div class="field"><label>测试代理端口</label><input type="number" name="proxyPort" value="${preset.windowsOptions.mixedPort}" /></div>
            </div>
          </div>
        </details>
        <button type="submit" class="btn btn-chain" id="btnStartBenchSubmit">⚡ 一键开始全链测速</button>
      </form>
      ${last?.finalists?.length ? `
        <div style="display:flex;flex-direction:column;gap:8px;">
          <strong>上次测速结果（推荐：${esc(last.recommendedHop || '-')}）</strong>
          <div class="sub-text">原节点恢复状态：${esc(last.restoreStatus || '-')}</div>
          ${last.finalists.map(f => `
            <div class="hop-item" data-use-bench="${esc(f.name)}">
              <div>
                <div style="font-weight:600;font-size:13px;">${esc(f.name)}</div>
                <div class="sub-text mono">${f.successCount}/${f.totalCount} 通过 · 均值 ${f.meanSec ?? '-'}s · 最大 ${f.maxSec ?? '-'}s</div>
              </div>
              <span class="btn btn-secondary btn-sm">设为首选</span>
            </div>
          `).join('')}
        </div>
      ` : ''}
    `;
    document.getElementById('drFormBench')?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const fd = new FormData(e.target);
      const btn = document.getElementById('btnStartBenchSubmit');
      if (btn) { btn.disabled = true; btn.textContent = '测速运行中，请稍候...'; }
      try {
        toast('全链测速运行中，请稍候（结束后自动还原原节点）...');
        const res = await api('/api/benchmark/hops', {
          method: 'POST',
          body: JSON.stringify({
            controllerUrl: String(fd.get('controllerUrl') || '').trim(),
            secret: String(fd.get('secret') || '').trim(),
            proxyPort: Number(fd.get('proxyPort') || preset.windowsOptions.mixedPort)
          })
        });
        toast(`测速完成，推荐：${res.benchmark.recommendedHop || '无'}`, res.benchmark.status === 'pass' ? 'ok' : 'info');
        await refresh();
      } catch (err) {
        toast(err.message, 'error');
      } finally {
        if (btn) { btn.disabled = false; btn.textContent = '⚡ 一键开始全链测速'; }
      }
    });
    bodyEl.querySelectorAll('[data-use-bench]').forEach(el => {
      el.addEventListener('click', () => patchBinding({ primaryFirstHop: el.dataset.useBench }, `已采用最快第一跳：${el.dataset.useBench}`));
    });
  }
}

// =========================================================
// 共用动作
// =========================================================
async function patchBinding(patch, msg) {
  try {
    await api('/api/binding', { method: 'PUT', body: JSON.stringify(patch) });
    ui.dirty = true;
    if (msg) toast(msg, 'ok');
    await refresh(true);
  } catch (err) { toast(err.message, 'error'); }
}

async function patchRules(patch, msg) {
  try {
    await api('/api/rules', { method: 'PUT', body: JSON.stringify(patch) });
    ui.dirty = true;
    if (msg) toast(msg, 'ok');
    await refresh(true);
  } catch (err) { toast(err.message, 'error'); }
}

async function runImportClashVerge() {
  try {
    toast('正在只读扫描本机 Clash Verge 全部配置...');
    const res = await api('/api/subscriptions/import-clash-verge', { method: 'POST' });
    ui.dirty = true;
    const extra = res.controllerDetected ? ' · 控制器已自动就绪' : '';
    toast(`已导入 ${res.importedSubscription} (${res.nodeCount} 节点)${res.importedExit ? ' + 静态出口 + 端口配置' : ''}${extra}`, 'ok');
    await refresh(true);
  } catch (err) { toast(err.message, 'error'); }
}

async function runWindowsProbe() {
  const btn = document.getElementById('btnQuickProbe');
  if (btn?.disabled) return;
  if (btn) { btn.disabled = true; btn.textContent = '探测中...'; }
  try {
    toast('正在探测 Windows 7897 / 17902 实际出口...');
    const res = await api('/api/probe/windows', { method: 'POST', body: JSON.stringify({ samples: 3 }) });
    toast(`探测结果：${res.probe.ruleProbe?.message || res.probe.status}`, res.probe.status === 'pass' ? 'ok' : 'error');
    await refresh();
  } catch (err) {
    toast(err.message, 'error');
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = '测出口'; }
  }
}

async function openApplyModal() {
  const modal = document.getElementById('applyBackdrop');
  const body = document.getElementById('applyBody');
  modal.classList.remove('hidden');
  body.innerHTML = '<div class="loading-state" style="padding:30px 0;">正在校验双端配置...</div>';
  try {
    const prev = await api('/api/preview');
    ui.preview = prev;
    document.getElementById('applySubtitle').textContent = `统一版本号：${prev.versionId}`;
    document.getElementById('btnConfirmApply').disabled = !prev.valid;

    if (!prev.valid) {
      body.innerHTML = `<div class="banner-inner danger"><span><strong>校验未通过：</strong>${esc(prev.validation.errors.join('；'))}</span></div>`;
      return;
    }

    body.innerHTML = `
      <div class="split-3">
        <div class="visual-card">
          <span class="tag tag-chain">Windows</span>
          <strong>Script.js</strong>
          <div class="sub-text">第一跳：${esc(prev.windows.summary.firstHops[0] || '-')}</div>
          <div class="sub-text mono">预期 ${esc(prev.windows.summary.expectedIp)}</div>
        </div>
        <div class="visual-card">
          <span class="tag tag-direct">手机日常版</span>
          <strong>Daily-Static-Chain</strong>
          <div class="sub-text">${prev.android.daily.ruleCount} 条规则 · 浏览器分流</div>
          <div class="sub-text">保留 GoLogin :${prev.android.daily.dedicatedListenerPort}</div>
        </div>
        <div class="visual-card">
          <span class="tag tag-chain">手机专用版</span>
          <strong>Claude-GoLogin-Static</strong>
          <div class="sub-text">${prev.android.dedicated.ruleCount} 条规则 · 接管 ${prev.android.dedicated.browserOverridesCount} 浏览器</div>
          <div class="sub-text">全应用 UDP 拦截</div>
        </div>
      </div>
      <details>
        <summary style="cursor:pointer;font-size:12.5px;color:var(--ink-2);">展开查看 Windows Script.js 详细差异 (+${prev.windows.diff.added} / -${prev.windows.diff.removed} 行)</summary>
        <div class="code-box" style="margin-top:8px;">${renderDiffLines(prev.windows.diff)}</div>
      </details>
    `;
  } catch (err) {
    body.innerHTML = `<div class="banner-inner danger"><span>预览失败：${esc(err.message)}</span></div>`;
  }
}

async function switchTab(tab) {
  ui.tab = tab;
  renderTopChrome();
  renderMainView();
  if ((tab === 'rules' || tab === 'android') && !ui.preview) {
    api('/api/preview').then(prev => {
      ui.preview = prev;
      if (ui.tab === tab) renderMainView();
    }).catch(() => {});
  }
  if (tab === 'hygiene' && !ui.hygieneCaches && !ui.hygieneAudit) {
    api('/api/hygiene/caches').then(c => {
      ui.hygieneCaches = c;
      if (ui.tab === 'hygiene') renderMainView();
    }).catch(() => {});
  }
}

function init() {
  if (localStorage.getItem('chain-studio-theme') === 'dark') {
    document.documentElement.dataset.theme = 'dark';
  }
  document.getElementById('brandHome').addEventListener('click', () => switchTab('canvas'));
  document.querySelectorAll('.seg-btn').forEach(b => b.addEventListener('click', () => switchTab(b.dataset.tab)));
  document.getElementById('btnToggleTheme').addEventListener('click', () => {
    const dark = document.documentElement.dataset.theme === 'dark';
    document.documentElement.dataset.theme = dark ? '' : 'dark';
    localStorage.setItem('chain-studio-theme', dark ? 'light' : 'dark');
  });
  document.getElementById('btnQuickProbe').addEventListener('click', () => runWindowsProbe());
  document.getElementById('btnOpenApply').addEventListener('click', () => openApplyModal());

  document.getElementById('btnCloseDrawer').addEventListener('click', closeDrawer);
  document.getElementById('drawerBackdrop').addEventListener('click', (e) => {
    if (e.target.id === 'drawerBackdrop') closeDrawer();
  });

  const closeApply = () => document.getElementById('applyBackdrop').classList.add('hidden');
  document.getElementById('btnCloseApply').addEventListener('click', closeApply);
  document.getElementById('btnCancelApply').addEventListener('click', closeApply);
  document.getElementById('applyBackdrop').addEventListener('click', (e) => {
    if (e.target.id === 'applyBackdrop') closeApply();
  });

  document.getElementById('btnConfirmApply').addEventListener('click', async () => {
    const btn = document.getElementById('btnConfirmApply');
    btn.disabled = true;
    try {
      const res = await api('/api/apply', {
        method: 'POST',
        body: JSON.stringify({
          applyToClashVerge: document.getElementById('chkApplyWin').checked,
          includeControllerInAndroid: document.getElementById('chkAndroidCtrl').checked
        })
      });
      ui.dirty = false;
      closeApply();
      toast(`${res.version.versionId} 已生成：${res.message}`, 'ok');
      await refresh(true);
    } catch (err) {
      toast(err.message, 'error');
    } finally {
      btn.disabled = false;
    }
  });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      closeDrawer();
      closeApply();
    }
  });

  refresh().catch(err => {
    document.getElementById('viewRoot').innerHTML = `<div class="banner-inner danger"><span>初始化失败：${esc(err.message)}</span></div>`;
  });
}

init();
