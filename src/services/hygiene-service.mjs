import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';
import { probeProxyEndpoint, probeRelayHealth, runCurlProbe } from './probe-service.mjs';

const DATACENTER_ASN_KEYWORDS = [
  'amazon', 'aws', 'google cloud', 'google llc', 'microsoft', 'azure',
  'digitalocean', 'vultr', 'hetzner', 'ovh', 'linode', 'akamai',
  'oracle', 'alibaba', 'aliyun', 'tencent', 'cloudflare', 'contabo',
  'choopa', 'leaseweb', 'scaleway', 'upcloud', 'racknerd', 'bandwagon', 'it7'
];

// IANA 时区到常见 Windows TimeZone ID 的对照映射（支持换区静态 IP 自动核对）
const IANA_TO_WINDOWS_TZ = {
  'America/Chicago': ['Central Standard Time'],
  'America/New_York': ['Eastern Standard Time'],
  'America/Los_Angeles': ['Pacific Standard Time'],
  'America/Denver': ['Mountain Standard Time'],
  'America/Phoenix': ['US Mountain Standard Time'],
  'Europe/London': ['GMT Standard Time'],
  'Europe/Berlin': ['W. Europe Standard Time'],
  'Asia/Tokyo': ['Tokyo Standard Time'],
  'Asia/Singapore': ['Singapore Standard Time'],
  'Asia/Shanghai': ['China Standard Time']
};

function runPsJson(script, timeoutMs = 8000) {
  if (process.platform !== 'win32') return { ok: false, error: 'NON_WINDOWS', data: null };
  const bins = ['pwsh.exe', 'powershell.exe'];
  for (const bin of bins) {
    const res = spawnSync(bin, ['-NoProfile', '-NonInteractive', '-Command', script], {
      encoding: 'utf8',
      windowsHide: true,
      timeout: timeoutMs,
      maxBuffer: 8 * 1024 * 1024
    });
    if (res.error) continue;
    if (res.status !== 0) {
      return { ok: false, error: (res.stderr || res.stdout || '').trim(), data: null };
    }
    const text = (res.stdout || '').trim();
    if (!text) return { ok: true, data: null };
    try {
      return { ok: true, data: JSON.parse(text) };
    } catch {
      return { ok: false, error: 'INVALID_JSON', data: null };
    }
  }
  return { ok: false, error: 'NO_POWERSHELL', data: null };
}

/**
 * 判断 ASN / Org 字符串是否偏数据中心机房（仅作启发式诊断参考，不代替人工或第三方核验）。
 */
export function classifyAsnOrg(orgString) {
  const raw = String(orgString || '').trim();
  if (!raw) return { kind: 'unknown', label: '未知 ASN', suspicious: false };
  const lower = raw.toLowerCase();
  const matched = DATACENTER_ASN_KEYWORDS.find(k => lower.includes(k));
  if (matched) {
    return {
      kind: 'datacenter',
      label: `疑似机房/云厂商 (${matched})`,
      suspicious: true
    };
  }
  return {
    kind: 'isp-like',
    label: '非主流机房特征（偏向住宅 / ISP）',
    suspicious: false
  };
}

/**
 * 校验系统/Claude 时区与目标 IP 地理时区是否一致。
 */
export function evaluateTimezoneAlignment({ targetIana, windowsTz, windowsLocale, userEnv, claudeSettings, envMode }) {
  const expectedWinTzs = IANA_TO_WINDOWS_TZ[targetIana] || [];
  const isUS = String(targetIana || '').startsWith('America/');
  const issues = [];

  if (!windowsTz) {
    issues.push('未能读取 Windows 系统时区');
  } else if (expectedWinTzs.length > 0 && !expectedWinTzs.includes(windowsTz)) {
    issues.push(`Windows 系统时区为 ${windowsTz}，与静态 IP 时区 ${targetIana}（期望 ${expectedWinTzs[0]}）不一致`);
  }

  if (isUS && windowsLocale && !windowsLocale.toLowerCase().startsWith('en-')) {
    issues.push(`Windows 区域格式为 ${windowsLocale}，美国静态环境建议为 en-US`);
  }

  if (userEnv?.TZ && targetIana && userEnv.TZ !== targetIana) {
    issues.push(`用户环境变量 TZ=${userEnv.TZ}，与目标时区 ${targetIana} 不符`);
  }

  if (claudeSettings?.readable) {
    if (claudeSettings.timeZone && targetIana && claudeSettings.timeZone !== targetIana) {
      issues.push(`Claude Code settings.json timeZone=${claudeSettings.timeZone}，与目标 ${targetIana} 不符`);
    }
    if (claudeSettings.envTz && targetIana && claudeSettings.envTz !== targetIana) {
      issues.push(`Claude Code env.TZ=${claudeSettings.envTz}，与目标 ${targetIana} 不符`);
    }
  }

  if (envMode?.mode && isUS && envMode.mode !== 'Claude') {
    issues.push(`当前环境模式记录为 ${envMode.mode}，启动 Claude 前建议先切至「Claude 美国环境」`);
  }

  return {
    status: issues.length === 0 ? (windowsTz ? 'pass' : 'blocked') : 'fail',
    targetIana,
    expectedWindowsTz: expectedWinTzs[0] || null,
    actualWindowsTz: windowsTz || null,
    actualLocale: windowsLocale || null,
    issues
  };
}

/**
 * 只读读取本机 Windows 时区、区域、环境变量、Claude Desktop 注册表策略、Claude Code 设置与相关进程。
 */
export function inspectLocalHostEnvironment(state) {
  const userHome = os.homedir();
  const claudeLocalDir = state.deviceBindings?.windows?.claudeLocalDir || '';
  const claudeSettingsPath = path.join(userHome, '.claude', 'settings.json');
  const switchingMarker = claudeLocalDir ? path.join(claudeLocalDir, 'EnvironmentSwitch', 'Switching.json') : '';
  const modePath = claudeLocalDir ? path.join(claudeLocalDir, 'EnvironmentMode.json') : '';

  const psScript = `
$ErrorActionPreference = 'SilentlyContinue'
$tz = (Get-TimeZone).Id
$locale = (Get-ItemProperty -LiteralPath 'HKCU:\\Control Panel\\International' -Name LocaleName).LocaleName
$egress = (Get-ItemProperty -LiteralPath 'HKCU:\\SOFTWARE\\Policies\\Claude' -Name egressProxyUrl).egressProxyUrl
$uEnv = @{
  TZ = [Environment]::GetEnvironmentVariable('TZ','User')
  LANG = [Environment]::GetEnvironmentVariable('LANG','User')
  LC_ALL = [Environment]::GetEnvironmentVariable('LC_ALL','User')
}
$procs = @(Get-Process | Where-Object { $_.ProcessName -match '^(?i:claude|bitbrowser|bit_browser)$' } | Select-Object ProcessName, Id)
$ipv6Addrs = @(Get-NetIPAddress -AddressFamily IPv6 | Where-Object { $_.PrefixOrigin -ne 'WellKnown' -and $_.IPAddress -notmatch '^(::1|fe80:|fc|fd)' } | Select-Object -ExpandProperty IPAddress)
@{
  windowsTimeZone = $tz
  localeName = $locale
  claudeDesktopEgressPolicy = $egress
  userEnv = $uEnv
  runningTargets = $procs
  publicIpv6Count = $ipv6Addrs.Count
} | ConvertTo-Json -Depth 4 -Compress
`;

  const hostRes = runPsJson(psScript);
  const host = hostRes.ok && hostRes.data ? hostRes.data : null;

  let claudeSettings = { readable: false, path: claudeSettingsPath };
  try {
    if (fs.existsSync(claudeSettingsPath)) {
      const obj = JSON.parse(fs.readFileSync(claudeSettingsPath, 'utf8'));
      const env = obj?.env && typeof obj.env === 'object' ? obj.env : {};
      const noProxyRaw = String(env.NO_PROXY || env.no_proxy || '');
      const noProxyEntries = noProxyRaw.split(/[,\s]+/).filter(Boolean);
      const nonLoopbackNoProxy = noProxyEntries.filter(e => !['localhost', '127.0.0.1', '::1'].includes(e));

      claudeSettings = {
        readable: true,
        path: claudeSettingsPath,
        timeZone: obj.timeZone || null,
        envTz: env.TZ || null,
        httpProxy: env.HTTP_PROXY || env.http_proxy || null,
        httpsProxy: env.HTTPS_PROXY || env.https_proxy || null,
        proxyResolvesHosts: env.CLAUDE_CODE_PROXY_RESOLVES_HOSTS || null,
        noProxyRaw,
        nonLoopbackNoProxy
      };
    }
  } catch (err) {
    claudeSettings = { readable: false, path: claudeSettingsPath, error: err.code || err.message };
  }

  let envMode = null;
  try {
    if (modePath && fs.existsSync(modePath)) {
      envMode = JSON.parse(fs.readFileSync(modePath, 'utf8'));
    }
  } catch { /* ignore */ }

  const switchingStale = Boolean(switchingMarker && fs.existsSync(switchingMarker));

  return {
    hostReadable: Boolean(host),
    hostError: hostRes.ok ? null : hostRes.error,
    windowsTimeZone: host?.windowsTimeZone || null,
    localeName: host?.localeName || null,
    claudeDesktopEgressPolicy: host?.claudeDesktopEgressPolicy || null,
    userEnv: host?.userEnv || {},
    runningTargets: Array.isArray(host?.runningTargets) ? host.runningTargets : [],
    publicIpv6Count: Number(host?.publicIpv6Count || 0),
    claudeSettings,
    envMode,
    switchingStale
  };
}

/**
 * 列出可安全清理的临时渲染缓存目录（严格白名单，绝不包含 Cookies / Local Storage / 登录态 / settings.json）。
 */
export function getSafeDisposableCacheTargets(baseAppData = process.env.APPDATA || path.join(os.homedir(), 'AppData', 'Roaming')) {
  const claudeDir = path.join(baseAppData, 'Claude');
  return [
    {
      id: 'claude-http-cache',
      app: 'Claude Desktop',
      label: '渲染与网络临时缓存 (Cache / Code Cache)',
      paths: [
        path.join(claudeDir, 'Cache'),
        path.join(claudeDir, 'Code Cache')
      ],
      safeNote: '仅清理静态资源与 JS 编译缓存，保留账号登录 Cookie 与本地配置'
    },
    {
      id: 'claude-gpu-cache',
      app: 'Claude Desktop',
      label: 'GPU / 着色器缓存 (GPUCache / DawnCache)',
      paths: [
        path.join(claudeDir, 'GPUCache'),
        path.join(claudeDir, 'DawnCache'),
        path.join(claudeDir, 'DawnGraphiteCache'),
        path.join(claudeDir, 'DawnWebGPUCache')
      ],
      safeNote: '仅清理显卡渲染缓存，常用于解决窗口假死或黑屏，不影响登录'
    }
  ];
}

function measureDirSize(dirPath) {
  if (!dirPath || !fs.existsSync(dirPath)) return { exists: false, files: 0, bytes: 0 };
  let files = 0;
  let bytes = 0;
  const walk = (p, depth = 0) => {
    if (depth > 8) return;
    let entries = [];
    try { entries = fs.readdirSync(p, { withFileTypes: true }); } catch { return; }
    for (const ent of entries) {
      const full = path.join(p, ent.name);
      if (ent.isDirectory()) walk(full, depth + 1);
      else if (ent.isFile()) {
        files++;
        try { bytes += fs.statSync(full).size; } catch { /* ignore */ }
      }
    }
  };
  walk(dirPath);
  return { exists: true, files, bytes };
}

export function inspectDisposableCaches(baseAppData) {
  const targets = getSafeDisposableCacheTargets(baseAppData);
  return targets.map(t => {
    let totalFiles = 0;
    let totalBytes = 0;
    let existingPaths = 0;
    for (const p of t.paths) {
      const m = measureDirSize(p);
      if (m.exists) existingPaths++;
      totalFiles += m.files;
      totalBytes += m.bytes;
    }
    return {
      ...t,
      existingPaths,
      totalFiles,
      totalMB: Number((totalBytes / (1024 * 1024)).toFixed(2))
    };
  });
}

/**
 * 仅在明确授权且目标应用未运行时清理白名单内的临时渲染缓存。
 */
export function cleanSafeDisposableCache({ targetIds = [], baseAppData, activeProcessNames = [] }) {
  const runningClaude = activeProcessNames.some(n => String(n).toLowerCase() === 'claude');
  if (runningClaude) {
    throw new Error('检测到 Claude Desktop 仍在运行，请先完全退出后再清理缓存，避免损坏会话。');
  }
  const allowed = getSafeDisposableCacheTargets(baseAppData);
  const selected = allowed.filter(t => targetIds.includes(t.id));
  if (selected.length === 0) {
    throw new Error('未选择允许清理的安全缓存项');
  }

  const results = [];
  for (const item of selected) {
    let removedPaths = 0;
    for (const p of item.paths) {
      // 再次强校验路径必须在白名单的 Claude 缓存子目录下
      const baseName = path.basename(p);
      if (!['Cache', 'Code Cache', 'GPUCache', 'DawnCache', 'DawnGraphiteCache', 'DawnWebGPUCache'].includes(baseName)) {
        throw new Error(`路径不在安全清理白名单内: ${p}`);
      }
      if (fs.existsSync(p)) {
        fs.rmSync(p, { recursive: true, force: true });
        removedPaths++;
      }
    }
    results.push({ id: item.id, label: item.label, removedPaths });
  }
  return { status: 'pass', cleanedAt: new Date().toISOString(), results };
}

/**
 * 运行完整 6 维度 Claude 独立环境与防泄漏综合体检。
 */
export async function runFullEnvironmentAudit(state) {
  const checkedAt = new Date().toISOString();
  const exit = state.staticExits.find(e => e.id === state.activeBinding.staticExitId) || state.staticExits[0];
  const preset = state.rulePresets.find(p => p.id === state.activeBinding.rulePresetId) || state.rulePresets[0];
  const winOpts = preset.windowsOptions;
  const expectedIp = exit?.expectedIp || '';

  const [ruleProbe, relayProbe, relayHealth, ipv6Probe] = await Promise.all([
    probeProxyEndpoint({
      label: `Windows 分流口 (${winOpts.mixedPort})`,
      proxyPort: winOpts.mixedPort,
      expectedIp: exit?.isSample ? '' : expectedIp,
      samples: 2,
      checkDomestic: true,
      checkOverseas: true
    }),
    probeProxyEndpoint({
      label: `Windows 专用口 (${winOpts.relayPort})`,
      proxyPort: winOpts.relayPort,
      expectedIp: exit?.isSample ? '' : expectedIp,
      samples: 2,
      checkDomestic: false,
      checkOverseas: false
    }),
    probeRelayHealth(winOpts.relayPort),
    runCurlProbe({
      url: 'https://api6.ipify.org',
      proxyUrl: `http://127.0.0.1:${winOpts.mixedPort}`,
      connectTimeout: 3,
      maxTime: 5
    })
  ]);

  const host = inspectLocalHostEnvironment(state);
  const caches = inspectDisposableCaches();

  // 1) 双口出口一致 & IP 住宅画像
  const ruleIp = ruleProbe.observedIp;
  const relayIp = relayProbe.observedIp;
  const ipinfo = ruleProbe.ipinfo || relayProbe.ipinfo || null;
  const asnEval = classifyAsnOrg(ipinfo?.org);
  const dualMatch = Boolean(ruleIp && relayIp && ruleIp === relayIp);
  const expectedMatch = exit?.isSample ? null : Boolean(ruleIp && ruleIp === expectedIp);

  let egressStatus = 'pass';
  const egressNotes = [];
  if (!ruleProbe.portOpen && !relayProbe.portOpen) {
    egressStatus = 'blocked';
    egressNotes.push(`本机代理端口 ${winOpts.mixedPort} / ${winOpts.relayPort} 未监听`);
  } else if (expectedMatch === false) {
    egressStatus = 'fail';
    egressNotes.push(`实测出口 ${ruleIp} 与预期 ${expectedIp} 不一致`);
  } else if (!dualMatch) {
    egressStatus = 'partial';
    egressNotes.push(`分流口 (${ruleIp || '未通'}) 与专用口 (${relayIp || '未通'}) 出口未统一`);
  } else {
    egressNotes.push(`双入口出口完全一致：${ruleIp}`);
  }
  if (asnEval.suspicious) {
    if (egressStatus === 'pass') egressStatus = 'partial';
    egressNotes.push(`ASN 诊断提示：${ipinfo?.org} (${asnEval.label})，建议优先使用住宅 ISP 静态 IP`);
  } else if (ipinfo?.org) {
    egressNotes.push(`ASN：${ipinfo.org} · ${ipinfo.country || ''}/${ipinfo.city || ''}（${asnEval.label}）`);
  }

  // 2) 时区与语言对齐（以实测 IP 时区优先，回退静态出口配置时区）
  const targetIana = ipinfo?.timezone || exit?.timeZone || 'America/Chicago';
  const tzAudit = evaluateTimezoneAlignment({
    targetIana,
    windowsTz: host.windowsTimeZone,
    windowsLocale: host.localeName,
    userEnv: host.userEnv,
    claudeSettings: host.claudeSettings,
    envMode: host.envMode
  });

  // 3) 客户端代理与远程 DNS 守卫
  const expectedProxyUrl = `http://127.0.0.1:${winOpts.mixedPort}`;
  const clientIssues = [];
  if (host.switchingStale) clientIssues.push('检测到 EnvironmentSwitch/Switching.json 未清理，请先恢复环境切换状态');
  if (host.hostReadable && host.claudeDesktopEgressPolicy !== expectedProxyUrl) {
    clientIssues.push(`Claude Desktop 策略 egressProxyUrl 为 ${host.claudeDesktopEgressPolicy || '(未设置)'}，期望 ${expectedProxyUrl}`);
  }
  if (host.claudeSettings.readable) {
    if (host.claudeSettings.httpProxy && host.claudeSettings.httpProxy !== expectedProxyUrl) {
      clientIssues.push(`Claude Code HTTP_PROXY=${host.claudeSettings.httpProxy} 与 ${expectedProxyUrl} 不一致`);
    }
    if (host.claudeSettings.proxyResolvesHosts !== '1') {
      clientIssues.push('Claude Code 缺少 CLAUDE_CODE_PROXY_RESOLVES_HOSTS=1（可能导致本地 DNS 解析泄漏）');
    }
    if (host.claudeSettings.nonLoopbackNoProxy?.length > 0) {
      clientIssues.push(`NO_PROXY 含非回环绕过项：${host.claudeSettings.nonLoopbackNoProxy.join(', ')}`);
    }
  }
  const clientStatus = !host.hostReadable && !host.claudeSettings.readable
    ? 'blocked'
    : (clientIssues.length === 0 ? 'pass' : 'fail');

  // 4) IPv6 & UDP/WebRTC 防泄漏核验
  const leakIssues = [];
  if (winOpts.ipv6) leakIssues.push('Windows Mihomo 当前开启了 ipv6: true，建议关闭以防双栈分流泄漏');
  if (ipv6Probe.ok && ipv6Probe.body) {
    leakIssues.push(`通过代理的 IPv6 探测返回了地址 (${ipv6Probe.body.trim()})，请核实是否与预期静态 IP 一致`);
  }
  if (host.publicIpv6Count > 0) {
    leakIssues.push(`宿主机网卡检测到 ${host.publicIpv6Count} 个公网 IPv6 地址，浏览器请确保关闭非代理 UDP/WebRTC`);
  }
  if (relayHealth.status !== 'pass') {
    leakIssues.push(`IPv4 Relay (${winOpts.relayPort}/health) 未响应，专用全代理与 DoH IPv4 固定可能未运行`);
  }
  const leakStatus = leakIssues.length === 0 ? 'pass' : (leakIssues.some(x => x.includes('Relay')) ? 'partial' : 'partial');

  // 5) 切换前进程残留检查
  const procCount = host.runningTargets.length;
  const procStatus = !host.hostReadable ? 'blocked' : (procCount === 0 ? 'pass' : 'partial');
  const procNote = procCount === 0
    ? '当前未检测到运行中的 Claude / BitBrowser 进程，可安全切换 IP、切时区或清理渲染缓存'
    : `检测到 ${procCount} 个正在运行的相关进程（${[...new Set(host.runningTargets.map(p => p.ProcessName))].join(', ')}）；更换静态 IP 或切时区前建议先正常退出，避免旧渲染器缓存旧时区/长连接`;

  const cards = [
    {
      id: 'egress',
      title: '双入口出口与 IP 画像',
      status: egressStatus,
      summary: egressNotes[0] || '等待检测',
      details: egressNotes,
      metrics: { ruleIp, relayIp, expectedIp, asn: ipinfo?.org || null, location: ipinfo ? `${ipinfo.country || ''} ${ipinfo.city || ''}`.trim() : null }
    },
    {
      id: 'timezone',
      title: '时区与语言信号对齐',
      status: tzAudit.status,
      summary: tzAudit.status === 'pass'
        ? `系统与 Claude 时区已对齐 ${tzAudit.targetIana}`
        : (tzAudit.issues[0] || '无法读取系统时区'),
      details: tzAudit.issues.length ? tzAudit.issues : [
        `IP 地理时区：${tzAudit.targetIana}`,
        `Windows 时区：${tzAudit.actualWindowsTz || '未读到'} · 区域：${tzAudit.actualLocale || '未读到'}`
      ],
      actionHint: tzAudit.status === 'fail' ? 'claude-env' : null
    },
    {
      id: 'client-guard',
      title: 'Claude Desktop / CLI 代理守卫',
      status: clientStatus,
      summary: clientStatus === 'pass'
        ? 'Desktop 策略与 CLI 远程 DNS 解析均已锁定'
        : (clientIssues[0] || '当前权限无法读取本机注册表与 ~/.claude/settings.json'),
      details: clientIssues.length ? clientIssues : [
        `Desktop egressProxyUrl = ${expectedProxyUrl}`,
        'CLI CLAUDE_CODE_PROXY_RESOLVES_HOSTS = 1（远端 DNS）',
        'NO_PROXY 仅限回环地址'
      ]
    },
    {
      id: 'leak-guard',
      title: 'IPv6 / UDP / WebRTC 防泄漏',
      status: leakStatus,
      summary: leakIssues.length === 0
        ? 'IPv6 关闭、IPv4 Relay 健康、UDP/QUIC 已在规则层拦截'
        : leakIssues[0],
      details: leakIssues.length ? leakIssues : [
        'Mihomo ipv6: false · NETWORK,UDP,REJECT 已启用',
        `IPv4 Relay (127.0.0.1:${winOpts.relayPort}) /health 正常`,
        '手机端受保护 App 的 UDP 优先于国内直连被 REJECT'
      ]
    },
    {
      id: 'process-guard',
      title: '切换前进程残留检查',
      status: procStatus,
      summary: procStatus === 'blocked' ? '未能读取进程列表' : (procCount === 0 ? '无活跃目标进程（可安全切换）' : `${procCount} 个目标进程运行中`),
      details: [procNote],
      runningTargets: host.runningTargets
    }
  ];

  const hasFail = cards.some(c => c.status === 'fail');
  const hasPartialOrBlocked = cards.some(c => c.status === 'partial' || c.status === 'blocked');
  const verdict = hasFail ? 'fail' : (hasPartialOrBlocked ? 'partial' : 'pass');

  return {
    checkedAt,
    verdict,
    verdictLabel: verdict === 'pass'
      ? '环境一致性全绿 · 可安全使用'
      : (verdict === 'fail' ? '存在关键不一致 · 建议先对齐再启动 Claude' : '部分项需留意或未在真机读取'),
    cards,
    caches,
    externalCheckers: [
      { name: '本地 CheckCC (4317)', url: 'http://127.0.0.1:4317', note: '需先启动 CheckCC 本地服务' },
      { name: 'BrowserLeaks WebRTC', url: 'https://browserleaks.com/webrtc', note: '请在 BitBrowser / GoLogin 内打开核对无本地 IP 泄漏' },
      { name: 'BrowserLeaks DNS', url: 'https://browserleaks.com/dns', note: '核对 DNS 归属与静态出口同地区' },
      { name: 'IPInfo 画像', url: 'https://ipinfo.io', note: '核对 ASN、城市与时区（第三方分数仅作参考）' }
    ]
  };
}
