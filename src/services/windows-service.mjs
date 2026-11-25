import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { parseYaml } from '../core/yaml-bridge.mjs';
import { writeFileAtomic } from '../core/vault.mjs';
import { normalizeSubscriptionProxies } from '../core/rule-engine.mjs';
import {
  computeUnifiedDiff,
  generateAndroidProfiles,
  generateDesktopStandaloneYaml,
  generateSharedRuntimeConfig,
  generateWindowsScript,
  validateCandidate
} from '../core/generators.mjs';
import { callMihomoApi, checkTcpPortOpen, probeRelayHealth } from './probe-service.mjs';

function listWindowsMihomoPipes() {
  if (process.platform !== 'win32') return [];
  const res = spawnSync(
    'pwsh.exe',
    ['-NoProfile', '-NonInteractive', '-Command', "[IO.Directory]::GetFiles('\\\\.\\pipe\\') | Where-Object { $_ -match 'verge-mihomo|mihomo' } | ConvertTo-Json -Compress"],
    { encoding: 'utf8', windowsHide: true, timeout: 3000 }
  );
  if (res.error || res.status !== 0 || !res.stdout?.trim()) return [];
  try {
    const parsed = JSON.parse(res.stdout.trim());
    return Array.isArray(parsed) ? parsed : (typeof parsed === 'string' ? [parsed] : []);
  } catch {
    return [];
  }
}

/**
 * 自动发现本机正在运行的 Clash Verge Rev / Mihomo Controller（支持 Windows Named Pipe、Unix Socket 与 TCP）。
 * 优先兼容 Clash Verge Rev 2.x Service Mode（-sidecar-release- 与 -production- 管道自动匹配）。
 */
export async function discoverClashVergeController(clashVergeDir) {
  const genRead = safeReadFile(path.join(clashVergeDir || '', 'clash-verge.yaml'));
  let secret = '';
  let cfgPipe = '';
  let cfgUnix = '';
  let cfgTcp = '';

  if (genRead.readable) {
    try {
      const doc = parseYaml(genRead.content);
      secret = String(doc?.secret || '').trim();
      cfgPipe = String(doc?.['external-controller-pipe'] || '').trim();
      cfgUnix = String(doc?.['external-controller-unix'] || '').trim();
      cfgTcp = String(doc?.['external-controller'] || '').trim();
    } catch { /* ignore */ }
  }

  const candidates = [];
  const seen = new Set();
  const addCandidate = (cand) => {
    const key = `${cand.transport}:${cand.socketPath || cand.controllerUrl}`;
    if (!seen.has(key)) {
      seen.add(key);
      candidates.push(cand);
    }
  };

  const tryCandidate = async (cand) => {
    try {
      const ver = await callMihomoApi({
        controllerUrl: cand.controllerUrl || '',
        socketPath: cand.socketPath || '',
        secret,
        apiPath: '/version',
        timeoutMs: 1200
      });
      if (ver && typeof ver === 'object') {
        return {
          detected: true,
          transport: cand.transport,
          socketPath: cand.socketPath || '',
          controllerUrl: cand.controllerUrl || '',
          secret,
          hasSecret: Boolean(secret),
          label: cand.label,
          coreVersion: ver.version || ''
        };
      }
    } catch { /* try next */ }
    return null;
  };

  // 第一阶段：优先探测无需 PowerShell 扫描的直连候选（<10ms 极速命中）
  if (process.platform === 'win32' && cfgPipe) {
    if (cfgPipe.includes('-sidecar-release-')) {
      addCandidate({
        transport: 'pipe',
        socketPath: cfgPipe.replace('-sidecar-release-', '-production-'),
        label: 'Clash Verge Service Pipe (自动识别)'
      });
    }
    addCandidate({ transport: 'pipe', socketPath: cfgPipe, label: 'Clash Verge Pipe (自动识别)' });
  } else if (process.platform !== 'win32' && cfgUnix && fs.existsSync(cfgUnix)) {
    addCandidate({ transport: 'unix', socketPath: cfgUnix, label: 'Clash Verge Unix Socket (自动识别)' });
  }

  if (cfgTcp) {
    const normalizedTcp = cfgTcp.startsWith('http') ? cfgTcp : `http://${cfgTcp.replace(/^:/, '127.0.0.1:')}`;
    addCandidate({ transport: 'tcp', controllerUrl: normalizedTcp, label: `Clash Controller (${normalizedTcp})` });
  }

  for (const cand of candidates) {
    const hit = await tryCandidate(cand);
    if (hit) return hit;
  }

  // 第二阶段：直连未命中时再动态枚举本机存活管道与默认 TCP 端口
  const fallbackCandidates = [];
  if (process.platform === 'win32') {
    for (const p of listWindowsMihomoPipes()) {
      const key = `pipe:${p}`;
      if (!seen.has(key)) {
        seen.add(key);
        fallbackCandidates.push({ transport: 'pipe', socketPath: p, label: 'Clash Verge Named Pipe (自动识别)' });
      }
    }
  }
  fallbackCandidates.push(
    { transport: 'tcp', controllerUrl: 'http://127.0.0.1:9097', label: 'Mihomo TCP (127.0.0.1:9097)' },
    { transport: 'tcp', controllerUrl: 'http://127.0.0.1:9090', label: 'Mihomo TCP (127.0.0.1:9090)' }
  );

  for (const cand of fallbackCandidates) {
    const hit = await tryCandidate(cand);
    if (hit) return hit;
  }

  return {
    detected: false,
    transport: null,
    socketPath: '',
    controllerUrl: '',
    secret: '',
    hasSecret: Boolean(secret),
    label: '未检测到运行中的 Mihomo Controller'
  };
}

function sha256(text) {
  return crypto.createHash('sha256').update(text, 'utf8').digest('hex');
}

function safeReadFile(filePath) {
  try {
    if (!filePath || !fs.existsSync(filePath)) return { exists: false, readable: false, content: null };
    return { exists: true, readable: true, content: fs.readFileSync(filePath, 'utf8') };
  } catch (err) {
    return { exists: true, readable: false, content: null, error: err.code || err.message };
  }
}

/**
 * 只读检查本机 Windows Clash Verge、端口、IPv4 Relay 与四个启动入口状态。
 */
export async function inspectWindowsEnvironment(state) {
  const winBind = state.deviceBindings.windows;
  const preset = state.rulePresets.find(p => p.id === state.activeBinding.rulePresetId) || state.rulePresets[0];
  const winOpts = preset.windowsOptions;

  const clashDir = winBind.clashVergeDir;
  const profilesYaml = safeReadFile(path.join(clashDir, 'profiles.yaml'));
  const scriptJs = safeReadFile(path.join(clashDir, 'profiles', 'Script.js'));
  const vergeYaml = safeReadFile(path.join(clashDir, 'verge.yaml'));
  const generatedYaml = safeReadFile(path.join(clashDir, 'clash-verge.yaml'));

  let activeProfileName = null;
  let activeProfileFile = null;
  if (profilesYaml.readable) {
    try {
      const parsed = parseYaml(profilesYaml.content);
      const currentUid = parsed?.current;
      const items = Array.isArray(parsed?.items) ? parsed.items : [];
      const current = items.find(i => i.uid === currentUid);
      if (current) {
        activeProfileName = current.name || current.uid;
        activeProfileFile = current.file || null;
      }
    } catch { /* ignore */ }
  }

  let vergeSummary = null;
  if (vergeYaml.readable) {
    try {
      const v = parseYaml(vergeYaml.content);
      vergeSummary = {
        enableSystemProxy: Boolean(v?.enable_system_proxy),
        enableProxyGuard: Boolean(v?.enable_proxy_guard),
        enableTunMode: Boolean(v?.enable_tun_mode)
      };
    } catch { /* ignore */ }
  }

  let envMode = null;
  const modeFile = safeReadFile(path.join(winBind.claudeLocalDir || '', 'EnvironmentMode.json'));
  if (modeFile.readable) {
    try { envMode = JSON.parse(modeFile.content); } catch { /* ignore */ }
  }

  const [rulePort, upstreamPort, relayPort, relayHealth, controller] = await Promise.all([
    checkTcpPortOpen(winOpts.mixedPort),
    checkTcpPortOpen(winOpts.upstreamPort),
    checkTcpPortOpen(winOpts.relayPort),
    probeRelayHealth(winOpts.relayPort),
    discoverClashVergeController(clashDir)
  ]);

  let liveFirstHopNow = null;
  let liveCandidatesCount = 0;
  if (controller.detected) {
    try {
      const grp = await callMihomoApi({
        controllerUrl: controller.controllerUrl,
        socketPath: controller.socketPath,
        secret: controller.secret,
        apiPath: `/proxies/${encodeURIComponent(winOpts.firstHopGroupName || 'Static-First-Hop')}`,
        timeoutMs: 1500
      });
      if (grp) {
        liveFirstHopNow = grp.now || null;
        liveCandidatesCount = Array.isArray(grp.all) ? grp.all.filter(x => x !== 'DIRECT' && x !== 'REJECT').length : 0;
      }
    } catch { /* ignore */ }
  }

  const resolveShortcutPath = (customDir, customFile, bundledFile) => {
    const custom = customDir ? path.join(customDir, customFile) : '';
    if (custom && fs.existsSync(custom)) return { path: custom, source: 'custom', exists: true };
    const bundled = path.resolve(path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1')), '..', '..', 'runtime', bundledFile);
    return { path: bundled, source: 'bundled', exists: fs.existsSync(bundled) };
  };

  const envSwitch = resolveShortcutPath(winBind.claudeEnvScriptsDir, 'Switch-ClaudeEnvironment.ps1', 'Switch-RegionEnvironment.ps1');
  const staticGuard = resolveShortcutPath(winBind.claudeLocalDir, 'Start-Claude-Static.cjs', 'Start-ClaudeStaticGuard.cjs');

  const shortcuts = [
    {
      id: 'claude-env',
      label: '代理地区环境',
      desc: '按静态出口时区与语言切换',
      scriptPath: envSwitch.path,
      source: envSwitch.source,
      exists: envSwitch.exists
    },
    {
      id: 'china-env',
      label: '本地日常环境',
      desc: '切回本地时区 · 切换前检查退出',
      scriptPath: envSwitch.path,
      source: envSwitch.source,
      exists: envSwitch.exists
    },
    {
      id: 'claude-desktop',
      label: 'Claude Desktop - Static IP',
      desc: '校验静态出口后启动桌面版',
      scriptPath: staticGuard.path,
      source: staticGuard.source,
      exists: staticGuard.exists
    },
    {
      id: 'claude-code',
      label: 'Claude Code - Static IP',
      desc: '校验静态出口 + 仅回环 NO_PROXY',
      scriptPath: staticGuard.path,
      source: staticGuard.source,
      exists: staticGuard.exists
    }
  ];

  return {
    checkedAt: new Date().toISOString(),
    clashVerge: {
      dir: clashDir,
      accessible: profilesYaml.readable || scriptJs.readable || generatedYaml.readable,
      accessError: profilesYaml.error || scriptJs.error || null,
      activeProfileName,
      activeProfileFile,
      hasScriptJs: scriptJs.readable,
      vergeSummary
    },
    ports: {
      mixed: rulePort,
      upstream: upstreamPort,
      relay: relayPort
    },
    controller: {
      detected: controller.detected,
      transport: controller.transport,
      label: controller.label,
      hasSecret: controller.hasSecret,
      coreVersion: controller.coreVersion || '',
      liveFirstHopNow,
      liveCandidatesCount
    },
    relayHealth,
    environmentMode: envMode,
    shortcuts
  };
}

/**
 * 只读读取本机 Clash Verge Rev 的活动订阅与已有静态出口，将其导入工作台（凭据直接入本地加密库）。
 */
export function importFromLocalClashVerge(state, vault, nextIdFn) {
  const clashDir = state.deviceBindings.windows.clashVergeDir;
  const profilesFile = path.join(clashDir, 'profiles.yaml');
  const readProfiles = safeReadFile(profilesFile);
  if (!readProfiles.readable) {
    throw new Error(`无法读取 Clash Verge 配置目录 (${profilesFile}): ${readProfiles.error || '文件不存在或无访问权限'}`);
  }

  const profilesDoc = parseYaml(readProfiles.content);
  const items = Array.isArray(profilesDoc?.items) ? profilesDoc.items : [];
  const activeItem = items.find(i => i.uid === profilesDoc?.current) || items.find(i => i.type === 'remote' || i.type === 'local');
  if (!activeItem || !activeItem.file) {
    throw new Error('在 profiles.yaml 中未找到当前活动订阅文件');
  }

  const subPath = path.join(clashDir, 'profiles', activeItem.file);
  const subRead = safeReadFile(subPath);
  if (!subRead.readable) {
    throw new Error(`无法读取活动订阅文件 (${subPath}): ${subRead.error || '不存在'}`);
  }

  const subDoc = parseYaml(subRead.content);
  const normalized = normalizeSubscriptionProxies(subDoc.proxies || []);
  const subId = nextIdFn('sub');
  let urlRef = null;
  if (activeItem.url) {
    urlRef = `url-${subId}`;
    vault.setSecret(urlRef, { url: activeItem.url });
  }

  const subscription = {
    id: subId,
    name: activeItem.name || path.basename(activeItem.file, '.yaml'),
    provider: '从本机 Clash Verge 导入',
    sourceType: 'clash-verge',
    sourceFile: activeItem.file,
    urlRef,
    priceNote: '已从本机 Clash Verge 导入',
    trafficInfo: activeItem.extra
      ? `已用 ${(((activeItem.extra.upload || 0) + (activeItem.extra.download || 0)) / (1024 ** 3)).toFixed(1)} GB / ${((activeItem.extra.total || 0) / (1024 ** 3)).toFixed(1)} GB`
      : '本机快照',
    updatedAt: new Date().toISOString(),
    nodes: normalized.nodes,
    filteredOut: normalized.filteredOut,
    rawRules: Array.isArray(subDoc.rules) ? subDoc.rules : [],
    nodeDomains: normalized.nodeDomainPatterns,
    isSample: false
  };

  // 尝试从 clash-verge.yaml 或 profiles/Script.js 提取已存在的静态末跳、第一跳组与全部核心选项
  let importedExit = null;
  let discoveredHops = [];
  let rawNode = null;
  const importedWindowsOptions = {};

  const genRead = safeReadFile(path.join(clashDir, 'clash-verge.yaml'));
  if (genRead.readable) {
    try {
      const genDoc = parseYaml(genRead.content);
      const genProxies = Array.isArray(genDoc.proxies) ? genDoc.proxies : [];
      const genGroups = Array.isArray(genDoc['proxy-groups']) ? genDoc['proxy-groups'] : [];
      const genListeners = Array.isArray(genDoc.listeners) ? genDoc.listeners : [];

      if (Number.isInteger(genDoc['mixed-port'])) importedWindowsOptions.mixedPort = genDoc['mixed-port'];
      if (typeof genDoc.ipv6 === 'boolean') importedWindowsOptions.ipv6 = genDoc.ipv6;
      if (typeof genDoc['allow-lan'] === 'boolean') importedWindowsOptions.allowLan = genDoc['allow-lan'];
      if (genDoc.tun && typeof genDoc.tun.enable === 'boolean') importedWindowsOptions.tunEnable = genDoc.tun.enable;
      if (genDoc.dns?.listen) importedWindowsOptions.dnsListen = String(genDoc.dns.listen);
      if (Array.isArray(genDoc.dns?.['direct-nameserver']) && genDoc.dns['direct-nameserver'].length) {
        importedWindowsOptions.domesticDns = genDoc.dns['direct-nameserver'].map(String);
      }

      const firstGroup = genGroups.find(g => g.name === 'Static-First-Hop');
      if (firstGroup && Array.isArray(firstGroup.proxies)) {
        importedWindowsOptions.firstHopGroupName = firstGroup.name;
        const validSet = new Set(normalized.nodes.map(n => n.name));
        discoveredHops = firstGroup.proxies.filter(n => validSet.has(n));
      }

      rawNode = genProxies.find(p => p['dialer-proxy'] === 'Static-First-Hop' && (p.type === 'http' || p.type === 'socks5'))
        || genProxies.find(p => p.name === 'NodeMaven-US-HTTP' || p.name === 'Static-Exit-Raw');
      if (rawNode?.name) importedWindowsOptions.rawProxyName = rawNode.name;

      // 识别本地 IPv4 Relay 前端代理节点（127.0.0.1:17902 等）
      const frontendNode = genProxies.find(p =>
        p.type === 'http' && p.server === '127.0.0.1' && Number(p.port) !== Number(genDoc['mixed-port']) &&
        (p.name === 'NodeMaven-US-Chain' || p.name === 'Static-Exit-Chain' || Number(p.port) === 17902)
      );
      if (frontendNode) {
        importedWindowsOptions.frontendProxyName = frontendNode.name;
        importedWindowsOptions.relayPort = Number(frontendNode.port);
      }

      // 识别上游 listener（127.0.0.1:17901 等）
      const upstreamListener = genListeners.find(l => l.proxy === rawNode?.name || Number(l.port) === 17901);
      if (upstreamListener) {
        importedWindowsOptions.upstreamListenerName = upstreamListener.name;
        importedWindowsOptions.upstreamPort = Number(upstreamListener.port);
      }
    } catch { /* ignore */ }
  }

  // 若 clash-verge.yaml 未提取到，回退解析 profiles/Script.js 中的 rawProxy
  if (!rawNode) {
    const scriptRead = safeReadFile(path.join(clashDir, 'profiles', 'Script.js'));
    if (scriptRead.readable) {
      const m = /const\s+rawProxy\s*=\s*(\{[\s\S]*?\});/.exec(scriptRead.content);
      if (m) {
        try { rawNode = JSON.parse(m[1]); } catch { /* ignore */ }
      }
    }
  }

  if (rawNode && rawNode.server) {
    const exitId = nextIdFn('exit');
    const credRef = `cred-${exitId}`;
    if (rawNode.username || rawNode.password) {
      vault.setSecret(credRef, { username: rawNode.username || '', password: rawNode.password || '' });
    }
    const lastWinProbe = (state.probeHistory || []).find(p => p.target === 'windows' && p.ruleProbe?.observedIp);
    const observedIp = lastWinProbe?.ruleProbe?.observedIp || '';
    const info = lastWinProbe?.ruleProbe?.ipinfo;
    const detectedRegion = info?.country && info?.city ? `${info.country} / ${info.city}` : 'US / 待核实';

    importedExit = {
      id: exitId,
      name: `${rawNode.name || 'Static-Exit'} (本机导入)`,
      provider: '本机 Clash Verge 导入',
      server: String(rawNode.server || ''),
      port: Number(rawNode.port || 5432),
      expectedIp: observedIp || String(rawNode.server || ''),
      region: detectedRegion,
      timeZone: info?.timezone || 'America/Chicago',
      windowsProtocol: rawNode.type === 'socks5' ? 'socks5' : 'http',
      androidProtocol: 'socks5',
      androidUdp: false,
      credentialRef: credRef,
      notes: observedIp && observedIp !== String(rawNode.server)
        ? `入口地址为 ${rawNode.server}，已按最近实测自动记录公网出口 IP ${observedIp}。`
        : '从本机 Clash Verge 自动导入；若代理入口与公网出口不同，可在「编辑」中分别维护。',
      isSample: false,
      updatedAt: new Date().toISOString()
    };
  }

  return { subscription, importedExit, discoveredHops, importedWindowsOptions };
}

/**
 * 生成候选预览与 Diff（完全不修改任何本机正式文件）。
 */
export function buildCandidatePreview(state, vault, versionId, overrides = {}) {
  const validation = validateCandidate(state, vault, overrides);
  if (!validation.valid) {
    return {
      valid: false,
      validation,
      versionId,
      windows: null,
      android: null,
      sharedRuntime: null
    };
  }

  const winArtifact = generateWindowsScript(state, vault, versionId, overrides);
  const androidArtifacts = generateAndroidProfiles(state, vault, versionId, overrides);
  const sharedRuntime = generateSharedRuntimeConfig(state, versionId, overrides);

  // 对比现有本机 Script.js（如果可读）
  const clashScriptPath = path.join(state.deviceBindings.windows.clashVergeDir, 'profiles', 'Script.js');
  const existingScript = safeReadFile(clashScriptPath);
  const redactedExisting = existingScript.readable ? vault.redactText(existingScript.content) : '';
  const windowsDiff = computeUnifiedDiff(redactedExisting, winArtifact.redactedContent);

  // 对比 Android Daily vs Dedicated 差异（直观验证普通浏览器是否仅在专用配置中被接管）
  const androidVariantDiff = computeUnifiedDiff(
    androidArtifacts.daily.redactedYaml,
    androidArtifacts.dedicated.redactedYaml
  );

  return {
    valid: true,
    validation,
    versionId,
    windows: {
      filename: winArtifact.filename,
      redactedContent: winArtifact.redactedContent,
      summary: winArtifact.summary,
      existingReadable: existingScript.readable,
      diff: windowsDiff
    },
    android: {
      daily: {
        profileName: androidArtifacts.daily.profileName,
        filename: androidArtifacts.daily.filename,
        redactedYaml: androidArtifacts.daily.redactedYaml,
        ruleCount: androidArtifacts.daily.ruleCount,
        proxyCount: androidArtifacts.daily.proxyCount,
        browserOverridesCount: androidArtifacts.daily.browserOverridesCount,
        dedicatedListenerPort: androidArtifacts.daily.dedicatedListenerPort
      },
      dedicated: {
        profileName: androidArtifacts.dedicated.profileName,
        filename: androidArtifacts.dedicated.filename,
        redactedYaml: androidArtifacts.dedicated.redactedYaml,
        ruleCount: androidArtifacts.dedicated.ruleCount,
        proxyCount: androidArtifacts.dedicated.proxyCount,
        browserOverridesCount: androidArtifacts.dedicated.browserOverridesCount,
        dedicatedListenerPort: androidArtifacts.dedicated.dedicatedListenerPort
      },
      variantDiff: androidVariantDiff
    },
    sharedRuntime
  };
}

/**
 * 正式生成版本产物到 output/<versionId>/，并按用户勾选原子应用到 Windows Clash Verge（附带完整回滚快照）。
 */
export function commitAndApplyVersion({
  state,
  vault,
  projectRoot,
  versionId,
  applyToClashVerge = false,
  includeControllerInAndroid = false,
  note = ''
}) {
  const validation = validateCandidate(state, vault);
  if (!validation.valid) {
    throw new Error(`配置校验未通过：${validation.errors.join('；')}`);
  }

  const winArtifact = generateWindowsScript(state, vault, versionId);
  const desktopYamlArtifact = generateDesktopStandaloneYaml(state, vault, versionId);
  const androidArtifacts = generateAndroidProfiles(state, vault, versionId, {
    includeController: includeControllerInAndroid
  });
  const sharedRuntime = generateSharedRuntimeConfig(state, versionId);

  const versionDir = path.join(projectRoot, 'output', versionId);
  const latestDir = path.join(projectRoot, 'output', 'latest');
  fs.mkdirSync(versionDir, { recursive: true });
  fs.mkdirSync(latestDir, { recursive: true });

  const winOutPath = path.join(versionDir, 'Script.js');
  const desktopYamlOutPath = path.join(versionDir, 'Desktop-Static-Chain.yaml');
  const dailyOutPath = path.join(versionDir, 'Daily-Static-Chain.yaml');
  const dedicatedOutPath = path.join(versionDir, 'Claude-GoLogin-Static.yaml');
  const runtimeOutPath = path.join(versionDir, 'chain-runtime.json');

  writeFileAtomic(winOutPath, winArtifact.content);
  writeFileAtomic(desktopYamlOutPath, desktopYamlArtifact.yamlText);
  writeFileAtomic(dailyOutPath, androidArtifacts.daily.yamlText);
  writeFileAtomic(dedicatedOutPath, androidArtifacts.dedicated.yamlText);
  writeFileAtomic(runtimeOutPath, JSON.stringify(sharedRuntime, null, 2));

  // 同时更新 output/latest/ 便于外部脚本或手机拉取
  writeFileAtomic(path.join(latestDir, 'Script.js'), winArtifact.content);
  writeFileAtomic(path.join(latestDir, 'Desktop-Static-Chain.yaml'), desktopYamlArtifact.yamlText);
  writeFileAtomic(path.join(latestDir, 'Daily-Static-Chain.yaml'), androidArtifacts.daily.yamlText);
  writeFileAtomic(path.join(latestDir, 'Claude-GoLogin-Static.yaml'), androidArtifacts.dedicated.yamlText);
  writeFileAtomic(path.join(latestDir, 'chain-runtime.json'), JSON.stringify(sharedRuntime, null, 2));

  if (androidArtifacts.controllerSecret) {
    vault.setSecret(`android-ctrl-${versionId}`, { secret: androidArtifacts.controllerSecret });
  }

  let windowsStatus = 'generated';
  let backupPath = null;
  let applyMessage = '已生成双端配置产物到 output 目录（未修改本机 Clash Verge）';

  if (applyToClashVerge) {
    const targetScriptPath = path.join(state.deviceBindings.windows.clashVergeDir, 'profiles', 'Script.js');
    const backupDir = path.join(projectRoot, 'data', 'backups', versionId);
    fs.mkdirSync(backupDir, { recursive: true });

    const existing = safeReadFile(targetScriptPath);
    if (existing.readable) {
      backupPath = path.join(backupDir, 'Script.js.before');
      writeFileAtomic(backupPath, existing.content);
    } else if (existing.exists && !existing.readable) {
      throw new Error(`无法读取现有 Clash Verge Script.js 进行备份 (${existing.error})，已中止写入`);
    }

    try {
      writeFileAtomic(targetScriptPath, winArtifact.content);
      const readback = fs.readFileSync(targetScriptPath, 'utf8');
      if (sha256(readback) !== sha256(winArtifact.content)) {
        throw new Error('写入后 SHA-256 回读不一致');
      }
      windowsStatus = 'applied';
      applyMessage = '已原子备份并写入 Clash Verge profiles/Script.js；请在 Clash Verge 中刷新配置后执行「端到端探测」。';
    } catch (err) {
      // 写入失败时尝试自动恢复备份
      if (backupPath && fs.existsSync(backupPath)) {
        try {
          writeFileAtomic(targetScriptPath, fs.readFileSync(backupPath, 'utf8'));
        } catch { /* ignore */ }
      }
      throw new Error(`写入 Clash Verge 失败（已回退）: ${err.message}`);
    }
  }

  const versionRecord = {
    versionId,
    createdAt: new Date().toISOString(),
    note: note || `订阅: ${winArtifact.summary.firstHops[0] || '-'} | 预期出口: ${winArtifact.summary.expectedIp}`,
    subscriptionId: state.activeBinding.subscriptionId,
    staticExitId: state.activeBinding.staticExitId,
    expectedIp: winArtifact.summary.expectedIp,
    primaryFirstHop: winArtifact.summary.firstHops[0] || null,
    firstHops: winArtifact.summary.firstHops,
    windowsStatus,
    androidDailyStatus: 'generated',
    androidDedicatedStatus: 'generated',
    backupPath,
    files: {
      windowsScript: winOutPath,
      desktopYaml: desktopYamlOutPath,
      androidDaily: dailyOutPath,
      androidDedicated: dedicatedOutPath,
      sharedRuntime: runtimeOutPath
    },
    hashes: {
      windowsScript: sha256(winArtifact.content),
      desktopYaml: sha256(desktopYamlArtifact.yamlText),
      androidDaily: sha256(androidArtifacts.daily.yamlText),
      androidDedicated: sha256(androidArtifacts.dedicated.yamlText)
    }
  };

  writeFileAtomic(
    path.join(versionDir, 'manifest.json'),
    JSON.stringify(vault.redactObject(versionRecord), null, 2)
  );

  return { versionRecord, applyMessage };
}

/**
 * 将 Windows Clash Verge 的 Script.js 回滚到指定版本应用前的快照。
 */
export function rollbackWindowsToVersion(state, versionRecord) {
  if (!versionRecord?.backupPath || !fs.existsSync(versionRecord.backupPath)) {
    throw new Error('该版本没有可用的应用前备份快照');
  }
  const targetScriptPath = path.join(state.deviceBindings.windows.clashVergeDir, 'profiles', 'Script.js');
  const backupContent = fs.readFileSync(versionRecord.backupPath, 'utf8');
  writeFileAtomic(targetScriptPath, backupContent);
  const readback = fs.readFileSync(targetScriptPath, 'utf8');
  if (sha256(readback) !== sha256(backupContent)) {
    throw new Error('回滚后 SHA-256 校验失败');
  }
  return {
    status: 'rolled-back',
    restoredFrom: versionRecord.backupPath,
    targetScriptPath,
    restoredAt: new Date().toISOString()
  };
}

/**
 * 安全触发已存在的四个本机快捷方式脚本之一（保留原有全部守卫和退出检查语义）。
 */
export function triggerExistingLauncher(action, state) {
  const winBind = state.deviceBindings.windows;
  const runtimeDir = path.resolve(path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1')), '..', '..', 'runtime');

  const customEnvScript = winBind.claudeEnvScriptsDir ? path.join(winBind.claudeEnvScriptsDir, 'Switch-ClaudeEnvironment.ps1') : '';
  const bundledEnvScript = path.join(runtimeDir, 'Switch-RegionEnvironment.ps1');
  const customLauncher = winBind.claudeLocalDir ? path.join(winBind.claudeLocalDir, 'Start-Claude-Static.cjs') : '';
  const bundledLauncher = path.join(runtimeDir, 'Start-ClaudeStaticGuard.cjs');

  let cmd = '';
  let args = [];
  let cwd = process.cwd();

  if (action === 'claude-env' || action === 'china-env') {
    const useCustom = Boolean(customEnvScript && fs.existsSync(customEnvScript));
    const script = useCustom ? customEnvScript : bundledEnvScript;
    if (!fs.existsSync(script)) {
      throw new Error(`未找到环境切换脚本: ${script}`);
    }
    cmd = 'pwsh.exe';
    const modeArg = useCustom
      ? (action === 'claude-env' ? 'Claude' : 'China')
      : (action === 'claude-env' ? 'ProxyRegion' : 'Local');
    args = ['-NoProfile', '-File', script, '-Mode', modeArg];
    cwd = path.dirname(script);
  } else if (action === 'claude-desktop' || action === 'claude-code') {
    const useCustom = Boolean(customLauncher && fs.existsSync(customLauncher));
    const script = useCustom ? customLauncher : bundledLauncher;
    if (!fs.existsSync(script)) {
      throw new Error(`未找到静态出口启动器: ${script}`);
    }
    cmd = process.execPath;
    args = [script, action === 'claude-desktop' ? 'desktop' : 'code'];
    cwd = path.dirname(script);
  } else {
    throw new Error(`未知启动动作: ${action}`);
  }

  const child = spawn(cmd, args, { cwd, detached: true, stdio: 'ignore', windowsHide: false });
  child.unref();
  return { triggered: true, action, pid: child.pid, script: args[args.length - 1] };
}
