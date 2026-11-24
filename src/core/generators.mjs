import crypto from 'node:crypto';
import net from 'node:net';
import { dumpYaml, parseYaml } from './yaml-bridge.mjs';
import {
  dedupeList,
  extractPolicyDomainPattern,
  formatCustomRule,
  isLoopbackHost,
  normalizeSubscriptionProxies,
  retargetUpstreamRules
} from './rule-engine.mjs';

const LOCAL_LAN_DIRECT_RULES = [
  'DOMAIN,localhost,DIRECT',
  'DOMAIN-SUFFIX,local,DIRECT',
  'DOMAIN-SUFFIX,lan,DIRECT',
  'IP-CIDR,127.0.0.0/8,DIRECT,no-resolve',
  'IP-CIDR,10.0.0.0/8,DIRECT,no-resolve',
  'IP-CIDR,172.16.0.0/12,DIRECT,no-resolve',
  'IP-CIDR,192.168.0.0/16,DIRECT,no-resolve',
  'IP-CIDR,100.64.0.0/10,DIRECT,no-resolve',
  'IP-CIDR6,::1/128,DIRECT,no-resolve',
  'IP-CIDR6,fc00::/7,DIRECT,no-resolve',
  'IP-CIDR6,fe80::/10,DIRECT,no-resolve'
];

export function resolveActiveContext(state, vault, overrides = {}) {
  const subId = overrides.subscriptionId ?? state.activeBinding.subscriptionId;
  const exitId = overrides.staticExitId ?? state.activeBinding.staticExitId;
  const presetId = overrides.rulePresetId ?? state.activeBinding.rulePresetId;

  const subscription = state.subscriptions.find(s => s.id === subId) || null;
  const staticExit = state.staticExits.find(e => e.id === exitId) || null;
  const rulePreset = state.rulePresets.find(p => p.id === presetId) || state.rulePresets[0] || null;

  const selectedFirstHops = Array.isArray(overrides.selectedFirstHops)
    ? overrides.selectedFirstHops
    : (state.activeBinding.selectedFirstHops || []);
  const primaryFirstHop = overrides.primaryFirstHop ?? state.activeBinding.primaryFirstHop ?? selectedFirstHops[0] ?? null;

  const credentials = staticExit?.credentialRef && vault
    ? vault.getSecret(staticExit.credentialRef)
    : null;

  return {
    subscription,
    staticExit,
    rulePreset,
    selectedFirstHops,
    primaryFirstHop,
    credentials
  };
}

/**
 * 在生成或应用之前执行完整的静态隔离校验。
 */
export function validateCandidate(state, vault, overrides = {}) {
  const ctx = resolveActiveContext(state, vault, overrides);
  const errors = [];
  const warnings = [];

  if (!ctx.subscription) {
    errors.push('未选择有效的第一跳订阅');
  }
  if (!ctx.staticExit) {
    errors.push('未选择有效的静态出口配置');
  }
  if (!ctx.rulePreset) {
    errors.push('未找到规则预设');
  }

  if (errors.length > 0) {
    return { valid: false, errors, warnings, stats: {} };
  }

  const winOpts = ctx.rulePreset.windowsOptions;
  const andOpts = ctx.rulePreset.androidOptions;
  const reservedNames = new Set([
    winOpts.rawProxyName,
    winOpts.frontendProxyName,
    winOpts.firstHopGroupName,
    winOpts.upstreamListenerName,
    andOpts.proxyName,
    andOpts.firstHopGroupName,
    andOpts.dedicatedListenerName
  ]);

  const normalized = normalizeSubscriptionProxies(ctx.subscription.nodes, reservedNames);
  const validNodeMap = new Map(normalized.nodes.map(n => [n.name, n]));

  // 检查端口冲突
  const winPorts = [
    ['Windows mixed-port', winOpts.mixedPort],
    ['Windows upstream listener', winOpts.upstreamPort],
    ['Windows IPv4 relay', winOpts.relayPort],
    ['Windows DNS listen', Number(String(winOpts.dnsListen || '').split(':').pop())]
  ];
  const seenWinPorts = new Map();
  for (const [label, port] of winPorts) {
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      errors.push(`${label} 端口非法: ${port}`);
    } else if (seenWinPorts.has(port)) {
      errors.push(`Windows 端口冲突: ${label} 与 ${seenWinPorts.get(port)} 均使用 ${port}`);
    } else {
      seenWinPorts.set(port, label);
    }
  }

  const andPorts = [
    ['Android mixed-port', andOpts.mixedPort],
    ['Android GoLogin listener', andOpts.dedicatedListenerPort],
    ['Android controller', andOpts.controllerPort]
  ];
  const seenAndPorts = new Map();
  for (const [label, port] of andPorts) {
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      errors.push(`${label} 端口非法: ${port}`);
    } else if (seenAndPorts.has(port)) {
      errors.push(`Android 端口冲突: ${label} 与 ${seenAndPorts.get(port)} 均使用 ${port}`);
    } else {
      seenAndPorts.set(port, label);
    }
  }

  // 检查静态出口字段
  const exit = ctx.staticExit;
  if (!exit.server || isLoopbackHost(exit.server)) {
    errors.push(`静态出口节点地址缺失或为回环地址: ${exit.server || '(空)'}`);
  }
  if (!Number.isInteger(Number(exit.port)) || Number(exit.port) < 1 || Number(exit.port) > 65535) {
    errors.push(`静态出口端口非法: ${exit.port}`);
  }
  if (!exit.expectedIp || !net.isIPv4(exit.expectedIp.trim())) {
    errors.push(`静态出口预期公网 IP 不是合法 IPv4: ${exit.expectedIp || '(空)'}`);
  }
  if (exit.isSample) {
    warnings.push('当前静态出口仍为文档示例占位配置（203.0.113.10），应用到真实设备前请填写实际地址与凭据');
  }
  if (!ctx.credentials?.username || !ctx.credentials?.password) {
    warnings.push('当前静态出口尚未在本地保险库配置用户名/密码，将使用占位凭据（仅适合干跑预览）');
  }

  // 检查第一跳候选组
  const requestedHops = ctx.selectedFirstHops.length > 0
    ? ctx.selectedFirstHops
    : normalized.nodes.slice(0, 2).map(n => n.name);

  if (requestedHops.length === 0) {
    errors.push('Static-First-Hop 组为空：订阅中没有可用的真实叶子节点');
  }

  const validSelectedHops = [];
  for (const hopName of requestedHops) {
    if (hopName === 'DIRECT' || hopName === 'REJECT') {
      errors.push(`Static-First-Hop 禁止包含 ${hopName}`);
      continue;
    }
    if (reservedNames.has(hopName)) {
      errors.push(`Static-First-Hop 禁止自引用或引用链式节点: ${hopName}`);
      continue;
    }
    const node = validNodeMap.get(hopName);
    if (!node) {
      errors.push(`已选第一跳节点「${hopName}」在当前订阅中不存在或已被过滤（可能已改名/下线）`);
      continue;
    }
    validSelectedHops.push(node.name);
  }

  // 上游规则语法检查
  const ruleCheck = retargetUpstreamRules(ctx.subscription.rawRules, winOpts.frontendProxyName);
  if (ruleCheck.flaggedComplexRules.length > 0) {
    warnings.push(`上游订阅包含 ${ruleCheck.flaggedComplexRules.length} 条复合规则（AND/OR/NOT/SUB-RULE），已隔离保留待人工审查，未静默改写`);
  }
  if (ruleCheck.invalidRules.length > 0) {
    warnings.push(`上游订阅包含 ${ruleCheck.invalidRules.length} 条无法解析的规则，已跳过`);
  }
  if (ctx.subscription.isSample) {
    warnings.push('当前使用的是示例订阅快照，请导入您的真实机场 YAML 订阅或从本机 Clash Verge 导入');
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings,
    stats: {
      totalRawNodes: Array.isArray(ctx.subscription.nodes) ? ctx.subscription.nodes.length : 0,
      validLeafNodes: normalized.nodes.length,
      filteredNodes: normalized.filteredOut.length,
      selectedFirstHops: validSelectedHops.length,
      nodeDomainPolicies: normalized.nodeDomainPatterns.length,
      upstreamRuleCount: Array.isArray(ctx.subscription.rawRules) ? ctx.subscription.rawRules.length : 0,
      flaggedComplexRules: ruleCheck.flaggedComplexRules
    }
  };
}

/**
 * 排列第一跳列表，确保 primaryFirstHop 排在第一位且无重复。
 */
function orderFirstHops(selectedHops, primaryHop, validNodeSet) {
  const cleaned = dedupeList(selectedHops.filter(name => validNodeSet.has(name)));
  if (primaryHop && validNodeSet.has(primaryHop)) {
    return [primaryHop, ...cleaned.filter(n => n !== primaryHop)];
  }
  return cleaned;
}

/**
 * 构建用于 Windows 和 Android 的 DNS nameserver-policy（自动包含当前订阅的所有节点域名）。
 */
function buildDnsPolicy(nodeDomainPatterns, domesticDns, staticServer) {
  const policy = {
    'geosite:cn': [...domesticDns]
  };
  for (const pat of nodeDomainPatterns) {
    policy[pat] = [...domesticDns];
  }
  const exitPat = extractPolicyDomainPattern(staticServer);
  if (exitPat) {
    policy[exitPat] = [...domesticDns];
  }
  return policy;
}

/**
 * 生成 Windows Clash Verge Rev 全局覆写脚本 Script.js（含明文凭据版与界面安全脱敏版）。
 */
export function generateWindowsScript(state, vault, versionId, overrides = {}) {
  const ctx = resolveActiveContext(state, vault, overrides);
  const winOpts = ctx.rulePreset.windowsOptions;
  const exit = ctx.staticExit;
  const reservedNames = new Set([
    winOpts.rawProxyName,
    winOpts.frontendProxyName,
    winOpts.firstHopGroupName,
    winOpts.upstreamListenerName
  ]);

  const normalized = normalizeSubscriptionProxies(ctx.subscription.nodes, reservedNames);
  const validNodeSet = new Set(normalized.nodes.map(n => n.name));
  const orderedHops = orderFirstHops(
    ctx.selectedFirstHops.length ? ctx.selectedFirstHops : normalized.nodes.slice(0, 2).map(n => n.name),
    ctx.primaryFirstHop,
    validNodeSet
  );

  const username = ctx.credentials?.username || 'STATIC_PROXY_USERNAME';
  const password = ctx.credentials?.password || 'STATIC_PROXY_PASSWORD';

  const makeScript = (useRedactedCreds) => {
    const rawProxy = {
      name: winOpts.rawProxyName,
      type: exit.windowsProtocol || 'http',
      server: exit.server,
      port: Number(exit.port),
      username: useRedactedCreds ? '***REDACTED***' : username,
      password: useRedactedCreds ? '***REDACTED***' : password,
      'dialer-proxy': winOpts.firstHopGroupName
    };
    if (rawProxy.type === 'socks5') {
      rawProxy.udp = false;
    }

    const frontendProxy = {
      name: winOpts.frontendProxyName,
      type: 'http',
      server: '127.0.0.1',
      port: Number(winOpts.relayPort)
    };

    const firstGroup = {
      name: winOpts.firstHopGroupName,
      type: 'select',
      proxies: orderedHops
    };

    const upstreamListener = {
      name: winOpts.upstreamListenerName,
      type: 'mixed',
      listen: '127.0.0.1',
      port: Number(winOpts.upstreamPort),
      proxy: winOpts.rawProxyName
    };

    // 构建精确排序的 headRules
    const gameRules = (ctx.rulePreset.gameDirectRules || [])
      .filter(r => r.enabled)
      .map(r => `${r.type},${r.payload},${r.action || 'DIRECT'}`);

    const protectedDomRules = (ctx.rulePreset.protectedDomains || [])
      .filter(r => r.enabled && (r.scope === 'both' || r.scope === 'windows'))
      .map(r => `${r.type},${r.payload},${winOpts.frontendProxyName}`);

    const winProcRules = (ctx.rulePreset.windowsProcesses || [])
      .filter(r => r.enabled)
      .map(r => `${r.type},${r.payload},${winOpts.frontendProxyName}`);

    const customHeadRules = (ctx.rulePreset.customRules || [])
      .filter(r => r.enabled && (r.scope === 'both' || r.scope === 'windows'))
      .map(r => formatCustomRule(r, winOpts.frontendProxyName))
      .filter(Boolean);

    const headRules = dedupeList([
      `IN-NAME,${winOpts.upstreamListenerName},${winOpts.rawProxyName}`,
      ...LOCAL_LAN_DIRECT_RULES,
      ...gameRules,
      ...protectedDomRules,
      ...winProcRules,
      ...customHeadRules
    ]);

    const domesticDns = winOpts.domesticDns?.length ? winOpts.domesticDns : ['119.29.29.29', '223.5.5.5'];
    const dnsPolicy = buildDnsPolicy(normalized.nodeDomainPatterns, domesticDns, exit.server);
    const dnsSettings = {
      enable: true,
      ipv6: Boolean(winOpts.ipv6),
      listen: winOpts.dnsListen || '127.0.0.1:7874',
      'use-hosts': true,
      'use-system-hosts': false,
      'enhanced-mode': 'fake-ip',
      'fake-ip-range': '198.18.0.0/15',
      nameserver: [`https://1.1.1.1/dns-query#${winOpts.rawProxyName}`],
      'proxy-server-nameserver': domesticDns,
      'direct-nameserver': domesticDns,
      'nameserver-policy': dnsPolicy
    };

    const tunSettings = {
      enable: Boolean(winOpts.tunEnable),
      device: 'Mihomo',
      stack: 'gvisor',
      'auto-route': true,
      'strict-route': true,
      'auto-detect-interface': true,
      'dns-hijack': ['any:53'],
      'inet6-address': ['fdfe:dcba:9876::1/126']
    };

    return `// Generated by Clash Chain Studio
// Version: ${versionId}
// GeneratedAt: ${new Date().toISOString()}
// Subscription: ${ctx.subscription.name}
// StaticExit: ${exit.name} (Expected IP: ${exit.expectedIp})
// Windows TUN default: ${Boolean(winOpts.tunEnable)} | IPv6: ${Boolean(winOpts.ipv6)}

const rawProxy = ${JSON.stringify(rawProxy, null, 2)};
const frontendProxy = ${JSON.stringify(frontendProxy, null, 2)};
const firstGroup = ${JSON.stringify(firstGroup, null, 2)};
const upstreamListener = ${JSON.stringify(upstreamListener, null, 2)};
const headRules = ${JSON.stringify(headRules, null, 2)};
const dnsSettings = ${JSON.stringify(dnsSettings, null, 2)};
const tunSettings = ${JSON.stringify(tunSettings, null, 2)};
const rejectTargets = new Set(["REJECT", "REJECT-DROP"]);
const trailingOptions = new Set(["no-resolve", "src"]);
const complexKinds = new Set(["AND", "OR", "NOT", "SUB-RULE"]);

function splitRuleTopLevel(rule) {
  const tokens = [];
  let cur = "";
  let depth = 0;
  for (let i = 0; i < rule.length; i++) {
    const ch = rule[i];
    if (ch === "(") { depth++; cur += ch; }
    else if (ch === ")") { depth = Math.max(0, depth - 1); cur += ch; }
    else if (ch === "," && depth === 0) { tokens.push(cur.trim()); cur = ""; }
    else { cur += ch; }
  }
  if (cur.length > 0 || rule.endsWith(",")) tokens.push(cur.trim());
  return depth === 0 ? tokens : null;
}

function classifyAndRetarget(rule) {
  if (typeof rule !== "string") return null;
  const trimmed = rule.trim();
  if (!trimmed || trimmed.startsWith("#")) return null;
  const parts = splitRuleTopLevel(trimmed);
  if (!parts || parts.length < 2) return null;
  const kind = parts[0].toUpperCase();
  if (kind === "MATCH") return null;
  if (complexKinds.has(kind)) return null; // 复合规则不在脚本中静默改写
  let idx = parts.length - 1;
  while (idx > 1 && trailingOptions.has(parts[idx].toLowerCase())) idx--;
  if (idx < 2) return null;
  const action = parts[idx];
  if (rejectTargets.has(action)) {
    return { bucket: "reject", rule: parts.join(",") };
  }
  if (action === "DIRECT" && /^PROCESS-(NAME|PATH)(-REGEX)?$/.test(kind)) {
    return { bucket: "directProcess", rule: trimmed };
  }
  const payload = parts.slice(1, idx).join(",").toLowerCase();
  const isDomestic = ((kind === "GEOIP" || kind === "GEOSITE") && payload === "cn") ||
    (kind === "DOMAIN-SUFFIX" && payload === "cn");
  parts[idx] = isDomestic ? "DIRECT" : frontendProxy.name;
  return { bucket: "other", rule: parts.join(",") };
}

function isSafeLeaf(p, managedNames) {
  if (!p || !p.name || !p.server || !p.type) return false;
  const type = String(p.type).toLowerCase();
  if (type === "direct" || type === "reject" || type === "pass") return false;
  if (managedNames.has(p.name) || p.name === firstGroup.name) return false;
  if (p["dialer-proxy"]) return false;
  const host = String(p.server).toLowerCase().replace(/^\\[|\\]$/g, "");
  if (host === "localhost" || host === "::1" || /^127\\./.test(host)) return false;
  return true;
}

function main(config, profileName) {
  if (!config || typeof config !== "object") {
    throw new Error("Expected Clash configuration object");
  }
  const proxies = Array.isArray(config.proxies) ? config.proxies : [];
  const managedNames = new Set([rawProxy.name, frontendProxy.name]);
  config.proxies = proxies.filter(p => p && !managedNames.has(p.name));

  const safeHops = firstGroup.proxies.filter(name =>
    config.proxies.some(p => p.name === name && isSafeLeaf(p, managedNames))
  );
  config.proxies.push(rawProxy, frontendProxy);

  const groups = Array.isArray(config["proxy-groups"]) ? config["proxy-groups"] : [];
  config["proxy-groups"] = groups.filter(g => g && g.name !== firstGroup.name);
  config["proxy-groups"].push({
    ...firstGroup,
    proxies: safeHops.length ? safeHops : ["REJECT"]
  });

  const listeners = Array.isArray(config.listeners) ? config.listeners : [];
  config.listeners = listeners.filter(l => l && l.name !== upstreamListener.name);
  config.listeners.push(upstreamListener);

  const sourceRules = Array.isArray(config.rules) ? config.rules : [];
  const rejectRules = [];
  const directProcessRules = [];
  const otherRules = [];
  for (const r of sourceRules) {
    const res = classifyAndRetarget(r);
    if (!res) continue;
    if (res.bucket === "reject") rejectRules.push(res.rule);
    else if (res.bucket === "directProcess") directProcessRules.push(res.rule);
    else otherRules.push(res.rule);
  }

  config.rules = [...new Set([
    ...headRules,
    ...rejectRules,
    ...directProcessRules,
    "GEOSITE,cn,DIRECT",
    "DOMAIN-SUFFIX,cn,DIRECT",
    "GEOIP,CN,DIRECT",
    "NETWORK,UDP,REJECT",
    ...otherRules,
    "MATCH," + frontendProxy.name
  ])];

  config.dns = {
    ...(config.dns || {}),
    ...dnsSettings,
    fallback: [],
    "respect-rules": false
  };
  config.tun = { ...(config.tun || {}), ...tunSettings };
  config.mode = "rule";
  config.ipv6 = ${Boolean(winOpts.ipv6)};
  config["allow-lan"] = ${Boolean(winOpts.allowLan)};
  config["mixed-port"] = ${Number(winOpts.mixedPort)};
  config["find-process-mode"] = "always";
  return config;
}
`;
  };

  return {
    filename: 'Script.js',
    content: makeScript(false),
    redactedContent: makeScript(true),
    summary: {
      versionId,
      firstHops: orderedHops,
      rawProxyName: winOpts.rawProxyName,
      frontendProxyName: winOpts.frontendProxyName,
      expectedIp: exit.expectedIp,
      ipv6: Boolean(winOpts.ipv6),
      tunEnable: Boolean(winOpts.tunEnable),
      nodeDomainPolicies: normalized.nodeDomainPatterns
    }
  };
}

/**
 * 生成通用桌面端独立 YAML（适用于 Mihomo Party / FlClash / macOS / Linux / 原生 Mihomo 核心）。
 */
export function generateDesktopStandaloneYaml(state, vault, versionId, overrides = {}) {
  const ctx = resolveActiveContext(state, vault, overrides);
  const winOpts = ctx.rulePreset.windowsOptions;
  const exit = ctx.staticExit;

  const reservedNames = new Set([
    winOpts.rawProxyName,
    winOpts.frontendProxyName,
    winOpts.firstHopGroupName,
    winOpts.upstreamListenerName
  ]);

  const normalized = normalizeSubscriptionProxies(ctx.subscription.nodes, reservedNames);
  const validNodeSet = new Set(normalized.nodes.map(n => n.name));
  const orderedHops = orderFirstHops(
    ctx.selectedFirstHops.length ? ctx.selectedFirstHops : normalized.nodes.slice(0, 2).map(n => n.name),
    ctx.primaryFirstHop,
    validNodeSet
  );

  const username = ctx.credentials?.username || 'STATIC_PROXY_USERNAME';
  const password = ctx.credentials?.password || 'STATIC_PROXY_PASSWORD';

  const buildOne = (useRedacted) => {
    const rawProxy = {
      name: winOpts.rawProxyName,
      type: exit.windowsProtocol || 'http',
      server: exit.server,
      port: Number(exit.port),
      username: useRedacted ? '***REDACTED***' : username,
      password: useRedacted ? '***REDACTED***' : password,
      'dialer-proxy': winOpts.firstHopGroupName
    };
    if (rawProxy.type === 'socks5') rawProxy.udp = false;

    const frontendProxy = {
      name: winOpts.frontendProxyName,
      type: 'http',
      server: '127.0.0.1',
      port: Number(winOpts.relayPort)
    };

    const proxies = normalized.nodes.map(n => {
      const clone = { ...n };
      delete clone.id;
      if (useRedacted) {
        if (clone.password) clone.password = '***REDACTED***';
        if (clone.uuid) clone.uuid = '***REDACTED***';
      }
      return clone;
    });
    proxies.push(rawProxy, frontendProxy);

    const gameRules = (ctx.rulePreset.gameDirectRules || [])
      .filter(r => r.enabled)
      .map(r => `${r.type},${r.payload},${r.action || 'DIRECT'}`);
    const protectedDomRules = (ctx.rulePreset.protectedDomains || [])
      .filter(r => r.enabled && (r.scope === 'both' || r.scope === 'windows'))
      .map(r => `${r.type},${r.payload},${winOpts.frontendProxyName}`);
    const winProcRules = (ctx.rulePreset.windowsProcesses || [])
      .filter(r => r.enabled)
      .map(r => `${r.type},${r.payload},${winOpts.frontendProxyName}`);
    const customRules = (ctx.rulePreset.customRules || [])
      .filter(r => r.enabled && (r.scope === 'both' || r.scope === 'windows'))
      .map(r => formatCustomRule(r, winOpts.frontendProxyName))
      .filter(Boolean);
    const retargeted = retargetUpstreamRules(ctx.subscription.rawRules, winOpts.frontendProxyName);

    const rules = dedupeList([
      `IN-NAME,${winOpts.upstreamListenerName},${winOpts.rawProxyName}`,
      ...LOCAL_LAN_DIRECT_RULES,
      ...gameRules,
      ...protectedDomRules,
      ...winProcRules,
      ...customRules,
      ...retargeted.rejectRules,
      ...retargeted.preservedDirectProcessRules,
      'GEOSITE,cn,DIRECT',
      'DOMAIN-SUFFIX,cn,DIRECT',
      'GEOIP,CN,DIRECT',
      'NETWORK,UDP,REJECT',
      ...retargeted.routedRules,
      `MATCH,${winOpts.frontendProxyName}`
    ]);

    const domesticDns = winOpts.domesticDns?.length ? winOpts.domesticDns : ['119.29.29.29', '223.5.5.5'];
    const dnsPolicy = buildDnsPolicy(normalized.nodeDomainPatterns, domesticDns, exit.server);

    const configObj = {
      'mixed-port': Number(winOpts.mixedPort),
      'allow-lan': Boolean(winOpts.allowLan),
      mode: 'rule',
      'log-level': 'info',
      ipv6: Boolean(winOpts.ipv6),
      'find-process-mode': 'always',
      profile: { 'store-selected': true, 'store-fake-ip': true },
      dns: {
        enable: true,
        ipv6: Boolean(winOpts.ipv6),
        listen: winOpts.dnsListen || '127.0.0.1:7874',
        'use-hosts': true,
        'use-system-hosts': false,
        'enhanced-mode': 'fake-ip',
        'fake-ip-range': '198.18.0.0/15',
        nameserver: [`https://1.1.1.1/dns-query#${winOpts.rawProxyName}`],
        'proxy-server-nameserver': domesticDns,
        'direct-nameserver': domesticDns,
        'nameserver-policy': dnsPolicy,
        'respect-rules': false
      },
      tun: {
        enable: Boolean(winOpts.tunEnable),
        device: 'Mihomo',
        stack: 'gvisor',
        'auto-route': true,
        'strict-route': true,
        'auto-detect-interface': true,
        'dns-hijack': ['any:53']
      },
      listeners: [
        {
          name: winOpts.upstreamListenerName,
          type: 'mixed',
          listen: '127.0.0.1',
          port: Number(winOpts.upstreamPort),
          proxy: winOpts.rawProxyName
        }
      ],
      proxies,
      'proxy-groups': [
        {
          name: winOpts.firstHopGroupName,
          type: 'select',
          proxies: orderedHops.length ? orderedHops : ['REJECT']
        }
      ],
      rules
    };

    const header = [
      '# Generated by Clash Chain Studio (Universal Desktop YAML)',
      `# Version: ${versionId}`,
      `# GeneratedAt: ${new Date().toISOString()}`,
      `# Subscription: ${ctx.subscription.name}`,
      `# StaticExit: ${exit.name} (Expected IP: ${exit.expectedIp})`,
      ''
    ].join('\n');

    const yamlText = header + dumpYaml(configObj);
    const roundTrip = parseYaml(yamlText);
    if (!roundTrip || !Array.isArray(roundTrip.rules) || roundTrip.rules.length !== rules.length) {
      throw new Error('Desktop standalone YAML 回读校验失败');
    }
    return { filename: 'Desktop-Static-Chain.yaml', yamlText, ruleCount: rules.length, proxyCount: proxies.length };
  };

  const real = buildOne(false);
  const redacted = buildOne(true);
  return { ...real, redactedYaml: redacted.yamlText };
}

/**
 * 同时生成 Android Clash Meta 双配置文件：
 * 1) Daily-Static-Chain.yaml（日常配置：普通浏览器分流直连国内，Claude/GoLogin 与指定域走静态链）
 * 2) Claude-GoLogin-Static.yaml（专用配置：额外强制指定浏览器整应用走静态链并阻断其 UDP）
 */
export function generateAndroidProfiles(state, vault, versionId, overrides = {}) {
  const ctx = resolveActiveContext(state, vault, overrides);
  const andOpts = ctx.rulePreset.androidOptions;
  const exit = ctx.staticExit;

  const reservedNames = new Set([
    andOpts.proxyName,
    andOpts.firstHopGroupName,
    andOpts.dedicatedListenerName
  ]);

  const normalized = normalizeSubscriptionProxies(ctx.subscription.nodes, reservedNames);
  const validNodeSet = new Set(normalized.nodes.map(n => n.name));
  const orderedHops = orderFirstHops(
    ctx.selectedFirstHops.length ? ctx.selectedFirstHops : normalized.nodes.slice(0, 2).map(n => n.name),
    ctx.primaryFirstHop,
    validNodeSet
  );

  const username = ctx.credentials?.username || 'STATIC_PROXY_USERNAME';
  const password = ctx.credentials?.password || 'STATIC_PROXY_PASSWORD';
  const controllerSecret = overrides.controllerSecret || crypto.randomBytes(24).toString('base64url');
  const includeController = overrides.includeController ?? Boolean(andOpts.includeControllerInExport);

  const buildOne = (variant, useRedacted) => {
    const isDedicated = variant === 'dedicated';
    const proxyName = andOpts.proxyName;
    const firstHopGroup = andOpts.firstHopGroupName;

    const exitNode = {
      name: proxyName,
      type: exit.androidProtocol || 'socks5',
      server: exit.server,
      port: Number(exit.port),
      username: useRedacted ? '***REDACTED***' : username,
      password: useRedacted ? '***REDACTED***' : password,
      'dialer-proxy': firstHopGroup
    };
    if (exitNode.type === 'socks5') {
      exitNode.udp = Boolean(exit.androidUdp);
    }

    const proxies = normalized.nodes.map(node => {
      const clone = { ...node };
      delete clone.id;
      if (useRedacted) {
        if (clone.password) clone.password = '***REDACTED***';
        if (clone.uuid) clone.uuid = '***REDACTED***';
      }
      return clone;
    });
    proxies.push(exitNode);

    const proxyGroups = [
      {
        name: firstHopGroup,
        type: 'select',
        proxies: orderedHops.length ? orderedHops : ['REJECT']
      }
    ];

    const listeners = [
      {
        name: andOpts.dedicatedListenerName,
        type: 'mixed',
        listen: '127.0.0.1',
        port: Number(andOpts.dedicatedListenerPort),
        proxy: proxyName
      }
    ];

    // 受保护核心 App（Daily 与 Dedicated 均强制保护并提前拦截 UDP）
    const coreApps = (ctx.rulePreset.androidCoreApps || []).filter(a => a.enabled);
    const browserApps = isDedicated
      ? (ctx.rulePreset.androidBrowserApps || []).filter(a => a.enabled)
      : [];

    const appRules = [];
    for (const app of [...coreApps, ...browserApps]) {
      if (app.blockUdp !== false) {
        appRules.push(`AND,((PROCESS-NAME,${app.packageName}),(NETWORK,UDP)),REJECT`);
      }
      appRules.push(`PROCESS-NAME,${app.packageName},${proxyName}`);
    }

    const protectedDomains = (ctx.rulePreset.protectedDomains || [])
      .filter(r => r.enabled && (r.scope === 'both' || r.scope === 'android'))
      .map(r => `${r.type},${r.payload},${proxyName}`);

    const customScopeMatch = isDedicated
      ? new Set(['both', 'android', 'android-dedicated'])
      : new Set(['both', 'android', 'android-daily']);

    const customRules = (ctx.rulePreset.customRules || [])
      .filter(r => r.enabled && customScopeMatch.has(r.scope))
      .map(r => formatCustomRule(r, proxyName))
      .filter(Boolean);

    const retargeted = retargetUpstreamRules(ctx.subscription.rawRules, proxyName);

    const rules = dedupeList([
      `IN-NAME,${andOpts.dedicatedListenerName},${proxyName}`,
      ...LOCAL_LAN_DIRECT_RULES,
      ...appRules,
      ...protectedDomains,
      ...customRules,
      ...retargeted.rejectRules,
      ...retargeted.preservedDirectProcessRules,
      'GEOSITE,cn,DIRECT',
      'DOMAIN-SUFFIX,cn,DIRECT',
      'GEOIP,CN,DIRECT',
      'NETWORK,UDP,REJECT',
      ...retargeted.routedRules,
      `MATCH,${proxyName}`
    ]);

    const domesticDns = andOpts.domesticDns?.length ? andOpts.domesticDns : ['223.5.5.5', '119.29.29.29'];
    const dnsPolicy = buildDnsPolicy(normalized.nodeDomainPatterns, domesticDns, exit.server);
    const useLocalClashDns = (andOpts.mobileDnsMode || 'local-clash-7874') === 'local-clash-7874';
    const dnsListen = andOpts.dnsListen || '127.0.0.1:7874';

    const dns = {
      enable: true,
      ipv6: Boolean(andOpts.ipv6),
      'enhanced-mode': 'fake-ip',
      'fake-ip-range': '198.18.0.0/15',
      nameserver: [
        `https://1.1.1.1/dns-query#${proxyName}`,
        `https://8.8.8.8/dns-query#${proxyName}`
      ],
      'proxy-server-nameserver': useLocalClashDns ? [`udp://${dnsListen}`] : domesticDns,
      'direct-nameserver': domesticDns,
      'nameserver-policy': dnsPolicy,
      'respect-rules': false
    };
    if (useLocalClashDns) {
      dns.listen = dnsListen;
    }

    const configObj = {
      'mixed-port': Number(andOpts.mixedPort),
      'allow-lan': Boolean(andOpts.allowLan),
      mode: 'rule',
      'log-level': 'info',
      ipv6: Boolean(andOpts.ipv6),
      'find-process-mode': 'always',
      profile: {
        'store-selected': true,
        'store-fake-ip': true
      },
      dns,
      listeners,
      proxies,
      'proxy-groups': proxyGroups,
      rules
    };

    if (includeController) {
      configObj['external-controller'] = `127.0.0.1:${Number(andOpts.controllerPort)}`;
      configObj.secret = useRedacted ? '***REDACTED***' : controllerSecret;
    }

    const header = [
      `# Generated by Clash Chain Studio (${isDedicated ? 'Claude-GoLogin-Static' : 'Daily-Static-Chain'})`,
      `# Version: ${versionId}`,
      `# GeneratedAt: ${new Date().toISOString()}`,
      `# Subscription: ${ctx.subscription.name}`,
      `# StaticExit: ${exit.name} (Expected IP: ${exit.expectedIp})`,
      `# MobileDnsMode: ${andOpts.mobileDnsMode || 'local-clash-7874'}`,
      ''
    ].join('\n');

    const yamlText = header + dumpYaml(configObj);
    // 往返校验确保生成的 YAML 可被标准解析器无损回读
    const roundTrip = parseYaml(yamlText);
    if (!roundTrip || !Array.isArray(roundTrip.rules) || roundTrip.rules.length !== rules.length) {
      throw new Error(`Android ${variant} YAML 回读校验失败`);
    }

    return {
      profileName: isDedicated ? 'Claude-GoLogin-Static' : 'Daily-Static-Chain',
      filename: isDedicated ? 'Claude-GoLogin-Static.yaml' : 'Daily-Static-Chain.yaml',
      yamlText,
      ruleCount: rules.length,
      proxyCount: proxies.length,
      browserOverridesCount: browserApps.length,
      dedicatedListenerPort: Number(andOpts.dedicatedListenerPort)
    };
  };

  const daily = buildOne('daily', false);
  const dailyRedacted = buildOne('daily', true);
  const dedicated = buildOne('dedicated', false);
  const dedicatedRedacted = buildOne('dedicated', true);

  return {
    versionId,
    daily: { ...daily, redactedYaml: dailyRedacted.yamlText },
    dedicated: { ...dedicated, redactedYaml: dedicatedRedacted.yamlText },
    controllerSecret: includeController ? controllerSecret : null
  };
}

/**
 * 生成供 4 个 Windows 快捷方式与启动守卫共用的运行时配置（取代硬编码 IP / 端口 / 组名）。
 */
export function generateSharedRuntimeConfig(state, versionId, overrides = {}) {
  const ctx = resolveActiveContext(state, vaultPlaceholder(), overrides);
  const winOpts = ctx.rulePreset.windowsOptions;
  const exit = ctx.staticExit;

  return {
    schemaVersion: 1,
    versionId,
    generatedAt: new Date().toISOString(),
    staticExitId: exit.id,
    staticExitName: exit.name,
    expectedIp: exit.expectedIp,
    region: exit.region,
    timeZone: exit.timeZone || 'America/Chicago',
    windows: {
      ruleProxyUrl: `http://127.0.0.1:${winOpts.mixedPort}`,
      relayProxyUrl: `http://127.0.0.1:${winOpts.relayPort}`,
      upstreamPort: Number(winOpts.upstreamPort),
      relayPort: Number(winOpts.relayPort),
      mixedPort: Number(winOpts.mixedPort),
      firstHopGroup: winOpts.firstHopGroupName,
      primaryFirstHop: ctx.primaryFirstHop
    },
    android: {
      mixedPort: Number(ctx.rulePreset.androidOptions.mixedPort),
      dedicatedListenerPort: Number(ctx.rulePreset.androidOptions.dedicatedListenerPort),
      proxyName: ctx.rulePreset.androidOptions.proxyName,
      firstHopGroup: ctx.rulePreset.androidOptions.firstHopGroupName
    }
  };
}

function vaultPlaceholder() {
  return { getSecret: () => null };
}

/**
 * 简单清晰的统一行级 Diff 生成器（供应用前预览差异）。
 */
export function computeUnifiedDiff(beforeText, afterText, maxLines = 400) {
  const a = String(beforeText || '').split(/\r?\n/);
  const b = String(afterText || '').split(/\r?\n/);

  // 对于超长文件（如数千行 YAML），按前后匹配与变化段摘要避免 O(N^2) 卡顿
  if (a.length * b.length > 2_000_000) {
    return computeFastDiff(a, b, maxLines);
  }

  const m = a.length;
  const n = b.length;
  const dp = Array.from({ length: m + 1 }, () => new Uint32Array(n + 1));
  for (let i = m - 1; i >= 0; i--) {
    for (let j = n - 1; j >= 0; j--) {
      dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
    }
  }

  const rawOps = [];
  let i = 0;
  let j = 0;
  while (i < m && j < n) {
    if (a[i] === b[j]) {
      rawOps.push({ type: 'same', line: a[i], oldLine: i + 1, newLine: j + 1 });
      i++; j++;
    } else if (dp[i + 1][j] >= dp[i][j + 1]) {
      rawOps.push({ type: 'del', line: a[i], oldLine: i + 1 });
      i++;
    } else {
      rawOps.push({ type: 'add', line: b[j], newLine: j + 1 });
      j++;
    }
  }
  while (i < m) { rawOps.push({ type: 'del', line: a[i], oldLine: i + 1 }); i++; }
  while (j < n) { rawOps.push({ type: 'add', line: b[j], newLine: j + 1 }); j++; }

  const added = rawOps.filter(x => x.type === 'add').length;
  const removed = rawOps.filter(x => x.type === 'del').length;

  // 只输出变动附近上下文 3 行
  const keep = new Set();
  rawOps.forEach((op, idx) => {
    if (op.type !== 'same') {
      for (let k = Math.max(0, idx - 3); k <= Math.min(rawOps.length - 1, idx + 3); k++) {
        keep.add(k);
      }
    }
  });

  const lines = [];
  let lastIdx = -1;
  for (let idx = 0; idx < rawOps.length; idx++) {
    if (!keep.has(idx)) continue;
    if (lastIdx !== -1 && idx > lastIdx + 1) {
      lines.push({ type: 'skip', text: `... 省略 ${idx - lastIdx - 1} 行未改动内容 ...` });
    }
    const op = rawOps[idx];
    lines.push({
      type: op.type,
      prefix: op.type === 'add' ? '+' : op.type === 'del' ? '-' : ' ',
      text: op.line
    });
    lastIdx = idx;
    if (lines.length >= maxLines) {
      lines.push({ type: 'skip', text: '... 差异过长，已截断预览 ...' });
      break;
    }
  }

  return { added, removed, changed: added > 0 || removed > 0, lines };
}

function computeFastDiff(a, b, maxLines) {
  const setA = new Set(a);
  const setB = new Set(b);
  const lines = [];
  let added = 0;
  let removed = 0;
  for (const line of a) {
    if (!setB.has(line)) {
      removed++;
      if (lines.length < maxLines) lines.push({ type: 'del', prefix: '-', text: line });
    }
  }
  for (const line of b) {
    if (!setA.has(line)) {
      added++;
      if (lines.length < maxLines) lines.push({ type: 'add', prefix: '+', text: line });
    }
  }
  return { added, removed, changed: added > 0 || removed > 0, lines };
}
