import net from 'node:net';

const INFO_NODE_PATTERNS = [
  /traffic\s*:/i,
  /expire\s*:/i,
  /剩余流量/,
  /套餐到期/,
  /到期时间/,
  /距离下次重置/,
  /官网/,
  /更新订阅/,
  /最新网址/,
  /异常请/
];

const RESERVED_ACTIONS = new Set(['DIRECT', 'REJECT', 'REJECT-DROP', 'PASS']);
const COMPLEX_RULE_KINDS = new Set(['AND', 'OR', 'NOT', 'SUB-RULE']);
const RULE_TRAILING_OPTIONS = new Set(['no-resolve', 'src']);

export function isLoopbackHost(host) {
  const cleaned = String(host || '').trim().toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
  if (!cleaned) return true;
  if (cleaned === 'localhost' || cleaned.endsWith('.localhost') || cleaned === '::1' || cleaned === '0.0.0.0') {
    return true;
  }
  if (/^127\./.test(cleaned)) return true;
  if (/^::ffff:127\./.test(cleaned) || /^::ffff:7f[0-9a-f]{2}:/.test(cleaned)) return true;
  return false;
}

/**
 * 提取域名主后缀（例如 tw2.node.apt-agent.org -> +.apt-agent.org），跳过纯 IP。
 */
export function extractPolicyDomainPattern(host) {
  const cleaned = String(host || '').trim().toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
  if (!cleaned || net.isIP(cleaned) || isLoopbackHost(cleaned)) return null;
  const parts = cleaned.split('.').filter(Boolean);
  if (parts.length < 2) return null;
  // 常见二级公共后缀（如 .co.uk, .com.cn）取最后三段，否则取最后两段
  const lastTwo = parts.slice(-2).join('.');
  const multiPartTlds = new Set(['com.cn', 'net.cn', 'org.cn', 'co.jp', 'co.uk', 'com.hk', 'com.tw']);
  if (parts.length >= 3 && multiPartTlds.has(lastTwo)) {
    return '+.' + parts.slice(-3).join('.');
  }
  return '+.' + lastTwo;
}

/**
 * 过滤并标准化订阅中的叶子节点，明确列出被排除项及原因。
 */
export function normalizeSubscriptionProxies(rawProxies, reservedNames = new Set()) {
  const list = Array.isArray(rawProxies) ? rawProxies : [];
  const validNodes = [];
  const filteredOut = [];
  const seenNames = new Set();
  const domainPatterns = new Set();

  for (const raw of list) {
    if (!raw || typeof raw !== 'object') {
      filteredOut.push({ name: '(无效条目)', reason: '节点不是合法对象' });
      continue;
    }
    const name = String(raw.name || '').trim();
    const type = String(raw.type || '').trim().toLowerCase();
    const server = String(raw.server || '').trim();
    const port = Number(raw.port);

    if (!name) {
      filteredOut.push({ name: '(未命名)', reason: '缺少节点名称' });
      continue;
    }
    if (RESERVED_ACTIONS.has(name.toUpperCase()) || reservedNames.has(name)) {
      filteredOut.push({ name, reason: '与保留策略或链式保留名冲突' });
      continue;
    }
    if (seenNames.has(name)) {
      filteredOut.push({ name, reason: '重复节点名称（已去重）' });
      continue;
    }
    if (INFO_NODE_PATTERNS.some(re => re.test(name))) {
      filteredOut.push({ name, reason: '套餐/流量提示伪节点' });
      continue;
    }
    if (!type || type === 'direct' || type === 'reject' || type === 'pass') {
      filteredOut.push({ name, reason: `非真实代理节点类型 (${type || 'empty'})` });
      continue;
    }
    if (raw['dialer-proxy']) {
      filteredOut.push({ name, reason: `已有 dialer-proxy (${raw['dialer-proxy']})，禁止嵌套第一跳` });
      continue;
    }
    if (!server || isLoopbackHost(server)) {
      filteredOut.push({ name, reason: `节点地址缺失或为回环地址 (${server || 'empty'})` });
      continue;
    }
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      filteredOut.push({ name, reason: `节点端口非法 (${raw.port})` });
      continue;
    }

    seenNames.add(name);
    validNodes.push({ ...raw, name, type, server, port });
    const pattern = extractPolicyDomainPattern(server);
    if (pattern) domainPatterns.add(pattern);
  }

  return {
    nodes: validNodes,
    filteredOut,
    nodeDomainPatterns: [...domainPatterns].sort()
  };
}

/**
 * 语法感知拆分 Mihomo 规则顶层逗号（正确保留 AND/OR/NOT 中的嵌套括号）。
 */
export function splitRuleTokens(ruleLine) {
  const text = String(ruleLine || '').trim();
  const tokens = [];
  let current = '';
  let depth = 0;

  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (ch === '(') {
      depth++;
      current += ch;
    } else if (ch === ')') {
      depth = Math.max(0, depth - 1);
      current += ch;
    } else if (ch === ',' && depth === 0) {
      tokens.push(current.trim());
      current = '';
    } else {
      current += ch;
    }
  }
  if (current.length > 0 || text.endsWith(',')) {
    tokens.push(current.trim());
  }
  return { tokens, unbalanced: depth !== 0 };
}

/**
 * 解析单条 Mihomo 规则，正确识别动作位置（位于可选 no-resolve / src 之前）。
 */
export function parseMihomoRule(ruleLine) {
  if (typeof ruleLine !== 'string') {
    return { valid: false, raw: ruleLine, reason: '规则不是字符串' };
  }
  const trimmed = ruleLine.trim();
  if (!trimmed || trimmed.startsWith('#')) {
    return { valid: false, raw: ruleLine, reason: '空行或注释', ignored: true };
  }

  const { tokens, unbalanced } = splitRuleTokens(trimmed);
  if (unbalanced) {
    return { valid: false, raw: trimmed, reason: '规则括号不匹配' };
  }

  const kind = tokens[0]?.toUpperCase() || '';
  if (!kind) {
    return { valid: false, raw: trimmed, reason: '缺少规则类型' };
  }

  if (kind === 'MATCH') {
    if (tokens.length < 2) return { valid: false, raw: trimmed, reason: 'MATCH 规则缺少目标动作' };
    return {
      valid: true,
      raw: trimmed,
      kind: 'MATCH',
      payload: '',
      action: tokens[1],
      actionIndex: 1,
      options: tokens.slice(2),
      tokens,
      isComplex: false,
      isMatch: true,
      isReject: tokens[1] === 'REJECT' || tokens[1] === 'REJECT-DROP',
      isDomestic: false
    };
  }

  if (tokens.length < 3) {
    return { valid: false, raw: trimmed, reason: '规则字段不足（至少需要 类型,匹配项,动作）' };
  }

  // 从末尾跳过可选修饰符（no-resolve / src）定位真实动作
  let actionIndex = tokens.length - 1;
  while (actionIndex > 1 && RULE_TRAILING_OPTIONS.has(tokens[actionIndex].toLowerCase())) {
    actionIndex--;
  }
  if (actionIndex < 2) {
    return { valid: false, raw: trimmed, reason: '无法定位规则动作列' };
  }

  const payload = tokens.slice(1, actionIndex).join(',');
  const action = tokens[actionIndex];
  const options = tokens.slice(actionIndex + 1);
  const isComplex = COMPLEX_RULE_KINDS.has(kind);
  const isReject = action === 'REJECT' || action === 'REJECT-DROP';
  const isDomestic =
    ((kind === 'GEOIP' || kind === 'GEOSITE') && payload.toLowerCase() === 'cn') ||
    (kind === 'DOMAIN-SUFFIX' && payload.toLowerCase() === 'cn');

  return {
    valid: true,
    raw: trimmed,
    kind,
    payload,
    action,
    actionIndex,
    options,
    tokens,
    isComplex,
    isMatch: false,
    isReject,
    isDomestic
  };
}

/**
 * 将上游订阅的原始规则按语法安全重映射：
 * - 保留 REJECT / REJECT-DROP（含 no-resolve 等后缀选项）
 * - 保留已有 PROCESS-* DIRECT 规则
 * - 保留国内 GEOIP/GEOSITE/DOMAIN-SUFFIX cn -> DIRECT
 * - 跳过 MATCH（由生成器在末尾统一追加）
 * - 遇到未确认的复杂复合规则（AND/OR/NOT/SUB-RULE）不静默改写，进入 flaggedComplexRules
 */
export function retargetUpstreamRules(rawRules, targetProxyName) {
  const list = Array.isArray(rawRules) ? rawRules : [];
  const rejectRules = [];
  const preservedDirectProcessRules = [];
  const routedRules = [];
  const flaggedComplexRules = [];
  const invalidRules = [];

  for (const line of list) {
    const parsed = parseMihomoRule(line);
    if (!parsed.valid) {
      if (!parsed.ignored) invalidRules.push({ raw: line, reason: parsed.reason });
      continue;
    }
    if (parsed.isMatch) continue;
    if (parsed.isComplex) {
      flaggedComplexRules.push({ raw: parsed.raw, kind: parsed.kind, action: parsed.action });
      continue;
    }
    if (parsed.isReject) {
      // 保留原始后缀选项（如 no-resolve）
      const rebuilt = [...parsed.tokens];
      rebuilt[parsed.actionIndex] = parsed.action;
      rejectRules.push(rebuilt.join(','));
      continue;
    }
    if (parsed.action === 'DIRECT' && /^PROCESS-(NAME|PATH)(-REGEX)?$/.test(parsed.kind)) {
      preservedDirectProcessRules.push(parsed.raw);
      continue;
    }
    const rebuilt = [...parsed.tokens];
    rebuilt[parsed.actionIndex] = parsed.isDomestic ? 'DIRECT' : targetProxyName;
    routedRules.push(rebuilt.join(','));
  }

  return {
    rejectRules: dedupeList(rejectRules),
    preservedDirectProcessRules: dedupeList(preservedDirectProcessRules),
    routedRules: dedupeList(routedRules),
    flaggedComplexRules,
    invalidRules
  };
}

export function dedupeList(items) {
  return [...new Set(items)];
}

export function formatCustomRule(rule, defaultChainTarget) {
  if (!rule || !rule.enabled) return null;
  const kind = String(rule.type || '').trim().toUpperCase();
  const payload = String(rule.payload || '').trim();
  const rawAction = String(rule.action || 'CHAIN').trim();
  if (!kind || !payload) return null;
  const action = rawAction === 'CHAIN' ? defaultChainTarget : rawAction;
  const parts = [kind, payload, action];
  if (rule.noResolve && (kind === 'IP-CIDR' || kind === 'IP-CIDR6' || kind === 'GEOIP')) {
    parts.push('no-resolve');
  }
  return parts.join(',');
}
