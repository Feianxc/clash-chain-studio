import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import vm from 'node:vm';

import { parseSubscriptionContent, parseYaml } from '../src/core/yaml-bridge.mjs';
import { LocalSecretVault } from '../src/core/vault.mjs';
import { createDefaultState, StateStore } from '../src/core/store.mjs';
import {
  normalizeSubscriptionProxies,
  parseMihomoRule,
  retargetUpstreamRules
} from '../src/core/rule-engine.mjs';
import {
  generateAndroidProfiles,
  generateDesktopStandaloneYaml,
  generateSharedRuntimeConfig,
  generateWindowsScript,
  validateCandidate
} from '../src/core/generators.mjs';
import {
  commitAndApplyVersion,
  rollbackWindowsToVersion
} from '../src/services/windows-service.mjs';
import {
  classifyAsnOrg,
  cleanSafeDisposableCache,
  evaluateTimezoneAlignment,
  inspectDisposableCaches
} from '../src/services/hygiene-service.mjs';
import { createAppServer } from '../src/server.mjs';

function makeTempDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

test('Rule engine: handles 0/1/N rules, no-resolve, REJECT preservation, and complex rule flagging', () => {
  // 0 rules
  const empty = retargetUpstreamRules([], 'NodeMaven-US-Chain');
  assert.deepEqual(empty.rejectRules, []);
  assert.deepEqual(empty.routedRules, []);
  assert.deepEqual(empty.flaggedComplexRules, []);

  // 1 rule
  const single = retargetUpstreamRules(['DOMAIN-SUFFIX,example.com,PROXY'], 'NodeMaven-US-Chain');
  assert.deepEqual(single.routedRules, ['DOMAIN-SUFFIX,example.com,NodeMaven-US-Chain']);

  // N rules with edge cases
  const mixed = retargetUpstreamRules([
    'IP-CIDR,198.51.100.0/24,REJECT,no-resolve',
    'DOMAIN-SUFFIX,ads.example.com,REJECT-DROP',
    'PROCESS-NAME,Steam.exe,DIRECT',
    'GEOIP,CN,PROXY,no-resolve',
    'GEOSITE,cn,PROXY',
    'DOMAIN-SUFFIX,github.com,AirportGroup',
    'AND,((PROCESS-NAME,com.test.app),(NETWORK,UDP)),REJECT',
    'MATCH,AirportGroup'
  ], 'NodeMaven-US-Chain');

  assert.deepEqual(mixed.rejectRules, [
    'IP-CIDR,198.51.100.0/24,REJECT,no-resolve',
    'DOMAIN-SUFFIX,ads.example.com,REJECT-DROP'
  ]);
  assert.deepEqual(mixed.preservedDirectProcessRules, ['PROCESS-NAME,Steam.exe,DIRECT']);
  assert.ok(mixed.routedRules.includes('GEOIP,CN,DIRECT,no-resolve'));
  assert.ok(mixed.routedRules.includes('GEOSITE,cn,DIRECT'));
  assert.ok(mixed.routedRules.includes('DOMAIN-SUFFIX,github.com,NodeMaven-US-Chain'));
  assert.equal(mixed.flaggedComplexRules.length, 1);
  assert.equal(mixed.flaggedComplexRules[0].kind, 'AND');

  // Verify nested parentheses parser directly
  const parsedAnd = parseMihomoRule('AND,((PROCESS-NAME,com.anthropic.claude),(NETWORK,UDP)),REJECT');
  assert.equal(parsedAnd.valid, true);
  assert.equal(parsedAnd.kind, 'AND');
  assert.equal(parsedAnd.action, 'REJECT');
  assert.equal(parsedAnd.isComplex, true);
});

test('Proxy normalizer: handles 0/1/N nodes and excludes info/chained/loopback/duplicate nodes', () => {
  // 0 nodes
  const zero = normalizeSubscriptionProxies([]);
  assert.equal(zero.nodes.length, 0);

  // 1 valid node
  const one = normalizeSubscriptionProxies([
    { name: '🇯🇵 Tokyo 1', type: 'ss', server: 'jp1.cheap-hop.example', port: 1443 }
  ]);
  assert.equal(one.nodes.length, 1);
  assert.deepEqual(one.nodeDomainPatterns, ['+.cheap-hop.example']);

  // N nodes with bad entries
  const many = normalizeSubscriptionProxies([
    { name: 'Traffic: 120GB left', type: 'ss', server: 'info.example.com', port: 443 },
    { name: '剩余流量：99GB', type: 'ss', server: 'info2.example.com', port: 443 },
    { name: 'DIRECT', type: 'direct', server: '1.1.1.1', port: 80 },
    { name: 'Chained-Node', type: 'http', server: 'chain.example.com', port: 8080, 'dialer-proxy': 'Other' },
    { name: 'Loopback-Node', type: 'ss', server: '127.0.0.1', port: 1080 },
    { name: '🇭🇰 HK 01', type: 'trojan', server: 'hk1.new-provider.net', port: 443 },
    { name: '🇭🇰 HK 01', type: 'trojan', server: 'hk1-dup.new-provider.net', port: 443 },
    { name: '🇸🇬 SG 02', type: 'ss', server: 'sg2.new-provider.net', port: 8443 }
  ]);

  assert.deepEqual(many.nodes.map(n => n.name), ['🇭🇰 HK 01', '🇸🇬 SG 02']);
  assert.equal(many.filteredOut.length, 6);
  assert.deepEqual(many.nodeDomainPatterns, ['+.new-provider.net']);
});

test('Windows Script.js execution + Android Dual Profiles: independent swap first-hop, static-exit, and both', () => {
  const tmpDir = makeTempDir('chain-studio-gen-');
  const vault = new LocalSecretVault(tmpDir);
  const state = createDefaultState();

  vault.setSecret('cred-exit-sample-us', {
    username: 'nm_user_real',
    password: 'nm_super_secret_password_123'
  });
  state.staticExits[0].server = '198.51.100.10';
  state.staticExits[0].expectedIp = '198.51.100.10';
  state.staticExits[0].isSample = false;

  // Scenario A: Swap ONLY first-hop subscription to a cheaper provider
  const cheapYaml = `
proxies:
  - name: "🇭🇰 便宜香港 01"
    type: ss
    server: hk01.budget-sub.org
    port: 20001
    cipher: aes-256-gcm
    password: hop_pass_secret_a
  - name: "🇯🇵 便宜日本 02"
    type: trojan
    server: jp02.budget-sub.org
    port: 443
    password: hop_pass_secret_b
rules:
  - DOMAIN-SUFFIX,github.com,BudgetGroup
  - DOMAIN-SUFFIX,ads.bad.com,REJECT
  - MATCH,BudgetGroup
`;
  const parsedCheap = parseSubscriptionContent(cheapYaml);
  const normCheap = normalizeSubscriptionProxies(parsedCheap.proxies);
  state.subscriptions.push({
    id: 'sub-budget',
    name: '便宜第一跳订阅',
    provider: 'BudgetVPN',
    sourceType: 'yaml',
    nodes: normCheap.nodes,
    filteredOut: normCheap.filteredOut,
    rawRules: parsedCheap.rules,
    nodeDomains: normCheap.nodeDomainPatterns,
    isSample: false,
    updatedAt: new Date().toISOString()
  });
  state.activeBinding.subscriptionId = 'sub-budget';
  state.activeBinding.selectedFirstHops = ['🇯🇵 便宜日本 02', '🇭🇰 便宜香港 01'];
  state.activeBinding.primaryFirstHop = '🇯🇵 便宜日本 02';

  const checkA = validateCandidate(state, vault);
  assert.equal(checkA.valid, true, `Validation errors: ${checkA.errors.join(', ')}`);

  // Generate & EXECUTE Windows Script.js in isolated VM!
  const winA = generateWindowsScript(state, vault, 'v20261123-001');
  assert.ok(!winA.redactedContent.includes('nm_super_secret_password_123'), 'Redacted script must not leak password');
  assert.ok(winA.content.includes('nm_super_secret_password_123'), 'Real script should include credential for local Mihomo');

  const sandbox = {};
  vm.createContext(sandbox);
  vm.runInContext(winA.content, sandbox);
  const mockSubConfig = {
    proxies: structuredClone(normCheap.nodes),
    'proxy-groups': [{ name: 'BudgetGroup', type: 'select', proxies: ['🇭🇰 便宜香港 01', '🇯🇵 便宜日本 02'] }],
    rules: [...parsedCheap.rules]
  };
  const outConfig = sandbox.main(mockSubConfig, 'Budget');

  assert.equal(outConfig.mode, 'rule');
  assert.equal(outConfig.ipv6, false);
  assert.equal(outConfig.tun.enable, false);
  assert.equal(outConfig.rules[0], 'IN-NAME,Static-Exit-Upstream,Static-Exit-Raw');
  assert.equal(outConfig.rules[outConfig.rules.length - 1], 'MATCH,Static-Exit-Chain');
  assert.ok(outConfig.rules.indexOf('DOMAIN-SUFFIX,google.cn,Static-Exit-Chain') < outConfig.rules.indexOf('GEOSITE,cn,DIRECT'));
  assert.ok(outConfig.rules.indexOf('DOMAIN-SUFFIX,claude.ai,Static-Exit-Chain') < outConfig.rules.indexOf('GEOSITE,cn,DIRECT'));
  assert.ok(outConfig.rules.includes('DOMAIN-SUFFIX,autopatchcn.yuanshen.com,DIRECT'));
  assert.ok(outConfig.rules.includes('DOMAIN-SUFFIX,ads.bad.com,REJECT'));
  assert.ok(outConfig.dns['nameserver-policy']['+.budget-sub.org'], 'New provider node domain must be in DNS policy');

  // Verify universal Desktop-Static-Chain.yaml
  const desktopA = generateDesktopStandaloneYaml(state, vault, 'v20261123-001');
  const desktopDoc = parseYaml(desktopA.yamlText);
  assert.equal(desktopDoc.rules[0], 'IN-NAME,Static-Exit-Upstream,Static-Exit-Raw');
  assert.equal(desktopDoc.rules[desktopDoc.rules.length - 1], 'MATCH,Static-Exit-Chain');
  assert.ok(!desktopA.redactedYaml.includes('nm_super_secret_password_123'));

  const firstHopGroup = outConfig['proxy-groups'].find(g => g.name === 'Static-First-Hop');
  assert.deepEqual([...firstHopGroup.proxies], ['🇯🇵 便宜日本 02', '🇭🇰 便宜香港 01']);
  assert.ok(!firstHopGroup.proxies.includes('DIRECT'));

  // Scenario B: Swap ONLY static exit to a different IP (node server != expected public IP)
  vault.setSecret('cred-exit-new', { username: 'new_static_u', password: 'new_static_p' });
  state.staticExits.push({
    id: 'exit-new-ip',
    name: '新美国静态出口',
    provider: 'NewProvider',
    server: 'gate.new-static.example',
    port: 10800,
    expectedIp: '198.51.100.77',
    region: 'US / Los Angeles',
    timeZone: 'America/Los_Angeles',
    windowsProtocol: 'http',
    androidProtocol: 'socks5',
    androidUdp: false,
    credentialRef: 'cred-exit-new',
    isSample: false
  });
  state.activeBinding.staticExitId = 'exit-new-ip';

  const androidB = generateAndroidProfiles(state, vault, 'v20261123-002');
  const dailyDoc = parseYaml(androidB.daily.yamlText);
  const dedicatedDoc = parseYaml(androidB.dedicated.yamlText);

  // Verify shared invariants on BOTH Android profiles
  for (const doc of [dailyDoc, dedicatedDoc]) {
    assert.equal(doc.ipv6, false);
    assert.equal(doc['mixed-port'], 7890);
    assert.deepEqual(doc.dns['proxy-server-nameserver'], ['udp://127.0.0.1:7874']);
    assert.ok(doc.dns['nameserver-policy']['+.budget-sub.org']);
    assert.ok(doc.dns['nameserver-policy']['+.new-static.example']);
    const exitProxy = doc.proxies.find(p => p.name === 'Static-Exit-SOCKS5');
    assert.equal(exitProxy.type, 'socks5');
    assert.equal(exitProxy.udp, false);
    assert.equal(exitProxy.server, 'gate.new-static.example');
    assert.equal(exitProxy.port, 10800);
    assert.equal(exitProxy['dialer-proxy'], 'Static-First-Hop');
    const goLoginListener = doc.listeners.find(l => l.name === 'Dedicated-Static-In');
    assert.equal(goLoginListener.port, 17990);
    // Protected app UDP guard before GEOSITE,cn,DIRECT
    const claudeUdpIdx = doc.rules.indexOf('AND,((PROCESS-NAME,com.anthropic.claude),(NETWORK,UDP)),REJECT');
    const cnIdx = doc.rules.indexOf('GEOSITE,cn,DIRECT');
    assert.ok(claudeUdpIdx > 0 && claudeUdpIdx < cnIdx);
    assert.equal(doc.rules[doc.rules.length - 1], 'MATCH,Static-Exit-SOCKS5');
  }

  // Verify Daily vs Dedicated browser rule distinction
  assert.ok(!dailyDoc.rules.includes('PROCESS-NAME,com.android.chrome,Static-Exit-SOCKS5'), 'Daily must NOT override Chrome');
  assert.ok(dedicatedDoc.rules.includes('PROCESS-NAME,com.android.chrome,Static-Exit-SOCKS5'), 'Dedicated MUST override Chrome');
  assert.ok(dedicatedDoc.rules.includes('AND,((PROCESS-NAME,com.mmbox.xbrowser),(NETWORK,UDP)),REJECT'), 'Dedicated MUST block xbrowser UDP');

  // Verify redacted Android YAML hides secrets
  assert.ok(!androidB.daily.redactedYaml.includes('new_static_p'));
  assert.ok(!androidB.daily.redactedYaml.includes('hop_pass_secret_a'));

  // Shared runtime config carries updated expectedIp
  const runtimeCfg = generateSharedRuntimeConfig(state, 'v20261123-002');
  assert.equal(runtimeCfg.expectedIp, '198.51.100.77');

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test('Validation blocks bad expected IP, port collision, empty group, and DIRECT injection', () => {
  const tmpDir = makeTempDir('chain-studio-val-');
  const vault = new LocalSecretVault(tmpDir);
  const state = createDefaultState();

  // Bad IP
  state.staticExits[0].expectedIp = 'not-an-ip';
  let res = validateCandidate(state, vault);
  assert.equal(res.valid, false);
  assert.ok(res.errors.some(e => e.includes('预期公网 IP')));

  // Port collision
  state.staticExits[0].expectedIp = '203.0.113.10';
  state.rulePresets[0].windowsOptions.relayPort = 17901;
  res = validateCandidate(state, vault);
  assert.equal(res.valid, false);
  assert.ok(res.errors.some(e => e.includes('端口冲突')));

  // DIRECT in Static-First-Hop
  state.rulePresets[0].windowsOptions.relayPort = 17902;
  state.activeBinding.selectedFirstHops = ['DIRECT'];
  res = validateCandidate(state, vault);
  assert.equal(res.valid, false);
  assert.ok(res.errors.some(e => e.includes('DIRECT')));

  // Missing renamed node
  state.activeBinding.selectedFirstHops = ['已改名的旧节点'];
  res = validateCandidate(state, vault);
  assert.equal(res.valid, false);
  assert.ok(res.errors.some(e => e.includes('不存在')));

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test('Atomic apply + backup + rollback restores exact original Script.js', () => {
  const tmpRoot = makeTempDir('chain-studio-apply-');
  const mockVergeDir = path.join(tmpRoot, 'mock-clash-verge');
  const profilesDir = path.join(mockVergeDir, 'profiles');
  fs.mkdirSync(profilesDir, { recursive: true });
  const originalScript = '// Original user Clash Verge Script.js\nfunction main(c) { return c; }\n';
  fs.writeFileSync(path.join(profilesDir, 'Script.js'), originalScript, 'utf8');

  const vault = new LocalSecretVault(path.join(tmpRoot, 'data'));
  const state = createDefaultState();
  state.deviceBindings.windows.clashVergeDir = mockVergeDir;

  const { versionRecord } = commitAndApplyVersion({
    state,
    vault,
    projectRoot: tmpRoot,
    versionId: 'v20261123-001',
    applyToClashVerge: true
  });

  assert.equal(versionRecord.windowsStatus, 'applied');
  assert.ok(fs.existsSync(versionRecord.backupPath));
  assert.ok(fs.existsSync(versionRecord.files.androidDaily));
  assert.ok(fs.existsSync(versionRecord.files.androidDedicated));

  const appliedContent = fs.readFileSync(path.join(profilesDir, 'Script.js'), 'utf8');
  assert.ok(appliedContent.includes('Generated by Clash Chain Studio'));
  assert.notEqual(appliedContent, originalScript);

  // Rollback
  const rb = rollbackWindowsToVersion(state, versionRecord);
  assert.equal(rb.status, 'rolled-back');
  const restoredContent = fs.readFileSync(path.join(profilesDir, 'Script.js'), 'utf8');
  assert.equal(restoredContent, originalScript);

  fs.rmSync(tmpRoot, { recursive: true, force: true });
});

test('HTTP Server end-to-end API flow & secret redaction', async () => {
  const { Readable } = await import('node:stream');
  const tmpProject = makeTempDir('chain-studio-http-');
  fs.cpSync(path.resolve('public'), path.join(tmpProject, 'public'), { recursive: true });

  const { handleRequest } = createAppServer({ projectRoot: tmpProject });

  async function invoke(method, urlPath, bodyObj = null) {
    const rawBody = bodyObj !== null ? Buffer.from(JSON.stringify(bodyObj), 'utf8') : Buffer.alloc(0);
    const req = Readable.from(rawBody.length ? [rawBody] : []);
    req.method = method;
    req.url = urlPath;
    req.headers = { 'content-type': 'application/json' };

    return new Promise((resolve, reject) => {
      let status = 200;
      let headers = {};
      const chunks = [];
      const res = {
        writeHead(code, hdrs = {}) { status = code; headers = hdrs; },
        end(data) {
          if (data) chunks.push(Buffer.isBuffer(data) ? data : Buffer.from(String(data)));
          const text = Buffer.concat(chunks).toString('utf8');
          resolve({ status, headers, text, json: () => JSON.parse(text) });
        }
      };
      Promise.resolve(handleRequest(req, res)).catch(reject);
    });
  }

  try {
    // Static UI
    const htmlRes = await invoke('GET', '/');
    assert.equal(htmlRes.status, 200);
    assert.ok(htmlRes.text.includes('Chain Studio'));

    const cssRes = await invoke('GET', '/styles.css');
    assert.equal(cssRes.status, 200);

    const jsRes = await invoke('GET', '/app.js');
    assert.equal(jsRes.status, 200);

    // Bootstrap
    const bootRes = await invoke('GET', '/api/bootstrap');
    assert.equal(bootRes.status, 200);
    const boot = bootRes.json();
    assert.equal(boot.preview.valid, true);

    // Add a static exit with secret password
    const addExitRes = await invoke('POST', '/api/static-exits', {
      name: 'Test US Static',
      server: '198.51.100.88',
      port: 5432,
      expectedIp: '198.51.100.88',
      username: 'secret_user_xyz',
      password: 'ultra_secret_password_999',
      activate: true
    });
    assert.equal(addExitRes.status, 200);
    assert.ok(!addExitRes.text.includes('ultra_secret_password_999'));

    // Generate version (dry-run output only)
    const applyRes = await invoke('POST', '/api/apply', { applyToClashVerge: false });
    assert.equal(applyRes.status, 200);
    const applyJson = applyRes.json();
    const verId = applyJson.version.versionId;

    // Download generated Desktop YAML + Android Daily & Dedicated YAML
    const dlDesktop = await invoke('GET', `/api/download/${verId}/Desktop-Static-Chain.yaml`);
    assert.equal(dlDesktop.status, 200);
    assert.ok(dlDesktop.text.includes('Static-Exit-Raw'));

    const dlDaily = await invoke('GET', `/api/download/${verId}/Daily-Static-Chain.yaml`);
    assert.equal(dlDaily.status, 200);
    assert.ok(dlDaily.text.includes('Static-Exit-SOCKS5'));
    assert.ok(!dlDaily.text.includes('PROCESS-NAME,com.android.chrome,Static-Exit-SOCKS5'));

    const dlDedicated = await invoke('GET', `/api/download/${verId}/Claude-GoLogin-Static.yaml`);
    assert.equal(dlDedicated.status, 200);
    assert.ok(dlDedicated.text.includes('PROCESS-NAME,com.android.chrome,Static-Exit-SOCKS5'));

    // Relay status endpoint
    const relayRes = await invoke('GET', '/api/relay/status');
    assert.equal(relayRes.status, 200);
    assert.equal(typeof relayRes.json().running, 'boolean');

    // Export redacted diagnostic report — verify zero secret leakage
    const repRes = await invoke('GET', '/api/report/export');
    assert.equal(repRes.status, 200);
    assert.ok(!repRes.text.includes('ultra_secret_password_999'));
    assert.ok(!repRes.text.includes('secret_user_xyz'));

    // Hygiene endpoints: caches read + clean requires explicit confirm:true
    const cacheRes = await invoke('GET', '/api/hygiene/caches');
    assert.equal(cacheRes.status, 200);
    const cleanReject = await invoke('POST', '/api/hygiene/clean-cache', { targetIds: ['claude-http-cache'] });
    assert.equal(cleanReject.status, 400);
  } finally {
    fs.rmSync(tmpProject, { recursive: true, force: true });
  }
});

test('Hygiene service: ASN classification, timezone alignment, and safe cache boundary guard', () => {
  // ASN classification
  assert.equal(classifyAsnOrg('AS6079 RCN').suspicious, false);
  assert.equal(classifyAsnOrg('AS16509 Amazon.com, Inc.').suspicious, true);
  assert.equal(classifyAsnOrg('AS14061 DigitalOcean, LLC').suspicious, true);

  // Timezone alignment: matching vs mismatched
  const okTz = evaluateTimezoneAlignment({
    targetIana: 'America/Chicago',
    windowsTz: 'Central Standard Time',
    windowsLocale: 'en-US',
    userEnv: { TZ: 'America/Chicago' },
    claudeSettings: { readable: true, timeZone: 'America/Chicago', envTz: 'America/Chicago' },
    envMode: { mode: 'Claude' }
  });
  assert.equal(okTz.status, 'pass');
  assert.equal(okTz.issues.length, 0);

  const badTz = evaluateTimezoneAlignment({
    targetIana: 'America/Chicago',
    windowsTz: 'China Standard Time',
    windowsLocale: 'zh-CN',
    userEnv: { TZ: 'Asia/Shanghai' },
    claudeSettings: { readable: true, timeZone: 'Asia/Shanghai', envTz: 'Asia/Shanghai' },
    envMode: { mode: 'China' }
  });
  assert.equal(badTz.status, 'fail');
  assert.ok(badTz.issues.length >= 4);

  // Safe cache cleanup: preserves Cookies/config.json and blocks when Claude is running
  const fakeAppData = makeTempDir('chain-studio-cache-');
  const claudeDir = path.join(fakeAppData, 'Claude');
  fs.mkdirSync(path.join(claudeDir, 'Cache'), { recursive: true });
  fs.mkdirSync(path.join(claudeDir, 'Network'), { recursive: true });
  fs.writeFileSync(path.join(claudeDir, 'Cache', 'temp.bin'), '123456', 'utf8');
  fs.writeFileSync(path.join(claudeDir, 'Network', 'Cookies'), 'KEEP_LOGIN_TOKEN', 'utf8');
  fs.writeFileSync(path.join(claudeDir, 'config.json'), '{"keep":true}', 'utf8');

  const scanned = inspectDisposableCaches(fakeAppData);
  const httpCache = scanned.find(x => x.id === 'claude-http-cache');
  assert.equal(httpCache.totalFiles, 1);

  // Refuses while Claude is running
  assert.throws(() => {
    cleanSafeDisposableCache({
      targetIds: ['claude-http-cache'],
      baseAppData: fakeAppData,
      activeProcessNames: ['claude']
    });
  }, /仍在运行/);
  assert.ok(fs.existsSync(path.join(claudeDir, 'Cache', 'temp.bin')));

  // Cleans ONLY whitelisted Cache when Claude is closed, preserving Cookies & config.json
  const cleaned = cleanSafeDisposableCache({
    targetIds: ['claude-http-cache'],
    baseAppData: fakeAppData,
    activeProcessNames: []
  });
  assert.equal(cleaned.status, 'pass');
  assert.equal(fs.existsSync(path.join(claudeDir, 'Cache')), false);
  assert.equal(fs.readFileSync(path.join(claudeDir, 'Network', 'Cookies'), 'utf8'), 'KEEP_LOGIN_TOKEN');
  assert.equal(fs.readFileSync(path.join(claudeDir, 'config.json'), 'utf8'), '{"keep":true}');

  fs.rmSync(fakeAppData, { recursive: true, force: true });
});
