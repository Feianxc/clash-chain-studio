import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { writeFileAtomic } from './vault.mjs';

export function createDefaultState() {
  const userProfile = os.homedir();
  const appData = process.env.APPDATA || path.join(userProfile, 'AppData', 'Roaming');
  const defaultClashVergeDir = process.platform === 'win32'
    ? path.join(appData, 'io.github.clash-verge-rev.clash-verge-rev')
    : path.join(userProfile, '.config', 'io.github.clash-verge-rev.clash-verge-rev');

  return {
    schemaVersion: 2,
    updatedAt: new Date().toISOString(),
    subscriptions: [
      {
        id: 'sub-sample-starter',
        name: '示例订阅（点击「从本机导入」或导入您的订阅）',
        provider: '示例 / 支持任意 Clash 或 Mihomo 订阅',
        sourceType: 'sample',
        urlRef: null,
        priceNote: '可记录套餐价格与月流量',
        trafficInfo: '示例快照 · 不含真实凭据',
        updatedAt: new Date().toISOString(),
        nodes: [
          {
            id: 'node-tw-demo',
            name: '🇹🇼 台湾节点 01 (示例)',
            type: 'ss',
            server: 'tw1.example-hop.invalid',
            port: 10002,
            cipher: 'aes-256-gcm',
            password: 'SAMPLE_NODE_PASSWORD',
            udp: true
          },
          {
            id: 'node-hk-demo',
            name: '🇭🇰 香港节点 01 (示例)',
            type: 'ss',
            server: 'hk1.example-hop.invalid',
            port: 10001,
            cipher: 'aes-256-gcm',
            password: 'SAMPLE_NODE_PASSWORD',
            udp: true
          },
          {
            id: 'node-jp-demo',
            name: '🇯🇵 日本节点 01 (示例)',
            type: 'ss',
            server: 'jp1.example-hop.invalid',
            port: 10005,
            cipher: 'aes-256-gcm',
            password: 'SAMPLE_NODE_PASSWORD',
            udp: true
          }
        ],
        filteredOut: [],
        rawRules: [
          'DOMAIN-SUFFIX,github.com,PROXY',
          'DOMAIN-SUFFIX,githubusercontent.com,PROXY',
          'DOMAIN-SUFFIX,youtube.com,PROXY',
          'DOMAIN-SUFFIX,doubleclick.net,REJECT',
          'GEOIP,CN,DIRECT',
          'MATCH,PROXY'
        ],
        nodeDomains: ['tw1.example-hop.invalid', 'hk1.example-hop.invalid', 'jp1.example-hop.invalid'],
        isSample: true
      }
    ],
    staticExits: [
      {
        id: 'exit-sample-us',
        name: '美国静态住宅 IP (示例占位)',
        provider: 'Static Residential ISP',
        server: '203.0.113.10',
        port: 5432,
        expectedIp: '203.0.113.10',
        region: 'US / Dallas',
        timeZone: 'America/Chicago',
        windowsProtocol: 'http',
        androidProtocol: 'socks5',
        androidUdp: false,
        credentialRef: 'cred-exit-sample-us',
        notes: 'RFC 5737 文档示例地址。请点击「从本机导入」或编辑填入您的真实静态住宅代理地址、端口、凭据与预期公网 IP。',
        isSample: true,
        updatedAt: new Date().toISOString()
      }
    ],
    activeBinding: {
      subscriptionId: 'sub-sample-starter',
      staticExitId: 'exit-sample-us',
      selectedFirstHops: [
        '🇹🇼 台湾节点 01 (示例)',
        '🇭🇰 香港节点 01 (示例)'
      ],
      primaryFirstHop: '🇹🇼 台湾节点 01 (示例)',
      rulePresetId: 'preset-default-chain'
    },
    rulePresets: [
      {
        id: 'preset-default-chain',
        name: '默认链式规则（国内/游戏直连 · AI与海外走静链）',
        windowsOptions: {
          mixedPort: 7897,
          upstreamPort: 17901,
          relayPort: 17902,
          dnsListen: '127.0.0.1:7874',
          ipv6: false,
          tunEnable: false,
          allowLan: false,
          rawProxyName: 'Static-Exit-Raw',
          frontendProxyName: 'Static-Exit-Chain',
          firstHopGroupName: 'Static-First-Hop',
          upstreamListenerName: 'Static-Exit-Upstream',
          domesticDns: ['119.29.29.29', '223.5.5.5']
        },
        androidOptions: {
          mixedPort: 7890,
          dedicatedListenerPort: 17990,
          dedicatedListenerName: 'Dedicated-Static-In',
          controllerPort: 19090,
          ipv6: false,
          allowLan: false,
          proxyName: 'Static-Exit-SOCKS5',
          firstHopGroupName: 'Static-First-Hop',
          mobileDnsMode: 'local-clash-7874',
          dnsListen: '127.0.0.1:7874',
          domesticDns: ['223.5.5.5', '119.29.29.29'],
          includeControllerInExport: false
        },
        gameDirectRules: [
          { id: 'game-steam', type: 'DOMAIN-SUFFIX', payload: 'steamcontent.com', action: 'DIRECT', enabled: true, note: 'Steam 游戏下载直连' },
          { id: 'game-bh3', type: 'DOMAIN-SUFFIX', payload: 'autopatchcn.bh3.com', action: 'DIRECT', enabled: true, note: '国内游戏补丁 CDN (bh3)' },
          { id: 'game-bhsr', type: 'DOMAIN-SUFFIX', payload: 'autopatchcn.bhsr.com', action: 'DIRECT', enabled: true, note: '国内游戏补丁 CDN (bhsr)' },
          { id: 'game-zzz', type: 'DOMAIN-SUFFIX', payload: 'autopatchcn.juequling.com', action: 'DIRECT', enabled: true, note: '国内游戏补丁 CDN (zzz)' },
          { id: 'game-ys', type: 'DOMAIN-SUFFIX', payload: 'autopatchcn.yuanshen.com', action: 'DIRECT', enabled: true, note: '国内游戏补丁 CDN (yuanshen)' }
        ],
        protectedDomains: [
          { id: 'dom-openai', type: 'DOMAIN-SUFFIX', payload: 'openai.com', enabled: true, scope: 'both', note: 'OpenAI' },
          { id: 'dom-chatgpt', type: 'DOMAIN-SUFFIX', payload: 'chatgpt.com', enabled: true, scope: 'both', note: 'ChatGPT' },
          { id: 'dom-oaistatic', type: 'DOMAIN-SUFFIX', payload: 'oaistatic.com', enabled: true, scope: 'both', note: 'OpenAI 静态资源' },
          { id: 'dom-oaiuser', type: 'DOMAIN-SUFFIX', payload: 'oaiusercontent.com', enabled: true, scope: 'both', note: 'OpenAI 用户资源' },
          { id: 'dom-claude-ai', type: 'DOMAIN-SUFFIX', payload: 'claude.ai', enabled: true, scope: 'both', note: 'Claude Web' },
          { id: 'dom-claude-com', type: 'DOMAIN-SUFFIX', payload: 'claude.com', enabled: true, scope: 'both', note: 'Claude 登录与 OAuth' },
          { id: 'dom-anthropic', type: 'DOMAIN-SUFFIX', payload: 'anthropic.com', enabled: true, scope: 'both', note: 'Anthropic API' },
          { id: 'dom-claudeuser', type: 'DOMAIN-SUFFIX', payload: 'claudeusercontent.com', enabled: true, scope: 'both', note: 'Claude 资源' },
          { id: 'dom-claudemcp', type: 'DOMAIN-SUFFIX', payload: 'claudemcpclient.com', enabled: true, scope: 'both', note: 'Claude MCP' },
          { id: 'dom-auth0', type: 'DOMAIN', payload: 'anthropic.auth0.com', enabled: true, scope: 'both', note: 'Anthropic Auth0' },
          { id: 'dom-antigravity', type: 'DOMAIN-SUFFIX', payload: 'antigravity.google', enabled: true, scope: 'both', note: 'Antigravity' },
          { id: 'dom-google-com', type: 'DOMAIN-SUFFIX', payload: 'google.com', enabled: true, scope: 'both', note: 'Google 主域' },
          { id: 'dom-google-cn', type: 'DOMAIN-SUFFIX', payload: 'google.cn', enabled: true, scope: 'both', note: 'Google CN（优先于国内直连）' },
          { id: 'dom-googleapis', type: 'DOMAIN-SUFFIX', payload: 'googleapis.com', enabled: true, scope: 'both', note: 'Google APIs' },
          { id: 'dom-googleapis-cn', type: 'DOMAIN-SUFFIX', payload: 'googleapis.cn', enabled: true, scope: 'both', note: 'Google APIs CN' },
          { id: 'dom-googleapis-cn2', type: 'DOMAIN-SUFFIX', payload: 'googleapis-cn.com', enabled: true, scope: 'both', note: 'Google APIs CN 域' },
          { id: 'dom-gstatic', type: 'DOMAIN-SUFFIX', payload: 'gstatic.com', enabled: true, scope: 'both', note: 'Google 静态资源' },
          { id: 'dom-googleusercontent', type: 'DOMAIN-SUFFIX', payload: 'googleusercontent.com', enabled: true, scope: 'both', note: 'Google 用户资源' },
          { id: 'dom-geosite-google', type: 'GEOSITE', payload: 'google', enabled: true, scope: 'windows', note: 'Google Geosite' },
          { id: 'dom-accounts-google', type: 'DOMAIN', payload: 'accounts.google.com', enabled: true, scope: 'both', note: 'Google 登录' }
        ],
        windowsProcesses: [
          {
            id: 'win-proc-ai',
            type: 'PROCESS-NAME-REGEX',
            payload: '(?i)^(?:codex|chatgpt|claude|claude-code)\\.exe$',
            enabled: true,
            note: 'Codex / ChatGPT / Claude / Claude Code 桌面与 CLI'
          }
        ],
        androidCoreApps: [
          { id: 'app-claude', packageName: 'com.anthropic.claude', label: 'Claude App', blockUdp: true, enabled: true },
          { id: 'app-gologin', packageName: 'com.gologin.gologin_mobile', label: 'GoLogin Mobile', blockUdp: true, enabled: true }
        ],
        androidBrowserApps: [
          { id: 'app-xbrowser', packageName: 'com.mmbox.xbrowser', label: 'X 浏览器', blockUdp: true, enabled: true },
          { id: 'app-chrome', packageName: 'com.android.chrome', label: 'Chrome', blockUdp: true, enabled: true },
          { id: 'app-edge', packageName: 'com.microsoft.emmx', label: 'Edge', blockUdp: true, enabled: true },
          { id: 'app-nubia', packageName: 'cn.nubia.browser', label: '设备内置浏览器', blockUdp: true, enabled: true }
        ],
        customRules: []
      }
    ],
    deviceBindings: {
      windows: {
        clashVergeDir: defaultClashVergeDir,
        claudeLocalDir: '',
        claudeEnvScriptsDir: '',
        currentVersion: null,
        lastAppliedAt: null,
        lastVerifiedAt: null,
        status: 'not run'
      },
      android: {
        deviceSerial: null,
        deviceModel: null,
        activeProfile: null,
        dailyStatus: 'not run',
        dedicatedStatus: 'not run',
        dailyVersion: null,
        dedicatedVersion: null,
        lastVerifiedAt: null
      }
    },
    versions: [],
    probeHistory: [],
    benchmarks: []
  };
}

export class StateStore {
  constructor(dataDir) {
    this.dataDir = dataDir;
    this.statePath = path.join(dataDir, 'state.json');
    this.lockPath = path.join(dataDir, 'state.lock');
    fs.mkdirSync(dataDir, { recursive: true });
    if (!fs.existsSync(this.statePath)) {
      this.save(createDefaultState());
    }
  }

  load() {
    const raw = fs.readFileSync(this.statePath, 'utf8');
    return JSON.parse(raw);
  }

  save(state) {
    state.updatedAt = new Date().toISOString();
    writeFileAtomic(this.statePath, JSON.stringify(state, null, 2));
    return state;
  }

  /**
   * 互斥更新状态文件，防止并发修改相互覆盖。
   */
  update(mutator) {
    const fd = this.#acquireLock();
    try {
      const state = this.load();
      const result = mutator(state);
      this.save(state);
      return result !== undefined ? result : state;
    } finally {
      this.#releaseLock(fd);
    }
  }

  #acquireLock(timeoutMs = 5000) {
    const start = Date.now();
    while (true) {
      try {
        return fs.openSync(this.lockPath, 'wx');
      } catch (err) {
        if (err.code !== 'EEXIST') throw err;
        // 检测陈旧锁（超过 30 秒视作异常残留）
        try {
          const stat = fs.statSync(this.lockPath);
          if (Date.now() - stat.mtimeMs > 30000) {
            fs.unlinkSync(this.lockPath);
            continue;
          }
        } catch { /* ignore */ }
        if (Date.now() - start > timeoutMs) {
          throw new Error('状态写入锁竞争超时，请稍后重试');
        }
        const wait = new Int32Array(new SharedArrayBuffer(4));
        Atomics.wait(wait, 0, 0, 25);
      }
    }
  }

  #releaseLock(fd) {
    try { fs.closeSync(fd); } catch { /* ignore */ }
    try { fs.unlinkSync(this.lockPath); } catch { /* ignore */ }
  }

  static nextId(prefix) {
    return `${prefix}-${crypto.randomBytes(4).toString('hex')}`;
  }

  static nextVersionId(existingVersions = []) {
    const now = new Date();
    const pad = n => String(n).padStart(2, '0');
    const datePart = `${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}`;
    const todayPrefix = `v${datePart}-`;
    const todayNums = existingVersions
      .map(v => v.versionId)
      .filter(id => typeof id === 'string' && id.startsWith(todayPrefix))
      .map(id => Number(id.slice(todayPrefix.length)))
      .filter(Number.isFinite);
    const nextSeq = (todayNums.length ? Math.max(...todayNums) : 0) + 1;
    return `${todayPrefix}${String(nextSeq).padStart(3, '0')}`;
  }
}
