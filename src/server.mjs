import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';

import { StateStore } from './core/store.mjs';
import { LocalSecretVault } from './core/vault.mjs';
import { parseSubscriptionContent } from './core/yaml-bridge.mjs';
import { normalizeSubscriptionProxies } from './core/rule-engine.mjs';
import { generateSharedRuntimeConfig, validateCandidate } from './core/generators.mjs';
import {
  buildCandidatePreview,
  commitAndApplyVersion,
  discoverClashVergeController,
  importFromLocalClashVerge,
  inspectWindowsEnvironment,
  rollbackWindowsToVersion,
  triggerExistingLauncher
} from './services/windows-service.mjs';
import {
  benchmarkFirstHops,
  fetchSubscriptionFromUrl,
  probeProxyEndpoint,
  probeRelayHealth
} from './services/probe-service.mjs';
import {
  checkAndroidPackages,
  inspectAndroidReadOnly,
  listAdbDevices,
  pushProfilesToAndroid,
  selectAndroidFirstHop
} from './services/adb-service.mjs';
import {
  cleanSafeDisposableCache,
  inspectDisposableCaches,
  listRunningTargetProcesses,
  runFullEnvironmentAudit
} from './services/hygiene-service.mjs';
import { RelayManager } from './services/relay-manager.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PROJECT_ROOT = path.resolve(__dirname, '..');

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.mjs': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.yaml': 'text/yaml; charset=utf-8',
  '.yml': 'text/yaml; charset=utf-8'
};

function sanitizeStateForClient(state, vault) {
  return {
    ...state,
    subscriptions: state.subscriptions.map((sub) => ({
      ...sub,
      hasUrl: Boolean(sub.urlRef && vault.hasSecret(sub.urlRef)),
      nodeCount: Array.isArray(sub.nodes) ? sub.nodes.length : 0,
      nodes: (sub.nodes || []).map((n) => ({
        name: n.name,
        type: n.type,
        server: n.server,
        port: n.port,
        udp: n.udp
      }))
    })),
    staticExits: state.staticExits.map((exit) => {
      const cred = exit.credentialRef ? vault.getSecret(exit.credentialRef) : null;
      return {
        ...exit,
        hasCredentials: Boolean(cred?.username && cred?.password),
        usernamePreview: cred?.username ? maskMiddle(cred.username) : ''
      };
    })
  };
}

function maskMiddle(str) {
  const s = String(str || '');
  if (s.length <= 4) return '****';
  return `${s.slice(0, 2)}***${s.slice(-2)}`;
}

function readJsonBody(req, maxBytes = 8 * 1024 * 1024) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    req.on('data', (chunk) => {
      total += chunk.length;
      if (total > maxBytes) {
        req.destroy();
        reject(new Error('请求体超过大小限制 (8MB)'));
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (chunks.length === 0) return resolve({});
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      } catch {
        reject(new Error('请求体不是合法 JSON'));
      }
    });
    req.on('error', reject);
  });
}

function sendJson(res, statusCode, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store'
  });
  res.end(body);
}

function getLocalLanAddresses() {
  const nets = os.networkInterfaces();
  const ips = [];
  for (const list of Object.values(nets)) {
    for (const info of list || []) {
      if (info.family === 'IPv4' && !info.internal) {
        ips.push(info.address);
      }
    }
  }
  return ips;
}

export function createAppServer({ projectRoot = PROJECT_ROOT } = {}) {
  const dataDir = path.join(projectRoot, 'data');
  const publicDir = path.join(projectRoot, 'public');
  const store = new StateStore(dataDir);
  const vault = new LocalSecretVault(dataDir);
  const relayManager = new RelayManager(projectRoot);
  const serverStartedAt = new Date().toISOString();

  const handleRequest = async (req, res) => {
    const url = new URL(req.url || '/', 'http://127.0.0.1');
    const pathname = decodeURIComponent(url.pathname);
    const method = req.method || 'GET';

    try {
      // --- API Routes ---
      if (pathname === '/api/health' && method === 'GET') {
        return sendJson(res, 200, {
          ok: true,
          service: 'ClashChainStudio',
          buildVersion: '2026-11-23.3',
          pid: process.pid,
          startedAt: serverStartedAt,
          time: new Date().toISOString()
        });
      }

      if (pathname === '/api/bootstrap' && method === 'GET') {
        const state = store.load();
        const winEnv = await inspectWindowsEnvironment(state);
        const nextVer = StateStore.nextVersionId(state.versions);
        const validation = validateCandidate(state, vault);
        const sharedRuntime = validation.valid ? generateSharedRuntimeConfig(state, nextVer) : null;
        return sendJson(res, 200, {
          state: sanitizeStateForClient(state, vault),
          windowsEnv: winEnv,
          preview: {
            valid: validation.valid,
            versionId: nextVer,
            validation,
            sharedRuntime
          },
          lanIps: getLocalLanAddresses()
        });
      }

      if (pathname === '/api/preview' && method === 'GET') {
        const state = store.load();
        const nextVer = StateStore.nextVersionId(state.versions);
        const preview = buildCandidatePreview(state, vault, nextVer);
        return sendJson(res, 200, preview);
      }

      // 1) 导入 YAML / Base64 文本订阅
      if (pathname === '/api/subscriptions/import-yaml' && method === 'POST') {
        const body = await readJsonBody(req);
        const parsed = parseSubscriptionContent(body.content || '');
        const normalized = normalizeSubscriptionProxies(parsed.proxies || []);
        if (normalized.nodes.length === 0) {
          return sendJson(res, 400, {
            error: '解析完成，但没有可用的真实叶子节点（所有节点可能都是提示条目或已被过滤）',
            filteredOut: normalized.filteredOut
          });
        }
        const subId = StateStore.nextId('sub');
        const sub = {
          id: subId,
          name: String(body.name || '新导入订阅').trim(),
          provider: String(body.provider || '手动导入 YAML').trim(),
          sourceType: 'yaml',
          urlRef: null,
          priceNote: String(body.priceNote || '').trim(),
          trafficInfo: String(body.trafficInfo || `${normalized.nodes.length} 个可用叶子节点`).trim(),
          updatedAt: new Date().toISOString(),
          nodes: normalized.nodes,
          filteredOut: normalized.filteredOut,
          rawRules: Array.isArray(parsed.rules) ? parsed.rules : [],
          nodeDomains: normalized.nodeDomainPatterns,
          isSample: false
        };

        const updatedState = store.update((s) => {
          s.subscriptions.push(sub);
          if (body.activate !== false) {
            s.activeBinding.subscriptionId = sub.id;
            const defaultHops = normalized.nodes.slice(0, 3).map(n => n.name);
            s.activeBinding.selectedFirstHops = defaultHops;
            s.activeBinding.primaryFirstHop = defaultHops[0] || null;
          }
          return s;
        });

        return sendJson(res, 200, {
          subscription: { id: sub.id, name: sub.name, nodeCount: sub.nodes.length, filteredOut: sub.filteredOut },
          state: sanitizeStateForClient(updatedState, vault)
        });
      }

      // 2) 从远程 URL 拉取订阅
      if (pathname === '/api/subscriptions/import-url' && method === 'POST') {
        const body = await readJsonBody(req);
        const subUrl = String(body.url || '').trim();
        if (!subUrl) return sendJson(res, 400, { error: '请填写订阅链接' });
        const fetched = await fetchSubscriptionFromUrl(subUrl, body.useProxy ? `http://127.0.0.1:${body.proxyPort || 7897}` : null);
        const parsed = parseSubscriptionContent(fetched.body);
        const normalized = normalizeSubscriptionProxies(parsed.proxies || []);
        if (normalized.nodes.length === 0) {
          return sendJson(res, 400, { error: '订阅已下载，但未解析出任何可用叶子节点', filteredOut: normalized.filteredOut });
        }

        const subId = StateStore.nextId('sub');
        const urlRef = `url-${subId}`;
        vault.setSecret(urlRef, { url: subUrl });

        const sub = {
          id: subId,
          name: String(body.name || new URL(subUrl).hostname).trim(),
          provider: String(body.provider || '远程 URL 订阅').trim(),
          sourceType: 'url',
          urlRef,
          priceNote: String(body.priceNote || '').trim(),
          trafficInfo: fetched.trafficInfo || `${normalized.nodes.length} 个可用节点`,
          updatedAt: new Date().toISOString(),
          nodes: normalized.nodes,
          filteredOut: normalized.filteredOut,
          rawRules: Array.isArray(parsed.rules) ? parsed.rules : [],
          nodeDomains: normalized.nodeDomainPatterns,
          isSample: false
        };

        const updatedState = store.update((s) => {
          s.subscriptions.push(sub);
          if (body.activate !== false) {
            s.activeBinding.subscriptionId = sub.id;
            const defaultHops = normalized.nodes.slice(0, 3).map(n => n.name);
            s.activeBinding.selectedFirstHops = defaultHops;
            s.activeBinding.primaryFirstHop = defaultHops[0] || null;
          }
          return s;
        });

        return sendJson(res, 200, {
          subscription: { id: sub.id, name: sub.name, nodeCount: sub.nodes.length, trafficInfo: sub.trafficInfo },
          state: sanitizeStateForClient(updatedState, vault)
        });
      }

      // 3) 刷新已有 URL 订阅
      if (pathname.startsWith('/api/subscriptions/') && pathname.endsWith('/refresh') && method === 'POST') {
        const subId = pathname.split('/')[3];
        const state = store.load();
        const existing = state.subscriptions.find(s => s.id === subId);
        if (!existing || !existing.urlRef) {
          return sendJson(res, 400, { error: '该订阅不是远程 URL 订阅，无法在线刷新' });
        }
        const secret = vault.getSecret(existing.urlRef);
        if (!secret?.url) return sendJson(res, 400, { error: '本地密钥库中缺少该订阅的链接' });

        const fetched = await fetchSubscriptionFromUrl(secret.url);
        const parsed = parseSubscriptionContent(fetched.body);
        const normalized = normalizeSubscriptionProxies(parsed.proxies || []);
        if (normalized.nodes.length === 0) {
          return sendJson(res, 400, { error: '刷新后的订阅没有可用节点，已保留旧快照' });
        }

        const validSet = new Set(normalized.nodes.map(n => n.name));
        const missingHops = (state.activeBinding.subscriptionId === subId ? state.activeBinding.selectedFirstHops : [])
          .filter(h => !validSet.has(h));

        const updatedState = store.update((s) => {
          const target = s.subscriptions.find(x => x.id === subId);
          if (target) {
            target.nodes = normalized.nodes;
            target.filteredOut = normalized.filteredOut;
            target.rawRules = Array.isArray(parsed.rules) ? parsed.rules : [];
            target.nodeDomains = normalized.nodeDomainPatterns;
            target.trafficInfo = fetched.trafficInfo || `${normalized.nodes.length} 个可用节点`;
            target.updatedAt = new Date().toISOString();
          }
          return s;
        });

        return sendJson(res, 200, {
          refreshed: true,
          nodeCount: normalized.nodes.length,
          missingHops,
          state: sanitizeStateForClient(updatedState, vault)
        });
      }

      // 4) 从本机 Clash Verge 一键只读导入（含订阅、静态出口、端口/核心选项与活跃控制器）
      if (pathname === '/api/subscriptions/import-clash-verge' && method === 'POST') {
        const current = store.load();
        const imported = importFromLocalClashVerge(current, vault, StateStore.nextId);
        const controller = await discoverClashVergeController(current.deviceBindings.windows.clashVergeDir);
        const updatedState = store.update((s) => {
          // 导入真实配置后清理初始示例占位，并按来源幂等更新（避免重复导入产生重复条目）
          s.subscriptions = s.subscriptions.filter(x => !x.isSample);
          const existingSubIdx = s.subscriptions.findIndex(x =>
            x.sourceType === 'clash-verge' && (x.sourceFile === imported.subscription.sourceFile || x.name === imported.subscription.name)
          );
          let activeSubId = imported.subscription.id;
          if (existingSubIdx >= 0) {
            const old = s.subscriptions[existingSubIdx];
            if (old.urlRef && old.urlRef !== imported.subscription.urlRef) vault.deleteSecret(old.urlRef);
            activeSubId = old.id;
            s.subscriptions[existingSubIdx] = { ...imported.subscription, id: old.id };
          } else {
            s.subscriptions.push(imported.subscription);
          }
          s.activeBinding.subscriptionId = activeSubId;

          const hops = imported.discoveredHops.length
            ? imported.discoveredHops
            : imported.subscription.nodes.slice(0, 2).map(n => n.name);
          s.activeBinding.selectedFirstHops = hops;
          s.activeBinding.primaryFirstHop = hops[0] || null;

          if (imported.importedExit) {
            s.staticExits = s.staticExits.filter(x => !x.isSample);
            const existingExitIdx = s.staticExits.findIndex(x =>
              x.provider === '本机 Clash Verge 导入' && x.server === imported.importedExit.server && Number(x.port) === Number(imported.importedExit.port)
            );
            let activeExitId = imported.importedExit.id;
            if (existingExitIdx >= 0) {
              const oldExit = s.staticExits[existingExitIdx];
              if (oldExit.credentialRef && oldExit.credentialRef !== imported.importedExit.credentialRef) {
                vault.deleteSecret(oldExit.credentialRef);
              }
              activeExitId = oldExit.id;
              s.staticExits[existingExitIdx] = {
                ...imported.importedExit,
                id: oldExit.id,
                region: oldExit.region && !oldExit.region.includes('待核实') ? oldExit.region : imported.importedExit.region
              };
            } else {
              s.staticExits.push(imported.importedExit);
            }
            s.activeBinding.staticExitId = activeExitId;
          }
          if (imported.importedWindowsOptions && Object.keys(imported.importedWindowsOptions).length > 0) {
            const preset = s.rulePresets.find(p => p.id === s.activeBinding.rulePresetId) || s.rulePresets[0];
            if (preset) {
              preset.windowsOptions = { ...preset.windowsOptions, ...imported.importedWindowsOptions };
            }
          }
          return s;
        });
        return sendJson(res, 200, {
          importedSubscription: imported.subscription.name,
          nodeCount: imported.subscription.nodes.length,
          importedExit: imported.importedExit ? imported.importedExit.name : null,
          discoveredHops: imported.discoveredHops,
          importedWindowsOptions: imported.importedWindowsOptions,
          controllerDetected: controller.detected,
          controllerLabel: controller.label,
          state: sanitizeStateForClient(updatedState, vault)
        });
      }

      // 删除订阅
      if (pathname.startsWith('/api/subscriptions/') && method === 'DELETE') {
        const subId = pathname.split('/')[3];
        const updatedState = store.update((s) => {
          if (s.subscriptions.length <= 1) throw new Error('至少保留一个订阅配置');
          const idx = s.subscriptions.findIndex(x => x.id === subId);
          if (idx < 0) throw new Error('订阅不存在');
          const [removed] = s.subscriptions.splice(idx, 1);
          if (removed.urlRef) vault.deleteSecret(removed.urlRef);
          if (s.activeBinding.subscriptionId === subId) {
            s.activeBinding.subscriptionId = s.subscriptions[0].id;
            const hops = (s.subscriptions[0].nodes || []).slice(0, 2).map(n => n.name);
            s.activeBinding.selectedFirstHops = hops;
            s.activeBinding.primaryFirstHop = hops[0] || null;
          }
          return s;
        });
        return sendJson(res, 200, { state: sanitizeStateForClient(updatedState, vault) });
      }

      // 静态出口 CRUD
      if (pathname === '/api/static-exits' && method === 'POST') {
        const body = await readJsonBody(req);
        const exitId = StateStore.nextId('exit');
        const credRef = `cred-${exitId}`;
        if (body.username || body.password) {
          vault.setSecret(credRef, {
            username: String(body.username || '').trim(),
            password: String(body.password || '').trim()
          });
        }
        const entry = {
          id: exitId,
          name: String(body.name || '新静态出口').trim(),
          provider: String(body.provider || '自定义静态代理').trim(),
          server: String(body.server || '').trim(),
          port: Number(body.port || 5432),
          expectedIp: String(body.expectedIp || body.server || '').trim(),
          region: String(body.region || 'US').trim(),
          timeZone: String(body.timeZone || 'America/Chicago').trim(),
          windowsProtocol: body.windowsProtocol === 'socks5' ? 'socks5' : 'http',
          androidProtocol: body.androidProtocol === 'http' ? 'http' : 'socks5',
          androidUdp: Boolean(body.androidUdp),
          credentialRef: credRef,
          notes: String(body.notes || '').trim(),
          isSample: false,
          updatedAt: new Date().toISOString()
        };
        const updatedState = store.update((s) => {
          s.staticExits.push(entry);
          if (body.activate) s.activeBinding.staticExitId = entry.id;
          return s;
        });
        return sendJson(res, 200, { exitId, state: sanitizeStateForClient(updatedState, vault) });
      }

      if (pathname.startsWith('/api/static-exits/') && method === 'PUT') {
        const exitId = pathname.split('/')[3];
        const body = await readJsonBody(req);
        const updatedState = store.update((s) => {
          const item = s.staticExits.find(e => e.id === exitId);
          if (!item) throw new Error('静态出口不存在');
          if (body.name !== undefined) item.name = String(body.name).trim();
          if (body.provider !== undefined) item.provider = String(body.provider).trim();
          if (body.server !== undefined) item.server = String(body.server).trim();
          if (body.port !== undefined) item.port = Number(body.port);
          if (body.expectedIp !== undefined) item.expectedIp = String(body.expectedIp).trim();
          if (body.region !== undefined) item.region = String(body.region).trim();
          if (body.timeZone !== undefined) item.timeZone = String(body.timeZone).trim();
          if (body.windowsProtocol !== undefined) item.windowsProtocol = body.windowsProtocol === 'socks5' ? 'socks5' : 'http';
          if (body.androidProtocol !== undefined) item.androidProtocol = body.androidProtocol === 'http' ? 'http' : 'socks5';
          if (body.androidUdp !== undefined) item.androidUdp = Boolean(body.androidUdp);
          if (body.notes !== undefined) item.notes = String(body.notes).trim();
          item.isSample = false;
          item.updatedAt = new Date().toISOString();

          if (body.username || body.password) {
            const existingCred = vault.getSecret(item.credentialRef) || {};
            vault.setSecret(item.credentialRef, {
              username: body.username ? String(body.username).trim() : (existingCred.username || ''),
              password: body.password ? String(body.password).trim() : (existingCred.password || '')
            });
          }
          return s;
        });
        return sendJson(res, 200, { state: sanitizeStateForClient(updatedState, vault) });
      }

      if (pathname.startsWith('/api/static-exits/') && method === 'DELETE') {
        const exitId = pathname.split('/')[3];
        const updatedState = store.update((s) => {
          if (s.staticExits.length <= 1) throw new Error('至少保留一个静态出口配置');
          const idx = s.staticExits.findIndex(e => e.id === exitId);
          if (idx < 0) throw new Error('静态出口不存在');
          const [removed] = s.staticExits.splice(idx, 1);
          if (removed.credentialRef) vault.deleteSecret(removed.credentialRef);
          if (s.activeBinding.staticExitId === exitId) {
            s.activeBinding.staticExitId = s.staticExits[0].id;
          }
          return s;
        });
        return sendJson(res, 200, { state: sanitizeStateForClient(updatedState, vault) });
      }

      // 独立切换当前绑定（订阅 / 第一跳 / 静态出口）
      if (pathname === '/api/binding' && method === 'PUT') {
        const body = await readJsonBody(req);
        const updatedState = store.update((s) => {
          if (body.subscriptionId && s.subscriptions.some(x => x.id === body.subscriptionId)) {
            const changedSub = s.activeBinding.subscriptionId !== body.subscriptionId;
            s.activeBinding.subscriptionId = body.subscriptionId;
            if (changedSub && !body.selectedFirstHops) {
              const sub = s.subscriptions.find(x => x.id === body.subscriptionId);
              const hops = (sub?.nodes || []).slice(0, 3).map(n => n.name);
              s.activeBinding.selectedFirstHops = hops;
              s.activeBinding.primaryFirstHop = hops[0] || null;
            }
          }
          if (body.staticExitId && s.staticExits.some(x => x.id === body.staticExitId)) {
            s.activeBinding.staticExitId = body.staticExitId;
          }
          if (Array.isArray(body.selectedFirstHops)) {
            s.activeBinding.selectedFirstHops = [...new Set(body.selectedFirstHops)];
            if (!s.activeBinding.selectedFirstHops.includes(s.activeBinding.primaryFirstHop)) {
              s.activeBinding.primaryFirstHop = s.activeBinding.selectedFirstHops[0] || null;
            }
          }
          if (body.primaryFirstHop !== undefined) {
            s.activeBinding.primaryFirstHop = body.primaryFirstHop;
            if (body.primaryFirstHop && !s.activeBinding.selectedFirstHops.includes(body.primaryFirstHop)) {
              s.activeBinding.selectedFirstHops = [body.primaryFirstHop, ...s.activeBinding.selectedFirstHops];
            }
          }
          return s;
        });
        return sendJson(res, 200, { state: sanitizeStateForClient(updatedState, vault) });
      }

      // 规则预设与设备参数更新
      if (pathname === '/api/rules' && method === 'PUT') {
        const body = await readJsonBody(req);
        const updatedState = store.update((s) => {
          const preset = s.rulePresets.find(p => p.id === s.activeBinding.rulePresetId) || s.rulePresets[0];
          if (body.windowsOptions) preset.windowsOptions = { ...preset.windowsOptions, ...body.windowsOptions };
          if (body.androidOptions) preset.androidOptions = { ...preset.androidOptions, ...body.androidOptions };
          if (Array.isArray(body.gameDirectRules)) preset.gameDirectRules = body.gameDirectRules;
          if (Array.isArray(body.protectedDomains)) preset.protectedDomains = body.protectedDomains;
          if (Array.isArray(body.windowsProcesses)) preset.windowsProcesses = body.windowsProcesses;
          if (Array.isArray(body.androidCoreApps)) preset.androidCoreApps = body.androidCoreApps;
          if (Array.isArray(body.androidBrowserApps)) preset.androidBrowserApps = body.androidBrowserApps;
          if (Array.isArray(body.customRules)) preset.customRules = body.customRules;
          return s;
        });
        return sendJson(res, 200, { state: sanitizeStateForClient(updatedState, vault) });
      }

      if (pathname === '/api/device-paths' && method === 'PUT') {
        const body = await readJsonBody(req);
        const updatedState = store.update((s) => {
          if (body.clashVergeDir !== undefined) s.deviceBindings.windows.clashVergeDir = String(body.clashVergeDir).trim();
          if (body.claudeLocalDir !== undefined) s.deviceBindings.windows.claudeLocalDir = String(body.claudeLocalDir).trim();
          if (body.claudeEnvScriptsDir !== undefined) s.deviceBindings.windows.claudeEnvScriptsDir = String(body.claudeEnvScriptsDir).trim();
          return s;
        });
        return sendJson(res, 200, { state: sanitizeStateForClient(updatedState, vault) });
      }

      // 生成并可选应用到本机 Clash Verge
      if (pathname === '/api/apply' && method === 'POST') {
        const body = await readJsonBody(req);
        const state = store.load();
        const versionId = StateStore.nextVersionId(state.versions);
        const result = commitAndApplyVersion({
          state,
          vault,
          projectRoot,
          versionId,
          applyToClashVerge: Boolean(body.applyToClashVerge),
          includeControllerInAndroid: Boolean(body.includeControllerInAndroid),
          note: String(body.note || '').trim()
        });

        const updatedState = store.update((s) => {
          s.versions.unshift(result.versionRecord);
          if (s.versions.length > 40) s.versions = s.versions.slice(0, 40);
          if (result.versionRecord.windowsStatus === 'applied') {
            s.deviceBindings.windows.currentVersion = versionId;
            s.deviceBindings.windows.lastAppliedAt = result.versionRecord.createdAt;
            s.deviceBindings.windows.status = 'partial'; // 已写入待探测
          }
          s.deviceBindings.android.dailyVersion = versionId;
          s.deviceBindings.android.dedicatedVersion = versionId;
          s.deviceBindings.android.dailyStatus = 'generated';
          s.deviceBindings.android.dedicatedStatus = 'generated';
          return s;
        });

        return sendJson(res, 200, {
          version: result.versionRecord,
          message: result.applyMessage,
          state: sanitizeStateForClient(updatedState, vault)
        });
      }

      // 回滚 Windows Clash Verge Script.js
      if (pathname === '/api/rollback' && method === 'POST') {
        const body = await readJsonBody(req);
        const state = store.load();
        const ver = state.versions.find(v => v.versionId === body.versionId);
        if (!ver) return sendJson(res, 404, { error: '未找到对应版本记录' });
        const rollbackRes = rollbackWindowsToVersion(state, ver);
        const updatedState = store.update((s) => {
          const item = s.versions.find(v => v.versionId === body.versionId);
          if (item) item.windowsStatus = 'rolled-back';
          s.deviceBindings.windows.status = 'partial';
          return s;
        });
        return sendJson(res, 200, { rollback: rollbackRes, state: sanitizeStateForClient(updatedState, vault) });
      }

      // Windows 端到端探测（7897 / 17902 / /health）
      if (pathname === '/api/probe/windows' && method === 'POST') {
        const body = await readJsonBody(req);
        const state = store.load();
        const exit = state.staticExits.find(e => e.id === state.activeBinding.staticExitId);
        const preset = state.rulePresets.find(p => p.id === state.activeBinding.rulePresetId) || state.rulePresets[0];
        const expectedIp = String(body.expectedIp || exit?.expectedIp || '').trim();
        const samples = Number(body.samples || 3);

        const [ruleProbe, relayProbe, relayHealth] = await Promise.all([
          probeProxyEndpoint({
            label: `Windows 分流入口 (${preset.windowsOptions.mixedPort})`,
            proxyPort: preset.windowsOptions.mixedPort,
            expectedIp,
            samples,
            checkDomestic: true,
            checkOverseas: true
          }),
          probeProxyEndpoint({
            label: `Windows 专用全代理入口 (${preset.windowsOptions.relayPort})`,
            proxyPort: preset.windowsOptions.relayPort,
            expectedIp,
            samples: Math.min(samples, 3),
            checkDomestic: false,
            checkOverseas: true
          }),
          probeRelayHealth(preset.windowsOptions.relayPort)
        ]);

        const overall =
          ruleProbe.status === 'pass' && relayProbe.status === 'pass' && relayHealth.status === 'pass'
            ? 'pass'
            : (ruleProbe.status === 'fail' || relayProbe.status === 'fail' ? 'fail'
              : (ruleProbe.status === 'blocked' && relayProbe.status === 'blocked' ? 'blocked' : 'partial'));

        const record = {
          id: StateStore.nextId('probe'),
          target: 'windows',
          status: overall,
          expectedIp,
          checkedAt: new Date().toISOString(),
          ruleProbe,
          relayProbe,
          relayHealth
        };

        const updatedState = store.update((s) => {
          s.probeHistory.unshift(record);
          if (s.probeHistory.length > 30) s.probeHistory = s.probeHistory.slice(0, 30);
          s.deviceBindings.windows.lastVerifiedAt = record.checkedAt;
          s.deviceBindings.windows.status = overall;
          return s;
        });

        return sendJson(res, 200, { probe: record, state: sanitizeStateForClient(updatedState, vault) });
      }

      // 第一跳全链测速（自动发现 Clash Verge Named Pipe / Unix Socket / TCP 及 Secret）
      if (pathname === '/api/benchmark/hops' && method === 'POST') {
        const body = await readJsonBody(req);
        const state = store.load();
        const exit = state.staticExits.find(e => e.id === state.activeBinding.staticExitId);
        const preset = state.rulePresets.find(p => p.id === state.activeBinding.rulePresetId) || state.rulePresets[0];

        let controllerUrl = String(body.controllerUrl || '').trim();
        let socketPath = '';
        let secret = String(body.secret || '').trim();

        if (!controllerUrl) {
          const detected = await discoverClashVergeController(state.deviceBindings.windows.clashVergeDir);
          if (!detected.detected) {
            return sendJson(res, 400, {
              error: '未能自动发现运行中的 Clash Verge / Mihomo 控制器（Named Pipe 与 9097/9090 均未响应）。请确认 Clash Verge 已启动，或在高级选项中手动填入 External Controller 地址。'
            });
          }
          controllerUrl = detected.controllerUrl;
          socketPath = detected.socketPath;
          if (!secret) secret = detected.secret;
        }

        const groupName = String(body.groupName || preset.windowsOptions.firstHopGroupName).trim();
        const proxyPort = Number(body.proxyPort || preset.windowsOptions.mixedPort);
        const expectedIp = String(body.expectedIp || (exit?.isSample ? '' : exit?.expectedIp) || '').trim();

        const report = await benchmarkFirstHops({
          controllerUrl,
          socketPath,
          secret,
          groupName,
          proxyPort,
          expectedIp,
          candidates: Array.isArray(body.candidates) ? body.candidates : null,
          screenSamples: Number(body.screenSamples || 2),
          finalistCount: Number(body.finalistCount || 5),
          finalistSamples: Number(body.finalistSamples || 5)
        });

        const updatedState = store.update((s) => {
          s.benchmarks.unshift(report);
          if (s.benchmarks.length > 15) s.benchmarks = s.benchmarks.slice(0, 15);
          return s;
        });

        return sendJson(res, 200, { benchmark: report, state: sanitizeStateForClient(updatedState, vault) });
      }

      // --- Android ADB APIs ---
      if (pathname === '/api/adb/devices' && method === 'GET') {
        const result = listAdbDevices();
        const authorized = result.devices.find(d => d.authorized);
        if (authorized) {
          store.update((s) => {
            s.deviceBindings.android.deviceSerial = authorized.serial;
            s.deviceBindings.android.deviceModel = authorized.model;
          });
        }
        return sendJson(res, 200, result);
      }

      if (pathname === '/api/adb/packages' && method === 'POST') {
        const body = await readJsonBody(req);
        const state = store.load();
        const preset = state.rulePresets.find(p => p.id === state.activeBinding.rulePresetId) || state.rulePresets[0];
        const serial = body.serial || state.deviceBindings.android.deviceSerial;
        const targetPkgs = [
          ...(preset.androidCoreApps || []).map(a => a.packageName),
          ...(preset.androidBrowserApps || []).map(a => a.packageName)
        ];
        const resPkg = checkAndroidPackages(serial, targetPkgs);
        return sendJson(res, 200, resPkg);
      }

      if (pathname === '/api/adb/push' && method === 'POST') {
        const body = await readJsonBody(req);
        const state = store.load();
        const serial = body.serial || state.deviceBindings.android.deviceSerial;
        const ver = body.versionId
          ? state.versions.find(v => v.versionId === body.versionId)
          : state.versions[0];
        if (!ver) return sendJson(res, 400, { error: '请先生成至少一个版本的手机配置' });
        const pushRes = pushProfilesToAndroid(serial, ver.versionId, [
          ver.files.androidDaily,
          ver.files.androidDedicated
        ]);
        const updatedState = store.update((s) => {
          const item = s.versions.find(v => v.versionId === ver.versionId);
          if (item) {
            item.androidDailyStatus = 'transferred';
            item.androidDedicatedStatus = 'transferred';
          }
          s.deviceBindings.android.dailyStatus = 'transferred';
          s.deviceBindings.android.dedicatedStatus = 'transferred';
          return s;
        });
        return sendJson(res, 200, { push: pushRes, state: sanitizeStateForClient(updatedState, vault) });
      }

      if (pathname === '/api/adb/inspect' && method === 'POST') {
        const body = await readJsonBody(req);
        const state = store.load();
        const preset = state.rulePresets.find(p => p.id === state.activeBinding.rulePresetId) || state.rulePresets[0];
        const exit = state.staticExits.find(e => e.id === state.activeBinding.staticExitId);
        const serial = body.serial || state.deviceBindings.android.deviceSerial;

        let secret = String(body.secret || '').trim();
        if (!secret && body.versionId) {
          secret = vault.getSecret(`android-ctrl-${body.versionId}`)?.secret || '';
        }

        const result = await inspectAndroidReadOnly({
          serial,
          controllerPort: preset.androidOptions.controllerPort,
          rulePort: preset.androidOptions.mixedPort,
          dedicatedPort: preset.androidOptions.dedicatedListenerPort,
          secret,
          expectedIp: exit?.expectedIp || '',
          groupName: preset.androidOptions.firstHopGroupName
        });

        const updatedState = store.update((s) => {
          s.probeHistory.unshift({
            id: StateStore.nextId('probe'),
            target: 'android',
            status: result.status,
            expectedIp: exit?.expectedIp || '',
            checkedAt: result.verifiedAt,
            ...result
          });
          if (s.probeHistory.length > 30) s.probeHistory = s.probeHistory.slice(0, 30);
          s.deviceBindings.android.lastVerifiedAt = result.verifiedAt;
          if (result.status === 'pass') {
            s.deviceBindings.android.dailyStatus = 'verified';
            s.deviceBindings.android.dedicatedStatus = 'verified';
          }
          return s;
        });

        return sendJson(res, 200, { inspect: result, state: sanitizeStateForClient(updatedState, vault) });
      }

      if (pathname === '/api/adb/select-hop' && method === 'POST') {
        const body = await readJsonBody(req);
        const state = store.load();
        const preset = state.rulePresets.find(p => p.id === state.activeBinding.rulePresetId) || state.rulePresets[0];
        const serial = body.serial || state.deviceBindings.android.deviceSerial;
        const result = await selectAndroidFirstHop({
          serial,
          controllerPort: preset.androidOptions.controllerPort,
          secret: String(body.secret || '').trim(),
          groupName: preset.androidOptions.firstHopGroupName,
          hopName: String(body.hopName || '').trim()
        });
        return sendJson(res, 200, result);
      }

      if (pathname === '/api/android/status' && method === 'PUT') {
        const body = await readJsonBody(req);
        const updatedState = store.update((s) => {
          if (body.activeProfile !== undefined) s.deviceBindings.android.activeProfile = body.activeProfile;
          if (body.dailyStatus) s.deviceBindings.android.dailyStatus = body.dailyStatus;
          if (body.dedicatedStatus) s.deviceBindings.android.dedicatedStatus = body.dedicatedStatus;
          return s;
        });
        return sendJson(res, 200, { state: sanitizeStateForClient(updatedState, vault) });
      }

      // 触发四个已有 Windows 快捷方式之一
      if (pathname === '/api/launcher/run' && method === 'POST') {
        const body = await readJsonBody(req);
        const state = store.load();
        const result = triggerExistingLauncher(body.action, state);
        return sendJson(res, 200, result);
      }

      // --- Claude 独立环境与防泄漏体检中心 API ---
      if (pathname === '/api/hygiene/scan' && method === 'POST') {
        const state = store.load();
        const audit = await runFullEnvironmentAudit(state);
        return sendJson(res, 200, { audit });
      }

      if (pathname === '/api/hygiene/caches' && method === 'GET') {
        const proc = listRunningTargetProcesses();
        const caches = inspectDisposableCaches();
        return sendJson(res, 200, {
          caches,
          runningTargets: proc.runningTargets,
          hostReadable: proc.ok
        });
      }

      if (pathname === '/api/hygiene/clean-cache' && method === 'POST') {
        const body = await readJsonBody(req);
        if (body.confirm !== true) {
          return sendJson(res, 400, { error: '请先确认清理操作（仅清理渲染临时缓存，不动登录态）' });
        }
        const proc = listRunningTargetProcesses();
        const activeNames = (proc.runningTargets || []).map(p => p.ProcessName);
        const cleaned = cleanSafeDisposableCache({
          targetIds: Array.isArray(body.targetIds) ? body.targetIds : [],
          activeProcessNames: activeNames
        });
        const cachesAfter = inspectDisposableCaches();
        return sendJson(res, 200, { cleaned, caches: cachesAfter });
      }

      // --- 内置 IPv4 Relay 进程管理 ---
      if (pathname === '/api/relay/status' && method === 'GET') {
        const state = store.load();
        const preset = state.rulePresets.find(p => p.id === state.activeBinding.rulePresetId) || state.rulePresets[0];
        const status = await relayManager.getStatus(preset.windowsOptions.relayPort);
        return sendJson(res, 200, status);
      }

      if (pathname === '/api/relay/start' && method === 'POST') {
        const state = store.load();
        const preset = state.rulePresets.find(p => p.id === state.activeBinding.rulePresetId) || state.rulePresets[0];
        const status = await relayManager.start({
          listenPort: preset.windowsOptions.relayPort,
          upstreamPort: preset.windowsOptions.upstreamPort
        });
        return sendJson(res, 200, status);
      }

      if (pathname === '/api/relay/stop' && method === 'POST') {
        const state = store.load();
        const preset = state.rulePresets.find(p => p.id === state.activeBinding.rulePresetId) || state.rulePresets[0];
        const status = await relayManager.stop(preset.windowsOptions.relayPort);
        return sendJson(res, 200, status);
      }

      // 下载产物文件（支持 latest 或具体 versionId）
      if (pathname.startsWith('/api/download/') && method === 'GET') {
        const parts = pathname.split('/').filter(Boolean); // ['api', 'download', versionId, filename]
        const versionId = parts[2];
        const fileName = parts[3];
        const allowedFiles = new Set([
          'Script.js',
          'Desktop-Static-Chain.yaml',
          'Daily-Static-Chain.yaml',
          'Claude-GoLogin-Static.yaml',
          'chain-runtime.json'
        ]);
        if (!versionId || !allowedFiles.has(fileName) || !/^[A-Za-z0-9_-]+$/.test(versionId)) {
          return sendJson(res, 400, { error: '不允许下载该文件' });
        }
        const targetFile = path.join(projectRoot, 'output', versionId, fileName);
        if (!fs.existsSync(targetFile)) {
          return sendJson(res, 404, { error: '尚未生成该版本文件，请先点击「生成 / 应用」' });
        }
        const content = fs.readFileSync(targetFile);
        res.writeHead(200, {
          'Content-Type': MIME_TYPES[path.extname(fileName)] || 'application/octet-stream',
          'Content-Disposition': `attachment; filename="${fileName}"`,
          'Cache-Control': 'no-store'
        });
        res.end(content);
        return;
      }

      // 导出脱敏诊断报表
      if (pathname === '/api/report/export' && method === 'GET') {
        const state = store.load();
        const winEnv = await inspectWindowsEnvironment(state);
        const report = vault.redactObject({
          exportedAt: new Date().toISOString(),
          tool: 'Clash Chain Studio',
          activeBinding: state.activeBinding,
          windowsEnv: winEnv,
          deviceBindings: state.deviceBindings,
          versions: state.versions.slice(0, 10),
          probeHistory: state.probeHistory.slice(0, 10),
          benchmarks: state.benchmarks.slice(0, 5)
        });
        res.writeHead(200, {
          'Content-Type': 'application/json; charset=utf-8',
          'Content-Disposition': `attachment; filename="chain-diagnostic-report-${Date.now()}.json"`
        });
        res.end(JSON.stringify(report, null, 2));
        return;
      }

      // --- Static Frontend Files ---
      const relPath = pathname === '/' ? 'index.html' : pathname.replace(/^\/+/, '');
      const fullPath = path.resolve(publicDir, relPath);
      if (!fullPath.startsWith(publicDir) || !fs.existsSync(fullPath) || fs.statSync(fullPath).isDirectory()) {
        res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('Not Found');
        return;
      }
      const ext = path.extname(fullPath);
      res.writeHead(200, {
        'Content-Type': MIME_TYPES[ext] || 'application/octet-stream',
        'Cache-Control': 'no-cache'
      });
      res.end(fs.readFileSync(fullPath));
    } catch (err) {
      sendJson(res, 500, { error: vault.redactText(err?.message || String(err)) });
    }
  };

  const server = http.createServer(handleRequest);

  return { server, handleRequest, store, vault };
}

// 直接运行启动服务器
const isMain = process.argv[1] && path.resolve(process.argv[1]) === __filename;
if (isMain) {
  const port = Number(process.env.PORT || 4328);
  const host = process.env.HOST || '127.0.0.1';
  const { server } = createAppServer();
  server.listen(port, host, () => {
    console.log(`[Clash Chain Studio] 已启动: http://${host}:${port}`);
  });
}
