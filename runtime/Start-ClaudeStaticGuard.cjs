'use strict';
/**
 * Generic Static-IP Guard Launcher for Claude Desktop & Claude Code.
 * Reads expected IP & proxy ports from output/latest/chain-runtime.json (zero hardcoding).
 * Usage:
 *   node runtime/Start-ClaudeStaticGuard.cjs desktop
 *   node runtime/Start-ClaudeStaticGuard.cjs code [args...]
 */
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const cp = require('node:child_process');

const PROJECT_ROOT = path.resolve(__dirname, '..');
const DEFAULT_RUNTIME_CONFIG = path.join(PROJECT_ROOT, 'output', 'latest', 'chain-runtime.json');

function loadRuntimeConfig() {
  const cfgPath = process.env.CHAIN_STUDIO_RUNTIME_CONFIG || DEFAULT_RUNTIME_CONFIG;
  if (!fs.existsSync(cfgPath)) {
    throw new Error(`未找到运行时配置 ${cfgPath}。请先在 Chain Studio 点击「生成并应用」生成配置。`);
  }
  const cfg = JSON.parse(fs.readFileSync(cfgPath, 'utf8'));
  if (!cfg.expectedIp || !cfg.windows?.ruleProxyUrl) {
    throw new Error('chain-runtime.json 缺少 expectedIp 或 windows.ruleProxyUrl');
  }
  return cfg;
}

function verifyStaticIp(proxyUrl, expectedIp) {
  const curlBin = process.platform === 'win32'
    ? path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'curl.exe')
    : 'curl';

  let lastErr = '';
  for (let attempt = 1; attempt <= 3; attempt++) {
    const res = cp.spawnSync(
      curlBin,
      ['--proxy', proxyUrl, '--noproxy', '', '--connect-timeout', '4', '--max-time', '8', '--fail', '--silent', '--show-error', 'https://api.ipify.org'],
      { encoding: 'utf8', windowsHide: true, timeout: 9000 }
    );
    if (res.status === 0) {
      const actual = (res.stdout || '').trim();
      if (actual === expectedIp) {
        return { ok: true, ip: actual, attempts: attempt };
      }
      throw new Error(`静态出口 IP 校验失败！预期 ${expectedIp}，实测 ${actual}。已阻止启动以防止出口漂移。`);
    }
    lastErr = (res.stderr || res.error?.message || `curl exit ${res.status}`).trim();
  }
  throw new Error(`无法通过静态代理 (${proxyUrl}) 访问 api.ipify.org：${lastErr}`);
}

function findClaudeDesktopExecutable() {
  if (process.platform === 'win32') {
    const base = path.join(process.env.LOCALAPPDATA || '', 'AnthropicClaude');
    if (fs.existsSync(base)) {
      const dirs = fs.readdirSync(base, { withFileTypes: true })
        .filter(d => d.isDirectory() && /^app-[0-9.]+$/.test(d.name))
        .map(d => d.name)
        .sort((a, b) => b.localeCompare(a, undefined, { numeric: true }));
      for (const dir of dirs) {
        const exe = path.join(base, dir, 'claude.exe');
        if (fs.existsSync(exe)) return exe;
      }
    }
    throw new Error('未在 %LOCALAPPDATA%\\AnthropicClaude 找到官方 Claude Desktop，已取消启动。');
  }
  if (process.platform === 'darwin') {
    const macApp = '/Applications/Claude.app/Contents/MacOS/Claude';
    if (fs.existsSync(macApp)) return macApp;
  }
  throw new Error('当前系统未找到 Claude Desktop 安装路径。');
}

function findClaudeCodeExecutable() {
  if (process.platform === 'win32') {
    const wingetLink = path.join(process.env.LOCALAPPDATA || '', 'Microsoft', 'WinGet', 'Links', 'claude.exe');
    if (fs.existsSync(wingetLink)) return wingetLink;
    return 'claude.exe';
  }
  return 'claude';
}

function buildIsolatedEnv(cfg) {
  const env = { ...process.env };
  for (const key of Object.keys(env)) {
    if (['HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY'].includes(key.toUpperCase())) {
      delete env[key];
    }
  }
  const proxyUrl = cfg.windows.ruleProxyUrl;
  const tz = cfg.timeZone || 'America/Chicago';
  const locale = tz === 'Asia/Shanghai' ? 'zh_CN.UTF-8' : 'en_US.UTF-8';

  env.HTTP_PROXY = proxyUrl;
  env.HTTPS_PROXY = proxyUrl;
  env.NO_PROXY = 'localhost,127.0.0.1,::1';
  env.CLAUDE_CODE_PROXY_RESOLVES_HOSTS = '1';
  env.TZ = tz;
  env.LANG = locale;
  env.LC_ALL = locale;
  return env;
}

function main() {
  const mode = process.argv[2] || 'code';
  if (!['desktop', 'code', 'check'].includes(mode)) {
    console.error('用法: node runtime/Start-ClaudeStaticGuard.cjs <desktop|code|check> [args...]');
    process.exit(2);
  }

  const cfg = loadRuntimeConfig();
  const check = verifyStaticIp(cfg.windows.ruleProxyUrl, cfg.expectedIp);
  console.log(`[StaticGuard] 静态出口核验通过: ${check.ip} (时区: ${cfg.timeZone || 'America/Chicago'})`);

  if (mode === 'check') return;

  const env = buildIsolatedEnv(cfg);
  if (mode === 'desktop') {
    const exe = findClaudeDesktopExecutable();
    const child = cp.spawn(exe, [], { env, detached: true, stdio: 'ignore' });
    child.unref();
    console.log(`[StaticGuard] 已通过隔离代理启动 Claude Desktop (PID ${child.pid})`);
    return;
  }

  const codeBin = findClaudeCodeExecutable();
  const child = cp.spawn(codeBin, process.argv.slice(3), { env, stdio: 'inherit', cwd: process.cwd() });
  child.on('exit', (code) => process.exit(code ?? 1));
  child.on('error', (err) => {
    console.error(`[StaticGuard] 启动 Claude Code 失败: ${err.message}`);
    process.exit(1);
  });
}

if (require.main === module) {
  try {
    main();
  } catch (err) {
    console.error(`[StaticGuard] ${err.message}`);
    process.exit(1);
  }
}

module.exports = { loadRuntimeConfig, buildIsolatedEnv };
