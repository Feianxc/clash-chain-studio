import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { callMihomoApi, checkTcpPortOpen, probeProxyEndpoint } from './probe-service.mjs';

function runAdb(args, timeoutMs = 15000) {
  const res = spawnSync('adb', args, {
    encoding: 'utf8',
    windowsHide: true,
    timeout: timeoutMs,
    maxBuffer: 16 * 1024 * 1024
  });
  if (res.error) {
    if (res.error.code === 'ENOENT') {
      return { ok: false, notFound: true, code: -1, stdout: '', stderr: '未在系统 PATH 中找到 adb.exe' };
    }
    return { ok: false, code: -1, stdout: '', stderr: res.error.message };
  }
  return {
    ok: res.status === 0,
    code: res.status,
    stdout: (res.stdout || '').trim(),
    stderr: (res.stderr || '').trim()
  };
}

/**
 * 只读查询已连接的 ADB 设备及授权状态。
 */
export function listAdbDevices() {
  const res = runAdb(['devices', '-l']);
  if (!res.ok) {
    return {
      available: !res.notFound,
      status: res.notFound ? 'blocked' : 'fail',
      error: res.stderr || 'adb devices 执行失败',
      devices: []
    };
  }
  const lines = res.stdout.split(/\r?\n/).slice(1).map(l => l.trim()).filter(Boolean);
  const devices = [];
  for (const line of lines) {
    const parts = line.split(/\s+/);
    const serial = parts[0];
    const state = parts[1] || 'unknown';
    const attrs = {};
    for (const token of parts.slice(2)) {
      const idx = token.indexOf(':');
      if (idx > 0) attrs[token.slice(0, idx)] = token.slice(idx + 1);
    }
    devices.push({
      serial,
      state,
      authorized: state === 'device',
      model: attrs.model || attrs.device || serial,
      product: attrs.product || '',
      transportId: attrs.transport_id || ''
    });
  }
  return {
    available: true,
    status: devices.some(d => d.authorized) ? 'pass' : (devices.length ? 'blocked' : 'not run'),
    devices
  };
}

/**
 * 只读核对手机已安装包名（Clash Meta、Claude、GoLogin 及浏览器）。
 */
export function checkAndroidPackages(serial, targetPackages = []) {
  if (!serial) {
    return { status: 'blocked', error: '未指定已授权的 Android 设备序列号', packages: {} };
  }
  const res = runAdb(['-s', serial, 'shell', 'pm', 'list', 'packages']);
  if (!res.ok) {
    return { status: 'fail', error: res.stderr || '读取包列表失败', packages: {} };
  }
  const installedSet = new Set(
    res.stdout
      .split(/\r?\n/)
      .map(l => l.trim().replace(/^package:/, ''))
      .filter(Boolean)
  );

  const checkList = [
    'com.github.metacubex.clash.meta',
    ...targetPackages
  ];
  const packages = {};
  for (const pkg of checkList) {
    packages[pkg] = installedSet.has(pkg);
  }

  // 只读检查 Clash Meta 进程是否存活
  const pidRes = runAdb(['-s', serial, 'shell', 'pidof', 'com.github.metacubex.clash.meta']);
  const clashRunning = pidRes.ok && Boolean(pidRes.stdout.trim());

  return {
    status: 'pass',
    serial,
    clashInstalled: installedSet.has('com.github.metacubex.clash.meta'),
    clashRunning,
    clashPids: clashRunning ? pidRes.stdout.trim().split(/\s+/) : [],
    packages
  };
}

/**
 * 将生成的双份手机 YAML 安全推送到手机 Download/ClashChainStudio/<versionId>/ 目录。
 * 不覆盖用户既有文件，仅做受控传输。
 */
export function pushProfilesToAndroid(serial, versionId, files) {
  if (!serial) throw new Error('未指定已授权的 Android 设备序列号');
  const remoteDir = `/sdcard/Download/ClashChainStudio/${versionId}`;
  const mkdirRes = runAdb(['-s', serial, 'shell', 'mkdir', '-p', remoteDir]);
  if (!mkdirRes.ok) {
    throw new Error(`创建手机目录失败: ${mkdirRes.stderr}`);
  }

  const pushed = [];
  for (const localFile of files) {
    if (!fs.existsSync(localFile)) {
      throw new Error(`本地文件不存在: ${localFile}`);
    }
    const base = path.basename(localFile);
    const remotePath = `${remoteDir}/${base}`;
    const res = runAdb(['-s', serial, 'push', localFile, remotePath], 30000);
    if (!res.ok) {
      throw new Error(`推送 ${base} 失败: ${res.stderr}`);
    }
    pushed.push({ filename: base, remotePath });
  }

  return {
    status: 'transferred',
    serial,
    remoteDir,
    pushed,
    nextStep: '请在手机 Clash Meta for Android 中选择「配置 → 新建 → 文件」导入上述两个 YAML，再按需激活并通过「只读探测」验收。'
  };
}

/**
 * 建立临时 ADB 端口映射，执行完全只读的手机 Core 状态与出口探测，结束后只清理本次建立的映射。
 */
export async function inspectAndroidReadOnly({
  serial,
  controllerPort = 19090,
  rulePort = 7890,
  dedicatedPort = 17990,
  localControllerPort = 19091,
  localRulePort = 17890,
  localDedicatedPort = 17891,
  secret = '',
  expectedIp = '',
  groupName = 'Static-First-Hop'
}) {
  if (!serial) {
    return { status: 'blocked', error: '未指定 Android 设备序列号' };
  }

  const createdForwards = [];
  const tryForward = async (localPort, remotePort) => {
    const busy = await checkTcpPortOpen(localPort, '127.0.0.1', 400);
    if (busy.open) {
      throw new Error(`本机映射端口 127.0.0.1:${localPort} 已被占用，已阻止建立 ADB 转发`);
    }
    const res = runAdb(['-s', serial, 'forward', '--no-rebind', `tcp:${localPort}`, `tcp:${remotePort}`]);
    if (!res.ok) {
      throw new Error(`建立 ADB forward tcp:${localPort} -> tcp:${remotePort} 失败: ${res.stderr}`);
    }
    createdForwards.push(`tcp:${localPort}`);
  };

  try {
    await tryForward(localRulePort, rulePort);
    await tryForward(localDedicatedPort, dedicatedPort);
    if (secret) {
      await tryForward(localControllerPort, controllerPort);
    }

    const ruleProbe = await probeProxyEndpoint({
      label: 'Android 规则入口 (7890)',
      proxyPort: localRulePort,
      expectedIp,
      samples: 3,
      checkDomestic: true,
      checkOverseas: true
    });

    const dedicatedProbe = await probeProxyEndpoint({
      label: 'Android GoLogin 专用入口 (17990)',
      proxyPort: localDedicatedPort,
      expectedIp,
      samples: 2,
      checkDomestic: false,
      checkOverseas: false
    });

    let coreApi = { status: 'not run', note: '未提供临时 Controller 令牌，跳过 Core API 读取' };
    if (secret) {
      try {
        const controllerUrl = `http://127.0.0.1:${localControllerPort}`;
        const [configs, proxies, connections] = await Promise.all([
          callMihomoApi({ controllerUrl, secret, apiPath: '/configs' }),
          callMihomoApi({ controllerUrl, secret, apiPath: '/proxies' }),
          callMihomoApi({ controllerUrl, secret, apiPath: '/connections' })
        ]);
        const group = proxies?.proxies?.[groupName] || null;
        coreApi = {
          status: 'pass',
          mode: configs?.mode,
          ipv6: configs?.ipv6,
          firstHopNow: group?.now || null,
          firstHopCandidates: group?.all || [],
          activeConnections: Array.isArray(connections?.connections) ? connections.connections.length : 0
        };
      } catch (err) {
        coreApi = { status: 'fail', error: err.message };
      }
    }

    const overall =
      ruleProbe.status === 'pass' && dedicatedProbe.status === 'pass'
        ? 'pass'
        : (ruleProbe.status === 'fail' || dedicatedProbe.status === 'fail' ? 'fail' : 'partial');

    return {
      status: overall,
      serial,
      verifiedAt: new Date().toISOString(),
      ruleProbe,
      dedicatedProbe,
      coreApi
    };
  } catch (err) {
    return {
      status: 'blocked',
      serial,
      error: err.message,
      verifiedAt: new Date().toISOString()
    };
  } finally {
    // 仅移除本次建立的映射
    for (const fwd of createdForwards) {
      runAdb(['-s', serial, 'forward', '--remove', fwd]);
    }
  }
}

/**
 * 显式切换手机端第一跳策略组选中节点并立即回读验证（独立于只读查看）。
 */
export async function selectAndroidFirstHop({
  serial,
  controllerPort = 19090,
  localControllerPort = 19092,
  secret,
  groupName = 'Static-First-Hop',
  hopName
}) {
  if (!serial || !secret || !hopName) {
    throw new Error('缺少设备序列号、Controller 令牌或目标节点名称');
  }
  const busy = await checkTcpPortOpen(localControllerPort, '127.0.0.1', 400);
  if (busy.open) {
    throw new Error(`本机端口 ${localControllerPort} 被占用`);
  }
  const fwd = runAdb(['-s', serial, 'forward', '--no-rebind', `tcp:${localControllerPort}`, `tcp:${controllerPort}`]);
  if (!fwd.ok) {
    throw new Error(`建立 ADB 转发失败: ${fwd.stderr}`);
  }
  try {
    const controllerUrl = `http://127.0.0.1:${localControllerPort}`;
    const encoded = encodeURIComponent(groupName);
    const before = await callMihomoApi({ controllerUrl, secret, apiPath: `/proxies/${encoded}` });
    await callMihomoApi({
      controllerUrl,
      secret,
      apiPath: `/proxies/${encoded}`,
      method: 'PUT',
      body: { name: hopName }
    });
    const after = await callMihomoApi({ controllerUrl, secret, apiPath: `/proxies/${encoded}` });
    if (after?.now !== hopName) {
      throw new Error(`切换后回读不匹配：期望 ${hopName}，实际 ${after?.now}`);
    }
    return {
      status: 'pass',
      previousHop: before?.now || null,
      currentHop: after.now
    };
  } finally {
    runAdb(['-s', serial, 'forward', '--remove', `tcp:${localControllerPort}`]);
  }
}
