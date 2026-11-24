import net from 'node:net';
import http from 'node:http';
import { spawn } from 'node:child_process';

export function checkTcpPortOpen(port, host = '127.0.0.1', timeoutMs = 1200) {
  return new Promise((resolve) => {
    const socket = net.connect({ host, port: Number(port) });
    let done = false;
    const finish = (open, error = null) => {
      if (done) return;
      done = true;
      socket.destroy();
      resolve({ open, host, port: Number(port), error });
    };
    socket.setTimeout(timeoutMs);
    socket.once('connect', () => finish(true));
    socket.once('timeout', () => finish(false, 'TIMEOUT'));
    socket.once('error', (err) => finish(false, err.code || 'CONNECT_ERROR'));
  });
}

export function probeRelayHealth(port = 17902, timeoutMs = 2000) {
  return new Promise((resolve) => {
    const req = http.get(
      { host: '127.0.0.1', port: Number(port), path: '/health', timeout: timeoutMs },
      (res) => {
        let body = '';
        res.setEncoding('utf8');
        res.on('data', (chunk) => { body += chunk; });
        res.on('end', () => {
          let json = null;
          try { json = JSON.parse(body); } catch { /* ignore */ }
          const ok = res.statusCode === 200 && Boolean(json?.service?.includes('StaticChainIPv4Relay'));
          resolve({
            status: ok ? 'pass' : 'fail',
            httpCode: res.statusCode,
            data: json,
            raw: ok ? undefined : body.slice(0, 200)
          });
        });
      }
    );
    req.on('timeout', () => { req.destroy(); resolve({ status: 'fail', error: 'TIMEOUT' }); });
    req.on('error', (err) => resolve({ status: 'fail', error: err.code || err.message }));
  });
}

export function runCurlProbe({ url, proxyUrl, connectTimeout = 5, maxTime = 12 }) {
  return new Promise((resolve) => {
    const curlBin = process.platform === 'win32' ? 'curl.exe' : 'curl';
    const args = [
      '--silent',
      '--show-error',
      '--noproxy', '',
      '--connect-timeout', String(connectTimeout),
      '--max-time', String(maxTime),
      '--write-out', '\n__METRICS__ %{http_code} %{time_connect} %{time_appconnect} %{time_total}'
    ];
    if (proxyUrl) {
      args.push('--proxy', proxyUrl);
    }
    args.push(url);

    const started = Date.now();
    const child = spawn(curlBin, args, { windowsHide: true });
    let stdout = '';
    let stderr = '';
    const killTimer = setTimeout(() => {
      try { child.kill(); } catch { /* ignore */ }
    }, (maxTime + 4) * 1000);

    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; });

    child.on('error', (err) => {
      clearTimeout(killTimer);
      resolve({
        ok: false,
        exitCode: -1,
        httpCode: 0,
        body: '',
        stderr: err.message,
        stage: 'curl-spawn-error',
        totalSec: Number(((Date.now() - started) / 1000).toFixed(3))
      });
    });

    child.on('close', (code) => {
      clearTimeout(killTimer);
      const markerIdx = stdout.lastIndexOf('\n__METRICS__ ');
      let body = stdout;
      let httpCode = 0;
      let connectSec = 0;
      let tlsSec = 0;
      let totalSec = Number(((Date.now() - started) / 1000).toFixed(3));

      if (markerIdx >= 0) {
        body = stdout.slice(0, markerIdx).trim();
        const fields = stdout.slice(markerIdx + '\n__METRICS__ '.length).trim().split(/\s+/);
        if (fields.length >= 4) {
          httpCode = Number(fields[0]) || 0;
          connectSec = Number(fields[1]) || 0;
          tlsSec = Number(fields[2]) || 0;
          totalSec = Number(fields[3]) || totalSec;
        }
      }

      let stage = 'ok';
      if (code !== 0) {
        if (code === 7) stage = 'proxy-connect-failed';
        else if (code === 28) stage = 'timeout';
        else if (code === 35) stage = 'tls-handshake-failed';
        else if (code === 56) stage = 'proxy-tunnel-reset';
        else if (code === 6) stage = 'dns-resolve-failed';
        else stage = `curl-exit-${code}`;
      } else if (httpCode === 0) {
        stage = 'no-http-response';
      }

      resolve({
        ok: code === 0 && httpCode >= 200 && httpCode < 400,
        exitCode: code,
        httpCode,
        connectSec: Number(connectSec.toFixed(3)),
        tlsSec: Number(tlsSec.toFixed(3)),
        totalSec: Number(totalSec.toFixed(3)),
        body,
        stderr: stderr.trim(),
        stage
      });
    });
  });
}

/**
 * 端到端探测某个本机代理入口的静态出口、地区、国内直连与海外可达性。
 */
export async function probeProxyEndpoint({
  label = 'Windows 分流入口',
  proxyPort = 7897,
  expectedIp = '',
  samples = 3,
  checkDomestic = true,
  checkOverseas = true
}) {
  const startedAt = new Date().toISOString();
  const proxyUrl = `http://127.0.0.1:${Number(proxyPort)}`;
  const portCheck = await checkTcpPortOpen(proxyPort);

  if (!portCheck.open) {
    return {
      label,
      proxyPort: Number(proxyPort),
      expectedIp,
      startedAt,
      finishedAt: new Date().toISOString(),
      status: 'blocked',
      stage: 'port-closed',
      message: `本机端口 127.0.0.1:${proxyPort} 未监听 (${portCheck.error})`,
      portOpen: false,
      ipSamples: [],
      observedIp: null,
      ipinfo: null,
      domestic: { status: 'not run' },
      overseas: { status: 'not run' }
    };
  }

  const ipSamples = [];
  let observedIp = null;
  let mismatchFound = false;

  for (let i = 0; i < Math.max(1, Math.min(samples, 20)); i++) {
    const res = await runCurlProbe({ url: 'https://api.ipify.org', proxyUrl, connectTimeout: 5, maxTime: 10 });
    const ip = res.ok ? res.body.trim() : null;
    if (ip && !observedIp) observedIp = ip;
    const ipMatch = ip && expectedIp ? ip === expectedIp.trim() : null;
    if (ipMatch === false) mismatchFound = true;
    ipSamples.push({
      attempt: i + 1,
      ok: res.ok && (ipMatch !== false),
      ip,
      ipMatch,
      httpCode: res.httpCode,
      exitCode: res.exitCode,
      totalSec: res.totalSec,
      stage: ipMatch === false ? 'ip-mismatch' : res.stage,
      error: res.stderr || undefined
    });
    if (ipMatch === false) break; // 发现出口漂移立即停止并报警
  }

  // 交叉确认 ipinfo
  let ipinfo = null;
  if (observedIp) {
    const infoRes = await runCurlProbe({ url: 'https://ipinfo.io/json', proxyUrl, connectTimeout: 5, maxTime: 10 });
    if (infoRes.ok) {
      try {
        const data = JSON.parse(infoRes.body);
        ipinfo = {
          status: !expectedIp || data.ip === expectedIp.trim() ? 'pass' : 'fail',
          ip: data.ip,
          country: data.country,
          region: data.region,
          city: data.city,
          org: data.org,
          timezone: data.timezone,
          totalSec: infoRes.totalSec
        };
      } catch {
        ipinfo = { status: 'partial', raw: infoRes.body.slice(0, 160), totalSec: infoRes.totalSec };
      }
    } else {
      ipinfo = { status: 'fail', stage: infoRes.stage, exitCode: infoRes.exitCode, totalSec: infoRes.totalSec };
    }
  }

  // 国内目标探测（仅作 HTTP 连通性提示，真实 DIRECT 命中需结合 Core /connections）
  let domestic = { status: 'not run' };
  if (checkDomestic) {
    const cnRes = await runCurlProbe({ url: 'https://www.baidu.com', proxyUrl, connectTimeout: 5, maxTime: 10 });
    domestic = {
      status: cnRes.ok ? 'pass' : 'fail',
      target: 'https://www.baidu.com',
      httpCode: cnRes.httpCode,
      totalSec: cnRes.totalSec,
      stage: cnRes.stage,
      note: 'HTTP 可达（精确 DIRECT 命中需结合 Mihomo /connections 核对）'
    };
  }

  // 海外目标探测
  let overseas = { status: 'not run' };
  if (checkOverseas) {
    const ovRes = await runCurlProbe({ url: 'https://play.google.com', proxyUrl, connectTimeout: 5, maxTime: 10 });
    overseas = {
      status: ovRes.ok ? 'pass' : 'fail',
      target: 'https://play.google.com',
      httpCode: ovRes.httpCode,
      totalSec: ovRes.totalSec,
      stage: ovRes.stage
    };
  }

  const passedCount = ipSamples.filter(s => s.ok).length;
  const latencies = ipSamples.filter(s => s.ok).map(s => s.totalSec);
  const meanSec = latencies.length ? Number((latencies.reduce((a, b) => a + b, 0) / latencies.length).toFixed(3)) : null;
  const maxSec = latencies.length ? Math.max(...latencies) : null;

  let status = 'pass';
  let stage = 'verified';
  let message = `静态出口 ${observedIp || '(未知)'} 验证通过 (${passedCount}/${ipSamples.length})`;

  if (mismatchFound) {
    status = 'fail';
    stage = 'ip-mismatch';
    message = `出口 IP 不符！预期 ${expectedIp}，实测 ${observedIp}（请勿启动受保护应用）`;
  } else if (passedCount === 0) {
    status = 'fail';
    stage = ipSamples[0]?.stage || 'probe-failed';
    message = `全部探测失败 (${stage})`;
  } else if (passedCount < ipSamples.length || (checkDomestic && domestic.status === 'fail')) {
    status = 'partial';
    stage = 'partial-pass';
    message = `部分样本通过 (${passedCount}/${ipSamples.length})`;
  }

  return {
    label,
    proxyPort: Number(proxyPort),
    expectedIp,
    startedAt,
    finishedAt: new Date().toISOString(),
    status,
    stage,
    message,
    portOpen: true,
    observedIp,
    passedCount,
    totalSamples: ipSamples.length,
    meanSec,
    maxSec,
    ipSamples,
    ipinfo,
    domestic,
    overseas
  };
}

/**
 * 调用 Mihomo External Controller API（严格区分只读 GET 与变更 PUT）。
 */
export function callMihomoApi({ controllerUrl, secret = '', apiPath, method = 'GET', body = null, timeoutMs = 6000 }) {
  return new Promise((resolve, reject) => {
    const url = new URL(apiPath, controllerUrl.endsWith('/') ? controllerUrl : `${controllerUrl}/`);
    const payload = body !== null ? JSON.stringify(body) : null;
    const headers = { Accept: 'application/json' };
    if (secret) headers.Authorization = `Bearer ${secret}`;
    if (payload !== null) {
      headers['Content-Type'] = 'application/json';
      headers['Content-Length'] = Buffer.byteLength(payload);
    }

    const req = http.request(
      {
        hostname: url.hostname,
        port: Number(url.port || 80),
        path: url.pathname + url.search,
        method,
        headers,
        timeout: timeoutMs
      },
      (res) => {
        let text = '';
        res.setEncoding('utf8');
        res.on('data', (chunk) => { text += chunk; });
        res.on('end', () => {
          if (res.statusCode < 200 || res.statusCode >= 300) {
            return reject(new Error(`Mihomo API ${method} ${apiPath} 返回 HTTP ${res.statusCode}: ${text.slice(0, 200)}`));
          }
          if (!text.trim()) return resolve(null);
          try {
            resolve(JSON.parse(text));
          } catch {
            resolve(text);
          }
        });
      }
    );
    req.on('timeout', () => { req.destroy(); reject(new Error(`Mihomo API 请求超时: ${apiPath}`)); });
    req.on('error', (err) => reject(new Error(`无法连接 Mihomo Controller (${controllerUrl}): ${err.message}`)));
    if (payload !== null) req.write(payload);
    req.end();
  });
}

/**
 * 固定静态末跳，逐一筛选第一跳并复测前 N 名；结束后强制恢复测试前的真实选中节点。
 */
export async function benchmarkFirstHops({
  controllerUrl,
  secret = '',
  groupName = 'Static-First-Hop',
  proxyPort = 7897,
  expectedIp,
  candidates = null,
  screenSamples = 2,
  finalistCount = 5,
  finalistSamples = 5,
  onProgress = null
}) {
  const startedAt = new Date().toISOString();
  const encodedGroup = encodeURIComponent(groupName);
  const groupInfo = await callMihomoApi({ controllerUrl, secret, apiPath: `/proxies/${encodedGroup}` });
  if (!groupInfo || !Array.isArray(groupInfo.all)) {
    throw new Error(`策略组 ${groupName} 不存在或不可切换`);
  }

  const originalSelection = groupInfo.now;
  const targetList = Array.isArray(candidates) && candidates.length
    ? candidates.filter(name => groupInfo.all.includes(name))
    : groupInfo.all.filter(name => name !== 'DIRECT' && name !== 'REJECT');

  if (targetList.length === 0) {
    throw new Error(`策略组 ${groupName} 中没有可测速的候选节点`);
  }

  const proxyUrl = `http://127.0.0.1:${Number(proxyPort)}`;
  const rows = [];
  const finalists = [];
  let abortedReason = null;
  let restoreStatus = 'pending';

  const selectAndVerify = async (hopName) => {
    await callMihomoApi({
      controllerUrl,
      secret,
      apiPath: `/proxies/${encodedGroup}`,
      method: 'PUT',
      body: { name: hopName }
    });
    const readback = await callMihomoApi({ controllerUrl, secret, apiPath: `/proxies/${encodedGroup}` });
    if (readback?.now !== hopName) {
      throw new Error(`节点切换回读不一致：期望 ${hopName}，实际 ${readback?.now}`);
    }
  };

  try {
    // 第一轮：逐节点快速初筛
    for (let i = 0; i < targetList.length; i++) {
      const name = targetList[i];
      await selectAndVerify(name);
      const samples = [];
      for (let s = 0; s < screenSamples; s++) {
        const res = await runCurlProbe({ url: 'https://api.ipify.org', proxyUrl, connectTimeout: 5, maxTime: 10 });
        const ip = res.ok ? res.body.trim() : null;
        const ipMatch = ip && expectedIp ? ip === expectedIp.trim() : null;
        const ok = res.ok && ipMatch !== false;
        samples.push({ ok, httpCode: res.httpCode, exitCode: res.exitCode, totalSec: res.totalSec, ipMatch, stage: res.stage });
        if (ipMatch === false) {
          abortedReason = `节点「${name}」实测出口为 ${ip}，与预期 ${expectedIp} 不符，已中止测速`;
          break;
        }
      }
      const good = samples.filter(x => x.ok).map(x => x.totalSec);
      const row = {
        name,
        successCount: good.length,
        totalCount: samples.length,
        passRate: Number((good.length / samples.length).toFixed(2)),
        meanSec: good.length ? Number((good.reduce((a, b) => a + b, 0) / good.length).toFixed(3)) : null,
        maxSec: good.length ? Math.max(...good) : null,
        samples
      };
      rows.push(row);
      if (onProgress) onProgress({ phase: 'screen', index: i + 1, total: targetList.length, row });
      if (abortedReason) break;
    }

    // 第二轮：复测通过率最高、均值最快的前 N 名
    if (!abortedReason && finalistCount > 0) {
      const top = [...rows]
        .filter(r => r.successCount === r.totalCount && r.meanSec !== null)
        .sort((a, b) => a.meanSec - b.meanSec)
        .slice(0, finalistCount);

      for (let i = 0; i < top.length; i++) {
        const name = top[i].name;
        await selectAndVerify(name);
        const samples = [];
        for (let s = 0; s < finalistSamples; s++) {
          const res = await runCurlProbe({ url: 'https://api.ipify.org', proxyUrl, connectTimeout: 5, maxTime: 10 });
          const ip = res.ok ? res.body.trim() : null;
          const ipMatch = ip && expectedIp ? ip === expectedIp.trim() : null;
          const ok = res.ok && ipMatch !== false;
          samples.push({ ok, httpCode: res.httpCode, exitCode: res.exitCode, totalSec: res.totalSec, ipMatch, stage: res.stage });
          if (ipMatch === false) {
            abortedReason = `复测节点「${name}」出口不符 (${ip})，已中止`;
            break;
          }
          if (samples.length >= 2 && !samples[samples.length - 1].ok && !samples[samples.length - 2].ok) {
            break;
          }
        }
        const play = samples.every(x => x.ok)
          ? await runCurlProbe({ url: 'https://play.google.com', proxyUrl, connectTimeout: 5, maxTime: 10 })
          : null;
        const good = samples.filter(x => x.ok).map(x => x.totalSec);
        const entry = {
          name,
          successCount: good.length,
          totalCount: samples.length,
          meanSec: good.length ? Number((good.reduce((a, b) => a + b, 0) / good.length).toFixed(3)) : null,
          maxSec: good.length ? Math.max(...good) : null,
          playHttp: play ? play.httpCode : null,
          playSec: play ? play.totalSec : null,
          samples
        };
        finalists.push(entry);
        if (onProgress) onProgress({ phase: 'finalist', index: i + 1, total: top.length, entry });
        if (abortedReason) break;
      }
    }
  } finally {
    // 严格恢复测速前的真实选中节点
    if (originalSelection) {
      try {
        await selectAndVerify(originalSelection);
        restoreStatus = `pass (${originalSelection})`;
      } catch (err) {
        restoreStatus = `fail: ${err.message}`;
      }
    }
  }

  finalists.sort((a, b) => {
    if (b.successCount !== a.successCount) return b.successCount - a.successCount;
    return (a.meanSec ?? 999) - (b.meanSec ?? 999);
  });

  return {
    startedAt,
    finishedAt: new Date().toISOString(),
    groupName,
    proxyPort: Number(proxyPort),
    expectedIp,
    originalSelection,
    restoreStatus,
    status: abortedReason ? 'fail' : (finalists.length > 0 ? 'pass' : 'partial'),
    abortedReason,
    candidateCount: targetList.length,
    recommendedHop: finalists[0]?.name || rows.filter(r => r.meanSec !== null).sort((a, b) => a.meanSec - b.meanSec)[0]?.name || null,
    rows,
    finalists
  };
}

/**
 * 拉取远程 Clash/Mihomo 订阅 URL，并解析 Subscription-Userinfo 流量与过期信息。
 */
export async function fetchSubscriptionFromUrl(url, proxyUrl = null) {
  const parsed = new URL(url);
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error('订阅地址必须以 http:// 或 https:// 开头');
  }

  return new Promise((resolve, reject) => {
    const curlBin = process.platform === 'win32' ? 'curl.exe' : 'curl';
    const args = [
      '--silent', '--show-error', '--location',
      '--connect-timeout', '10', '--max-time', '25',
      '--include',
      '-H', 'User-Agent: clash-verge/v2.0.0 mihomo/1.19',
      url
    ];
    if (proxyUrl) {
      args.unshift('--proxy', proxyUrl);
    } else {
      args.unshift('--noproxy', '*');
    }

    const child = spawn(curlBin, args, { windowsHide: true });
    const chunks = [];
    let stderr = '';
    child.stdout.on('data', d => chunks.push(d));
    child.stderr.setEncoding('utf8');
    child.stderr.on('data', d => { stderr += d; });
    child.on('error', err => reject(new Error(`订阅拉取失败: ${err.message}`)));
    child.on('close', code => {
      if (code !== 0) {
        return reject(new Error(`订阅拉取失败 (curl exit ${code}): ${stderr.trim()}`));
      }
      const raw = Buffer.concat(chunks).toString('utf8');
      // 处理重定向后的最后一个 HTTP 响应头
      const parts = raw.split(/\r?\n\r?\n/);
      let headerBlock = '';
      let bodyStartIdx = 1;
      for (let i = 0; i < parts.length - 1; i++) {
        if (/^HTTP\/\d/i.test(parts[i].trim())) {
          headerBlock = parts[i];
          bodyStartIdx = i + 1;
        }
      }
      const body = parts.slice(bodyStartIdx).join('\n\n');
      const statusMatch = /^HTTP\/\d(?:\.\d)?\s+(\d{3})/i.exec(headerBlock.trim());
      const statusCode = statusMatch ? Number(statusMatch[1]) : 200;
      if (statusCode < 200 || statusCode >= 300) {
        return reject(new Error(`订阅服务器返回 HTTP ${statusCode}`));
      }

      const userInfoMatch = /^subscription-userinfo:\s*(.+)$/im.exec(headerBlock);
      const trafficInfo = userInfoMatch ? formatSubscriptionUserInfo(userInfoMatch[1]) : null;
      resolve({ body, statusCode, trafficInfo });
    });
  });
}

export function formatSubscriptionUserInfo(headerValue) {
  const fields = {};
  for (const part of String(headerValue || '').split(';')) {
    const [k, v] = part.trim().split('=');
    if (k && v) fields[k.trim().toLowerCase()] = Number(v.trim());
  }
  const toGb = (bytes) => Number.isFinite(bytes) ? `${(bytes / (1024 ** 3)).toFixed(1)} GB` : '?';
  const used = (fields.upload || 0) + (fields.download || 0);
  const total = fields.total;
  const expire = fields.expire ? new Date(fields.expire * 1000).toISOString().slice(0, 10) : null;
  const chunks = [];
  if (Number.isFinite(total)) chunks.push(`已用 ${toGb(used)} / ${toGb(total)}`);
  if (expire) chunks.push(`到期 ${expire}`);
  return chunks.join(' · ') || headerValue.trim();
}
