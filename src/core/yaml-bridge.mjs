import { spawnSync } from 'node:child_process';

const PY_PARSE_SCRIPT = `
import sys, json, yaml
raw = sys.stdin.read()
data = yaml.safe_load(raw)
sys.stdout.write(json.dumps(data, ensure_ascii=False))
`;

const PY_DUMP_SCRIPT = `
import sys, json, yaml
data = json.loads(sys.stdin.read())
out = yaml.safe_dump(data, allow_unicode=True, sort_keys=False, default_flow_style=False, width=4096)
sys.stdout.write(out)
`;

function runPython(code, inputText) {
  const candidates = process.platform === 'win32' ? ['python', 'py'] : ['python3', 'python'];
  let lastError = null;
  for (const bin of candidates) {
    const args = bin === 'py' ? ['-3', '-X', 'utf8', '-c', code] : ['-X', 'utf8', '-c', code];
    const res = spawnSync(bin, args, {
      input: inputText,
      encoding: 'utf8',
      windowsHide: true,
      maxBuffer: 64 * 1024 * 1024,
      env: { ...process.env, PYTHONUTF8: '1', PYTHONIOENCODING: 'utf-8' }
    });
    if (res.error) {
      lastError = res.error;
      continue;
    }
    if (res.status !== 0) {
      throw new Error(`YAML 处理失败: ${(res.stderr || res.stdout || '').trim()}`);
    }
    return res.stdout;
  }
  throw new Error(`未找到可用的 Python 3 环境来解析 YAML (${lastError?.message || 'unknown'})`);
}

export function parseYaml(yamlText) {
  if (typeof yamlText !== 'string' || !yamlText.trim()) {
    return {};
  }
  const jsonText = runPython(PY_PARSE_SCRIPT, yamlText);
  const parsed = JSON.parse(jsonText);
  return parsed === null || parsed === undefined ? {} : parsed;
}

export function dumpYaml(value) {
  const jsonText = JSON.stringify(value);
  return runPython(PY_DUMP_SCRIPT, jsonText);
}

/**
 * 尝试将 Base64 编码的订阅文本或单行 URI 列表（ss://, trojan:// 等）标准化为 Clash 配置对象。
 * 优先解析标准 Clash/Mihomo YAML。
 */
export function parseSubscriptionContent(rawText) {
  const trimmed = String(rawText || '').trim();
  if (!trimmed) {
    throw new Error('订阅内容为空');
  }

  // 先尝试直接按 YAML 解析
  try {
    const direct = parseYaml(trimmed);
    if (direct && typeof direct === 'object' && !Array.isArray(direct) && (Array.isArray(direct.proxies) || Array.isArray(direct.rules) || Array.isArray(direct['proxy-groups']))) {
      return direct;
    }
  } catch {
    // 继续尝试 Base64
  }

  // 尝试 Base64 解码（常见机场通用订阅）
  const compact = trimmed.replace(/\s+/g, '');
  if (/^[A-Za-z0-9+/_-]+=*$/.test(compact) && compact.length >= 16) {
    const normalized = compact.replace(/-/g, '+').replace(/_/g, '/');
    const decoded = Buffer.from(normalized, 'base64').toString('utf8');
    // 解码后可能是 YAML
    try {
      const asYaml = parseYaml(decoded);
      if (asYaml && typeof asYaml === 'object' && !Array.isArray(asYaml) && Array.isArray(asYaml.proxies)) {
        return asYaml;
      }
    } catch {
      // 也可能是 URI 行列表
    }
    const proxies = parseProxyUriLines(decoded);
    if (proxies.length > 0) {
      return { proxies, 'proxy-groups': [], rules: [] };
    }
  }

  // 直接按 URI 行列表解析
  const directUris = parseProxyUriLines(trimmed);
  if (directUris.length > 0) {
    return { proxies: directUris, 'proxy-groups': [], rules: [] };
  }

  throw new Error('无法识别该订阅格式，请提供 Clash/Mihomo YAML 订阅或标准代理 URI 列表');
}

function parseProxyUriLines(text) {
  const lines = String(text || '').split(/\r?\n/).map(l => l.trim()).filter(Boolean);
  const proxies = [];
  for (const line of lines) {
    try {
      if (line.startsWith('ss://')) {
        const parsed = parseShadowsocksUri(line);
        if (parsed) proxies.push(parsed);
      } else if (line.startsWith('trojan://')) {
        const u = new URL(line);
        const name = decodeURIComponent(u.hash.replace(/^#/, '') || `${u.hostname}:${u.port}`);
        proxies.push({
          name,
          type: 'trojan',
          server: u.hostname,
          port: Number(u.port || 443),
          password: decodeURIComponent(u.username || ''),
          sni: u.searchParams.get('sni') || u.searchParams.get('peer') || u.hostname,
          'skip-cert-verify': u.searchParams.get('allowInsecure') === '1'
        });
      } else if (line.startsWith('vmess://')) {
        const body = Buffer.from(line.slice(8).trim(), 'base64').toString('utf8');
        const obj = JSON.parse(body);
        proxies.push({
          name: obj.ps || `${obj.add}:${obj.port}`,
          type: 'vmess',
          server: obj.add,
          port: Number(obj.port),
          uuid: obj.id,
          alterId: Number(obj.aid || 0),
          cipher: obj.scy || 'auto',
          tls: obj.tls === 'tls',
          network: obj.net || 'tcp',
          servername: obj.sni || obj.host || undefined
        });
      } else if (line.startsWith('http://') || line.startsWith('https://') || line.startsWith('socks5://')) {
        const u = new URL(line);
        const type = u.protocol.startsWith('socks') ? 'socks5' : 'http';
        const name = decodeURIComponent(u.hash.replace(/^#/, '') || `${type}-${u.hostname}:${u.port}`);
        const node = {
          name,
          type,
          server: u.hostname,
          port: Number(u.port || (type === 'socks5' ? 1080 : 8080))
        };
        if (u.username) node.username = decodeURIComponent(u.username);
        if (u.password) node.password = decodeURIComponent(u.password);
        proxies.push(node);
      }
    } catch {
      // 跳过单条无法解析的 URI
    }
  }
  return proxies;
}

function parseShadowsocksUri(uri) {
  const hashIdx = uri.indexOf('#');
  const rawName = hashIdx >= 0 ? decodeURIComponent(uri.slice(hashIdx + 1)) : '';
  const mainPart = hashIdx >= 0 ? uri.slice(5, hashIdx) : uri.slice(5);
  const queryIdx = mainPart.indexOf('?');
  const core = queryIdx >= 0 ? mainPart.slice(0, queryIdx) : mainPart;

  let cipher = '';
  let password = '';
  let server = '';
  let port = 0;

  if (core.includes('@')) {
    const [userInfo, hostPort] = core.split('@');
    let decodedUser = userInfo;
    if (!userInfo.includes(':')) {
      decodedUser = Buffer.from(userInfo.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
    }
    const colon = decodedUser.indexOf(':');
    cipher = decodedUser.slice(0, colon);
    password = decodedUser.slice(colon + 1);
    const lastColon = hostPort.lastIndexOf(':');
    server = hostPort.slice(0, lastColon).replace(/^\[|\]$/g, '');
    port = Number(hostPort.slice(lastColon + 1));
  } else {
    const decoded = Buffer.from(core.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
    const at = decoded.lastIndexOf('@');
    const [methodPass, hostPort] = [decoded.slice(0, at), decoded.slice(at + 1)];
    const colon = methodPass.indexOf(':');
    cipher = methodPass.slice(0, colon);
    password = methodPass.slice(colon + 1);
    const lastColon = hostPort.lastIndexOf(':');
    server = hostPort.slice(0, lastColon).replace(/^\[|\]$/g, '');
    port = Number(hostPort.slice(lastColon + 1));
  }

  if (!server || !Number.isInteger(port) || port <= 0) return null;
  return {
    name: rawName || `${server}:${port}`,
    type: 'ss',
    server,
    port,
    cipher,
    password,
    udp: true
  };
}
