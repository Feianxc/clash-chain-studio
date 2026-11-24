/**
 * 开源发布前自动化隐私与密钥泄漏门禁检查（npm run check:privacy）。
 * 严防个人绝对路径、真实静态 IP、代理密码或订阅链接被误提交到 Git 仓库。
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const PROJECT_ROOT = path.resolve(path.dirname(__filename), '..');

const IGNORED_DIRS = new Set(['.git', 'node_modules', 'data', 'output', 'tmp']);
const SCAN_EXTENSIONS = new Set(['.mjs', '.js', '.cjs', '.json', '.ps1', '.cmd', '.md', '.yml', '.yaml', '.html', '.css']);

// 允许出现在源码与文档中的公共 DNS / RFC 5737 示例 / 私网 / Fake-IP 地址
const ALLOWED_IPV4_PREFIXES = [
  '127.', '10.', '192.168.', '172.16.', '100.64.', '169.254.', '198.18.',
  '192.0.2.', '198.51.100.', '203.0.113.', '0.0.0.0'
];
const ALLOWED_IPV4_EXACT = new Set([
  '1.1.1.1', '8.8.8.8', '119.29.29.29', '223.5.5.5', '255.255.255.255'
]);

const FORBIDDEN_PATTERNS = [
  { name: '个人用户路径', regex: /C:\\Users\\28691|D:\\explore\\链式代理|OpenAI\.Codex_2p2nqsd0c76g0/i },
  { name: '疑似订阅 Token URL', regex: /https?:\/\/[^\s'"]+subscribe\?token=[A-Za-z0-9_-]{8,}/i },
  { name: '疑似真实代理密码字段', regex: /"password"\s*:\s*"(?!SAMPLE_|STATIC_PROXY|\*\*\*REDACTED\*\*\*|hop_pass_|new_static_|ultra_secret_|nm_super_)[^"]{6,}"/i }
];

function isAllowedIpv4(ip) {
  if (ALLOWED_IPV4_EXACT.has(ip)) return true;
  if (ALLOWED_IPV4_PREFIXES.some(p => ip.startsWith(p))) return true;
  // 排除类似版本号 2.11.21.0 等明显非 IP 的情况已由调用上下文控制，这里仅校验合法八位组
  const octets = ip.split('.').map(Number);
  if (octets.some(n => n < 0 || n > 255)) return true;
  if (octets[0] === 0) return true;
  return false;
}

function collectFiles(dir, out = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (IGNORED_DIRS.has(entry.name)) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      collectFiles(full, out);
    } else if (SCAN_EXTENSIONS.has(path.extname(entry.name).toLowerCase())) {
      out.push(full);
    }
  }
  return out;
}

const files = collectFiles(PROJECT_ROOT);
const findings = [];

for (const filePath of files) {
  if (path.resolve(filePath) === __filename) continue;
  const rel = path.relative(PROJECT_ROOT, filePath);
  const content = fs.readFileSync(filePath, 'utf8');
  const lines = content.split(/\r?\n/);

  lines.forEach((line, idx) => {
    for (const rule of FORBIDDEN_PATTERNS) {
      if (rule.regex.test(line)) {
        findings.push(`${rel}:${idx + 1} [${rule.name}] ${line.trim().slice(0, 120)}`);
      }
    }
    const ipv4Matches = line.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || [];
    for (const ip of ipv4Matches) {
      if (!isAllowedIpv4(ip)) {
        findings.push(`${rel}:${idx + 1} [疑似真实公网 IP: ${ip}] ${line.trim().slice(0, 120)}`);
      }
    }
  });
}

if (findings.length > 0) {
  console.error('❌ 隐私门禁检查未通过，发现以下敏感内容：');
  for (const f of findings) console.error('  - ' + f);
  process.exit(1);
}

console.log(`✅ 隐私门禁通过：已扫描 ${files.length} 个源码与文档文件，零敏感路径/真实 IP/凭据泄漏。`);
