import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

export function writeFileAtomic(filePath, content) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  const tmp = `${filePath}.${process.pid}.${crypto.randomBytes(4).toString('hex')}.tmp`;
  try {
    fs.writeFileSync(tmp, content, 'utf8');
    fs.renameSync(tmp, filePath);
  } finally {
    if (fs.existsSync(tmp)) {
      try { fs.unlinkSync(tmp); } catch { /* ignore */ }
    }
  }
}

export class LocalSecretVault {
  constructor(dataDir) {
    this.dataDir = dataDir;
    this.keyPath = path.join(dataDir, '.vault.key');
    this.vaultPath = path.join(dataDir, 'vault.local.json');
    fs.mkdirSync(dataDir, { recursive: true });
  }

  #getKey() {
    if (!fs.existsSync(this.keyPath)) {
      const key = crypto.randomBytes(32);
      writeFileAtomic(this.keyPath, key.toString('hex'));
      return key;
    }
    const hex = fs.readFileSync(this.keyPath, 'utf8').trim();
    return Buffer.from(hex, 'hex');
  }

  #loadRaw() {
    if (!fs.existsSync(this.vaultPath)) return {};
    try {
      const parsed = JSON.parse(fs.readFileSync(this.vaultPath, 'utf8'));
      return parsed && typeof parsed === 'object' ? parsed : {};
    } catch {
      return {};
    }
  }

  #saveRaw(map) {
    writeFileAtomic(this.vaultPath, JSON.stringify(map, null, 2));
  }

  setSecret(refId, secretValue) {
    const key = this.#getKey();
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const plaintext = JSON.stringify(secretValue);
    const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();

    const map = this.#loadRaw();
    map[refId] = {
      alg: 'aes-256-gcm',
      iv: iv.toString('base64'),
      tag: tag.toString('base64'),
      data: encrypted.toString('base64'),
      updatedAt: new Date().toISOString()
    };
    this.#saveRaw(map);
    return refId;
  }

  getSecret(refId) {
    if (!refId) return null;
    const map = this.#loadRaw();
    const entry = map[refId];
    if (!entry) return null;
    const key = this.#getKey();
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(entry.iv, 'base64'));
    decipher.setAuthTag(Buffer.from(entry.tag, 'base64'));
    const decrypted = Buffer.concat([
      decipher.update(Buffer.from(entry.data, 'base64')),
      decipher.final()
    ]).toString('utf8');
    return JSON.parse(decrypted);
  }

  hasSecret(refId) {
    if (!refId) return false;
    const map = this.#loadRaw();
    return Boolean(map[refId]);
  }

  deleteSecret(refId) {
    const map = this.#loadRaw();
    if (refId in map) {
      delete map[refId];
      this.#saveRaw(map);
    }
  }

  /**
   * 收集当前存储的所有敏感字符串用于报告脱敏。
   */
  collectSensitiveValues() {
    const map = this.#loadRaw();
    const secrets = new Set();
    for (const refId of Object.keys(map)) {
      try {
        const val = this.getSecret(refId);
        collectStrings(val, secrets);
      } catch { /* ignore */ }
    }
    return [...secrets].filter(s => typeof s === 'string' && s.length >= 4);
  }

  redactText(text) {
    let out = String(text ?? '');
    for (const secret of this.collectSensitiveValues()) {
      out = out.split(secret).join('***REDACTED***');
    }
    // 掩码常见凭据字段模式
    out = out.replace(/("password"\s*:\s*")([^"]+)(")/gi, '$1***REDACTED***$3');
    out = out.replace(/(password\s*:\s*)(['"]?)([^\s,'"\r\n]+)(\2)/gi, '$1***REDACTED***');
    out = out.replace(/(secret\s*:\s*)(['"]?)([^\s,'"\r\n]+)(\2)/gi, '$1***REDACTED***');
    out = out.replace(/(Bearer\s+)([A-Za-z0-9._~+/-]+)/gi, '$1***REDACTED***');
    return out;
  }

  redactObject(obj) {
    const json = JSON.stringify(obj);
    return JSON.parse(this.redactText(json));
  }
}

function collectStrings(value, target) {
  if (typeof value === 'string') {
    if (value.trim().length >= 4) target.add(value.trim());
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) collectStrings(item, target);
    return;
  }
  if (value && typeof value === 'object') {
    for (const [k, v] of Object.entries(value)) {
      if (['password', 'username', 'url', 'secret', 'token', 'uuid'].includes(k.toLowerCase())) {
        collectStrings(v, target);
      }
    }
  }
}
