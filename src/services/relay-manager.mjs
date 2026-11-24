import path from 'node:path';
import fs from 'node:fs';
import { spawn } from 'node:child_process';
import { probeRelayHealth } from './probe-service.mjs';

export class RelayManager {
  constructor(projectRoot) {
    this.projectRoot = projectRoot;
    this.relayScript = path.join(projectRoot, 'runtime', 'StaticChainIPv4Relay.cjs');
    this.child = null;
    this.managedPid = null;
  }

  async getStatus(listenPort = 17902) {
    const health = await probeRelayHealth(listenPort);
    const running = health.status === 'pass';
    return {
      running,
      managedByStudio: Boolean(this.child && !this.child.killed && this.child.exitCode === null),
      pid: this.managedPid,
      listenPort: Number(listenPort),
      health
    };
  }

  async start({ listenPort = 17902, upstreamPort = 17901 } = {}) {
    const current = await this.getStatus(listenPort);
    if (current.running) {
      return { started: false, alreadyRunning: true, ...current };
    }
    if (!fs.existsSync(this.relayScript)) {
      throw new Error(`未找到内置 IPv4 Relay 脚本: ${this.relayScript}`);
    }

    const child = spawn(process.execPath, [this.relayScript], {
      cwd: this.projectRoot,
      env: {
        ...process.env,
        STATIC_CHAIN_LISTEN_PORT: String(listenPort),
        STATIC_CHAIN_UPSTREAM_PORT: String(upstreamPort)
      },
      stdio: 'ignore',
      windowsHide: true
    });
    this.child = child;
    this.managedPid = child.pid;
    child.on('exit', () => {
      if (this.child === child) {
        this.child = null;
        this.managedPid = null;
      }
    });

    const deadline = Date.now() + 4000;
    while (Date.now() < deadline) {
      const check = await probeRelayHealth(listenPort, 600);
      if (check.status === 'pass') {
        return {
          started: true,
          alreadyRunning: false,
          running: true,
          managedByStudio: true,
          pid: this.managedPid,
          listenPort: Number(listenPort),
          health: check
        };
      }
      await new Promise(r => setTimeout(r, 200));
    }
    throw new Error(`IPv4 Relay (127.0.0.1:${listenPort}) 启动超时，请检查端口占用`);
  }

  async stop(listenPort = 17902) {
    if (this.child && this.child.exitCode === null) {
      try { this.child.kill('SIGTERM'); } catch { /* ignore */ }
      await new Promise(r => setTimeout(r, 300));
      if (this.child && this.child.exitCode === null) {
        try { this.child.kill('SIGKILL'); } catch { /* ignore */ }
      }
      this.child = null;
      this.managedPid = null;
    }
    const status = await this.getStatus(listenPort);
    return { stopped: !status.running, ...status };
  }
}
