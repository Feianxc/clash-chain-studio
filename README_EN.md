# Clash Chain Studio

<p align="center">
  <strong>Visual WYSIWYG Chained-Proxy &amp; Environment Consistency Studio for Mihomo / Clash Verge / Clash Meta for Android</strong><br/>
  Independently swap first-hop subscriptions and static residential exits, generate synchronized Desktop &amp; dual Android profiles, and verify IP/DNS/timezone/WebRTC consistency before launching AI clients.
</p>

<p align="center">
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/License-MIT-15803d.svg" /></a>
  <img alt="Node >= 20" src="https://img.shields.io/badge/Node.js-%3E%3D20-2563eb.svg" />
  <a href="README.md"><img alt="中文文档" src="https://img.shields.io/badge/Docs-简体中文-111827.svg" /></a>
</p>

---

## Key Features

- **Visual Dual-Lane Routing Canvas (WYSIWYG)**: Interactive topology separating **Static Chain Traffic** (AI / overseas apps) from **Direct Traffic** (local sites / game updates), with a built-in live route simulator.
- **Independent First-Hop & Static Exit Swapping**:
  - Import subscriptions via URL, YAML, Base64, proxy URIs (`ss://`, `trojan://`, `vmess://`), or read-only from local Clash Verge Rev.
  - Automatically filters pseudo info nodes, `DIRECT`, chained `dialer-proxy` entries, loopback servers, and duplicates, while auto-extracting upstream node hostnames into `dns.nameserver-policy`.
  - Separates proxy entry `server:port`, `expectedIp`, protocol (`HTTP` + IPv4 DoH Relay on Desktop / `SOCKS5 udp:false` on Android), and locally encrypted credentials (`AES-256-GCM`).
- **Synchronized Desktop + Dual Android Outputs**:
  - Generates `Script.js` (Clash Verge Rev), `Desktop-Static-Chain.yaml` (universal Mihomo / FlClash / Mihomo Party), `Daily-Static-Chain.yaml` (Android daily split-routing), `Claude-GoLogin-Static.yaml` (Android strict browser isolation + dedicated `127.0.0.1:17990` listener), and `chain-runtime.json`.
  - Controlled ADB tooling with strict separation between read-only inspection and mutating actions, plus automatic port-forward cleanup.
- **5-Dimension Environment Consistency & Leak Audit**:
  - Dual-port static IP parity & ASN check, IP-to-OS/CLI timezone & locale alignment, Claude Desktop/CLI proxy & remote DNS guard, IPv6/UDP/WebRTC leak check, pre-switch live process check, and whitelisted non-destructive render-cache cleanup (never touches login cookies or settings).
- **Atomic Backup & One-Click Rollback**: Every write to Clash Verge is preceded by a timestamped snapshot and SHA-256 readback verification.

## Quick Start

### Prerequisites

- **Node.js >= 20** (zero third-party npm runtime dependencies)
- **Python 3 + PyYAML** (`pip install pyyaml`)
- Optional: `adb` for Android push & read-only verification

### Run Locally

```bash
# Start local studio server on http://127.0.0.1:4328
npm start

# On Windows, you can also double-click:
# Start-ChainStudio.cmd
```

### Verification & Privacy Gate

```bash
npm run verify
```

See [ARCHITECTURE.md](ARCHITECTURE.md), [SECURITY.md](SECURITY.md), and [CONTRIBUTING.md](CONTRIBUTING.md) for engineering details.
