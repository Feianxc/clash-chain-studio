# 技术架构说明（ARCHITECTURE）

## 1. 设计目标与原则

1. **零外部运行时 npm 依赖**：后端基于 Node.js 20+ 原生模块（`node:http`, `node:crypto`, `node:net`, `node:tls`, `node:child_process`），前端使用原生 ES Module + CSS，无需打包即可毫秒级启动。
2. **输入、配置、产物与凭据严格分层**：
   - `data/state.json`：非敏感结构化状态（订阅元数据、静态出口非密钥字段、规则预设、版本索引、探测历史），写入采用互斥文件锁 + 原子替换。
   - `data/vault.local.json` + `data/.vault.key`：本地 AES-256-GCM 加密凭据库（代理账号密码、订阅链接、临时 Controller 令牌）。任何 UI 响应、日志、报错与导出的诊断报表均经过 `vault.redactText/redactObject` 脱敏。
   - `output/<versionId>/` 与 `output/latest/`：同一版本号下同步生成的 `Script.js`、`Desktop-Static-Chain.yaml`、`Daily-Static-Chain.yaml`、`Claude-GoLogin-Static.yaml`、`chain-runtime.json`。
   - `data/backups/<versionId>/`：覆盖本机 Clash Verge `profiles/Script.js` 前的原子快照，供一键回滚。

## 2. 链式代理数据面与 IPv4 DoH Relay 原理

```text
普通应用 / Claude Desktop / Claude Code ──▶ Mihomo 127.0.0.1:7897 (rule)
  ├─ 国内 / 局域网 / 游戏更新 ──▶ DIRECT
  └─ 受保护应用 & 海外 TCP   ──▶ Static-Exit-Chain (127.0.0.1:17902)
                                     │
BitBrowser 专用 Profile ─────────────┘
                                     ▼
                    StaticChainIPv4Relay.cjs (127.0.0.1:17902)
                      ├─ 经上游代理通过 Cloudflare DoH (1.1.1.1) 仅查询 IPv4 A 记录并缓存
                      └─ 以目标 IPv4 建立 CONNECT 隧道，客户端保留原始域名 TLS SNI
                                     ▼
                    Mihomo Upstream Listener (127.0.0.1:17901)
                      └─ IN-NAME 规则置顶直绑 Static-Exit-Raw（防止回环再进入 MATCH）
                                     ▼
                    Static-First-Hop (订阅叶子节点，严格排除 DIRECT / 嵌套链)
                                     ▼
                    Static-Exit-Raw (dialer-proxy: Static-First-Hop) ──▶ 目标站点
```

### 为什么需要 `17902 → 17901` IPv4 Relay？
部分住宅 HTTP 代理节点在处理某些高严格度站点（如 Google Accounts、Cloudflare）的域名 `CONNECT` 请求时会出现 TLS 握手失败（如 curl exit 35）或 IPv6 双栈漂移。通过 `StaticChainIPv4Relay.cjs` 在本地经上游隧道执行 DoH IPv4 解析并以纯 IPv4 拨通隧道，同时让浏览器/客户端保持原域名 TLS SNI 与证书校验，可显著提高连通稳定性；同时为指纹浏览器提供独立全代理入口（国内检测页与海外站看到同一静态出口）。

## 3. 语法感知规则引擎（`src/core/rule-engine.mjs`）

传统按逗号简单拆分规则的脚本存在三大隐患：
1. `IP-CIDR,x.x.x.x/24,REJECT,no-resolve` 的动作在倒数第二列，按结尾判断会把 `REJECT` 漏出优先段；
2. 嵌套括号复合规则 `AND,((PROCESS-NAME,...),(NETWORK,UDP)),REJECT` 按逗号切分会被破坏；
3. 上游 `PROCESS-* DIRECT` 规则会被误改写。

本引擎实现了**括号深度感知的顶层逗号分词器**与**尾随修饰符（`no-resolve` / `src`）识别**：
- 保留 `REJECT` / `REJECT-DROP` 及其后缀；
- 保留已有 `PROCESS-*` 的 `DIRECT` 规则；
- 上游复杂规则（`AND`/`OR`/`NOT`/`SUB-RULE`）不静默改写，进入人工审查提示列表；
- 生成顺序严格保证：`IN-NAME` 置顶 → 本地 LAN `DIRECT` → 游戏直连 → 受保护应用 UDP `REJECT`（Android）与 AI/Google 域名（含 `.cn` 变体）→ 上游 `REJECT` → 国内 `GEOSITE,cn` / `.cn` / `GEOIP,CN` → `NETWORK,UDP,REJECT` → 重映射海外规则 → 唯一尾随 `MATCH`。

## 4. Android 双配置与移动数据 DNS 方案

- **同源双配置**：`Daily-Static-Chain.yaml` 与 `Claude-GoLogin-Static.yaml` 由同一订阅快照生成，保证节点版本与静态出口完全一致；两者唯一区别在于是否接管普通浏览器整应用流量。
- **UDP 提前拦截**：对 `com.anthropic.claude`、`com.gologin.gologin_mobile`（以及专用版中的浏览器）在 `GEOSITE,cn,DIRECT` 之前注入 `AND,((PROCESS-NAME,<pkg>),(NETWORK,UDP)),REJECT`，防止 SOCKS5 `udp: false` 时 UDP 跳过应用规则落入国内直连。
- **移动数据 DNS**：默认启用 `dns.listen: 127.0.0.1:7874` + `proxy-server-nameserver: ["udp://127.0.0.1:7874"]` + 自动从当前订阅提取所有节点域名写入 `nameserver-policy`（指向 `223.5.5.5` / `119.29.29.29`），避免更换新第一跳订阅后在蜂窝网络下解析超时。

## 5. 目录结构

```text
├── public/                     # 零构建原生前端（链路画布、手机可视化预览、环境体检）
├── runtime/                    # 可独立运行的桌面辅助套件
│   ├── StaticChainIPv4Relay.cjs      # IPv4 DoH Relay (17902 → 17901)
│   ├── Start-ClaudeStaticGuard.cjs   # 通用静态 IP 启动守卫
│   └── Switch-RegionEnvironment.ps1  # 通用多地区时区/语言原子切换器
├── scripts/
│   ├── Start-ChainStudio.ps1         # 自动热重启并打开桌面窗口的 Windows 启动脚本
│   └── check-privacy.mjs             # 开源发布隐私与密钥泄漏门禁
├── src/
│   ├── core/                         # store / vault / yaml-bridge / rule-engine / generators
│   ├── services/                     # windows / probe / adb / hygiene / relay-manager
│   └── server.mjs                    # 原生 HTTP API 与静态文件服务
└── tests/                            # node:test 全场景自动化测试套件
```
