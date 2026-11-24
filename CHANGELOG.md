# 更新日志（CHANGELOG）

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 与语义化版本规范。

## [1.0.0] - 2026-11-23

### Added
- **图形化双车道链路画布**：可视化展示「静态链通道」与「国内/游戏直连通道」，内置实时路由模拟器与右侧滑出式快换抽屉。
- **第一跳订阅与静态出口独立管理**：支持 URL / YAML / Base64 / URI 及 Clash Verge 本机只读导入；支持节点入口与预期公网 IP 分离维护、AES-256-GCM 本地凭据加密与两轮全链测速。
- **桌面与手机多端同步生成**：一次生成 `Script.js`（Clash Verge Rev）、`Desktop-Static-Chain.yaml`（通用 Mihomo 桌面端）、`Daily-Static-Chain.yaml`（手机日常版）、`Claude-GoLogin-Static.yaml`（手机专用版）与 `chain-runtime.json`。
- **手机可视化预览与受控 ADB**：点击手机预览框 App 卡片实时开关规则，支持移动数据 7874 稳态 DNS 切换、ADB 一键推送与自动清理转发的只读双口探测。
- **5 维 Claude 独立环境与防泄漏体检中心**：涵盖双口 IP 与 ASN 画像、时区/语言对齐、Desktop/CLI 守卫、IPv6/UDP 防泄漏、切换前进程残留检查与保留登录态的白名单渲染缓存清理。
- **内置桌面运行时套件**：随仓内置一键启停的 `StaticChainIPv4Relay.cjs`、通用静态出口启动守卫 `Start-ClaudeStaticGuard.cjs` 与多地区时区切换器 `Switch-RegionEnvironment.ps1`。
- **开源工程基础设施**：MIT License、双语文档、架构说明、安全策略、GitHub Actions 跨平台 CI 与 `npm run check:privacy` 隐私防泄漏门禁。
