# 安全与隐私策略（SECURITY）

## 凭据与本地隐私保护

- **全本地运行**：服务默认仅绑定 `127.0.0.1:4328`，不向任何第三方遥测服务器发送数据。
- **凭据加密存储**：静态代理用户名/密码、远程订阅 URL 及临时 Android Controller Secret 均通过 AES-256-GCM 加密保存在本地 `data/vault.local.json`，密钥独立存于 `data/.vault.key`。
- **导出强制脱敏**：界面预览的 `Script.js` / `YAML`、错误响应和导出的诊断报告（`/api/report/export`）均自动经过脱敏过滤，不会输出明文密码或订阅链接。
- **安全缓存清理边界**：环境体检中的缓存清理仅允许作用于明确白名单内的临时渲染缓存目录（`Cache`、`Code Cache`、`GPUCache`、`DawnCache`），严格拒绝删除登录 Cookie、Local Storage 或用户配置，且在目标进程运行时拒绝执行。
- **Git 提交防泄漏门禁**：提交或发布前请运行 `npm run check:privacy`，自动阻断真实公网 IP、个人绝对路径、明文凭据与 `data/`/`output/` 目录进入版本库。

## 报告安全漏洞

如发现本地提权、路径穿越、命令注入或凭据泄漏问题，请勿在公开 Issue 中直接贴出可利用细节或真实凭据，建议通过 GitHub Security Advisories 私密反馈并附上复现步骤。
