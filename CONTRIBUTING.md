# 参与贡献指南（CONTRIBUTING）

欢迎提交 Issue 与 Pull Request 一起完善 Clash Chain Studio！

## 开发环境

1. 确保已安装 Node.js >= 20 与 Python 3（`pip install pyyaml`）。
2. 启动本地开发服务：
   ```bash
   npm start
   ```
3. 提交 PR 前务必全部通过本地验证：
   ```bash
   npm run verify
   ```

## 提交规范

- **严禁提交私有数据**：不要提交 `data/`、`output/`、真实静态 IP、代理账号密码、个人订阅链接或本机绝对路径（CI 会自动执行 `npm run check:privacy` 拦截）。
- **保持零运行时 npm 依赖**：核心后端与前端尽量使用 Node.js 原生标准库与标准 Web API，保持轻量和易部署。
- **新增核心逻辑必须附带测试**：规则解析、双端生成器、校验或清理边界改动需在 `tests/` 补充 0 / 1 / N 及异常分支测试。
- **遵守现有安全边界**：所有覆盖外部配置文件的操作必须先备份、原子写入并做回读校验；ADB 只读探测与变更操作必须分接口隔离。
