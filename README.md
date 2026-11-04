# XMem Community

XMem 为本地工程保存可核对的历史、规则版本和来源，并在新 Codex 会话中显式检索、完整回读及保存检查点。这里提供 X Suite 联合验收使用的 R6 本地源码。

## 构建与接入

目标环境为 Windows、Node 24.20.0、npm 11.19.0。执行 `npm ci` 和 `npm run build`。本地 SQLite 依赖需要匹配目标平台的原生模块。

Codex 通过 Node 启动构建后的 `dist/src/engineering-companion.js`。工具列出后，选择明确的本地项目和存储策略。联合验收使用的显式保存、项目回读和 checkpoint 与宿主自身的记忆分别记录。项目记忆数据库不随源码分发。

XMem 社区源码及本仓库自有文件采用 MPL-2.0。原有第三方声明继续适用。
