# XMem Community

XMem 为本地工程保存可核对的历史、规则版本和来源，并在新 Codex 会话中显式检索、完整回读及保存检查点。这里提供 X Suite 联合验收使用的 R6 本地源码。

当前社区版为 **V0.1**（软件包版本 `0.1.1`）。与 XDev `v0.1.1` 配套时，安装工具会生成部署清单。

## 构建与接入

目标环境为 Windows x64、Node 24.20.0、npm 11.19.0。使用锁定的 SQLite 依赖随包提供的 Windows x64 二进制。

```powershell
npm.cmd ci --ignore-scripts
npm.cmd run build
node tools/stage-runtime.mjs C:\XSuite\xmem-runtime
Set-Location C:\XSuite\xmem-runtime
npm.cmd ci --omit=dev --ignore-scripts
```

运行目录必须是尚未创建的绝对路径。将源代码与运行目录分开放置，XDev 会对运行目录中的程序和包清单做完整性检查。

Codex 通过 Node 启动运行目录中的 `dist/src/engineering-companion.js`。项目配置和 XDev 绑定步骤见 [X Suite 安装指南](https://github.com/NUVANU/X-Suite/blob/main/INSTALL.md)。显式保存、项目回读和 checkpoint 与宿主自身的记忆分别记录。项目记忆数据库不随源码分发。

XMem 社区源码及本仓库自有文件采用 MPL-2.0。原有第三方声明继续适用。
