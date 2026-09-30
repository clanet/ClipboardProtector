# 首次公开与发布

[返回首页](../readme.md) · [构建和测试](development.md)

## 本地准备

1. 确认 `LICENSE` 中的 MIT 选择及版权署名适合本项目，并确认有权公开全部项目代码和图标。图标的原始作者/授权信息未在旧提交中说明，仓库所有者应补充来源确认；不把未经核实的第三方素材当作原创。
2. 检查全部 Git 历史和本次待提交文件，核对提交邮箱是否愿意公开。`.gitignore` 无法从历史中移除秘密。
3. 阅读 [验证记录](validation.md)，完成发布所需的隔离测试，更新 `VERSION` 和 `CHANGELOG.md`。
4. 如需界面截图，在隔离环境以虚构数据演示；只截应用窗口，不包含真实日志、地址、姓名或文件路径。首页目前使用项目图标，没有用示意图伪装产品截图。

## 在 GitHub 创建仓库

新建空仓库，名称建议 `ClipboardProtector`；不要让 GitHub 自动生成另一个 README 或许可证。仓库描述建议：

> Windows clipboard access monitor and rule-based protection with BTC/ETH/SOL address replacement detection. Experimental.

建议 topics：`windows`、`clipboard`、`cpp`、`win32`、`security`、`detours`。

首次上传前可以先设为 Private 完成检查，再改为 Public。设置 `origin` 时使用你实际创建的仓库地址，不把访问令牌写进 URL：

```powershell
git remote -v
git remote add origin https://github.com/YOUR-ACCOUNT/ClipboardProtector.git
git push -u origin main
```

如果 `origin` 已存在，先确认它是否正确，不要直接覆盖其他远端。

在仓库设置中启用 Private Vulnerability Reporting，并确认 `Security → Advisories → Report a vulnerability` 可用；检查 Actions 允许执行本项目工作流。按需要设置 `main` 分支保护，在一次成功 CI 后将对应检查设为合并条件。

## 生成正式发布包

从干净、已提交的工作区运行：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/package-release.ps1
```

脚本显式设置 `BUILD_TESTING=OFF` 和 `CLIP_NO_ELEVATE=OFF`，先构建 Win32，再构建 x64。输出位于 `dist/`，包含 ZIP 和外部 SHA-256 校验文件。ZIP 内含：

- `ClipboardProtector.exe`、`HookDll.dll`。
- `HookHost32.exe`、`HookDll32.dll`。
- `HookDllUnloader.exe`、`HookDllUnloader32.exe`。
- 项目说明、许可证、第三方声明、文档、构建元数据和文件校验清单。

`BUILDINFO.json` 记录版本、源码提交、工作区是否有未提交改动和工具链信息。脚本默认拒绝脏工作区；本地试打包可以显式加 `-AllowDirty`，这类包只用于检查，不能冒充对应提交的正式产物。

核验包内容和哈希，在干净 VM 中解压验证。不应发布测试构建目录或只复制一个 EXE；当前构建没有代码签名，不得宣称已签名。

## GitHub Release

确认源码提交、CI、包内容和已知限制后，再创建并推送与 `VERSION` 一致的 tag：

```powershell
git tag -a v0.1.0-alpha -m "ClipboardProtector 0.1.0-alpha"
git push origin v0.1.0-alpha
```

tag 会触发 `Release package`，也可手动运行它。下载该次 Actions artifact，解压后核验 ZIP 及 `.sha256`；工作流不会自动创建或公开 Release。

在 GitHub 创建 Draft Release，选中同一 tag，勾选 **Set as a pre-release**，附上 ZIP、`.sha256`、本版变更与已知限制。最后人工确认后发布。尚未完成的事务/长期稳定性测试必须明确列出，不写“全场景验证通过”。
