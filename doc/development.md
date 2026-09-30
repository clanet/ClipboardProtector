# 构建和测试

[返回首页](../readme.md) · [完整参考](manual.md) · [发布指南](publishing.md)

## 环境

- Windows 10/11 x64。
- Visual Studio 2022 或 Build Tools 2022，安装“使用 C++ 的桌面开发”、MSVC x86/x64 工具链和 Windows SDK。
- CMake 3.20+、Git、PowerShell。发布脚本兼容 Windows PowerShell 5.1 与 PowerShell 7。

## 输出目录

所有本地构建文件统一放在 `build/`，按用途和架构区分：

| 目录 | 用途 |
| --- | --- |
| `build/release/x64/bin/Release/` | 正式构建的完整运行目录，包含 32 位辅助组件 |
| `build/release/x86/bin/Release/` | 正式构建的 32 位组件 |
| `build/dev/x64/bin/Release/`、`build/dev/x86/bin/Release/` | 开发程序和测试工具 |
| `build/ci/` | CI 构建和测试日志 |
| `build/tools/` | 本地下载的检查工具 |
| `build/archive/` | 旧构建、临时脚本和日志归档；其中的 CMake 缓存不能直接复用 |
| `dist/` | 可分发的 ZIP 包及 SHA-256 校验文件 |

`tools/package-release.ps1` 默认在 `build/release/` 构建，并在其 `package-*` 子目录暂存打包内容；可通过 `-BuildRoot`、`-OutputDirectory` 覆盖默认路径。`build/` 和 `dist/` 均不提交到 Git。

迁移旧构建目录后，应在上述新路径重新运行 CMake 配置和编译。不要直接使用旧目录中的工程或缓存。

## 本地开发构建

以下命令在仓库根目录的 PowerShell 执行。开发构建关闭 UAC 提权，启用测试工具；它不等同于正式发布包。

```powershell
cmake -S . -B build/dev/x86 -G "Visual Studio 17 2022" -A Win32 -DBUILD_TESTING=ON -DCLIP_NO_ELEVATE=ON
cmake --build build/dev/x86 --config Release --parallel
cmake -S . -B build/dev/x64 -G "Visual Studio 17 2022" -A x64 -DBUILD_TESTING=ON -DCLIP_NO_ELEVATE=ON -DCLIP_X86_BIN_DIR="$PWD/build/dev/x86/bin/Release"
cmake --build build/dev/x64 --config Release --parallel
```

先完成 Win32 构建，再配置 x64，才能将 32 位保护组件一并复制到 x64 输出目录。

## 基础回归

```powershell
ctest --test-dir build/dev/x86 -C Release -R '^(common_smoke|hook_smoke|injection_smoke)$' --output-on-failure
ctest --test-dir build/dev/x64 -C Release -R '^(common_smoke|hook_smoke|injection_smoke)$' --output-on-failure
```

`injection_smoke` 只向自己创建的子进程注入。完整复制事务子用例使用私有窗口站；如果系统拒绝创建，输出 `crypto-transactions-skipped=private-window-station-unavailable`，其余无 `OpenClipboard` 的用例仍执行。CTest 的整体通过不代表该子用例已执行。

## 桌面和端到端回归

在专用、可丢弃的 Windows 测试环境中执行完整 CTest：

```powershell
ctest --test-dir build/dev/x64 -C Release --output-on-failure
```

其中产品覆盖测试可能启动全局覆盖路径。真实剪贴板/UI 测试优先使用源码中的 `tools/sandbox/run.ps1`；全局多进程、登录/重启、自启和长期压力在带快照的 VM 执行。不要在日常工作桌面运行这些全局测试。

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/sandbox/run.ps1 -BuildDir build/dev/x64/bin/Release -Scenario Ui
```

更多隔离配置、命令行探针和卸载验证见 [完整参考](manual.md)。

私有剪贴板的 `private_clipboard_smoke` 会启动并仅注入自建测试进程，临时切换焦点，验证就绪握手、真实 Ctrl+C / Ctrl+V、中文/表情、多行、选区替换、格式查询、OLE、密码框和清空。未就绪时不能发送按键；延迟写入及异步失败后仍须隔离。测试只锁定真实剪贴板而不读取或修改内容，以防遗漏的拦截覆盖用户数据，并核对其序列号不变。不启用全局注入；需在可交互的测试桌面执行：

```powershell
ctest --test-dir build/dev/x64 -C Release -R '^private_clipboard_smoke$' --output-on-failure
```

## 中英文界面回归

`language_smoke` 验证文字表、语言配置往返、旧配置回退和用户原文保留；已纳入默认 CI。`language_ui_smoke` 使用独立临时配置和模拟 IPC 客户端，验证真实菜单、五个对话框、确认窗口即时切换、内置事件翻译、保存失败回滚和重启记忆，不执行注入或访问系统剪贴板。需可交互桌面，CI 中随扩展测试手动执行：

```powershell
ctest --test-dir build/dev/x64 -C Release -R '^language(_ui)?_smoke$' --output-on-failure
```

界面文字集中在 `common/ui_strings.inc`，使用 `TextId` 查找；资源对话框通过 `app/dialog_strings.inc` 将模板和控件 ID 关联到文字。新增提示应同时提供两种语言。Hook 的内置规则和预览标记使用独立协议枚举，不能按用户文字匹配翻译。

## GitHub Actions

- `CI`：Windows Server 2022 runner，分别构建 Win32/x64，运行三项基础 smoke 和语言单元回归；通过手动运行的 `extended_tests` 可执行额外桌面测试。CI 不代表 Windows 10/11 桌面兼容性或长期稳定性验收。
- `Secret scan`：拉取完整 Git 历史，使用固定版本与 SHA-256 校验的 Gitleaks；不上传包含发现项的报告文件。
- `Release package`：按 `VERSION` 编译正式 x86/x64 组件，生成 ZIP、校验文件和构建元数据。版本 tag 触发时自动创建 GitHub Release 并提供下载，带后缀的版本标为预发布；手动选择 `main` 时只生成 Actions artifact。

工作流的 checkout/upload-artifact 固定到具体 commit；CI 和发布构建 job 的 token 仅有源码读取权限，checkout 不保留凭据。独立的发布 job 使用 `actions: read` 下载构建附件、`contents: write` 创建 Release，无需另配私钥或 PAT。

## 敏感信息检查

安装 [Gitleaks v8.30.1](https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1)，核对发布页的校验文件后执行：

```powershell
gitleaks git . --log-opts="--all --full-history" --redact=100
git diff --check
```

Git 历史检查不包含未提交内容；发布前还需扫描准备提交的文件。发现真实凭据后应先吊销/轮换，再决定是否清理历史；不要只删除当前版本里的文件。

## 版本

`VERSION` 是版本号的单一来源，例如 `0.1.0-alpha`。CMake 从中读取数字版本，主程序文件属性保留完整预发布版本。发布 tag 使用 `v` 前缀，例如 `v0.1.0-alpha`。
