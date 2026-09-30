# 使用与开发参考

[返回项目首页](../readme.md) · [构建和测试](development.md)


Windows 剪贴板访问监控与保护工具。

## 功能

- 记录程序读取和写入剪贴板的行为；保护模式还会记录被拒绝的清空和 `OpenClipboard`
- 主窗口顶部显示保护状态、已连接进程、今日记录和今日拦截
- 日志按时间倒序显示，最新访问始终位于最上方
- 日志列：时间、访问进程、PID、内容来源、来源 PID、操作、格式、命中规则、处理方式、结果通知、预览、状态、监控缺口和次数
- Crypto 地址保护开启时，BTC、ETH、SOL 地址日志会显示红色 `Crypto` 标志，并隐藏地址原文和内容哈希
- 日志行右键可用完整访问进程路径预填新规则，或重新复制实际保存的文本；显式开启快照后也可复制图片和文件列表
- 双击日志查看详情；关闭主窗口只隐藏到托盘，需通过“窗口 → 退出”或托盘菜单真正退出
- 同一用户会话只允许一个主程序实例；再次启动会恢复并前置已有窗口
- 默认识别并忽略自定义注册格式（如 格式#49899）：不走规则且不在主列表显示，但保留内存审计并可导出；可在设置中关闭
- 规则可组合访问进程、内容来源进程、读取/写入、文本/非文本格式、区块链地址、私钥助记词和内容正则表达式
- 访问决策、结果通知与列表显示独立配置；“不显示日志”仍保留内存记录和 CSV 导出
- “每次询问”确认窗口可勾选“一直这样”，按访问进程和内容来源把放行或阻止规则插到列表最前并立即保存
- 进程名和完整路径条件支持 `*`、`?` 通配符，内容条件使用无灾难性回溯的安全正则子集
- 规则按顺序首次命中，支持启用/停用、添加、编辑、删除、上移和下移
- 系统托盘常驻；主窗口菜单栏和完整托盘菜单
- 开发者可通过环境变量指定兼容桌面进程的 PID，进行会话级单进程保护验证
- 全局注入默认关闭，可从“保护 → 开启保护 / 关闭保护”菜单显式启用或关闭（仅当前会话）；也可在设置中勾选启动时自动开启
- 全局注入先用 `WH_GETMESSAGE` 覆盖 GUI 进程，再每 2 秒巡检同会话同用户进程，对超过宽限期仍未就绪的目标做远程初始化
- 可仅允许 Ctrl+C/Ctrl+Insert 与 Ctrl+V/Shift+Insert 触发的剪贴板访问，其他 API 访问直接拒绝并记录
- 可保护纯文本及段落中的 BTC、ETH 和 SOL 地址，阻止后台程序替换为其他地址，并在粘贴前复核
- 日志清空、详情查看和 CSV 导出；队列过载时明确记录监控缺失条数
- 主窗口尺寸会写入配置；可启动时最小化到托盘
- 管理员权限运行
- 使用 Windows 计划任务开机自启

## 界面语言

在“选项 → 语言 / Language”中选择“中文”或“English”。切换立即刷新主窗口、托盘提示和已打开的访问确认窗口，不重启保护，也不清空日志或私有剪贴板。保护切换或私有操作进行中时，语言选项暂不可用。

选择写入配置的 `settings.language`，支持 `zh-CN` 和 `en`；保存失败会保留原语言。首次使用按 Windows 界面语言选择：中文系统使用中文，其他系统使用英文。旧配置缺少该字段或值不受支持时使用中文。

用户填写的规则名称、进程名、路径和剪贴板原文保持不变；内置规则说明和隐藏内容提示按当前语言显示。CSV 列顺序不变，表头和状态描述使用导出时的语言。升级时请整套替换主程序与 Hook DLL；旧模块上报的内置文字可能保留中文。系统文件选择器和系统自带按钮可能随 Windows 显示语言变化。

## 架构

```text
ClipboardProtector.exe
  ├─ Win32 主界面与系统托盘
  ├─ 规则和配置管理
  ├─ 命名管道服务端
  ├─ Hook 注入器（WH_GETMESSAGE）
  └─ 全局覆盖巡检（CoverageMonitor，远程 LoadLibrary）

HookDll.dll / HookDll32.dll
  ├─ WH_GETMESSAGE 回调
  ├─ Detours API Hook
  ├─ 本地规则判断
  └─ 命名管道异步上报

HookHost32.exe
  └─ x64 主程序覆盖 32 位 GUI 进程，并执行 32 位远程初始化

HookDllUnloader.exe / HookDllUnloader32.exe
  └─ 仅用于清理旧版本遗留模块的受限维护工具
```

## 构建

要求：

- Windows 10/11 x64
- Visual Studio 2022 或 MSVC Build Tools
- Windows SDK
- CMake 3.20+

完整的 x64 正式交付需要先生成 Win32 helper 和 DLL，再让 x64 构建复制它们：

```text
cmake -S . -B build/release/x86 -G "Visual Studio 17 2022" -A Win32 -DBUILD_TESTING=OFF -DCLIP_NO_ELEVATE=OFF
cmake --build build/release/x86 --config Release

cmake -S . -B build/release/x64 -G "Visual Studio 17 2022" -A x64 -DBUILD_TESTING=OFF -DCLIP_NO_ELEVATE=OFF -DCLIP_X86_BIN_DIR="$PWD/build/release/x86/bin/Release"
cmake --build build/release/x64 --config Release
```

`CLIP_X86_BIN_DIR` 必须指向已经构建好的 Win32 `bin/Release` 目录。最终
`build/release/x64/bin/Release` 应包含 `ClipboardProtector.exe`、`HookDll.dll`、
`HookHost32.exe`、`HookDll32.dll`、`HookDllUnloader.exe` 和
`HookDllUnloader32.exe`。`HookHost32.exe` 是正式组件；
`clipclient.exe` 和各 smoke 程序才会在 `BUILD_TESTING=OFF` 时排除。`BUILD_TESTING=ON` 时还会生成并注册
CTest：`hook_smoke`、`common_smoke`、`injection_smoke`、`injector_smoke`、
`product_single_process_smoke`、`product_coverage_smoke`（x64 且提供 Win32 `clipclient.exe` 时另有
`product_coverage_x86_smoke`）和 `remote_unload_smoke`。

## 私有剪贴板与快捷键

私有复制默认使用 `Alt+Shift+C`，私有粘贴默认使用 `Alt+Shift+V`。请先开启保护，确认源进程和目标进程已注入新版模块。在应用中保持选区或输入焦点，按下快捷键后松开。程序先等待目标进程确认私有会话就绪，再发送带标记的 Ctrl+C / Ctrl+V；目标应用自己执行复制或粘贴，模块将剪贴板操作重定向到私有内存。无需目标控件提供 UI Automation TextPattern；UI Automation 仅用于识别密码输入区域。

- **选项 → 设置快捷键**：点击对应输入框后按组合键。支持 Ctrl / Alt / Shift 加字母、数字或 F1–F24，至少包含 Ctrl 或 Alt；三项快捷键不能相同；第三项用于切换“仅允许复制 / 粘贴快捷键”模式，默认为 `Ctrl+Alt+F9`，也可修改。发生系统注册冲突或配置保存失败时会恢复原设置并提示。启动时若组合键被其他程序占用，私有复制、粘贴均不启用，需重新设置。
- **选项 → 清空私有剪贴板**：清空内存并取消尚未完成的操作。每次新复制会先清空旧内容，失败时不会保留过期文字；退出程序也清空。没有历史列表或磁盘持久化。
- 首版只支持文字，最多 65536 个 UTF-16 字符，保留换行及 Tab。Win32 复制支持 Unicode/ANSI/OEM 文字，粘贴以 Unicode 为主，并提供 ANSI/OEM 文字及区域信息；OLE 支持能同步提供 Unicode 文字的数据对象。其他格式不进入系统剪贴板。未注入、旧模块未确认就绪、密码框或焦点变化时，不发送按键。
- 虚拟化 OpenClipboard / EmptyClipboard / SetClipboardData / GetClipboardData / CloseClipboard、格式查询及 OLE 入口；不临时保存、清空、写入或恢复真实剪贴板。文字不进入访问事件、内容预览和日志。
- 当前已验证新版记事本和标准 Edit / RichEdit。旧式 ANSI 输入框可能无法表示表情等字符。跨进程代理、绕过被拦截接口的实现及后台工作线程不保证兼容；不能仅凭进程已注入就推断所有复制通道均被覆盖。
- 若已发送按键，但超时、延迟渲染、取消或其他异常导致操作未完整结束，目标进程保留剪贴板隔离，阻止迟到的写入。重新进行私有操作不会解除这个隔离；恢复该进程的普通复制粘贴需要重启目标应用。停止保护时，这种进程内的安全拦截可能保留至进程退出。
- 操作期间切换焦点、长按修饰键或清空内容会取消任务；分批输入中途取消可能已经写入部分文字，不会自动撤销目标应用的改动。

配置只保存 `privateCopyModifiers`、`privateCopyKey`、`privatePasteModifiers`、`privatePasteKey`、`shortcutOnlyModifiers`、`shortcutOnlyKey` 六个快捷键数值。内容不进入访问日志、通知正文、配置文件或系统剪贴板历史；释放自有内容缓冲区前会擦除文字。此功能防止普通系统剪贴板读取者看到这些内容，不提供对键盘监听、进程内存读取或目标应用的隔离。

## 旧版 DLL 应急清理

新版程序会协作式安全卸载 DLL。以下维护工具只用于清理修复前已经遗留在目标进程中的旧
模块，不能代替正常的“停止监控”流程。工具要求传入 DLL 绝对路径并按完整路径匹配；省略
`--execute` 时只列出目标，不修改进程：

```text
HookDllUnloader.exe --dll D:\absolute\path\HookDll.dll
HookDllUnloader.exe --dll D:\absolute\path\HookDll.dll --execute
HookDllUnloader32.exe --dll D:\absolute\path\HookDll32.dll --execute
```

可用 `--pid <PID>` 限制为单个进程。默认跳过 Windows 目录中的进程；确认已停止
`ClipboardProtector.exe` 后，才可额外传入 `--include-system`。工具会拒绝关键进程，且每个
匹配模块只调用一次远程 `FreeLibrary`，不会循环递减未知引用计数。即便如此，强制卸载旧 DLL
仍可能使正在执行旧 Hook 代码的目标程序崩溃，优先选择重启目标程序、注销或重启系统。

开发构建可以不弹 UAC，但仍然不应在物理主机加载全局 Hook：

```text
cmake -S . -B build/dev/x64 -G "Visual Studio 17 2022" -A x64 -DBUILD_TESTING=ON -DCLIP_NO_ELEVATE=ON
cmake --build build/dev/x64 --config Release
```

输出文件位于：

```text
build/dev/x64/bin/Release/
```

## 单进程隔离验证（开发入口）

为避免全局注入影响其他程序，首轮验证只能指定一个自行生成的测试进程。

1. 仅启动本项目自己生成的 `clipclient.exe` 子进程，不启动主程序的全局注入模式。宿主机上的 `wait` 模式不传第三个参数，因此不会主动读写真实剪贴板。
2. 启动测试程序：

   ```text
   clipclient.exe wait 60000
   ```

3. 读取测试程序输出的 PID。
4. 在同一 PowerShell 会话中设置开发入口，再启动开发构建：
   ```powershell
   $env:CLIPBOARDPROTECTOR_TEST_TARGET_PID = "<PID>"
   Remove-Item Env:CLIPBOARDPROTECTOR_ENABLE_GLOBAL_HOOK -ErrorAction SilentlyContinue
   .\build\dev\x64\bin\Release\ClipboardProtector.exe
   ```
5. 等待状态栏显示目标 PID 后进行测试。该入口只约束指定进程，不会因目标无效而回退到全局保护。
6. 测试结束后退出程序，并清除本会话的 `CLIPBOARDPROTECTOR_TEST_TARGET_PID` 环境变量。
7. 单进程保护和全局覆盖互斥。日常菜单隐藏单进程保护及全局注入安全说明；“保护 → 开启保护”用于正常的全局覆盖。
8. 设置中的“打开后自动保护”复用 `startGlobalProtection` 配置，默认关闭。启用后在下次及以后启动时自动开启保护；显式指定测试目标 PID 时仍优先进入单进程测试。

测试分三层：主机上仅执行自行创建的单进程定向 smoke；真实剪贴板、主程序 GUI 和有限多进程验证优先使用一次性 Windows Sandbox；安装、自启、重启、长时间全局稳定性和兼容性再使用带快照的普通虚拟机。Sandbox/VM 是隔离手段，不是单进程 smoke 的强制前置条件。

`product_single_process_smoke` 会走真实“单进程保护”菜单，并让交互式
`clipclient` 执行已知内容的 `w` 和 `r`，验证扩展规则能力协商、原有 v1 DLL
不发送状态 ACK 时的兼容初始化，以及规则编辑窗口、写入、读取日志、来源追踪、
正则阻止、长文本保守阻止、确认阻止和停止后的再次注入。该测试会把剪贴板文本临时改为
`clipboardprotector-product-smoke`，适合在专用测试会话或 Sandbox 中运行。

`product_coverage_smoke` 只在测试构建中启用全局巡检，并用 `CLIP_TEST_COVERAGE_TARGET_PATH`
把目标限制为自行复制的 `clipclient`。它用 `nopump` 模式验证：没有消息循环的进程仍能被远程
初始化，短暂进程退出后连接数回落，主程序退出后模块从仍存活的目标中卸载。x64 构建若提供
Win32 `clipclient.exe`，还会额外运行 `product_coverage_x86_smoke`。该测试会设置
`CLIPBOARDPROTECTOR_ENABLE_GLOBAL_HOOK=1`，只能在隔离环境运行。

当前禁止直接在物理主机上进行全局 Hook 验证。

### clipclient 交互测试

`clipclient.exe` 不带参数（或使用 `console` 参数）时进入交互模式，并在同一 PID 内持续泵送消息以等待单进程保护注入：

```text
clipclient.exe
```

控制台命令：

- `r`：读取 Unicode 文本剪贴板并打印完整内容。
- `w`：向剪贴板写入默认文本 `test`。
- `w <content>`：向剪贴板写入指定文本。
- `q`：正常退出测试进程。

交互模式不会查询 Hook 状态，也不会自动读写剪贴板；只有输入 `r` 或 `w` 时才执行相应操作。由于进程和 PID 始终不变，适合通过上述开发环境变量指定 PID 后反复验证读取、写入、规则热更新与暂停状态。
主程序会等待目标 DLL 回报“完整状态已应用”后才结束启动操作；菜单恢复响应且状态栏显示目标 PID 后，再输入 `r` 或 `w`，可避免初始化期间的 fail-open 调用被跳过。

其它命令行模式：

- `clipclient wait <ms>`：保持消息循环并打印 PID，不主动读写剪贴板。
- `clipclient wait <ms> <text> [signal-dir]`：Sandbox 探针；带信号目录时按阻断/暂停/恢复/退出分阶段验收。
- `clipclient nopump <ms> [ready-file]`：不泵送消息，供覆盖巡检验证远程初始化。
- `clipclient set <text>` / `get` / `roundtrip <text>`：一次性写入、读取或往返。

## Windows Sandbox 自动验证

Sandbox 测试使用 `CLIP_NO_ELEVATE=ON` 的测试构建，避免 UAC 阻塞自动化：

```text
cmake -S . -B build/dev/x64 -G "Visual Studio 17 2022" -A x64 -DBUILD_TESTING=ON -DCLIP_NO_ELEVATE=ON
cmake --build build/dev/x64 --config Release
powershell -NoProfile -ExecutionPolicy Bypass -File tools/sandbox/run.ps1 -BuildDir build/dev/x64/bin/Release
```

宿主脚本只校验/暂存构建产物、生成 `.wsb` 并启动 Windows Sandbox；不会在宿主启动
`ClipboardProtector.exe`、`HookHost32.exe` 或 Hook。构建输入以只读目录映射到 Sandbox，
结果目录单独可写；网络、宿主剪贴板重定向、打印机、音频输入、视频输入和 vGPU 均禁用。
Sandbox 内会先把产物复制到本地目录，再执行以下定向流程：

```text
clipclient.exe wait 30000 SandboxProbe <阶段信号目录>
CLIPBOARDPROTECTOR_TEST_TARGET_PID=<clipclient PID>
ClipboardProtector.exe
```

只有带第三个参数的 `clipclient wait 60000 SandboxProbe` 才会在 warmup 后实际写入和读取
Sandbox 自己的剪贴板。脚本绝不设置 `CLIPBOARDPROTECTOR_ENABLE_GLOBAL_HOOK`，并验证 Hook DLL
确实加载到这个自建进程。测试前会写入一条仅匹配 `clipclient.exe` 的阻止规则，
先确认读取返回 `ERROR_ACCESS_DENIED` 且主窗口日志列表收到阻止事件；再通过工具栏命令暂停
保护并确认同一读取放行，恢复保护后确认再次阻止。随后脚本向主 UI 线程投递 `WM_QUIT`，
要求程序走正常清理路径；测试版 DLL 的诊断导出必须从 installed 变为 detached，且仍存活的
`clipclient` 必须在主程序退出后再次成功完成真实剪贴板 roundtrip，最后自然退出。
DLL 会先解除 Detours、等待正在执行的 Hook 调用完成，再由 worker 通过
`FreeLibraryAndExitThread` 释放额外模块引用；控制端卸载系统 Hook 后，模块必须从仍存活的
目标进程中消失。只有 Detours 无法安全解除时才会保守地保留模块到目标进程退出。
整个验收不会用 `TerminateProcess` 掩盖生命周期问题。

结构化结果和日志写入 `sandbox-results/<时间戳>/`。只生成配置但不启动 GUI 可使用：

```text
powershell -NoProfile -ExecutionPolicy Bypass -File tools/sandbox/run.ps1 -BuildDir build/dev/x64/bin/Release -GenerateOnly
```

Windows Sandbox 适合真实剪贴板和 GUI 的一次性定向验收；计划任务自启、重启恢复、长期压力
以及正式全局 Hook 仍应放在带快照的普通 VM 中。

开发迭代时也可以显式保留本次 harness 新建的 Sandbox，以便在同一 guest
中连续执行多轮 UI 验证；默认命令仍然是一轮一关：

```text
powershell -NoProfile -ExecutionPolicy Bypass -File tools/sandbox/run.ps1 -BuildDir build/dev/x64/bin/Release -Scenario Ui -ReuseSession
powershell -NoProfile -ExecutionPolicy Bypass -File tools/sandbox/run.ps1 -BuildDir build/dev/x64/bin/Release -Scenario Uia -ReuseSession
powershell -NoProfile -ExecutionPolicy Bypass -File tools/sandbox/run.ps1 -CloseReuseSession
```

复用状态保存在 `sandbox-results/.reuse-session.json`，每轮结果仍写入独立子目录。
复用前会核对唯一 `WindowsSandboxRemoteSession` 的 PID、启动时间和 guest heartbeat，
并检查/清理测试进程、计划任务、配置和信号状态；状态不匹配时拒绝操作，不能控制
用户自行打开的 Sandbox。若 guest 已异常退出，可用 `-CloseReuseSession` 仅回收状态中
精确匹配的 harness 会话；最终交付验收仍应关闭复用会话后重新运行一次 fresh Sandbox。

## 配置文件

```text
%APPDATA%\ClipboardProtector\config.json
```

配置包括：

- 是否关闭所有规则右下角通知（`balloonNotificationsDisabled`）
- 是否仅允许 Ctrl+C/Ctrl+Insert 与 Ctrl+V/Shift+Insert 访问剪贴板（`shortcutOnlyMode`）
- 是否让 Ctrl+C/Ctrl+Insert 写入和 Ctrl+V/Shift+Insert 读取直接绕过普通规则（`shortcutDirectAllow`）
- 快捷键授权窗口（`shortcutAuthorizationWindowMs`，默认 1000ms，仅配置文件可改，范围 100–5000）
- 是否开启 BTC、ETH 和 SOL 地址保护（`cryptoProtection`）
- 日志数量上限（`maxLogEntries`，100–100000，默认 5000）
- 是否记录文本预览（`previewEnabled`，预览最多 64 个字符）
- 是否在内存中保存图片和文件列表快照（`captureImageFileSnapshots`，默认关闭）
- 是否忽略自定义注册格式（`ignoreCustomFormats`，默认开启）
- 是否开机自启（`autostart`）
- 是否“打开后自动保护”（`startGlobalProtection`，默认关闭；下次及以后启动时生效，启动路径不弹出菜单确认）
- 是否启动时最小化到托盘（`startMinimized`）
- 主窗口 96-DPI 逻辑宽高（`windowWidth`/`windowHeight`；0 表示首次默认值，有效范围宽 860–8192、高 600–8192）
- 有序访问规则及其名称、状态、条件、处理方式、通知方式、列表显示和确认超时策略

## 访问规则

规则从上到下计算，第一条完整命中的规则决定本次访问的处理与通知方式，后续规则不再计算。
因此应把范围更小的可信例外放在通用阻止规则之前。没有规则命中时默认放行并记录。

每条规则可配置：

- 访问进程：按进程名或完整路径匹配，支持 `*` 和 `?`；填写 `*` 表示任意进程。
- 内容来源：任意来源、来源进程名、来源完整路径、与访问进程相同、与访问进程不同或来源未知。
- 访问类型：读取和写入、仅读取或仅写入。
- 数据格式：任意格式、非文本格式、文本格式、区块链地址或私钥助记词。
- 内容条件：可选安全正则表达式，并可选择忽略大小写。编辑窗口可直接输入样例测试。
- 处理方式：放行、阻止或每次询问。
- 结果通知：静默或右下角通知，可与放行、阻止和每次询问独立组合。
- 不显示日志：命中后不将记录放入主窗口日志列表，但仍计入审计统计、保留在内存中并可导出 CSV。
- 确认策略：等待 1 到 60 秒，超时后按规则选择阻止或放行。

读取规则中的“内容来源”表示当前剪贴板内容最后一次由哪个进程写入；写入规则中的
“内容来源”就是本次写入进程。程序优先使用带剪贴板序列号的共享来源记录，无法对应时
回退到 Windows 剪贴板所有者；两种方式都无法识别时按“来源未知”处理。

当前正则最长 512 个字符，最多 64 个分组。支持字面量、`.`、`^`、`$`、字符类、
`\d` / `\w` / `\s`（及其大写否定形式）、`\b`、分组和非捕获分组、分支、
`*` / `+` / `?` / `{m,n}` 量词以及 `\xHH` / `\uHHHH`；不支持回溯引用、前后查找和
其他特殊分组。`\d`、`\w`、`\s` 和词边界按 ASCII 解释。表达式由 Thompson NFA 执行，
单次剪贴板匹配有累计工作量上限，超时对阻止/询问规则按可能命中处理。


用于匹配的文本最多捕获前 4096 个字符。若完整文本超过该长度且前缀未命中，放行
规则视为未命中；阻止/询问规则按可能在未捕获后缀中命中处理，以避免长文本绕过保护。
“文本格式”统一覆盖 `CF_TEXT`/`CF_DSPTEXT`（包括 ASCII/ANSI）、`CF_OEMTEXT`、`CF_UNICODETEXT`
以及名称为 `UTF8_STRING`、`text/plain` 或明确声明 UTF-8 charset 的常见注册格式。Hook 会按
相应代码页实际解码；声明为 UTF-8 但字节序列无效时不会把损坏内容交给正则或语义识别。
“非文本格式”匹配其余图片、文件列表和自定义二进制格式，不能与内容正则组合。

正则只对能够成功提取的上述文本内容生效；任意格式规则若带正则，也只会在本次格式可解码为
文本时命中。单纯选择“文本格式”时，即使内容句柄暂时无法读取，格式条件本身仍可匹配；需要
正则、地址或私钥助记词判断时则必须成功捕获完整的相应内容。

“区块链地址”识别完整有效的 BTC、ETH/EVM 和 SOL 地址。Crypto 地址保护开启时只记录
命中标志和隐藏占位符，不保存地址原文或内容哈希。“私钥助记词”识别 32 或 64 字节十六进制私钥、BTC WIF、
xprv/tprv、BIP38、SOL 64 字节 Base58 secret，以及 SOL 常见的 32/64 字节 JSON 数组。
助记词目前使用官方英文 BIP39 词表，只接受校验和正确的 12 或 24 词完整短语；普通的
12/24 个英文单词不会命中。

地址、私钥或助记词前后可以有空白，但混有金额、说明文字或多个值的整段文本不会命中；两种
语义格式都可以继续叠加内容正则。只要成功识别为私钥或助记词，原文和内容哈希都会自动从日志、
通知及确认窗口中隐藏，即使它命中的是“任意格式”或“文本格式”规则，也不受“记录内容预览”
设置影响。由于 64 位十六进制文本无法从格式上区分私钥
与普通 256 位哈希，该格式可能同时匹配这类哈希值，需要时应再组合访问进程、来源或正则条件。

“右下角通知”使用自动消失的托盘气泡，不阻塞主窗口，可分别用于放行或阻止结果；“静默”
只记录结果。选择“每次询问”时会先显示确认窗口，若同时选择右下角通知，则确认完成后再
显示最终放行或阻止结果。确认窗口可勾选“一直这样”：本次点击放行就写一条始终放行的规则，
点击阻止就写一条始终阻止的规则，同一“访问进程 + 内容来源”只保留一条，且总是位于规则列表
最前，读写任意格式都生效且不弹通知，名称形如“始终放行：xxx.exe（同进程）”。来源条件按
确认窗口显示的来源生成：来源就是访问进程本身时为“与访问进程相同”，来源是其它进程时按
来源进程名匹配，来源未知时只在来源仍未知的访问上生效。只有点击“放行”或“阻止”按钮才会写
规则；倒计时超时、Escape 和直接关闭确认窗口只决定本次访问，不会留下规则。规则保存失败时
本次访问仍按点击结果处理，但会弹出失败气泡。规则编辑窗口打开期间产生的“一直这样”请求会在
保存规则时合并。
设置中的“关闭所有规则右下角通知”只关闭气泡，不影响每次询问的确认窗口。同一进程一秒内的
连续通知会合并，点击气泡仍会定位到最后一条相关日志。

设置中的“仅允许复制 / 粘贴快捷键访问剪贴板”是一个临时封锁模式。开启后，成功注入的
进程只有在收到 Ctrl+C 或 Ctrl+Insert 后一秒内才能写入或清空剪贴板，只有在收到 Ctrl+V 或
Shift+Insert 后一秒内才能打开和读取剪贴板；其他 `OpenClipboard`、读取、写入和清空调用直接返回
`ERROR_ACCESS_DENIED`，并以“复制 / 粘贴快捷键专用保护”规则名记录为已阻止事件。获准的
快捷键访问仍会继续执行普通访问规则，因此普通规则仍可进一步询问或阻止。

默认使用 `Ctrl+Alt+F9` 在程序运行时全局切换该模式，可在“选项 → 设置快捷键”中修改，“选项”菜单和状态栏会显示当前状态。通过
菜单命令、右键菜单等其他入口触发的访问不属于上述复制 / 粘贴快捷键，会被
直接阻止。此模式只约束已成功加载 Hook DLL 的进程；若目的是阻止其他程序读取私钥等敏感
内容，必须同时开启全局注入。全局注入关闭时，界面中的“待注入”表示该配置尚不能保护其他
程序；单进程保护时则只约束指定 PID。

设置中的“复制 / 粘贴快捷键操作直接放行”与上述封锁模式相互独立。开启后，Ctrl+C 或
Ctrl+Insert 授权窗口内只有 `SetClipboardData` 写入会绕过普通访问规则，Ctrl+V 或 Shift+Insert
授权窗口内只有 `GetClipboardData` 读取会绕过普通访问规则；复制快捷键不授权读取，粘贴快捷键不授权写入，
`OpenClipboard` 和 `EmptyClipboard` 也不会因此绕过普通规则。直接放行的访问仍写入审计日志，
区块链地址、私钥和助记词仍按敏感内容规则脱敏。授权窗口默认 1000ms，可直接编辑配置文件中的
`shortcutAuthorizationWindowMs`，有效范围为 100–5000ms；设置窗口只提供功能开关，不提供时长输入。

设置中的“开启 Crypto 地址保护”识别 BTC 主网 Base58Check、BTC `bc1` Bech32/
Bech32m、`0x` 开头的 20 字节 ETH/EVM 地址，以及解码为 32 字节公钥的 SOL Base58 地址。
支持纯地址、带说明文字的段落及多个地址；地址必须是完整的字母数字词元，中文、空格、换行和
标点可作为分隔符，不从更长的标识符中截取地址。ETH 地址格式本身无法区分 Ethereum 和其他
EVM 网络，因此统一按 ETH/EVM 地址处理。

成功写入含地址的文本后会建立五分钟保护基线。保护期间，新旧内容中同时有地址减少和其他地址
增加时，才认定为“地址替换”，在普通放行规则之前阻止写入；读取时也采用相同比较方式。
因此地址 A → 地址 B、段落中 A → B、多个地址中任意一个被换掉都会拦截；普通文字覆盖、
仅修改说明文字、地址顺序调整、仅增加或删除地址不会触发 Crypto 拦截。比较保留重复地址的
数量，ETH 大小写及合法 BTC Bech32 大小写按规范化值比较。

`EmptyClipboard` 不再单独被 Crypto 阻止；同一次打开剪贴板期间，清空后的写入仍与清空前的
基线比较，防止先清空再替换地址绕过检查。成功写入普通文本会清除基线；只清空或写入非文本
的复制流程会在关闭剪贴板时清除基线。清空已经实际执行，因此后续地址写入被拦截时剪贴板
可能为空。只有本进程刚观察到的 Ctrl+C 或 Ctrl+Insert（默认一秒，使用可配置授权时限）视为
用户主动复制，可直接更新地址基线；菜单复制按内容比较，普通文本可正常覆盖。普通访问规则
和“仅快捷键访问”开关仍独立生效。

地址扫描独立于日志预览，最多处理 65,536 个 UTF-16 字符、256 个地址；超出限制、读取不完整
或共享基线不可用时，不凭不完整信息判定地址替换。暂停保护、关闭 Crypto 保护、停止监控或
退出主程序也会清除基线。包含地址的 Crypto 日志隐藏原文和内容哈希，阻止事件只记录规则名。
共享地址基线使用 v2 映射，主程序和 x86/x64 DLL 需配套更新。当前 DLL 的开关以管道设置为准，
不再信任共享映射里的 `enabled` 字段。

该功能只约束已加载当前 Hook DLL 的进程，必须开启全局注入才能覆盖随后启动的普通桌面
程序；单进程保护只约束指定 PID。它用于降低常见剪贴板地址替换攻击的风险，不能代替
钱包界面的地址核对，也不能防御未注入、内核级，或直接改写共享基线字段的程序。


主程序与 Hook DLL 仍使用 IPC v1 帧。连接建立后先发送原有 DLL 可解析的旧规则快照；
新 DLL 通过状态 ACK 声明扩展能力后，主程序才发送来源、内容正则、格式、处理方式和通知字段。
原有 DLL 不会收到扩展规则或设置字段；若当前规则无法用旧格式准确表达，或开启了仅允许
复制 / 粘贴快捷键封锁、快捷键直接放行或 Crypto 保护，单进程保护会明确拒绝以降级状态启动。旧格式兼容范围为访问进程/
路径条件以及不显示通知、不隐藏日志的放行或阻止；多条启用规则还必须使用相同处理方式，避免旧 DLL 的优先级算法
与当前“首条命中”顺序产生不同决定。

CAP6 状态 ACK 表示 DLL 支持当前文本/非文本、区块链地址和私钥助记词格式模型，并额外报告
Crypto 共享区是否实际可用。CAP7 在此基础上增加第三个设置字节，由管道明确同步 Crypto 开关；
服务器仍向 CAP6 DLL 发送原来的两字节设置，避免升级主程序后让已注入的旧 DLL 反复断线。
CAP8 再增加日志事件的 Crypto 内容标志；服务器只对 CAP8 客户端解释该标志，避免把旧 DLL 的
普通内容哈希误认为 Crypto 事件。CAP9 增加图片和文件列表快照；只有服务器通过第四个设置字节
明确启用后，DLL 才会在扩展事件末尾发送有界快照，因此 CAP8 及更早 DLL 的事件布局保持不变。
CA10 再增加快捷键直接放行开关和授权时限；服务器只向声明 CA10 的 DLL 发送这两个字段，
CAP9 及更早 DLL 仍接收原来的设置帧。
CA11 再增加忽略自定义格式开关；服务器只向声明 CA11 的 DLL 发送该字节，默认开启时注册的
非文本格式（如 格式#49899）不走访问规则，`UTF8_STRING` / `text/plain` 等已识别文本注册格式以及标准文本、图片、文件列表仍照常处理。
忽略的访问和快捷键封锁下的拒绝都会保留为内存审计事件，不在主列表显示，但会进入 CSV 导出。
CAP10 及更早 DLL 保持原行为，需重新加载当前 DLL 后新设置才生效。
新增的 CA12/CLR4 在规则和事件中传递主列表隐藏标记；只有已应用 CLR4 的 DLL 才会发送新事件字节，旧版事件布局保持不变。开启忽略自定义格式或存在隐藏规则时，CA11 及更早 DLL 不会被标记为监控就绪。
只要规则使用了“任意格式”之外的格式，CAP5 及更早 DLL 就只会收到安全降级快照且不会被误标记
为监控就绪，必须重新启动目标进程加载当前 DLL。

配置模型版本 5 增加规则的“不显示日志”字段；版本 4 引入新的五项格式值。加载更旧配置时，原“所有文本”“Unicode 文本”和
“ANSI 文本”会统一迁移为“文本格式”；原“区块链相关”会展开为相邻的“区块链地址”和
“私钥助记词”两条规则，以保持原来的覆盖范围与首次命中顺序。

Hook 端和主程序端都使用有界事件队列。Hook 热路径只进行短暂的有界锁尝试；竞争、容量或内存不足时，
下一条事件或独立缺口帧会携带缺失数量，主窗口日志、详情和 CSV 都会明确显示“监控缺口”，
不会再把过载造成的数据缺失伪装成完整审计记录。

## 全局注入与覆盖巡检

菜单“保护 → 开启保护”会弹出风险确认；设置中的“打开后自动保护”
或环境变量 `CLIPBOARDPROTECTOR_ENABLE_GLOBAL_HOOK=1` 会在启动时直接启用，不再弹确认。
已指定 `CLIPBOARDPROTECTOR_TEST_TARGET_PID` 时不会走启动全局路径。单进程保护与全局注入互斥。

启用后：

1. 先用 `SetWindowsHookExW(WH_GETMESSAGE)` 覆盖会泵送消息的同架构 GUI 进程；x64 主程序再启动
   `HookHost32.exe` 覆盖 32 位 GUI 进程。
2. `CoverageMonitor` 每 2 秒扫描当前会话、同一用户的进程。新进程先等待 4 秒宽限期，让
   `WH_GETMESSAGE` 有机会自然注入。
3. 宽限期后仍未 Ready 的目标会远程 `LoadLibrary` 当前 Hook DLL（32 位经 `HookHost32.exe`）。
   巡检不会向目标发送窗口或线程消息来唤醒它。
4. 每轮最多启动 4 个目标；失败按 5s / 15s / 60s 退避。进程创建时间用于拒绝 PID 复用。
5. 跳过 PID 0/4、主程序自身、关键/受保护进程、内部组件、其它会话和其它用户。测试构建还要求
   `CLIP_TEST_COVERAGE_TARGET_PATH` 精确匹配，避免误伤其它程序。

关闭全局注入时先停止巡检，再通知已连接 DLL 进入 fail-open、解除 Detours 并完成调用清退，
最后卸载系统 Hook 和远程加载留下的额外模块引用。

保护范围切换和退出清理由同一个常驻后台线程执行；该线程在空闲时处理消息，确保安装的
Windows Hook 一直有有效的所属线程。切换期间主窗口仍可响应，退出请求会排在当前操作之后。
Detours 的指令解析和跳板准备移到暂停线程之前，提交事务时仍会暂停目标线程；卸载检查失败
后的重试间隔逐步增加，避免密集暂停目标。真正卸载前仍保留调用清退检查，因此无响应目标
仍可能延长清理时间。

## 权限与限制

程序正式版本使用 `requireAdministrator` 清单，启动时需要 UAC 授权。

用户态 DLL 注入存在以下限制：

- 封锁、Crypto 和普通规则只对成功加载当前 Hook DLL 的进程生效；未注入进程仍可正常访问剪贴板
- UWP/AppContainer 程序可能无法注入
- `WH_GETMESSAGE` 需要目标有消息循环；全局巡检可远程初始化同会话同用户、无消息循环的进程，但仍会跳过关键/受保护进程和部分 UWP
- 受保护进程和安全软件可能拒绝注入
- 用户态 Hook 无法防御直接系统调用、伪造快捷键消息、内核级访问等主动绕过
- `SetClipboardData(format, NULL)` 的延迟渲染在写入当时没有内容，带内容/语义格式的规则不会命中；数据在 `WM_RENDERFORMAT` 时才出现
- 普通规则和普通日志忽略 `EmptyClipboard`；快捷键独占模式仍会阻止并记录未经授权的清空，Crypto 在后续文本写入时比较地址
- 内容来源与 Crypto 基线共享区用于普通桌面程序，不提供针对恶意同用户进程改写基线字段的防篡改保证
- 用户态 Hook 可能影响宿主稳定性；在 Sandbox 或带快照 VM 完成相应验证前不得用于真实环境

## 隐私与日志

启用文本预览时，符合条件的文本前缀会进入内存日志、详情窗口和 CSV 导出；日志和配置文件
应按敏感数据处理，不要把导出文件提交到公共位置。关闭文本预览后，普通日志事件不会保留
预览内容；普通规则的“右下角通知”与“每次询问”仍会在本次交互中显示匹配内容；Crypto
保护识别出的地址以及私钥或助记词始终隐藏原文和哈希。PID、访问进程、
内容来源、操作、格式、命中规则、处理方式、通知方式和阻止状态仍会记录，以便审计。Hook 只观察
剪贴板 API，不提供内核级防护，不能阻止绕过用户态 API 的程序。
规则的“不显示日志”只影响主窗口列表；记录仍保留在有界内存日志中，CSV 会导出 18 列并用“列表显示”列标明其状态。

图片和文件列表快照默认关闭，只有在设置中显式开启后才会采集。快照只保存在内存中，不写入
配置或 CSV；文件列表包含恢复剪贴板所需的完整本地路径。单条快照最大 1 MB，Hook 待发送队列和
主程序接收队列各最多保留 16 MB，界面日志最多保留 32 MB；达到上限时优先保留审计记录并释放
旧快照，右键复制会相应禁用。被阻止的访问不采集快照，清空日志或退出程序会立即释放这些内容。
从日志把图片或文件列表恢复到剪贴板前会再次确认；文件列表确认框会明确提示其中包含完整本地路径。

## 当前状态

项目仍处于原型开发阶段。单进程保护、规则、确认窗口、配置/CSV 和定向 Sandbox 已有运行证据；
全局多进程、重启自启和长时间压力仍未完成。全局 Hook 曾导致宿主程序卡死，当前重点是：

- 验证单进程注入的稳定性
- 验证 Hook 卸载、worker 生命周期和覆盖巡检的远程引用释放
- 验证管道断开时宿主进程仍然 fail-open
- 验证规则阻断不会导致宿主程序崩溃或卡死

在这些问题关闭前，不应启用全局注入、启动时自动全局保护或开机自启。
