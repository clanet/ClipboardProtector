# 更新记录

## 0.1.0-alpha — 待发布

首个公开开发预览版本，发布日期以 GitHub Release 为准。

- Disable remote FreeLibrary in the DLL inspection tools. Reject --execute because controller exit cannot prove Detour removal or completion of calls through the module.
- Isolate shared mappings and stop events by controller PID and creation time. Bind Hook workers to the authenticated pipe server before installing Detours, and report IPC startup errors instead of silently exiting.
- Enumerate only the current process's threads during Detours transactions, retaining thread handles to prevent ID reuse. Distinguish detached, retained, disconnected, and pending shutdown outcomes so failed detachments do not cause an unconditional five-second wait.
- Add per-process shutdown trace files with monotonic stage timings, thread IDs, and error codes. Record Detour teardown, thread suspension/resumption, global hook removal, pipe acknowledgements, and module rundown. Use preallocated file mappings during suspension so diagnostics do not allocate on the host heap or issue per-record file writes.
- 退出与卸钩诊断日志默认关闭；复现退弹问题前设置 `CLIP_SHUTDOWN_TRACE=1` 才写入 `Diagnostics`。
- Exclude the bundled 32-bit Hook host from self-injection, and bypass Hook initialization in both controller processes. Cross-bitness callbacks must not start Detours inside the process responsible for pumping global Hook messages.
- Keep the native global Hook message loop on a dedicated thread so shutdown acknowledgements, coverage cleanup, and helper waits cannot block it. Preserve the message loop and DLL reference if Hook removal fails, allowing a safe retry.
- Remove global message hooks before requesting host Detour teardown, and remove the native hook before waiting for the 32-bit helper to exit. Bound helper message draining so continuous traffic cannot starve its stop event.
- Remove host heap locking from Detours transactions. Use fixed transaction-node storage and preallocated native thread snapshots while threads are suspended; abort preparation when the time budget or storage limit is exceeded. Add heap-owner and partial-freeze rollback regressions.
- Limit host thread suspension to Detours transactions, check module release safety during detach, and acknowledge shutdown before waiting for in-flight calls. Retain the DLL reference when immediate unloading is unsafe instead of suspending the host again.
- Enable Crypto address protection by default while preserving existing explicit off settings. Independently monitor clipboard address changes and report them through redacted logs and tray notifications, including changes made by uninjected processes. Observed changes are not reported as blocked.
- Add per-rule priority 0-9 (0 matches first). Rules match by priority, then list order; new rules, including rules added from access logs, go to the front of their priority group. Existing configurations keep their order with priority 5.
- Enable "Allow copy/paste shortcuts without checking rules" by default while preserving existing explicit off settings.
- Add "Silent non-text reads and writes" and "Clipboard read and write notifications" when creating the first configuration. Preserve existing configurations and deliberately emptied rule lists.
- 推送版本标签后，GitHub Actions 自动构建并发布 ZIP；alpha 等版本自动标记为预发布。ZIP 仅含四个运行组件和中英文 README，许可文本合并到英文 README，SHA-256 文件仅用于发布流程内部核验。
- 内置中文和英文界面；通过语言菜单即时切换并保存选择，保留用户内容与保护状态。
- 修复 Base58 格式识别误接受内嵌空字符的问题。
- 统一 IPC 版本协商解析与窗口绘图辅助函数，简化字符串反序列化，并补充协议边界测试。
- 注入压力测试改为等待线程就绪，保留调用量断言，增加失败诊断和整体超时余量。
- 修复首次能力协商的扩展规则重发竞态；服务端析构等待所属线程退出，普通停止操作继续使用有界等待。
- 区分远程模块释放的“未提交、已提交、已完成”，超时或取消等待后不再重复减引用；修复 Hook 安装超时后晚失败导致无法再次开启保护的问题。
- 巡检暂停失败时保留现有保护状态；退出先等待保护操作和巡检收尾，再销毁管道及其依赖。
- 通配符工作预算耗尽后不再绕过后续阻止规则；确认窗口记忆的规则统一使用优先级 0 组首，并正确更新已有组首规则。
- 修复输入前取消误触发私有隔离，以及私有会话延迟卸钩与下一会话交错的问题；保留进程内多 GUI 线程切换。
- 在剪贴板锁内发布来源序列号，避免将后续写入归到前一进程；按 `CF_LOCALE` 解码 ANSI 文本。
- 保留独立 Crypto 阻止事件；无内容指纹的事件不按相同内容合并，日志去重不再丢失上游事件缺口计数。
- CA13 协商确认请求的绝对截止时间，界面排队不再延长请求，过期请求和迟到决策不再保存记忆规则。
- Windows 剪贴板访问日志、规则、通知及交互确认。
- 会话级单进程保护、可选全局注入与 x86/x64 覆盖组件。
- 快捷键授权、配置持久化、CSV 导出及托盘管理。
- 私有文字剪贴板：目标进程确认注入及私有会话就绪后，发送 Ctrl+C / Ctrl+V，通过拦截 Win32/OLE 剪贴板接口在内存中传递文字；失败时阻止回落到系统剪贴板。
- BTC / ETH / SOL 地址保护：支持纯地址和段落内替换检测，普通文字覆盖不再误判为地址替换。
- 改进退出、卸载与注入生命周期；增加回归测试。
- 增加开源许可、第三方声明、贡献说明、GitHub CI 和发布包构建流程。

已知限制与未完成验证见 [验证记录](doc/validation.md) 和 [开发待办](doc/todo.md)。此版本不宣称已完成全局长期稳定性验收。
