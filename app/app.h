#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <deque>
#include <unordered_map>
#include "config.h"

namespace clip {

struct App;
class Tray;
class MainWindow;
class PipeServer;
class Injector;

// 日志行数据（ListView 与导出共用）
struct LogRow {
    unsigned long long id = 0;   // 行唯一标识
    DWORD pid = 0;               // 本次访问进程
    unsigned long long hash = 0; // 内容指纹
    SYSTEMTIME time{};
    std::wstring process;        // 进程名，如 notepad.exe
    std::wstring path;           // 完整路径
    BYTE op = 0;                 // kOpRead/kOpWrite/kOpClear
    BYTE action = 0;             // 事件发生时命中的 RuleAction
    bool showNotification = false;
    bool hideFromLogList = false;
    UINT fmt = 0;                // 剪贴板格式 ID
    bool blocked = false;
    std::wstring preview;
    DWORD clipboardSequence = 0;
    DWORD sourcePid = 0;
    std::wstring sourceProcess;
    std::wstring sourcePath;
    std::wstring ruleName;
    BuiltinRule builtinRule = BuiltinRule::None;
    PreviewKind previewKind = PreviewKind::Text;
    bool cryptoContent = false;       // Crypto protection recognized this content
    BYTE snapshotKind = 0;       // ClipboardSnapshotKind
    DWORD snapshotOriginalBytes = 0;
    std::vector<BYTE> snapshot;  // bounded image/file data, memory only
    DWORD count = 1;             // 每条审计记录固定为一次
    unsigned long long missingEvents = 0;
    bool gap = false;
};

// 全局应用状态。生命周期 = 进程生命周期。
struct App {
    HINSTANCE hInst = nullptr;
    Config cfg;
    std::wstring cfgPath;
    bool paused = false;
    // 今日统计（跨日重置）
    int todayRecorded = 0;
    int todayBlocked = 0;
    WORD todayDay = 0;           // wMonth*100+wDay 简易跨日检测
    size_t injectedClients = 0;  // 已注入连接数（M2 起由服务端更新）

    Tray* tray = nullptr;
    MainWindow* wnd = nullptr;
    PipeServer* server = nullptr;      // M2：命名管道服务端
    Injector* injector = nullptr;      // M2：全局钩子注入器

    bool SaveConfig() { return cfg.Save(cfgPath); }
};

extern App g_app;

} // namespace clip
