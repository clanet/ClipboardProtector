#include "i18n.h"
#include "drawing.h"
#include "mainwnd.h"
#include "tray.h"
#include "mainloop.h"
#include "ipc.h"
#include "messages.h"
#include "pipeserver.h"
#include "injector.h"
#include "autostart.h"
#include "app.h"
#include "dlgapi.h"
#include "resource.h"
#include "rules.h"
#include "util.h"
#include <commdlg.h>
#include <dwmapi.h>
#include <uxtheme.h>
#include <windowsx.h>
#include <shellapi.h>
#include <shlobj.h>
#include <algorithm>
#include <cstring>
#include <utility>

namespace clip {

// 工具栏命令 ID
static constexpr int kCmdPause = 3000, kCmdRules = 3001, kCmdClear = 3002,
                     kCmdExport = 3003, kCmdSettings = 3004,
                     kCmdShow = 3005, kCmdHide = 3006, kCmdExit = 3007,
                     kCmdGlobalInjection = 3008, kCmdInjectionInfo = 3009,
                     kCmdSingleProcessTest = 3010,
                     kCmdShortcutOnlyMode = 3011;
static constexpr int kShortcutOnlyHotkeyId = 1;
static constexpr int kPrivateCopyHotkeyId = 2;
static constexpr int kPrivatePasteHotkeyId = 3;
static constexpr int kCmdAppHotkeys = 3012;
static constexpr int kCmdPrivateClear = 3013;
static constexpr UINT_PTR kNotifyTimerId = 1;
static constexpr UINT kNotifyPeriodMs = 200;

static constexpr int kLogStatusColumn = 11;
static constexpr UINT kLogMenuAddRule = 1;
static constexpr UINT kLogMenuCopy = 2;

struct CommandButtonDef {
    int id;
    TextId text;
    int width96;
};

static constexpr CommandButtonDef kCommandButtons[] = {
    {kCmdPause, TextId::PauseProtection, 96},
    {kCmdRules, TextId::AccessRules, 96},
    {kCmdSettings, TextId::Settings, 78},
    {kCmdExport, TextId::ExportLog, 92},
    {kCmdClear, TextId::Clear, 78},
};

struct LogColumnDef {
    TextId name;
    int width96;
};

static constexpr LogColumnDef kLogColumns[] = {
    {TextId::Time, 110}, {TextId::Process, 105}, {TextId::Pid, 70},
    {TextId::Source, 105}, {TextId::SourcePID, 70}, {TextId::Operation, 50},
    {TextId::Format2, 80}, {TextId::MatchedRule, 110}, {TextId::Decision, 75},
    {TextId::Notification, 95}, {TextId::Preview, 280}, {TextId::Status, 60},
    {TextId::MissingEvents, 78}, {TextId::Count, 44},
};

static int ButtonWidth(const CommandButtonDef& button) {
    if (CurrentLanguage() == Language::Chinese) return button.width96;
    return button.id == kCmdPause ? 155 : (std::max)(button.width96,
        static_cast<int>(wcslen(UiText(button.text))) * 8 + 28);
}

static std::wstring FormatTime(const SYSTEMTIME& st) {
    wchar_t buf[32];
    swprintf_s(buf, L"%02d-%02d %02d:%02d:%02d", st.wMonth, st.wDay,
               st.wHour, st.wMinute, st.wSecond);
    return buf;
}

std::wstring FormatName(UINT fmt) {
    switch (fmt) {
        case CF_UNICODETEXT: return UiText(TextId::Text);
        case CF_TEXT:        return UiText(TextId::ANSIText);
        case CF_HDROP:       return UiText(TextId::FileList);
        case CF_BITMAP:      return UiText(TextId::Bitmap);
        case CF_DIB:         return UiText(TextId::DIBImage);
        case CF_DIBV5:       return UiText(TextId::DIBV5Image);
        case CF_ENHMETAFILE: return UiText(TextId::Metafile);
        default:             return UiText(TextId::Format3) + std::to_wstring(fmt);
    }
}

static std::wstring OpName(BYTE op) {
    switch (op) {
        case kOpRead:  return UiText(TextId::Read);
        case kOpWrite: return UiText(TextId::Write);
        case kOpOpen:  return UiText(TextId::Open);
        case kOpClear: return UiText(TextId::Clear);
        default:       return UiText(TextId::Unknown);
    }
}

static std::wstring DecisionName(BYTE action) {
    switch (action) {
        case kRuleAllow:
        case kRuleShow: return UiText(TextId::Allow);
        case kRuleConfirm: return UiText(TextId::AskEveryTime);
        case kRuleBlock: return UiText(TextId::Block);
        default: return UiText(TextId::Unknown);
    }
}

static const wchar_t* NotificationName(bool showNotification) {
    return showNotification ? UiText(TextId::TrayNotification) : UiText(TextId::Silent);
}

static HGLOBAL CopyToGlobalMemory(const void* data, SIZE_T bytes) {
    if (!data || bytes == 0) return nullptr;
    HGLOBAL memory = GlobalAlloc(GMEM_MOVEABLE, bytes);
    if (!memory) return nullptr;
    void* target = GlobalLock(memory);
    if (!target) {
        GlobalFree(memory);
        return nullptr;
    }
    std::memcpy(target, data, bytes);
    GlobalUnlock(memory);
    return memory;
}

static bool OpenClipboardForWrite(HWND owner) {
    for (int attempt = 0; attempt < 5; ++attempt) {
        if (OpenClipboard(owner)) return true;
        if (attempt != 4) Sleep(20);
    }
    return false;
}

static bool WriteClipboardGlobalData(HWND owner, UINT format, const void* data,
                                     SIZE_T bytes) {
    HGLOBAL memory = CopyToGlobalMemory(data, bytes);
    if (!memory) return false;

    if (!OpenClipboardForWrite(owner)) {
        GlobalFree(memory);
        return false;
    }
    if (!EmptyClipboard() || !SetClipboardData(format, memory)) {
        GlobalFree(memory);
        CloseClipboard();
        return false;
    }
    CloseClipboard();
    return true;
}

static bool WriteClipboardFileDrop(HWND owner,
                                   const std::vector<BYTE>& data) {
    HGLOBAL files = CopyToGlobalMemory(data.data(), data.size());
    const DWORD effectValue = DROPEFFECT_COPY;
    HGLOBAL effect = CopyToGlobalMemory(&effectValue, sizeof(effectValue));
    if (!files || !effect) {
        if (files) GlobalFree(files);
        if (effect) GlobalFree(effect);
        return false;
    }
    if (!OpenClipboardForWrite(owner)) {
        GlobalFree(files);
        GlobalFree(effect);
        return false;
    }
    if (!EmptyClipboard() || !SetClipboardData(CF_HDROP, files)) {
        GlobalFree(files);
        GlobalFree(effect);
        CloseClipboard();
        return false;
    }
    const UINT preferredEffect =
        RegisterClipboardFormatW(CFSTR_PREFERREDDROPEFFECT);
    if (preferredEffect == 0 ||
        !SetClipboardData(preferredEffect, effect)) {
        GlobalFree(effect);
    }
    CloseClipboard();
    return true;
}

static bool WriteClipboardText(HWND owner, const std::wstring& text) {
    return !text.empty() &&
           WriteClipboardGlobalData(owner, CF_UNICODETEXT, text.c_str(),
                                    (text.size() + 1) * sizeof(wchar_t));
}

static bool DibDimensions(const std::vector<BYTE>& data, DWORD& width,
                          DWORD& height) {
    width = height = 0;
    if (data.size() < sizeof(DWORD)) return false;
    DWORD headerSize = 0;
    std::memcpy(&headerSize, data.data(), sizeof(headerSize));
    if (headerSize == sizeof(BITMAPCOREHEADER)) {
        if (data.size() < sizeof(BITMAPCOREHEADER)) return false;
        BITMAPCOREHEADER header = {};
        std::memcpy(&header, data.data(), sizeof(header));
        width = header.bcWidth;
        height = header.bcHeight;
        return width != 0 && height != 0;
    }
    if (headerSize < sizeof(BITMAPINFOHEADER) ||
        headerSize > data.size() || data.size() < sizeof(BITMAPINFOHEADER))
        return false;
    BITMAPINFOHEADER header = {};
    std::memcpy(&header, data.data(), sizeof(header));
    if (header.biWidth <= 0 || header.biHeight == 0 ||
        header.biHeight == LONG_MIN)
        return false;
    width = static_cast<DWORD>(header.biWidth);
    height = static_cast<DWORD>(
        header.biHeight < 0 ? -header.biHeight : header.biHeight);
    return true;
}

static bool FileDropCount(const std::vector<BYTE>& data, size_t& count) {
    count = 0;
    if (data.size() < sizeof(DROPFILES)) return false;
    DROPFILES drop = {};
    std::memcpy(&drop, data.data(), sizeof(drop));
    if (drop.pFiles >= data.size()) return false;
    const BYTE* text = data.data() + drop.pFiles;
    const size_t bytes = data.size() - drop.pFiles;
    bool atPathStart = true;
    bool previousNull = false;
    if (drop.fWide) {
        if (bytes < sizeof(wchar_t) * 2 || (drop.pFiles & 1) != 0) return false;
        for (size_t offset = 0; offset + sizeof(wchar_t) <= bytes;
             offset += sizeof(wchar_t)) {
            wchar_t value = 0;
            std::memcpy(&value, text + offset, sizeof(value));
            if (value != L'\0') {
                if (atPathStart) ++count;
                atPathStart = false;
                previousNull = false;
            } else {
                if (previousNull) return true;
                previousNull = true;
                atPathStart = true;
            }
        }
    } else {
        if (bytes < 2) return false;
        for (size_t offset = 0; offset < bytes; ++offset) {
            const char value = static_cast<char>(text[offset]);
            if (value != '\0') {
                if (atPathStart) ++count;
                atPathStart = false;
                previousNull = false;
            } else {
                if (previousNull) return true;
                previousNull = true;
                atPathStart = true;
            }
        }
    }
    return false;
}

static std::wstring SnapshotSizeText(DWORD bytes) {
    wchar_t text[48] = {};
    if (bytes >= 1024u * 1024u) {
        const DWORD tenths = static_cast<DWORD>(
            (static_cast<unsigned long long>(bytes) * 10) / (1024u * 1024u));
        swprintf_s(text, L"%lu.%lu MB", tenths / 10, tenths % 10);
    } else if (bytes >= 1024) {
        swprintf_s(text, L"%lu KB", (bytes + 1023) / 1024);
    } else {
        swprintf_s(text, L"%lu B", bytes);
    }
    return text;
}

static bool IsSnapshotFormat(UINT format) {
    return format == CF_BITMAP || format == CF_DIB || format == CF_DIBV5 ||
           format == CF_HDROP;
}

static std::wstring SnapshotSummary(const LogRow& row) {
    const bool image = row.fmt == CF_BITMAP || row.fmt == CF_DIB ||
                       row.fmt == CF_DIBV5;
    const wchar_t* type = image ? UiText(TextId::Image) : UiText(TextId::FileList);
    if (row.snapshotKind == kSnapshotTooLarge)
        return std::wstring(type) + UiText(TextId::Over1MBNotSaved);
    if (row.snapshotKind == kSnapshotDiscarded)
        return std::wstring(type) + UiText(TextId::MemoryLimitSnapshotReleased);
    if (row.snapshotKind == kSnapshotImage) {
        DWORD width = 0, height = 0;
        if (!DibDimensions(row.snapshot, width, height)) return UiText(TextId::ImageInvalidSnapshot);
        return UiText(TextId::Image2) + std::to_wstring(width) + L" x " +
               std::to_wstring(height) + L" · " +
               SnapshotSizeText(row.snapshotOriginalBytes);
    }
    if (row.snapshotKind == kSnapshotFiles) {
        size_t count = 0;
        if (!FileDropCount(row.snapshot, count)) return UiText(TextId::FileListInvalidSnapshot);
        return UiFormat(TextId::FileSnapshotDescription,
            {std::to_wstring(count), SnapshotSizeText(row.snapshotOriginalBytes)});
    }
    return L"";
}

static std::wstring LogContentSummary(const LogRow& row) {
    return row.preview.empty() && row.previewKind == PreviewKind::Text
        ? SnapshotSummary(row) : DisplayPreview(row.preview, row.previewKind);
}

static bool CanCopyLogContent(const LogRow& row) {
    if (!row.preview.empty()) return true;
    if (row.snapshotKind == kSnapshotImage) {
        DWORD width = 0, height = 0;
        return DibDimensions(row.snapshot, width, height);
    }
    if (row.snapshotKind == kSnapshotFiles) {
        size_t count = 0;
        return FileDropCount(row.snapshot, count);
    }
    return false;
}

static std::wstring NotificationTitle(const LogRow& row) {
    if (row.blocked) return UiText(TextId::ClipboardAccessBlocked);
    return row.op == kOpWrite ? UiText(TextId::ClipboardWrite) :
           row.op == kOpClear ? UiText(TextId::ClipboardClear) : UiText(TextId::ClipboardRead);
}

static std::wstring NotificationText(const LogRow& row, DWORD merged) {
    std::wstring text =
        UiText(TextId::Process2) + (row.process.empty() ? UiText(TextId::Unknown) : row.process);
    if (row.pid) text += L" (PID " + std::to_wstring(row.pid) + L")";
    text += UiText(TextId::Operation2) + OpName(row.op) +
            (row.blocked ? UiText(TextId::Blocked) : UiText(TextId::Allowed));
    text += UiText(TextId::Source2) +
            (row.sourceProcess.empty() ? std::wstring(UiText(TextId::Unknown))
                                       : row.sourceProcess);
    if (row.sourcePid)
        text += L" (PID " + std::to_wstring(row.sourcePid) + L")";
    if (!row.ruleName.empty()) text += UiText(TextId::MatchedRule2) + DisplayRuleName(row.ruleName, row.builtinRule);
    const std::wstring content = LogContentSummary(row);
    if (!content.empty()) text += UiText(TextId::Content) + content;
    if (merged > 1)
        text += UiFormat(TextId::MergedNotificationCount, {std::to_wstring(merged)});
    return text;
}

static bool RestoreAutostartState(AutostartState state) {
    switch (state) {
    case AutostartState::Enabled: return EnableAutostart();
    case AutostartState::Disabled: return DisableAutostart();
    case AutostartState::Absent: return RemoveAutostart();
    }
    return false;
}

// “一直这样”生成的自动规则名称前缀，只用于命名；识别复用靠名称全等。
constexpr TextId kAlwaysAllowRulePrefix = TextId::AlwaysAllow;
constexpr TextId kAlwaysBlockRulePrefix = TextId::AlwaysBlock;
// 规则名称上限 128；进程名和来源名各自截断，避免超限导致整份规则无法保存。
constexpr size_t kAlwaysDecisionNamePartLimit = 48;

static std::wstring BoundedRuleNamePart(const std::wstring& value) {
    return value.size() <= kAlwaysDecisionNamePartLimit
               ? value
               : value.substr(0, kAlwaysDecisionNamePartLimit);
}

// 来源条件必须能命中产生它的那次访问，否则规则形同不存在：
// 来源 PID 缺失即来源未知；来源是访问进程自己用 kSourceSameProcess；其它已知
// 来源按来源进程名；只有 PID 没有名字时无名称条件可用，退回 kSourceDifferentProcess。
static void AlwaysDecisionSourceCondition(const AlwaysDecision& decision,
                                          unsigned char& sourceMode,
                                          std::wstring& sourcePattern) {
    sourcePattern.clear();
    if (decision.sourceProcessId == 0) {
        sourceMode = kSourceUnknown;
    } else if (decision.sourceProcessId == decision.processId) {
        sourceMode = kSourceSameProcess;
    } else if (!decision.sourceProcess.empty()) {
        sourceMode = kSourceName;
        sourcePattern = decision.sourceProcess;
    } else {
        sourceMode = kSourceDifferentProcess;
    }
}

static std::wstring AlwaysDecisionRuleName(const AlwaysDecision& decision,
                                           unsigned char sourceMode,
                                           Language language = CurrentLanguage()) {
    std::wstring name = decision.action == kRuleBlock ? UiText(kAlwaysBlockRulePrefix, language)
                                                      : UiText(kAlwaysAllowRulePrefix, language);
    name += BoundedRuleNamePart(decision.process);
    if (sourceMode == kSourceSameProcess)
        name += UiText(TextId::SameProcess, language);
    else if (sourceMode == kSourceUnknown)
        name += UiText(TextId::UnknownSource, language);
    else if (sourceMode == kSourceDifferentProcess)
        name += UiText(TextId::OtherProcess, language);
    else
        name += UiText(TextId::Source3, language) + BoundedRuleNamePart(decision.sourceProcess) + UiText(TextId::CloseParenthesis, language);
    return name;
}

// 同一“访问进程 + 来源条件”只保留一条自动规则：已存在则改写决策并移到最前，
// 使首次命中的结果与用户最后一次点击一致。
static bool UpsertAlwaysDecisionRule(std::vector<Rule>& rules,
                                     const AlwaysDecision& decision) {
    unsigned char sourceMode = kSourceAny;
    std::wstring sourcePattern;
    AlwaysDecisionSourceCondition(decision, sourceMode, sourcePattern);
    const std::wstring processLower = ToLower(decision.process);
    const std::wstring sourceLower = ToLower(sourcePattern);
    const std::wstring name = AlwaysDecisionRuleName(decision, sourceMode);

    size_t existing = 0;
    bool found = false;
    for (size_t i = 0; i < rules.size(); ++i) {
        const Rule& rule = rules[i];
        if (rule.enabled && !rule.isPath &&
            ToLower(rule.pattern) == processLower &&
            rule.operations == kRuleReadWrite && rule.format == kFormatAny &&
            rule.contentRegex.empty() && rule.sourceMode == sourceMode &&
            ToLower(rule.sourcePattern) == sourceLower &&
            (rule.name == name ||
             rule.name == AlwaysDecisionRuleName(decision, sourceMode, Language::Chinese) ||
             rule.name == AlwaysDecisionRuleName(decision, sourceMode, Language::English))) {
            existing = i;
            found = true;
            break;
        }
    }

    Rule rule;
    if (found) {
        if (existing == 0) return false;  // 已是同一条规则且位于最前
        rule = std::move(rules[existing]);
        rules.erase(rules.begin() + existing);
    }
    if (!found) rule.name = name;
    rule.pattern = decision.process;
    rule.isPath = false;
    rule.action = decision.action;
    rule.showNotification = false;
    rule.hideFromLogList = false;
    rule.operations = kRuleReadWrite;
    rule.format = kFormatAny;
    rule.contentRegex.clear();
    rule.ignoreCase = true;
    rule.enabled = true;
    rule.sourceMode = sourceMode;
    rule.sourcePattern = std::move(sourcePattern);
    rules.insert(rules.begin(), std::move(rule));
    return true;
}

MainWindow::~MainWindow() {
    privateClipboard_.Stop();
    JoinProtectionOperation();
    JoinAutostartQuery();
}

void MainWindow::JoinProtectionOperation() {
    protectionWorkerStop_.store(true, std::memory_order_release);
    if (protectionWorkEvent_) SetEvent(protectionWorkEvent_);
    if (protectionThread_.joinable()) protectionThread_.join();
    if (protectionWorkEvent_) CloseHandle(protectionWorkEvent_);
    protectionWorkEvent_ = nullptr;
}

void MainWindow::RunProtectionWorker() {
    // Windows hooks belong to the installing thread. Keep that thread alive
    // and pumping messages between operations, until its hooks are removed.
    for (;;) {
        const DWORD wait = MsgWaitForMultipleObjectsEx(
            1, &protectionWorkEvent_, INFINITE, QS_ALLINPUT, MWMO_INPUTAVAILABLE);
        if (protectionWorkerStop_.load(std::memory_order_acquire)) return;
        if (wait == WAIT_OBJECT_0) {
            std::function<void()> task;
            {
                std::lock_guard<std::mutex> lock(protectionTaskMutex_);
                task = std::move(protectionTask_);
            }
            if (task) task();
            if (protectionWorkerStop_.load(std::memory_order_acquire)) return;
        } else if (wait == WAIT_OBJECT_0 + 1) {
            MSG message;
            for (int count = 0; count < 64 &&
                 PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE); ++count) {
                TranslateMessage(&message);
                DispatchMessageW(&message);
            }
        }
    }
}

void MainWindow::StartAutostartQuery() {
    if (autostartQueryThread_.joinable() || !hwnd_) return;
    const HWND target = hwnd_;
    autostartQueryStarted_ = true;
    autostartQueryKnown_ = false;
    autostartQueryState_ = AutostartState::Absent;
    autostartQueryPending_ = true;
    try {
        autostartQueryThread_ = std::thread([this, target] {
            AutostartState state = AutostartState::Absent;
            bool known = false;
            try {
                known = QueryAutostart(state);
            } catch (...) {
                // Keep startup usable if a transient allocation fails while
                // collecting scheduler output.
            }
            // The UI reads these fields only after joining this worker.
            autostartQueryState_ = state;
            autostartQueryKnown_ = known;
            // The HWND value is safe to retain; PostMessage simply fails if
            // teardown has already destroyed that window.
            PostMessageW(target, kMsgAutostartQuery,
                         known ? static_cast<WPARAM>(state) : 0,
                         known ? 1 : 0);
        });
    } catch (...) {
        // A failed worker allocation leaves startup usable; settings can
        // still perform a synchronous query when the user edits autostart.
        autostartQueryStarted_ = false;
        autostartQueryKnown_ = false;
        autostartQueryPending_ = false;
    }
}

void MainWindow::JoinAutostartQuery() {
    autostartQueryPending_ = false;
    autostartQueryDeferred_ = false;
    if (autostartQueryThread_.joinable()) autostartQueryThread_.join();
}

bool MainWindow::Create(HINSTANCE hInst) {
    WNDCLASSEXW wc = {sizeof(wc)};
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = &MainWindow::WndProcStatic;
    wc.hInstance = hInst;
    wc.hIcon = (HICON)LoadImageW(hInst, MAKEINTRESOURCEW(IDI_APP_ICON),
                                 IMAGE_ICON, 32, 32, LR_SHARED);
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = nullptr;
    wc.hIconSm = (HICON)LoadImageW(hInst, MAKEINTRESOURCEW(IDI_APP_ICON),
                                   IMAGE_ICON, 16, 16, LR_SHARED);
    wc.lpszClassName = L"ClipProtectorMainWnd";
    RegisterClassExW(&wc);

    // 保存的是 96-DPI 逻辑尺寸；在当前显示缩放下还原并限制到工作区。
    RECT rc{};
    SystemParametersInfoW(SPI_GETWORKAREA, 0, &rc, 0);
    const UINT dpi = GetDpiForSystem();
    const int workWidth = rc.right - rc.left;
    const int workHeight = rc.bottom - rc.top;
    int w = g_app.cfg.settings.windowWidth > 0
                ? DpiScale(g_app.cfg.settings.windowWidth, dpi)
                : std::min(workWidth * 3 / 4, DpiScale(1440, dpi));
    int h = g_app.cfg.settings.windowHeight > 0
                ? DpiScale(g_app.cfg.settings.windowHeight, dpi)
                : std::min(workHeight * 3 / 4, DpiScale(900, dpi));
    w = std::min(std::max(w, DpiScale(860, dpi)), workWidth);
    h = std::min(std::max(h, DpiScale(600, dpi)), workHeight);
    hwnd_ = CreateWindowExW(0, wc.lpszClassName, UiText(TextId::ClipboardProtector),
                            WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
                            rc.left + (rc.right - rc.left - w) / 2,
                            rc.top + (rc.bottom - rc.top - h) / 2, w, h,
                            nullptr, nullptr, hInst, this);
    if (!hwnd_) return false;
    if (!g_app.cfg.settings.startMinimized) {
        ShowWindow(hwnd_, SW_SHOWNORMAL);
        UpdateWindow(hwnd_);
    }
    return true;
}

LRESULT CALLBACK MainWindow::WndProcStatic(HWND h, UINT m, WPARAM wp, LPARAM lp) {
    MainWindow* self = reinterpret_cast<MainWindow*>(GetWindowLongPtrW(h, GWLP_USERDATA));
    if (m == WM_NCCREATE) {
        // 首个携带创建参数的消息：存回 this 指针，并把窗口句柄写入成员，
        // 保证 WM_CREATE 阶段 OnCreate 能拿到有效 hwnd。
        auto* cs = reinterpret_cast<CREATESTRUCTW*>(lp);
        self = reinterpret_cast<MainWindow*>(cs->lpCreateParams);
        SetWindowLongPtrW(h, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
        self->hwnd_ = h;
    }
    return self ? self->WndProc(m, wp, lp) : DefWindowProcW(h, m, wp, lp);
}

LRESULT MainWindow::WndProc(UINT msg, WPARAM wp, LPARAM lp) {
    // explorer 重启广播：重建被销毁的托盘图标
    static const UINT kTaskbarCreated = RegisterWindowMessageW(L"TaskbarCreated");
    if (msg == kTaskbarCreated) {
        if (g_app.tray) g_app.tray->ReAdd();
        return 0;
    }
    switch (msg) {
    case WM_CREATE:
        OnCreate();
        return 0;
    case WM_GETMINMAXINFO: {
        auto* limits = reinterpret_cast<MINMAXINFO*>(lp);
        const UINT dpi = dpi_ ? dpi_ : GetDpiForSystem();
        limits->ptMinTrackSize.x = DpiScale(860, dpi);
        limits->ptMinTrackSize.y = DpiScale(600, dpi);
        return 0;
    }
    case WM_SIZE:
        Layout();
        return 0;
    case WM_ERASEBKGND:
        return 1;
    case WM_PAINT:
        Paint();
        return 0;
    case WM_SETCURSOR:
        if (reinterpret_cast<HWND>(wp) == hwnd_ && LOWORD(lp) == HTCLIENT) {
            POINT point = {};
            GetCursorPos(&point);
            ScreenToClient(hwnd_, &point);
            if (PtInRect(&cardRects_[3], point)) {
                SetCursor(LoadCursorW(nullptr, IDC_HAND));
                return TRUE;
            }
        }
        break;
    case WM_LBUTTONUP: {
        POINT point = {GET_X_LPARAM(lp), GET_Y_LPARAM(lp)};
        if (PtInRect(&cardRects_[3], point)) {
            ToggleBlockedFilter();
            return 0;
        }
        break;
    }
    case WM_DRAWITEM: {
        const auto* draw = reinterpret_cast<DRAWITEMSTRUCT*>(lp);
        if (draw && draw->CtlType == ODT_BUTTON) {
            DrawCommandButton(*draw);
            return TRUE;
        }
        break;
    }
    case WM_TIMER:
        if (wp == kNotifyTimerId) {
            FlushDueNotifications();
            return 0;
        }
        break;
    case WM_INITMENUPOPUP:
        if (!HIWORD(lp)) {
            SyncMenuState();
            return 0;
        }
        break;
#ifdef CLIP_TEST_OBJECT_NAMES
    case WM_APP + 60: // Test-only state; never expose the private text.
        return (privateClipboard_.Busy() ? 1 : 0) | (privateClipboard_.HasText() ? 2 : 0);
    case WM_APP + 61:
        return SetWindowTextW(hwnd_, privateClipboard_.DiagnosticStatusForTest());
#endif
    case WM_HOTKEY:
        if (wp == kPrivateCopyHotkeyId || wp == kPrivatePasteHotkeyId) {
            if (!exitRequested_ && privateHotkeysRegistered_ &&
                GetLastActivePopup(hwnd_) == hwnd_) {
                if (!privateClipboard_.Start(wp == kPrivateCopyHotkeyId
                        ? PrivateClipboard::Operation::copy : PrivateClipboard::Operation::paste,
                            GetForegroundWindow(), hwnd_, kMsgPrivateClipboard,
                            [](DWORD pid, const std::wstring& name) {
                                return g_app.server && g_app.server->QueuePrivateClipboard(pid, name);
                            }))
                    NotifyPrivateClipboard(UiText(TextId::APrivateClipboardOperationIsInProgress));
            }
            return 0;
        }
        if (wp == kShortcutOnlyHotkeyId) {
            // Do not let a modal editor overwrite a hotkey change with its
            // older checkbox snapshot when the dialog later closes.
            if (!protectionOperationPending_ &&
                GetLastActivePopup(hwnd_) == hwnd_)
                ToggleShortcutOnlyMode();
            return 0;
        }
        break;
    case kMsgProtectionOperation:
        CompleteProtectionOperation();
        return 0;
    case kMsgPrivateClipboard: {
        std::wstring message;
        bool success = false;
        if (privateClipboard_.TakeResult(message, success) && !exitRequested_)
            NotifyPrivateClipboard(message.c_str());
        return 0;
    }
    case kMsgPrivateHotkeyWarning:
        if (g_app.tray) g_app.tray->ShowBalloon(UiText(TextId::KeyboardShortcuts),
            UiText(TextId::SomeShortcutsAreAlreadyInUseAnd), false);
        return 0;
    case kMsgAutostartQuery:
        if (!autostartQueryPending_) return 0;
        // Server transitions read settings on the worker. Apply this result
        // after completion, so configuration changes stay serialized.
        if (protectionOperationPending_) {
            autostartQueryDeferred_ = true;
            return 0;
        }
        autostartQueryPending_ = false;
        JoinAutostartQuery();
        if (autostartQueryKnown_) {
            const bool oldAutostart = g_app.cfg.settings.autostart;
            const bool queriedAutostart =
                autostartQueryState_ == AutostartState::Enabled;
            if (oldAutostart != queriedAutostart) {
                g_app.cfg.settings.autostart = queriedAutostart;
                if (!g_app.SaveConfig()) {
                    g_app.cfg.settings.autostart = oldAutostart;
                } else if (g_app.server) {
                    g_app.server->BroadcastSettings(g_app.cfg.settings);
                }
            }
        }
        autostartQueryStarted_ = false;
        return 0;
    case WM_CLOSE:          // 关闭 = 隐藏到托盘
        ShowWindow(hwnd_, SW_HIDE);
        return 0;
    case WM_DPICHANGED: {
        ApplyDpi(HIWORD(wp));
        auto* r = reinterpret_cast<RECT*>(lp);
        SetWindowPos(hwnd_, nullptr, r->left, r->top,
                     r->right - r->left, r->bottom - r->top,
                     SWP_NOZORDER | SWP_NOACTIVATE);
        return 0;
    }
    case WM_COMMAND: {
        const int command = LOWORD(wp);
        if (protectionOperationPending_ &&
            (command == kCmdPause || command == kCmdRules ||
             command == kCmdSettings || command == kCmdGlobalInjection ||
             command == kCmdSingleProcessTest ||
             command == kCmdShortcutOnlyMode)) {
            return 0;
        }
        switch (LOWORD(wp)) {
        case IDM_LANGUAGE_CHINESE:
        case IDM_LANGUAGE_ENGLISH:
            if (!protectionOperationPending_ && !exitRequested_ &&
                !privateClipboard_.Busy() && IsWindowEnabled(hwnd_))
                ChangeLanguage(LOWORD(wp) == IDM_LANGUAGE_ENGLISH
                    ? Language::English : Language::Chinese);
            return 0;
        case kCmdAppHotkeys:
            if (!protectionOperationPending_ && !exitRequested_) ConfigureHotkeys();
            return 0;
        case kCmdPrivateClear:
            privateClipboard_.Clear();
            NotifyPrivateClipboard(UiText(TextId::PrivateClipboardCleared));
            return 0;
        case kCmdShow:
            ShowMainWindow();
            return 0;
        case kCmdHide:
            ShowWindow(hwnd_, SW_HIDE);
            return 0;
        case kCmdExit:
            RequestExit();
            return 0;
        case kCmdPause:
            TogglePause();
            return 0;
        case kCmdGlobalInjection:
            ToggleGlobalInjection();
            return 0;
        case kCmdSingleProcessTest:
            ToggleSingleProcessTest();
            return 0;
        case kCmdInjectionInfo:
            ShowInjectionSafetyInfo();
            return 0;
        case kCmdRules:
            {
                std::vector<Rule> editedRules;
                try {
                    editedRules = g_app.cfg.rules;
                    pendingAlwaysDecisions_.clear();
                } catch (...) {
                    UiMessageBox(hwnd_, UiText(TextId::NotEnoughMemoryToOpenAccessRules),
                                UiText(TextId::RuleSettings), MB_ICONERROR);
                    return 0;
                }

                bool changed = false;
                rulesDialogOpen_ = true;
                try {
                    changed = ShowRulesDialog(hwnd_, editedRules);
                } catch (...) {
                    rulesDialogOpen_ = false;
                    pendingAlwaysDecisions_.clear();
                    UiMessageBox(hwnd_, UiText(TextId::TheRulesDialogFailedExistingRulesWere),
                                UiText(TextId::RuleSettings), MB_ICONERROR);
                    return 0;
                }
                rulesDialogOpen_ = false;
                if (!changed) {
                    pendingAlwaysDecisions_.clear();
                    return 0;
                }

                try {
                    // 确认框在规则窗口打开期间仍可响应；把期间新增的
                    // “一直这样”规则合并到编辑结果首位，避免被旧副本覆盖。
                    for (const AlwaysDecision& decision :
                         pendingAlwaysDecisions_)
                        UpsertAlwaysDecisionRule(editedRules, decision);
                    pendingAlwaysDecisions_.clear();
                    if (!IsRuleSetSupported(editedRules)) {
                        UiMessageBox(hwnd_, UiText(TextId::TheMergedRulesExceedTheCountOr),
                                    UiText(TextId::RuleSettings), MB_ICONERROR);
                        return 0;
                    }
                    std::vector<Rule> currentRules = g_app.cfg.rules;
                    g_app.cfg.rules = std::move(editedRules);
                    if (!g_app.SaveConfig()) {
                        g_app.cfg.rules = std::move(currentRules);
                        if (g_app.server)
                            g_app.server->BroadcastRules(g_app.cfg.rules);
                        UiMessageBox(hwnd_,
                                    UiText(TextId::CouldNotSaveTheRulesInMemory),
                                    UiText(TextId::SaveFailed), MB_ICONERROR);
                        return 0;
                    }
                    if (g_app.server)
                        g_app.server->BroadcastRules(g_app.cfg.rules);
                } catch (...) {
                    pendingAlwaysDecisions_.clear();
                    UiMessageBox(hwnd_, UiText(TextId::NotEnoughMemoryToMergeTheRules),
                                UiText(TextId::RuleSettings), MB_ICONERROR);
                }
            }
            return 0;
        case kCmdClear: ClearLog(); return 0;
        case kCmdExport: ExportCsv(); return 0;
        case kCmdSettings:
            {
                const Settings configBeforeDialog = g_app.cfg.settings;
                // Join the startup query so the dialog reflects the actual
                // scheduler state without issuing a second query when its
                // result is already available.
                JoinAutostartQuery();
                AutostartState oldTaskState = AutostartState::Absent;
                bool oldTaskKnown = false;
                if (autostartQueryStarted_) {
                    oldTaskKnown = autostartQueryKnown_;
                    oldTaskState = autostartQueryState_;
                }
                if (!oldTaskKnown) oldTaskKnown = QueryAutostart(oldTaskState);
                if (oldTaskKnown)
                    g_app.cfg.settings.autostart =
                        oldTaskState == AutostartState::Enabled;
                const Settings oldSettings = g_app.cfg.settings;
                autostartQueryStarted_ = false;

                if (!ShowSettingsDialog(hwnd_, g_app.cfg.settings)) {
                    // Keep the startup task snapshot in sync even when the
                    // user cancels. If persistence fails, restore the exact
                    // pre-dialog state and report the failed synchronization.
                    if (oldSettings.autostart != configBeforeDialog.autostart &&
                        !g_app.SaveConfig()) {
                        g_app.cfg.settings = configBeforeDialog;
                        UiMessageBox(hwnd_,
                                    UiText(TextId::CouldNotSaveTheScheduledTaskState),
                                    UiText(TextId::SaveFailed), MB_ICONERROR);
                    }
                    return 0;
                }
                const bool taskChanged =
                    g_app.cfg.settings.autostart != oldSettings.autostart;
                if (taskChanged && !oldTaskKnown) {
                    g_app.cfg.settings = oldSettings;
                    UiMessageBox(hwnd_,
                                UiText(TextId::CouldNotQueryTheScheduledTaskStartup),
                                UiText(TextId::SettingsFailed), MB_ICONERROR);
                    return 0;
                }
                if (taskChanged &&
                    !SetAutostart(g_app.cfg.settings.autostart, oldTaskState)) {
                    const bool taskRestored = oldTaskKnown &&
                                              RestoreAutostartState(oldTaskState);
                    g_app.cfg.settings = oldSettings;
                    UiMessageBox(hwnd_,
                                 taskRestored
                                     ? UiText(TextId::CouldNotUpdateTheScheduledTaskConfiguration)
                                     : UiText(TextId::CouldNotUpdateTheScheduledTaskOr),
                                 UiText(TextId::SettingsFailed), MB_ICONERROR);
                    return 0;
                }
                if (!g_app.SaveConfig()) {
                    g_app.cfg.settings = oldSettings;
                    bool taskRestored = !taskChanged;
                    if (taskChanged) {
                        taskRestored = oldTaskKnown &&
                                        RestoreAutostartState(oldTaskState);
                    }
                    if (g_app.server)
                        g_app.server->BroadcastSettings(oldSettings);
                    UiMessageBox(hwnd_,
                                taskRestored
                                    ? UiText(TextId::CouldNotSaveSettingsInMemoryAnd)
                                    : UiText(TextId::CouldNotSaveSettingsSomeScheduledTask),
                                UiText(TextId::SaveFailed), MB_ICONERROR);
                    return 0;
                }
                TrimToLimit();
                if (g_app.server)
                    g_app.server->BroadcastSettings(g_app.cfg.settings);
                notify_.clear();
                SyncProtectionState();
            }
            return 0;
        case kCmdShortcutOnlyMode:
            ToggleShortcutOnlyMode();
            return 0;
        }
        break;
    }
    case WM_CONTEXTMENU:
        if (reinterpret_cast<HWND>(wp) == lv_) {
            ShowLogContextMenu(GET_X_LPARAM(lp), GET_Y_LPARAM(lp));
            return 0;
        }
        break;
    case WM_NOTIFY: {
        auto* nm = reinterpret_cast<NMHDR*>(lp);
        if (nm->idFrom != 102) break;   // 仅处理日志列表的通知
        if (nm->code == NM_CUSTOMDRAW && nm->hwndFrom == lv_) {
            auto* cd = reinterpret_cast<NMLVCUSTOMDRAW*>(nm);
            switch (cd->nmcd.dwDrawStage) {
            case CDDS_PREPAINT: return CDRF_NOTIFYITEMDRAW;
            case CDDS_ITEMPREPAINT: {
                size_t i = cd->nmcd.dwItemSpec;
                if (!(cd->nmcd.uItemState & CDIS_SELECTED)) {
                    const LogRow* row = ListRow(static_cast<int>(i));
                    if (row && row->cryptoContent) {
                        cd->clrTextBk = RGB(255, 238, 238);
                        cd->clrText = RGB(88, 45, 45);
                    } else {
                        cd->clrTextBk = i % 2 == 0 ? RGB(255, 255, 255)
                                                   : RGB(247, 250, 249);
                        cd->clrText = row && row->gap
                                          ? RGB(171, 92, 8)
                                          : row && row->blocked
                                                ? RGB(185, 45, 45)
                                                : RGB(42, 65, 62);
                    }
                }
                return CDRF_NOTIFYSUBITEMDRAW;
            }
            case CDDS_ITEMPREPAINT | CDDS_SUBITEM:
                if (!(cd->nmcd.uItemState & CDIS_SELECTED) &&
                    cd->iSubItem == kLogStatusColumn) {
                    const LogRow* row =
                        ListRow(static_cast<int>(cd->nmcd.dwItemSpec));
                    if (row && row->gap)
                        cd->clrText = RGB(171, 92, 8);
                    else if (row && (row->cryptoContent || row->blocked))
                        cd->clrText = RGB(185, 45, 45);
                    else
                        cd->clrText = RGB(13, 121, 111);
                }
                return CDRF_DODEFAULT;
            }
            return CDRF_DODEFAULT;
        }
        if (nm->code == NM_DBLCLK && nm->hwndFrom == lv_) {
            auto* di = reinterpret_cast<NMITEMACTIVATE*>(nm);
            if (di->iItem >= 0) ShowDetails(di->iItem);
            return 0;
        }
        break;
    }
    case kMsgEvent: {
        // 只消费主程序进程内的受保护事件队列；lParam 永远不作为指针使用。
        if (g_app.server) {
            LogRow row;
            while (g_app.server->PopEvent(row)) OnEvent(std::move(row));
        }
        return 0;
    }
    case kMsgConfirmation:
        if (wp != 0)
            confirmations_.erase(static_cast<DWORD>(wp));
        ShowPendingConfirmations();
        return 0;
    case kMsgConfirmationDecision:
        CompleteConfirmation(static_cast<DWORD>(wp), (lp & 1) != 0,
                             (lp & 2) != 0);
        return 0;
    case kMsgClients:
        SetInjectedCount((size_t)wp);
        return 0;
#ifdef CLIP_TEST_OBJECT_NAMES
    case kMsgTestClientCount:
        return static_cast<LRESULT>(0x10000u | g_app.injectedClients);
#endif
    case kTrayMsg: {
        // NOTIFYICON_VERSION_4 puts the mouse/balloon event in lParam;
        // wParam carries the callback coordinates/identifier.
        WORD ev = LOWORD(lp);
        if (ev == WM_CONTEXTMENU) {
            ShowContextMenu(GET_X_LPARAM(wp), GET_Y_LPARAM(wp));
        } else if (ev == NIN_BALLOONUSERCLICK) {
            FocusNotifiedRow();
        } else if (ev == NIN_SELECT || ev == WM_LBUTTONDBLCLK) {
            ToggleVisible();
        }
        return 0;
    }
    case WM_DESTROY:
        UnregisterHotkeys();
        privateClipboard_.Stop();
        confirmations_.clear();
        SaveWindowSize();
        KillTimer(hwnd_, kNotifyTimerId);
        JoinProtectionOperation();
        JoinAutostartQuery();
        for (HFONT font : {uiFont_, titleFont_, metricFont_, sectionFont_,
                           smallFont_}) {
            if (font) DeleteObject(font);
        }
        uiFont_ = titleFont_ = metricFont_ = sectionFont_ = smallFont_ = nullptr;
        if (rowHeightImages_) ImageList_Destroy(rowHeightImages_);
        rowHeightImages_ = nullptr;
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd_, msg, wp, lp);
}

bool MainWindow::TranslateConfirmationMessage(MSG& message) {
    for (const auto& item : confirmations_) {
        const HWND window = item.second ? item.second->hwnd() : nullptr;
        if (window && IsWindow(window) && IsDialogMessageW(window, &message))
            return true;
    }
    return false;
}

void MainWindow::OnCreate() {
    dpi_ = GetDpiForWindow(hwnd_);

    CreateApplicationMenu();
    if (!RegisterHotkeys(g_app.cfg.settings.hotkeys))
        PostMessageW(hwnd_, kMsgPrivateHotkeyWarning, 0, 0);
    SyncMenuState();

    for (size_t i = 0; i < commandButtons_.size(); ++i) {
        commandButtons_[i] = CreateWindowExW(
            0, L"BUTTON", UiText(kCommandButtons[i].text),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW,
            0, 0, 0, 0, hwnd_,
            reinterpret_cast<HMENU>(static_cast<INT_PTR>(kCommandButtons[i].id)),
            g_app.hInst, nullptr);
    }

    lv_ = CreateWindowExW(0, WC_LISTVIEWW, nullptr,
                          WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SHOWSELALWAYS |
                              LVS_NOSORTHEADER,
                          0, 0, 0, 0, hwnd_, (HMENU)(INT_PTR)102, g_app.hInst, nullptr);
    ListView_SetExtendedListViewStyle(
        lv_, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER |
                 LVS_EX_HEADERINALLVIEWS | LVS_EX_HEADERDRAGDROP);
    ListView_SetBkColor(lv_, RGB(255, 255, 255));
    ListView_SetTextBkColor(lv_, RGB(255, 255, 255));
    SetWindowTheme(lv_, L"Explorer", nullptr);
    LVCOLUMNW c = {};
    c.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT;
    c.fmt = LVCFMT_LEFT;
    for (int i = 0; i < _countof(kLogColumns); ++i) {
        c.pszText = const_cast<LPWSTR>(UiText(kLogColumns[i].name));
        c.cx = DpiScale(CurrentLanguage() == Language::English
                    ? (std::max)(kLogColumns[i].width96, static_cast<int>(wcslen(UiText(kLogColumns[i].name))) * 8 + 24)
                    : kLogColumns[i].width96, dpi_);
        ListView_InsertColumn(lv_, i, &c);
    }

    ApplyDpi(dpi_);
    constexpr DWORD kDwmWindowCornerPreference = 33;
    const DWORD roundCorners = 2; // DWMWCP_ROUND on Windows 11; ignored earlier.
    DwmSetWindowAttribute(hwnd_, kDwmWindowCornerPreference, &roundCorners,
                          sizeof(roundCorners));
    SYSTEMTIME st;
    GetLocalTime(&st);
    g_app.todayDay = (WORD)(st.wMonth * 100 + st.wDay);
    SetTimer(hwnd_, kNotifyTimerId, kNotifyPeriodMs, nullptr);
    UpdateStatusBar();
    Layout();
}

void MainWindow::CreateFonts(UINT dpi) {
    for (HFONT font : {uiFont_, titleFont_, metricFont_, sectionFont_,
                       smallFont_}) {
        if (font) DeleteObject(font);
    }
    const wchar_t* family = UiFontFamily();
    auto makeFont = [dpi, family](int points, int weight) {
        return CreateFontW(-MulDiv(points, static_cast<int>(dpi), 72), 0, 0, 0,
                           weight, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                           OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                           CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE,
                           family);
    };
    uiFont_ = makeFont(10, FW_NORMAL);
    titleFont_ = makeFont(18, FW_SEMIBOLD);
    metricFont_ = makeFont(21, FW_SEMIBOLD);
    sectionFont_ = makeFont(11, FW_SEMIBOLD);
    smallFont_ = makeFont(9, FW_NORMAL);
}

void MainWindow::ApplyDpi(UINT dpi) {
    dpi_ = dpi ? dpi : 96;
    CreateFonts(dpi_);
    for (HWND button : commandButtons_)
        if (button) SendMessageW(button, WM_SETFONT, (WPARAM)uiFont_, TRUE);
    if (lv_) {
        SendMessageW(lv_, WM_SETFONT, (WPARAM)uiFont_, TRUE);
        HWND header = ListView_GetHeader(lv_);
        if (header) SendMessageW(header, WM_SETFONT, (WPARAM)smallFont_, TRUE);
        for (int i = 0; i < _countof(kLogColumns); ++i)
            ListView_SetColumnWidth(
                lv_, i, DpiScale(CurrentLanguage() == Language::English
                    ? (std::max)(kLogColumns[i].width96, static_cast<int>(wcslen(UiText(kLogColumns[i].name))) * 8 + 24)
                    : kLogColumns[i].width96, dpi_));

        SendMessageW(lv_, LVM_SETIMAGELIST, LVSIL_SMALL, 0);
        if (rowHeightImages_) ImageList_Destroy(rowHeightImages_);
        rowHeightImages_ = ImageList_Create(
            1, DpiScale(28, dpi_), ILC_COLOR32 | ILC_MASK, 1, 1);
        if (rowHeightImages_)
            ListView_SetImageList(lv_, rowHeightImages_, LVSIL_SMALL);
    }
    Layout();
    InvalidateRect(hwnd_, nullptr, TRUE);
}

void MainWindow::NotifyPrivateClipboard(const wchar_t* text) {
    // Never include private content in notifications or logs.
    if (g_app.tray) g_app.tray->ShowBalloon(UiText(TextId::PrivateClipboard), text, false);
}

void MainWindow::UnregisterHotkeys() {
    UnregisterHotKey(hwnd_, kShortcutOnlyHotkeyId);
    shortcutHotkeyRegistered_ = false;
    UnregisterHotKey(hwnd_, kPrivateCopyHotkeyId);
    UnregisterHotKey(hwnd_, kPrivatePasteHotkeyId);
    privateHotkeysRegistered_ = false;
}

bool MainWindow::RegisterHotkeys(const AppHotkeys& keys) {
    hotkeyRegistrationError_.clear();
    if (!ValidHotkeys(keys)) return false;
    const auto failed = [this](const wchar_t* name, unsigned int modifiers, unsigned int key) {
        const DWORD code = GetLastError();
        if (!hotkeyRegistrationError_.empty()) hotkeyRegistrationError_ += L"\n";
        hotkeyRegistrationError_ += std::wstring(name) + UiText(TextId::Colon) + HotkeyText(modifiers, key) +
            UiText(TextId::SystemError) + std::to_wstring(code) + UiText(TextId::CloseParenthesis);
    };
    // Preserve the toggle at startup if a private shortcut is unavailable.
    // Settings changes roll back the whole group on any registration failure.
    shortcutHotkeyRegistered_ = RegisterHotKey(hwnd_, kShortcutOnlyHotkeyId,
        keys.shortcutOnlyModifiers | MOD_NOREPEAT, keys.shortcutOnlyKey) != FALSE;
    if (!shortcutHotkeyRegistered_)
        failed(UiText(TextId::ModeToggle), keys.shortcutOnlyModifiers, keys.shortcutOnlyKey);
    if (!RegisterHotKey(hwnd_, kPrivateCopyHotkeyId,
                        keys.copyModifiers | MOD_NOREPEAT, keys.copyKey)) {
        failed(UiText(TextId::PrivateCopy), keys.copyModifiers, keys.copyKey);
        return false;
    }
    if (!RegisterHotKey(hwnd_, kPrivatePasteHotkeyId,
                        keys.pasteModifiers | MOD_NOREPEAT, keys.pasteKey)) {
        failed(UiText(TextId::PrivatePaste), keys.pasteModifiers, keys.pasteKey);
        UnregisterHotKey(hwnd_, kPrivateCopyHotkeyId);
        return false;
    }
    privateHotkeysRegistered_ = true;
    return shortcutHotkeyRegistered_;
}

void MainWindow::ConfigureHotkeys() {
    ShowHotkeyDialog(hwnd_, g_app.cfg.settings.hotkeys,
        [this](const AppHotkeys& keys, std::wstring& error) {
            const AppHotkeys previous = g_app.cfg.settings.hotkeys;
            UnregisterHotkeys();
            if (!RegisterHotkeys(keys)) {
                UnregisterHotkeys();
                error = UiText(TextId::AShortcutIsInUseByAnother) + hotkeyRegistrationError_;
                if (!RegisterHotkeys(previous))
                    error += UiText(TextId::ThePreviousShortcutsCouldNotBeRestored);
                return false;
            }
            g_app.cfg.settings.hotkeys = keys;
            bool saved = false;
            try { saved = g_app.SaveConfig(); } catch (...) {}
            if (!saved) {
                g_app.cfg.settings.hotkeys = previous;
                UnregisterHotkeys();
                error = UiText(TextId::CouldNotSaveShortcutsThePreviousSettings);
                if (!RegisterHotkeys(previous))
                    error += UiText(TextId::ThePreviousShortcutsCouldNotBeRegistered);
                return false;
            }
            return true;
        });
    SyncMenuState();
    InvalidateRect(hwnd_, nullptr, FALSE);
}

std::wstring MainWindow::ShortcutOnlyMenuText() const {
    const auto& keys = g_app.cfg.settings.hotkeys;
    return std::wstring(UiText(TextId::AllowCopyPasteShortcutsOnly)) +
        (shortcutHotkeyRegistered_ ? L"\t" : UiText(TextId::ShortcutUnavailable)) +
        HotkeyText(keys.shortcutOnlyModifiers, keys.shortcutOnlyKey);
}

void MainWindow::CreateApplicationMenu() {
    HMENU root = CreateMenu();
    HMENU protection = CreatePopupMenu();
    HMENU logs = CreatePopupMenu();
    HMENU options = CreatePopupMenu();
    HMENU window = CreatePopupMenu();
    HMENU language = CreatePopupMenu();
    if (!root || !protection || !logs || !options || !window || !language) {
        if (root) DestroyMenu(root);
        if (protection) DestroyMenu(protection);
        if (logs) DestroyMenu(logs);
        if (options) DestroyMenu(options);
        if (window) DestroyMenu(window);
        if (language) DestroyMenu(language);
        return;
    }

    AppendMenuW(protection, MF_STRING, kCmdPause, UiText(TextId::PauseProtection2));
    AppendMenuW(protection, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(protection, MF_STRING, kCmdGlobalInjection,
                UiText(TextId::EnableProtectionG));
    AppendMenuW(protection, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(protection, MF_STRING, kCmdRules, UiText(TextId::AccessRules2));

    AppendMenuW(logs, MF_STRING, kCmdExport, UiText(TextId::ExportCSV));
    AppendMenuW(logs, MF_STRING, kCmdClear, UiText(TextId::ClearLog));

    AppendMenuW(options, MF_STRING, kCmdShortcutOnlyMode,
                ShortcutOnlyMenuText().c_str());
    AppendMenuW(options, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(options, MF_STRING, kCmdSettings, UiText(TextId::Settings2));

    AppendMenuW(options, MF_STRING, kCmdAppHotkeys, UiText(TextId::KeyboardShortcuts2));
    AppendMenuW(language, MF_STRING, IDM_LANGUAGE_CHINESE, L"中文");
    AppendMenuW(language, MF_STRING, IDM_LANGUAGE_ENGLISH, L"English");
    AppendMenuW(options, MF_POPUP, reinterpret_cast<UINT_PTR>(language), L"语言 / Language");
    AppendMenuW(options, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(options, MF_STRING, kCmdPrivateClear, UiText(TextId::ClearPrivateClipboard));

    AppendMenuW(window, MF_STRING, kCmdHide, UiText(TextId::HideToTray));
    AppendMenuW(window, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(window, MF_STRING, kCmdExit, UiText(TextId::EXit));

    AppendMenuW(root, MF_POPUP, reinterpret_cast<UINT_PTR>(protection),
                UiText(TextId::Protection));
    AppendMenuW(root, MF_POPUP, reinterpret_cast<UINT_PTR>(logs), UiText(TextId::Log));
    AppendMenuW(root, MF_POPUP, reinterpret_cast<UINT_PTR>(options),
                UiText(TextId::Options));
    AppendMenuW(root, MF_POPUP, reinterpret_cast<UINT_PTR>(window), UiText(TextId::Window));
    if (!SetMenu(hwnd_, root)) {
        DestroyMenu(root);
        return;
    }
    if (menu_) DestroyMenu(menu_);
    menu_ = root;
    SyncMenuState();
}

void MainWindow::SyncMenuState() {
    if (!menu_) return;
    HMENU protection = GetSubMenu(menu_, 0);
    if (!protection) return;

    ModifyMenuW(protection, kCmdPause, MF_BYCOMMAND | MF_STRING, kCmdPause,
                g_app.paused ? UiText(TextId::ResumeProtection) : UiText(TextId::PauseProtection2));
    CheckMenuItem(protection, kCmdPause,
                  MF_BYCOMMAND | (g_app.paused ? MF_CHECKED : MF_UNCHECKED));

    const bool targeted = IsTargetedInjectionMode();
    const bool global = IsGlobalInjectionEnabled();
    ModifyMenuW(protection, kCmdGlobalInjection,
                MF_BYCOMMAND | MF_STRING, kCmdGlobalInjection,
                protectionOperation_ == ProtectionOperation::globalInjection
                    ? UiText(TextId::ChangingProtection)
                    : global ? UiText(TextId::DisableProtectionG) : UiText(TextId::EnableProtectionG));
    CheckMenuItem(protection, kCmdGlobalInjection,
                  MF_BYCOMMAND | (global ? MF_CHECKED : MF_UNCHECKED));
    EnableMenuItem(protection, kCmdGlobalInjection,
                   MF_BYCOMMAND |
                       (targeted || protectionOperationPending_ ? MF_GRAYED
                                                                   : MF_ENABLED));
    HMENU options = GetSubMenu(menu_, 2);
    if (options) {
        HMENU language = GetSubMenu(options, 4);
        CheckMenuRadioItem(language, IDM_LANGUAGE_CHINESE, IDM_LANGUAGE_ENGLISH,
            CurrentLanguage() == Language::English ? IDM_LANGUAGE_ENGLISH : IDM_LANGUAGE_CHINESE,
            MF_BYCOMMAND);
        const UINT languageState = protectionOperationPending_ || exitRequested_ ||
            privateClipboard_.Busy() ? MF_GRAYED : MF_ENABLED;
        EnableMenuItem(language, IDM_LANGUAGE_CHINESE, MF_BYCOMMAND | languageState);
        EnableMenuItem(language, IDM_LANGUAGE_ENGLISH, MF_BYCOMMAND | languageState);
        const std::wstring shortcutLabel = ShortcutOnlyMenuText();
        ModifyMenuW(options, kCmdShortcutOnlyMode,
                    MF_BYCOMMAND | MF_STRING, kCmdShortcutOnlyMode,
                    shortcutLabel.c_str());
        CheckMenuItem(options, kCmdShortcutOnlyMode,
                      MF_BYCOMMAND |
                          (g_app.cfg.settings.shortcutOnlyMode
                               ? MF_CHECKED
                               : MF_UNCHECKED));
    }
    const UINT enabled = protectionOperationPending_ || exitRequested_
                             ? MF_GRAYED : MF_ENABLED;
    EnableMenuItem(protection, kCmdPause, MF_BYCOMMAND | enabled);
    EnableMenuItem(protection, kCmdRules, MF_BYCOMMAND | enabled);
    if (options) {
        EnableMenuItem(options, kCmdSettings, MF_BYCOMMAND | enabled);
        EnableMenuItem(options, kCmdShortcutOnlyMode, MF_BYCOMMAND | enabled);
    }
    DrawMenuBar(hwnd_);
}

void MainWindow::ChangeLanguage(Language language) {
    if (language == CurrentLanguage()) return;
    const Language previous = g_app.cfg.settings.language;
    g_app.cfg.settings.language = language;
    bool saved = false;
    try { saved = g_app.SaveConfig(); } catch (...) {}
    if (!saved) {
        g_app.cfg.settings.language = previous;
        UiMessageBox(hwnd_, UiText(TextId::LanguageSaveFailed),
                    UiText(TextId::SaveFailed), MB_OK | MB_ICONERROR);
        return;
    }
    SetLanguage(language);
    ApplyLanguage();
}

void MainWindow::ApplyLanguage() {
    SetWindowTextW(hwnd_, UiText(TextId::ClipboardProtector));
    CreateApplicationMenu();
    CreateFonts(dpi_);
    for (size_t i = 0; i < commandButtons_.size(); ++i) {
        SetWindowTextW(commandButtons_[i], UiText(kCommandButtons[i].text));
        SendMessageW(commandButtons_[i], WM_SETFONT, reinterpret_cast<WPARAM>(uiFont_), TRUE);
    }
    SendMessageW(lv_, WM_SETFONT, reinterpret_cast<WPARAM>(uiFont_), TRUE);
    SendMessageW(ListView_GetHeader(lv_), WM_SETFONT,
                 reinterpret_cast<WPARAM>(smallFont_), TRUE);
    for (int i = 0; i < _countof(kLogColumns); ++i) {
        LVCOLUMNW column{};
        column.mask = LVCF_TEXT;
        column.pszText = const_cast<wchar_t*>(UiText(kLogColumns[i].name));
        ListView_SetColumn(lv_, i, &column);
        if (CurrentLanguage() == Language::English) {
            const int width = DpiScale((std::max)(kLogColumns[i].width96,
                static_cast<int>(wcslen(column.pszText)) * 8 + 24), dpi_);
            ListView_SetColumnWidth(lv_, i, (std::max)(width, ListView_GetColumnWidth(lv_, i)));
        }
    }
    const int selected = ListView_GetNextItem(lv_, -1, LVNI_SELECTED);
    const int top = ListView_GetTopIndex(lv_);
    RebuildLogList();
    if (selected >= 0)
        ListView_SetItemState(lv_, selected, LVIS_SELECTED | LVIS_FOCUSED,
                             LVIS_SELECTED | LVIS_FOCUSED);
    if (top > 0) {
        RECT item{};
        if (ListView_GetItemRect(lv_, 0, &item, LVIR_BOUNDS))
            ListView_Scroll(lv_, 0, top * (item.bottom - item.top));
    }
    if (g_app.tray) g_app.tray->SetPaused(g_app.paused);
    for (auto& item : confirmations_) item.second->ApplyLanguage();
    SyncProtectionState();
    Layout();
    RedrawWindow(hwnd_, nullptr, nullptr, RDW_INVALIDATE | RDW_ALLCHILDREN);
}

void MainWindow::Layout() {
    if (!hwnd_) return;
    RECT rc{};
    GetClientRect(hwnd_, &rc);
    const int margin = DpiScale(24, dpi_);
    const int gap = DpiScale(12, dpi_);
    const int buttonGap = DpiScale(8, dpi_);
    const int buttonHeight = DpiScale(38, dpi_);
    int buttonsWidth = 0;
    for (const auto& button : kCommandButtons)
        buttonsWidth += DpiScale(ButtonWidth(button), dpi_);
    buttonsWidth += buttonGap * (static_cast<int>(commandButtons_.size()) - 1);
    int buttonX = rc.right - margin - buttonsWidth;
    const bool english = CurrentLanguage() == Language::English;
    const int buttonY = DpiScale(english ? 84 : 28, dpi_);
    for (size_t i = 0; i < commandButtons_.size(); ++i) {
        const int width = DpiScale(ButtonWidth(kCommandButtons[i]), dpi_);
        MoveWindow(commandButtons_[i], buttonX, buttonY, width, buttonHeight,
                   TRUE);
        buttonX += width + buttonGap;
    }

    const int cardsTop = DpiScale(english ? 148 : 102, dpi_);
    const int cardsHeight = DpiScale(86, dpi_);
    const int cardsWidth = static_cast<int>(
        std::max<LONG>(1, rc.right - margin * 2 - gap * 3));
    const int cardWidth = cardsWidth / 4;
    int cardLeft = margin;
    for (size_t i = 0; i < cardRects_.size(); ++i) {
        const int right = i + 1 == cardRects_.size()
                              ? rc.right - margin
                              : cardLeft + cardWidth;
        cardRects_[i] = {cardLeft, cardsTop, right, cardsTop + cardsHeight};
        cardLeft = right + gap;
    }

    const int footerHeight = DpiScale(42, dpi_);
    footerRect_ = {margin, rc.bottom - footerHeight, rc.right - margin,
                   rc.bottom};
    logPanelRect_ = {margin, DpiScale(english ? 256 : 210, dpi_), rc.right - margin,
                     footerRect_.top - DpiScale(10, dpi_)};
    const int panelInset = DpiScale(10, dpi_);
    const int listTop = logPanelRect_.top + DpiScale(48, dpi_);
    MoveWindow(lv_, logPanelRect_.left + panelInset, listTop,
               static_cast<int>(std::max<LONG>(
                   1, logPanelRect_.right - logPanelRect_.left -
                          panelInset * 2)),
               static_cast<int>(std::max<LONG>(
                   1, logPanelRect_.bottom - listTop - panelInset)), TRUE);
    InvalidateRect(hwnd_, nullptr, FALSE);
}

void MainWindow::Paint() {
    PAINTSTRUCT paint{};
    HDC dc = BeginPaint(hwnd_, &paint);
    RECT client{};
    GetClientRect(hwnd_, &client);
    HDC bufferDc = CreateCompatibleDC(dc);
    HBITMAP bufferBitmap = CreateCompatibleBitmap(
        dc, std::max(1L, client.right), std::max(1L, client.bottom));
    if (bufferDc && bufferBitmap) {
        HGDIOBJ oldBitmap = SelectObject(bufferDc, bufferBitmap);
        PaintBackground(bufferDc, client);
        BitBlt(dc, 0, 0, client.right, client.bottom, bufferDc, 0, 0, SRCCOPY);
        SelectObject(bufferDc, oldBitmap);
    } else {
        PaintBackground(dc, client);
    }
    if (bufferBitmap) DeleteObject(bufferBitmap);
    if (bufferDc) DeleteDC(bufferDc);
    EndPaint(hwnd_, &paint);
}

void MainWindow::PaintBackground(HDC dc, const RECT& client) {
    TRIVERTEX vertices[2] = {
        {client.left, client.top, 0xF100, 0xF800, 0xF600, 0x0000},
        {client.right, client.bottom, 0xF700, 0xF800, 0xF800, 0x0000},
    };
    GRADIENT_RECT gradient = {0, 1};
    GradientFill(dc, vertices, 2, &gradient, 1, GRADIENT_FILL_RECT_V);

    const int margin = DpiScale(24, dpi_);
    const int iconSize = DpiScale(46, dpi_);
    HICON icon = reinterpret_cast<HICON>(LoadImageW(
        g_app.hInst, MAKEINTRESOURCEW(IDI_APP_ICON), IMAGE_ICON, iconSize,
        iconSize, LR_SHARED));
    if (icon)
        DrawIconEx(dc, margin, DpiScale(22, dpi_), icon, iconSize, iconSize, 0,
                   nullptr, DI_NORMAL);

    int buttonsWidth = DpiScale(32, dpi_);
    for (const auto& button : kCommandButtons)
        buttonsWidth += DpiScale(ButtonWidth(button), dpi_);
    RECT titleRect = {margin + DpiScale(60, dpi_), DpiScale(18, dpi_),
                      client.right - margin - buttonsWidth - DpiScale(16, dpi_),
                      DpiScale(51, dpi_)};
    if (CurrentLanguage() == Language::English) titleRect.right = client.right - margin;
    DrawTextLine(dc, UiText(TextId::ClipboardProtector), titleRect, titleFont_, RGB(24, 48, 46),
                 DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
    RECT subtitleRect = titleRect;
    subtitleRect.top = DpiScale(51, dpi_);
    subtitleRect.bottom = DpiScale(76, dpi_);
    DrawTextLine(dc, UiText(TextId::ReviewClipboardAccessAndDecideBeforeSensitive),
                 subtitleRect, smallFont_, RGB(83, 105, 101),
                 DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);

    const std::wstring values[] = {
        protectionValue_, std::to_wstring(g_app.injectedClients),
        std::to_wstring(g_app.todayRecorded),
        std::to_wstring(g_app.todayBlocked),
    };
    const wchar_t* labels[] = {
        UiText(TextId::Protection2), UiText(TextId::ConnectedProcesses), UiText(TextId::RecordedToday), UiText(TextId::Blocked2),
    };
    const wchar_t* blockedDetail =
        blockedOnly_ ? UiText(TextId::FilteredClickToShowAll) : UiText(TextId::TodayClickToFilter);
    const wchar_t* details[] = {
        protectionDetail_.c_str(), UiText(TextId::ActiveMonitoringConnections), UiText(TextId::RecordedThisSession),
        blockedDetail,
    };
    COLORREF statusColor = RGB(15, 118, 110);
    if (g_app.paused)
        statusColor = RGB(180, 103, 5);
    else if (IsTargetedInjectionMode())
        statusColor = RGB(37, 99, 190);
    else if (!IsGlobalInjectionEnabled())
        statusColor = RGB(51, 65, 85);

    for (size_t i = 0; i < cardRects_.size(); ++i) {
        RECT shadow = cardRects_[i];
        OffsetRect(&shadow, 0, DpiScale(2, dpi_));
        FillRoundRect(dc, shadow, DpiScale(14, dpi_), RGB(224, 231, 229),
                      RGB(224, 231, 229));
        const bool primary = i == 0;
        const bool blockedFilterCard = i == 3;
        const bool highlighted =
            primary || (blockedFilterCard && blockedOnly_);
        const COLORREF accent =
            primary ? statusColor : RGB(185, 45, 45);
        const COLORREF fill =
            highlighted ? accent : RGB(255, 255, 255);
        const COLORREF border =
            highlighted ? accent
                        : blockedFilterCard ? RGB(235, 195, 195)
                                            : RGB(220, 229, 226);
        FillRoundRect(dc, cardRects_[i], DpiScale(14, dpi_), fill, border);

        const int inset = DpiScale(16, dpi_);
        RECT labelRect = cardRects_[i];
        labelRect.left += inset;
        labelRect.top += DpiScale(9, dpi_);
        labelRect.bottom = labelRect.top + DpiScale(20, dpi_);
        DrawTextLine(dc, labels[i], labelRect, smallFont_,
                     primary ? RGB(220, 245, 241)
                             : highlighted ? RGB(255, 235, 235)
                                           : RGB(91, 110, 106),
                     DT_LEFT | DT_VCENTER | DT_SINGLELINE);
        RECT valueRect = labelRect;
        valueRect.top = labelRect.bottom - DpiScale(2, dpi_);
        valueRect.bottom = valueRect.top + DpiScale(34, dpi_);
        DrawTextLine(dc, values[i], valueRect,
                     i == 0 && CurrentLanguage() == Language::English ? sectionFont_ : metricFont_,
                     highlighted ? RGB(255, 255, 255) : RGB(29, 52, 49),
                     DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
        RECT detailRect = valueRect;
        detailRect.top = valueRect.bottom - DpiScale(3, dpi_);
        detailRect.bottom = cardRects_[i].bottom - DpiScale(7, dpi_);
        DrawTextLine(dc, details[i], detailRect, smallFont_,
                     primary ? RGB(220, 245, 241)
                             : highlighted ? RGB(255, 225, 225)
                                           : RGB(120, 136, 132),
                     DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
    }

    RECT panelShadow = logPanelRect_;
    OffsetRect(&panelShadow, 0, DpiScale(2, dpi_));
    FillRoundRect(dc, panelShadow, DpiScale(14, dpi_), RGB(225, 232, 230),
                  RGB(225, 232, 230));
    FillRoundRect(dc, logPanelRect_, DpiScale(14, dpi_), RGB(255, 255, 255),
                  RGB(220, 229, 226));
    RECT sectionRect = logPanelRect_;
    sectionRect.left += DpiScale(16, dpi_);
    sectionRect.top += DpiScale(7, dpi_);
    sectionRect.right -= DpiScale(130, dpi_);
    sectionRect.bottom = sectionRect.top + DpiScale(25, dpi_);
    DrawTextLine(dc, UiText(TextId::ClipboardAccessLog), sectionRect, sectionFont_,
                 RGB(29, 52, 49), DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    RECT hintRect = sectionRect;
    hintRect.top += DpiScale(21, dpi_);
    hintRect.bottom += DpiScale(21, dpi_);
    DrawTextLine(dc, UiText(TextId::ReadsWritesSourcesAndRuleDecisions), hintRect,
                 smallFont_, RGB(119, 135, 131),
                 DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
    RECT countRect = logPanelRect_;
    countRect.left = countRect.right - DpiScale(125, dpi_);
    countRect.right -= DpiScale(16, dpi_);
    countRect.top += DpiScale(12, dpi_);
    countRect.bottom = countRect.top + DpiScale(22, dpi_);
    DrawTextLine(dc,
                 std::to_wstring(ListView_GetItemCount(lv_)) + UiText(TextId::Records),
                 countRect, smallFont_, RGB(91, 110, 106),
                 DT_RIGHT | DT_VCENTER | DT_SINGLELINE);

    HBRUSH dotBrush = CreateSolidBrush(
        g_app.paused ? RGB(217, 119, 6) : RGB(13, 148, 136));
    HGDIOBJ oldBrush = SelectObject(dc, dotBrush);
    HGDIOBJ oldPen = SelectObject(dc, GetStockObject(NULL_PEN));
    const int dot = DpiScale(7, dpi_);
    const int dotY = footerRect_.top + DpiScale(17, dpi_);
    Ellipse(dc, footerRect_.left, dotY, footerRect_.left + dot,
            dotY + dot);
    SelectObject(dc, oldPen);
    SelectObject(dc, oldBrush);
    DeleteObject(dotBrush);
    RECT footerText = footerRect_;
    footerText.left += DpiScale(16, dpi_);
    footerText.right -= DpiScale(265, dpi_);
    DrawTextLine(dc,
                 UiFormat(TextId::MainFooter, {HotkeyText(g_app.cfg.settings.hotkeys.shortcutOnlyModifiers, g_app.cfg.settings.hotkeys.shortcutOnlyKey)}),
                 footerText, smallFont_, RGB(89, 107, 103),
                 DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
    RECT shortcutText = footerRect_;
    shortcutText.left = shortcutText.right - DpiScale(260, dpi_);
    std::wstring protectionModes;
    if (g_app.cfg.settings.shortcutOnlyMode)
        protectionModes = UiText(TextId::ShortcutOnly);
    if (g_app.cfg.settings.cryptoProtection) {
        if (!protectionModes.empty()) protectionModes += L" + ";
        protectionModes += L"Crypto";
    }
    DrawTextLine(dc,
                 protectionModes.empty() ? UiText(TextId::ExtraProtectionOff)
                                         : protectionModes + UiText(TextId::On),
                 shortcutText, smallFont_,
                 protectionModes.empty() ? RGB(119, 135, 131)
                                         : RGB(13, 121, 111),
                 DT_RIGHT | DT_VCENTER | DT_SINGLELINE);
}

void MainWindow::DrawCommandButton(const DRAWITEMSTRUCT& draw) const {
    RECT rect = draw.rcItem;
    HBRUSH background = CreateSolidBrush(RGB(243, 248, 247));
    FillRect(draw.hDC, &rect, background);
    DeleteObject(background);
    InflateRect(&rect, -1, -1);
    const bool primary = draw.CtlID == kCmdPause;
    const bool pressed = (draw.itemState & ODS_SELECTED) != 0;
    const bool disabled = (draw.itemState & ODS_DISABLED) != 0;
    COLORREF fill = primary ? RGB(15, 118, 110) : RGB(255, 255, 255);
    COLORREF border = primary ? RGB(15, 118, 110) : RGB(205, 220, 216);
    COLORREF textColor = primary ? RGB(255, 255, 255) : RGB(38, 65, 61);
    if (pressed) {
        fill = primary ? RGB(12, 94, 88) : RGB(231, 239, 237);
        border = primary ? fill : RGB(180, 204, 198);
    }
    if (disabled) {
        fill = RGB(235, 239, 238);
        border = RGB(220, 225, 224);
        textColor = RGB(148, 159, 156);
    }
    FillRoundRect(draw.hDC, rect, DpiScale(9, dpi_), fill, border);
    wchar_t text[64] = {};
    GetWindowTextW(draw.hwndItem, text, _countof(text));
    if (pressed) OffsetRect(&rect, 0, DpiScale(1, dpi_));
    DrawTextLine(draw.hDC, text, rect, uiFont_, textColor,
                 DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
    if (draw.itemState & ODS_FOCUS) {
        InflateRect(&rect, -DpiScale(5, dpi_), -DpiScale(5, dpi_));
        DrawFocusRect(draw.hDC, &rect);
    }
}

void MainWindow::SaveWindowSize() {
    WINDOWPLACEMENT placement{sizeof(placement)};
    if (!GetWindowPlacement(hwnd_, &placement)) return;
    const int pixelWidth = placement.rcNormalPosition.right -
                           placement.rcNormalPosition.left;
    const int pixelHeight = placement.rcNormalPosition.bottom -
                            placement.rcNormalPosition.top;
    const UINT dpi = GetDpiForWindow(hwnd_);
    const int width = MulDiv(pixelWidth, 96, static_cast<int>(dpi ? dpi : 96));
    const int height = MulDiv(pixelHeight, 96, static_cast<int>(dpi ? dpi : 96));
    if (width < 860 || width > 8192 || height < 600 || height > 8192)
        return;
    if (g_app.cfg.settings.windowWidth == width &&
        g_app.cfg.settings.windowHeight == height)
        return;
    g_app.cfg.settings.windowWidth = width;
    g_app.cfg.settings.windowHeight = height;
    g_app.SaveConfig();
}

void MainWindow::SyncPauseButton() {
    if (commandButtons_[0])
        SetWindowTextW(commandButtons_[0],
                       g_app.paused ? UiText(TextId::ResumeProtection2) : UiText(TextId::PauseProtection));
    if (commandButtons_[0]) InvalidateRect(commandButtons_[0], nullptr, TRUE);
}

void MainWindow::SyncProtectionState() {
    SyncPauseButton();
    SyncMenuState();
    for (size_t i = 0; i < commandButtons_.size(); ++i) {
        const int command = kCommandButtons[i].id;
        if (command == kCmdPause || command == kCmdRules || command == kCmdSettings)
            EnableWindow(commandButtons_[i], !protectionOperationPending_ &&
                                             !exitRequested_);
    }
    UpdateStatusBar();
}

void MainWindow::ShowPendingConfirmations() {
    if (!g_app.server) return;
    DWORD cancelled = 0;
    while (g_app.server->PopCancelledConfirmation(cancelled))
        confirmations_.erase(cancelled);

    AccessConfirmationRequest request;
    while (g_app.server->PopConfirmation(request)) {
        if (confirmations_.find(request.id) != confirmations_.end()) {
            g_app.server->ResolveConfirmation(request.id,
                                              !request.timeoutBlock);
            continue;
        }
        const DWORD requestId = request.id;
        const bool fallbackAllow = !request.timeoutBlock;
        auto window = AccessConfirmationWindow::Create(
            g_app.hInst, hwnd_, std::move(request), confirmations_.size());
        if (!window) {
            g_app.server->ResolveConfirmation(requestId, fallbackAllow);
            continue;
        }
        confirmations_.emplace(requestId, std::move(window));
    }
}

bool MainWindow::AddAlwaysDecisionRule(const AlwaysDecision& decision) {
    // “PID 1234”占位名没有可匹配的进程名，无法生成规则；由调用方提示用户。
    if (decision.process.empty() || decision.process.rfind(L"PID ", 0) == 0)
        return false;
    try {
        if (protectionOperationPending_) {
            deferredAlwaysDecisions_.push_back(decision);
            return true;
        }
        std::vector<Rule> updatedRules = g_app.cfg.rules;
        std::vector<AlwaysDecision> pending = pendingAlwaysDecisions_;
        if (rulesDialogOpen_) pending.push_back(decision);
        const bool changed = UpsertAlwaysDecisionRule(updatedRules, decision);
        if (!changed) {
            pendingAlwaysDecisions_.swap(pending);
            return true;
        }
        if (!IsRuleSetSupported(updatedRules)) return false;

        g_app.cfg.rules.swap(updatedRules);
        bool saved = false;
        try {
            saved = g_app.SaveConfig();
        } catch (...) {
            saved = false;   // SaveConfig 内部会分配内存，可能抛异常
        }
        if (!saved) {
            g_app.cfg.rules.swap(updatedRules);   // 回滚，避免内存与磁盘不一致
            return false;
        }
        pendingAlwaysDecisions_.swap(pending);
        if (g_app.server) g_app.server->BroadcastRules(g_app.cfg.rules);
        return true;
    } catch (...) {
        return false;
    }
}

void MainWindow::CompleteConfirmation(DWORD requestId, bool allow,
                                      bool persistDecision) {
    const auto found = confirmations_.find(requestId);
    if (found == confirmations_.end()) return;
    const AccessConfirmationRequest& request = found->second->request();
    if (persistDecision) {
        AlwaysDecision decision;
        decision.process = request.process;
        decision.processId = request.processId;
        decision.sourceProcess = request.sourceProcess;
        decision.sourceProcessId = request.sourceProcessId;
        decision.action = allow ? kRuleAllow : kRuleBlock;
        if (!AddAlwaysDecisionRule(decision) && g_app.tray) {
            g_app.tray->ShowBalloon(
                UiText(TextId::CouldNotSaveTheRememberedChoice),
                UiFormat(TextId::RememberRuleFailedDetail,
                    {UiText(allow ? TextId::Allow : TextId::Block), request.process})
                    .c_str(),
                false);
        }
    }
    if (g_app.server)
        g_app.server->ResolveConfirmation(requestId, allow);
    confirmations_.erase(found);
}

void MainWindow::OnEvent(LogRow row) {
    if (row.gap) {
        row.id = nextId_++;
        InsertRow(std::move(row));
        UpdateStatusBar();
        return;
    }
    if (row.missingEvents != 0) {
        LogRow gap;
        gap.id = nextId_++;
        gap.pid = row.pid;
        gap.time = row.time;
        gap.process = row.process;
        gap.path = row.path;
        gap.gap = true;
        gap.missingEvents = row.missingEvents;
        InsertRow(std::move(gap));
        row.missingEvents = 0;
    }
    // 跨日重置统计
    SYSTEMTIME st;
    GetLocalTime(&st);
    WORD day = (WORD)(st.wMonth * 100 + st.wDay);
    if (day != g_app.todayDay) {
        g_app.todayDay = day;
        g_app.todayRecorded = 0;
        g_app.todayBlocked = 0;
    }
    ++g_app.todayRecorded;
    if (row.blocked) ++g_app.todayBlocked;

    // Every clipboard API event is an audit record and gets its own row.
    row.id = nextId_++;
    const unsigned long long rowId = row.id;
    const bool shouldNotify =
        row.showNotification &&
        !g_app.cfg.settings.balloonNotificationsDisabled;
    LogRow notificationRow;
    bool notificationReady = false;
    if (shouldNotify) {
        try {
            notificationRow.id = row.id;
            notificationRow.pid = row.pid;
            notificationRow.time = row.time;
            notificationRow.process = row.process;
            notificationRow.op = row.op;
            notificationRow.blocked = row.blocked;
            notificationRow.sourcePid = row.sourcePid;
            notificationRow.sourceProcess = row.sourceProcess;
            notificationRow.ruleName = row.ruleName;
            notificationRow.builtinRule = row.builtinRule;
            notificationRow.previewKind = row.previewKind;
            notificationRow.preview = row.previewKind == PreviewKind::Text
                ? LogContentSummary(row) : row.preview;
            notificationReady = true;
        } catch (...) {
        }
    }
    InsertRow(std::move(row));
    if (notificationReady && g_app.tray) {
        try {
            FlushDueNotifications();
            const ULONGLONG now = GetTickCount64();
            NotifyState& state = notify_[notificationRow.pid];
            if (state.lastTick != 0 && now - state.lastTick < 1000) {
                ++state.suppressed;
                state.lastRowId = rowId;
                state.lastRow = notificationRow;
            } else {
                const std::wstring message = NotificationText(notificationRow, 1);
                g_app.tray->ShowBalloon(
                    NotificationTitle(notificationRow).c_str(),
                    message.c_str(), notificationRow.blocked);
                lastNotifiedRowId_ = rowId;
                state.lastTick = now;
                state.suppressed = 0;
                state.lastRowId = rowId;
                state.lastRow = notificationRow;
            }
        } catch (...) {
        }
    }
    UpdateStatusBar();
}

void MainWindow::FlushDueNotifications() {
    if (!g_app.tray) return;
    const ULONGLONG now = GetTickCount64();
    for (auto it = notify_.begin(); it != notify_.end();) {
        NotifyState& state = it->second;
        if (state.suppressed > 0 && state.lastTick != 0 &&
            now - state.lastTick >= 1000) {
            std::wstring message =
                NotificationText(state.lastRow, state.suppressed + 1);
            g_app.tray->ShowBalloon(
                NotificationTitle(state.lastRow).c_str(), message.c_str(),
                state.lastRow.blocked);
            lastNotifiedRowId_ = state.lastRowId;
            state.suppressed = 0;
            state.lastTick = now;
        }

        // Do not retain one entry for every PID ever observed. Pending bursts
        // are kept until flushed; quiet entries expire after one minute.
        if (state.suppressed == 0 && state.lastTick != 0 &&
            now - state.lastTick > 60000) {
            it = notify_.erase(it);
        } else {
            ++it;
        }
    }
}

void MainWindow::FocusNotifiedRow() {
    if (lastNotifiedRowId_ == 0) return;
    const int count = ListView_GetItemCount(lv_);
    for (int i = 0; i < count; ++i) {
        const LogRow* row = ListRow(i);
        if (!row || row->id != lastNotifiedRowId_) continue;
        ListView_SetItemState(lv_, i, LVIS_SELECTED | LVIS_FOCUSED,
                              LVIS_SELECTED | LVIS_FOCUSED);
        ListView_EnsureVisible(lv_, i, FALSE);
        ShowWindow(hwnd_, SW_RESTORE);
        SetForegroundWindow(hwnd_);
        return;
    }
    ShowWindow(hwnd_, SW_RESTORE);
    SetForegroundWindow(hwnd_);
}

void MainWindow::InsertRow(LogRow row) {
    const size_t snapshotBytes = row.snapshot.size();
    rows_.push_front(std::move(row));
    snapshotBytes_ += snapshotBytes;
    const LogRow& stored = rows_.front();
    if (!ShouldShowListRow(stored)) {
        TrimToLimit();
        TrimSnapshotMemory();
        return;
    }
    InsertListRow(stored, 0);
    TrimToLimit();
    TrimSnapshotMemory();
    ListView_EnsureVisible(lv_, 0, FALSE);
}

void MainWindow::InsertListRow(const LogRow& stored, int index) {
    LVITEMW it = {};
    it.mask = LVIF_PARAM;
    it.iItem = index;
    it.lParam = reinterpret_cast<LPARAM>(&stored);
    ListView_InsertItem(lv_, &it);

    const std::wstring texts[14] = {
        FormatTime(stored.time), stored.process,
        stored.pid ? std::to_wstring(stored.pid) : L"",
        stored.gap ? L"" : stored.sourceProcess.empty() ? UiText(TextId::Unknown)
                                                        : stored.sourceProcess,
        stored.sourcePid ? std::to_wstring(stored.sourcePid) : L"",
        stored.gap ? UiText(TextId::MissingEvents) : OpName(stored.op),
        stored.gap ? L"" : FormatName(stored.fmt), DisplayRuleName(stored.ruleName, stored.builtinRule),
        stored.gap ? L"" : DecisionName(stored.action),
        stored.gap ? L"" : NotificationName(stored.showNotification),
        LogContentSummary(stored),
        stored.gap ? UiText(TextId::MissingEvents2)
                : stored.cryptoContent
                      ? stored.blocked ? UiText(TextId::CryptoBlocked)
                                    : UiText(TextId::CryptoAllowed)
                      : stored.blocked ? UiText(TextId::Blocked3) : UiText(TextId::Allowed2),
        stored.missingEvents ? std::to_wstring(stored.missingEvents) : L"",
        stored.gap ? L"" : std::to_wstring(stored.count),
    };
    LVITEMW sub = {};
    sub.mask = LVIF_TEXT;
    sub.iItem = index;
    for (int col = 0; col < 14; ++col) {
        sub.iSubItem = col;
        sub.pszText = (LPWSTR)texts[col].c_str();
        ListView_SetItem(lv_, &sub);
    }
}

bool MainWindow::ShouldShowListRow(const LogRow& row) const {
    return !row.hideFromLogList && (!blockedOnly_ || row.blocked);
}

void MainWindow::RebuildLogList() {
    SendMessageW(lv_, WM_SETREDRAW, FALSE, 0);
    ListView_DeleteAllItems(lv_);
    int index = 0;
    for (const LogRow& row : rows_) {
        if (!ShouldShowListRow(row)) continue;
        InsertListRow(row, index++);
    }
    SendMessageW(lv_, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(lv_, nullptr, TRUE);
    InvalidateRect(hwnd_, &logPanelRect_, FALSE);
}

void MainWindow::ToggleBlockedFilter() {
    blockedOnly_ = !blockedOnly_;
    RebuildLogList();
    InvalidateRect(hwnd_, &cardRects_[3], FALSE);
}

const LogRow* MainWindow::ListRow(int index) const {
    if (index < 0) return nullptr;
    LVITEMW item = {};
    item.mask = LVIF_PARAM;
    item.iItem = index;
    if (!ListView_GetItem(lv_, &item)) return nullptr;
    return reinterpret_cast<const LogRow*>(item.lParam);
}

int MainWindow::ListIndexForRow(const LogRow* row) const {
    if (!row) return -1;
    const int count = ListView_GetItemCount(lv_);
    for (int i = 0; i < count; ++i) {
        if (ListRow(i) == row) return i;
    }
    return -1;
}

void MainWindow::TrimToLimit() {
    int limit = g_app.cfg.settings.maxLogEntries;
    while ((int)rows_.size() > limit) {
        const LogRow* removed = &rows_.back();
        const int listIndex = ListIndexForRow(removed);
        snapshotBytes_ -=
            (std::min)(snapshotBytes_, rows_.back().snapshot.size());
        rows_.pop_back();
        if (listIndex >= 0) ListView_DeleteItem(lv_, listIndex);
    }
}

void MainWindow::TrimSnapshotMemory() {
    static constexpr size_t kSnapshotMemoryLimit = 32u << 20;
    while (snapshotBytes_ > kSnapshotMemoryLimit) {
        bool released = false;
        for (size_t i = rows_.size(); i-- > 0;) {
            LogRow& row = rows_[i];
            if (row.snapshot.empty()) continue;
            snapshotBytes_ -=
                (std::min)(snapshotBytes_, row.snapshot.size());
            std::vector<BYTE>().swap(row.snapshot);
            row.snapshotKind = kSnapshotDiscarded;
            const std::wstring summary = LogContentSummary(row);
            const int listIndex = ListIndexForRow(&row);
            if (listIndex >= 0)
                ListView_SetItemText(lv_, listIndex, 10,
                                     const_cast<LPWSTR>(summary.c_str()));
            released = true;
            break;
        }
        if (!released) {
            snapshotBytes_ = 0;
            break;
        }
    }
}

void MainWindow::ClearLog() {
    ListView_DeleteAllItems(lv_);
    rows_.clear();
    snapshotBytes_ = 0;
    notify_.clear();
    InvalidateRect(hwnd_, &logPanelRect_, FALSE);
}

void MainWindow::SetInjectedCount(size_t n) {
    g_app.injectedClients = n;
    UpdateStatusBar();
}

void MainWindow::UpdateStatusBar() {
    if (exitRequested_ || protectionOperationPending_) {
        protectionValue_ = exitRequested_ ? UiText(TextId::Exiting) : UiText(TextId::Changing);
        protectionDetail_ = exitRequested_ ? UiText(TextId::ReleasingProtectionResourcesPleaseWait)
                                          : UiText(TextId::UpdatingProtectionCoveragePleaseWait);
        InvalidateRect(hwnd_, nullptr, FALSE);
        return;
    }
    if (g_app.paused) {
        protectionValue_ = UiText(TextId::Paused);
        protectionDetail_ = UiText(TextId::ClipboardRulesAreTemporarilyInactive);
    } else if (IsTargetedInjectionMode()) {
        const DWORD processId = TargetedInjectionPid();
        protectionValue_ = UiText(TextId::SingleProcess);
        protectionDetail_ = processId != 0
                                ? UiText(TextId::TargetPID) + std::to_wstring(processId)
                                : UiText(TextId::InvalidTargetSettings);
    } else if (IsGlobalInjectionEnabled()) {
        protectionValue_ = UiText(TextId::GlobalProtection);
        protectionDetail_ = UiText(TextId::MonitoringInjectedProcesses);
    } else {
        protectionValue_ = UiText(TextId::Ready);
        protectionDetail_ = UiText(TextId::SelectProtectionCoverageToBegin);
    }
    if (g_app.cfg.settings.shortcutOnlyMode) {
        protectionDetail_ += IsGlobalInjectionEnabled()
                                 ? UiText(TextId::ShortcutOnly2)
                                 : IsTargetedInjectionMode()
                                       ? UiText(TextId::ShortcutOnlyForTarget)
                                       : UiText(TextId::ShortcutOnlyAwaitingInjection);
    }
    if (!g_app.paused && g_app.cfg.settings.cryptoProtection) {
        protectionDetail_ += IsGlobalInjectionEnabled()
                                 ? UiText(TextId::CryptoAddressProtection)
                                 : IsTargetedInjectionMode()
                                       ? UiText(TextId::CryptoForTargetOnly)
                                       : UiText(TextId::CryptoAwaitingInjection);
    }

    InvalidateRect(hwnd_, nullptr, FALSE);
}

namespace {

constexpr size_t kCsvBufferBytes = 64 * 1024;
constexpr size_t kCsvWideChunk = 256;

class CsvWriter {
public:
    explicit CsvWriter(HANDLE file) : file_(file) {
        buffer_.reserve(kCsvBufferBytes);
    }

    bool Append(const char* data, size_t size) {
        if (!data && size != 0) return false;
        while (size != 0) {
            if (buffer_.size() == kCsvBufferBytes && !Flush()) return false;
            const size_t room = kCsvBufferBytes - buffer_.size();
            const size_t chunk = (std::min)(size, room);
            buffer_.append(data, chunk);
            data += chunk;
            size -= chunk;
        }
        return true;
    }

    bool AppendByte(char value) { return Append(&value, 1); }

    bool AppendWide(const wchar_t* data, size_t size) {
        while (size != 0) {
            size_t chunk = (std::min)(size, kCsvWideChunk);
            // Keep UTF-16 surrogate pairs together when a conversion chunk is
            // split; this also avoids manufacturing replacement characters.
            if (chunk < size && chunk > 0 &&
                data[chunk - 1] >= 0xD800 && data[chunk - 1] <= 0xDBFF &&
                data[chunk] >= 0xDC00 && data[chunk] <= 0xDFFF)
                --chunk;
            if (chunk == 0) chunk = 1;

            char utf8[kCsvWideChunk * 4] = {};
            const int bytes = WideCharToMultiByte(
                CP_UTF8, WC_ERR_INVALID_CHARS, data, static_cast<int>(chunk), utf8,
                static_cast<int>(sizeof(utf8)), nullptr, nullptr);
            if (bytes <= 0 || !Append(utf8, static_cast<size_t>(bytes)))
                return false;
            data += chunk;
            size -= chunk;
        }
        return true;
    }

    bool Finish() { return Flush(); }

private:
    bool Flush() {
        size_t offset = 0;
        while (offset < buffer_.size()) {
            const DWORD chunk = static_cast<DWORD>(
                (std::min)(buffer_.size() - offset, static_cast<size_t>(MAXDWORD)));
            DWORD written = 0;
            if (!WriteFile(file_, buffer_.data() + offset, chunk, &written,
                           nullptr) ||
                written == 0 || written > chunk) {
                return false;
            }
            offset += written;
        }
        buffer_.clear();
        return true;
    }

    HANDLE file_ = INVALID_HANDLE_VALUE;
    std::string buffer_;
};

bool WriteCsvField(CsvWriter& writer, const std::wstring& value) {
    if (!writer.AppendByte('"')) return false;
    const size_t first = value.find_first_not_of(L" \t\r\n");
    if (first != std::wstring::npos &&
        (value[first] == L'=' || value[first] == L'+' || value[first] == L'-' ||
         value[first] == L'@')) {
        // Excel treats these leading characters as formulas even inside CSV
        // fields. Keep the existing apostrophe mitigation inside the quote.
        if (!writer.AppendByte('\'')) return false;
    }

    size_t start = 0;
    while (start < value.size()) {
        const size_t quote = value.find(L'"', start);
        const size_t end = quote == std::wstring::npos ? value.size() : quote;
        if (!writer.AppendWide(value.data() + start, end - start)) return false;
        if (quote == std::wstring::npos) break;
        if (!writer.Append("\"\"", 2)) return false;
        start = quote + 1;
    }
    return writer.AppendByte('"');
}

bool WriteCsvSeparator(CsvWriter& writer) {
    return writer.Append(",", 1);
}

} // namespace

void MainWindow::ExportCsv() {
    wchar_t file[MAX_PATH] = L"clipboard_log.csv";
    OPENFILENAMEW ofn = {sizeof(ofn)};
    ofn.hwndOwner = hwnd_;
    ofn.lpstrFilter = UiText(TextId::CSVFilesCsvCsvAllFiles);
    ofn.lpstrFile = file;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrDefExt = L"csv";
    ofn.Flags = OFN_OVERWRITEPROMPT;
    if (!GetSaveFileNameW(&ofn)) return;

    HANDLE h = CreateFileW(file, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        UiMessageBox(hwnd_, UiText(TextId::CouldNotCreateTheFile), UiText(TextId::ExportFailed), MB_ICONERROR);
        return;
    }
    bool ok = false;
    try {
        CsvWriter writer(h);
        ok = writer.Append("\xEF\xBB\xBF", 3);
        const wchar_t* header[] = {
            UiText(TextId::Time), UiText(TextId::Process), UiText(TextId::ProcessPath), UiText(TextId::ProcessPID), UiText(TextId::SourceProcess),
            UiText(TextId::SourcePath), UiText(TextId::SourcePID), UiText(TextId::ClipboardSequence), UiText(TextId::Operation), UiText(TextId::Format2),
            UiText(TextId::MatchedRule), UiText(TextId::Decision), UiText(TextId::Notification), UiText(TextId::ListVisibility), UiText(TextId::Preview),
            UiText(TextId::Status), UiText(TextId::MissingEventCount), UiText(TextId::Count),
        };
        for (size_t i = 0; ok && i < _countof(header); ++i) {
            ok = WriteCsvField(writer, header[i]);
            if (ok && i + 1 != _countof(header)) ok = WriteCsvSeparator(writer);
        }
        if (ok) ok = writer.Append("\r\n", 2);
        for (const auto& r : rows_) {
            if (!ok) break;
            const std::wstring pid = r.pid ? std::to_wstring(r.pid) : L"";
            const std::wstring sourcePid =
                r.sourcePid ? std::to_wstring(r.sourcePid) : L"";
            const std::wstring sequence =
                r.clipboardSequence
                    ? std::to_wstring(r.clipboardSequence)
                    : L"";
            const std::wstring count = std::to_wstring(r.count);
            const std::wstring missing =
                r.missingEvents ? std::to_wstring(r.missingEvents) : L"";
            const std::wstring fields[18] = {
                FormatTime(r.time), r.process, r.path, pid,
                r.sourceProcess, r.sourcePath, sourcePid, sequence,
                r.gap ? UiText(TextId::MissingEvents) : OpName(r.op),
                r.gap ? L"" : FormatName(r.fmt), DisplayRuleName(r.ruleName, r.builtinRule),
                r.gap ? L"" : DecisionName(r.action),
                r.gap ? L"" : NotificationName(r.showNotification),
                r.gap ? L"" : r.hideFromLogList ? UiText(TextId::Hidden) : UiText(TextId::Visible),
                LogContentSummary(r),
                r.gap ? UiText(TextId::MonitoringGap) : r.blocked ? UiText(TextId::Blocked3) : UiText(TextId::Allowed2),
                missing, r.gap ? L"" : count,
            };
            for (size_t i = 0; ok && i < _countof(fields); ++i) {
                ok = WriteCsvField(writer, fields[i]);
                if (ok && i + 1 != _countof(fields)) ok = WriteCsvSeparator(writer);
            }
            if (ok) ok = writer.Append("\r\n", 2);
        }
        if (ok) ok = writer.Finish();
    } catch (...) {
        // A huge log or a conversion/allocation failure must not escape the
        // window procedure and crash the host process.
        ok = false;
    }
    CloseHandle(h);
    if (!ok) {
        UiMessageBox(hwnd_, UiText(TextId::NotEnoughMemoryOrAFileWrite), UiText(TextId::ExportFailed),
                    MB_ICONERROR);
        return;
    }
    UiMessageBox(hwnd_, UiText(TextId::LogExported), UiText(TextId::ExportComplete), MB_ICONINFORMATION);
}

void MainWindow::ShowDetails(int index) {
    const LogRow* selected = ListRow(index);
    if (!selected) return;
    const LogRow& r = *selected;
    if (r.gap) {
        std::wstring text =
            UiText(TextId::TheMonitoringServiceCouldNotRetain) + std::to_wstring(r.missingEvents) +
            UiText(TextId::ClipboardAccessEventsTheTargetMayHave);
        if (!r.process.empty())
            text += UiText(TextId::RelatedProcess) + r.process +
                    (r.pid ? L" (PID " + std::to_wstring(r.pid) + L")" : L"");
        UiMessageBox(hwnd_, text.c_str(), UiText(TextId::MonitoringGap), MB_ICONWARNING);
        return;
    }
    const std::wstring content = LogContentSummary(r);
    std::wstring text =
        UiText(TextId::Time2) + FormatTime(r.time) +
        UiText(TextId::Process3) + r.process +
        UiText(TextId::Path) + (r.path.empty() ? UiText(TextId::Unknown2) : r.path) +
        L"\nPID：" + std::to_wstring(r.pid) +
        UiText(TextId::Source2) +
            (r.sourceProcess.empty() ? UiText(TextId::Unknown2) : r.sourceProcess) +
        (r.sourcePid ? L" (PID " + std::to_wstring(r.sourcePid) + L")" : L"") +
        UiText(TextId::SourcePath2) +
            (r.sourcePath.empty() ? UiText(TextId::Unknown2) : r.sourcePath) +
        UiText(TextId::ClipboardSequence2) +
            (r.clipboardSequence ? std::to_wstring(r.clipboardSequence)
                                 : UiText(TextId::Unknown2)) +
        UiText(TextId::Operation2) + OpName(r.op) +
        UiText(TextId::Format4) + FormatName(r.fmt) +
        UiText(TextId::MatchedRule2) +
            (r.ruleName.empty() ? UiText(TextId::DefaultAllowSilent) : DisplayRuleName(r.ruleName, r.builtinRule)) +
        UiText(TextId::Decision2) + DecisionName(r.action) +
        UiText(TextId::Notification2) + NotificationName(r.showNotification) +
        UiText(TextId::ListVisibility2) + (r.hideFromLogList ? UiText(TextId::Hidden) : UiText(TextId::Visible)) +
        UiText(TextId::Result) + (r.blocked ? UiText(TextId::Blocked3) : UiText(TextId::Allow)) +
        (r.cryptoContent ? UiText(TextId::SecurityFlagCryptoContent) : L"") +
        UiText(TextId::Count2) + std::to_wstring(r.count) +
        (content.empty() ? L"" : UiText(TextId::Content2) + content);
    UiMessageBox(hwnd_, text.c_str(), UiText(TextId::AccessDetails), MB_ICONINFORMATION);
}

void MainWindow::ShowLogContextMenu(int x, int y) {
    int index = ListView_GetNextItem(lv_, -1, LVNI_SELECTED);
    POINT screenPoint{x, y};
    if (x != -1 || y != -1) {
        POINT clientPoint = screenPoint;
        ScreenToClient(lv_, &clientPoint);
        LVHITTESTINFO hit = {};
        hit.pt = clientPoint;
        index = ListView_SubItemHitTest(lv_, &hit);
        if (index < 0) return;
        ListView_SetItemState(lv_, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
        ListView_SetItemState(lv_, index, LVIS_SELECTED | LVIS_FOCUSED,
                              LVIS_SELECTED | LVIS_FOCUSED);
    } else {
        if (index < 0) return;
        RECT itemRect = {};
        if (!ListView_GetItemRect(lv_, index, &itemRect, LVIR_BOUNDS)) return;
        screenPoint = {itemRect.left + DpiScale(24, dpi_), itemRect.bottom};
        ClientToScreen(lv_, &screenPoint);
    }
    const LogRow* selectedRow = ListRow(index);
    if (!selectedRow) return;
    const LogRow& row = *selectedRow;
    const unsigned long long rowId = row.id;
    HMENU menu = CreatePopupMenu();
    if (!menu) return;
    const UINT addFlags = !row.gap && !row.path.empty() ? MF_STRING
                                                        : MF_STRING | MF_GRAYED;
    const UINT copyFlags = !row.gap && CanCopyLogContent(row)
                               ? MF_STRING
                               : MF_STRING | MF_GRAYED;
    AppendMenuW(menu, addFlags, kLogMenuAddRule, UiText(TextId::AddRule));
    AppendMenuW(menu, copyFlags, kLogMenuCopy, UiText(TextId::Copy));
    SetForegroundWindow(hwnd_);
    const UINT command = TrackPopupMenuEx(
        menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, screenPoint.x, screenPoint.y,
        hwnd_, nullptr);
    DestroyMenu(menu);
    PostMessageW(hwnd_, WM_NULL, 0, 0);
    const auto selected = std::find_if(
        rows_.begin(), rows_.end(), [rowId](const LogRow& candidate) {
            return candidate.id == rowId;
        });
    if (selected == rows_.end()) return;
    const int currentIndex = ListIndexForRow(&*selected);
    if (currentIndex < 0) return;
    if (command == kLogMenuAddRule)
        AddRuleFromLog(currentIndex);
    else if (command == kLogMenuCopy)
        CopyLogContent(currentIndex);
}

void MainWindow::AddRuleFromLog(int index) {
    if (protectionOperationPending_ || exitRequested_) return;
    const LogRow* selected = ListRow(index);
    if (!selected) return;
    const LogRow& row = *selected;
    if (row.gap || row.path.empty()) return;

    Rule rule;
    rule.name = UiText(TextId::FromLog) +
                (row.process.empty() ? std::wstring(UiText(TextId::UnknownProcess)) : row.process);
    if (rule.name.size() > 128) rule.name.resize(128);
    rule.pattern = row.path;
    rule.isPath = true;
    if (!ShowRuleEditor(hwnd_, rule)) return;

    try {
        std::vector<Rule> updated = g_app.cfg.rules;
        updated.push_back(std::move(rule));
        if (!IsRuleSetSupported(updated)) {
            UiMessageBox(hwnd_, UiText(TextId::TheRuleCountFieldLengthOrTotal),
                        UiText(TextId::CouldNotAddRule), MB_ICONWARNING);
            return;
        }
        g_app.cfg.rules.swap(updated);
        if (!g_app.SaveConfig()) {
            g_app.cfg.rules.swap(updated);
            UiMessageBox(hwnd_, UiText(TextId::CouldNotSaveConfigurationTheRuleWas), UiText(TextId::SaveFailed),
                        MB_ICONERROR);
            return;
        }
        if (g_app.server) g_app.server->BroadcastRules(g_app.cfg.rules);
    } catch (...) {
        UiMessageBox(hwnd_, UiText(TextId::NotEnoughMemoryTheRuleWasNot), UiText(TextId::CouldNotAddRule),
                    MB_ICONERROR);
    }
}

void MainWindow::CopyLogContent(int index) {
    const LogRow* selected = ListRow(index);
    if (!selected) return;
    const LogRow& row = *selected;
    if (row.gap || !CanCopyLogContent(row)) return;
    if (row.snapshotKind == kSnapshotImage ||
        row.snapshotKind == kSnapshotFiles) {
        const wchar_t* warning =
            row.snapshotKind == kSnapshotFiles
                ? UiText(TextId::ThisWillReplaceTheCurrentClipboardWith)
                : UiText(TextId::ThisWillReplaceTheCurrentClipboardWith2);
        if (UiMessageBox(hwnd_, warning, UiText(TextId::RestoreClipboard),
                        MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) != IDYES)
            return;
    }
    bool copied = false;
    if (!row.preview.empty()) {
        copied = WriteClipboardText(hwnd_, row.preview);
    } else if (row.snapshotKind == kSnapshotImage &&
               IsSnapshotFormat(row.fmt)) {
        const UINT format = row.fmt == CF_DIBV5 ? CF_DIBV5 : CF_DIB;
        copied = WriteClipboardGlobalData(hwnd_, format, row.snapshot.data(),
                                          row.snapshot.size());
    } else if (row.snapshotKind == kSnapshotFiles && row.fmt == CF_HDROP) {
        copied = WriteClipboardFileDrop(hwnd_, row.snapshot);
    }
    if (!copied)
        UiMessageBox(hwnd_, UiText(TextId::CouldNotWriteToTheClipboardPlease), UiText(TextId::CopyFailed),
                    MB_ICONWARNING);
}

void MainWindow::ShowMainWindow() {
    ShowWindow(hwnd_, SW_RESTORE);
    SetForegroundWindow(hwnd_);
}

void MainWindow::ToggleVisible() {
    if (IsWindowVisible(hwnd_) && !IsIconic(hwnd_))
        ShowWindow(hwnd_, SW_HIDE);
    else
        ShowMainWindow();
}

void MainWindow::ShowContextMenu(int x, int y) {
    HMENU menu = CreatePopupMenu();
    if (!menu) return;

    std::wstring status = g_app.paused ? UiText(TextId::StatusProtectionPaused)
                                       : UiText(TextId::StatusProtectionRunning);
    if (IsTargetedInjectionMode())
        status += TargetedInjectionPid() != 0
                      ? UiText(TextId::SingleProcessPID) +
                            std::to_wstring(TargetedInjectionPid())
                      : UiText(TextId::InvalidSingleProcessSettings);
    else
        status += IsGlobalInjectionEnabled() ? UiText(TextId::GlobalInjectionOn)
                                             : UiText(TextId::GlobalInjectionOff);
    if (g_app.cfg.settings.shortcutOnlyMode)
        status += IsGlobalInjectionEnabled() ? UiText(TextId::ShortcutOnly2)
                                             : UiText(TextId::ShortcutOnlyAccessAppliesToInjectedProcesses);
    if (!g_app.paused && g_app.cfg.settings.cryptoProtection)
        status += IsGlobalInjectionEnabled()
                      ? UiText(TextId::CryptoAddressProtection)
                      : IsTargetedInjectionMode()
                            ? UiText(TextId::CryptoForTargetOnly)
                            : UiText(TextId::CryptoAwaitingInjection);

    AppendMenuW(menu, MF_STRING | MF_GRAYED, 0, status.c_str());
    AppendMenuW(menu, MF_STRING, kCmdShow, UiText(TextId::OpenMainWindow));
    SetMenuDefaultItem(menu, kCmdShow, FALSE);
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING | (g_app.paused ? MF_CHECKED : 0), kCmdPause,
                g_app.paused ? UiText(TextId::ResumeProtection) : UiText(TextId::PauseProtection2));
    UINT globalFlags = MF_STRING;
    if (IsGlobalInjectionEnabled()) globalFlags |= MF_CHECKED;
    if (IsTargetedInjectionMode() || protectionOperationPending_)
        globalFlags |= MF_GRAYED;
    AppendMenuW(menu, globalFlags, kCmdGlobalInjection,
                protectionOperation_ == ProtectionOperation::globalInjection
                    ? UiText(TextId::ChangingProtection)
                    : IsGlobalInjectionEnabled() ? UiText(TextId::DisableProtectionG)
                                                 : UiText(TextId::EnableProtectionG));
    AppendMenuW(menu, MF_STRING, kCmdRules, UiText(TextId::AccessRules2));
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING, kCmdExport, UiText(TextId::ExportLog2));
    AppendMenuW(menu,
                MF_STRING |
                    (g_app.cfg.settings.shortcutOnlyMode ? MF_CHECKED : 0),
                kCmdShortcutOnlyMode,
                ShortcutOnlyMenuText().c_str());
    AppendMenuW(menu, MF_STRING, kCmdSettings, UiText(TextId::Settings2));
    AppendMenuW(menu, MF_STRING, kCmdAppHotkeys, UiText(TextId::KeyboardShortcuts2));
    AppendMenuW(menu, MF_STRING, kCmdPrivateClear, UiText(TextId::ClearPrivateClipboard));
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    if (IsWindowVisible(hwnd_))
        AppendMenuW(menu, MF_STRING, kCmdHide, UiText(TextId::HideToTray));
    AppendMenuW(menu, MF_STRING, kCmdExit, UiText(TextId::EXit));
    SetForegroundWindow(hwnd_);   // 托盘菜单必须前置才能正常消失

    POINT anchor = {x, y};
    MONITORINFO monitor = {sizeof(monitor)};
    GetMonitorInfoW(MonitorFromPoint(anchor, MONITOR_DEFAULTTONEAREST), &monitor);
    const int midX = monitor.rcMonitor.left +
                     (monitor.rcMonitor.right - monitor.rcMonitor.left) / 2;
    const int midY = monitor.rcMonitor.top +
                     (monitor.rcMonitor.bottom - monitor.rcMonitor.top) / 2;
    const UINT alignment = (x >= midX ? TPM_RIGHTALIGN : TPM_LEFTALIGN) |
                           (y >= midY ? TPM_BOTTOMALIGN : TPM_TOPALIGN);
    int cmd = TrackPopupMenu(menu,
                             TPM_RETURNCMD | TPM_NONOTIFY | TPM_RIGHTBUTTON |
                                 alignment,
                             x, y, 0, hwnd_, nullptr);
    PostMessageW(hwnd_, WM_NULL, 0, 0);
    DestroyMenu(menu);
    if (cmd != 0) SendMessageW(hwnd_, WM_COMMAND, MAKEWPARAM(cmd, 0), 0);
}

void MainWindow::TogglePause() {
    g_app.paused = !g_app.paused;
    if (g_app.tray) g_app.tray->SetPaused(g_app.paused);
    if (g_app.server) g_app.server->BroadcastPause(g_app.paused);
    SyncProtectionState();
}

void MainWindow::ToggleShortcutOnlyMode() {
    const bool oldValue = g_app.cfg.settings.shortcutOnlyMode;
    g_app.cfg.settings.shortcutOnlyMode = !oldValue;
    if (!g_app.SaveConfig()) {
        g_app.cfg.settings.shortcutOnlyMode = oldValue;
        UiMessageBox(hwnd_, UiText(TextId::CouldNotSaveShortcutOnlyModeSettings),
                    UiText(TextId::SettingsFailed), MB_ICONERROR);
        return;
    }
    if (g_app.server) g_app.server->BroadcastSettings(g_app.cfg.settings);
    SyncProtectionState();
    if (g_app.tray) {
        const wchar_t* message = nullptr;
        if (!g_app.cfg.settings.shortcutOnlyMode) {
            message = UiText(TextId::DisabledRegularRulesDetermineClipboardAccess);
        } else if (IsGlobalInjectionEnabled()) {
            message = UiText(TextId::EnabledOnlyCopyPasteShortcutsCanAccess);
        } else if (IsTargetedInjectionMode()) {
            message = UiText(TextId::EnabledForTheCurrentSingleProcessTarget);
        } else {
            message = UiText(TextId::TheModeIsEnabledButGlobalInjection);
        }
        g_app.tray->ShowBalloon(UiText(TextId::ShortcutOnlyMode), message,
                                g_app.cfg.settings.shortcutOnlyMode &&
                                    !IsGlobalInjectionEnabled());
    }
}

void MainWindow::ToggleGlobalInjection() {
    if (protectionOperationPending_ || exitRequested_) return;
    if (IsTargetedInjectionMode()) {
        UiMessageBox(hwnd_, UiText(TextId::SingleProcessProtectionInjectsOnlyTheSelected),
                    UiText(TextId::GlobalInjectionUnavailable), MB_ICONINFORMATION);
        return;
    }

    const bool enable = !IsGlobalInjectionEnabled();
    if (enable) {
        const int answer = UiMessageBox(
            hwnd_,
            UiText(TextId::GlobalInjectionCoversCompatibleDesktopGUIProcesses),
            UiText(TextId::EnableProtection), MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON2);
        if (answer != IDYES) return;
    }

    BeginProtectionOperation(ProtectionOperation::globalInjection, !enable);
}

void MainWindow::ToggleSingleProcessTest() {
    if (protectionOperationPending_) return;
    if (IsGlobalInjectionEnabled()) {
        UiMessageBox(hwnd_, UiText(TextId::TurnOffGlobalInjectionBeforeStartingSingle),
                    UiText(TextId::SingleProcessProtectionUnavailable), MB_ICONINFORMATION);
        return;
    }

    DWORD processId = 0;
    const bool stopping = IsTargetedInjectionMode();
    if (!stopping && !ShowTargetProcessDialog(hwnd_, processId)) return;

    BeginSingleProcessOperation(stopping, processId, false);
}

void MainWindow::StartInitialSingleProcessTest(DWORD processId) {
    if (protectionOperationPending_) return;
    BeginSingleProcessOperation(false, processId, true);
}

void MainWindow::BeginSingleProcessOperation(bool stopping, DWORD processId,
                                             bool serverPrepared) {
    BeginProtectionOperation(ProtectionOperation::singleProcess, stopping,
                             processId, serverPrepared);
}

void MainWindow::StartInitialGlobalInjection() {
    BeginProtectionOperation(ProtectionOperation::globalInjection);
}

void MainWindow::BeginExit() {
    if (exitRequested_) return;
    UnregisterHotkeys();
    privateClipboard_.Clear();
    exitRequested_ = true;
    SyncProtectionState();
    // Queue teardown after an in-flight switch; never wait for I/O in a UI
    // command handler. Keep the window alive until cleanup has completed.
    if (!protectionOperationPending_)
        BeginProtectionOperation(ProtectionOperation::shutdown);
}

void MainWindow::BeginProtectionOperation(ProtectionOperation operation,
                                          bool stopping, DWORD processId,
                                          bool serverPrepared) {
    if (protectionOperationPending_) return;
    protectionOperation_ = operation;
    protectionOperationPending_ = true;
    protectionChanged_ = false;
    protectionResultReady_.store(false, std::memory_order_release);
    protectionError_.clear();
    SyncProtectionState();
    try {
        std::function<void()> task =
            [this, operation, stopping, processId, serverPrepared] {
                std::wstring error;
                bool changed = false;
                try {
                    if (operation == ProtectionOperation::shutdown) {
                        StopProtectionForExit();
                        if (autostartQueryThread_.joinable())
                            autostartQueryThread_.join();
                        changed = true;
                    } else if (operation == ProtectionOperation::globalInjection) {
                        changed = SetGlobalInjectionEnabled(!stopping, error);
                    } else {
                        changed = serverPrepared
                                      ? StartPreparedSingleProcessTest(processId, error)
                                      : stopping ? StopSingleProcessTest(error)
                                                 : StartSingleProcessTest(processId, error);
                    }
                } catch (...) {
                    error = UiText(TextId::TheProtectionOperationCouldNotBeCompleted);
                }
                protectionChanged_ = changed;
                protectionError_ = std::move(error);
                if (operation == ProtectionOperation::shutdown && changed)
                    protectionWorkerStop_.store(true, std::memory_order_release);
                protectionResultReady_.store(true, std::memory_order_release);
                PostMessageW(hwnd_, kMsgProtectionOperation, 0, 0);
            };
        if (!protectionWorkEvent_)
            protectionWorkEvent_ = CreateEventW(nullptr, FALSE, FALSE, nullptr);
        if (!protectionWorkEvent_) throw std::bad_alloc();
        if (!protectionThread_.joinable()) {
            protectionWorkerStop_.store(false, std::memory_order_release);
            protectionThread_ = std::thread(&MainWindow::RunProtectionWorker, this);
        }
        {
            std::lock_guard<std::mutex> lock(protectionTaskMutex_);
            protectionTask_ = std::move(task);
        }
        SetEvent(protectionWorkEvent_);
    } catch (...) {
        protectionOperationPending_ = false;
        protectionOperation_ = ProtectionOperation::none;
        exitRequested_ = false;
        protectionError_ = UiText(TextId::CouldNotStartTheBackgroundProtectionTask);
        SyncProtectionState();
        UiMessageBox(hwnd_, protectionError_.c_str(),
                    UiText(TextId::ClipboardProtector), MB_ICONERROR);
        if (autostartQueryDeferred_)
            PostMessageW(hwnd_, kMsgAutostartQuery, 0, 0);
    }
}

void MainWindow::CompleteProtectionOperation() {
    if (!protectionOperationPending_ ||
        !protectionResultReady_.exchange(false, std::memory_order_acquire)) return;
    const ProtectionOperation completed = protectionOperation_;
    protectionOperation_ = ProtectionOperation::none;
    protectionOperationPending_ = false;
    std::vector<AlwaysDecision> deferred;
    deferred.swap(deferredAlwaysDecisions_);
    for (const AlwaysDecision& decision : deferred) {
        if (!AddAlwaysDecisionRule(decision) && g_app.tray)
            g_app.tray->ShowBalloon(UiText(TextId::CouldNotSaveRule),
                                    UiText(TextId::CouldNotSaveTheRememberedChoicePlease), true);
    }
    if (completed == ProtectionOperation::shutdown && protectionChanged_) {
        JoinProtectionOperation();
        DestroyWindow(hwnd_);
        return;
    }
    if (completed == ProtectionOperation::shutdown) exitRequested_ = false;
    if (exitRequested_) {
        BeginProtectionOperation(ProtectionOperation::shutdown);
        return;
    }
    if (!IsGlobalInjectionEnabled() && !IsTargetedInjectionMode())
        g_app.injectedClients = 0;
    SyncProtectionState();
    if (autostartQueryDeferred_)
        PostMessageW(hwnd_, kMsgAutostartQuery, 0, 0);
    if (!protectionChanged_) {
        UiMessageBox(hwnd_, protectionError_.empty()
                               ? UiText(TextId::CouldNotChangeProtectionState)
                               : protectionError_.c_str(),
                    completed == ProtectionOperation::globalInjection
                        ? UiText(TextId::GlobalInjection) : UiText(TextId::SingleProcessProtection), MB_ICONERROR);
    }
}

void MainWindow::ShowInjectionSafetyInfo() {
    UiMessageBox(
        hwnd_,
        UiText(TextId::GlobalInjectionUsesWHGETMESSAGEForCompatible),
        UiText(TextId::GlobalInjectionInformation), MB_ICONINFORMATION);
}

} // namespace clip
