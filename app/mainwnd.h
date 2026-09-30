#pragma once
#include <windows.h>
#include <commctrl.h>
#include <array>
#include <atomic>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>
#include "app.h"
#include "autostart.h"
#include "confirmwnd.h"
#include "privateclipboard.h"

namespace clip {

constexpr UINT kMsgAutostartQuery = WM_APP + 4;
constexpr UINT kMsgProtectionOperation = WM_APP + 7;
constexpr UINT kMsgPrivateClipboard = WM_APP + 20;
constexpr UINT kMsgPrivateHotkeyWarning = WM_APP + 21;

// 确认窗口“一直这样”的结果：需要持久化为规则的访问决策。
// 来源进程为空或来源 PID 为 0 表示来源未知。
struct AlwaysDecision {
    std::wstring process;
    DWORD processId = 0;
    std::wstring sourceProcess;
    DWORD sourceProcessId = 0;
    int action = kRuleAllow;
};

// 主窗口：保护概览 + 快捷操作 + 日志列表；关闭即隐藏到托盘。
class MainWindow {
public:
    ~MainWindow();
    bool Create(HINSTANCE hInst);
    HWND hwnd() const { return hwnd_; }
    // Query the scheduler off the UI thread. The result is applied by a
    // window message, and the thread is always joined before teardown.
    void StartAutostartQuery();
    void StartInitialSingleProcessTest(DWORD processId);
    void StartInitialGlobalInjection();
    void BeginExit();
    void JoinAutostartQuery();
    void JoinProtectionOperation();
    bool TranslateConfirmationMessage(MSG& message);

    // UI 线程从 PipeServer 事件队列取出并追加日志
    void OnEvent(LogRow row);
    // UI 线程更新状态栏“已注入进程数”
    void SetInjectedCount(size_t n);
    // 暂停状态变化后同步工具栏按钮文字
    void SyncPauseButton();
    // 注入模式或暂停状态变化后同步菜单与状态栏
    void SyncProtectionState();

private:
    enum class ProtectionOperation { none, singleProcess, globalInjection, shutdown };
    static LRESULT CALLBACK WndProcStatic(HWND, UINT, WPARAM, LPARAM);
    LRESULT WndProc(UINT, WPARAM, LPARAM);

    void OnCreate();
    void CreateApplicationMenu();
    void ChangeLanguage(Language language);
    void ApplyLanguage();
    bool RegisterHotkeys(const AppHotkeys& keys);
    void UnregisterHotkeys();
    void ConfigureHotkeys();
    std::wstring ShortcutOnlyMenuText() const;
    void NotifyPrivateClipboard(const wchar_t* text);
    void CreateFonts(UINT dpi);
    void ApplyDpi(UINT dpi);
    void SyncMenuState();
    void Layout();
    void Paint();
    void PaintBackground(HDC dc, const RECT& client);
    void DrawCommandButton(const DRAWITEMSTRUCT& draw) const;
    void SaveWindowSize();
    void InsertRow(LogRow row);
    void InsertListRow(const LogRow& row, int index);
    void RebuildLogList();
    void ToggleBlockedFilter();
    bool ShouldShowListRow(const LogRow& row) const;
    const LogRow* ListRow(int index) const;
    int ListIndexForRow(const LogRow* row) const;
    void TrimToLimit();
    void TrimSnapshotMemory();
    void ClearLog();
    void ExportCsv();
    void ShowDetails(int index);
    void ShowLogContextMenu(int x, int y);
    void AddRuleFromLog(int index);
    void CopyLogContent(int index);
    void FocusNotifiedRow();
    void FlushDueNotifications();
    void ShowContextMenu(int x, int y);
    void ShowMainWindow();
    void ToggleVisible();
    void TogglePause();
    void ToggleShortcutOnlyMode();
    void ToggleGlobalInjection();
    void ToggleSingleProcessTest();
    void BeginSingleProcessOperation(bool stopping, DWORD processId,
                                     bool serverPrepared);
    void CompleteProtectionOperation();
    void RunProtectionWorker();
    void BeginProtectionOperation(ProtectionOperation operation, bool stopping = false,
                                  DWORD processId = 0, bool serverPrepared = false);
    void ShowInjectionSafetyInfo();
    void UpdateStatusBar();
    void ShowPendingConfirmations();
    void CompleteConfirmation(DWORD requestId, bool allow,
                              bool persistDecision);
    bool AddAlwaysDecisionRule(const AlwaysDecision& decision);

    HWND hwnd_ = nullptr, lv_ = nullptr;
    std::array<HWND, 5> commandButtons_{};
    std::array<RECT, 4> cardRects_{};
    RECT logPanelRect_{};
    RECT footerRect_{};
    HMENU menu_ = nullptr;
    HFONT uiFont_ = nullptr;
    HFONT titleFont_ = nullptr;
    HFONT metricFont_ = nullptr;
    HFONT sectionFont_ = nullptr;
    HFONT smallFont_ = nullptr;
    HIMAGELIST rowHeightImages_ = nullptr;
    UINT dpi_ = 96;
    std::wstring protectionValue_;
    std::wstring protectionDetail_;
    std::deque<LogRow> rows_;
    size_t snapshotBytes_ = 0;
    unsigned long long nextId_ = 1;

    struct NotifyState {
        ULONGLONG lastTick = 0;
        DWORD suppressed = 0;
        unsigned long long lastRowId = 0;
        LogRow lastRow;
    };
    std::unordered_map<DWORD, NotifyState> notify_; // pid -> 通知合并状态
    std::unordered_map<DWORD, std::unique_ptr<AccessConfirmationWindow>>
        confirmations_;
    std::vector<AlwaysDecision> pendingAlwaysDecisions_;
    std::vector<AlwaysDecision> deferredAlwaysDecisions_;
    unsigned long long lastNotifiedRowId_ = 0;
    std::thread autostartQueryThread_;
    std::thread protectionThread_;
    HANDLE protectionWorkEvent_ = nullptr;
    std::mutex protectionTaskMutex_;
    std::function<void()> protectionTask_;
    std::atomic<bool> protectionWorkerStop_{false};
    std::atomic<bool> protectionResultReady_{false};
    std::wstring protectionError_;
    bool protectionChanged_ = false;
    bool protectionOperationPending_ = false;
    ProtectionOperation protectionOperation_ = ProtectionOperation::none;
    bool exitRequested_ = false;
    bool autostartQueryPending_ = false;
    bool autostartQueryDeferred_ = false;
    bool autostartQueryStarted_ = false;
    bool autostartQueryKnown_ = false;
    AutostartState autostartQueryState_ = AutostartState::Absent;
    bool shortcutHotkeyRegistered_ = false;
    bool privateHotkeysRegistered_ = false;
    std::wstring hotkeyRegistrationError_;
    PrivateClipboard privateClipboard_;
    bool rulesDialogOpen_ = false;
    bool blockedOnly_ = false;
};

// 剪贴板格式 ID -> 显示名
std::wstring FormatName(UINT fmt);

} // namespace clip
