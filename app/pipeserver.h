#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <deque>
#include <unordered_map>
#include <mutex>
#include <atomic>
#include "config.h"
#include "app.h"
#include "ipc.h"

namespace clip {

struct LogRow;

struct AccessConfirmationRequest {
    DWORD id = 0;
    DWORD processId = 0;
    std::wstring process;
    std::wstring path;
    ClipOp operation = kOpRead;
    UINT format = 0;
    DWORD sourceProcessId = 0;
    std::wstring sourceProcess;
    std::wstring sourcePath;
    std::wstring ruleName;
    std::wstring preview;
    PreviewKind previewKind = PreviewKind::Text;
    DWORD timeoutMs = 15000;
    bool timeoutBlock = true;
};

struct ReadyProcessIdentity {
    DWORD processId = 0;
    ULONGLONG creationTime = 0;
};

// 命名管道服务端：接收 Hook.dll 的事件上报，向其广播规则/暂停状态。
// 事件不直接操作 UI，而是 PostMessage 封送到主窗口线程。
class PipeServer {
public:
    ~PipeServer();
    bool Start(HWND notifyWnd, bool targetedMode = false,
               DWORD targetedPid = 0);
    void Stop();

    void BroadcastRules(const std::vector<Rule>& rules);
    void BroadcastPause(bool paused);
    void BroadcastSettings(const Settings& settings);
    bool PopEvent(LogRow& event);
    bool PopConfirmation(AccessConfirmationRequest& request);
    bool PopCancelledConfirmation(DWORD& requestId);
    bool ResolveConfirmation(DWORD requestId, bool allow);
    bool IsTargetConnected(DWORD processId);
    bool IsTargetStateDelivered(DWORD processId);
    bool IsTargetReady(DWORD processId);
    bool QueuePrivateClipboard(DWORD processId, const std::wstring& mappingName);
    std::vector<ReadyProcessIdentity> ReadyProcessIdentities();

private:
    struct ConfirmationResponse {
        unsigned long long token = 0;
        bool allow = false;
    };

    struct ClientCtx {
        PipeServer* self = nullptr;
        HANDLE pipe = INVALID_HANDLE_VALUE;
        HANDLE thread = nullptr;
        std::atomic<bool> finished{false};
        DWORD pid = 0;
        ULONGLONG creationTime = 0;
        unsigned long long connectionId = 0;
        std::wstring path;
        std::mutex responsesMu;
        std::deque<ConfirmationResponse> responses;
        std::deque<std::string> privateRequests;
        std::atomic<unsigned long long> deliveredVersion{0};
        std::atomic<bool> shutdownAck{false};
        std::atomic<bool> stateReady{false};
        std::atomic<bool> privateClipboardCapable{false};
        std::atomic<bool> textMetadataCapable{false};
        std::atomic<bool> extendedCapable{false};
        std::atomic<bool> notificationCapable{false};
        std::atomic<bool> formatModelCapable{false};
        std::atomic<bool> cryptoSettingsCapable{false};
        std::atomic<bool> cryptoEventCapable{false};
        std::atomic<bool> snapshotCapable{false};
        std::atomic<bool> shortcutPolicyCapable{false};
        std::atomic<bool> ignoreCustomCapable{false};
        std::atomic<bool> logVisibilityCapable{false};
        std::atomic<bool> sentExtended{false};
        std::atomic<bool> sentLogVisibility{false};
    };

    static DWORD WINAPI ListenThreadStatic(LPVOID self);
    static DWORD WINAPI ClientThreadStatic(LPVOID param);
    DWORD ListenThreadNoThrow() noexcept;
    DWORD ClientThreadNoThrow(ClientCtx* ctx) noexcept;
    DWORD ListenThread();
    DWORD ClientThread(ClientCtx* ctx);

    HANDLE CreatePipe(bool firstInstance);
    bool EnsureSourceMapping();
    bool EnsureCryptoMapping();
    void PublishCryptoSetting(bool enabled, bool resetState = false) noexcept;
    void ClientFinished(ClientCtx* ctx) noexcept;
    void PostClientCountLocked();
    void ReapClients();
    void StopClients(bool waitForever);
    bool QueueLogRow(LogRow row) noexcept;
    bool QueueConfirmation(ClientCtx* ctx, AccessConfirmationRequest request,
                           unsigned long long token);
    bool QueueConfirmationResponse(ClientCtx* ctx,
                                   unsigned long long token, bool allow);
    bool AcceptInboundBytes(size_t bytes) noexcept;
    void CancelClientConfirmations(unsigned long long connectionId);

    std::atomic<HWND> wnd_{nullptr};
    HANDLE listenThread_ = nullptr;
    HANDLE stopEvent_ = nullptr;
    HANDLE initialPipe_ = INVALID_HANDLE_VALUE;
    HANDLE sourceMapping_ = nullptr;
    SharedClipboardSource* source_ = nullptr;
    HANDLE cryptoMapping_ = nullptr;
    SharedCryptoProtection* crypto_ = nullptr;
    std::mutex listenMu_;
    std::atomic<bool> stop_{false};
    std::atomic<bool> accepting_{false};
    DWORD targetedPid_ = 0;
    bool targetedMode_ = false;

    std::mutex stateMu_;
    std::string rulesMsg_;
    std::string rulesV3Msg_;
    std::string rulesV2Msg_;
    std::string legacyRulesMsg_;
    std::string pauseMsg_;
    std::string settingsMsg_;
    std::string settingsCryptoMsg_;
    std::string settingsSnapshotMsg_;
    std::string settingsShortcutPolicyMsg_;
    std::string settingsIgnoreCustomMsg_;
    std::string legacySettingsMsg_;

    std::unordered_map<std::wstring, BYTE> notificationActionsByRule_;
    bool shuttingDown_ = false;
    unsigned long long stateVersion_ = 0;
    std::atomic<bool> previewEnabled_{false};
    std::atomic<bool> cryptoProtectionEnabled_{false};
    std::atomic<bool> shortcutPolicyRequired_{false};
    std::atomic<bool> modernFormatsEnabled_{false};
    std::atomic<bool> logVisibilityRequired_{false};

    std::mutex clientsMu_;
    std::vector<ClientCtx*> clients_;
    std::mutex eventsMu_;
    std::deque<LogRow> events_;
    size_t eventsSnapshotBytes_ = 0;
    unsigned long long serverDroppedEvents_ = 0;
    std::mutex inboundRateMu_;
    ULONGLONG inboundRateWindowStart_ = 0;
    size_t inboundRateBytes_ = 0;

    struct ConfirmationTarget {
        unsigned long long connectionId = 0;
        unsigned long long token = 0;
    };
    std::mutex confirmationsMu_;
    std::deque<AccessConfirmationRequest> confirmations_;
    std::deque<DWORD> cancelledConfirmations_;
    std::unordered_map<DWORD, ConfirmationTarget> confirmationTargets_;
    std::atomic<DWORD> nextConfirmationId_{1};
    std::atomic<unsigned long long> nextConnectionId_{1};
};

} // namespace clip
