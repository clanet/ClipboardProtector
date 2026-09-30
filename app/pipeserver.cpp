#include "pipeserver.h"
#include "app.h"
#include "messages.h"
#include "ipc.h"
#include "rules.h"
#include "winutil.h"
#include <sddl.h>
#include <algorithm>
#include <new>
#include <utility>
namespace clip {

namespace {

constexpr size_t kQueuedSnapshotBytesCapacity = 16u << 20;
constexpr size_t kClientInboundBytesPerSecond = 8u << 20;
constexpr size_t kGlobalInboundBytesPerSecond = 64u << 20;

static std::string ExtendedRulesMessage(const std::vector<Rule>& rules,
                                        unsigned modelVersion) {
    if (!IsRuleSetSupported(rules)) return {};
    const bool splitNotification = modelVersion >= 3;
    const bool includeLogVisibility = modelVersion >= 4;
    std::string payload;
    PutU32(payload, (DWORD)rules.size());
    PutU32(payload, includeLogVisibility
                        ? kRulePayloadMarkerV4
                        : splitNotification ? kRulePayloadMarkerV3
                                            : kRulePayloadMarker);
    for (const auto& rule : rules) {
        PutWStr(payload, rule.name);
        PutWStr(payload, rule.pattern);
        PutU8(payload, rule.isPath ? 1 : 0);
        const BYTE action = !splitNotification && rule.showNotification &&
                                    rule.action == kRuleAllow
                                ? kRuleShow
                                : static_cast<BYTE>(rule.action);
        PutU8(payload, action);
        if (splitNotification)
            PutU8(payload, rule.showNotification ? 1 : 0);
        if (includeLogVisibility)
            PutU8(payload, rule.hideFromLogList ? 1 : 0);
        PutU8(payload, rule.operations);
        PutU8(payload, rule.format);
        PutWStr(payload, rule.contentRegex);
        PutU8(payload, rule.ignoreCase ? 1 : 0);
        PutU8(payload, rule.enabled ? 1 : 0);
        PutU8(payload, rule.sourceMode);
        PutWStr(payload, rule.sourcePattern);
        PutU32(payload, rule.confirmTimeoutMs);
        PutU8(payload, rule.timeoutBlock ? 1 : 0);
    }
    if (payload.size() > kIpcMaxPayload) return {};
    std::string message;
    PutFrame(message, kIpcRulesExtended, payload);
    return message;
}

static bool HasModernFormatRule(const std::vector<Rule>& rules) {
    return std::any_of(rules.begin(), rules.end(), [](const Rule& rule) {
        return rule.enabled && rule.format != kFormatAny;
    });
}

static bool HasHiddenLogRule(const std::vector<Rule>& rules) {
    return std::any_of(rules.begin(), rules.end(), [](const Rule& rule) {
        return rule.enabled && rule.hideFromLogList;
    });
}


static std::string LegacyRulesMessage(const std::vector<Rule>& rules) {
    const bool compatible = IsLegacyRuleSetCompatible(rules);
    DWORD count = 0;
    if (compatible) {
        for (const auto& rule : rules) {
            if (rule.enabled) ++count;
        }
    }
    std::string payload;
    PutU32(payload, count);
    if (compatible) {
        for (const auto& rule : rules) {
            if (!rule.enabled) continue;
            PutWStr(payload, rule.pattern);
            PutU8(payload, rule.isPath ? 1 : 0);
            PutU8(payload, rule.action == kRuleBlock ? 2 : 0);
        }
    }
    if (payload.size() > kIpcMaxPayload) return {};
    std::string message;
    PutFrame(message, kIpcRules, payload);
    return message;
}

static std::unordered_map<std::wstring, BYTE> NotificationRuleMap(
    const std::vector<Rule>& rules) {
    std::unordered_map<std::wstring, BYTE> result;
    for (const auto& rule : rules) {
        if (!rule.enabled || !rule.showNotification || rule.name.empty() ||
            !IsRuleDecision(rule.action))
            continue;
        result[rule.name] |= static_cast<BYTE>(1u << rule.action);
    }
    return result;
}

static std::string PauseMessage(bool paused) {
    std::string payload;
    PutU8(payload, paused ? 1 : 0);
    std::string message;
    PutFrame(message, kIpcPause, payload);
    return message;
}

static std::string SettingsMessage(const Settings& settings, bool extended,
                                   bool includeCrypto = false,
                                   bool includeSnapshots = false,
                                   bool includeShortcutPolicy = false,
                                   bool includeIgnoreCustom = false) {
    std::string payload;
    PutU8(payload, settings.previewEnabled ? 1 : 0);
    if (extended) {
        PutU8(payload, settings.shortcutOnlyMode ? 1 : 0);
        if (includeCrypto)
            PutU8(payload, settings.cryptoProtection ? 1 : 0);
        if (includeSnapshots)
            PutU8(payload, settings.captureImageFileSnapshots ? 1 : 0);
        if (includeShortcutPolicy) {
            PutU8(payload, settings.shortcutDirectAllow ? 1 : 0);
            PutU32(payload,
                   std::clamp(settings.shortcutAuthorizationWindowMs,
                              kMinShortcutAuthorizationWindowMs,
                              kMaxShortcutAuthorizationWindowMs));
        }
        if (includeIgnoreCustom)
            PutU8(payload, settings.ignoreCustomFormats ? 1 : 0);
    }
    std::string message;
    PutFrame(message, kIpcSettings, payload);
    return message;
}


static std::string ShutdownMessage() {
    std::string message;
    PutFrame(message, kIpcShutdown);
    return message;
}

static std::string ConfirmationResponseMessage(unsigned long long token,
                                               bool allow) {
    std::string payload;
    PutU64(payload, token);
    PutU8(payload, allow ? 1 : 0);
    std::string message;
    PutFrame(message, kIpcConfirmResponse, payload);
    return message;
}

struct OutboundState {
    std::string rules;
    std::string rulesV3;
    std::string rulesV2;
    std::string legacyRules;
    std::string pause;
    std::string settings;
    std::string settingsCrypto;
    std::string settingsSnapshot;
    std::string settingsShortcutPolicy;
    std::string settingsIgnoreCustom;
    std::string legacySettings;
    unsigned long long version = 0;
    bool changed = false;
    bool shuttingDown = false;
    bool modernFormatsRequired = false;
};


// 解析一条完整的 Hook DLL 事件。
// 事件 payload：u32 pid,u64 hash,u8 op,u32 fmt,u8 action,u8 blocked,wstr preview。
static bool ParseEvent(const char* data, size_t size, size_t& consumed,
                       LogRow& row, bool snapshotsAllowed,
                       bool logVisibilityAllowed, bool textMetadataAllowed) {
    IpcFrameView frame;
    const IpcFrameResult result = ParseFrame(data, size, frame);
    consumed = frame.consumed;
    if (result != IpcFrameResult::complete || frame.type != kIpcEvent)
        return false;
    Reader reader(frame.payload, frame.payloadSize);
    DWORD pid = 0;
    unsigned long long hash = 0;
    DWORD fmt = 0;
    BYTE op = 0;
    BYTE action = 0;
    BYTE blocked = 0;
    std::wstring preview;
    DWORD sequence = 0;
    DWORD sourcePid = 0;
    std::wstring sourceName;
    std::wstring sourcePath;
    std::wstring ruleName;
    unsigned long long missingEvents = 0;
    BYTE hideFromLogList = 0;

    if (!(reader.GetU32(pid) && reader.GetU64(hash) && reader.GetU8(op) &&
          reader.GetU32(fmt) && reader.GetU8(action) && reader.GetU8(blocked) &&
          reader.GetWStr(preview))) {
        return false;
    }
    if (reader.n != 0 &&
        !(reader.GetU32(sequence) && reader.GetU32(sourcePid) &&
          reader.GetWStr(sourceName) && reader.GetWStr(sourcePath) &&
          reader.GetWStr(ruleName)))
        return false;
    if (reader.n != 0 && !reader.GetU64(missingEvents)) return false;
    if (reader.n != 0 && logVisibilityAllowed &&
        (!reader.GetU8(hideFromLogList) || hideFromLogList > 1))
        return false;
    if (reader.n != 0) {
        BYTE snapshotKind = kSnapshotNone;
        DWORD snapshotOriginalBytes = 0;
        DWORD snapshotBytes = 0;
        if (!snapshotsAllowed || !reader.GetU8(snapshotKind) ||
            !reader.GetU32(snapshotOriginalBytes) ||
            !reader.GetU32(snapshotBytes) ||
            snapshotKind > kSnapshotDiscarded ||
            snapshotBytes > kMaxClipboardSnapshotBytes ||
            reader.n < snapshotBytes)
            return false;
        const bool imageFormat =
            fmt == CF_BITMAP || fmt == CF_DIB || fmt == CF_DIBV5;
        const bool fileFormat = fmt == CF_HDROP;
        const bool stored = snapshotKind == kSnapshotImage ||
                            snapshotKind == kSnapshotFiles;
        const bool unavailable = snapshotKind == kSnapshotTooLarge ||
                                 snapshotKind == kSnapshotDiscarded;
        if ((snapshotKind == kSnapshotNone &&
             (snapshotBytes != 0 || snapshotOriginalBytes != 0)) ||
            (stored &&
             (snapshotBytes == 0 || snapshotOriginalBytes != snapshotBytes)) ||
            (unavailable &&
             (snapshotBytes != 0 || snapshotOriginalBytes == 0)) ||
            (snapshotKind == kSnapshotTooLarge &&
             snapshotOriginalBytes <= kMaxClipboardSnapshotBytes) ||
            (snapshotKind == kSnapshotImage && !imageFormat) ||
            (snapshotKind == kSnapshotFiles && !fileFormat) ||
            (unavailable && !imageFormat && !fileFormat))
            return false;
        try {
            row.snapshot.assign(
                reinterpret_cast<const BYTE*>(reader.p),
                reinterpret_cast<const BYTE*>(reader.p) + snapshotBytes);
        } catch (...) {
            return false;
        }
        row.snapshotKind = snapshotKind;
        row.snapshotOriginalBytes = snapshotOriginalBytes;
        reader.p += snapshotBytes;
        reader.n -= snapshotBytes;
    }
    if (reader.n != 0) {
        BYTE builtin = 0, previewKind = 0;
        if (!textMetadataAllowed || !reader.GetU8(builtin) ||
            !reader.GetU8(previewKind) ||
            builtin > static_cast<BYTE>(BuiltinRule::IgnoreCustomFormat) ||
            previewKind > static_cast<BYTE>(PreviewKind::CryptoAddress))
            return false;
        row.builtinRule = static_cast<BuiltinRule>(builtin);
        row.previewKind = static_cast<PreviewKind>(previewKind);
    }
    const bool showNotification =
        (action & kEventNotificationFlag) != 0;
    action &= static_cast<BYTE>(~kEventNotificationFlag);
    if (op > kOpOpen || action > kRuleBlock || blocked > 1 ||
        preview.size() > 64) {
        return false;
    }
    if (reader.n != 0) return false;
    row.pid = pid;
    row.hash = hash;
    row.op = op;
    row.showNotification = showNotification || action == kRuleShow;
    row.hideFromLogList = hideFromLogList != 0;
    row.action = action == kRuleShow ? kRuleAllow : action;
    row.fmt = fmt;
    row.blocked = blocked != 0;
    row.preview = std::move(preview);
    row.clipboardSequence = sequence;
    row.sourcePid = sourcePid;
    row.sourceProcess = std::move(sourceName);
    row.sourcePath = std::move(sourcePath);
    row.ruleName = std::move(ruleName);
    row.missingEvents = missingEvents;
    GetLocalTime(&row.time);
    return true;
}

} // namespace

PipeServer::~PipeServer() {
    Stop();
    if (listenThread_) {
        CancelSynchronousIo(listenThread_);
        WaitForSingleObject(listenThread_, INFINITE);
        CloseHandle(listenThread_);
        listenThread_ = nullptr;
    }
    StopClients(true);
    if (stopEvent_) CloseHandle(stopEvent_);
    if (source_) UnmapViewOfFile(source_);
    if (sourceMapping_) CloseHandle(sourceMapping_);
    if (crypto_) UnmapViewOfFile(crypto_);
    if (cryptoMapping_) CloseHandle(cryptoMapping_);
}

bool PipeServer::EnsureSourceMapping() {
    if (sourceMapping_ && source_) return true;
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!CreateLocalUserSecurityDescriptor(&descriptor)) return false;
    SECURITY_ATTRIBUTES security = {sizeof(security), descriptor, FALSE};
    const std::wstring name = ResolveObjectName(
        L"CLIP_TEST_SOURCE_MAP", kClipboardSourceMapName);

    sourceMapping_ = CreateFileMappingW(
        INVALID_HANDLE_VALUE, &security, PAGE_READWRITE, 0,
        sizeof(SharedClipboardSource), name.c_str());
    const DWORD createError = GetLastError();
    LocalFree(descriptor);
    if (!sourceMapping_) return false;
    if (createError == ERROR_ALREADY_EXISTS) {
        CloseHandle(sourceMapping_);
        sourceMapping_ = nullptr;
        SetLastError(ERROR_ALREADY_EXISTS);
        return false;
    }
    source_ = static_cast<SharedClipboardSource*>(
        MapViewOfFile(sourceMapping_, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0,
                      sizeof(SharedClipboardSource)));
    if (!source_) {
        CloseHandle(sourceMapping_);
        sourceMapping_ = nullptr;
        return false;
    }
    ZeroMemory(source_, sizeof(*source_));
    return true;
}

bool PipeServer::EnsureCryptoMapping() {
    if (cryptoMapping_ && crypto_) return true;
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!CreateLocalUserSecurityDescriptor(&descriptor)) return false;
    SECURITY_ATTRIBUTES security = {sizeof(security), descriptor, FALSE};
    const std::wstring name = ResolveObjectName(
        L"CLIP_TEST_CRYPTO_MAP", kCryptoProtectionMapName);

    cryptoMapping_ = CreateFileMappingW(
        INVALID_HANDLE_VALUE, &security, PAGE_READWRITE, 0,
        sizeof(SharedCryptoProtection), name.c_str());
    const DWORD createError = GetLastError();
    LocalFree(descriptor);
    if (!cryptoMapping_) return false;
    if (createError == ERROR_ALREADY_EXISTS) {
        CloseHandle(cryptoMapping_);
        cryptoMapping_ = nullptr;
        SetLastError(ERROR_ALREADY_EXISTS);
        return false;
    }
    crypto_ = static_cast<SharedCryptoProtection*>(
        MapViewOfFile(cryptoMapping_, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0,
                      sizeof(SharedCryptoProtection)));
    if (!crypto_) {
        CloseHandle(cryptoMapping_);
        cryptoMapping_ = nullptr;
        return false;
    }
    cryptoProtectionEnabled_.store(false, std::memory_order_release);
    InterlockedExchange(&crypto_->enabled, 0);
    // The controller is the single authoritative writer during startup. Reset
    // a mapping retained by DLLs from a previous controller instance.
    InterlockedExchange(&crypto_->guard, 1);
    crypto_->structureVersion = kCryptoProtectionVersion;
    crypto_->active = 0;
    crypto_->addressCount = 0;
    crypto_->writerProcessId = 0;
    crypto_->clipboardSequence = 0;
    crypto_->reserved = 0;
    crypto_->expiresAt = 0;
    ZeroMemory(crypto_->addresses, sizeof(crypto_->addresses));
    MemoryBarrier();
    InterlockedExchange(&crypto_->guard, 0);
    return true;
}

void PipeServer::PublishCryptoSetting(bool enabled, bool resetState) noexcept {
    if (!crypto_) {
        cryptoProtectionEnabled_.store(false, std::memory_order_release);
        return;
    }
    if (!enabled) InterlockedExchange(&crypto_->enabled, 0);
    const bool previous =
        cryptoProtectionEnabled_.load(std::memory_order_acquire);
    const bool published =
        InterlockedCompareExchange(&crypto_->enabled, 0, 0) != 0;
    if (!resetState && previous == enabled && published == enabled) return;
    for (int attempt = 0; attempt < 1024; ++attempt) {
        if (InterlockedCompareExchange(&crypto_->guard, 1, 0) == 0) {
            crypto_->structureVersion = kCryptoProtectionVersion;
            crypto_->active = 0;
            crypto_->addressCount = 0;
            crypto_->writerProcessId = 0;
            crypto_->clipboardSequence = 0;
            crypto_->reserved = 0;
            crypto_->expiresAt = 0;
            ZeroMemory(crypto_->addresses, sizeof(crypto_->addresses));
            InterlockedExchange(&crypto_->enabled, enabled ? 1 : 0);
            MemoryBarrier();
            InterlockedExchange(&crypto_->guard, 0);
            cryptoProtectionEnabled_.store(enabled, std::memory_order_release);
            return;
        }
        if ((attempt & 63) == 63)
            Sleep(1);
        else
            YieldProcessor();
    }
    cryptoProtectionEnabled_.store(false, std::memory_order_release);
}


bool PipeServer::Start(HWND notifyWnd, bool targetedMode, DWORD targetedPid) {
    if (listenThread_) return false;
    const bool sourceWasReady = sourceMapping_ && source_;
    const bool cryptoWasReady = cryptoMapping_ && crypto_;
    const bool stopEventWasReady = stopEvent_ != nullptr;
    auto rollbackStart = [&](DWORD error) {
        if (stopEvent_) SetEvent(stopEvent_);
        if (!stopEventWasReady && stopEvent_) {
            CloseHandle(stopEvent_);
            stopEvent_ = nullptr;
        }
        if (!cryptoWasReady) {
            if (crypto_) {
                UnmapViewOfFile(crypto_);
                crypto_ = nullptr;
            }
            if (cryptoMapping_) {
                CloseHandle(cryptoMapping_);
                cryptoMapping_ = nullptr;
            }
        }
        if (!sourceWasReady) {
            if (source_) {
                UnmapViewOfFile(source_);
                source_ = nullptr;
            }
            if (sourceMapping_) {
                CloseHandle(sourceMapping_);
                sourceMapping_ = nullptr;
            }
        }
        cryptoProtectionEnabled_.store(false, std::memory_order_release);
        wnd_.store(nullptr, std::memory_order_release);
        SetLastError(error);
    };

    wnd_.store(notifyWnd, std::memory_order_release);
    stop_.store(false, std::memory_order_release);
    accepting_.store(false, std::memory_order_release);
    targetedPid_ = targetedPid;
    targetedMode_ = targetedMode;
    {
        std::lock_guard<std::mutex> lock(confirmationsMu_);
        confirmations_.clear();
        confirmationTargets_.clear();
    }
    if (!EnsureSourceMapping()) {
        const DWORD error = GetLastError();
        rollbackStart(error);
        return false;
    }
    if (!EnsureCryptoMapping()) {
        const DWORD error = GetLastError();
        rollbackStart(error);
        return false;
    }
    const std::wstring stopEventName =
        ResolveObjectName(L"CLIP_TEST_STOP_EVENT", kStopEventName);
    if (!stopEvent_) {
        stopEvent_ = CreateLocalUserNamedEvent(stopEventName.c_str(), TRUE, FALSE);
        const DWORD createError = GetLastError();
        if (stopEvent_ && createError == ERROR_ALREADY_EXISTS) {
            CloseHandle(stopEvent_);
            stopEvent_ = nullptr;
            rollbackStart(ERROR_ALREADY_EXISTS);
            return false;
        }
    }

    if (!stopEvent_ || !ResetEvent(stopEvent_)) {
        const DWORD error = GetLastError();
        rollbackStart(error);
        return false;
    }
    try {
        std::lock_guard<std::mutex> lock(clientsMu_);
        clients_.reserve(512);
    } catch (...) {
        rollbackStart(ERROR_NOT_ENOUGH_MEMORY);
        return false;
    }
    std::string initialRules = ExtendedRulesMessage(g_app.cfg.rules, 4);
    std::string initialRulesV3 = ExtendedRulesMessage(g_app.cfg.rules, 3);
    std::string initialRulesV2 = ExtendedRulesMessage(g_app.cfg.rules, 2);
    std::string initialLegacyRules = LegacyRulesMessage(g_app.cfg.rules);
    std::unordered_map<std::wstring, BYTE> initialNotificationRules;
    bool notificationRulesReady = true;
    try {
        initialNotificationRules = NotificationRuleMap(g_app.cfg.rules);
    } catch (...) {
        notificationRulesReady = false;
    }
    if (initialRules.empty() || initialRulesV3.empty() ||
        initialRulesV2.empty() ||
        initialLegacyRules.empty() || !notificationRulesReady) {
        rollbackStart(ERROR_NOT_ENOUGH_MEMORY);
        return false;
    }
    {
        std::lock_guard<std::mutex> lock(stateMu_);
        shuttingDown_ = false;
        rulesMsg_ = std::move(initialRules);
        rulesV3Msg_ = std::move(initialRulesV3);
        rulesV2Msg_ = std::move(initialRulesV2);
        legacyRulesMsg_ = std::move(initialLegacyRules);
        pauseMsg_ = PauseMessage(g_app.paused);
        settingsMsg_ = SettingsMessage(g_app.cfg.settings, true);
        settingsCryptoMsg_ = SettingsMessage(g_app.cfg.settings, true, true);
        settingsSnapshotMsg_ =
            SettingsMessage(g_app.cfg.settings, true, true, true);
        settingsShortcutPolicyMsg_ =
            SettingsMessage(g_app.cfg.settings, true, true, true, true);
        settingsIgnoreCustomMsg_ =
            SettingsMessage(g_app.cfg.settings, true, true, true, true, true);
        legacySettingsMsg_ = SettingsMessage(g_app.cfg.settings, false);

        notificationActionsByRule_ = std::move(initialNotificationRules);
        modernFormatsEnabled_.store(
            HasModernFormatRule(g_app.cfg.rules), std::memory_order_release);
        logVisibilityRequired_.store(
            g_app.cfg.settings.ignoreCustomFormats ||
                HasHiddenLogRule(g_app.cfg.rules),
            std::memory_order_release);
        stateVersion_ = 1;
    }
    previewEnabled_.store(g_app.cfg.settings.previewEnabled,
                          std::memory_order_release);
    shortcutPolicyRequired_.store(
        g_app.cfg.settings.shortcutDirectAllow ||
            g_app.cfg.settings.shortcutOnlyMode ||
            g_app.cfg.settings.cryptoProtection,
        std::memory_order_release);

    HANDLE firstPipe = CreatePipe(true);
    if (firstPipe == INVALID_HANDLE_VALUE) {
        const DWORD error = GetLastError();
        rollbackStart(error);
        return false;
    }
    {
        std::lock_guard<std::mutex> lock(listenMu_);
        initialPipe_ = firstPipe;
    }
    listenThread_ = CreateThread(nullptr, 0, ListenThreadStatic, this, 0, nullptr);
    if (!listenThread_) {
        const DWORD error = GetLastError();
        CloseHandle(firstPipe);
        {
            std::lock_guard<std::mutex> lock(listenMu_);
            initialPipe_ = INVALID_HANDLE_VALUE;
        }
        rollbackStart(error);
        return false;
    }
    PublishCryptoSetting(g_app.cfg.settings.cryptoProtection && !g_app.paused,
                         true);
    accepting_.store(true, std::memory_order_release);
    return true;
}

void PipeServer::Stop() {
    PublishCryptoSetting(false, true);
    if (!listenThread_) return;
    // Prevent late worker notifications from targeting a window that is being
    // torn down. The pipe threads only use this atomic snapshot for PostMessage.
    const HWND notifyWnd = wnd_.exchange(nullptr, std::memory_order_acq_rel);
    bool cancelledConfirmations = false;
    {
        std::lock_guard<std::mutex> lock(confirmationsMu_);
        for (const auto& target : confirmationTargets_) {
            try {
                cancelledConfirmations_.push_back(target.first);
                cancelledConfirmations = true;
            } catch (...) {
                // Preserve bounded shutdown under memory pressure. Passing the
                // request ID avoids leaving the modeless window open if the
                // cancellation queue cannot grow.
                if (notifyWnd)
                    PostMessageW(notifyWnd, kMsgConfirmation, target.first, 0);
            }
        }
        confirmationTargets_.clear();
        confirmations_.clear();
    }
    if (cancelledConfirmations && notifyWnd)
        PostMessageW(notifyWnd, kMsgConfirmation, 0, 0);
    // Stop accepting new clients immediately. Existing clients still get the
    // shutdown frame and have a bounded window to acknowledge it.
    accepting_.store(false, std::memory_order_release);

    // Publish shuttingDown_ before stop_: a client can observe stop_ and exit
    // without sending its shutdown ACK if these stores happen in the reverse
    // order.
    unsigned long long shutdownVersion = 0;
    {
        std::lock_guard<std::mutex> lock(stateMu_);
        shuttingDown_ = true;
        shutdownVersion = ++stateVersion_;
    }
    stop_.store(true, std::memory_order_release);

    HANDLE initial = INVALID_HANDLE_VALUE;
    {
        std::lock_guard<std::mutex> lock(listenMu_);
        initial = initialPipe_;
    }
    if (initial != INVALID_HANDLE_VALUE) CancelIoEx(initial, nullptr);
    const std::wstring pipeName =
        ResolveObjectName(L"CLIP_TEST_PIPE_NAME", kPipeName);
    HANDLE wake = CreateFileW(pipeName.c_str(), GENERIC_READ | GENERIC_WRITE, 0,
                              nullptr, OPEN_EXISTING, 0, nullptr);
    if (wake != INVALID_HANDLE_VALUE) CloseHandle(wake);

    // Give each worker enough time to remove Detours, finish call rundown, and
    // return its ACK; unloading a system hook before that is unsafe.
    ULONGLONG deadline = GetTickCount64() + 5000;
    for (;;) {
        ReapClients();
        bool delivered = true;
        {
        std::lock_guard<std::mutex> lock(clientsMu_);
            for (ClientCtx* ctx : clients_) {
                if (ctx->deliveredVersion.load(std::memory_order_acquire) <
                    shutdownVersion ||
                    !ctx->shutdownAck.load(std::memory_order_acquire)) {
                    delivered = false;
                    break;
                }
            }
        }
        if (delivered || GetTickCount64() >= deadline) break;
        Sleep(10);
    }
    HANDLE listener = listenThread_;
    DWORD listenerResult = WaitForSingleObject(listener, 5000);
    if (listenerResult != WAIT_OBJECT_0) {
        CancelSynchronousIo(listener);
        // Keep the handle and object ownership if cancellation is slow. The
        // UI stop remains bounded; the destructor performs the final wait.
        listenerResult = WaitForSingleObject(listener, 2000);
    }
    if (listenerResult == WAIT_OBJECT_0) CloseHandle(listener);
    if (listenerResult == WAIT_OBJECT_0) listenThread_ = nullptr;
    SetEvent(stopEvent_);
    StopClients(false);
    {
        std::lock_guard<std::mutex> lock(eventsMu_);
        events_.clear();
        eventsSnapshotBytes_ = 0;
        serverDroppedEvents_ = 0;
    }
}

void PipeServer::BroadcastRules(const std::vector<Rule>& rules) {
    std::string message = ExtendedRulesMessage(rules, 4);
    std::string messageV3 = ExtendedRulesMessage(rules, 3);
    std::string messageV2 = ExtendedRulesMessage(rules, 2);
    std::string legacyMessage = LegacyRulesMessage(rules);
    std::unordered_map<std::wstring, BYTE> notificationRules;
    try {
        notificationRules = NotificationRuleMap(rules);
    } catch (...) {
        return;
    }
    if (message.empty() || messageV3.empty() || messageV2.empty() ||
        legacyMessage.empty())
        return;
    std::lock_guard<std::mutex> lock(stateMu_);
    rulesMsg_ = std::move(message);
    rulesV3Msg_ = std::move(messageV3);
    rulesV2Msg_ = std::move(messageV2);
    legacyRulesMsg_ = std::move(legacyMessage);
    notificationActionsByRule_ = std::move(notificationRules);
    modernFormatsEnabled_.store(HasModernFormatRule(rules),
                                std::memory_order_release);
    logVisibilityRequired_.store(
        g_app.cfg.settings.ignoreCustomFormats || HasHiddenLogRule(rules),
        std::memory_order_release);
    ++stateVersion_;
}

void PipeServer::BroadcastPause(bool paused) {
    PublishCryptoSetting(g_app.cfg.settings.cryptoProtection && !paused, true);
    std::lock_guard<std::mutex> lock(stateMu_);
    pauseMsg_ = PauseMessage(paused);
    ++stateVersion_;
}

void PipeServer::BroadcastSettings(const Settings& settings) {
    previewEnabled_.store(settings.previewEnabled, std::memory_order_release);
    shortcutPolicyRequired_.store(
        settings.shortcutDirectAllow || settings.shortcutOnlyMode ||
            settings.cryptoProtection,
        std::memory_order_release);
    logVisibilityRequired_.store(
        settings.ignoreCustomFormats || HasHiddenLogRule(g_app.cfg.rules),
        std::memory_order_release);
    PublishCryptoSetting(settings.cryptoProtection && !g_app.paused);
    std::lock_guard<std::mutex> lock(stateMu_);
    settingsMsg_ = SettingsMessage(settings, true);
    settingsCryptoMsg_ = SettingsMessage(settings, true, true);
    settingsSnapshotMsg_ = SettingsMessage(settings, true, true, true);
    settingsShortcutPolicyMsg_ =
        SettingsMessage(settings, true, true, true, true);
    settingsIgnoreCustomMsg_ =
        SettingsMessage(settings, true, true, true, true, true);
    legacySettingsMsg_ = SettingsMessage(settings, false);

    ++stateVersion_;
}
bool PipeServer::PopEvent(LogRow& event) {
    std::lock_guard<std::mutex> lock(eventsMu_);
    if (events_.empty()) {
        if (serverDroppedEvents_ == 0) return false;
        event = LogRow{};
        event.gap = true;
        event.missingEvents = serverDroppedEvents_;
        serverDroppedEvents_ = 0;
        GetLocalTime(&event.time);
        return true;
    }
    event = std::move(events_.front());
    eventsSnapshotBytes_ -=
        (std::min)(eventsSnapshotBytes_, event.snapshot.size());
    events_.pop_front();
    return true;
}

bool PipeServer::PopConfirmation(AccessConfirmationRequest& request) {
    std::lock_guard<std::mutex> lock(confirmationsMu_);
    if (confirmations_.empty()) return false;
    request = std::move(confirmations_.front());
    confirmations_.pop_front();
    return true;
}

bool PipeServer::PopCancelledConfirmation(DWORD& requestId) {
    std::lock_guard<std::mutex> lock(confirmationsMu_);
    if (cancelledConfirmations_.empty()) return false;
    requestId = cancelledConfirmations_.front();
    cancelledConfirmations_.pop_front();
    return true;
}

bool PipeServer::QueueConfirmationResponse(ClientCtx* ctx,
                                           unsigned long long token,
                                           bool allow) {
    if (!ctx) return false;
    try {
        std::lock_guard<std::mutex> lock(ctx->responsesMu);
        if (ctx->responses.size() >= 256) return false;
        ctx->responses.push_back({token, allow});
        return true;
    } catch (...) {
        return false;
    }
}

bool PipeServer::AcceptInboundBytes(size_t bytes) noexcept {
    try {
        std::lock_guard<std::mutex> lock(inboundRateMu_);
        const ULONGLONG now = GetTickCount64();
        if (now - inboundRateWindowStart_ >= 1000) {
            inboundRateWindowStart_ = now;
            inboundRateBytes_ = 0;
        }
        if (bytes > kGlobalInboundBytesPerSecond -
                        (std::min)(inboundRateBytes_,
                                   kGlobalInboundBytesPerSecond))
            return false;
        inboundRateBytes_ += bytes;
        return true;
    } catch (...) {
        return false;
    }
}

bool PipeServer::QueueConfirmation(ClientCtx* ctx,
                                   AccessConfirmationRequest request,
                                   unsigned long long token) {
    if (!ctx) return false;
    const DWORD next = nextConfirmationId_.fetch_add(1,
                                                      std::memory_order_relaxed);
    request.id = next ? next : nextConfirmationId_.fetch_add(
                                  1, std::memory_order_relaxed);
    const DWORD requestId = request.id;
    request.processId = ctx->pid;
    request.path = ctx->path;
    const size_t slash = request.path.find_last_of(L"\\/");
    request.process = slash == std::wstring::npos
                          ? request.path
                          : request.path.substr(slash + 1);
    if (request.process.empty())
        request.process = L"PID " + std::to_wstring(ctx->pid);

    try {
        std::lock_guard<std::mutex> lock(confirmationsMu_);
        if (confirmationTargets_.size() >= 256 || confirmations_.size() >= 256)
            return false;
        const auto inserted = confirmationTargets_.emplace(
            requestId, ConfirmationTarget{ctx->connectionId, token});
        if (!inserted.second) return false;
        try {
            confirmations_.push_back(std::move(request));
        } catch (...) {
            confirmationTargets_.erase(requestId);
            throw;
        }
    } catch (...) {
        return false;
    }

    HWND wnd = wnd_.load(std::memory_order_acquire);
    if (wnd && PostMessageW(wnd, kMsgConfirmation, 0, 0)) return true;

    std::lock_guard<std::mutex> lock(confirmationsMu_);
    auto target = confirmationTargets_.find(requestId);
    if (target != confirmationTargets_.end()) confirmationTargets_.erase(target);
    auto queued = std::find_if(
        confirmations_.begin(), confirmations_.end(),
        [requestId](const AccessConfirmationRequest& item) {
            return item.id == requestId;
        });
    if (queued != confirmations_.end()) confirmations_.erase(queued);
    return false;
}

bool PipeServer::ResolveConfirmation(DWORD requestId, bool allow) {
    ConfirmationTarget target;
    {
        std::lock_guard<std::mutex> lock(confirmationsMu_);
        const auto found = confirmationTargets_.find(requestId);
        if (found == confirmationTargets_.end()) return false;
        target = found->second;
        confirmationTargets_.erase(found);
    }

    std::lock_guard<std::mutex> clientsLock(clientsMu_);
    for (ClientCtx* ctx : clients_) {
        if (ctx->connectionId == target.connectionId)
            return QueueConfirmationResponse(ctx, target.token, allow);
    }
    return false;
}

void PipeServer::CancelClientConfirmations(
    unsigned long long connectionId) {
    bool changed = false;
    bool queuedCancellation = false;
    const HWND wnd = wnd_.load(std::memory_order_acquire);
    {
        std::lock_guard<std::mutex> lock(confirmationsMu_);
        for (auto it = confirmationTargets_.begin();
             it != confirmationTargets_.end();) {
            if (it->second.connectionId != connectionId) {
                ++it;
                continue;
            }
            try {
                cancelledConfirmations_.push_back(it->first);
                queuedCancellation = true;
            } catch (...) {
                if (wnd)
                    PostMessageW(wnd, kMsgConfirmation, it->first, 0);
            }
            it = confirmationTargets_.erase(it);
            changed = true;
        }
        if (changed) {
            confirmations_.erase(
                std::remove_if(
                    confirmations_.begin(), confirmations_.end(),
                    [this](const AccessConfirmationRequest& request) {
                        return confirmationTargets_.find(request.id) ==
                               confirmationTargets_.end();
                    }),
                confirmations_.end());
        }
    }
    if (queuedCancellation && wnd)
        PostMessageW(wnd, kMsgConfirmation, 0, 0);
}

bool PipeServer::QueueLogRow(LogRow row) noexcept {
    try {
        std::lock_guard<std::mutex> lock(eventsMu_);
        if (events_.size() >= 8192) {
            const bool important = row.gap || row.blocked ||
                                   row.showNotification ||
                                   row.action == kRuleConfirm;
            auto victim = events_.end();
            if (important) {
                victim = std::find_if(events_.begin(), events_.end(),
                                      [](const LogRow& queued) {
                    return !queued.gap && !queued.blocked &&
                           queued.action == kRuleSilent;
                });
            }
            if (victim != events_.end()) {
                eventsSnapshotBytes_ -=
                    (std::min)(eventsSnapshotBytes_, victim->snapshot.size());
                serverDroppedEvents_ += victim->missingEvents + 1;
                events_.erase(victim);
            } else {
                serverDroppedEvents_ +=
                    row.missingEvents + (row.gap ? 0 : 1);
                return true;
            }
        }
        row.missingEvents += serverDroppedEvents_;
        serverDroppedEvents_ = 0;
        if (!row.snapshot.empty() &&
            row.snapshot.size() >
                kQueuedSnapshotBytesCapacity -
                    (std::min)(eventsSnapshotBytes_,
                               kQueuedSnapshotBytesCapacity)) {
            std::vector<BYTE>().swap(row.snapshot);
            row.snapshotKind = kSnapshotDiscarded;
        }
        const size_t snapshotBytes = row.snapshot.size();
        events_.push_back(std::move(row));
        eventsSnapshotBytes_ += snapshotBytes;
        return true;
    } catch (...) {
        std::lock_guard<std::mutex> lock(eventsMu_);
        serverDroppedEvents_ += row.missingEvents + (row.gap ? 0 : 1);
        return true;
    }
}

bool PipeServer::IsTargetConnected(DWORD processId) {
    std::lock_guard<std::mutex> lock(clientsMu_);
    for (ClientCtx* client : clients_) {
        if (client->pid == processId && client->thread &&
            WaitForSingleObject(client->thread, 0) == WAIT_TIMEOUT)
            return true;
    }
    return false;
}

bool PipeServer::IsTargetStateDelivered(DWORD processId) {
    std::lock_guard<std::mutex> lock(clientsMu_);
    for (ClientCtx* client : clients_) {
        if (client->pid == processId &&
            client->deliveredVersion.load(std::memory_order_acquire) != 0 &&
            client->thread &&
            WaitForSingleObject(client->thread, 0) == WAIT_TIMEOUT)
            return true;
    }
    return false;
}

bool PipeServer::QueuePrivateClipboard(DWORD processId, const std::wstring& mappingName) {
    std::lock_guard<std::mutex> lock(clientsMu_);
    for (ClientCtx* ctx : clients_) {
        if (ctx->pid != processId || !ctx->stateReady.load(std::memory_order_acquire) ||
            !ctx->privateClipboardCapable.load(std::memory_order_acquire) ||
            ctx->finished.load() || !ctx->thread || WaitForSingleObject(ctx->thread, 0) != WAIT_TIMEOUT)
            continue;
        std::string payload, frame;
        PutWStr(payload, mappingName);
        PutFrame(frame, kIpcPrivateClipboard, payload);
        std::lock_guard<std::mutex> queueLock(ctx->responsesMu);
        if (ctx->privateRequests.size() >= 2) return false;
        ctx->privateRequests.push_back(std::move(frame));
        return true;
    }
    return false;
}

bool PipeServer::IsTargetReady(DWORD processId) {
    std::lock_guard<std::mutex> lock(clientsMu_);
    for (ClientCtx* client : clients_) {
        if (client->pid == processId &&
            client->stateReady.load(std::memory_order_acquire) &&
            client->thread &&
            WaitForSingleObject(client->thread, 0) == WAIT_TIMEOUT)
            return true;
    }
    return false;
}

std::vector<ReadyProcessIdentity> PipeServer::ReadyProcessIdentities() {
    std::vector<ReadyProcessIdentity> result;
    std::lock_guard<std::mutex> lock(clientsMu_);
    try {
        result.reserve(clients_.size());
        for (ClientCtx* client : clients_) {
            if (client->creationTime != 0 &&
                client->stateReady.load(std::memory_order_acquire) &&
                client->thread &&
                WaitForSingleObject(client->thread, 0) == WAIT_TIMEOUT) {
                result.push_back({client->pid, client->creationTime});
            }
        }
    } catch (...) {
        result.clear();
    }
    return result;
}

HANDLE PipeServer::CreatePipe(bool firstInstance) {
    DWORD openMode = PIPE_ACCESS_DUPLEX;
    if (firstInstance) openMode |= FILE_FLAG_FIRST_PIPE_INSTANCE;

    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!CreateLocalUserSecurityDescriptor(&descriptor))
        return INVALID_HANDLE_VALUE;
    SECURITY_ATTRIBUTES security = {sizeof(security), descriptor, FALSE};
    const std::wstring pipeName =
        ResolveObjectName(L"CLIP_TEST_PIPE_NAME", kPipeName);

    HANDLE pipe = CreateNamedPipeW(
        pipeName.c_str(), openMode,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
        PIPE_UNLIMITED_INSTANCES,
        64 * 1024, 64 * 1024, 0, &security);
    LocalFree(descriptor);
    return pipe;
}

DWORD WINAPI PipeServer::ListenThreadStatic(LPVOID self) {
    auto* server = static_cast<PipeServer*>(self);
    __try {
        return server->ListenThreadNoThrow();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        server->stop_.store(true, std::memory_order_release);
        return GetExceptionCode();
    }
}

DWORD PipeServer::ListenThreadNoThrow() noexcept {
    try {
        return ListenThread();
    } catch (...) {
        stop_.store(true, std::memory_order_release);
        return ERROR_UNHANDLED_EXCEPTION;
    }
}

DWORD PipeServer::ListenThread() {
    HANDLE pipe = INVALID_HANDLE_VALUE;
    {
        std::lock_guard<std::mutex> lock(listenMu_);
        pipe = initialPipe_;
    }
    while (!stop_.load(std::memory_order_acquire)) {
        if (pipe == INVALID_HANDLE_VALUE) {
            pipe = CreatePipe(false);
            if (pipe == INVALID_HANDLE_VALUE) {
                Sleep(100);
                continue;
            }
        }
        {
            std::lock_guard<std::mutex> lock(listenMu_);
            initialPipe_ = pipe;
        }

        BOOL connected = ConnectNamedPipe(pipe, nullptr)
                            ? TRUE
                            : (GetLastError() == ERROR_PIPE_CONNECTED);
        {
            std::lock_guard<std::mutex> lock(listenMu_);
            if (initialPipe_ == pipe) initialPipe_ = INVALID_HANDLE_VALUE;
        }

        if (stop_.load(std::memory_order_acquire) ||
            !accepting_.load(std::memory_order_acquire)) {
            CloseHandle(pipe);
            pipe = INVALID_HANDLE_VALUE;
            break;
        }
        if (!connected) {
            CloseHandle(pipe);
            pipe = INVALID_HANDLE_VALUE;
            continue;
        }

        ReapClients();
        {
            std::lock_guard<std::mutex> lock(clientsMu_);
            if (clients_.size() >= 512) {
                DisconnectNamedPipe(pipe);
                CloseHandle(pipe);
                pipe = INVALID_HANDLE_VALUE;
                continue;
            }
        }
        ULONG pid = 0;
        if (!GetNamedPipeClientProcessId(pipe, &pid) || pid == 0) {
            CloseHandle(pipe);
            pipe = INVALID_HANDLE_VALUE;
            continue;
        }
        if ((targetedMode_ && (targetedPid_ == 0 || pid != targetedPid_))) {
            DisconnectNamedPipe(pipe);
            CloseHandle(pipe);
            pipe = INVALID_HANDLE_VALUE;
            continue;
        }
        DWORD serverSession = 0;
        DWORD clientSession = 0;
        if (!ProcessIdToSessionId(GetCurrentProcessId(), &serverSession) ||
            !GetNamedPipeClientSessionId(pipe, &clientSession) ||
            serverSession != clientSession) {
            DisconnectNamedPipe(pipe);
            CloseHandle(pipe);
            pipe = INVALID_HANDLE_VALUE;
            continue;
        }
        auto* ctx = new (std::nothrow) ClientCtx;
        if (!ctx) {
            CloseHandle(pipe);
            pipe = INVALID_HANDLE_VALUE;
            continue;
        }
        ctx->self = this;
        ctx->pipe = pipe;
        ctx->pid = pid;
        ctx->connectionId = nextConnectionId_.fetch_add(
            1, std::memory_order_relaxed);
        HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (process) {
            try {
                ProcessImagePath(process, ctx->path);
                ProcessCreationTime(process, ctx->creationTime);
            } catch (...) {
                // 路径只用于显示/规则审计；内存不足时保留可信 PID 并继续。
            }
            CloseHandle(process);
        }

        ctx->thread = CreateThread(nullptr, 0, ClientThreadStatic, ctx, 0, nullptr);
        if (!ctx->thread) {
            CloseHandle(ctx->pipe);
            delete ctx;
        } else {
            {
                std::lock_guard<std::mutex> lock(clientsMu_);
                clients_.push_back(ctx);
                PostClientCountLocked();
            }
        }
        pipe = INVALID_HANDLE_VALUE;
        ReapClients();
    }
    if (pipe != INVALID_HANDLE_VALUE) CloseHandle(pipe);
    return 0;
}

DWORD WINAPI PipeServer::ClientThreadStatic(LPVOID param) {
    auto* ctx = static_cast<ClientCtx*>(param);
    DWORD result = 0;
    __try {
        result = ctx->self->ClientThreadNoThrow(ctx);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DisconnectNamedPipe(ctx->pipe);
        result = GetExceptionCode();
    }
    ctx->self->CancelClientConfirmations(ctx->connectionId);
    ctx->self->ClientFinished(ctx);
    return result;
}

DWORD PipeServer::ClientThreadNoThrow(ClientCtx* ctx) noexcept {
    try {
        return ClientThread(ctx);
    } catch (...) {
        DisconnectNamedPipe(ctx->pipe);
        return ERROR_UNHANDLED_EXCEPTION;
    }
}

DWORD PipeServer::ClientThread(ClientCtx* ctx) {
    HANDLE pipe = ctx->pipe;
    std::string input;
    ULONGLONG partialSince = 0;
    ULONGLONG inboundWindowStart = GetTickCount64();
    size_t inboundWindowBytes = 0;
    auto acceptInbound = [&](DWORD bytes) {
        const ULONGLONG now = GetTickCount64();
        if (now - inboundWindowStart >= 1000) {
            inboundWindowStart = now;
            inboundWindowBytes = 0;
        }
        if (bytes > kClientInboundBytesPerSecond -
                        (std::min)(inboundWindowBytes,
                                   kClientInboundBytesPerSecond))
            return false;
        inboundWindowBytes += bytes;
        return AcceptInboundBytes(bytes);
    };
    char buffer[64 * 1024];
    for (;;) {
        OutboundState state;
        {
            std::lock_guard<std::mutex> lock(stateMu_);
            state.version = stateVersion_;
            state.shuttingDown = shuttingDown_;
            state.modernFormatsRequired = modernFormatsEnabled_.load(
                std::memory_order_acquire);
            state.changed =
                ctx->deliveredVersion.load(std::memory_order_acquire) !=
                state.version;
            if (state.changed && !state.shuttingDown) {
                state.rules = rulesMsg_;
                state.rulesV3 = rulesV3Msg_;
                state.rulesV2 = rulesV2Msg_;
                state.legacyRules = legacyRulesMsg_;
                state.pause = pauseMsg_;
                state.settings = settingsMsg_;
                state.settingsCrypto = settingsCryptoMsg_;
                state.settingsSnapshot = settingsSnapshotMsg_;
                state.settingsShortcutPolicy = settingsShortcutPolicyMsg_;
                state.settingsIgnoreCustom = settingsIgnoreCustomMsg_;
                state.legacySettings = legacySettingsMsg_;

            }
        }

        if (state.shuttingDown) {
            if (WriteAll(pipe, ShutdownMessage())) {
                // Wait for fail-open, Detour removal, and call rundown before
                // allowing the injector to remove its system hook.
                ULONGLONG deadline = GetTickCount64() + 3000;
                while (GetTickCount64() < deadline) {
                    DWORD available = 0;
                    if (!PeekNamedPipe(pipe, nullptr, 0, nullptr, &available, nullptr)) break;
                    if (available > 0) {
                        DWORD want = (std::min)(available, (DWORD)sizeof(buffer));
                        DWORD got = 0;
                        if (!ReadFile(pipe, buffer, want, &got, nullptr) || got == 0)
                            break;
                        input.append(buffer, got);
                        if (input.size() > kIpcMaxPayload + kIpcFrameHeaderSize) break;
                        size_t offset = 0;
                        while (offset < input.size()) {
                            IpcFrameView frame;
                            const IpcFrameResult result = ParseFrame(
                                input.data() + offset, input.size() - offset,
                                frame);
                            if (result == IpcFrameResult::incomplete) break;
                            if (result == IpcFrameResult::invalid) {
                                offset += frame.consumed
                                              ? frame.consumed
                                              : 1;
                                continue;
                            }
                            offset += frame.consumed;
                            if (frame.type == kIpcShutdownAck &&
                                frame.payloadSize == 0)
                                ctx->shutdownAck.store(true, std::memory_order_release);
                        }
                        input.erase(0, offset);
                        if (ctx->shutdownAck.load(std::memory_order_acquire)) break;
                    }
                    Sleep(10);
                }
            }
            if (input.size() > kIpcMaxPayload + kIpcFrameHeaderSize) break;
            ctx->deliveredVersion.store(state.version,
                                        std::memory_order_release);
            break;
        }
        if (stop_.load(std::memory_order_acquire)) {
            // Stop publishes shuttingDown_ first, but this client may have
            // captured its snapshot just before that publication.
            std::lock_guard<std::mutex> lock(stateMu_);
            if (shuttingDown_) continue;
            break;
        }
        if (state.changed) {
            const bool extended =
                ctx->extendedCapable.load(std::memory_order_acquire);
            const bool notification =
                ctx->notificationCapable.load(std::memory_order_acquire);
            const bool formatModel =
                ctx->formatModelCapable.load(std::memory_order_acquire);
            const bool cryptoSettings =
                ctx->cryptoSettingsCapable.load(std::memory_order_acquire);
            const bool snapshots =
                ctx->snapshotCapable.load(std::memory_order_acquire);
            const bool shortcutPolicy =
                ctx->shortcutPolicyCapable.load(std::memory_order_acquire);
            const bool ignoreCustom =
                ctx->ignoreCustomCapable.load(std::memory_order_acquire);
            const bool logVisibility =
                ctx->logVisibilityCapable.load(std::memory_order_acquire);
            const bool sendExtended =
                extended &&
                (!state.modernFormatsRequired || formatModel);
            std::string& selectedRules =
                sendExtended
                    ? (logVisibility
                           ? state.rules
                           : notification ? state.rulesV3 : state.rulesV2)
                    : state.legacyRules;
            std::string* selectedSettings = &state.legacySettings;
            if (sendExtended) {
                if (ignoreCustom)
                    selectedSettings = &state.settingsIgnoreCustom;
                else if (shortcutPolicy)
                    selectedSettings = &state.settingsShortcutPolicy;
                else if (snapshots)
                    selectedSettings = &state.settingsSnapshot;
                else if (cryptoSettings)
                    selectedSettings = &state.settingsCrypto;
                else
                    selectedSettings = &state.settings;
            }

            std::string begin;
            std::string metadataSettings;
            if (sendExtended && logVisibility && ignoreCustom &&
                ctx->textMetadataCapable.load(std::memory_order_acquire)) {
                std::string payload(selectedSettings->data() + kIpcFrameHeaderSize,
                    selectedSettings->size() - kIpcFrameHeaderSize);
                PutU8(payload, 1);
                PutFrame(metadataSettings, kIpcSettings, payload);
                selectedSettings = &metadataSettings;
            }
            PutFrame(begin, kIpcStateBegin);
            ctx->stateReady.store(false, std::memory_order_release);
            ctx->sentExtended.store(sendExtended,
                                    std::memory_order_release);
            ctx->sentLogVisibility.store(
                sendExtended && logVisibility, std::memory_order_release);
            if (!WriteAll(pipe, begin) || !WriteAll(pipe, selectedRules) ||
                !WriteAll(pipe, state.pause) ||
                !WriteAll(pipe, *selectedSettings))
                break;
            ctx->deliveredVersion.store(state.version,
                                        std::memory_order_release);
        }

        std::deque<std::string> privateRequests;
        std::deque<ConfirmationResponse> responses;
        {
            std::lock_guard<std::mutex> lock(ctx->responsesMu);
            responses.swap(ctx->responses);
            privateRequests.swap(ctx->privateRequests);
        }
        bool responseWriteFailed = false;
        for (const auto& response : responses) {
            if (!WriteAll(pipe, ConfirmationResponseMessage(
                                    response.token, response.allow))) {
                responseWriteFailed = true;
                break;
            }
        }
        if (responseWriteFailed) break;
        for (const auto& request : privateRequests) {
            if (!WriteAll(pipe, request)) { responseWriteFailed = true; break; }
        }
        if (responseWriteFailed) break;

        DWORD available = 0;
        if (!PeekNamedPipe(pipe, nullptr, 0, nullptr, &available, nullptr)) break;
        if (available > 0) {
            DWORD want = (std::min)(available, (DWORD)sizeof(buffer));
            DWORD got = 0;
            if (!ReadFile(pipe, buffer, want, &got, nullptr) || got == 0) break;
            if (!acceptInbound(got)) break;
            input.append(buffer, got);

            size_t offset = 0;
            while (offset < input.size()) {
                IpcFrameView frame;
                const IpcFrameResult result = ParseFrame(
                    input.data() + offset, input.size() - offset, frame);
                if (result == IpcFrameResult::incomplete) break;
                if (result == IpcFrameResult::invalid) {
                    offset += frame.consumed ? frame.consumed : 1;
                    continue;
                }
                if (frame.type == kIpcStateAck) {
                    const bool sentExtended =
                        ctx->sentExtended.load(std::memory_order_acquire);
                    StateAck ack;
                    // Empty/invalid ACKs cannot prove extended-rule support.
                    if (ParseStateAck(frame.payload, frame.payloadSize, ack)) {
                        const unsigned version = ack.version;
                        ctx->textMetadataCapable.store(ack.HasTextMetadata(),
                                                       std::memory_order_release);
                        ctx->privateClipboardCapable.store(
                            (ack.flags & kStateAckPrivateClipboardAvailable) != 0,
                            std::memory_order_release);
                        ctx->extendedCapable.store(true, std::memory_order_release);
                        ctx->notificationCapable.store(version >= 3, std::memory_order_release);
                        ctx->formatModelCapable.store(version >= 6, std::memory_order_release);
                        ctx->cryptoSettingsCapable.store(version >= 7, std::memory_order_release);
                        ctx->cryptoEventCapable.store(version >= 8, std::memory_order_release);
                        ctx->snapshotCapable.store(version >= 9, std::memory_order_release);
                        ctx->shortcutPolicyCapable.store(version >= 10, std::memory_order_release);
                        ctx->ignoreCustomCapable.store(version >= 11, std::memory_order_release);
                        ctx->logVisibilityCapable.store(version >= 12, std::memory_order_release);
                        const bool formatsReady =
                            !modernFormatsEnabled_.load(std::memory_order_acquire) || version >= 6;
                        if (ack.extendedApplied && sentExtended) {
                            const bool cryptoReady =
                                !cryptoProtectionEnabled_.load(std::memory_order_acquire) ||
                                ack.HasCryptoMapping();
                            const bool shortcutPolicyReady =
                                !shortcutPolicyRequired_.load(std::memory_order_acquire) || version >= 10;
                            const bool logVisibilityReady =
                                !logVisibilityRequired_.load(std::memory_order_acquire) || version >= 12;
                            ctx->stateReady.store(
                                cryptoReady && formatsReady && shortcutPolicyReady && logVisibilityReady,
                                std::memory_order_release);
                        } else if (!ack.extendedApplied && !sentExtended && formatsReady) {
                            ctx->deliveredVersion.store(0, std::memory_order_release);
                        }
                    }
                    offset += frame.consumed;
                    continue;
                }
                if (frame.type == kIpcConfirmRequest) {
                    Reader requestReader(frame.payload, frame.payloadSize);
                    AccessConfirmationRequest request;
                    unsigned long long token = 0;
                    BYTE operation = 0;
                    BYTE timeoutBlock = 0;
                    DWORD format = 0;
                    bool valid =
                        requestReader.GetU64(token) && token != 0 &&
                        requestReader.GetU8(operation) &&
                        operation <= kOpWrite &&
                        requestReader.GetU32(format) &&
                        requestReader.GetU32(request.sourceProcessId) &&
                        requestReader.GetWStr(request.sourceProcess) &&
                        requestReader.GetWStr(request.sourcePath) &&
                        requestReader.GetWStr(request.ruleName) &&
                        requestReader.GetWStr(request.preview) &&
                        requestReader.GetU32(request.timeoutMs) &&
                        requestReader.GetU8(timeoutBlock) &&
                        timeoutBlock <= 1 &&
                        request.sourceProcess.size() <= 260 &&
                        request.sourcePath.size() <= 32768 &&
                        request.ruleName.size() <= 128 &&
                        request.preview.size() <= 300 &&
                        request.timeoutMs >= 1000 &&
                        request.timeoutMs <= 60000;
                    if (valid && requestReader.n != 0) {
                        BYTE kind = 0;
                        valid = ctx->textMetadataCapable.load(std::memory_order_acquire) &&
                            requestReader.GetU8(kind) && kind <= static_cast<BYTE>(PreviewKind::Truncated);
                        request.previewKind = static_cast<PreviewKind>(kind);
                    }
                    valid = valid && requestReader.n == 0;
                    offset += frame.consumed;
                    if (!valid) continue;
                    request.operation = static_cast<ClipOp>(operation);
                    request.format = format;
                    request.timeoutBlock = timeoutBlock != 0;
                    const bool fallbackAllow = !request.timeoutBlock;
                    if (!QueueConfirmation(ctx, std::move(request), token))
                        QueueConfirmationResponse(ctx, token, fallbackAllow);
                    continue;
                }
                if (frame.type != kIpcEvent && frame.type != kIpcEventGap) {
                    offset += frame.consumed;
                    continue;
                }
                LogRow row;
                if (frame.type == kIpcEventGap) {
                    Reader gap(frame.payload, frame.payloadSize);
                    DWORD pid = 0;
                    unsigned long long missing = 0;
                    offset += frame.consumed;
                    if (!gap.GetU32(pid) || !gap.GetU64(missing) ||
                        gap.n != 0 || missing == 0)
                        continue;
                    row.pid = pid;
                    row.gap = true;
                    row.missingEvents = missing;
                    GetLocalTime(&row.time);
                } else {
                    size_t consumed = 0;
                    if (!ParseEvent(
                            input.data() + offset, input.size() - offset,
                            consumed, row,
                            ctx->snapshotCapable.load(
                                std::memory_order_acquire),
                            ctx->sentLogVisibility.load(
                                std::memory_order_acquire),
                            ctx->textMetadataCapable.load(
                                std::memory_order_acquire))) {
                        if (consumed > 0) {
                            offset += consumed;
                            continue;
                        }
                        break;
                    }
                    offset += consumed;
                }
                if (row.pid != ctx->pid) continue;
                if (ctx->cryptoEventCapable.load(std::memory_order_acquire)) {
                    row.cryptoContent =
                        (row.hash & kEventCryptoContentFlag) != 0;
                    row.hash &= ~kEventCryptoContentFlag;
                }
                if (!ctx->sentExtended.load(std::memory_order_acquire) &&
                    row.action == 2)
                    row.action = kRuleBlock;
                if (!row.gap && !row.showNotification &&
                    !ctx->notificationCapable.load(std::memory_order_acquire) &&
                    !row.ruleName.empty()) {
                    std::lock_guard<std::mutex> lock(stateMu_);
                    const auto it = notificationActionsByRule_.find(row.ruleName);
                    if (it != notificationActionsByRule_.end() &&
                        (it->second & static_cast<BYTE>(1u << row.action)) != 0)
                        row.showNotification = true;
                }
                row.path = ctx->path;
                size_t slash = row.path.find_last_of(L"\\/");
                row.process = slash == std::wstring::npos
                                  ? row.path
                                  : row.path.substr(slash + 1);
                if (!row.gap &&
                    !previewEnabled_.load(std::memory_order_acquire) &&
                    !row.showNotification && row.action != kRuleConfirm &&
                    !row.cryptoContent)
                    row.preview.clear();
                const bool queued = QueueLogRow(std::move(row));
                HWND wnd = wnd_.load(std::memory_order_acquire);
                if (queued && wnd) PostMessageW(wnd, kMsgEvent, 0, 0);
            }
            input.erase(0, offset);
        }
        if (input.size() > kIpcMaxPayload + kIpcFrameHeaderSize) break;
        if (input.empty()) {
            partialSince = 0;
        } else if (partialSince == 0) {
            partialSince = GetTickCount64();
        } else if (GetTickCount64() - partialSince > 5000) {
            break;
        }
        if (available == 0) Sleep(30);
    }

    DisconnectNamedPipe(pipe);
    return 0;
}

void PipeServer::ClientFinished(ClientCtx* ctx) noexcept {
    ctx->finished.store(true, std::memory_order_release);
    try {
        std::lock_guard<std::mutex> lock(clientsMu_);
        PostClientCountLocked();
    } catch (...) {
        // The connection is already marked inactive; a later server update
        // will publish the same count if notification cannot be queued here.
    }
}

void PipeServer::PostClientCountLocked() {
    size_t active = 0;
    for (ClientCtx* ctx : clients_) {
        if (!ctx->finished.load(std::memory_order_acquire)) ++active;
    }
    HWND wnd = wnd_.load(std::memory_order_acquire);
    if (wnd) PostMessageW(wnd, kMsgClients, static_cast<WPARAM>(active), 0);
}

void PipeServer::ReapClients() {
    std::vector<ClientCtx*> dead;
    bool preserveDead = false;
    {
        std::lock_guard<std::mutex> lock(stateMu_);
        preserveDead = shuttingDown_;
    }
    {
        std::lock_guard<std::mutex> lock(clientsMu_);
        auto it = clients_.begin();
        while (it != clients_.end()) {
            ClientCtx* ctx = *it;
            if (!preserveDead && ctx->thread &&
                WaitForSingleObject(ctx->thread, 0) == WAIT_OBJECT_0) {
                dead.push_back(ctx);
                it = clients_.erase(it);
            } else {
                ++it;
            }
        }
        PostClientCountLocked();
    }
    for (ClientCtx* ctx : dead) {
        CloseHandle(ctx->thread);
        CloseHandle(ctx->pipe);
        delete ctx;
    }
}

void PipeServer::StopClients(bool waitForever) {
    std::vector<ClientCtx*> clients;
    {
        std::lock_guard<std::mutex> lock(clientsMu_);
        clients.swap(clients_);
    }
    const ULONGLONG deadline = waitForever ? 0 : GetTickCount64() + 3000;
    for (ClientCtx* ctx : clients) CancelSynchronousIo(ctx->thread);

    std::vector<ClientCtx*> survivors;
    for (ClientCtx* ctx : clients) {
        DWORD timeout = INFINITE;
        if (!waitForever) {
            const ULONGLONG now = GetTickCount64();
            timeout = now >= deadline
                          ? 0
                          : (DWORD)(std::min)(deadline - now,
                                               (ULONGLONG)MAXDWORD);
        }
        DWORD result = WaitForSingleObject(ctx->thread, timeout);
        if (result == WAIT_OBJECT_0) {
            CloseHandle(ctx->thread);
            CloseHandle(ctx->pipe);
            delete ctx;
        } else {
            // A timeout is not permission to detach a thread that still owns
            // ctx->self. Cancel its synchronous I/O and retain ownership for
            // the destructor, without TerminateThread.
            CancelSynchronousIo(ctx->thread);
            if (waitForever) {
                WaitForSingleObject(ctx->thread, INFINITE);
                CloseHandle(ctx->thread);
                CloseHandle(ctx->pipe);
                delete ctx;
            } else {
                survivors.push_back(ctx);
            }
        }
    }
    {
        std::lock_guard<std::mutex> lock(clientsMu_);
        if (!survivors.empty())
            clients_.insert(clients_.end(), survivors.begin(), survivors.end());
        PostClientCountLocked();
    }
}

} // namespace clip
