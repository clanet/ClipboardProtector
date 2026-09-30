// Hook.dll：注入宿主进程，拦截剪贴板 API 并上报/阻断。
// 设计要点：
//  - 注入由主程序 SetWindowsHookExW(WH_GETMESSAGE) 完成，本 DLL 导出 GetMsgProc。
//  - 主程序自身（按 exe 名判断）不挂钩不上报，避免自触发。
//  - 拦截决策基于规则快照（主程序经管道推送），纯内存判断。
//    规则使用原子不可变快照；事件队列只在移动队首/队尾时短暂持锁。
//  - 钩子函数体全部 SEH 包裹：本 DLL 内部异常绝不外溢到宿主。
//  - 事件经队列 + 专用线程异步写管道；管道断开自动重连。
//  - Detours 挂载在管道线程内完成，避开 DllMain 加载器锁。
//    对已运行进程：先锁本 DLL 的 CRT 堆并挂起其他线程至快照稳定，再 Begin/Attach/Commit；
//    析构路径必 Resume，避免漏挂线程改写崩溃，以及 Commit/Abort 在堆锁上死等。
#include <windows.h>
#include <shellapi.h>
#include <shlobj.h>
#include <tlhelp32.h>
#include "detours.h"
#include "privateclip.h"
#include "../common/ipc.h"
#include "../common/rules.h"
#include "../common/config.h"   // RuleAction 枚举
#include "../common/crypto.h"
#include "../common/util.h"
#include "../common/winutil.h"
#include <string>
#include <vector>
#include <deque>
#include <unordered_map>
#include <atomic>
#include <algorithm>
#include <memory>
#include <malloc.h>

static HMODULE g_self = nullptr;
static bool g_isSelf = false;
static std::atomic<bool> g_hooksInstalled{false};
static std::atomic<bool> g_connected{false};
static std::atomic<LONG> g_workerRunning{0};
static std::atomic<LONG> g_activeDetourCalls{0};
static std::atomic<bool> g_stop{false};

static std::atomic<bool> g_workerStarted{false};
static std::atomic<HMODULE> g_workerModule{nullptr};
static HANDLE g_stopEvent = nullptr;
static HANDLE g_controllerMutex = nullptr;
static HANDLE g_sourceMapping = nullptr;
static clip::SharedClipboardSource* g_source = nullptr;
static HANDLE g_cryptoMapping = nullptr;
static clip::SharedCryptoProtection* g_crypto = nullptr;
static std::wstring g_pipeName;
static CRITICAL_SECTION g_pipeCs;
static bool g_pipeCsInitialized = false;
static std::string g_controlInput;
static ULONGLONG g_controlPartialSince = 0;
static std::atomic<bool> g_shutdownRequested{false};

// ---- 规则快照与暂停状态 ----
static CRITICAL_SECTION g_cs;
static std::shared_ptr<const std::vector<clip::RuleLite>> g_rules;
static bool g_paused = false;
static bool g_previewEnabled = false;
static bool g_shortcutOnlyMode = false;
static std::atomic<bool> g_shortcutDirectAllow{false};
static std::atomic<DWORD> g_shortcutAuthorizationWindowMs{
    clip::kDefaultShortcutAuthorizationWindowMs};
static std::atomic<bool> g_cryptoEnabled{false};
static std::atomic<bool> g_cryptoSettingKnown{false};
static std::atomic<bool> g_extendedStateApplied{false};
static std::atomic<bool> g_notificationStateApplied{false};
static std::atomic<bool> g_logVisibilityStateApplied{false};
static std::atomic<bool> g_snapshotProtocolCapable{false};
static std::atomic<bool> g_snapshotTransportEnabled{false};
static std::atomic<bool> g_ignoreCustomFormats{false};
static std::atomic<bool> g_textMetadataEnabled{false};

static std::wstring g_processPathLower;
static std::wstring g_processNameLower;
static const std::wstring g_shortcutProtectionName =
    L"复制 / 粘贴快捷键专用保护";
static const std::wstring g_shortcutCopyAllowName = L"复制快捷键直接放行";
static const std::wstring g_shortcutPasteAllowName = L"粘贴快捷键直接放行";
static const std::wstring g_cryptoReplacementName =
    L"Crypto 保护：地址替换";
static const std::wstring g_ignoreCustomFormatName = L"忽略自定义格式";
static const std::wstring g_sensitiveContentPlaceholder =
    L"（区块链敏感内容已隐藏）";
static const std::wstring g_cryptoAddressPlaceholder =
    L"（区块链地址已隐藏）";

// ---- 事件队列（钩子生产，管道线程消费） ----
struct ClipboardSnapshot {
    BYTE kind = clip::kSnapshotNone;
    DWORD originalBytes = 0;
    std::vector<BYTE> data;
};

struct PendingEvent {
    clip::BuiltinRule builtinRule = clip::BuiltinRule::None;
    clip::PreviewKind previewKind = clip::PreviewKind::Text;
    clip::ClipOp op;
    UINT fmt;
    BYTE action;
    bool showNotification = false;
    bool hideFromLogList = false;
    bool blocked;
    unsigned long long hash;
    bool cryptoContent = false;
    std::wstring preview;
    DWORD sequence = 0;
    DWORD sourcePid = 0;
    std::wstring sourceName;
    std::wstring sourcePath;
    std::wstring ruleName;
    BYTE snapshotKind = clip::kSnapshotNone;
    DWORD snapshotOriginalBytes = 0;
    std::vector<BYTE> snapshot;
    unsigned long long droppedBefore = 0;
};
static std::deque<PendingEvent> g_queue;
static CRITICAL_SECTION g_qcs;
static std::atomic<unsigned long long> g_droppedEvents{0};
static constexpr size_t kEventQueueCapacity = 4096;
static size_t g_queuedSnapshotBytes = 0;
static constexpr size_t kQueuedSnapshotBytesCapacity = 16u << 20;

struct PendingConfirmationRequest {
    clip::PreviewKind previewKind = clip::PreviewKind::Text;
    unsigned long long token = 0;
    clip::ClipOp operation = clip::kOpRead;
    UINT format = 0;
    DWORD sourceProcessId = 0;
    std::wstring sourceProcess;
    std::wstring sourcePath;
    std::wstring ruleName;
    std::wstring preview;
    DWORD timeoutMs = 15000;
    bool timeoutBlock = true;
};

struct ConfirmationWaiter {
    HANDLE event = nullptr;
    bool allow = false;
    bool completed = false;
    bool defaultAllow = false;
};

static CRITICAL_SECTION g_confirmationCs;
static std::deque<PendingConfirmationRequest> g_confirmationQueue;
static std::unordered_map<unsigned long long, ConfirmationWaiter*>
    g_confirmationWaiters;
static std::atomic<unsigned long long> g_nextConfirmationToken{1};
static constexpr size_t kConfirmationQueueCapacity = 256;

// ---- 原始 API ----
static decltype(&OpenClipboard) Real_OpenClipboard = OpenClipboard;
static decltype(&CloseClipboard) Real_CloseClipboard = CloseClipboard;
static decltype(&GetClipboardData) Real_GetClipboardData = GetClipboardData;
static decltype(&SetClipboardData) Real_SetClipboardData = SetClipboardData;
static decltype(&EmptyClipboard) Real_EmptyClipboard = EmptyClipboard;
static thread_local bool g_clipboardModified = false;
// Keep the baseline across EmptyClipboard -> SetClipboardData. A clear without
// a subsequent text write retires it before CloseClipboard releases the lock.
static thread_local bool g_cryptoClearPending = false;
static thread_local bool g_controlKeyDown = false;
static thread_local ULONGLONG g_controlKeyDownSince = 0;
static thread_local bool g_shiftKeyDown = false;
static thread_local ULONGLONG g_shiftKeyDownSince = 0;
static std::atomic<ULONGLONG> g_copyShortcutUntil{0};
static std::atomic<ULONGLONG> g_pasteShortcutUntil{0};

// SEH 外壳（定义在文件后部），PipeThread 挂载时需要
static BOOL WINAPI Hooked_OpenClipboard(HWND owner);
static BOOL WINAPI Hooked_CloseClipboard();
static HANDLE WINAPI Hooked_GetClipboardData(UINT fmt);
static HANDLE WINAPI Hooked_SetClipboardData(UINT fmt, HANDLE mem);
static BOOL WINAPI Hooked_EmptyClipboard();
// ---------------- 工具 ----------------

static bool IsSelfProcess() noexcept {
    // DllMain 内不分配 C++ 堆对象；大缓冲区放在 DLL 数据段而不是宿主线程栈上。
    static wchar_t processPath[32768] = {};
    static wchar_t dllPath[32768] = {};
    DWORD processLength = GetModuleFileNameW(nullptr, processPath,
                                             (DWORD)_countof(processPath));
    DWORD dllLength = GetModuleFileNameW(g_self, dllPath, (DWORD)_countof(dllPath));
    if (processLength == 0 || processLength >= _countof(processPath) ||
        dllLength == 0 || dllLength >= _countof(dllPath))
        return false;
    wchar_t* slash = wcsrchr(dllPath, L'\\');
    wchar_t* altSlash = wcsrchr(dllPath, L'/');
    if (!slash || (altSlash && altSlash > slash)) slash = altSlash;
    size_t prefix = slash ? (size_t)(slash - dllPath + 1) : 0;
    constexpr wchar_t fileName[] = L"ClipboardProtector.exe";
    if (prefix + _countof(fileName) > _countof(dllPath)) return false;
    wcscpy_s(dllPath + prefix, _countof(dllPath) - prefix, fileName);
    return _wcsicmp(processPath, dllPath) == 0;
}

static void PrepareProcessIdentity() {
    std::wstring path;
    if (!clip::ModulePath(nullptr, path)) {
        g_processPathLower.clear();
        g_processNameLower.clear();
        return;
    }
    g_processPathLower = clip::ToLower(path);
    size_t pos = g_processPathLower.find_last_of(L"\\/");
    g_processNameLower = pos == std::wstring::npos
                             ? g_processPathLower
                             : g_processPathLower.substr(pos + 1);
}

static void CloseSourceMapping() noexcept {
    if (g_source) {
        UnmapViewOfFile(g_source);
        g_source = nullptr;
    }
    if (g_sourceMapping) {
        CloseHandle(g_sourceMapping);
        g_sourceMapping = nullptr;
    }
}

static void OpenSourceMapping() {
    CloseSourceMapping();
    const std::wstring name = clip::ResolveObjectName(
        L"CLIP_TEST_SOURCE_MAP", clip::kClipboardSourceMapName);
    g_sourceMapping = OpenFileMappingW(FILE_MAP_READ | FILE_MAP_WRITE, FALSE,
                                       name.c_str());
    if (!g_sourceMapping) return;
    g_source = static_cast<clip::SharedClipboardSource*>(
        MapViewOfFile(g_sourceMapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0,
                      sizeof(clip::SharedClipboardSource)));
    if (!g_source) CloseSourceMapping();
}

static void CloseCryptoMapping() noexcept {
    if (g_crypto) {
        UnmapViewOfFile(g_crypto);
        g_crypto = nullptr;
    }
    if (g_cryptoMapping) {
        CloseHandle(g_cryptoMapping);
        g_cryptoMapping = nullptr;
    }
}

static void OpenCryptoMapping() {
    CloseCryptoMapping();
    const std::wstring name = clip::ResolveObjectName(
        L"CLIP_TEST_CRYPTO_MAP", clip::kCryptoProtectionMapName);
    g_cryptoMapping = OpenFileMappingW(FILE_MAP_READ | FILE_MAP_WRITE, FALSE,
                                       name.c_str());
    if (!g_cryptoMapping) return;
    g_crypto = static_cast<clip::SharedCryptoProtection*>(
        MapViewOfFile(g_cryptoMapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0,
                      sizeof(clip::SharedCryptoProtection)));
    if (!g_crypto) CloseCryptoMapping();
}

struct CryptoSnapshot {
    std::vector<clip::CryptoAddress> addresses;
};

enum class CryptoLookup { off, inactive, active, unavailable };

static bool LockCryptoState();
static void UnlockCryptoState();

static bool CryptoFeatureEnabled() {
    if (g_cryptoSettingKnown.load(std::memory_order_acquire))
        return g_cryptoEnabled.load(std::memory_order_acquire);
    return g_crypto && InterlockedCompareExchange(&g_crypto->enabled, 0, 0) != 0;
}

static CryptoLookup ReadCryptoSnapshot(CryptoSnapshot& snapshot) {
    snapshot = {};
    if (!CryptoFeatureEnabled()) return CryptoLookup::off;
    // Allocate before acquiring the shared spin lock.
    auto copy = std::make_unique<clip::SharedCryptoProtection>();
    if (!g_crypto || !LockCryptoState()) return CryptoLookup::unavailable;
    memcpy(copy.get(), g_crypto, sizeof(*copy));
    UnlockCryptoState();
    if (copy->structureVersion != clip::kCryptoProtectionVersion ||
        copy->addressCount > clip::kMaxProtectedCryptoAddresses)
        return CryptoLookup::unavailable;
    if (!copy->active || !copy->addressCount ||
        copy->expiresAt < GetTickCount64()) return CryptoLookup::inactive;
    for (DWORD index = 0; index < copy->addressCount; ++index) {
        const auto& stored = copy->addresses[index];
        clip::CryptoAddress address;
        if (stored.canonical[clip::kCryptoAddressChars - 1] != L'\0' ||
            !clip::ParseCryptoAddress(stored.canonical, address.kind,
                                      address.canonical) ||
            stored.kind != address.kind || stored.canonical != address.canonical)
            return CryptoLookup::unavailable;
        snapshot.addresses.push_back(std::move(address));
    }
    return CryptoLookup::active;
}


static bool LockCryptoState() {
    if (!g_crypto) return false;
    for (int attempt = 0; attempt < 64; ++attempt) {
        if (InterlockedCompareExchange(&g_crypto->guard, 1, 0) == 0)
            return true;
        YieldProcessor();
    }
    return false;
}

static void UnlockCryptoState() {
    MemoryBarrier();
    InterlockedExchange(&g_crypto->guard, 0);
}

static void ClearCryptoAddress() {
    if (!LockCryptoState()) return;
    g_crypto->active = 0;
    g_crypto->addressCount = 0;
    g_crypto->writerProcessId = 0;
    g_crypto->clipboardSequence = 0;
    g_crypto->reserved = 0;
    g_crypto->expiresAt = 0;
    ZeroMemory(g_crypto->addresses, sizeof(g_crypto->addresses));
    UnlockCryptoState();
}

static void PublishCryptoAddress(const std::vector<clip::CryptoAddress>& addresses,
                                 DWORD sequence) {
    constexpr ULONGLONG kProtectionWindowMs = 5ull * 60ull * 1000ull;
    if (!g_crypto || addresses.empty() ||
        addresses.size() > clip::kMaxProtectedCryptoAddresses ||
        !CryptoFeatureEnabled() || !LockCryptoState()) return;
    g_crypto->structureVersion = clip::kCryptoProtectionVersion;
    g_crypto->active = 1;
    g_crypto->addressCount = static_cast<DWORD>(addresses.size());
    g_crypto->writerProcessId = GetCurrentProcessId();
    g_crypto->clipboardSequence = sequence;
    g_crypto->reserved = 0;
    g_crypto->expiresAt = GetTickCount64() + kProtectionWindowMs;
    ZeroMemory(g_crypto->addresses, sizeof(g_crypto->addresses));
    for (size_t index = 0; index < addresses.size(); ++index) {
        g_crypto->addresses[index].kind = addresses[index].kind;
        const auto& canonical = addresses[index].canonical;
        memcpy(g_crypto->addresses[index].canonical, canonical.data(),
               canonical.size() * sizeof(wchar_t));
    }
    UnlockCryptoState();
}

static bool QueryProcessIdentity(DWORD processId,
                                 clip::RuleSourceIdentity& source) {
    if (!processId) return false;
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                                 processId);
    if (!process) return false;
    std::wstring path;
    const bool ok = clip::ProcessImagePath(process, path);
    CloseHandle(process);
    if (!ok) return false;
    source.known = true;
    source.pid = processId;
    source.pathLower = clip::ToLower(path);
    const size_t slash = source.pathLower.find_last_of(L"\\/");
    source.nameLower = slash == std::wstring::npos
                           ? source.pathLower
                           : source.pathLower.substr(slash + 1);
    return true;
}

static clip::RuleSourceIdentity CurrentClipboardSource(DWORD sequence) {
    clip::RuleSourceIdentity source;
    if (g_source) {
        clip::SharedClipboardSource snapshot = {};
        for (int attempt = 0; attempt < 4; ++attempt) {
            const LONG before = InterlockedCompareExchange(&g_source->guard, 0, 0);
            if (before != 0) {
                YieldProcessor();
                continue;
            }
            MemoryBarrier();
            snapshot.sequence = g_source->sequence;
            snapshot.processId = g_source->processId;
            memcpy(snapshot.processPath, g_source->processPath,
                   sizeof(snapshot.processPath));
            MemoryBarrier();
            if (InterlockedCompareExchange(&g_source->guard, 0, 0) == 0)
                break;
            snapshot.sequence = 0;
        }
        if (snapshot.sequence == sequence && snapshot.processId != 0) {
            snapshot.processPath[clip::kClipboardSourcePathChars - 1] = L'\0';
            source.known = true;
            source.pid = snapshot.processId;
            source.pathLower = clip::ToLower(snapshot.processPath);
            const size_t slash = source.pathLower.find_last_of(L"\\/");
            source.nameLower = slash == std::wstring::npos
                                   ? source.pathLower
                                   : source.pathLower.substr(slash + 1);
            return source;
        }
    }

    DWORD ownerProcessId = 0;
    HWND owner = GetClipboardOwner();
    if (owner) GetWindowThreadProcessId(owner, &ownerProcessId);
    (void)QueryProcessIdentity(ownerProcessId, source);
    return source;
}

static void PublishClipboardSource() noexcept {
    if (!g_source) return;
    const DWORD sequence = GetClipboardSequenceNumber();
    if (!sequence) return;
    InterlockedExchange(&g_source->guard, 1);
    g_source->sequence = sequence;
    g_source->processId = GetCurrentProcessId();
    const size_t length = (std::min)(
        g_processPathLower.size(),
        static_cast<size_t>(clip::kClipboardSourcePathChars - 1));
    memcpy(g_source->processPath, g_processPathLower.data(),
           length * sizeof(wchar_t));
    g_source->processPath[length] = L'\0';
    MemoryBarrier();
    InterlockedExchange(&g_source->guard, 0);
}

// A bounded spin avoids both indefinite host-thread waits and needless audit
// loss when the sender owns the queue for only a few instructions.
static void QueueEvent(clip::ClipOp op, UINT fmt, BYTE action, bool blocked,
                       unsigned long long hash, const std::wstring& preview,
                       DWORD sequence = 0,
                       const clip::RuleSourceIdentity* source = nullptr,
                       const std::wstring* ruleName = nullptr,
                       bool showNotification = false,
                       bool cryptoContent = false,
                       ClipboardSnapshot* snapshot = nullptr,
                       bool hideFromLogList = false,
                       clip::BuiltinRule builtinRule = clip::BuiltinRule::None) noexcept {
    PendingEvent event;
    try {
        event.op = op;
        event.builtinRule = builtinRule;
        if (ruleName == &g_shortcutProtectionName)
            event.builtinRule = clip::BuiltinRule::ShortcutProtection;
        else if (ruleName == &g_cryptoReplacementName)
            event.builtinRule = clip::BuiltinRule::CryptoReplacement;
        else if (ruleName == &g_ignoreCustomFormatName)
            event.builtinRule = clip::BuiltinRule::IgnoreCustomFormat;
        if (&preview == &g_cryptoAddressPlaceholder)
            event.previewKind = clip::PreviewKind::CryptoAddress;
        event.fmt = fmt;
        event.action = action;
        event.showNotification = showNotification;
        event.hideFromLogList = hideFromLogList;
        event.blocked = blocked;
        event.hash = hash;
        event.cryptoContent = cryptoContent;
        event.preview = preview.substr(0, 64);
        event.sequence = sequence;
        if (source && source->known) {
            event.sourcePid = source->pid;
            event.sourceName = source->nameLower;
            event.sourcePath = source->pathLower;
        }
        if (ruleName) event.ruleName = ruleName->substr(0, 128);
        if (snapshot) {
            event.snapshotKind = snapshot->kind;
            event.snapshotOriginalBytes = snapshot->originalBytes;
            event.snapshot = std::move(snapshot->data);
        }
    } catch (...) {
        g_droppedEvents.fetch_add(1, std::memory_order_relaxed);
        return;
    }

    bool queueLocked = false;
    for (int attempt = 0; attempt < 32; ++attempt) {
        if (TryEnterCriticalSection(&g_qcs)) {
            queueLocked = true;
            break;
        }
        YieldProcessor();
    }
    if (!queueLocked) {
        g_droppedEvents.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    struct Guard {
        CRITICAL_SECTION* cs;
        ~Guard() { LeaveCriticalSection(cs); }
    } guard{&g_qcs};
    if (g_queue.size() >= kEventQueueCapacity) {
        g_droppedEvents.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    if (!event.snapshot.empty() &&
        event.snapshot.size() >
            kQueuedSnapshotBytesCapacity -
                (std::min)(g_queuedSnapshotBytes,
                           kQueuedSnapshotBytesCapacity)) {
        std::vector<BYTE>().swap(event.snapshot);
        event.snapshotKind = clip::kSnapshotDiscarded;
    }
    const unsigned long long droppedBefore =
        g_droppedEvents.exchange(0, std::memory_order_acq_rel);
    event.droppedBefore = droppedBefore;
    const size_t snapshotBytes = event.snapshot.size();
    try {
        g_queuedSnapshotBytes += snapshotBytes;
        g_queue.push_back(std::move(event));
    } catch (...) {
        g_queuedSnapshotBytes -= snapshotBytes;
        g_droppedEvents.fetch_add(droppedBefore + 1,
                                  std::memory_order_relaxed);
    }
}

static void QueueCryptoBlock(clip::ClipOp op, UINT format,
                             const clip::RuleSourceIdentity* source,
                             const std::wstring& ruleName,
                             bool cryptoContent = false) noexcept {
    QueueEvent(op, format, clip::kRuleBlock, true, 0, L"",
               GetClipboardSequenceNumber(), source, &ruleName, true,
               cryptoContent);
}


struct TextSnapshot {
    wchar_t text[clip::kMaxRegexContentLength + 1] = {};
    SIZE_T length = 0;
    unsigned long long hash = 0;
    bool comparable = true;
};

// 此函数只使用 POD 局部变量，确保 SEH 展开时 __finally 总会解锁 HGLOBAL。
static bool CaptureText(HANDLE h, TextSnapshot* snapshot) {
    if (!h) return false;
    SIZE_T bytes = GlobalSize(h);
    const wchar_t* p = (const wchar_t*)GlobalLock(h);
    if (!p) return false;
    bool ok = false;
    __try {
        SIZE_T chars = bytes / sizeof(wchar_t);
        SIZE_T scanLength =
            (std::min)(chars, (SIZE_T)clip::kMaxRegexContentLength);
        SIZE_T len = 0;
        while (len < scanLength && p[len]) ++len;
        bool terminated =
            (len < scanLength && p[len] == L'\0') ||
            (len == scanLength && chars > scanLength && p[len] == L'\0');
        snapshot->comparable = terminated || scanLength == chars;
        unsigned long long hash = 14695981039346656037ull;
        for (SIZE_T i = 0; i < len; ++i) {
            const BYTE* value = reinterpret_cast<const BYTE*>(&p[i]);
            for (int byte = 0; byte < 2; ++byte) {
                hash ^= value[byte];
                hash *= 1099511628211ull;
            }
        }
        // 未在前缀内遇到 NUL 时不把前缀指纹当成完整内容指纹。
        snapshot->hash = snapshot->comparable
            ? hash ^ ((unsigned long long)len << 32)
            : 0;
        snapshot->length = len;
        for (SIZE_T i = 0; i < len; ++i) snapshot->text[i] = p[i];
        snapshot->text[len] = L'\0';
        ok = true;
    }
    __finally {
        GlobalUnlock(h);
    }
    return ok;

}

// 从剪贴板全局内存提取文本预览与内容哈希（哈希=前 4096 字符 ^ 长度）
static bool PeekText(HANDLE h, bool capturePreview, std::wstring& preview,
                     unsigned long long& hash, std::wstring& content,
                     bool& contentComplete) {
    TextSnapshot snapshot;
    if (!CaptureText(h, &snapshot)) return false;
    hash = snapshot.hash;
    contentComplete = snapshot.comparable;
    if (capturePreview)
        preview.assign(snapshot.text, (std::min)(snapshot.length, (SIZE_T)64));
    content.assign(snapshot.text, snapshot.length);
    return true;
}

struct ByteTextSnapshot {
    char text[clip::kMaxRegexContentLength + 1] = {};
    SIZE_T length = 0;
    bool comparable = true;
};

static bool CaptureByteText(HANDLE h, ByteTextSnapshot* snapshot) {
    if (!h) return false;
    const SIZE_T bytes = GlobalSize(h);
    const char* text = static_cast<const char*>(GlobalLock(h));
    if (!text) return false;
    bool ok = false;
    __try {
        const SIZE_T scanLength =
            (std::min)(bytes, (SIZE_T)clip::kMaxRegexContentLength);
        SIZE_T length = 0;
        while (length < scanLength && text[length]) ++length;
        snapshot->comparable =
            (length < scanLength && text[length] == '\0') ||
            (length == scanLength && bytes > scanLength &&
             text[length] == '\0') ||
            scanLength == bytes;
        snapshot->length = length;
        memcpy(snapshot->text, text, length);
        snapshot->text[length] = '\0';
        ok = true;
    }
    __finally {
        GlobalUnlock(h);
    }
    return ok;
}

enum class ClipboardTextEncoding {
    none,
    ansi,
    oem,
    utf16,
    utf8,
};

static ClipboardTextEncoding TextEncodingForFormat(UINT format) {
    if (format == CF_TEXT || format == CF_DSPTEXT)
        return ClipboardTextEncoding::ansi;
    if (format == CF_OEMTEXT) return ClipboardTextEncoding::oem;
    if (format == CF_UNICODETEXT) return ClipboardTextEncoding::utf16;
    if (format < 0xc000) return ClipboardTextEncoding::none;

    wchar_t rawName[256] = {};
    const int length = GetClipboardFormatNameW(
        format, rawName, static_cast<int>(_countof(rawName)));
    if (length <= 0 || length >= static_cast<int>(_countof(rawName)))
        return ClipboardTextEncoding::none;
    std::wstring name;
    name.reserve(static_cast<size_t>(length));
    for (int index = 0; index < length; ++index) {
        wchar_t value = rawName[index];
        if (value == L' ' || value == L'\t' || value == L'\r' ||
            value == L'\n')
            continue;
        if (value >= L'A' && value <= L'Z') value += L'a' - L'A';
        name.push_back(value);
    }
    if (name == L"utf8_string" || name == L"text/plain" ||
        name == L"text/plain;charset=utf-8" ||
        name == L"text/plain;charset=utf8")
        return ClipboardTextEncoding::utf8;
    return ClipboardTextEncoding::none;
}

static bool IgnoreCustomClipboardFormat(UINT format) {
    if (!g_ignoreCustomFormats.load(std::memory_order_acquire))
        return false;
    if (format < 0xC000) return false;
    return TextEncodingForFormat(format) == ClipboardTextEncoding::none;
}

static bool PeekClipboardText(UINT format, HANDLE memory, std::wstring& content,
                               unsigned long long& hash,
                               bool& contentComplete, bool& textFormat) {
    const ClipboardTextEncoding encoding = TextEncodingForFormat(format);
    textFormat = encoding != ClipboardTextEncoding::none;
    std::wstring unusedPreview;
    if (encoding == ClipboardTextEncoding::utf16)
        return PeekText(memory, false, unusedPreview, hash, content,
                        contentComplete);
    if (!textFormat) return false;
    ByteTextSnapshot snapshot;
    if (!CaptureByteText(memory, &snapshot)) return false;
    contentComplete = snapshot.comparable;
    const UINT codePage = encoding == ClipboardTextEncoding::utf8
                              ? CP_UTF8
                              : encoding == ClipboardTextEncoding::oem
                                    ? CP_OEMCP
                                    : CP_ACP;
    const DWORD flags = encoding == ClipboardTextEncoding::utf8
                            ? MB_ERR_INVALID_CHARS
                            : 0;
    const int chars = MultiByteToWideChar(
        codePage, flags, snapshot.text,
        static_cast<int>(snapshot.length), nullptr, 0);
    if (snapshot.length != 0 && chars <= 0) return false;
    content.resize(static_cast<size_t>(chars));
    if (chars > 0 &&
        MultiByteToWideChar(codePage, flags, snapshot.text,
                            static_cast<int>(snapshot.length), content.data(),
                            chars) != chars)
        return false;
    hash = contentComplete ? clip::FnvHash64(content) : 0;
    return true;
}

// POD-only helper: always release the clipboard HGLOBAL even on a host fault.
static bool CopyCryptoTextBytes(HANDLE memory, BYTE* output, SIZE_T bytes) {
    const void* input = GlobalLock(memory);
    if (!input) return false;
    __try {
        memcpy(output, input, bytes);
    } __finally {
        GlobalUnlock(memory);
    }
    return true;
}

static bool PeekCryptoAddresses(UINT format, HANDLE memory,
                                const std::wstring& prefix, bool complete,
                                std::vector<clip::CryptoAddress>& addresses) {
    if (complete) return clip::ExtractCryptoAddresses(prefix, addresses);
    const auto encoding = TextEncodingForFormat(format);
    if (!memory || encoding == ClipboardTextEncoding::none) return false;
    const SIZE_T available = GlobalSize(memory);
    const bool wide = encoding == ClipboardTextEncoding::utf16;
    const SIZE_T limit = (clip::kMaxCryptoTextLength + 1) * (wide ? 2 : 4);
    const SIZE_T size = (std::min)(available, limit);
    if (!size) return false;
    std::vector<BYTE> bytes(size);
    if (!CopyCryptoTextBytes(memory, bytes.data(), size)) return false;
    std::wstring text;
    if (wide) {
        if (size % sizeof(wchar_t)) return false;
        const auto* chars = reinterpret_cast<const wchar_t*>(bytes.data());
        const SIZE_T count = size / sizeof(wchar_t);
        SIZE_T length = 0;
        while (length < count && chars[length]) ++length;
        if (length == count && size < available) return false;
        text.assign(chars, length);
    } else {
        SIZE_T length = 0;
        while (length < size && bytes[length]) ++length;
        if (length == size && size < available) return false;
        const UINT codePage = encoding == ClipboardTextEncoding::utf8 ? CP_UTF8 :
                              encoding == ClipboardTextEncoding::oem ? CP_OEMCP : CP_ACP;
        const DWORD flags = codePage == CP_UTF8 ? MB_ERR_INVALID_CHARS : 0;
        const auto* chars = reinterpret_cast<const char*>(bytes.data());
        const int count = MultiByteToWideChar(codePage, flags, chars,
                                              static_cast<int>(length), nullptr, 0);
        if (length && count <= 0) return false;
        text.resize(count);
        if (count && MultiByteToWideChar(codePage, flags, chars,
                                         static_cast<int>(length), text.data(), count) != count)
            return false;
    }
    return clip::ExtractCryptoAddresses(text, addresses);
}

static DWORD BoundedSnapshotSize(SIZE_T bytes) noexcept {
    return bytes > MAXDWORD ? MAXDWORD : static_cast<DWORD>(bytes);
}

static bool CopyGlobalBytes(HANDLE memory, BYTE* output, SIZE_T bytes) noexcept {
    if (!memory || !output || bytes == 0) return false;
    const void* source = GlobalLock(memory);
    if (!source) return false;
    bool copied = false;
    __try {
        __try {
            memcpy(output, source, bytes);
            copied = true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            copied = false;
        }
    }
    __finally {
        GlobalUnlock(memory);
    }
    return copied;
}

static ClipboardSnapshot CaptureGlobalSnapshot(HANDLE memory,
                                               BYTE kind) noexcept {
    ClipboardSnapshot snapshot;
    const SIZE_T bytes = memory ? GlobalSize(memory) : 0;
    if (bytes == 0) return snapshot;
    snapshot.originalBytes = BoundedSnapshotSize(bytes);
    if (bytes > clip::kMaxClipboardSnapshotBytes) {
        snapshot.kind = clip::kSnapshotTooLarge;
        return snapshot;
    }
    try {
        snapshot.data.resize(bytes);
    } catch (...) {
        snapshot.kind = clip::kSnapshotDiscarded;
        return snapshot;
    }
    if (!CopyGlobalBytes(memory, snapshot.data.data(), bytes)) {
        snapshot.data.clear();
        snapshot.originalBytes = 0;
        return snapshot;
    }
    snapshot.kind = kind;
    return snapshot;
}

static ClipboardSnapshot CaptureBitmapSnapshot(HBITMAP bitmap) noexcept {
    ClipboardSnapshot snapshot;
    BITMAP object = {};
    if (!bitmap || GetObjectW(bitmap, sizeof(object), &object) != sizeof(object) ||
        object.bmWidth <= 0 || object.bmHeight == 0 ||
        object.bmHeight == LONG_MIN)
        return snapshot;
    const DWORD width = static_cast<DWORD>(object.bmWidth);
    const DWORD height = static_cast<DWORD>(
        object.bmHeight < 0 ? -object.bmHeight : object.bmHeight);
    const unsigned long long pixelBytes =
        static_cast<unsigned long long>(width) * height * 4;
    const unsigned long long totalBytes = sizeof(BITMAPINFOHEADER) + pixelBytes;
    snapshot.originalBytes = totalBytes > MAXDWORD
                                 ? MAXDWORD
                                 : static_cast<DWORD>(totalBytes);
    if (totalBytes > clip::kMaxClipboardSnapshotBytes) {
        snapshot.kind = clip::kSnapshotTooLarge;
        return snapshot;
    }
    try {
        snapshot.data.resize(static_cast<size_t>(totalBytes));
    } catch (...) {
        snapshot.kind = clip::kSnapshotDiscarded;
        return snapshot;
    }
    auto* info = reinterpret_cast<BITMAPINFO*>(snapshot.data.data());
    ZeroMemory(info, sizeof(BITMAPINFOHEADER));
    info->bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    info->bmiHeader.biWidth = static_cast<LONG>(width);
    info->bmiHeader.biHeight = static_cast<LONG>(height);
    info->bmiHeader.biPlanes = 1;
    info->bmiHeader.biBitCount = 32;
    info->bmiHeader.biCompression = BI_RGB;
    info->bmiHeader.biSizeImage = static_cast<DWORD>(pixelBytes);
    HDC dc = CreateCompatibleDC(nullptr);
    if (!dc || GetDIBits(dc, bitmap, 0, height,
                         snapshot.data.data() + sizeof(BITMAPINFOHEADER), info,
                         DIB_RGB_COLORS) != static_cast<int>(height)) {
        if (dc) DeleteDC(dc);
        snapshot.data.clear();
        snapshot.originalBytes = 0;
        return snapshot;
    }
    DeleteDC(dc);
    snapshot.kind = clip::kSnapshotImage;
    return snapshot;
}

static ClipboardSnapshot CaptureFileDropSnapshot(HDROP drop) noexcept {
    ClipboardSnapshot snapshot;
    if (!drop) return snapshot;
    const UINT count = DragQueryFileW(drop, 0xffffffffu, nullptr, 0);
    if (count == 0) return snapshot;
    if (count > 1024) {
        snapshot.kind = clip::kSnapshotTooLarge;
        snapshot.originalBytes = (std::max)(
            BoundedSnapshotSize(GlobalSize(drop)),
            clip::kMaxClipboardSnapshotBytes + 1);
        return snapshot;
    }

    size_t characters = 1;
    for (UINT index = 0; index < count; ++index) {
        const UINT length = DragQueryFileW(drop, index, nullptr, 0);
        if (length == 0 || characters > SIZE_MAX - length - 1) return {};
        characters += static_cast<size_t>(length) + 1;
    }
    if (characters > (SIZE_MAX - sizeof(DROPFILES)) / sizeof(wchar_t))
        return {};
    const size_t bytes = sizeof(DROPFILES) + characters * sizeof(wchar_t);
    snapshot.originalBytes = BoundedSnapshotSize(bytes);
    if (bytes > clip::kMaxClipboardSnapshotBytes) {
        snapshot.kind = clip::kSnapshotTooLarge;
        return snapshot;
    }

    try {
        snapshot.data.assign(bytes, 0);
        auto* files = reinterpret_cast<DROPFILES*>(snapshot.data.data());
        files->pFiles = sizeof(DROPFILES);
        files->fWide = TRUE;
        wchar_t* output = reinterpret_cast<wchar_t*>(snapshot.data.data() +
                                                     sizeof(DROPFILES));
        size_t remaining = characters;
        for (UINT index = 0; index < count; ++index) {
            const UINT copied = DragQueryFileW(
                drop, index, output, static_cast<UINT>((std::min)(
                                         remaining,
                                         static_cast<size_t>(UINT_MAX))));
            if (copied == 0 || static_cast<size_t>(copied) + 1 > remaining)
                return {};
            output += copied + 1;
            remaining -= copied + 1;
        }
        snapshot.kind = clip::kSnapshotFiles;
        return snapshot;
    } catch (...) {
        snapshot.data.clear();
        snapshot.kind = clip::kSnapshotDiscarded;
        return snapshot;
    }
}

static ClipboardSnapshot CaptureClipboardSnapshot(UINT format,
                                                  HANDLE memory) noexcept {
    if (!g_snapshotTransportEnabled.load(std::memory_order_acquire)) return {};
    if (format == CF_DIB || format == CF_DIBV5)
        return CaptureGlobalSnapshot(memory, clip::kSnapshotImage);
    if (format == CF_HDROP)
        return CaptureFileDropSnapshot(reinterpret_cast<HDROP>(memory));
    if (format == CF_BITMAP)
        return CaptureBitmapSnapshot(reinterpret_cast<HBITMAP>(memory));
    return {};
}

// 返回值：0=未知（拿不到锁，按放行处理），1=未暂停，2=已暂停
static int PausedState() {
    if (!g_connected.load(std::memory_order_acquire)) return 2;
    if (!TryEnterCriticalSection(&g_cs)) return 0;
    int state = g_paused ? 2 : 1;
    LeaveCriticalSection(&g_cs);
    return state;
}

static bool PreviewEnabled() {
    if (!TryEnterCriticalSection(&g_cs)) return false;
    bool enabled = g_previewEnabled;
    LeaveCriticalSection(&g_cs);
    return enabled;
}

static bool ShortcutOnlyEnabled() {
    if (!TryEnterCriticalSection(&g_cs)) return false;
    const bool enabled = g_shortcutOnlyMode;
    LeaveCriticalSection(&g_cs);
    return enabled;
}

static bool ShortcutTokenActive(bool write) {
    const ULONGLONG deadline =
        write ? g_copyShortcutUntil.load(std::memory_order_acquire)
              : g_pasteShortcutUntil.load(std::memory_order_acquire);
    return deadline != 0 && GetTickCount64() <= deadline;
}

static bool LikelyUserClipboardWrite() {
    return ShortcutTokenActive(true);
}

static bool DirectShortcutAllowed(bool write) {
    return g_shortcutDirectAllow.load(std::memory_order_acquire) &&
           ShortcutTokenActive(write);
}

static bool AnyShortcutTokenActive() {
    return ShortcutTokenActive(false) || ShortcutTokenActive(true);
}

static void QueueShortcutBlock(clip::ClipOp op, UINT format) noexcept {
    QueueEvent(op, format, clip::kRuleBlock, true, 0, L"",
               GetClipboardSequenceNumber(), nullptr,
               &g_shortcutProtectionName);
}

static bool IsControlKey(WPARAM key) {
    return key == VK_CONTROL || key == VK_LCONTROL || key == VK_RCONTROL;
}

static bool IsShiftKey(WPARAM key) {
    return key == VK_SHIFT || key == VK_LSHIFT || key == VK_RSHIFT;
}

static void ObserveShortcutMessage(const MSG& message, WPARAM removeFlag) {
    if (removeFlag != PM_REMOVE) return;
    const bool keyDown = message.message == WM_KEYDOWN ||
                         message.message == WM_SYSKEYDOWN;
    const bool keyUp = message.message == WM_KEYUP ||
                       message.message == WM_SYSKEYUP;
    if (!keyDown && !keyUp) return;

    const ULONGLONG now = GetTickCount64();
    if (IsControlKey(message.wParam)) {
        g_controlKeyDown = keyDown;
        g_controlKeyDownSince = keyDown ? now : 0;
        return;
    }
    if (IsShiftKey(message.wParam)) {
        g_shiftKeyDown = keyDown;
        g_shiftKeyDownSince = keyDown ? now : 0;
        return;
    }
    if (!keyDown || (message.wParam != L'C' && message.wParam != L'V' &&
                     message.wParam != VK_INSERT))
        return;

    const bool trackedControl =
        g_controlKeyDown && g_controlKeyDownSince != 0 &&
        now - g_controlKeyDownSince <= 10000;
    const bool trackedShift =
        g_shiftKeyDown && g_shiftKeyDownSince != 0 &&
        now - g_shiftKeyDownSince <= 10000;
    const bool controlDown =
        trackedControl || (GetKeyState(VK_CONTROL) & 0x8000) != 0;
    const bool shiftDown =
        trackedShift || (GetKeyState(VK_SHIFT) & 0x8000) != 0;
    const bool copyShortcut =
        controlDown &&
        (message.wParam == L'C' ||
         (message.wParam == VK_INSERT && !shiftDown));
    const bool pasteShortcut =
        (controlDown && message.wParam == L'V') ||
        (shiftDown && !controlDown && message.wParam == VK_INSERT);
    if (!copyShortcut && !pasteShortcut) return;

    const DWORD authorizationWindowMs =
        g_shortcutAuthorizationWindowMs.load(std::memory_order_acquire);
    if (copyShortcut)
        g_copyShortcutUntil.store(now + authorizationWindowMs,
                                  std::memory_order_release);
    else
        g_pasteShortcutUntil.store(now + authorizationWindowMs,
                                   std::memory_order_release);
}

// ---------------- 管道客户端线程 ----------------

static HANDLE g_pipe = INVALID_HANDLE_VALUE;

static void CancelConfirmations() noexcept {
    EnterCriticalSection(&g_confirmationCs);
    g_confirmationQueue.clear();
    for (auto& entry : g_confirmationWaiters) {
        ConfirmationWaiter* waiter = entry.second;
        if (!waiter || waiter->completed) continue;
        waiter->allow = waiter->defaultAllow;
        waiter->completed = true;
        SetEvent(waiter->event);
    }
    LeaveCriticalSection(&g_confirmationCs);
}

static void ClosePipe() noexcept {
    if (!g_pipeCsInitialized) return;
    EnterCriticalSection(&g_pipeCs);
    HANDLE pipe = g_pipe;
    g_pipe = INVALID_HANDLE_VALUE;
    LeaveCriticalSection(&g_pipeCs);
    if (pipe != INVALID_HANDLE_VALUE) CloseHandle(pipe);
    g_controlInput.clear();
    g_controlPartialSince = 0;
    g_connected.store(false, std::memory_order_release);
    g_snapshotProtocolCapable.store(false, std::memory_order_release);
    g_snapshotTransportEnabled.store(false, std::memory_order_release);
    CancelConfirmations();
}

static bool SendAll(const std::string& b) {
    return clip::WriteAll(g_pipe, b);
}

static bool CompleteConfirmation(unsigned long long token, bool allow) {
    bool completed = false;
    EnterCriticalSection(&g_confirmationCs);
    const auto found = g_confirmationWaiters.find(token);
    if (found != g_confirmationWaiters.end() && found->second &&
        !found->second->completed) {
        found->second->allow = allow;
        found->second->completed = true;
        SetEvent(found->second->event);
        completed = true;
    }
    LeaveCriticalSection(&g_confirmationCs);
    return completed;
}

static bool ConfirmationPending(unsigned long long token) {
    EnterCriticalSection(&g_confirmationCs);
    const auto found = g_confirmationWaiters.find(token);
    const bool pending = found != g_confirmationWaiters.end() &&
                         found->second && !found->second->completed;
    LeaveCriticalSection(&g_confirmationCs);
    return pending;
}

static bool SendConfirmationRequests() {
    for (;;) {
        PendingConfirmationRequest request;
        EnterCriticalSection(&g_confirmationCs);
        if (g_confirmationQueue.empty()) {
            LeaveCriticalSection(&g_confirmationCs);
            return true;
        }
        request = std::move(g_confirmationQueue.front());
        g_confirmationQueue.pop_front();
        LeaveCriticalSection(&g_confirmationCs);
        if (!ConfirmationPending(request.token)) continue;

        std::string payload;
        clip::PutU64(payload, request.token);
        clip::PutU8(payload, static_cast<BYTE>(request.operation));
        clip::PutU32(payload, request.format);
        clip::PutU32(payload, request.sourceProcessId);
        clip::PutWStr(payload, request.sourceProcess);
        clip::PutWStr(payload, request.sourcePath);
        clip::PutWStr(payload, request.ruleName);
        const bool textMetadata = g_textMetadataEnabled.load(std::memory_order_acquire);
        clip::PutWStr(payload, textMetadata && request.previewKind == clip::PreviewKind::Truncated
            ? request.preview.substr(0, 256) : request.preview);
        clip::PutU32(payload, request.timeoutMs);
        clip::PutU8(payload, request.timeoutBlock ? 1 : 0);
        if (textMetadata) clip::PutU8(payload, static_cast<BYTE>(request.previewKind));
        std::string frame;
        clip::PutFrame(frame, clip::kIpcConfirmRequest, payload);
        if (SendAll(frame)) continue;
        CompleteConfirmation(request.token, !request.timeoutBlock);
        return false;
    }
}

static void CloseControllerSignals() {
    CloseSourceMapping();
    CloseCryptoMapping();
    if (g_stopEvent) {
        CloseHandle(g_stopEvent);
        g_stopEvent = nullptr;
    }
    if (g_controllerMutex) {
        CloseHandle(g_controllerMutex);
        g_controllerMutex = nullptr;
    }
}

static bool WaitForStop(DWORD timeout) {
    if (g_stop.load(std::memory_order_acquire)) return true;
    HANDLE handles[2] = {};
    bool mutexHandle[2] = {};
    DWORD count = 0;
    if (g_stopEvent) handles[count++] = g_stopEvent;
    if (g_controllerMutex) {
        mutexHandle[count] = true;
        handles[count++] = g_controllerMutex;
    }
    if (count == 0) {
        // A worker without either controller signal has no trustworthy
        // lifetime owner. Stop before installing or retaining Detours.
        g_stop.store(true, std::memory_order_release);
        g_connected.store(false, std::memory_order_release);
        return true;
    }

    DWORD result = WaitForMultipleObjects(count, handles, FALSE, timeout);
    if (result == WAIT_TIMEOUT)
        return g_stop.load(std::memory_order_acquire);
    DWORD index = MAXDWORD;
    if (result >= WAIT_OBJECT_0 && result < WAIT_OBJECT_0 + count)
        index = result - WAIT_OBJECT_0;
    else if (result >= WAIT_ABANDONED_0 && result < WAIT_ABANDONED_0 + count)
        index = result - WAIT_ABANDONED_0;
    if (index != MAXDWORD) {
        if (mutexHandle[index]) ReleaseMutex(handles[index]);
        g_stop.store(true, std::memory_order_release);
        g_connected.store(false, std::memory_order_release);
        return true;
    }
    // 控制句柄失效时也应 fail-open 并卸钩，不能把 Detour 永久留在宿主中。
    g_stop.store(true, std::memory_order_release);
    g_connected.store(false, std::memory_order_release);
    return true;
}

static bool IsTrustedPipeServer(HANDLE pipe) {
    ULONG pid = 0;
    if (!GetNamedPipeServerProcessId(pipe, &pid) || pid == 0) return false;
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!process) return false;
    std::wstring serverPath;
    const bool ok = clip::ProcessImagePath(process, serverPath);
    CloseHandle(process);
    if (!ok) return false;

    std::wstring expected;
#ifdef CLIP_TEST_EXPORTS
    expected = clip::ResolveObjectName(L"CLIP_TEST_SERVER_PATH", L"");
#endif
    if (expected.empty()) {
        if (!clip::ModuleDirectory(g_self, expected)) return false;
        expected += L"ClipboardProtector.exe";
    }
    return _wcsicmp(expected.c_str(), serverPath.c_str()) == 0;
}

static bool SendEvent(const PendingEvent& e) {
    const bool extended =
        g_extendedStateApplied.load(std::memory_order_acquire);
    try {
        std::string frame;
        frame.reserve(512 + e.snapshot.size());
        clip::PutHeader(frame, clip::kIpcEvent);
        clip::PutU32(frame, 0);
        clip::PutU32(frame, GetCurrentProcessId());
        const unsigned long long wireHash =
            (e.hash & ~clip::kEventCryptoContentFlag) |
            (e.cryptoContent ? clip::kEventCryptoContentFlag : 0);
        clip::PutU64(frame, wireHash);
        clip::PutU8(frame, (BYTE)e.op);
        clip::PutU32(frame, e.fmt);
        BYTE wireAction =
            !extended && e.action == clip::kRuleBlock ? 2 : e.action;
        if (g_notificationStateApplied.load(std::memory_order_acquire) &&
            e.showNotification)
            wireAction |= clip::kEventNotificationFlag;
        clip::PutU8(frame, wireAction);
        clip::PutU8(frame, e.blocked ? 1 : 0);
        clip::PutWStr(frame, e.preview);
        if (extended) {
            clip::PutU32(frame, e.sequence);
            clip::PutU32(frame, e.sourcePid);
            clip::PutWStr(frame, e.sourceName);
            clip::PutWStr(frame, e.sourcePath);
            clip::PutWStr(frame, e.ruleName);
            clip::PutU64(frame, e.droppedBefore);
            if (g_logVisibilityStateApplied.load(
                    std::memory_order_acquire))
                clip::PutU8(frame, e.hideFromLogList ? 1 : 0);
            if (g_snapshotProtocolCapable.load(std::memory_order_acquire)) {
                clip::PutU8(frame, e.snapshotKind);
                clip::PutU32(frame, e.snapshotOriginalBytes);
                clip::PutU32(frame, static_cast<DWORD>(e.snapshot.size()));
                if (!e.snapshot.empty()) {
                    frame.append(
                        reinterpret_cast<const char*>(e.snapshot.data()),
                        e.snapshot.size());
                }
            }
            if (g_textMetadataEnabled.load(std::memory_order_acquire)) {
                clip::PutU8(frame, static_cast<BYTE>(e.builtinRule));
                clip::PutU8(frame, static_cast<BYTE>(e.previewKind));
            }
        }
        const size_t payloadBytes = frame.size() - clip::kIpcFrameHeaderSize;
        if (payloadBytes > clip::kIpcMaxPayload) return false;
        const DWORD wireBytes = static_cast<DWORD>(payloadBytes);
        for (int index = 0; index < 4; ++index)
            frame[2 + index] =
                static_cast<char>((wireBytes >> (index * 8)) & 0xff);
        return SendAll(frame);
    } catch (...) {
        return false;
    }
}

static bool SendEventGap() {
    if (!g_extendedStateApplied.load(std::memory_order_acquire)) return true;
    const unsigned long long dropped =
        g_droppedEvents.exchange(0, std::memory_order_acq_rel);
    if (dropped == 0) return true;
    std::string payload;
    clip::PutU32(payload, GetCurrentProcessId());
    clip::PutU64(payload, dropped);
    std::string frame;
    clip::PutFrame(frame, clip::kIpcEventGap, payload);
    if (SendAll(frame)) return true;
    g_droppedEvents.fetch_add(dropped, std::memory_order_relaxed);
    return false;
}

// Returns 0 when more bytes are needed, 1 after a shutdown frame, and -1 for
// malformed input.  ReadFile is only issued for bytes reported by PeekNamedPipe;
// a split frame therefore remains in g_controlInput instead of blocking forever.
static int PumpServerMessages() {
    DWORD available = 0;
    if (!PeekNamedPipe(g_pipe, nullptr, 0, nullptr, &available, nullptr)) return -1;
    if (available) {
        char buffer[4096];
        DWORD want = (std::min)(available, (DWORD)sizeof(buffer));
        DWORD got = 0;
        if (!ReadFile(g_pipe, buffer, want, &got, nullptr) || got == 0) return -1;
        g_controlInput.append(buffer, got);
    }

    for (;;) {
        if (g_controlInput.size() > clip::kIpcMaxPayload + clip::kIpcFrameHeaderSize)
            return -1;
        clip::IpcFrameView frame;
        const clip::IpcFrameResult frameResult = clip::ParseFrame(
            g_controlInput.data(), g_controlInput.size(), frame);
        if (frameResult == clip::IpcFrameResult::invalid) return -1;
        if (frameResult == clip::IpcFrameResult::incomplete) {
            if (!g_controlInput.empty() && g_controlPartialSince == 0)
                g_controlPartialSince = GetTickCount64();
            if (!g_controlInput.empty() &&
                GetTickCount64() - g_controlPartialSince > 5000)
                return -1;
            return 0;
        }
        const BYTE type = frame.type;
        const size_t length = frame.payloadSize;
        const size_t frameSize = frame.consumed;
        clip::Reader r(frame.payload, frame.payloadSize);
        bool ok = true;
        if (type == clip::kIpcStateBegin) {
            ok = length == 0;
            if (ok) {
                g_connected.store(false, std::memory_order_release);
                g_extendedStateApplied.store(false,
                                             std::memory_order_release);
                g_notificationStateApplied.store(false,
                                                 std::memory_order_release);
                g_logVisibilityStateApplied.store(false,
                                                  std::memory_order_release);
                g_snapshotProtocolCapable.store(false,
                                                std::memory_order_release);
                g_snapshotTransportEnabled.store(false,
                                                 std::memory_order_release);
                g_ignoreCustomFormats.store(false, std::memory_order_release);
            }
        } else if (type == clip::kIpcPause) {
            BYTE paused = 0;
            ok = r.GetU8(paused) && r.n == 0;
            if (ok) {
                EnterCriticalSection(&g_cs);
                g_paused = paused != 0;
                LeaveCriticalSection(&g_cs);
            }
        } else if (type == clip::kIpcRules ||
                   type == clip::kIpcRulesExtended) {
            DWORD count = 0;
            std::vector<clip::RuleLite> next;
            ok = r.GetU32(count) && count <= 4096;
            bool extendedRules = type == clip::kIpcRulesExtended;
            bool notificationRules = false;
            bool logVisibilityRules = false;
            if (ok) {
                clip::Reader probe = r;
                DWORD marker = 0;
                if (probe.GetU32(marker) &&
                    (marker == clip::kRulePayloadMarker ||
                     marker == clip::kRulePayloadMarkerV3 ||
                     marker == clip::kRulePayloadMarkerV4)) {
                    r = probe;
                    extendedRules = true;
                    notificationRules =
                        marker == clip::kRulePayloadMarkerV3 ||
                        marker == clip::kRulePayloadMarkerV4;
                    logVisibilityRules =
                        marker == clip::kRulePayloadMarkerV4;
                } else if (type == clip::kIpcRulesExtended) {
                    ok = false;
                }
            }
            if (ok) {
                try { next.reserve(count); } catch (...) { ok = false; }
            }
            for (DWORD i = 0; i < count && ok; ++i) {
                clip::RuleLite rule;
                std::wstring pattern;
                BYTE isPath = 0, action = 0;
                if (extendedRules) {
                    BYTE showNotification = 0, hideFromLogList = 0,
                         ignoreCase = 0, enabled = 0, timeoutBlock = 0;
                    DWORD confirmTimeoutMs = 0;
                    ok = r.GetWStr(rule.name) && r.GetWStr(pattern) &&
                         r.GetU8(isPath) && r.GetU8(action);
                    if (ok && notificationRules)
                        ok = r.GetU8(showNotification) &&
                             showNotification <= 1;
                    if (ok && logVisibilityRules)
                        ok = r.GetU8(hideFromLogList) &&
                             hideFromLogList <= 1;
                    ok = ok &&
                         r.GetU8(rule.operations) && r.GetU8(rule.format) &&
                         r.GetWStr(rule.contentPattern) &&
                         r.GetU8(ignoreCase) && r.GetU8(enabled) &&
                         r.GetU8(rule.sourceMode) &&
                         r.GetWStr(rule.sourcePatternLower) &&
                         r.GetU32(confirmTimeoutMs) &&
                         r.GetU8(timeoutBlock);
                    rule.confirmTimeoutMs = confirmTimeoutMs;
                    rule.showNotification = notificationRules
                                                ? showNotification != 0
                                                : action == clip::kRuleShow;
                    rule.hideFromLogList =
                        logVisibilityRules && hideFromLogList != 0;
                    rule.ignoreCase = ignoreCase != 0;
                    rule.enabled = enabled != 0;
                    rule.timeoutBlock = timeoutBlock != 0;
                } else {
                    ok = r.GetWStr(pattern) && r.GetU8(isPath) &&
                         r.GetU8(action);
                    rule.operations = clip::kRuleReadWrite;
                    rule.format = clip::kFormatAny;
                    rule.ignoreCase = true;
                    rule.enabled = true;
                    rule.sourceMode = clip::kSourceAny;
                    rule.confirmTimeoutMs = 15000;
                    rule.timeoutBlock = true;
                    action = static_cast<BYTE>(
                        action >= 2 ? clip::kRuleBlock : clip::kRuleSilent);
                }
                if (!ok) break;
                if (notificationRules && !clip::IsRuleDecision(action)) {
                    ok = false;
                    break;
                }
                if (action > clip::kRuleBlock) action = clip::kRuleSilent;
                rule.patternLower = clip::ToLower(pattern);
                rule.sourcePatternLower =
                    clip::ToLower(rule.sourcePatternLower);
                rule.isPath = isPath != 0;
                rule.action = action;
                ok = clip::CompileRuleContentRegex(rule);
                if (ok) {
                    try { next.push_back(std::move(rule)); }
                    catch (...) { ok = false; }
                }
            }
            ok = ok && r.n == 0 && clip::IsRuleSetSupported(next);
            if (ok) {
                std::shared_ptr<const std::vector<clip::RuleLite>> prepared;
                try {
                    prepared = std::make_shared<std::vector<clip::RuleLite>>(
                        std::move(next));
                } catch (...) {
                    ok = false;
                }
                if (ok) {
                    std::atomic_store_explicit(&g_rules, std::move(prepared),
                                               std::memory_order_release);
                    g_extendedStateApplied.store(extendedRules,
                                                 std::memory_order_release);
                    g_notificationStateApplied.store(
                        notificationRules, std::memory_order_release);
                    g_logVisibilityStateApplied.store(
                        logVisibilityRules, std::memory_order_release);
                }
            }
        } else if (type == clip::kIpcSettings) {
            BYTE preview = 0;
            BYTE shortcutOnly = 0;
            ok = r.GetU8(preview) && preview <= 1;
            if (ok && r.n != 0)
                ok = r.GetU8(shortcutOnly) && shortcutOnly <= 1;
            BYTE crypto = 0;
            bool cryptoPresent = false;
            if (ok && r.n != 0) {
                ok = r.GetU8(crypto) && crypto <= 1;
                cryptoPresent = ok;
            }
            BYTE snapshots = 0;
            bool snapshotsPresent = false;
            if (ok && r.n != 0) {
                ok = r.GetU8(snapshots) && snapshots <= 1;
                snapshotsPresent = ok;
            }
            BYTE shortcutDirectAllow = 0;
            DWORD shortcutWindowMs =
                clip::kDefaultShortcutAuthorizationWindowMs;
            bool shortcutPolicyPresent = false;
            if (ok && r.n != 0) {
                ok = r.GetU8(shortcutDirectAllow) &&
                     shortcutDirectAllow <= 1 &&
                     r.GetU32(shortcutWindowMs) &&
                     shortcutWindowMs >=
                         clip::kMinShortcutAuthorizationWindowMs &&
                     shortcutWindowMs <=
                         clip::kMaxShortcutAuthorizationWindowMs;
                shortcutPolicyPresent = ok;
            }
            BYTE ignoreCustom = 0;
            bool ignoreCustomPresent = false;
            if (ok && r.n != 0) {
                ok = r.GetU8(ignoreCustom) && ignoreCustom <= 1;
                ignoreCustomPresent = ok;
            }
            BYTE textMetadata = 0;
            if (ok && r.n != 0)
                ok = r.GetU8(textMetadata) && textMetadata <= 1;
            ok = ok && r.n == 0;
            if (ok) {
                g_textMetadataEnabled.store(textMetadata != 0, std::memory_order_release);
                EnterCriticalSection(&g_cs);
                const bool wasShortcutOnly = g_shortcutOnlyMode;
                g_previewEnabled = preview != 0;
                g_shortcutOnlyMode = shortcutOnly != 0;
                LeaveCriticalSection(&g_cs);
                if (cryptoPresent) {
                    g_cryptoEnabled.store(crypto != 0, std::memory_order_release);
                    g_cryptoSettingKnown.store(true, std::memory_order_release);
                }
                g_snapshotProtocolCapable.store(snapshotsPresent,
                                                std::memory_order_release);
                g_snapshotTransportEnabled.store(
                    snapshotsPresent && snapshots != 0,
                    std::memory_order_release);
                const bool wasShortcutDirectAllow =
                    g_shortcutDirectAllow.load(std::memory_order_acquire);
                const DWORD previousShortcutWindowMs =
                    g_shortcutAuthorizationWindowMs.load(
                        std::memory_order_acquire);
                const bool nextShortcutDirectAllow =
                    shortcutPolicyPresent && shortcutDirectAllow != 0;
                const DWORD nextShortcutWindowMs =
                    shortcutPolicyPresent
                        ? shortcutWindowMs
                        : clip::kDefaultShortcutAuthorizationWindowMs;
                g_shortcutDirectAllow.store(
                    nextShortcutDirectAllow,
                    std::memory_order_release);
                g_shortcutAuthorizationWindowMs.store(
                    nextShortcutWindowMs,
                    std::memory_order_release);
                g_ignoreCustomFormats.store(
                    ignoreCustomPresent && ignoreCustom != 0,
                    std::memory_order_release);

                // Do not carry pre-existing copy/paste authorization into a
                // newly enabled protection window.
                if ((!wasShortcutOnly && shortcutOnly != 0) ||
                    (!wasShortcutDirectAllow && nextShortcutDirectAllow) ||
                    previousShortcutWindowMs != nextShortcutWindowMs) {
                    g_copyShortcutUntil.store(0, std::memory_order_release);
                    g_pasteShortcutUntil.store(0, std::memory_order_release);
                }
                // settings is the final member of a complete state snapshot.
                g_connected.store(true, std::memory_order_release);
#ifdef CLIP_TEST_EXPORTS
                wchar_t suppressAck[2] = {};
                const bool ackSuppressed =
                    GetEnvironmentVariableW(L"CLIP_TEST_SUPPRESS_STATE_ACK",
                                            suppressAck,
                                            _countof(suppressAck)) == 1 &&
                    suppressAck[0] == L'1';
#else
                const bool ackSuppressed = false;
#endif
                std::string ack;
                if (!ackSuppressed) {
                    std::string ackPayload;
                    clip::PutU32(ackPayload,
                                 clip::kStateAckCapabilityMarkerV12);
                    clip::PutU8(
                        ackPayload,
                        g_extendedStateApplied.load(
                            std::memory_order_acquire)
                            ? 1
                            : 0);
                    clip::PutU8(
                        ackPayload,
                        (g_crypto ? clip::kStateAckCryptoMappingAvailable : 0) |
                        clip::kStateAckPrivateClipboardAvailable |
                        clip::kStateAckTextMetadataAvailable);
                    clip::PutFrame(ack, clip::kIpcStateAck, ackPayload);
                    if (!SendAll(ack)) return -1;
                }
            }
        } else if (type == clip::kIpcPrivateClipboard) {
            std::wstring mappingName;
            ok = r.GetWStr(mappingName) && r.n == 0 && mappingName.size() <= 128;
            if (ok && g_hooksInstalled.load(std::memory_order_acquire))
                privateclip::Arm(mappingName);
        } else if (type == clip::kIpcConfirmResponse) {
            unsigned long long token = 0;
            BYTE allow = 0;
            ok = r.GetU64(token) && token != 0 && r.GetU8(allow) &&
                 allow <= 1 && r.n == 0;
            if (ok) CompleteConfirmation(token, allow != 0);
        } else if (type == clip::kIpcShutdown) {
            ok = length == 0;
            if (ok) {
                g_shutdownRequested.store(true, std::memory_order_release);
                CancelConfirmations();
            }
        } else {
            ok = false;
        }
        g_controlInput.erase(0, frameSize);
        g_controlPartialSince = 0;
        if (!ok) return -1;
        if (type == clip::kIpcShutdown) {
            g_stop.store(true, std::memory_order_release);
            return 1;
        }
    }
}

// 诊断状态：导出给自动化验证查询
static std::atomic<long> g_dbThread{0}, g_dbTxBegin{-1}, g_dbA1{-1}, g_dbA2{-1},
                         g_dbA3{-1}, g_dbCommit{-1}, g_dbPipe{0}, g_dbThreads{0};
#ifdef CLIP_TEST_EXPORTS
static std::atomic<long> g_testHookCalls{0};
extern "C" __declspec(dllexport) BOOL ClipHookPrivateArmForTest(const wchar_t* name) {
    if (!name || !g_hooksInstalled.load()) return FALSE;
    privateclip::Arm(name);
    return TRUE;
}
extern "C" __declspec(dllexport) BOOL ClipHookPrivateBlockingForTest() {
    return privateclip::Blocking();
}
extern "C" __declspec(dllexport) DWORD ClipHookPrivateDiagnosticsForTest() {
    return privateclip::Diagnostics();
}
#endif

#ifdef CLIP_TEST_EXPORTS
extern "C" __declspec(dllexport)
void ClipHookDebug(long out[8]) {
    if (!out) return;
    out[0] = g_dbThread.load(); out[1] = g_hooksInstalled.load();
    out[2] = g_dbTxBegin.load(); out[3] = g_dbA1.load();
    out[4] = g_dbA2.load(); out[5] = g_dbA3.load();
    out[6] = g_dbCommit.load(); out[7] = g_dbPipe.load();
}

extern "C" __declspec(dllexport)
long ClipHookLifecycleForTest() {
    return g_workerRunning.load() |
           (g_workerStarted.load() ? 0x100 : 0) |
           (g_stop.load() ? 0x200 : 0) |
           (g_workerModule.load() ? 0x400 : 0) |
           (g_activeDetourCalls.load() != 0 ? 0x800 : 0);
}

extern "C" __declspec(dllexport)
long ClipHookReadyForTest() {
    return (g_connected.load(std::memory_order_acquire) ? 1 : 0) |
           (g_hooksInstalled.load(std::memory_order_acquire) ? 2 : 0) |
           (g_extendedStateApplied.load(std::memory_order_acquire) ? 4 : 0);
}
#endif

#ifdef CLIP_TEST_EXPORTS
extern "C" __declspec(dllexport)
void ClipHookShutdownForTest() {
    g_connected.store(false, std::memory_order_release);
    g_stop.store(true, std::memory_order_release);
}

extern "C" __declspec(dllexport)
long ClipHookCallsForTest() {
    return g_testHookCalls.load(std::memory_order_acquire);
}
#endif

// 事务期间禁止扩容：先 reserve，再挂起宿主线程。
static constexpr size_t kMaxFrozenThreads = 4096;
static constexpr int kFreezeStableRounds = 8;

struct FrozenThreads {
    std::vector<HANDLE> handles;
    std::vector<DWORD> ids;

    bool Prepare() noexcept {
        try {
            handles.reserve(kMaxFrozenThreads);
            ids.reserve(kMaxFrozenThreads);
            return true;
        } catch (...) {
            return false;
        }
    }

    bool Contains(DWORD id) const noexcept {
        for (DWORD existing : ids) {
            if (existing == id) return true;
        }
        return false;
    }

    bool AddSuspended(HANDLE thread, DWORD id) noexcept {
        if (handles.size() >= handles.capacity()) {
            ResumeThread(thread);
            CloseHandle(thread);
            return false;
        }
        handles.push_back(thread);
        ids.push_back(id);
        return true;
    }

    void ThawAndClose() noexcept {
        for (HANDLE thread : handles) {
            ResumeThread(thread);
            CloseHandle(thread);
        }
        handles.clear();
        ids.clear();
    }

    ~FrozenThreads() { ThawAndClose(); }
};

static bool SelfModuleRange(ULONG_PTR& begin, ULONG_PTR& end) noexcept {
    begin = reinterpret_cast<ULONG_PTR>(g_self);
    end = begin;
    __try {
        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(g_self);
        if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0 ||
            dos->e_lfanew > 1024 * 1024)
            return false;
        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(
            reinterpret_cast<const BYTE*>(g_self) + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE ||
            nt->OptionalHeader.SizeOfImage == 0)
            return false;
        end = begin + nt->OptionalHeader.SizeOfImage;
        return end > begin;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        end = begin;
        return false;
    }
}

static bool FrozenThreadsOutsideSelf(const FrozenThreads& frozen) noexcept {
    ULONG_PTR moduleBegin = 0;
    ULONG_PTR moduleEnd = 0;
    if (!SelfModuleRange(moduleBegin, moduleEnd)) return false;
    for (HANDLE thread : frozen.handles) {
        if (WaitForSingleObject(thread, 0) == WAIT_OBJECT_0) continue;
        CONTEXT context = {};
        context.ContextFlags = CONTEXT_CONTROL;
        if (!GetThreadContext(thread, &context)) return false;
#ifdef _WIN64
        const ULONG_PTR instruction = static_cast<ULONG_PTR>(context.Rip);
#else
        const ULONG_PTR instruction = static_cast<ULONG_PTR>(context.Eip);
#endif
        if (instruction >= moduleBegin && instruction < moduleEnd) return false;
    }
    return true;
}

// Detours 的 new/delete 走本 DLL 静态 CRT 堆。挂起前锁住它，避免宿主
// 线程停在 Hook 路径的 malloc 里，随后 Commit/Abort 再 delete 死等。
struct CrtHeapLock {
    HANDLE heap = nullptr;
    bool Lock() noexcept {
        heap = reinterpret_cast<HANDLE>(_get_heap_handle());
        if (!heap) return false;
        if (!HeapLock(heap)) {
            heap = nullptr;
            return false;
        }
        return true;
    }
    void Unlock() noexcept {
        if (!heap) return;
        HeapUnlock(heap);
        heap = nullptr;
    }
    ~CrtHeapLock() { Unlock(); }
};

static bool FreezeOtherThreads(FrozenThreads& frozen,
                               bool requireStableSnapshot = true) noexcept {
    const DWORD selfPid = GetCurrentProcessId();
    const DWORD selfTid = GetCurrentThreadId();
    for (int round = 0; round < kFreezeStableRounds; ++round) {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snap == INVALID_HANDLE_VALUE) return false;
        THREADENTRY32 te = {sizeof(te)};
        if (!Thread32First(snap, &te)) {
            CloseHandle(snap);
            return false;
        }
        bool grew = false;
        do {
            if (te.th32OwnerProcessID != selfPid) continue;
            if (te.th32ThreadID == selfTid) continue;
            if (frozen.Contains(te.th32ThreadID)) continue;
            HANDLE thread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT |
                                           THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION,
                                       FALSE, te.th32ThreadID);
            if (!thread) {
                if (GetLastError() != ERROR_INVALID_PARAMETER) {
                    CloseHandle(snap);
                    return false;
                }
                continue;
            }
            if (SuspendThread(thread) == (DWORD)-1) {
                CloseHandle(thread);
                continue;
            }
            if (!frozen.AddSuspended(thread, te.th32ThreadID)) {
                CloseHandle(snap);
                return false;
            }
            grew = true;
        } while (Thread32Next(snap, &te));
        CloseHandle(snap);
        if (!requireStableSnapshot) return true;
        if (!grew) return true;
    }
    return false;
}

// Detach prevents new API calls from entering this DLL. Existing calls may
// still be returning through a Hooked_* frame, including a thread stopped in
// the few instructions before it increments the active-call counter. Freeze
// and inspect all other instruction pointers before dropping the worker's
// final module reference.
static bool WaitForModuleRundown() noexcept {
    const ULONGLONG deadline = GetTickCount64() + 10000;
    // 先被动等待在途 Hook 调用返回：此阶段完全不触碰宿主线程。
    while (g_activeDetourCalls.load(std::memory_order_acquire) != 0 &&
           GetTickCount64() < deadline)
        Sleep(15);
    // 校验轮次固定间隔 250ms、最多 5 轮。旧实现以 1-32ms 间隔反复
    // “全系统线程快照 + 挂起宿主全部线程 + 读取上下文”，多个宿主同时
    // 卸载时会让所有程序一起卡顿。拉长间隔不影响安全结论：校验不过时
    // 仍然返回 false，由调用方保留模块引用（宁可泄漏也不卸载代码页）。
    for (int pass = 0; pass < 5; ++pass) {
        bool clear = false;
        if (g_activeDetourCalls.load(std::memory_order_acquire) == 0) {
            FrozenThreads frozen;
            if (frozen.Prepare() && FreezeOtherThreads(frozen, false)) {
                clear =
                    g_activeDetourCalls.load(std::memory_order_acquire) == 0 &&
                    FrozenThreadsOutsideSelf(frozen);
            }
        }
        if (clear) return true;
        if (GetTickCount64() >= deadline) return false;
        Sleep(250);
    }
    return false;
}

static bool UpdateAllThreadsForTransaction(const std::vector<HANDLE>& threads) noexcept {
    if (DetourUpdateThread(GetCurrentThread()) != NO_ERROR) return false;
    g_dbThreads.fetch_add(1);
    for (HANDLE thread : threads) {
        if (WaitForSingleObject(thread, 0) == WAIT_OBJECT_0) continue;
        if (DetourUpdateThread(thread) != NO_ERROR) return false;
        g_dbThreads.fetch_add(1);
    }
    return true;
}

static bool RunDetourTransaction(bool install) noexcept {
    FrozenThreads frozen;
    if (!frozen.Prepare()) return false;

    const LONG begin = DetourTransactionBegin();
    if (install) g_dbTxBegin = begin;
    if (begin != NO_ERROR) return false;

    bool opsOk = false;
    if (install) {
        LONG openAttach = DetourAttach(&(PVOID&)Real_OpenClipboard,
                                       Hooked_OpenClipboard);
        LONG closeAttach = DetourAttach(&(PVOID&)Real_CloseClipboard,
                                        Hooked_CloseClipboard);
        g_dbA1 = DetourAttach(&(PVOID&)Real_GetClipboardData, Hooked_GetClipboardData);
        g_dbA2 = DetourAttach(&(PVOID&)Real_SetClipboardData, Hooked_SetClipboardData);
        g_dbA3 = DetourAttach(&(PVOID&)Real_EmptyClipboard, Hooked_EmptyClipboard);
        opsOk = openAttach == NO_ERROR && closeAttach == NO_ERROR &&
                g_dbA1.load() == NO_ERROR &&
                g_dbA2.load() == NO_ERROR && g_dbA3.load() == NO_ERROR;
    } else {
        LONG openDetach = DetourDetach(&(PVOID&)Real_OpenClipboard,
                                       Hooked_OpenClipboard);
        LONG closeDetach = DetourDetach(&(PVOID&)Real_CloseClipboard,
                                        Hooked_CloseClipboard);
        LONG detach1 = DetourDetach(&(PVOID&)Real_GetClipboardData,
                                    Hooked_GetClipboardData);
        LONG detach2 = DetourDetach(&(PVOID&)Real_SetClipboardData,
                                    Hooked_SetClipboardData);
        LONG detach3 = DetourDetach(&(PVOID&)Real_EmptyClipboard,
                                    Hooked_EmptyClipboard);
        opsOk = openDetach == NO_ERROR && closeDetach == NO_ERROR &&
                detach1 == NO_ERROR &&
                detach2 == NO_ERROR && detach3 == NO_ERROR;
    }

    opsOk = privateclip::Attach(install) && opsOk;
    // Attach/Detach only stage the transaction. Prepare trampolines and
    // decode instructions while the host is still running; freeze only for
    // thread-context updates and the commit that actually patches code.
    bool froze = false;
    if (opsOk) {
        CrtHeapLock crt;
        if (crt.Lock()) {
            froze = FreezeOtherThreads(frozen);
            crt.Unlock();
        }
    }
    const bool updateOk = opsOk && froze &&
                          UpdateAllThreadsForTransaction(frozen.handles);
    const LONG result = updateOk ? DetourTransactionCommit() : DetourTransactionAbort();
    if (install) g_dbCommit = result;
    return updateOk && result == NO_ERROR;
}

static bool InstallHooks() {
    privateclip::Initialize(&g_activeDetourCalls);
    if (g_hooksInstalled.load(std::memory_order_acquire)) return true;
    bool ok = RunDetourTransaction(true);
    g_hooksInstalled.store(ok, std::memory_order_release);
    return ok;
}

static bool RemoveHooks() {
    if (!privateclip::CanDetach()) return false;
    if (!g_hooksInstalled.load(std::memory_order_acquire)) return true;
    bool ok = RunDetourTransaction(false);
    if (ok) g_hooksInstalled.store(false, std::memory_order_release);
    return ok;
}

static HMODULE PrepareWorkerExit(bool allowRestart) noexcept {
    CloseControllerSignals();
    if (allowRestart) g_workerStarted.store(false, std::memory_order_release);
    HMODULE workerModule =
        g_workerModule.exchange(nullptr, std::memory_order_acq_rel);
    // Publish workerRunning last. A concurrent reinjection can now start only
    // after the old handles are closed and must acquire its own module ref.
    g_workerRunning.store(0, std::memory_order_release);
    return workerModule;
}

[[noreturn]] static void FinishWorkerExit(HMODULE workerModule) noexcept {
    if (workerModule) FreeLibraryAndExitThread(workerModule, 0);
    ExitThread(0);
}

[[noreturn]] static void WorkerExit(bool allowRestart,
                                    bool rundownComplete = false) {
    if (!rundownComplete && !WaitForModuleRundown()) {
        CloseControllerSignals();
        g_workerRunning.store(0, std::memory_order_release);
        ExitThread(0);
    }
    FinishWorkerExit(PrepareWorkerExit(allowRestart));
}

static DWORD PipeThreadBody() {
    g_dbThread = 1;
    g_workerRunning.store(1, std::memory_order_release);
    if (WaitForStop(0)) WorkerExit(true);
    PrepareProcessIdentity();
    OpenSourceMapping();
    OpenCryptoMapping();
    if (!InstallHooks()) {
        WorkerExit(false);
        return 0;
    }

    while (!WaitForStop(0)) {
        privateclip::Poll();
        if (g_pipe == INVALID_HANDLE_VALUE) {
            HANDLE pipe = CreateFileW(g_pipeName.c_str(), GENERIC_READ | GENERIC_WRITE,
                                      0, nullptr, OPEN_EXISTING, 0, nullptr);
            if (pipe == INVALID_HANDLE_VALUE) {
                WaitForStop(2000);
                continue;
            }
            if (!IsTrustedPipeServer(pipe)) {
                CloseHandle(pipe);
                WaitForStop(2000);
                continue;
            }
            EnterCriticalSection(&g_pipeCs);
            g_pipe = pipe;
            LeaveCriticalSection(&g_pipeCs);
            DWORD mode = PIPE_READMODE_BYTE;
            SetNamedPipeHandleState(g_pipe, &mode, nullptr, nullptr);
            g_dbPipe = 1;
        }

        if (!SendConfirmationRequests()) {
            ClosePipe();
            g_dbPipe = 0;
            continue;
        }

        for (;;) {
            if (g_stop.load(std::memory_order_acquire)) break;
            PendingEvent e;
            {
                EnterCriticalSection(&g_qcs);
                if (g_queue.empty()) {
                    LeaveCriticalSection(&g_qcs);
                    break;
                }
                e = std::move(g_queue.front());
                const size_t snapshotBytes = e.snapshot.size();
                g_queuedSnapshotBytes -=
                    (std::min)(g_queuedSnapshotBytes, snapshotBytes);
                g_queue.pop_front();
                LeaveCriticalSection(&g_qcs);
            }
            if (!SendEvent(e)) {
                bool requeued = false;
                const unsigned long long lostIfNotRequeued =
                    e.droppedBefore + 1;
                EnterCriticalSection(&g_qcs);
                if (g_queue.size() < kEventQueueCapacity) {
                    if (!e.snapshot.empty() &&
                        e.snapshot.size() >
                            kQueuedSnapshotBytesCapacity -
                                (std::min)(g_queuedSnapshotBytes,
                                           kQueuedSnapshotBytesCapacity)) {
                        std::vector<BYTE>().swap(e.snapshot);
                        e.snapshotKind = clip::kSnapshotDiscarded;
                    }
                    const size_t snapshotBytes = e.snapshot.size();
                    try {
                        g_queuedSnapshotBytes += snapshotBytes;
                        g_queue.push_front(std::move(e));
                        requeued = true;
                    } catch (...) {
                        g_queuedSnapshotBytes -= snapshotBytes;
                    }
                }
                LeaveCriticalSection(&g_qcs);
                if (!requeued)
                    g_droppedEvents.fetch_add(lostIfNotRequeued,
                                              std::memory_order_relaxed);
                ClosePipe();
                g_dbPipe = 0;
                break;
            }
        }

        if (g_pipe != INVALID_HANDLE_VALUE && !SendEventGap()) {
            ClosePipe();
            g_dbPipe = 0;
        }

        if (g_stop.load(std::memory_order_acquire)) break;
        if (PumpServerMessages() < 0) {
            ClosePipe();
        }
        WaitForStop(30);
    }

    bool shutdownRequested = g_shutdownRequested.exchange(false,
                                                           std::memory_order_acq_rel);
    g_connected.store(false, std::memory_order_release);
    bool hooksRemoved = RemoveHooks();
    const bool rundownOk = !hooksRemoved || WaitForModuleRundown();
    HMODULE exitingModule = nullptr;
    if (hooksRemoved && shutdownRequested && rundownOk)
        exitingModule = PrepareWorkerExit(false);
    // A shutdown ACK proves fail-open, successful Detour removal, and that no
    // target thread can still return through this module's code pages. The
    // old worker state is published before ACK so immediate reinjection must
    // acquire a new module reference instead of racing this thread's release.
    if (shutdownRequested && hooksRemoved && rundownOk &&
        g_pipe != INVALID_HANDLE_VALUE) {
        std::string ack;
        clip::PutFrame(ack, clip::kIpcShutdownAck);
        (void)SendAll(ack);
    }
    ClosePipe();
    // A controller-initiated shutdown is terminal for this injected module;
    // allowing EnsureWorker to restart between ACK and stop-event propagation
    // would invalidate the ACK's lifecycle guarantee.
    if (hooksRemoved && rundownOk) {
        if (shutdownRequested) FinishWorkerExit(exitingModule);
        WorkerExit(true, true);
    }

    // 无法安全移除 Detours 时保留模块引用，宁可泄漏到进程退出也不卸载代码页。
    g_workerRunning.store(0, std::memory_order_release);
    return 0;
}

static DWORD PipeThreadCpp() {
    try {
        return PipeThreadBody();
    } catch (...) {
        g_connected.store(false, std::memory_order_release);
        ClosePipe();
        if (RemoveHooks()) WorkerExit(false);
        // 保留模块引用和可能仍存在的 Hook，所有 API 因 disconnected 而 fail-open。
        g_workerRunning.store(0, std::memory_order_release);
        return ERROR_UNHANDLED_EXCEPTION;
    }
}

static DWORD WINAPI PipeThread(LPVOID) {
    __try {
        return PipeThreadCpp();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        g_connected.store(false, std::memory_order_release);
        g_stop.store(true, std::memory_order_release);
        // Keep the module and synchronization objects alive while a clean-up
        // thread gets a normal stack to attempt DetourDetach. If creation
        // fails, leaving g_hooksInstalled set intentionally prevents unload.
        HANDLE recovery = CreateThread(nullptr, 0, [](LPVOID) -> DWORD {
            __try {
                bool removed = RemoveHooks();
                ClosePipe();
                CloseControllerSignals();
                if (removed) {
                    g_hooksInstalled.store(false, std::memory_order_release);
                    WorkerExit(false);
                }
                g_workerRunning.store(0, std::memory_order_release);
                return removed ? 0 : ERROR_FUNCTION_FAILED;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                g_connected.store(false, std::memory_order_release);
                g_workerRunning.store(0, std::memory_order_release);
                return GetExceptionCode();
            }
        }, nullptr, 0, nullptr);
        if (recovery) {
            CloseHandle(recovery);
        } else {
            CloseControllerSignals();
            g_workerRunning.store(0, std::memory_order_release);
        }
        return GetExceptionCode();
    }
}

// ---------------- 钩子实现（C++ 主体 + SEH 外壳） ----------------

static clip::RuleMatch CurrentRule(unsigned char operation, bool textFormat,
                                   const clip::RuleSourceIdentity& source,
                                   const std::wstring* content,
                                   bool contentComplete) {
    clip::RuleMatch match;
    const auto rules =
        std::atomic_load_explicit(&g_rules, std::memory_order_acquire);
    if (!rules) return match;
    try {
        (void)clip::FindClipboardRule(
            *rules, g_processNameLower, g_processPathLower,
            GetCurrentProcessId(), operation, textFormat, source, content,
            contentComplete, match);
    } catch (...) {
    }
    return match;
}

static std::wstring DialogPreview(const std::wstring& content) {
    std::wstring preview = content.substr(0, 256);
    for (wchar_t& value : preview) {
        if (value == L'\r' || value == L'\n' || value == L'\t') continue;
        if (value < 0x20) value = L' ';
    }
    if (content.size() > preview.size()) preview += L"\n…（内容已截断）";
    return preview;
}

static bool ConfirmAccess(const clip::RuleMatch& match, clip::ClipOp operation,
                          UINT format,
                          const clip::RuleSourceIdentity& source,
                          const std::wstring& content) {
#ifdef CLIP_TEST_EXPORTS
    wchar_t responseText[16] = {};
    const DWORD responseLength = GetEnvironmentVariableW(
        L"CLIP_TEST_CONFIRM_RESPONSE", responseText, _countof(responseText));
    if (responseLength > 0 && responseLength < _countof(responseText)) {
        if (_wcsicmp(responseText, L"allow") == 0) return true;
        if (_wcsicmp(responseText, L"block") == 0) return false;
    }
#endif
    const bool defaultAllow = !match.timeoutBlock;
    if (!g_connected.load(std::memory_order_acquire)) return defaultAllow;

    HANDLE event = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    if (!event) return defaultAllow;
    unsigned long long token = g_nextConfirmationToken.fetch_add(
        1, std::memory_order_relaxed);
    if (token == 0)
        token = g_nextConfirmationToken.fetch_add(1,
                                                   std::memory_order_relaxed);
    ConfirmationWaiter waiter{event, defaultAllow, false, defaultAllow};
    PendingConfirmationRequest request;
    try {
        request.token = token;
        request.operation = operation;
        request.format = format;
        if (source.known) {
            request.sourceProcessId = source.pid;
            request.sourceProcess = source.nameLower;
            request.sourcePath = source.pathLower;
        }
        request.ruleName = match.name.substr(0, 128);
        request.previewKind = &content == &g_cryptoAddressPlaceholder
            ? clip::PreviewKind::CryptoAddress
            : &content == &g_sensitiveContentPlaceholder ? clip::PreviewKind::Sensitive
            : content.empty() ? clip::PreviewKind::Empty
            : content.size() > 256 ? clip::PreviewKind::Truncated : clip::PreviewKind::Text;
        request.preview = content.empty() ? L"（无可显示文本）"
                                          : DialogPreview(content);
        request.timeoutMs = (std::clamp)(match.confirmTimeoutMs, 1000u,
                                         60000u);
        request.timeoutBlock = match.timeoutBlock;
    } catch (...) {
        CloseHandle(event);
        return defaultAllow;
    }
    const DWORD timeoutMs = request.timeoutMs;

    bool queued = false;
    EnterCriticalSection(&g_confirmationCs);
    try {
        if (g_confirmationQueue.size() < kConfirmationQueueCapacity) {
            g_confirmationWaiters.emplace(token, &waiter);
            try {
                g_confirmationQueue.push_back(std::move(request));
                queued = true;
            } catch (...) {
                g_confirmationWaiters.erase(token);
            }
        }
    } catch (...) {
        g_confirmationWaiters.erase(token);
    }
    LeaveCriticalSection(&g_confirmationCs);
    if (!queued) {
        CloseHandle(event);
        return defaultAllow;
    }

    HANDLE waits[2] = {event, g_stopEvent};
    const DWORD waitCount = g_stopEvent ? 2 : 1;
    WaitForMultipleObjects(waitCount, waits, FALSE, timeoutMs);

    bool allow = defaultAllow;
    EnterCriticalSection(&g_confirmationCs);
    if (waiter.completed) allow = waiter.allow;
    g_confirmationWaiters.erase(token);
    const auto unsent = std::find_if(
        g_confirmationQueue.begin(), g_confirmationQueue.end(),
        [token](const PendingConfirmationRequest& pending) {
            return pending.token == token;
        });
    if (unsent != g_confirmationQueue.end())
        g_confirmationQueue.erase(unsent);
    LeaveCriticalSection(&g_confirmationCs);
    CloseHandle(event);
    return allow;
}

static BOOL WINAPI OpenClipboard_Impl(HWND owner) {
    BOOL privateResult = FALSE;
    if (privateclip::Open(owner, privateResult)) return privateResult;
    DWORD incomingLastError = GetLastError();
    const int state = PausedState();
    if (state != 2 && state != 0 && ShortcutOnlyEnabled() &&
        !AnyShortcutTokenActive()) {
        QueueShortcutBlock(clip::kOpOpen, 0);
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    SetLastError(incomingLastError);
    const BOOL opened = Real_OpenClipboard(owner);
    if (opened) {
        g_clipboardModified = false;
        g_cryptoClearPending = false;
    }
    return opened;
}

static BOOL WINAPI OpenClipboard_Cpp(HWND owner) noexcept {
    DWORD incomingLastError = GetLastError();
    try {
        return OpenClipboard_Impl(owner);
    } catch (...) {
        if (privateclip::Blocking()) { privateclip::Fault(); SetLastError(ERROR_ACCESS_DENIED); return 0; }
        SetLastError(incomingLastError);
        return Real_OpenClipboard ? Real_OpenClipboard(owner) : FALSE;
    }
}

static BOOL WINAPI Hooked_OpenClipboard(HWND owner) {
    DWORD incomingLastError = GetLastError();
    BOOL result = FALSE;
    g_activeDetourCalls.fetch_add(1, std::memory_order_acq_rel);
    __try {
        __try {
            result = OpenClipboard_Cpp(owner);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            UNREFERENCED_PARAMETER(incomingLastError);
            SetLastError(ERROR_FUNCTION_FAILED);
            result = FALSE;
        }
    }
    __finally {
        g_activeDetourCalls.fetch_sub(1, std::memory_order_acq_rel);
    }
    return result;
}

static BOOL WINAPI CloseClipboard_Impl() {
    BOOL privateResult = FALSE;
    if (privateclip::Close(privateResult)) return privateResult;
    const DWORD incomingLastError = GetLastError();
    // Clear before releasing the OS clipboard lock, so another writer cannot
    // publish a new baseline that this transaction would subsequently erase.
    if (g_cryptoClearPending) {
        ClearCryptoAddress();
        g_cryptoClearPending = false;
    }
    SetLastError(incomingLastError);
    const BOOL closed = Real_CloseClipboard();
    const DWORD lastError = GetLastError();
    if (closed && g_clipboardModified) PublishClipboardSource();
    g_clipboardModified = false;
    SetLastError(lastError);
    return closed;
}

static BOOL WINAPI CloseClipboard_Cpp() noexcept {
    const DWORD incomingLastError = GetLastError();
    try {
        return CloseClipboard_Impl();
    } catch (...) {
        if (privateclip::Blocking()) { privateclip::Fault(); SetLastError(ERROR_ACCESS_DENIED); return 0; }
        SetLastError(incomingLastError);
        return Real_CloseClipboard ? Real_CloseClipboard() : FALSE;
    }
}

static BOOL WINAPI Hooked_CloseClipboard() {
    BOOL result = FALSE;
    g_activeDetourCalls.fetch_add(1, std::memory_order_acq_rel);
    __try {
        __try {
            result = CloseClipboard_Cpp();
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            SetLastError(ERROR_FUNCTION_FAILED);
            result = FALSE;
        }
    }
    __finally {
        g_activeDetourCalls.fetch_sub(1, std::memory_order_acq_rel);
    }
    return result;
}

static HANDLE WINAPI GetClipboardData_Impl(UINT fmt) {
    HANDLE privateResult = nullptr;
    if (privateclip::Get(fmt, privateResult)) return privateResult;
    DWORD incomingLastError = GetLastError();
    int state = PausedState();
    if (state == 2) {
        SetLastError(incomingLastError);
        return Real_GetClipboardData(fmt);
    }
    if (IgnoreCustomClipboardFormat(fmt)) {
        const DWORD sequence = GetClipboardSequenceNumber();
        clip::RuleSourceIdentity source = CurrentClipboardSource(sequence);
        if (state != 0 && ShortcutOnlyEnabled() &&
            !ShortcutTokenActive(false)) {
            QueueEvent(clip::kOpRead, fmt, clip::kRuleBlock, true, 0, L"",
                       sequence, &source, &g_ignoreCustomFormatName, false,
                       false, nullptr, true);
            SetLastError(ERROR_ACCESS_DENIED);
            return nullptr;
        }
        SetLastError(incomingLastError);
        HANDLE result = Real_GetClipboardData(fmt);
        const DWORD lastError = GetLastError();
        QueueEvent(clip::kOpRead, fmt, clip::kRuleAllow, false, 0, L"",
                   sequence, &source, &g_ignoreCustomFormatName, false,
                   false, nullptr, true);
        SetLastError(lastError);
        return result;
    }
    if (state != 0 && ShortcutOnlyEnabled() &&
        !ShortcutTokenActive(false)) {
        QueueShortcutBlock(clip::kOpRead, fmt);
        SetLastError(ERROR_ACCESS_DENIED);
        return nullptr;
    }
    const bool directShortcutRead = DirectShortcutAllowed(false);
    SetLastError(incomingLastError);
    HANDLE h = Real_GetClipboardData(fmt);
    DWORD lastError = GetLastError();
    const DWORD sequence = GetClipboardSequenceNumber();
    clip::RuleSourceIdentity source = CurrentClipboardSource(sequence);
    std::wstring content;
    unsigned long long hash = 0;
    bool contentComplete = false;
    bool textFormat = false;
    const bool hasContent =
        PeekClipboardText(fmt, h, content, hash, contentComplete, textFormat);
    const bool sensitiveContent =
        hasContent && contentComplete &&
        clip::IsPrivateKeyOrMnemonicContent(content);
    std::vector<clip::CryptoAddress> cryptoAddresses;
    const bool cryptoComplete = textFormat && PeekCryptoAddresses(
        fmt, h, content, hasContent && contentComplete, cryptoAddresses);
    const bool cryptoCandidate = cryptoComplete && !cryptoAddresses.empty();
    CryptoSnapshot cryptoSnapshot;
    const CryptoLookup cryptoLookup = ReadCryptoSnapshot(cryptoSnapshot);
    const bool cryptoMismatch = cryptoComplete &&
        cryptoLookup == CryptoLookup::active &&
        clip::HasCryptoAddressReplacement(cryptoSnapshot.addresses, cryptoAddresses);
    if (!directShortcutRead && cryptoMismatch) {
        QueueCryptoBlock(clip::kOpRead, fmt, &source,
                         g_cryptoReplacementName, true);
        SetLastError(ERROR_ACCESS_DENIED);
        return nullptr;
    }
    clip::RuleMatch match;
    if (directShortcutRead) {
        match.name = g_shortcutPasteAllowName;
    } else if (state != 0) {
        match = CurrentRule(clip::kRuleRead, textFormat, source,
                            hasContent ? &content : nullptr, contentComplete);
    }
    const bool cryptoProtectedContent =
        cryptoCandidate && CryptoFeatureEnabled();
    const bool redactContent = match.redactContent || sensitiveContent ||
                               cryptoProtectedContent;
    bool allow = match.action != clip::kRuleBlock;
    if (allow && match.action == clip::kRuleConfirm) {
        const std::wstring& confirmationContent =
            cryptoProtectedContent
                ? g_cryptoAddressPlaceholder
                : redactContent ? g_sensitiveContentPlaceholder : content;
        allow = ConfirmAccess(match, clip::kOpRead, fmt, source,
                              confirmationContent);
    }
    std::wstring preview;
    if (hasContent && !redactContent &&
        (PreviewEnabled() || match.showNotification ||
         match.action == clip::kRuleConfirm))
        preview = content.substr(0, 64);
    if (!allow) {
        QueueEvent(clip::kOpRead, fmt, static_cast<BYTE>(match.action), true,
                   redactContent ? 0 : hash,
                   cryptoProtectedContent ? g_cryptoAddressPlaceholder : preview,
                   sequence, &source,
                   &match.name, match.showNotification,
                   cryptoProtectedContent, nullptr,
                   match.hideFromLogList, directShortcutRead ? clip::BuiltinRule::PasteAllowed : clip::BuiltinRule::None);
        SetLastError(ERROR_ACCESS_DENIED);
        return nullptr;
    }
    ClipboardSnapshot snapshot = CaptureClipboardSnapshot(fmt, h);
    QueueEvent(clip::kOpRead, fmt, static_cast<BYTE>(match.action), false,
               redactContent ? 0 : hash,
               cryptoProtectedContent ? g_cryptoAddressPlaceholder : preview,
               sequence, &source, &match.name, match.showNotification,
               cryptoProtectedContent, &snapshot, match.hideFromLogList, directShortcutRead ? clip::BuiltinRule::PasteAllowed : clip::BuiltinRule::None);
    SetLastError(lastError);
    return h;
}

static HANDLE WINAPI GetClipboardData_Cpp(UINT fmt) noexcept {
    DWORD incomingLastError = GetLastError();
    try {
        return GetClipboardData_Impl(fmt);
    } catch (...) {
        if (privateclip::Blocking()) { privateclip::Fault(); SetLastError(ERROR_ACCESS_DENIED); return 0; }
        SetLastError(incomingLastError);
        return Real_GetClipboardData ? Real_GetClipboardData(fmt) : nullptr;
    }
}

static HANDLE WINAPI Hooked_GetClipboardData(UINT fmt) {
#ifdef CLIP_TEST_EXPORTS
    g_testHookCalls.fetch_add(1, std::memory_order_relaxed);
#endif
    DWORD incomingLastError = GetLastError();
    HANDLE result = nullptr;
    g_activeDetourCalls.fetch_add(1, std::memory_order_acq_rel);
    __try {
        __try {
            result = GetClipboardData_Cpp(fmt);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            UNREFERENCED_PARAMETER(incomingLastError);
            SetLastError(ERROR_FUNCTION_FAILED);
            result = nullptr;
        }
    }
    __finally {
        g_activeDetourCalls.fetch_sub(1, std::memory_order_acq_rel);
    }
    return result;
}

static HANDLE WINAPI SetClipboardData_Impl(UINT fmt, HANDLE mem) {
    HANDLE privateResult = nullptr;
    if (privateclip::Set(fmt, mem, privateResult)) return privateResult;
    DWORD incomingLastError = GetLastError();
    int state = PausedState();
    if (state == 2) {
        SetLastError(incomingLastError);
        return Real_SetClipboardData(fmt, mem);
    }
    if (IgnoreCustomClipboardFormat(fmt)) {
        clip::RuleSourceIdentity source;
        source.known = true;
        source.pid = GetCurrentProcessId();
        source.nameLower = g_processNameLower;
        source.pathLower = g_processPathLower;
        if (state != 0 && ShortcutOnlyEnabled() &&
            !ShortcutTokenActive(true)) {
            QueueEvent(clip::kOpWrite, fmt, clip::kRuleBlock, true, 0, L"",
                       GetClipboardSequenceNumber(), &source,
                       &g_ignoreCustomFormatName, false, false, nullptr, true);
            SetLastError(ERROR_ACCESS_DENIED);
            return nullptr;
        }
        SetLastError(incomingLastError);
        HANDLE result = Real_SetClipboardData(fmt, mem);
        const DWORD lastError = GetLastError();
        QueueEvent(clip::kOpWrite, fmt, clip::kRuleAllow, false, 0, L"",
                   GetClipboardSequenceNumber(), &source,
                   &g_ignoreCustomFormatName, false, false, nullptr, true);
        SetLastError(lastError);
        return result;
    }
    if (state != 0 && ShortcutOnlyEnabled() &&
        !ShortcutTokenActive(true)) {
        QueueShortcutBlock(clip::kOpWrite, fmt);
        SetLastError(ERROR_ACCESS_DENIED);
        return nullptr;
    }
    const bool directShortcutWrite = DirectShortcutAllowed(true);
    clip::RuleSourceIdentity source;
    source.known = true;
    source.pid = GetCurrentProcessId();
    source.nameLower = g_processNameLower;
    source.pathLower = g_processPathLower;
    std::wstring content;
    unsigned long long hash = 0;
    bool contentComplete = false;
    bool textFormat = false;
    const bool hasContent =
        PeekClipboardText(fmt, mem, content, hash, contentComplete, textFormat);
    const bool sensitiveContent =
        hasContent && contentComplete &&
        clip::IsPrivateKeyOrMnemonicContent(content);
    std::vector<clip::CryptoAddress> cryptoAddresses;
    const bool cryptoComplete = textFormat && PeekCryptoAddresses(
        fmt, mem, content, hasContent && contentComplete, cryptoAddresses);
    const bool cryptoCandidate = cryptoComplete && !cryptoAddresses.empty();
    CryptoSnapshot cryptoSnapshot;
    const CryptoLookup cryptoLookup = ReadCryptoSnapshot(cryptoSnapshot);
    const bool likelyUserWrite = LikelyUserClipboardWrite();
    const bool cryptoMismatch = cryptoComplete &&
        cryptoLookup == CryptoLookup::active &&
        clip::HasCryptoAddressReplacement(cryptoSnapshot.addresses, cryptoAddresses);
    if (!likelyUserWrite && cryptoMismatch) {
        QueueCryptoBlock(clip::kOpWrite, fmt, &source,
                         g_cryptoReplacementName, true);
        SetLastError(ERROR_ACCESS_DENIED);
        return nullptr;
    }
    clip::RuleMatch match;
    if (directShortcutWrite) {
        match.name = g_shortcutCopyAllowName;
    } else if (state != 0) {
        match = CurrentRule(clip::kRuleWrite, textFormat, source,
                            hasContent ? &content : nullptr, contentComplete);
    }
    const bool cryptoProtectedContent =
        cryptoCandidate && CryptoFeatureEnabled();
    const bool redactContent = match.redactContent || sensitiveContent ||
                               cryptoProtectedContent;
    bool allow = match.action != clip::kRuleBlock;
    if (allow && match.action == clip::kRuleConfirm) {
        const std::wstring& confirmationContent =
            cryptoProtectedContent
                ? g_cryptoAddressPlaceholder
                : redactContent ? g_sensitiveContentPlaceholder : content;
        allow = ConfirmAccess(match, clip::kOpWrite, fmt, source,
                              confirmationContent);
    }
    std::wstring preview;
    if (hasContent && !redactContent &&
        (PreviewEnabled() || match.showNotification ||
         match.action == clip::kRuleConfirm))
        preview = content.substr(0, 64);
    if (!allow) {
        QueueEvent(clip::kOpWrite, fmt, static_cast<BYTE>(match.action), true,
                   redactContent ? 0 : hash,
                   cryptoProtectedContent ? g_cryptoAddressPlaceholder : preview,
                   GetClipboardSequenceNumber(), &source, &match.name,
                   match.showNotification, cryptoProtectedContent, nullptr,
                   match.hideFromLogList, directShortcutWrite ? clip::BuiltinRule::CopyAllowed : clip::BuiltinRule::None);
        SetLastError(ERROR_ACCESS_DENIED);
        return nullptr;
    }
    ClipboardSnapshot snapshot = CaptureClipboardSnapshot(fmt, mem);
    SetLastError(incomingLastError);
    HANDLE h = Real_SetClipboardData(fmt, mem);
    DWORD lastError = GetLastError();
    if (h) {
        g_clipboardModified = true;
        if (cryptoComplete) {
            if (cryptoCandidate)
                PublishCryptoAddress(cryptoAddresses, GetClipboardSequenceNumber());
            else
                ClearCryptoAddress();
            g_cryptoClearPending = false;
        }
    }
    QueueEvent(clip::kOpWrite, fmt, static_cast<BYTE>(match.action), false,
               redactContent ? 0 : hash,
               cryptoProtectedContent ? g_cryptoAddressPlaceholder : preview,
               GetClipboardSequenceNumber(), &source, &match.name,
               match.showNotification, cryptoProtectedContent, &snapshot,
               match.hideFromLogList, directShortcutWrite ? clip::BuiltinRule::CopyAllowed : clip::BuiltinRule::None);
    SetLastError(lastError);
    return h;
}

static HANDLE WINAPI SetClipboardData_Cpp(UINT fmt, HANDLE mem) noexcept {
    DWORD incomingLastError = GetLastError();
    try {
        return SetClipboardData_Impl(fmt, mem);
    } catch (...) {
        if (privateclip::Blocking()) { privateclip::Fault(); SetLastError(ERROR_ACCESS_DENIED); return 0; }
        SetLastError(incomingLastError);
        return Real_SetClipboardData ? Real_SetClipboardData(fmt, mem) : nullptr;
    }
}

static HANDLE WINAPI Hooked_SetClipboardData(UINT fmt, HANDLE mem) {
#ifdef CLIP_TEST_EXPORTS
    g_testHookCalls.fetch_add(1, std::memory_order_relaxed);
#endif
    DWORD incomingLastError = GetLastError();
    HANDLE result = nullptr;
    g_activeDetourCalls.fetch_add(1, std::memory_order_acq_rel);
    __try {
        __try {
            result = SetClipboardData_Cpp(fmt, mem);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            UNREFERENCED_PARAMETER(incomingLastError);
            SetLastError(ERROR_FUNCTION_FAILED);
            result = nullptr;
        }
    }
    __finally {
        g_activeDetourCalls.fetch_sub(1, std::memory_order_acq_rel);
    }
    return result;
}

static BOOL WINAPI EmptyClipboard_Impl() {
    BOOL privateResult = FALSE;
    if (privateclip::Empty(privateResult)) return privateResult;
    DWORD incomingLastError = GetLastError();
    int state = PausedState();
    if (state == 2) {
        SetLastError(incomingLastError);
        return Real_EmptyClipboard();
    }
    if (state != 0 && ShortcutOnlyEnabled() &&
        !ShortcutTokenActive(true)) {
        QueueShortcutBlock(clip::kOpClear, 0);
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    SetLastError(incomingLastError);
    BOOL ok = Real_EmptyClipboard();
    DWORD lastError = GetLastError();
    if (ok) {
        g_clipboardModified = true;
        g_cryptoClearPending = true;
    }
    SetLastError(lastError);
    return ok;
}


static BOOL WINAPI EmptyClipboard_Cpp() noexcept {
    DWORD incomingLastError = GetLastError();
    try {
        return EmptyClipboard_Impl();
    } catch (...) {
        if (privateclip::Blocking()) { privateclip::Fault(); SetLastError(ERROR_ACCESS_DENIED); return 0; }
        SetLastError(incomingLastError);
        return Real_EmptyClipboard ? Real_EmptyClipboard() : FALSE;
    }
}

static BOOL WINAPI Hooked_EmptyClipboard() {
#ifdef CLIP_TEST_EXPORTS
    g_testHookCalls.fetch_add(1, std::memory_order_relaxed);
#endif
    DWORD incomingLastError = GetLastError();
    BOOL result = FALSE;
    g_activeDetourCalls.fetch_add(1, std::memory_order_acq_rel);
    __try {
        __try {
            result = EmptyClipboard_Cpp();
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            UNREFERENCED_PARAMETER(incomingLastError);
            SetLastError(ERROR_FUNCTION_FAILED);
            result = FALSE;
        }
    }
    __finally {
        g_activeDetourCalls.fetch_sub(1, std::memory_order_acq_rel);
    }
    return result;
}

// ---------------- 导出的钩子过程 ----------------

static void EnsureWorker(bool explicitStart) {
    if (g_isSelf) return;
    if (explicitStart &&
        g_workerRunning.load(std::memory_order_acquire) == 0 &&
        !g_hooksInstalled.load(std::memory_order_acquire)) {
        bool terminal = true;
        if (g_workerStarted.compare_exchange_strong(
                terminal, false, std::memory_order_acq_rel)) {
            g_stop.store(false, std::memory_order_release);
            g_shutdownRequested.store(false, std::memory_order_release);
            g_connected.store(false, std::memory_order_release);
            g_controlInput.clear();
            g_controlPartialSince = 0;
            EnterCriticalSection(&g_qcs);
            g_queue.clear();
            g_queuedSnapshotBytes = 0;
            LeaveCriticalSection(&g_qcs);
            CancelConfirmations();
            g_droppedEvents.store(0, std::memory_order_release);
            g_extendedStateApplied.store(false,
                                         std::memory_order_release);
            g_notificationStateApplied.store(false,
                                             std::memory_order_release);
            g_logVisibilityStateApplied.store(false,
                                              std::memory_order_release);
            g_snapshotProtocolCapable.store(false,
                                            std::memory_order_release);
            g_snapshotTransportEnabled.store(false,
                                             std::memory_order_release);
        }
    }
    bool expected = false;
    if (!g_workerStarted.compare_exchange_strong(expected, true)) return;

    std::wstring stopEventName =
        clip::ResolveObjectName(L"CLIP_TEST_STOP_EVENT", clip::kStopEventName);
    std::wstring controllerMutexName =
        clip::ResolveObjectName(L"CLIP_TEST_CONTROLLER_MUTEX",
                                clip::kSingleInstanceMutexName);
    g_pipeName = clip::ResolveObjectName(L"CLIP_TEST_PIPE_NAME",
                                         clip::kPipeName);
    g_stopEvent = OpenEventW(SYNCHRONIZE, FALSE, stopEventName.c_str());
    g_controllerMutex = OpenMutexW(SYNCHRONIZE | MUTEX_MODIFY_STATE, FALSE,
                                   controllerMutexName.c_str());
    if (!g_stopEvent || !g_controllerMutex) {
        // Injection is only valid while the controller owns both lifetime
        // signals. Do not install Detours when that owner is already gone.
        CloseControllerSignals();
        g_stop.store(true, std::memory_order_release);
        g_connected.store(false, std::memory_order_release);
        g_workerStarted.store(false, std::memory_order_release);
        return;
    }
    if (g_stopEvent && WaitForSingleObject(g_stopEvent, 0) == WAIT_OBJECT_0) {
        CloseControllerSignals();
        g_workerStarted.store(false, std::memory_order_release);
        return;
    }
    g_stop.store(false, std::memory_order_release);

    if (!g_workerModule.load(std::memory_order_acquire)) {
        HMODULE module = nullptr;
        if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                                reinterpret_cast<LPCWSTR>(&EnsureWorker),
                                &module)) {
            CloseControllerSignals();
            g_workerStarted.store(false, std::memory_order_release);
            return;
        }
        g_workerModule.store(module, std::memory_order_release);
    }
    HANDLE thread = CreateThread(nullptr, 0, PipeThread, nullptr, 0, nullptr);
    if (!thread) {
        CloseControllerSignals();
        g_workerStarted.store(false, std::memory_order_release);
        return;
    }
    CloseHandle(thread);
}

static void EnsureWorkerCpp(bool explicitStart) noexcept {
    try {
        EnsureWorker(explicitStart);
    } catch (...) {
        g_connected.store(false, std::memory_order_release);
        CloseControllerSignals();
        g_workerStarted.store(false, std::memory_order_release);
    }
}

static void EnsureWorkerSafe(bool explicitStart = false) {
    __try {
        EnsureWorkerCpp(explicitStart);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        g_connected.store(false, std::memory_order_release);
        g_workerStarted.store(false, std::memory_order_release);
    }
}

extern "C"
DWORD WINAPI ClipHookStartRemote(LPVOID) {
    EnsureWorkerSafe(true);
    return g_workerStarted.load(std::memory_order_acquire) ? 1 : 0;
}

#ifdef CLIP_TEST_EXPORTS
extern "C" __declspec(dllexport)
void ClipHookStartForTest() {
    EnsureWorkerSafe(true);
}
#endif

extern "C"
LRESULT CALLBACK GetMsgProc(int code, WPARAM wp, LPARAM lp) {
    bool explicitStart = false;
    if (code >= 0 && lp) {
        const auto* message = reinterpret_cast<const MSG*>(lp);
        if (!privateclip::Blocking()) ObserveShortcutMessage(*message, wp);
        static std::atomic<UINT> startMessageId{0};
        UINT startMessage = startMessageId.load(std::memory_order_acquire);
        if (startMessage == 0) {
            startMessage = RegisterWindowMessageW(
                clip::kTargetHookStartMessageName);
            if (startMessage != 0)
                startMessageId.store(startMessage, std::memory_order_release);
        }
        explicitStart = startMessage != 0 && message->message == startMessage;
    }
    EnsureWorkerSafe(explicitStart);
    return CallNextHookEx(nullptr, code, wp, lp);
}

BOOL APIENTRY DllMain(HMODULE self, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        g_self = self;
        DisableThreadLibraryCalls(self);
        g_isSelf = IsSelfProcess();
        if (!g_isSelf) {
            InitializeCriticalSection(&g_cs);
            InitializeCriticalSection(&g_qcs);
            InitializeCriticalSection(&g_pipeCs);
            InitializeCriticalSection(&g_confirmationCs);
            g_pipeCsInitialized = true;
        }
    } else if (reason == DLL_PROCESS_DETACH) {
        if (g_isSelf) return TRUE;
        g_stop.store(true, std::memory_order_release);
        g_connected.store(false, std::memory_order_release);
        // The worker owns the pipe handle and performs the sole CloseHandle.
        // Do not enter a DLL-owned lock from DllMain during process teardown.
        // A clean stop reaches this path only after the worker has removed all
        // Detours, completed rundown, and released its module reference.
        if (g_workerRunning.load(std::memory_order_acquire) == 0 &&
            !g_hooksInstalled.load(std::memory_order_acquire) &&
            g_pipeCsInitialized) {
            DeleteCriticalSection(&g_cs);
            DeleteCriticalSection(&g_qcs);
            DeleteCriticalSection(&g_pipeCs);
            DeleteCriticalSection(&g_confirmationCs);
            g_pipeCsInitialized = false;
        }
    }
    return TRUE;
}
