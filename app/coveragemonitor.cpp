#include "coveragemonitor.h"

#include "pipeserver.h"
#include "remotehook.h"
#include "winutil.h"

#include <tlhelp32.h>
#include <algorithm>
#include <unordered_map>
#include <unordered_set>

namespace clip {
namespace {

constexpr ULONGLONG kScanIntervalMs = 2000;
constexpr ULONGLONG kGlobalHookGraceMs = 4000;
constexpr unsigned kMaximumStartsPerScan = 4;

struct ScopedHandle {
    HANDLE value = nullptr;
    ~ScopedHandle() {
        if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value);
    }
    explicit operator bool() const {
        return value && value != INVALID_HANDLE_VALUE;
    }
};

bool IsCriticalProcess(HANDLE process) {
    using Function = BOOL(WINAPI*)(HANDLE, PBOOL);
    static const auto function = reinterpret_cast<Function>(GetProcAddress(
        GetModuleHandleW(L"kernel32.dll"), "IsProcessCritical"));
    BOOL critical = FALSE;
    return function && function(process, &critical) && critical;
}

bool IsInternalProcess(const std::wstring& path) {
    const size_t slash = path.find_last_of(L"\\/");
    const wchar_t* name = slash == std::wstring::npos
                              ? path.c_str()
                              : path.c_str() + slash + 1;
    return _wcsicmp(name, L"ClipboardProtector.exe") == 0 ||
           _wcsicmp(name, L"HookHost32.exe") == 0 ||
           _wcsicmp(name, L"HookDllUnloader.exe") == 0 ||
           _wcsicmp(name, L"HookDllUnloader32.exe") == 0;
}

ULONGLONG BackoffDelay(unsigned attempts) {
    if (attempts <= 1) return 5000;
    if (attempts == 2) return 15000;
    return 60000;
}

#ifdef CLIP_TEST_OBJECT_NAMES
bool TestCoverageTargetPath(std::wstring& path) {
    std::vector<wchar_t> buffer(32768);
    const DWORD length = GetEnvironmentVariableW(
        L"CLIP_TEST_COVERAGE_TARGET_PATH", buffer.data(),
        static_cast<DWORD>(buffer.size()));
    if (length == 0 || length >= buffer.size()) return false;
    path.assign(buffer.data(), length);
    return true;
}
#endif

bool QueryArchitecture(HANDLE process,
                       CoverageMonitor::Architecture& architecture) {
    BOOL targetWow64 = FALSE;
    if (!IsWow64Process(process, &targetWow64)) return false;
#ifdef _WIN64
    architecture = targetWow64 ? CoverageMonitor::Architecture::x86
                               : CoverageMonitor::Architecture::native;
    return true;
#else
    BOOL currentWow64 = FALSE;
    if (!IsWow64Process(GetCurrentProcess(), &currentWow64) ||
        currentWow64 != targetWow64)
        return false;
    architecture = CoverageMonitor::Architecture::native;
    return true;
#endif
}

} // namespace

CoverageMonitor::~CoverageMonitor() {
    Pause();
    if (stopEvent_) CloseHandle(stopEvent_);
}

bool CoverageMonitor::LoadCurrentUserSid() {
    ScopedHandle token;
    token.value = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token.value))
        return false;
    DWORD bytes = 0;
    GetTokenInformation(token.value, TokenUser, nullptr, 0, &bytes);
    if (bytes == 0 || GetLastError() != ERROR_INSUFFICIENT_BUFFER) return false;
    try {
        currentUserSid_.resize(bytes);
    } catch (...) {
        return false;
    }
    if (!GetTokenInformation(token.value, TokenUser, currentUserSid_.data(),
                             bytes, &bytes)) {
        currentUserSid_.clear();
        return false;
    }
    return true;
}

bool CoverageMonitor::SameUser(HANDLE process) const {
    if (currentUserSid_.empty()) return false;
    ScopedHandle token;
    if (!OpenProcessToken(process, TOKEN_QUERY, &token.value)) return false;
    DWORD bytes = 0;
    GetTokenInformation(token.value, TokenUser, nullptr, 0, &bytes);
    if (bytes == 0 || GetLastError() != ERROR_INSUFFICIENT_BUFFER) return false;
    std::vector<BYTE> target;
    try {
        target.resize(bytes);
    } catch (...) {
        return false;
    }
    if (!GetTokenInformation(token.value, TokenUser, target.data(), bytes,
                             &bytes))
        return false;
    const auto* current =
        reinterpret_cast<const TOKEN_USER*>(currentUserSid_.data());
    const auto* other = reinterpret_cast<const TOKEN_USER*>(target.data());
    return EqualSid(current->User.Sid, other->User.Sid) != FALSE;
}

bool CoverageMonitor::Start(PipeServer& server,
                            const std::wstring& nativeDllPath,
                            const std::wstring& helper32Path,
                            const std::wstring& dll32Path) {
    if (thread_) return true;
    if (nativeDllPath.empty() || !LoadCurrentUserSid()) return false;
    server_ = &server;
    nativeDllPath_ = nativeDllPath;
    helper32Path_ = helper32Path;
    dll32Path_ = dll32Path;
    if (!stopEvent_)
        stopEvent_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!stopEvent_) return false;
    return Resume();
}

bool CoverageMonitor::Pause() {
    if (!thread_) return true;
    SetEvent(stopEvent_);
    // 有界等待：巡检线程可能正阻塞在一次远程调用里（最长约 20s）。退出
    // 或切换保护时不能被它无限拖住；超时后线程会自行观察到停止事件并
    // 退出，Resume() 会先回收旧线程再重建。
    const DWORD wait = WaitForSingleObject(thread_, 3000);
    if (wait != WAIT_OBJECT_0) return false;
    CloseHandle(thread_);
    thread_ = nullptr;
    return true;
}

bool CoverageMonitor::Resume() {
    // 上一次 Pause 超时后旧线程可能仍在收尾；先等它退出，避免出现两个
    // 巡检线程同时遍历 entries_。
    if (thread_) {
        if (WaitForSingleObject(thread_, 2000) != WAIT_OBJECT_0) return true;
        CloseHandle(thread_);
        thread_ = nullptr;
    }
    if (!server_ || !stopEvent_ || !ResetEvent(stopEvent_)) return false;
    thread_ = CreateThread(nullptr, 0, ThreadStatic, this, 0, nullptr);
    return thread_ != nullptr;
}

void CoverageMonitor::Clear() {
    if (thread_) return;
    for (auto it = entries_.begin(); it != entries_.end();) {
        if (!it->second.retainedReference)
            it = entries_.erase(it);
        else
            ++it;
    }
}

DWORD WINAPI CoverageMonitor::ThreadStatic(LPVOID parameter) {
    auto* self = static_cast<CoverageMonitor*>(parameter);
    __try {
        return self->ThreadNoThrow();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
}

DWORD CoverageMonitor::ThreadNoThrow() noexcept {
    try {
        return ThreadBody();
    } catch (...) {
        return ERROR_UNHANDLED_EXCEPTION;
    }
}

DWORD CoverageMonitor::ThreadBody() {
    do {
        try {
            Scan();
        } catch (...) {
            // A transient allocation/query failure must not permanently stop
            // future coverage sweeps.
        }
    } while (WaitForSingleObject(stopEvent_, kScanIntervalMs) == WAIT_TIMEOUT);
    return 0;
}

void CoverageMonitor::Scan() {
    if (!server_) return;
#ifdef CLIP_TEST_OBJECT_NAMES
    // Test object names live in the target's inherited environment. Restrict
    // test sweeps explicitly so a smoke run never modifies unrelated apps.
    std::wstring testTargetPath;
    if (!TestCoverageTargetPath(testTargetPath)) return;
#endif
    const ULONGLONG now = GetTickCount64();
    std::unordered_map<DWORD, ULONGLONG> ready;
    std::unordered_set<DWORD> seen;
    try {
        for (const ReadyProcessIdentity& identity :
             server_->ReadyProcessIdentities())
            ready[identity.processId] = identity.creationTime;
        seen.reserve(entries_.size() + 32);
    } catch (...) {
        return;
    }

    DWORD currentSession = 0;
    if (!ProcessIdToSessionId(GetCurrentProcessId(), &currentSession)) return;
    ScopedHandle snapshot;
    snapshot.value = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (!snapshot || snapshot.value == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W processEntry = {sizeof(processEntry)};
    if (!Process32FirstW(snapshot.value, &processEntry)) return;
    do {
        const DWORD processId = processEntry.th32ProcessID;
        if (processId == 0 || processId == 4 ||
            processId == GetCurrentProcessId())
            continue;
        try {
            seen.insert(processId);
        } catch (...) {
            return;
        }
        DWORD targetSession = 0;
        if (!ProcessIdToSessionId(processId, &targetSession) ||
            targetSession != currentSession)
            continue;

        ScopedHandle process;
        process.value = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION |
                                        SYNCHRONIZE,
                                    FALSE, processId);
        if (!process ||
            WaitForSingleObject(process.value, 0) != WAIT_TIMEOUT ||
            IsCriticalProcess(process.value) || !SameUser(process.value))
            continue;
        ULONGLONG creationTime = 0;
        std::wstring path;
        Architecture architecture = Architecture::native;
        if (!ProcessCreationTime(process.value, creationTime) ||
            !ProcessImagePath(process.value, path) || IsInternalProcess(path) ||
            !QueryArchitecture(process.value, architecture))
            continue;
#ifdef CLIP_TEST_OBJECT_NAMES
        if (_wcsicmp(path.c_str(), testTargetPath.c_str()) != 0) continue;
#endif
#ifdef _WIN64
        if (architecture == Architecture::x86 &&
            (helper32Path_.empty() || dll32Path_.empty()))
            continue;
#endif
        auto found = entries_.find(processId);
        if (found == entries_.end() ||
            found->second.creationTime != creationTime) {
            Entry fresh;
            fresh.processId = processId;
            fresh.creationTime = creationTime;
            fresh.architecture = architecture;
            fresh.firstSeen = now;
            fresh.nextAttempt = now + kGlobalHookGraceMs;
            entries_[processId] = std::move(fresh);
            continue;
        }

        Entry& entry = found->second;
        const auto readyIdentity = ready.find(processId);
        const bool isReady = readyIdentity != ready.end() &&
                             readyIdentity->second == creationTime;
        if (isReady) {
            entry.wasReady = true;
            entry.attempts = 0;
            entry.nextAttempt = now + kScanIntervalMs;
            if (entry.retainedReference && now >= entry.nextReleaseAttempt) {
                if (ReleaseTarget(entry)) {
                    entry.retainedReference = false;
                    entry.releaseAttempts = 0;
                } else {
                    ++entry.releaseAttempts;
                    entry.nextReleaseAttempt =
                        now + BackoffDelay(entry.releaseAttempts);
                }
            }
            continue;
        }
        if (entry.wasReady) {
            entry.wasReady = false;
            entry.firstSeen = now;
            entry.nextAttempt = now + kGlobalHookGraceMs;
            continue;
        }
    } while (Process32NextW(snapshot.value, &processEntry));

    for (auto it = entries_.begin(); it != entries_.end();) {
        if (seen.find(it->first) == seen.end())
            it = entries_.erase(it);
        else
            ++it;
    }

    std::vector<Entry*> candidates;
    try {
        candidates.reserve(entries_.size());
        for (auto& item : entries_) {
            Entry& entry = item.second;
            if (!entry.wasReady && now >= entry.nextAttempt)
                candidates.push_back(&entry);
        }
        std::sort(candidates.begin(), candidates.end(),
                  [](const Entry* left, const Entry* right) {
                      if (left->firstSeen != right->firstSeen)
                          return left->firstSeen > right->firstSeen;
                      if (left->attempts != right->attempts)
                          return left->attempts < right->attempts;
                      return left->processId < right->processId;
                  });
    } catch (...) {
        return;
    }
    const size_t count =
        (std::min)(candidates.size(),
                   static_cast<size_t>(kMaximumStartsPerScan));
    for (size_t index = 0; index < count; ++index) {
        if (WaitForSingleObject(stopEvent_, 0) == WAIT_OBJECT_0) break;
        Entry& entry = *candidates[index];
        const bool retainedReference = StartTarget(entry);
        if (retainedReference && !entry.retainedReference) {
            entry.retainedReference = true;
            entry.releaseAttempts = 0;
            entry.nextReleaseAttempt =
                GetTickCount64() + BackoffDelay(1);
        }
        ++entry.attempts;
        entry.nextAttempt = GetTickCount64() + BackoffDelay(entry.attempts);
    }
}

bool CoverageMonitor::StartTarget(const Entry& entry) {
#ifdef _WIN64
    if (entry.architecture == Architecture::x86) {
        DWORD exitCode = kRemoteHelperFailed;
        if (!Run32BitHelper(L"--remote-start", entry, exitCode))
            return exitCode == WAIT_TIMEOUT;
        return exitCode == kRemoteHelperStartedRetained ||
               exitCode == kRemoteHelperFailedRetained;
    }
#endif
    const RemoteHookStartResult result = RemoteHookStart(
        entry.processId, entry.creationTime, nativeDllPath_);
    return result.retainedReference;
}

bool CoverageMonitor::Run32BitHelper(const wchar_t* command,
                                     const Entry& entry, DWORD& exitCode) {
#ifdef _WIN64
    std::wstring commandLine = L"\"" + helper32Path_ + L"\" " + command +
                               L" " + std::to_wstring(entry.processId) +
                               L" " + std::to_wstring(entry.creationTime) +
                               L" \"" + dll32Path_ + L"\"";
    STARTUPINFOW startup = {sizeof(startup)};
    PROCESS_INFORMATION process = {};
    if (!CreateProcessW(helper32Path_.c_str(), commandLine.data(), nullptr,
                        nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr,
                        &startup, &process)) {
        exitCode = GetLastError();
        return false;
    }
    CloseHandle(process.hThread);
    // 同时等待停止事件：退出流程不再被这里最长 20s 的等待拖住。
    HANDLE waits[2] = {process.hProcess, stopEvent_};
    const DWORD wait = stopEvent_
                           ? WaitForMultipleObjects(2, waits, FALSE, 20000)
                           : WaitForSingleObject(process.hProcess, 20000);
    bool completed = wait == WAIT_OBJECT_0 &&
                     GetExitCodeProcess(process.hProcess, &exitCode);
    if (!completed && (wait == WAIT_TIMEOUT || wait == WAIT_OBJECT_0 + 1)) {
        TerminateProcess(process.hProcess, WAIT_TIMEOUT);
        WaitForSingleObject(process.hProcess, 3000);
        exitCode = WAIT_TIMEOUT;
    } else if (!completed) {
        exitCode = GetLastError();
    }
    CloseHandle(process.hProcess);
    return completed;
#else
    UNREFERENCED_PARAMETER(command);
    UNREFERENCED_PARAMETER(entry);
    exitCode = ERROR_NOT_SUPPORTED;
    return false;
#endif
}

bool CoverageMonitor::ReleaseTarget(const Entry& entry) {
#ifdef _WIN64
    if (entry.architecture == Architecture::x86) {
        DWORD exitCode = kRemoteHelperFailed;
        return Run32BitHelper(L"--remote-release", entry, exitCode) &&
               exitCode == kRemoteHelperStarted;
    }
#endif
    DWORD error = ERROR_SUCCESS;
    return RemoteHookRelease(entry.processId, entry.creationTime,
                             nativeDllPath_, error);
}

void CoverageMonitor::ReleaseRetainedReferences() {
    if (thread_) return;
    // 每次释放是一次远程 FreeLibrary（卡在加载器锁的宿主上最多 5s）。
    // 退出路径给整个清理一个总上限：超限条目按泄漏处理，DLL 在宿主中
    // 保留 fail-open 状态，比把退出拖住几分钟更可接受。
    const ULONGLONG deadline = GetTickCount64() + 10000;
    for (int pass = 0; pass < 3; ++pass) {
        bool pending = false;
        for (auto& item : entries_) {
            Entry& entry = item.second;
            if (!entry.retainedReference) continue;
            if (GetTickCount64() >= deadline) return;
            if (ReleaseTarget(entry))
                entry.retainedReference = false;
            else
                pending = true;
        }
        if (!pending) break;
        if (pass != 2) Sleep(50);
    }
}

} // namespace clip
