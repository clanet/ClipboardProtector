#pragma once

#include <windows.h>
#include <atomic>
#include <string>
#include <unordered_map>
#include <vector>

namespace clip {

class PipeServer;

// Complements WH_GETMESSAGE with a bounded, in-memory coverage sweep for
// processes that never dispatch a message and therefore never trigger it.
class CoverageMonitor {
public:
    enum class Architecture { native, x86 };

    ~CoverageMonitor();

    bool Start(PipeServer& server, const std::wstring& nativeDllPath,
               const std::wstring& helper32Path = {},
               const std::wstring& dll32Path = {});
    bool Pause();
    // Final ownership barrier, used only by destruction/final exit workers.
    // Ordinary protection changes use bounded Pause() and abort on failure.
    void Join();
    bool Resume();
    void ReleaseRetainedReferences();
    void Clear();
    bool running() const { return running_.load(std::memory_order_acquire); }

#ifdef CLIP_TEST_COVERAGE_MONITOR
    bool StartBlockedForTest(HANDLE entered, HANDLE resume, HANDLE joining);
#endif

private:
    struct Entry {
        DWORD processId = 0;
        ULONGLONG creationTime = 0;
        Architecture architecture = Architecture::native;
        ULONGLONG firstSeen = 0;
        ULONGLONG nextAttempt = 0;
        unsigned attempts = 0;
        unsigned releaseAttempts = 0;
        bool wasReady = false;
        bool retainedReference = false;
        // A terminated helper may already have submitted FreeLibrary. Keep a
        // tombstone until this process identity exits; never guess and retry.
        bool abandonedReference = false;
        ULONGLONG nextReleaseAttempt = 0;
    };

    static DWORD WINAPI ThreadStatic(LPVOID parameter);
    DWORD ThreadNoThrow() noexcept;
    DWORD ThreadBody();
    void Scan();
    // Returns whether this attempt may have left an extra LoadLibrary ref.
    // allowLoad=false 时只启动已加载的模块，不再追加 LoadLibrary。
    bool StartTarget(Entry& entry, bool allowLoad);
    // True consumes the release responsibility; entry records unknown results.
    bool ReleaseTarget(Entry& entry);
    bool Run32BitHelper(const wchar_t* command, const Entry& entry,
                        DWORD& exitCode, bool& launched);
    bool LoadCurrentUserSid();
    bool SameUser(HANDLE process) const;
    bool ReapStaleThread();

    PipeServer* server_ = nullptr;
    HANDLE stopEvent_ = nullptr;
    HANDLE thread_ = nullptr;
    std::atomic<bool> running_{false};
    std::wstring nativeDllPath_;
    std::wstring helper32Path_;
    std::wstring dll32Path_;
    std::vector<BYTE> currentUserSid_;
    std::unordered_map<DWORD, Entry> entries_;
#ifdef CLIP_TEST_COVERAGE_MONITOR
    HANDLE testEntered_ = nullptr;
    HANDLE testResume_ = nullptr;
    HANDLE testJoining_ = nullptr;
#endif
};

} // namespace clip
