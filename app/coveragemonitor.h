#pragma once

#include <windows.h>
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
    bool Resume();
    void ReleaseRetainedReferences();
    void Clear();
    bool running() const { return thread_ != nullptr; }

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
        ULONGLONG nextReleaseAttempt = 0;
    };

    static DWORD WINAPI ThreadStatic(LPVOID parameter);
    DWORD ThreadNoThrow() noexcept;
    DWORD ThreadBody();
    void Scan();
    // Returns whether this attempt may have left an extra LoadLibrary ref.
    bool StartTarget(const Entry& entry);
    bool ReleaseTarget(const Entry& entry);
    bool Run32BitHelper(const wchar_t* command, const Entry& entry,
                        DWORD& exitCode);
    bool LoadCurrentUserSid();
    bool SameUser(HANDLE process) const;

    PipeServer* server_ = nullptr;
    HANDLE stopEvent_ = nullptr;
    HANDLE thread_ = nullptr;
    std::wstring nativeDllPath_;
    std::wstring helper32Path_;
    std::wstring dll32Path_;
    std::vector<BYTE> currentUserSid_;
    std::unordered_map<DWORD, Entry> entries_;
};

} // namespace clip
