#pragma once
#include <windows.h>
#include <atomic>
#include <memory>

namespace clip {

// Keep the global hook's installing thread responsive while its caller waits
// for pipe clients, coverage workers, or the other architecture's helper.
class HookThread {
public:
    HookThread() = default;
    ~HookThread();
    HookThread(const HookThread&) = delete;
    HookThread& operator=(const HookThread&) = delete;

    // Lifecycle operations are serialized by the protection worker.
    DWORD Install(HOOKPROC procedure, HMODULE module, DWORD targetThreadId);
    DWORD Remove();
    bool installed() const { return installed_.load(std::memory_order_acquire); }

#ifdef CLIP_TEST_HOOK_THREAD
    HWND windowForTest() const;
    void failNextRemovalForTest();
    void delayNextInstallForTest(HANDLE gate, DWORD timeout);
    bool waitForOwnerExitForTest(DWORD timeout) const;
#endif

private:
    struct State;
    static DWORD WINAPI Run(void* argument);
    std::shared_ptr<State> state_;
    std::atomic<bool> installed_{false};
#ifdef CLIP_TEST_HOOK_THREAD
    HANDLE installGateForTest_ = nullptr;
    DWORD installTimeoutForTest_ = 10000;
#endif
};

} // namespace clip
