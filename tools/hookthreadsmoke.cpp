#include "hookthread.h"
#include <atomic>
#include <cstdio>
#include <thread>

namespace {

constexpr UINT kProbe = WM_APP + 1;
std::atomic<unsigned> hookCalls{0};

LRESULT CALLBACK Hook(int code, WPARAM wp, LPARAM lp) {
    if (code >= 0 && wp == PM_REMOVE &&
        reinterpret_cast<MSG*>(lp)->message == kProbe)
        hookCalls.fetch_add(1);
    return CallNextHookEx(nullptr, code, wp, lp);
}

LRESULT CALLBACK WindowProc(HWND window, UINT message, WPARAM wp, LPARAM lp) {
    if (message == kProbe) {
        SetEvent(reinterpret_cast<HANDLE>(lp));
        return 0;
    }
    return DefWindowProcW(window, message, wp, lp);
}

struct Target {
    HANDLE ready = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    HANDLE received = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    HANDLE thread = nullptr;
    DWORD threadId = 0;
    HWND window = nullptr;

    ~Target() {
        if (thread) {
            PostThreadMessageW(threadId, WM_QUIT, 0, 0);
            WaitForSingleObject(thread, INFINITE);
            CloseHandle(thread);
        }
        if (ready) CloseHandle(ready);
        if (received) CloseHandle(received);
    }

    bool Start() {
        if (!ready || !received) return false;
        thread = CreateThread(nullptr, 0, Run, this, 0, &threadId);
        return thread && WaitForSingleObject(ready, 3000) == WAIT_OBJECT_0 && window;
    }

    bool Probe() {
        return PostMessageW(window, kProbe, 0, reinterpret_cast<LPARAM>(received)) &&
               WaitForSingleObject(received, 1000) == WAIT_OBJECT_0;
    }

    static DWORD WINAPI Run(void* context) {
        auto& target = *static_cast<Target*>(context);
        WNDCLASSW wc = {};
        wc.hInstance = GetModuleHandleW(nullptr);
        wc.lpfnWndProc = WindowProc;
        wc.lpszClassName = L"ClipboardProtectorHookThreadTest";
        RegisterClassW(&wc);
        target.window = CreateWindowExW(0, wc.lpszClassName, L"", 0, 0, 0, 0, 0,
                                        HWND_MESSAGE, nullptr, wc.hInstance, nullptr);
        SetEvent(target.ready);
        MSG message;
        while (GetMessageW(&message, nullptr, 0, 0) > 0) {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
        if (target.window) DestroyWindow(target.window);
        UnregisterClassW(wc.lpszClassName, wc.hInstance);
        return 0;
    }
};

bool Responds(HWND window) {
    DWORD_PTR result = 0;
    return window && SendMessageTimeoutW(window, WM_NULL, 0, 0,
                                         SMTO_ABORTIFHUNG | SMTO_BLOCK,
                                         500, &result) != 0;
}

bool ProbeWhileCallerWaits(clip::HookThread& hook, Target& target) {
    HANDLE finished = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!finished) return false;
    const HWND owner = hook.windowForTest();
    const unsigned before = hookCalls.load();
    bool responsive = false;
    std::thread probe([&] {
        responsive = true;
        for (int i = 0; i < 8; ++i) {
            if (!Responds(owner) || !target.Probe()) {
                responsive = false;
                break;
            }
        }
        SetEvent(finished);
    });
    // Deliberately do not pump on the lifecycle caller, as during a blocking
    // shutdown ACK/helper wait. Both hook-owner and target must still respond.
    const DWORD wait = WaitForSingleObject(finished, 5000);
    probe.join();
    CloseHandle(finished);
    return wait == WAIT_OBJECT_0 && responsive && hookCalls.load() == before + 8;
}

int Run() {
    Target target;
    if (!target.Start()) return 1;
    clip::HookThread hook;
    if (hook.Install(nullptr, nullptr, target.threadId) == ERROR_SUCCESS ||
        hook.installed() || hook.Remove() != ERROR_SUCCESS)
        return 2;
    for (int round = 0; round < 3; ++round) {
        if (hook.Install(Hook, nullptr, target.threadId) != ERROR_SUCCESS ||
            !hook.installed()) return 3;
        const DWORD owner = GetWindowThreadProcessId(hook.windowForTest(), nullptr);
        if (!owner || owner == GetCurrentThreadId() || owner == target.threadId)
            return 4;
        if (!ProbeWhileCallerWaits(hook, target)) return 5;
        hook.failNextRemovalForTest();
        if (hook.Remove() != ERROR_ACCESS_DENIED || !hook.installed() ||
            !ProbeWhileCallerWaits(hook, target)) return 6;
        if (hook.Remove() != ERROR_SUCCESS || hook.installed() ||
            hook.Remove() != ERROR_SUCCESS) return 7;
        const unsigned before = hookCalls.load();
        if (!target.Probe() || hookCalls.load() != before) return 8;
    }
    {
        clip::HookThread scopedHook;
        if (scopedHook.Install(Hook, nullptr, target.threadId) != ERROR_SUCCESS)
            return 9;
    }
    const unsigned before = hookCalls.load();
    if (!target.Probe() || hookCalls.load() != before) return 10;
    return 0;
}

} // namespace

int main() {
    const int result = Run();
    if (result) {
        std::fprintf(stderr, "hook-thread-smoke-failed=%d error=%lu\n", result,
                     GetLastError());
        return result;
    }
    std::puts("blocked-caller-responsive=1 removal-retry=1 restart=1 scoped-cleanup=1");
    return 0;
}
