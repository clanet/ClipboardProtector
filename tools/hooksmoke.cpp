#include <windows.h>
#include <stdio.h>
#include <atomic>
#include <string>
#include <thread>
#include <vector>

using StartFn = void (*)();
using DebugFn = void (*)(long[8]);
using ShutdownFn = void (*)();
using CallsFn = long (*)();
using LifecycleFn = long (*)();
using LifecycleEventsFn = void (*)(HANDLE, HANDLE);
using HoldCallFn = BOOL (*)(HANDLE, HANDLE);

struct LifecycleProbe {
    HANDLE detached = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    HANDLE stopped = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    HANDLE entered = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    HANDLE release = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    std::thread caller;
    BOOL completed = FALSE;

    bool Hold(HoldCallFn hold) {
        try {
            caller = std::thread([this, hold] { completed = hold(entered, release); });
        } catch (...) { return false; }
        return WaitForSingleObject(entered, 3000) == WAIT_OBJECT_0;
    }
    void Release() {
        if (release) SetEvent(release);
        if (caller.joinable()) caller.join();
    }
    ~LifecycleProbe() {
        Release();
        if (release) CloseHandle(release);
        if (entered) CloseHandle(entered);
        if (stopped) CloseHandle(stopped);
        if (detached) CloseHandle(detached);
    }
};

struct ApiStress {
    std::atomic<bool> running{true};
    std::atomic<unsigned long long> calls{0};
    std::atomic<unsigned long> threadFailures{0};
};

void CallClipboardApis(ApiStress& stress, unsigned count) {
    for (unsigned i = 0; i < count && stress.running.load(std::memory_order_acquire);
         ++i) {
        // These calls intentionally omit OpenClipboard. They fail without
        // changing the user's clipboard while still exercising each Detour.
        (void)GetClipboardData(CF_UNICODETEXT);
        (void)SetClipboardData(CF_UNICODETEXT, nullptr);
        (void)EmptyClipboard();
        stress.calls.fetch_add(3, std::memory_order_relaxed);
    }
}

bool StartApiStress(ApiStress& stress, std::vector<std::thread>& callers,
                    std::vector<std::thread>& churners) {
    try {
        // Keep callers active throughout attach and detach so a transaction
        // must synchronize threads that are already executing all three APIs.
        for (int i = 0; i < 8; ++i) {
            callers.emplace_back([&stress] {
                while (stress.running.load(std::memory_order_acquire))
                    CallClipboardApis(stress, 256);
            });
        }
        // Continuously create and join short-lived threads during each worker
        // transaction; this covers the snapshot's dynamic-thread boundary.
        for (int i = 0; i < 2; ++i) {
            churners.emplace_back([&stress] {
                for (int round = 0;
                     round < 2000 && stress.running.load(std::memory_order_acquire);
                     ++round) {
                    try {
                        std::thread ephemeral([&stress] { CallClipboardApis(stress, 64); });
                        ephemeral.join();
                    } catch (...) {
                        stress.threadFailures.fetch_add(1, std::memory_order_relaxed);
                        stress.running.store(false, std::memory_order_release);
                        return;
                    }
                }
            });
        }
    } catch (...) {
        stress.threadFailures.fetch_add(1, std::memory_order_relaxed);
        stress.running.store(false, std::memory_order_release);
        for (auto& thread : churners) thread.join();
        for (auto& thread : callers) thread.join();
        return false;
    }
    return true;
}

void StopApiStress(ApiStress& stress, std::vector<std::thread>& callers,
                   std::vector<std::thread>& churners) {
    stress.running.store(false, std::memory_order_release);
    for (auto& thread : churners) thread.join();
    for (auto& thread : callers) thread.join();
}

int wmain(int argc, wchar_t** argv) {
    if (argc == 3 && wcscmp(argv[1], L"--freeze-abort") == 0) {
        HMODULE dll = LoadLibraryW(argv[2]);
        if (!dll) return 30;
        auto abortFreeze = reinterpret_cast<BOOL (*)(DWORD)>(GetProcAddress(dll, "ClipHookAbortFreezeForTest"));
        if (!abortFreeze) return 31;
        ApiStress stress;
        std::vector<std::thread> callers, churners;
        if (!StartApiStress(stress, callers, churners)) return 32;
        bool aborted = true, resumed = true;
        for (DWORD phase : {1u, 2u}) {
            aborted = abortFreeze(phase) && aborted;
            const auto before = stress.calls.load();
            Sleep(30);
            resumed = stress.calls.load() > before && resumed;
        }
        StopApiStress(stress, callers, churners);
        FreeLibrary(dll);
        printf("partial-freeze-and-enlist-aborted=%d callers-resumed=%d\n", aborted, resumed);
        return aborted && resumed ? 0 : 33;
    }
    if (argc == 4 && wcscmp(argv[1], L"--owner-check") == 0) {
        HMODULE dll = LoadLibraryW(argv[2]);
        if (!dll) return 20;
        auto owner = reinterpret_cast<CallsFn>(GetProcAddress(dll, "ClipHookOwnerForTest"));
        auto lifecycle = reinterpret_cast<LifecycleFn>(GetProcAddress(dll, "ClipHookLifecycleForTest"));
        auto start = reinterpret_cast<StartFn>(GetProcAddress(dll, "ClipHookStartForTest"));
        auto callback = reinterpret_cast<HOOKPROC>(GetProcAddress(dll, "GetMsgProc"));
        if (!owner || !lifecycle || !start || !callback) {
            FreeLibrary(dll);
            return 21;
        }
        const bool expected = wcscmp(argv[3], L"1") == 0;
        const bool actual = owner() != 0;
        // Only exercise the callback in a verified owner. Other aliases must
        // remain eligible targets, without connecting to a live controller.
        if (actual && expected) {
            MSG message = {};
            message.message = WM_NULL;
            callback(HC_ACTION, PM_REMOVE, reinterpret_cast<LPARAM>(&message));
            start();
        }
        const long state = lifecycle();
        wprintf(L"owner expected=%d actual=%d lifecycle=%ld\n", expected, actual, state);
        FreeLibrary(dll);
        return actual == expected && state == 0 ? 0 : 22;
    }
    if (argc != 2) return 2;
    HMODULE dll = LoadLibraryW(argv[1]);
    if (!dll) return 3;
    fwprintf(stderr, L"loaded\n");
    fflush(stderr);
    auto start = reinterpret_cast<StartFn>(GetProcAddress(dll, "ClipHookStartForTest"));
    auto debug = reinterpret_cast<DebugFn>(GetProcAddress(dll, "ClipHookDebug"));
    auto shutdown = reinterpret_cast<ShutdownFn>(
        GetProcAddress(dll, "ClipHookShutdownForTest"));
    auto calls = reinterpret_cast<CallsFn>(GetProcAddress(dll, "ClipHookCallsForTest"));
    auto lifecycle = reinterpret_cast<LifecycleFn>(
        GetProcAddress(dll, "ClipHookLifecycleForTest"));
    auto freezes = reinterpret_cast<CallsFn>(
        GetProcAddress(dll, "ClipHookFreezeCallsForTest"));
    auto freezeMicros = reinterpret_cast<ULONGLONG (*)()>(
        GetProcAddress(dll, "ClipHookFreezeMicrosForTest"));
    auto lifecycleEvents = reinterpret_cast<LifecycleEventsFn>(
        GetProcAddress(dll, "ClipHookLifecycleEventsForTest"));
    auto holdCall = reinterpret_cast<HoldCallFn>(
        GetProcAddress(dll, "ClipHookHoldCallForTest"));
    LifecycleProbe probe;
    FARPROC getMsgProc = GetProcAddress(dll, "GetMsgProc");
    if (!start || !debug || !shutdown || !calls || !lifecycle || !getMsgProc ||
        !freezes || !freezeMicros || !lifecycleEvents || !holdCall ||
        !probe.detached || !probe.stopped || !probe.entered || !probe.release) {
        FreeLibrary(dll);
        return 4;
    }
    lifecycleEvents(probe.detached, probe.stopped);

    std::wstring suffix = std::to_wstring(GetCurrentProcessId());
    std::wstring stopName = L"Local\\ClipboardProtector.HookSmokeStop." + suffix;
    std::wstring mutexName = L"Local\\ClipboardProtector.HookSmokeController." + suffix;
    SetEnvironmentVariableW(L"CLIP_TEST_STOP_EVENT", stopName.c_str());
    SetEnvironmentVariableW(L"CLIP_TEST_CONTROLLER_MUTEX", mutexName.c_str());
    HANDLE stopEvent = CreateEventW(nullptr, TRUE, FALSE, stopName.c_str());
    HANDLE controllerMutex = CreateMutexW(nullptr, TRUE, mutexName.c_str());
    if (!stopEvent || !controllerMutex) {
        if (stopEvent) CloseHandle(stopEvent);
        if (controllerMutex) CloseHandle(controllerMutex);
        FreeLibrary(dll);
        return 7;
    }

    ApiStress stress;
    std::vector<std::thread> callers;
    std::vector<std::thread> churners;
    bool stressActive = false;
    auto stopStress = [&] {
        if (!stressActive) return;
        StopApiStress(stress, callers, churners);
        stressActive = false;
    };

    SetLastError(0x12345678u);
    HANDLE baselineGet = GetClipboardData(CF_UNICODETEXT);
    DWORD baselineGetError = GetLastError();
    SetLastError(0x12345678u);
    BOOL baselineEmpty = EmptyClipboard();
    DWORD baselineEmptyError = GetLastError();

    if (!StartApiStress(stress, callers, churners)) {
        CloseHandle(controllerMutex);
        CloseHandle(stopEvent);
        FreeLibrary(dll);
        return 8;
    }
    stressActive = true;
    start();   // 启动与全局 Hook 回调相同的初始化路径。
    fwprintf(stderr, L"worker-started\n");
    fflush(stderr);
    ULONGLONG deadline = GetTickCount64() + 5000;
    long state[8] = {};
    do {
        debug(state);
        if (state[1] != 0) break;
        Sleep(10);
    } while (GetTickCount64() < deadline);
    if (state[1] == 0) {
        fwprintf(stderr, L"install-timeout tx=%ld attach=%ld/%ld/%ld commit=%ld freeze-us=%llu\n",
                 state[2], state[3], state[4], state[5], state[6], freezeMicros());
        fflush(stderr);
        stopStress();
        shutdown();
        ReleaseMutex(controllerMutex);
        CloseHandle(controllerMutex);
        CloseHandle(stopEvent);
        FreeLibrary(dll);
        return 5;
    }


    long callsBefore = calls();
    SetLastError(0x12345678u);
    HANDLE hookedGet = GetClipboardData(CF_UNICODETEXT);
    DWORD hookedGetError = GetLastError();
    SetLastError(0x12345678u);
    BOOL hookedEmpty = EmptyClipboard();
    DWORD hookedEmptyError = GetLastError();
    if (calls() - callsBefore < 2 || hookedGet != baselineGet ||
        hookedGetError != baselineGetError || hookedEmpty != baselineEmpty ||
        hookedEmptyError != baselineEmptyError) {
        stopStress();
        shutdown();
        ReleaseMutex(controllerMutex);
        CloseHandle(controllerMutex);
        CloseHandle(stopEvent);
        FreeLibrary(dll);
        return 10;
    }

    // Hold a call across detach and pipe closure. Shutdown must acknowledge
    // detachment without dropping the reference or suspending threads again.
    if (!probe.Hold(holdCall)) {
        probe.Release();
        stopStress();
        shutdown();
        ReleaseMutex(controllerMutex);
        CloseHandle(controllerMutex);
        CloseHandle(stopEvent);
        FreeLibrary(dll);
        return 12;
    }

    // 未打开剪贴板时调用只会失败，不改变用户数据，但会经过真实 Detour。
    // 并发调用覆盖 detach 时仍有线程位于 Hook 中的宿主安全场景。
    std::atomic<bool> keepCalling{true};
    std::vector<std::thread> detachCallers;
    for (int i = 0; i < 4; ++i) {
        detachCallers.emplace_back([&keepCalling] {
            while (keepCalling.load(std::memory_order_acquire)) {
                (void)GetClipboardData(CF_UNICODETEXT);
                (void)EmptyClipboard();
            }
        });
    }
    Sleep(50);

    const long freezesBeforeStop = freezes();
    const ULONGLONG installMicros = freezeMicros();
    SetEvent(stopEvent);
    fwprintf(stderr, L"installed; shutdown-requested\n");
    fflush(stderr);
    const DWORD detachedWait = WaitForSingleObject(probe.detached, 5000);
    debug(state);
    keepCalling.store(false, std::memory_order_release);
    for (auto& caller : detachCallers) caller.join();
    bool detached = state[1] == 0 && detachedWait == WAIT_OBJECT_0;
    fwprintf(stderr, L"detach-observed=%d\n", detached ? 1 : 0);
    fflush(stderr);
    if (!detached) {
        probe.Release();
        stopStress();
        shutdown();
        ReleaseMutex(controllerMutex);
        CloseHandle(controllerMutex);
        CloseHandle(stopEvent);
        FreeLibrary(dll);
        return 6;
    }

    long lifecycleState = lifecycle();
    const ULONGLONG detachMicros = freezeMicros();
    const bool busyRetained = (lifecycleState & 0xC01) == 0xC01;
    probe.Release();
    const DWORD stoppedWait = WaitForSingleObject(probe.stopped, 5000);
    lifecycleState = lifecycle();
    const bool singleFreeze = freezes() == freezesBeforeStop + 1;
    if (!busyRetained || !singleFreeze || !probe.completed ||
        stoppedWait != WAIT_OBJECT_0 || (lifecycleState & 0x401) != 0x400) {
        fwprintf(stderr, L"busy-detach lifecycle=%ld freeze-delta=%ld held-call=%d\n",
                 lifecycleState, freezes() - freezesBeforeStop, probe.completed);
        fflush(stderr);
        stopStress();
        ReleaseMutex(controllerMutex);
        CloseHandle(controllerMutex);
        CloseHandle(stopEvent);
        FreeLibrary(dll);
        return 11;
    }

    // Reuse the retained worker reference on restart, then require its release
    // during an idle stop. Waiting on an event keeps the test thread out of DLL
    // diagnostic exports during the one-shot instruction-pointer inspection.
    ResetEvent(stopEvent);
    ResetEvent(probe.detached);
    ResetEvent(probe.stopped);
    start();
    deadline = GetTickCount64() + 5000;
    do {
        debug(state);
        if (state[1] != 0) break;
        Sleep(10);
    } while (GetTickCount64() < deadline);
    if (state[1] == 0) {
        fwprintf(stderr,
                 L"restart-timeout worker=%ld hooks=%ld tx=%ld "
                 L"attach=%ld/%ld/%ld commit=%ld lifecycle=%ld freeze-us=%llu\n",
                 state[0], state[1], state[2], state[3], state[4], state[5],
                 state[6], lifecycle(), freezeMicros());
        fflush(stderr);
        stopStress();
        shutdown();
        ReleaseMutex(controllerMutex);
        CloseHandle(controllerMutex);
        CloseHandle(stopEvent);
        FreeLibrary(dll);
        return 8;
    }

    // 模拟控制进程退出/崩溃：互斥体失去所有者后 worker 应 fail-open 并卸钩。
    stopStress();
    const long freezesBeforeIdleStop = freezes();
    ReleaseMutex(controllerMutex);
    const DWORD idleWait = WaitForSingleObject(probe.stopped, 5000);
    debug(state);
    bool controllerDetach = state[1] == 0 && idleWait == WAIT_OBJECT_0;
    lifecycleState = lifecycle();
    const bool controllerUnload = (lifecycleState & 0x401) == 0;
    const bool idleSingleFreeze = freezes() == freezesBeforeIdleStop + 1;
    const ULONGLONG idleMicros = freezeMicros();
    CloseHandle(controllerMutex);
    CloseHandle(stopEvent);
    FreeLibrary(dll);
    wprintf(L"freeze-us install=%llu busy-detach=%llu idle-detach=%llu\n",
            installMicros, detachMicros, idleMicros);
    wprintf(L"installed=1 detached=1 busy-reference-retained=1 restarted=1 "
            L"controller-detached=%d controller-release=%d single-freeze=%d pipe=%ld\n",
            controllerDetach ? 1 : 0, controllerUnload ? 1 : 0,
            idleSingleFreeze ? 1 : 0, state[7]);
    return controllerDetach && controllerUnload && idleSingleFreeze ? 0 : 9;
}
