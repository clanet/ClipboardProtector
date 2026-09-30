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
    FARPROC getMsgProc = GetProcAddress(dll, "GetMsgProc");
    if (!start || !debug || !shutdown || !calls || !lifecycle || !getMsgProc) {
        FreeLibrary(dll);
        return 4;
    }

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
        fwprintf(stderr, L"install-timeout tx=%ld attach=%ld/%ld/%ld commit=%ld\n",
                 state[2], state[3], state[4], state[5], state[6]);
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

    SetEvent(stopEvent);
    fwprintf(stderr, L"installed; shutdown-requested\n");
    fflush(stderr);
    deadline = GetTickCount64() + 5000;
    do {
        debug(state);
        if (state[1] == 0) break;
        Sleep(10);
    } while (GetTickCount64() < deadline);
    keepCalling.store(false, std::memory_order_release);
    for (auto& caller : detachCallers) caller.join();
    bool detached = state[1] == 0;
    fwprintf(stderr, L"detach-observed=%d\n", detached ? 1 : 0);
    fflush(stderr);
    if (!detached) {
        stopStress();
        shutdown();
        ReleaseMutex(controllerMutex);
        CloseHandle(controllerMutex);
        CloseHandle(stopEvent);
        FreeLibrary(dll);
        return 6;
    }

    // Detour removal is published before the worker releases its own module
    // reference. Wait for that second phase before simulating reinjection.
    deadline = GetTickCount64() + 5000;
    long lifecycleState = 0;
    do {
        lifecycleState = lifecycle();
        if ((lifecycleState & 0x401) == 0) break;
        Sleep(10);
    } while (GetTickCount64() < deadline);
    if ((lifecycleState & 0x401) != 0) {
        fwprintf(stderr, L"worker-unload-timeout lifecycle=%ld\n",
                 lifecycleState);
        fflush(stderr);
        stopStress();
        ReleaseMutex(controllerMutex);
        CloseHandle(controllerMutex);
        CloseHandle(stopEvent);
        FreeLibrary(dll);
        return 11;
    }

    // A remaining caller-owned LoadLibrary reference keeps the test export
    // available while a new worker acquires and later releases its own one.
    ResetEvent(stopEvent);
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
                 L"attach=%ld/%ld/%ld commit=%ld lifecycle=%ld\n",
                 state[0], state[1], state[2], state[3], state[4], state[5],
                 state[6], lifecycle());
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
    ReleaseMutex(controllerMutex);
    deadline = GetTickCount64() + 5000;
    do {
        debug(state);
        if (state[1] == 0) break;
        Sleep(10);
    } while (GetTickCount64() < deadline);
    bool controllerDetach = state[1] == 0;
    stopStress();
    deadline = GetTickCount64() + 5000;
    do {
        lifecycleState = lifecycle();
        if ((lifecycleState & 0x401) == 0) break;
        Sleep(10);
    } while (GetTickCount64() < deadline);
    const bool controllerUnload = (lifecycleState & 0x401) == 0;
    CloseHandle(controllerMutex);
    CloseHandle(stopEvent);
    FreeLibrary(dll);
    wprintf(L"installed=1 detached=1 worker-release=1 restarted=1 "
            L"controller-detached=%d controller-release=%d pipe=%ld\n",
            controllerDetach ? 1 : 0, controllerUnload ? 1 : 0, state[7]);
    return controllerDetach && controllerUnload ? 0 : 9;
}
