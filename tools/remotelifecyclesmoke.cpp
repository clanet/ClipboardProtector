#include "remotehook.h"
#include "winutil.h"
#include <windows.h>
#include <cstdio>
#include <cwchar>
#include <string>
#include <thread>

namespace {

enum Event { ready, entered, ownerReady, releaseGate, released, verify, verified, quit, eventCount };
struct Shared {
    HANDLE events[eventCount] = {};
    ULONG_PTR releaseFunction = 0;
    volatile LONG calls = 0;
    DWORD verification = 0;
    bool startMode = false;
};
Shared* g_shared = nullptr;

DWORD WINAPI DelayedRelease(void* module) {
    SetEvent(g_shared->events[entered]);
    WaitForSingleObject(g_shared->events[releaseGate], INFINITE);
    InterlockedIncrement(&g_shared->calls);
    const BOOL result = FreeLibrary(static_cast<HMODULE>(module));
    SetEvent(g_shared->events[released]);
    return result;
}

int Target(HANDLE mapping, const wchar_t* dllPath) {
    g_shared = static_cast<Shared*>(MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0,
                                                 sizeof(Shared)));
    if (!g_shared) return 20;
    HMODULE owner = nullptr;
    if (!g_shared->startMode) {
        owner = LoadLibraryW(dllPath);
        HMODULE extra = LoadLibraryW(dllPath);
        if (!owner || !extra) return 21;
    }
    g_shared->releaseFunction = reinterpret_cast<ULONG_PTR>(DelayedRelease);
    SetEvent(g_shared->events[ready]);
    if (g_shared->startMode) {
        HANDLE startWaits[2] = {g_shared->events[entered], g_shared->events[quit]};
        if (WaitForMultipleObjects(2, startWaits, FALSE, INFINITE) != WAIT_OBJECT_0)
            return 22;
        owner = LoadLibraryW(dllPath);
        if (!owner) return 23;
        SetEvent(g_shared->events[ownerReady]);
    }
    HANDLE waits[2] = {g_shared->events[verify], g_shared->events[quit]};
    if (WaitForMultipleObjects(2, waits, FALSE, INFINITE) == WAIT_OBJECT_0) {
        // The balancing release must leave the independently owned reference
        // alive. Removing that owner must then unload the fixture completely.
        if (GetModuleHandleW(dllPath) && FreeLibrary(owner) &&
            !GetModuleHandleW(dllPath) && g_shared->calls == 1)
            g_shared->verification = 1;
        SetEvent(g_shared->events[verified]);
        WaitForSingleObject(g_shared->events[quit], INFINITE);
    }
    UnmapViewOfFile(g_shared);
    return 0;
}

struct Fixture {
    HANDLE mapping = nullptr;
    HANDLE process = nullptr;
    Shared* shared = nullptr;
    DWORD processId = 0;
    ULONGLONG creationTime = 0;

    ~Fixture() {
        if (shared) {
            if (shared->events[releaseGate]) SetEvent(shared->events[releaseGate]);
            if (shared->events[quit]) SetEvent(shared->events[quit]);
        }
        if (process) {
            if (WaitForSingleObject(process, 3000) != WAIT_OBJECT_0) {
                TerminateProcess(process, 99);
                WaitForSingleObject(process, 3000);
            }
            CloseHandle(process);
        }
        if (shared) {
            for (HANDLE event : shared->events) if (event) CloseHandle(event);
            UnmapViewOfFile(shared);
        }
        if (mapping) CloseHandle(mapping);
    }

    bool Start(const wchar_t* dllPath, bool startMode = false) {
        SECURITY_ATTRIBUTES security = {sizeof(security), nullptr, TRUE};
        mapping = CreateFileMappingW(INVALID_HANDLE_VALUE, &security,
                                      PAGE_READWRITE, 0, sizeof(Shared), nullptr);
        if (!mapping) return false;
        shared = static_cast<Shared*>(MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS,
                                                   0, 0, sizeof(Shared)));
        if (!shared) return false;
        *shared = Shared{};
        shared->startMode = startMode;
        for (HANDLE& event : shared->events) {
            event = CreateEventW(&security, TRUE, FALSE, nullptr);
            if (!event) return false;
        }
        wchar_t executable[32768] = {};
        const DWORD length = GetModuleFileNameW(nullptr, executable, _countof(executable));
        if (!length || length >= _countof(executable)) return false;
        std::wstring command = L"\"" + std::wstring(executable) + L"\" --target " +
            std::to_wstring(reinterpret_cast<ULONG_PTR>(mapping)) + L" \"" + dllPath + L"\"";
        STARTUPINFOW startup = {sizeof(startup)};
        PROCESS_INFORMATION child = {};
        if (!CreateProcessW(executable, command.data(), nullptr, nullptr, TRUE,
                            CREATE_NO_WINDOW, nullptr, nullptr, &startup, &child))
            return false;
        process = child.hProcess;
        processId = child.dwProcessId;
        CloseHandle(child.hThread);
        return WaitForSingleObject(shared->events[ready], 5000) == WAIT_OBJECT_0 &&
               clip::ProcessCreationTime(process, creationTime);
    }
};

bool Run(const wchar_t* dllPath, bool cancel) {
    Fixture fixture;
    if (!fixture.Start(dllPath)) return false;
    auto* function = reinterpret_cast<LPTHREAD_START_ROUTINE>(
        fixture.shared->releaseFunction);
    clip::RemoteHookReleaseForTest(function, cancel ? 5000 : 20);
    HANDLE stop = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!stop) return false;
    // Cancellation before submission leaves the original responsibility intact.
    SetEvent(stop);
    DWORD cancelledError = ERROR_SUCCESS;
    const auto cancelled = clip::RemoteHookRelease(
        fixture.processId, fixture.creationTime, dllPath, cancelledError, stop);
    ResetEvent(stop);
    if (cancelled != clip::RemoteHookReleaseState::retryable ||
        cancelledError != WAIT_TIMEOUT || fixture.shared->calls != 0) {
        CloseHandle(stop);
        return false;
    }
    clip::RemoteHookReleaseState result = clip::RemoteHookReleaseState::retryable;
    DWORD error = ERROR_SUCCESS;
    if (cancel) {
        std::thread caller([&] {
            result = clip::RemoteHookRelease(fixture.processId, fixture.creationTime,
                                             dllPath, error, stop);
        });
        const DWORD wait = WaitForSingleObject(fixture.shared->events[entered], 3000);
        SetEvent(stop);
        caller.join();
        if (wait != WAIT_OBJECT_0) {
            CloseHandle(stop);
            return false;
        }
    } else {
        result = clip::RemoteHookRelease(fixture.processId, fixture.creationTime,
                                         dllPath, error, stop);
    }
    CloseHandle(stop);
    if (result != clip::RemoteHookReleaseState::submitted || error != WAIT_TIMEOUT)
        return false;
    // This is the controller's retry contract: only a call that never submitted
    // a thread may retry. A pending release already consumes this reference.
    bool retained = result == clip::RemoteHookReleaseState::retryable;
    for (int attempt = 0; attempt < 3 && retained; ++attempt) {
        retained = clip::RemoteHookRelease(fixture.processId, fixture.creationTime,
                                           dllPath, error) ==
                   clip::RemoteHookReleaseState::retryable;
    }
    SetEvent(fixture.shared->events[releaseGate]);
    if (WaitForSingleObject(fixture.shared->events[released], 3000) != WAIT_OBJECT_0)
        return false;
    SetEvent(fixture.shared->events[verify]);
    return WaitForSingleObject(fixture.shared->events[verified], 3000) == WAIT_OBJECT_0 &&
           fixture.shared->verification == 1;
}

bool RunStart(const wchar_t* dllPath) {
    Fixture fixture;
    if (!fixture.Start(dllPath, true)) return false;
    clip::RemoteHookReleaseForTest(reinterpret_cast<LPTHREAD_START_ROUTINE>(
        fixture.shared->releaseFunction), 20);
    const clip::RemoteHookStartResult result = clip::RemoteHookStart(
        fixture.processId, fixture.creationTime, dllPath);
    if (!result.started || result.retainedReference || !result.releaseSubmitted ||
        result.error != WAIT_TIMEOUT)
        return false;
    if (WaitForSingleObject(fixture.shared->events[ownerReady], 3000) != WAIT_OBJECT_0)
        return false;
    SetEvent(fixture.shared->events[releaseGate]);
    if (WaitForSingleObject(fixture.shared->events[released], 3000) != WAIT_OBJECT_0)
        return false;
    SetEvent(fixture.shared->events[verify]);
    return WaitForSingleObject(fixture.shared->events[verified], 3000) == WAIT_OBJECT_0 &&
           fixture.shared->verification == 1;
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc == 4 && wcscmp(argv[1], L"--target") == 0) {
        return Target(reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(
            _wcstoui64(argv[2], nullptr, 10))), argv[3]);
    }
    if (argc != 2) return 2;
    if (!Run(argv[1], false) || !Run(argv[1], true) || !RunStart(argv[1])) {
        std::fprintf(stderr, "remote-lifecycle-smoke-failed error=%lu\n", GetLastError());
        return 1;
    }
    std::puts("delayed-release-once=1 cancelled-release-once=1 startup-release-once=1 independent-reference-preserved=1");
    return 0;
}
