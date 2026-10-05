#include <windows.h>
#include <cstdio>
#include <string>
#include <thread>
#include <atomic>
#include <filesystem>
#include <fstream>
#include <iterator>
#include "app.h"
#include "pipeserver.h"
#include "winutil.h"

namespace clip { App g_app; }

namespace {
bool HasOutcome(const char* stage) {
    wchar_t directory[32768] = {};
    GetEnvironmentVariableW(L"CLIP_SHUTDOWN_LOG_DIR", directory, _countof(directory));
    const std::wstring prefix = L"shutdown-pipe-server-p" +
        std::to_wstring(GetCurrentProcessId()) + L"-";
    for (const auto& entry : std::filesystem::directory_iterator(directory)) {
        if (entry.path().filename().wstring().find(prefix) != 0) continue;
        std::ifstream file(entry.path(), std::ios::binary);
        const std::string text{std::istreambuf_iterator<char>(file), {}};
        if (text.find(stage) != std::string::npos) return true;
    }
    return false;
}

struct Handle {
    HANDLE value = nullptr;
    ~Handle() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); }
};

bool WaitReady(clip::PipeServer& server) {
    const ULONGLONG deadline = GetTickCount64() + 5000;
    while (GetTickCount64() < deadline) {
        if (server.IsTargetReady(GetCurrentProcessId())) return true;
        Sleep(10);
    }
    return false;
}

bool DisconnectedClient(clip::PipeServer& server, const std::wstring& pipeName) {
    std::atomic<bool> received{false};
    std::thread client([&] {
        Handle pipe{CreateFileW(pipeName.c_str(), GENERIC_READ | GENERIC_WRITE,
            0, nullptr, OPEN_EXISTING, 0, nullptr)};
        if (pipe.value == INVALID_HANDLE_VALUE) {
            fprintf(stderr, "client open error=%lu\n", GetLastError());
            return;
        }
        std::string input;
        const ULONGLONG deadline = GetTickCount64() + 8000;
        while (GetTickCount64() < deadline) {
            DWORD available = 0;
            if (!PeekNamedPipe(pipe.value, nullptr, 0, nullptr, &available, nullptr)) return;
            if (!available) { Sleep(5); continue; }
            char buffer[4096];
            DWORD got = 0;
            if (!ReadFile(pipe.value, buffer, sizeof(buffer), &got, nullptr) || !got) return;
            input.append(buffer, got);
            while (!input.empty()) {
                clip::IpcFrameView frame;
                const auto result = clip::ParseFrame(input.data(), input.size(), frame);
                if (result == clip::IpcFrameResult::incomplete) break;
                if (result != clip::IpcFrameResult::complete) return;
                if (frame.type == clip::kIpcShutdown) { received = true; return; }
                input.erase(0, frame.consumed);
            }
        }
    });
    const ULONGLONG deadline = GetTickCount64() + 3000;
    while (!server.IsTargetConnected(GetCurrentProcessId()) && GetTickCount64() < deadline)
        Sleep(5);
    const bool connected = server.IsTargetConnected(GetCurrentProcessId());
    const ULONGLONG started = GetTickCount64();
    server.Stop();
    const ULONGLONG elapsed = GetTickCount64() - started;
    client.join();
    printf("connected=%d shutdown-received=%d stop-ms=%llu\n", connected, received.load(), elapsed);
    return connected && received && elapsed < 2000 && HasOutcome("stage=server.client.disconnected");
}
}

int wmain(int argc, wchar_t** argv) {
    if (argc != 3) return 1;
    const bool retained = wcscmp(argv[2], L"retained") == 0;
    const bool disconnected = wcscmp(argv[2], L"disconnected") == 0;
    const std::wstring suffix = std::to_wstring(GetCurrentProcessId());
    const auto logDirectory = std::filesystem::current_path() / (L"shutdown-lifecycle-" + suffix);
    std::filesystem::create_directories(logDirectory);
    SetEnvironmentVariableW(L"CLIP_SHUTDOWN_LOG_DIR", logDirectory.c_str());
    SetEnvironmentVariableW(L"CLIP_SHUTDOWN_TRACE", L"1");
    const std::wstring pipeName = L"\\\\.\\pipe\\ClipboardProtector.ShutdownSmoke." + suffix;
    const std::wstring mutexName = L"Local\\ClipboardProtector.ShutdownSmoke." + suffix;
    SetEnvironmentVariableW(L"CLIP_TEST_PIPE_NAME", pipeName.c_str());
    SetEnvironmentVariableW(L"CLIP_TEST_CONTROLLER_MUTEX", mutexName.c_str());
    SetEnvironmentVariableW(L"CLIP_TEST_STOP_EVENT", nullptr);
    SetEnvironmentVariableW(L"CLIP_TEST_SOURCE_MAP", nullptr);
    SetEnvironmentVariableW(L"CLIP_TEST_CRYPTO_MAP", nullptr);
    std::wstring path;
    if (!clip::ModulePath(nullptr, path)) return 2;
    SetEnvironmentVariableW(L"CLIP_TEST_SERVER_PATH", path.c_str());
    Handle mutex{CreateMutexW(nullptr, TRUE, mutexName.c_str())};
    if (!mutex.value) return 3;
    ULONGLONG created = 0;
    if (!clip::ProcessCreationTime(GetCurrentProcess(), created)) return 4;

    // Simulate objects retained from an earlier controller using the same PID.
    // Neither startup nor shutdown may reset the previous generation's event.
    const auto oldName = [&](const wchar_t* base) {
        return clip::ControllerObjectName(L"", base, GetCurrentProcessId(), created - 1);
    };
    Handle oldSource{CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE,
        0, sizeof(clip::SharedClipboardSource), oldName(clip::kClipboardSourceMapName).c_str())};
    Handle oldCrypto{CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE,
        0, sizeof(clip::SharedCryptoProtection), oldName(clip::kCryptoProtectionMapName).c_str())};
    Handle oldStop{CreateEventW(nullptr, TRUE, TRUE, oldName(clip::kStopEventName).c_str())};
    if (!oldSource.value || !oldCrypto.value || !oldStop.value) return 5;

    clip::PipeServer server;
    if (!server.Start(nullptr, true, GetCurrentProcessId())) return 6;
    const std::wstring stopName = clip::CurrentControllerObjectName(L"", clip::kStopEventName);
    Handle stop{OpenEventW(SYNCHRONIZE, FALSE, stopName.c_str())};
    if (!stop.value || WaitForSingleObject(stop.value, 0) != WAIT_TIMEOUT ||
        WaitForSingleObject(oldStop.value, 0) != WAIT_OBJECT_0) return 7;
    if (disconnected) return DisconnectedClient(server, pipeName) ? 0 : 8;

    HMODULE dll = LoadLibraryW(argv[1]);
    if (!dll) return 9;
    auto start = reinterpret_cast<void (*)()>(GetProcAddress(dll, "ClipHookStartForTest"));
    auto abortDetach = reinterpret_cast<void (*)()>(GetProcAddress(dll, "ClipHookAbortNextDetachForTest"));
    auto ready = reinterpret_cast<long (*)()>(GetProcAddress(dll, "ClipHookReadyForTest"));
    auto lifecycle = reinterpret_cast<long (*)()>(GetProcAddress(dll, "ClipHookLifecycleForTest"));
    auto calls = reinterpret_cast<long (*)()>(GetProcAddress(dll, "ClipHookCallsForTest"));
    if (!start || !abortDetach || !ready || !lifecycle || !calls) return 10;
    start();
    if (!WaitReady(server)) {
        fprintf(stderr, "ready timeout lifecycle=%ld ready=%ld connected=%d\n",
                lifecycle(), ready(), server.IsTargetConnected(GetCurrentProcessId()));
        return 11;
    }
    if (retained) abortDetach();
    const ULONGLONG started = GetTickCount64();
    server.Stop();
    const ULONGLONG elapsed = GetTickCount64() - started;
    const ULONGLONG deadline = GetTickCount64() + 3000;
    while ((lifecycle() & 1) && GetTickCount64() < deadline) Sleep(5);
    const bool stopped = (lifecycle() & 1) == 0;
    const bool hooksRemain = (ready() & 2) != 0;
    const bool connected = (ready() & 1) != 0;
    const long before = calls();
    // No OpenClipboard: exercise the retained entry point without reading or
    // modifying clipboard contents. A forced unload would crash this call.
    (void)GetClipboardData(CF_UNICODETEXT);
    const bool retainedCallable = !retained || calls() > before;
    const bool oldEventIntact = WaitForSingleObject(oldStop.value, 0) == WAIT_OBJECT_0;
    printf("retained=%d hooks-remain=%d stopped=%d connected=%d callable=%d "
           "old-generation-intact=%d stop-ms=%llu\n", retained, hooksRemain,
           stopped, connected, retainedCallable, oldEventIntact, elapsed);
    // Retained Hooks and their module references belong to this disposable
    // test process; never FreeLibrary a module with live Detour entry points.
    const bool outcome = HasOutcome(retained ? "stage=server.client.retained" :
                                               "stage=server.client.detached");
    return stopped && hooksRemain == retained && !connected && retainedCallable &&
        oldEventIntact && outcome && elapsed < 2000 ? 0 : 12;
}
