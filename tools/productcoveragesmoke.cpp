#include <windows.h>
#include <tlhelp32.h>

#include <cstdio>
#include <string>
#include <vector>

namespace {

constexpr UINT kCommandExit = 3007;
constexpr UINT kCommandGlobalInjection = 3008;
constexpr UINT kQueryClientCount = WM_APP + 8;

struct ChildProcess {
    HANDLE process = nullptr;
    DWORD id = 0;
};

struct WindowSearch {
    DWORD processId = 0;
    HWND result = nullptr;
};

// Hold only our test child still, so shutdown must wait for a real client
// ACK. The controller must keep pumping messages throughout that wait.
struct SuspendedTarget {
    std::vector<HANDLE> threads;
    ~SuspendedTarget() {
        for (HANDLE thread : threads) {
            ResumeThread(thread);
            CloseHandle(thread);
        }
    }
    bool Suspend(DWORD processId) {
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snapshot == INVALID_HANDLE_VALUE) return false;
        THREADENTRY32 entry = {sizeof(entry)};
        if (Thread32First(snapshot, &entry)) {
            do {
                if (entry.th32OwnerProcessID != processId) continue;
                HANDLE thread = OpenThread(THREAD_SUSPEND_RESUME, FALSE,
                                           entry.th32ThreadID);
                if (!thread) continue;
                if (SuspendThread(thread) == static_cast<DWORD>(-1)) {
                    CloseHandle(thread);
                    continue;
                }
                threads.push_back(thread);
            } while (Thread32Next(snapshot, &entry));
        }
        CloseHandle(snapshot);
        return !threads.empty();
    }
};

bool WindowResponds(HWND window) {
    DWORD_PTR response = 0;
    return SendMessageTimeoutW(window, kQueryClientCount, 0, 0,
                               SMTO_ABORTIFHUNG | SMTO_BLOCK, 250, &response) &&
           (response & 0x10000u) != 0;
}

BOOL CALLBACK FindMainWindow(HWND window, LPARAM parameter) {
    auto* search = reinterpret_cast<WindowSearch*>(parameter);
    DWORD processId = 0;
    GetWindowThreadProcessId(window, &processId);
    if (processId != search->processId) return TRUE;
    wchar_t className[128] = {};
    GetClassNameW(window, className, _countof(className));
    if (wcscmp(className, L"ClipProtectorMainWnd") == 0) {
        search->result = window;
        return FALSE;
    }
    return TRUE;
}

HWND MainWindow(DWORD processId) {
    WindowSearch search{processId, nullptr};
    EnumWindows(FindMainWindow, reinterpret_cast<LPARAM>(&search));
    return search.result;
}

bool ClientCountIs(HWND window, size_t expected) {
    DWORD_PTR result = 0;
    return SendMessageTimeoutW(window, kQueryClientCount, 0, 0,
                               SMTO_ABORTIFHUNG | SMTO_BLOCK, 1000, &result) &&
           (result & 0x10000u) != 0 && (result & 0xffffu) == expected;
}

bool QueryHookModule(DWORD processId, bool& present) {
    present = false;
    HANDLE snapshot = INVALID_HANDLE_VALUE;
    for (int attempt = 0; attempt < 8; ++attempt) {
        snapshot = CreateToolhelp32Snapshot(
            TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
        if (snapshot != INVALID_HANDLE_VALUE) break;
        if (GetLastError() != ERROR_BAD_LENGTH) return false;
        Sleep(10);
    }
    if (snapshot == INVALID_HANDLE_VALUE) return false;
    MODULEENTRY32W entry = {sizeof(entry)};
    const bool enumerated = Module32FirstW(snapshot, &entry) != FALSE;
    if (enumerated) {
        do {
            if (_wcsicmp(entry.szModule, L"HookDll.dll") == 0 ||
                _wcsicmp(entry.szModule, L"HookDll32.dll") == 0) {
                present = true;
                break;
            }
        } while (Module32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return enumerated;
}

template <typename Predicate>
bool WaitUntil(Predicate predicate, DWORD timeout) {
    const ULONGLONG deadline = GetTickCount64() + timeout;
    do {
        if (predicate()) return true;
        Sleep(20);
    } while (GetTickCount64() < deadline);
    return predicate();
}

bool Launch(const std::wstring& application, std::wstring commandLine,
            ChildProcess& child) {
    STARTUPINFOW startup = {sizeof(startup)};
    PROCESS_INFORMATION process = {};
    if (!CreateProcessW(application.c_str(), commandLine.data(), nullptr,
                        nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr,
                        &startup, &process))
        return false;
    CloseHandle(process.hThread);
    child.process = process.hProcess;
    child.id = process.dwProcessId;
    return true;
}

std::wstring TemporaryDirectory() {
    std::vector<wchar_t> buffer(32768);
    const DWORD length = GetTempPathW(static_cast<DWORD>(buffer.size()),
                                      buffer.data());
    if (length == 0 || length >= buffer.size()) return {};
    return std::wstring(buffer.data(), length) +
           L"ClipboardProtector-coverage-smoke-" +
           std::to_wstring(GetCurrentProcessId());
}

bool WriteConfig(const std::wstring& path) {
    static constexpr char contents[] =
        "{\"ruleModelVersion\":4,\"settings\":{"
        "\"balloonNotificationsDisabled\":true,"
        "\"shortcutOnlyMode\":false,\"maxLogEntries\":5000,"
        "\"previewEnabled\":false,\"autostart\":false,"
        "\"startGlobalProtection\":false,\"startMinimized\":true},"
        "\"rules\":[]}";
    HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ,
                              nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
                              nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    DWORD written = 0;
    const bool ok = WriteFile(file, contents,
                              static_cast<DWORD>(sizeof(contents) - 1),
                              &written, nullptr) &&
                    written == sizeof(contents) - 1;
    CloseHandle(file);
    return ok;
}

void CloseChild(ChildProcess& child) {
    if (child.process) CloseHandle(child.process);
    child = {};
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc != 3) {
        fwprintf(stderr,
                 L"usage: productcoveragesmoke <ClipboardProtector> "
                 L"<clipclient>\n");
        return 2;
    }

    std::vector<wchar_t> fullServer(32768);
    const DWORD serverLength = GetFullPathNameW(
        argv[1], static_cast<DWORD>(fullServer.size()), fullServer.data(),
        nullptr);
    if (serverLength == 0 || serverLength >= fullServer.size()) return 2;
    std::wstring serverPath(fullServer.data(), serverLength);
    for (wchar_t& character : serverPath) {
        if (character == L'/') character = L'\\';
    }

    const std::wstring tempRoot = TemporaryDirectory();
    const std::wstring configDir = tempRoot + L"\\ClipboardProtector";
    const std::wstring targetPath = tempRoot + L"\\coverage-target.exe";
    const std::wstring readyPath = tempRoot + L"\\coverage.ready";
    const std::wstring transientReadyPath =
        tempRoot + L"\\coverage-transient.ready";
    const bool directoriesReady =
        !tempRoot.empty() &&
        (CreateDirectoryW(tempRoot.c_str(), nullptr) ||
         GetLastError() == ERROR_ALREADY_EXISTS) &&
        (CreateDirectoryW(configDir.c_str(), nullptr) ||
         GetLastError() == ERROR_ALREADY_EXISTS);
    const bool filesReady = directoriesReady &&
        CopyFileW(argv[2], targetPath.c_str(), FALSE) &&
        WriteConfig(configDir + L"\\config.json");
    if (!filesReady) {
        fwprintf(stderr, L"coverage smoke setup failed: %lu\n",
                 GetLastError());
        return 3;
    }

    const std::wstring suffix = std::to_wstring(GetCurrentProcessId());
    const std::wstring pipeName =
        L"\\\\.\\pipe\\ClipboardProtector.CoverageSmoke." + suffix;
    const std::wstring stopName =
        L"Local\\ClipboardProtector.CoverageSmoke.Stop." + suffix;
    const std::wstring mutexName =
        L"Local\\ClipboardProtector.CoverageSmoke.Mutex." + suffix;
    const std::wstring sourceName =
        L"Local\\ClipboardProtector.CoverageSmoke.Source." + suffix;
    const std::wstring cryptoName =
        L"Local\\ClipboardProtector.CoverageSmoke.Crypto." + suffix;
    SetEnvironmentVariableW(L"CLIP_TEST_PIPE_NAME", pipeName.c_str());
    SetEnvironmentVariableW(L"CLIP_TEST_STOP_EVENT", stopName.c_str());
    SetEnvironmentVariableW(L"CLIP_TEST_CONTROLLER_MUTEX", mutexName.c_str());
    SetEnvironmentVariableW(L"CLIP_TEST_SOURCE_MAP", sourceName.c_str());
    SetEnvironmentVariableW(L"CLIP_TEST_CRYPTO_MAP", cryptoName.c_str());
    SetEnvironmentVariableW(L"CLIP_TEST_CONFIG_DIR", configDir.c_str());
    SetEnvironmentVariableW(L"CLIP_TEST_SERVER_PATH", serverPath.c_str());
    SetEnvironmentVariableW(L"CLIP_TEST_COVERAGE_TARGET_PATH",
                            targetPath.c_str());
    SetEnvironmentVariableW(L"CLIPBOARDPROTECTOR_TEST_TARGET_PID", nullptr);
    SetEnvironmentVariableW(L"CLIPBOARDPROTECTOR_ENABLE_GLOBAL_HOOK", L"1");

    ChildProcess app;
    ChildProcess target;
    ChildProcess transientTarget;
    HWND mainWindow = nullptr;
    bool appStarted = false;
    bool transientStarted = false;
    bool transientConnected = false;
    bool transientExited = false;
    bool transientRemoved = false;
    bool targetStarted = false;
    bool hooksInstalled = false;
    bool forcedReady = false;
    bool cleanExit = false;
    bool unloaded = false;
    bool switchResponsive = false;
    bool exitResponsive = false;

    std::wstring appCommand = L"\"" + serverPath + L"\"";
    appStarted = Launch(serverPath, appCommand, app) &&
                 WaitUntil([&] {
                     mainWindow = MainWindow(app.id);
                     return mainWindow != nullptr;
                 }, 5000);
    if (appStarted) {
        std::wstring transientCommand =
            L"\"" + targetPath + L"\" nopump 10000 \"" +
            transientReadyPath + L"\"";
        transientStarted =
            Launch(targetPath, transientCommand, transientTarget);
    }
    if (transientStarted) {
        transientConnected = WaitUntil(
            [&] {
                bool modulePresent = false;
                return GetFileAttributesW(transientReadyPath.c_str()) !=
                           INVALID_FILE_ATTRIBUTES &&
                       QueryHookModule(transientTarget.id, modulePresent) &&
                       modulePresent && ClientCountIs(mainWindow, 1);
            },
            12000);
        transientExited =
            WaitForSingleObject(transientTarget.process, 15000) == WAIT_OBJECT_0;
        transientRemoved = transientExited &&
                           WaitUntil([&] { return ClientCountIs(mainWindow, 0); },
                                     5000);
    }
    if (appStarted) {
        std::wstring targetCommand = L"\"" + targetPath +
                                     L"\" nopump 20000 \"" + readyPath + L"\"";
        targetStarted = Launch(targetPath, targetCommand, target);
    }
    if (targetStarted) {
        forcedReady = WaitUntil(
            [&] {
                bool modulePresent = false;
                return GetFileAttributesW(readyPath.c_str()) !=
                           INVALID_FILE_ATTRIBUTES &&
                       QueryHookModule(target.id, modulePresent) &&
                       modulePresent;
            }, 12000);
        QueryHookModule(target.id, hooksInstalled);
    }

    {
        SuspendedTarget suspended;
        const bool clientReady = forcedReady && WaitUntil(
            [&] { return ClientCountIs(mainWindow, 1); }, 3000);
        const bool held = clientReady && suspended.Suspend(target.id);
        if (held) {
            PostMessageW(mainWindow, WM_COMMAND, kCommandGlobalInjection, 0);
            Sleep(100);
            switchResponsive = WindowResponds(mainWindow);
        }
        if (mainWindow)
            PostMessageW(mainWindow, WM_COMMAND, kCommandExit, 0);
        if (held) {
            exitResponsive = true;
            for (int probe = 0; probe < 3; ++probe) {
                Sleep(100);
                exitResponsive = WindowResponds(mainWindow) && exitResponsive;
            }
        }
    }
    if (app.process)
        cleanExit = WaitForSingleObject(app.process, 10000) == WAIT_OBJECT_0;
    if (forcedReady) {
        unloaded = WaitUntil(
            [&] {
                bool modulePresent = true;
                return QueryHookModule(target.id, modulePresent) &&
                       !modulePresent;
            }, 5000);
    }

    if (target.process &&
        WaitForSingleObject(target.process, 0) != WAIT_OBJECT_0)
        TerminateProcess(target.process, 30);
    if (transientTarget.process &&
        WaitForSingleObject(transientTarget.process, 0) != WAIT_OBJECT_0)
        TerminateProcess(transientTarget.process, 32);
    if (app.process && WaitForSingleObject(app.process, 0) != WAIT_OBJECT_0)
        TerminateProcess(app.process, 31);
    if (target.process) WaitForSingleObject(target.process, 3000);
    if (transientTarget.process)
        WaitForSingleObject(transientTarget.process, 3000);
    if (app.process) WaitForSingleObject(app.process, 3000);
    CloseChild(target);
    CloseChild(transientTarget);
    CloseChild(app);

    SetEnvironmentVariableW(L"CLIPBOARDPROTECTOR_ENABLE_GLOBAL_HOOK", nullptr);
    SetEnvironmentVariableW(L"CLIP_TEST_COVERAGE_TARGET_PATH", nullptr);
    SetEnvironmentVariableW(L"CLIP_TEST_SERVER_PATH", nullptr);
    SetEnvironmentVariableW(L"CLIP_TEST_CONFIG_DIR", nullptr);
    SetEnvironmentVariableW(L"CLIP_TEST_SOURCE_MAP", nullptr);
    SetEnvironmentVariableW(L"CLIP_TEST_CRYPTO_MAP", nullptr);
    SetEnvironmentVariableW(L"CLIP_TEST_CONTROLLER_MUTEX", nullptr);
    SetEnvironmentVariableW(L"CLIP_TEST_STOP_EVENT", nullptr);
    SetEnvironmentVariableW(L"CLIP_TEST_PIPE_NAME", nullptr);

    DeleteFileW((configDir + L"\\config.json").c_str());
    DeleteFileW(readyPath.c_str());
    DeleteFileW(transientReadyPath.c_str());
    DeleteFileW(targetPath.c_str());
    RemoveDirectoryW(configDir.c_str());
    RemoveDirectoryW(tempRoot.c_str());

    wprintf(L"app=%d transient-started=%d transient-connected=%d "
            L"transient-exited=%d transient-removed=%d target=%d hooks=%d "
            L"forced-ready=%d clean-exit=%d unloaded=%d switch-responsive=%d exit-responsive=%d\n",
            appStarted, transientStarted, transientConnected, transientExited,
            transientRemoved, targetStarted, hooksInstalled, forcedReady,
            cleanExit, unloaded, switchResponsive, exitResponsive);
    return appStarted && transientStarted && transientConnected &&
                   transientExited && transientRemoved && targetStarted &&
                   forcedReady && cleanExit && unloaded &&
                   switchResponsive && exitResponsive
               ? 0
               : 4;
}
