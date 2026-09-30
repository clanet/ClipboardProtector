#include "injector.h"
#include <tlhelp32.h>
#include <windows.h>
#include <cstdio>
#include <string>
#include <vector>

namespace {

bool HasMessageWindow(DWORD processId) {
    HWND window = nullptr;
    for (;;) {
        window = FindWindowExW(HWND_MESSAGE, window, L"ClipClientTestWnd", nullptr);
        if (!window) return false;
        DWORD ownerPid = 0;
        GetWindowThreadProcessId(window, &ownerPid);
        if (ownerPid == processId) return true;
    }
}

bool HasModule(DWORD processId, const wchar_t* moduleName) {
    HANDLE snapshot = CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
    if (snapshot == INVALID_HANDLE_VALUE) return false;
    MODULEENTRY32W entry = {sizeof(entry)};
    bool found = false;
    if (Module32FirstW(snapshot, &entry)) {
        do {
            if (_wcsicmp(entry.szModule, moduleName) == 0) {
                found = true;
                break;
            }
        } while (Module32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return found;
}

std::wstring TemporaryTargetPath() {
    std::vector<wchar_t> directory(32768);
    DWORD length = GetTempPathW(static_cast<DWORD>(directory.size()),
                                directory.data());
    if (length == 0 || length >= directory.size()) return {};
    return std::wstring(directory.data(), length) + L"arbitrary-target-" +
           std::to_wstring(GetCurrentProcessId()) + L".exe";
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc != 3) {
        fwprintf(stderr, L"usage: injectorsmoke <HookDll> <clipclient>\n");
        return 2;
    }

    const std::wstring targetPath = TemporaryTargetPath();
    if (targetPath.empty() ||
        !CopyFileW(argv[2], targetPath.c_str(), FALSE)) {
        fwprintf(stderr, L"copy target failed: %lu\n", GetLastError());
        return 3;
    }

    std::wstring command = L"\"" + targetPath + L"\" wait 4000";
    STARTUPINFOW startup = {sizeof(startup)};
    PROCESS_INFORMATION process = {};
    const BOOL created = CreateProcessW(
        targetPath.c_str(), command.data(), nullptr, nullptr, FALSE,
        CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process);
    if (!created) {
        const DWORD error = GetLastError();
        DeleteFileW(targetPath.c_str());
        fwprintf(stderr, L"create target failed: %lu\n", error);
        return 4;
    }
    CloseHandle(process.hThread);

    bool ready = false;
    const ULONGLONG readyDeadline = GetTickCount64() + 2000;
    do {
        ready = HasMessageWindow(process.dwProcessId);
        if (!ready) Sleep(20);
    } while (!ready && GetTickCount64() < readyDeadline);

    clip::Injector injector;
    bool installed = ready && injector.InstallForProcess(
                                  argv[1], process.dwProcessId, targetPath);
    bool loaded = false;
    const ULONGLONG loadDeadline = GetTickCount64() + 2000;
    do {
        loaded = HasModule(process.dwProcessId, L"HookDll.dll");
        if (!loaded) Sleep(20);
    } while (installed && !loaded && GetTickCount64() < loadDeadline);
    const bool removed = injector.Remove();
    bool unloaded = false;
    const ULONGLONG unloadDeadline = GetTickCount64() + 2000;
    do {
        unloaded = !HasModule(process.dwProcessId, L"HookDll.dll");
        if (!unloaded) Sleep(20);
    } while (removed && !unloaded && GetTickCount64() < unloadDeadline);

    const DWORD waitResult = WaitForSingleObject(process.hProcess, 7000);
    DWORD exitCode = STILL_ACTIVE;
    if (waitResult == WAIT_OBJECT_0)
        GetExitCodeProcess(process.hProcess, &exitCode);
    CloseHandle(process.hProcess);
    const bool deleted = DeleteFileW(targetPath.c_str()) != FALSE;

    if (!ready || !installed || !loaded || !removed || !unloaded ||
        waitResult != WAIT_OBJECT_0 || exitCode != 0 || !deleted) {
        fwprintf(stderr,
                 L"ready=%d installed=%d loaded=%d removed=%d unloaded=%d "
                 L"wait=%lu exit=%lu deleted=%d injector-error=%lu %ls\n",
                 ready, installed, loaded, removed, unloaded, waitResult,
                 exitCode, deleted, injector.lastError(),
                 injector.lastErrorText().c_str());
        return 5;
    }
    wprintf(L"arbitrary-target=1 targeted-injection=1 module-unloaded=1 "
            L"clean-exit=1\n");
    return 0;
}
