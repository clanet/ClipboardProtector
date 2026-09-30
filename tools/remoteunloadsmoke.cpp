#include <windows.h>
#include <tlhelp32.h>

#include <cstdio>
#include <string>

namespace {

std::wstring Quote(const std::wstring& value) {
    return L"\"" + value + L"\"";
}

std::wstring NormalizePath(std::wstring path) {
    for (wchar_t& value : path) {
        if (value == L'/') value = L'\\';
    }
    return path;
}

bool HasModulePath(DWORD processId, const std::wstring& path) {
    HANDLE snapshot = CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
    if (snapshot == INVALID_HANDLE_VALUE) return false;
    MODULEENTRY32W entry = {sizeof(entry)};
    bool found = false;
    const std::wstring expected = NormalizePath(path);
    if (Module32FirstW(snapshot, &entry)) {
        do {
            if (_wcsicmp(NormalizePath(entry.szExePath).c_str(),
                         expected.c_str()) == 0) {
                found = true;
                break;
            }
        } while (Module32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return found;
}

bool WaitForModuleState(DWORD processId, const std::wstring& path, bool loaded,
                        DWORD timeout) {
    const ULONGLONG deadline = GetTickCount64() + timeout;
    do {
        if (HasModulePath(processId, path) == loaded) return true;
        Sleep(20);
    } while (GetTickCount64() < deadline);
    return false;
}

void StopChild(PROCESS_INFORMATION& process, HANDLE stop) {
    if (stop) SetEvent(stop);
    if (process.hProcess &&
        WaitForSingleObject(process.hProcess, 3000) != WAIT_OBJECT_0) {
        TerminateProcess(process.hProcess, ERROR_PROCESS_ABORTED);
        WaitForSingleObject(process.hProcess, 3000);
    }
    if (process.hThread) CloseHandle(process.hThread);
    if (process.hProcess) CloseHandle(process.hProcess);
    process = {};
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc != 4) return 2;
    const std::wstring suffix = std::to_wstring(GetCurrentProcessId());
    const std::wstring readyName =
        L"Local\\ClipboardProtector.RemoteUnloadReady." + suffix;
    const std::wstring stopName =
        L"Local\\ClipboardProtector.RemoteUnloadStop." + suffix;
    HANDLE ready = CreateEventW(nullptr, TRUE, FALSE, readyName.c_str());
    HANDLE stop = CreateEventW(nullptr, TRUE, FALSE, stopName.c_str());
    if (!ready || !stop) {
        if (ready) CloseHandle(ready);
        if (stop) CloseHandle(stop);
        return 3;
    }

    std::wstring targetCommand = Quote(argv[2]) + L" " + Quote(argv[3]) +
                                 L" " + readyName + L" " + stopName;
    STARTUPINFOW startup = {sizeof(startup)};
    PROCESS_INFORMATION target = {};
    if (!CreateProcessW(argv[2], targetCommand.data(), nullptr, nullptr, FALSE,
                        CREATE_NO_WINDOW, nullptr, nullptr, &startup, &target)) {
        CloseHandle(ready);
        CloseHandle(stop);
        return 4;
    }
    CloseHandle(target.hThread);
    target.hThread = nullptr;
    if (WaitForSingleObject(ready, 5000) != WAIT_OBJECT_0 ||
        !WaitForModuleState(target.dwProcessId, argv[3], true, 3000)) {
        StopChild(target, stop);
        CloseHandle(ready);
        CloseHandle(stop);
        return 5;
    }

    std::wstring unloadCommand =
        Quote(argv[1]) + L" --dll " + Quote(argv[3]) + L" --pid " +
        std::to_wstring(target.dwProcessId) + L" --execute";
    PROCESS_INFORMATION unloader = {};
    if (!CreateProcessW(argv[1], unloadCommand.data(), nullptr, nullptr, FALSE,
                        CREATE_NO_WINDOW, nullptr, nullptr, &startup,
                        &unloader)) {
        StopChild(target, stop);
        CloseHandle(ready);
        CloseHandle(stop);
        return 6;
    }
    CloseHandle(unloader.hThread);
    const DWORD unloadWait = WaitForSingleObject(unloader.hProcess, 10000);
    DWORD unloadExit = STILL_ACTIVE;
    if (unloadWait == WAIT_OBJECT_0)
        GetExitCodeProcess(unloader.hProcess, &unloadExit);
    CloseHandle(unloader.hProcess);

    const bool targetAlive =
        WaitForSingleObject(target.hProcess, 0) == WAIT_TIMEOUT;
    const bool moduleGone = targetAlive &&
        WaitForModuleState(target.dwProcessId, argv[3], false, 3000);
    SetEvent(stop);
    const bool cleanTargetExit =
        WaitForSingleObject(target.hProcess, 5000) == WAIT_OBJECT_0;
    DWORD targetExit = STILL_ACTIVE;
    if (cleanTargetExit) GetExitCodeProcess(target.hProcess, &targetExit);
    if (!cleanTargetExit) {
        TerminateProcess(target.hProcess, ERROR_PROCESS_ABORTED);
        WaitForSingleObject(target.hProcess, 3000);
    }
    CloseHandle(target.hProcess);
    CloseHandle(ready);
    CloseHandle(stop);

    if (unloadWait != WAIT_OBJECT_0 || unloadExit != 0 || !targetAlive ||
        !moduleGone || !cleanTargetExit || targetExit != 0) {
        fwprintf(stderr,
                 L"unload-wait=%lu unload-exit=%lu target-alive=%d "
                 L"module-gone=%d target-clean=%d target-exit=%lu\n",
                 unloadWait, unloadExit, targetAlive ? 1 : 0,
                 moduleGone ? 1 : 0, cleanTargetExit ? 1 : 0, targetExit);
        return 7;
    }
    wprintf(L"remote-thread=1 free-library=1 module-gone=1 target-alive=1\n");
    return 0;
}
