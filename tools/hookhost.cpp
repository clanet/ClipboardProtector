#include <windows.h>
#include <shellapi.h>
#include "remotehook.h"
#include "winutil.h"
#include <cwchar>
#include <string>
#include <vector>

using GetMsgProcFn = LRESULT(CALLBACK*)(int, WPARAM, LPARAM);

namespace {

bool ParseProcessId(const wchar_t* text, DWORD& processId) {
    if (!text || !*text) return false;
    wchar_t* end = nullptr;
    const unsigned long value = wcstoul(text, &end, 10);
    if (end == text || *end != L'\0' || value == 0) return false;
    processId = static_cast<DWORD>(value);
    return true;
}

bool ParseCreationTime(const wchar_t* text, ULONGLONG& creationTime) {
    if (!text || !*text) return false;
    wchar_t* end = nullptr;
    const unsigned long long value = _wcstoui64(text, &end, 10);
    if (end == text || *end != L'\0' || value == 0) return false;
    creationTime = value;
    return true;
}

bool IsBundledHookDll(const wchar_t* path) {
    if (!path || !*path) return false;
    std::wstring directory;
    if (!clip::ModuleDirectory(nullptr, directory)) return false;
    std::vector<wchar_t> expected(32768);
    std::vector<wchar_t> actual(32768);
    const std::wstring bundled = directory + L"HookDll32.dll";
    const DWORD expectedLength = GetFullPathNameW(
        bundled.c_str(), static_cast<DWORD>(expected.size()), expected.data(),
        nullptr);
    const DWORD actualLength = GetFullPathNameW(
        path, static_cast<DWORD>(actual.size()), actual.data(), nullptr);
    return expectedLength > 0 && expectedLength < expected.size() &&
           actualLength > 0 && actualLength < actual.size() &&
           _wcsicmp(expected.data(), actual.data()) == 0;
}

DWORD RunRemoteCommand(int argc, wchar_t** argv) {
    if (argc != 5) return 2;
    const bool start = _wcsicmp(argv[1], L"--remote-start") == 0;
    const bool release = _wcsicmp(argv[1], L"--remote-release") == 0;
    DWORD processId = 0;
    ULONGLONG creationTime = 0;
    if ((!start && !release) || !ParseProcessId(argv[2], processId) ||
        !ParseCreationTime(argv[3], creationTime) ||
        !IsBundledHookDll(argv[4]))
        return 2;
    if (start) {
        const clip::RemoteHookStartResult result =
            clip::RemoteHookStart(processId, creationTime, argv[4]);
        if (result.started)
            return result.retainedReference
                       ? clip::kRemoteHelperStartedRetained
                       : clip::kRemoteHelperStarted;
        return result.retainedReference ? clip::kRemoteHelperFailedRetained
                                        : clip::kRemoteHelperFailed;
    }
    DWORD error = ERROR_SUCCESS;
    return clip::RemoteHookRelease(processId, creationTime, argv[4], error)
               ? clip::kRemoteHelperStarted
               : clip::kRemoteHelperFailed;
}

} // namespace

int APIENTRY wWinMain(HINSTANCE, HINSTANCE, LPWSTR, int) {
    int argc = 0;
    wchar_t** argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv) return 2;
    if (argc >= 2 &&
        (_wcsicmp(argv[1], L"--remote-start") == 0 ||
         _wcsicmp(argv[1], L"--remote-release") == 0)) {
        const DWORD result = RunRemoteCommand(argc, argv);
        LocalFree(argv);
        return static_cast<int>(result);
    }
    if (argc != 5) {
        if (argv) LocalFree(argv);
        return 2;
    }
    DWORD controllerPid = wcstoul(argv[1], nullptr, 10);
    HANDLE stopEvent = reinterpret_cast<HANDLE>(
        static_cast<ULONG_PTR>(_wcstoui64(argv[2], nullptr, 10)));
    HANDLE readyEvent = reinterpret_cast<HANDLE>(
        static_cast<ULONG_PTR>(_wcstoui64(argv[3], nullptr, 10)));
    std::wstring dllPath = argv[4];
    LocalFree(argv);

    HANDLE controller = OpenProcess(SYNCHRONIZE, FALSE, controllerPid);
    if (!controller) return 3;
    HMODULE dll = LoadLibraryW(dllPath.c_str());
    if (!dll) {
        CloseHandle(controller);
        return 4;
    }
    auto proc = reinterpret_cast<GetMsgProcFn>(GetProcAddress(dll, "GetMsgProc"));
    HHOOK hook = proc ? SetWindowsHookExW(WH_GETMESSAGE, proc, dll, 0) : nullptr;
    if (!hook) {
        FreeLibrary(dll);
        CloseHandle(controller);
        return 5;
    }

    SetEvent(readyEvent);
    CloseHandle(readyEvent);
    HANDLE waits[2] = {controller, stopEvent};
    bool running = true;
    while (running) {
        DWORD result = MsgWaitForMultipleObjects(2, waits, FALSE, INFINITE,
                                                 QS_ALLINPUT);
        if (result == WAIT_OBJECT_0 || result == WAIT_OBJECT_0 + 1 ||
            result == WAIT_FAILED) {
            running = false;
        } else if (result == WAIT_OBJECT_0 + 2) {
            MSG message;
            while (PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE)) {
                if (message.message == WM_QUIT) {
                    running = false;
                    break;
                }
                TranslateMessage(&message);
                DispatchMessageW(&message);
            }
        }
    }

    if (UnhookWindowsHookEx(hook)) FreeLibrary(dll);
    CloseHandle(stopEvent);
    CloseHandle(controller);
    return 0;
}
