#include "i18n.h"
#include "injector.h"
#include "ipc.h"
#include "winutil.h"
#include "shutdowntrace.h"
#include <tlhelp32.h>
#include <utility>
#include <vector>

namespace clip {

typedef LRESULT(CALLBACK *GetMsgProcFn)(int, WPARAM, LPARAM);

namespace {

bool FullPath(const std::wstring& input, std::wstring& output) {
    std::vector<wchar_t> buffer(32768);
    DWORD length = GetFullPathNameW(input.c_str(), (DWORD)buffer.size(),
                                    buffer.data(), nullptr);
    if (length == 0 || length >= buffer.size()) return false;
    output.assign(buffer.data(), length);
    return true;
}

struct WindowThreadSearch {
    DWORD processId = 0;
    DWORD threadId = 0;
};

BOOL CALLBACK FindWindowThread(HWND window, LPARAM parameter) {
    auto* search = reinterpret_cast<WindowThreadSearch*>(parameter);
    DWORD windowProcessId = 0;
    const DWORD threadId = GetWindowThreadProcessId(window, &windowProcessId);
    if (threadId != 0 && windowProcessId == search->processId) {
        search->threadId = threadId;
        return FALSE;
    }
    return TRUE;
}

DWORD FindProcessMessageThread(DWORD processId) {
    // Prefer a top-level UI thread because it is the most likely place for a
    // desktop application's clipboard calls.
    WindowThreadSearch search{processId, 0};
    EnumWindows(FindWindowThread, reinterpret_cast<LPARAM>(&search));
    if (search.threadId != 0) return search.threadId;

    // Message-only windows are not included in EnumWindows.
    HWND window = nullptr;
    for (;;) {
        window = FindWindowExW(HWND_MESSAGE, window, nullptr, nullptr);
        if (!window) break;
        DWORD windowProcessId = 0;
        const DWORD threadId =
            GetWindowThreadProcessId(window, &windowProcessId);
        if (threadId != 0 && windowProcessId == processId) return threadId;
    }

    // Some programs pump a thread queue without owning a window. WM_NULL is
    // harmless and PostThreadMessage succeeds only when that queue exists.
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;
    THREADENTRY32 entry = {sizeof(entry)};
    DWORD result = 0;
    if (Thread32First(snapshot, &entry)) {
        do {
            if (entry.th32OwnerProcessID != processId) continue;
            HANDLE thread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION |
                                           SYNCHRONIZE,
                                       FALSE, entry.th32ThreadID);
            if (!thread) continue;
            const bool running = WaitForSingleObject(thread, 0) == WAIT_TIMEOUT;
            CloseHandle(thread);
            if (running &&
                PostThreadMessageW(entry.th32ThreadID, WM_NULL, 0, 0)) {
                result = entry.th32ThreadID;
                break;
            }
        } while (Thread32Next(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return result;
}

struct ScopedHandle {
    HANDLE value = INVALID_HANDLE_VALUE;
    ~ScopedHandle() {
        if (value != INVALID_HANDLE_VALUE && value != nullptr) CloseHandle(value);
    }
    explicit operator bool() const {
        return value != INVALID_HANDLE_VALUE && value != nullptr;
    }
};

bool ReadFileAt(HANDLE file, ULONGLONG offset, void* data, DWORD bytes,
                DWORD& error) {
    LARGE_INTEGER position;
    position.QuadPart = (LONGLONG)offset;
    if (!SetFilePointerEx(file, position, nullptr, FILE_BEGIN)) {
        error = GetLastError();
        return false;
    }
    DWORD read = 0;
    if (!ReadFile(file, data, bytes, &read, nullptr)) {
        error = GetLastError();
        return false;
    }
    if (read != bytes) {
        error = ERROR_HANDLE_EOF;
        return false;
    }
    return true;
}

bool ValidateHookDllImage(const std::wstring& path, ScopedHandle& file,
                          DWORD& error) {
    file.value = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
                              nullptr);
    if (!file) {
        error = GetLastError();
        return false;
    }
    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(file.value, &fileSize) || fileSize.QuadPart < 0) {
        error = GetLastError();
        if (error == ERROR_SUCCESS) error = ERROR_INVALID_DATA;
        return false;
    }
    const ULONGLONG size = (ULONGLONG)fileSize.QuadPart;
    if (size < sizeof(IMAGE_DOS_HEADER)) {
        error = ERROR_BAD_EXE_FORMAT;
        return false;
    }

    IMAGE_DOS_HEADER dos = {};
    if (!ReadFileAt(file.value, 0, &dos, sizeof(dos), error)) return false;
    constexpr DWORD kDosSignature = IMAGE_DOS_SIGNATURE;
    if (dos.e_magic != kDosSignature || dos.e_lfanew < 0 ||
        (ULONGLONG)dos.e_lfanew > (16ull << 20)) {
        error = ERROR_BAD_EXE_FORMAT;
        return false;
    }

    const ULONGLONG ntOffset = (ULONGLONG)dos.e_lfanew;
    const ULONGLONG prefixSize = sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) +
                                 sizeof(WORD);
    if (ntOffset > size || prefixSize > size - ntOffset) {
        error = ERROR_BAD_EXE_FORMAT;
        return false;
    }
    DWORD signature = 0;
    IMAGE_FILE_HEADER fileHeader = {};
    WORD optionalMagic = 0;
    if (!ReadFileAt(file.value, ntOffset, &signature, sizeof(signature), error) ||
        !ReadFileAt(file.value, ntOffset + sizeof(signature), &fileHeader,
                    sizeof(fileHeader), error) ||
        !ReadFileAt(file.value, ntOffset + sizeof(signature) +
                        sizeof(fileHeader), &optionalMagic,
                    sizeof(optionalMagic), error))
        return false;

#ifdef _WIN64
    constexpr WORD expectedMachine = IMAGE_FILE_MACHINE_AMD64;
    constexpr WORD expectedOptionalMagic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    constexpr WORD expectedOptionalSize = sizeof(IMAGE_OPTIONAL_HEADER64);
#else
    constexpr WORD expectedMachine = IMAGE_FILE_MACHINE_I386;
    constexpr WORD expectedOptionalMagic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
    constexpr WORD expectedOptionalSize = sizeof(IMAGE_OPTIONAL_HEADER32);
#endif
    if (signature != IMAGE_NT_SIGNATURE ||
        fileHeader.Machine != expectedMachine ||
        (fileHeader.Characteristics & IMAGE_FILE_DLL) == 0 ||
        optionalMagic != expectedOptionalMagic ||
        fileHeader.SizeOfOptionalHeader < expectedOptionalSize ||
        (ULONGLONG)fileHeader.SizeOfOptionalHeader > 4096 ||
        (ULONGLONG)fileHeader.SizeOfOptionalHeader >
            size - (ntOffset + sizeof(signature) + sizeof(fileHeader))) {
        error = ERROR_BAD_EXE_FORMAT;
        return false;
    }
    return true;
}

} // namespace

bool Injector::Install(const std::wstring& hookDllPath) {
    return InstallForThread(hookDllPath, 0);
}

bool Injector::InstallForThread(const std::wstring& hookDllPath, DWORD threadId) {
    return InstallForThreadImpl(hookDllPath, threadId, nullptr, nullptr, {});
}

bool Injector::InstallForThreadImpl(const std::wstring& hookDllPath,
                                    DWORD threadId, HANDLE targetProcess,
                                    HANDLE targetThread,
                                    const std::wstring& expectedTargetPath) {
    if (hook_.installed()) return true;
    lastError_ = ERROR_SUCCESS;
    lastErrorText_.clear();
    if (hookDllPath.empty()) {
        lastError_ = ERROR_INVALID_PARAMETER;
        lastErrorText_ = UiText(TextId::TheHookDLLPathIsEmpty);
        return false;
    }
    ScopedHandle imageFile;
    DWORD imageError = ERROR_SUCCESS;
    if (!ValidateHookDllImage(hookDllPath, imageFile, imageError)) {
        lastError_ = imageError;
        lastErrorText_ = imageError == ERROR_BAD_EXE_FORMAT
                             ? UiText(TextId::TheHookDLLIsNotAValid)
                             : UiText(TextId::CouldNotReadTheHookDLLPE);
        return false;
    }
    if (mod_) {
        FreeLibrary(mod_);
        mod_ = nullptr;
    }
    mod_ = LoadLibraryW(hookDllPath.c_str());
    if (!mod_) {
        lastError_ = GetLastError();
        lastErrorText_ = UiText(TextId::LoadLibraryWFailed);
        return false;
    }
    auto proc = (GetMsgProcFn)GetProcAddress(mod_, "GetMsgProc");
    if (!proc) {
        lastError_ = ERROR_PROC_NOT_FOUND;
        lastErrorText_ = UiText(TextId::TheHookDLLDoesNotExportGetMsgProc);
        FreeLibrary(mod_);
        mod_ = nullptr;
        return false;
    }
    if (targetProcess) {
        std::wstring actualPath;
        if (WaitForSingleObject(targetProcess, 0) != WAIT_TIMEOUT ||
            GetProcessId(targetProcess) == 0 ||
            !ProcessImagePath(targetProcess, actualPath) ||
            _wcsicmp(actualPath.c_str(), expectedTargetPath.c_str()) != 0) {
            lastError_ = ERROR_INVALID_NAME;
            lastErrorText_ = UiText(TextId::TheTargetProcessExitedOrItsPath);
            FreeLibrary(mod_);
            mod_ = nullptr;
            return false;
        }
    }
    if (targetThread &&
        (WaitForSingleObject(targetThread, 0) != WAIT_TIMEOUT ||
         GetProcessIdOfThread(targetThread) != GetProcessId(targetProcess))) {
        lastError_ = ERROR_INVALID_THREAD_ID;
        lastErrorText_ = UiText(TextId::TheTargetThreadExitedOrNoLonger);
        FreeLibrary(mod_);
        mod_ = nullptr;
        return false;
    }
    lastError_ = hook_.Install(proc, mod_, threadId);
    if (lastError_ != ERROR_SUCCESS) {
        lastErrorText_ = UiText(TextId::SetWindowsHookExWFailed);
        // WAIT_TIMEOUT means the hook owner thread did not exit; it may still
        // install the hook, so keep the module reference until Remove retries.
        if (lastError_ != WAIT_TIMEOUT) {
            FreeLibrary(mod_);
            mod_ = nullptr;
        }
        return false;
    }
    // This registered message both wakes an idle queue and explicitly starts
    // a new worker when the DLL remains safely resident after an earlier stop.
    const UINT startMessage = RegisterWindowMessageW(kTargetHookStartMessageName);
    if (threadId != 0 &&
        (startMessage == 0 ||
         !PostThreadMessageW(threadId, startMessage, 0, 0))) {
        const DWORD wakeError = GetLastError();
        // Without a queue wakeup there is no evidence that the targeted hook
        // can ever load. Roll it back, retaining the module if unhook fails.
        if (hook_.Remove() == ERROR_SUCCESS) {
            FreeLibrary(mod_);
            mod_ = nullptr;
        }
        lastError_ = wakeError != ERROR_SUCCESS ? wakeError
                                                 : ERROR_INVALID_THREAD_ID;
        lastErrorText_ = UiText(TextId::TheTargetMessageThreadCouldNotReceive);
        return false;
    }
    return true;
}

bool Injector::InstallForProcess(const std::wstring& hookDllPath,
                                 DWORD processId) {
    return InstallForProcess(hookDllPath, processId, {});
}

bool Injector::InstallForProcess(const std::wstring& hookDllPath,
                                 DWORD processId,
                                 const std::wstring& expectedTargetPath) {
    if (processId == 0 || processId == GetCurrentProcessId()) {
        lastError_ = ERROR_INVALID_PARAMETER;
        lastErrorText_ = UiText(TextId::TheTargetPIDIsInvalidOrRefers);
        return false;
    }
    HANDLE target = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
                                FALSE, processId);
    if (!target) {
        lastError_ = GetLastError();
        lastErrorText_ = UiText(TextId::CouldNotOpenTheTargetProcess);
        return false;
    }
    std::wstring actualPath;
    if (GetProcessId(target) != processId ||
        !ProcessImagePath(target, actualPath)) {
        lastError_ = ERROR_INVALID_NAME;
        lastErrorText_ = UiText(TextId::CouldNotVerifyTheTargetProcessPath);
        CloseHandle(target);
        return false;
    }
    std::wstring targetPath = actualPath;
    if (!expectedTargetPath.empty()) {
        if (!FullPath(expectedTargetPath, targetPath) ||
            _wcsicmp(actualPath.c_str(), targetPath.c_str()) != 0) {
            lastError_ = ERROR_INVALID_NAME;
            lastErrorText_ = UiText(TextId::TheTargetProcessPathChangedBeforeInjection);
            CloseHandle(target);
            return false;
        }
    }
    DWORD currentSession = 0;
    DWORD targetSession = 0;
    if (!ProcessIdToSessionId(GetCurrentProcessId(), &currentSession) ||
        !ProcessIdToSessionId(processId, &targetSession) ||
        currentSession != targetSession) {
        lastError_ = ERROR_ACCESS_DENIED;
        lastErrorText_ = UiText(TextId::TheTargetProcessIsNotInThe);
        CloseHandle(target);
        return false;
    }
    DWORD architectureError = ERROR_SUCCESS;
    if (!SameProcessArchitecture(target, &architectureError)) {
        lastError_ = architectureError;
        lastErrorText_ = architectureError == ERROR_BAD_EXE_FORMAT
                             ? UiText(TextId::TheTargetArchitectureDiffersFromThisApplication)
                             : UiText(TextId::CouldNotDetermineTheTargetProcessArchitecture);
        CloseHandle(target);
        return false;
    }
    const DWORD threadId = FindProcessMessageThread(processId);
    if (threadId == 0) {
        lastError_ = ERROR_NOT_FOUND;
        lastErrorText_ = UiText(TextId::TheTargetProcessHasNoAvailableDesktop);
        CloseHandle(target);
        return false;
    }
    HANDLE targetThread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION |
                                         SYNCHRONIZE,
                                     FALSE, threadId);
    if (!targetThread) {
        lastError_ = GetLastError();
        lastErrorText_ = UiText(TextId::CouldNotOpenTheTargetMessageThread);
        CloseHandle(target);
        return false;
    }
    const bool installed = InstallForThreadImpl(hookDllPath, threadId, target,
                                                targetThread, targetPath);
    // Keep both handles alive through SetWindowsHookExW in the implementation;
    // close them only after it returns.
    CloseHandle(targetThread);
    CloseHandle(target);
    return installed;
}

#ifdef _WIN64
bool Injector::Install32BitHelper(const std::wstring& helperPath,
                                  const std::wstring& hookDllPath) {
    if (helperProcess_) {
        DWORD exitCode = 0;
        if (GetExitCodeProcess(helperProcess_, &exitCode) &&
            exitCode == STILL_ACTIVE)
            return true;
        CloseHandle(helperProcess_);
        helperProcess_ = nullptr;
    }
    if (helperStopEvent_) {
        CloseHandle(helperStopEvent_);
        helperStopEvent_ = nullptr;
    }

    SECURITY_ATTRIBUTES sa = {sizeof(sa), nullptr, TRUE};
    HANDLE stopEvent = CreateEventW(&sa, TRUE, FALSE, nullptr);
    HANDLE readyEvent = CreateEventW(&sa, TRUE, FALSE, nullptr);
    if (!stopEvent || !readyEvent) {
        if (stopEvent) CloseHandle(stopEvent);
        if (readyEvent) CloseHandle(readyEvent);
        return false;
    }

    std::wstring command = L"\"" + helperPath + L"\" " +
                           std::to_wstring(GetCurrentProcessId()) + L" " +
                           std::to_wstring((unsigned long long)(ULONG_PTR)stopEvent) + L" " +
                           std::to_wstring((unsigned long long)(ULONG_PTR)readyEvent) + L" \"" +
                           hookDllPath + L"\"";
    STARTUPINFOW startup = {sizeof(startup)};
    PROCESS_INFORMATION process = {};
    BOOL created = CreateProcessW(helperPath.c_str(), &command[0], nullptr, nullptr,
                                  TRUE, CREATE_NO_WINDOW, nullptr, nullptr,
                                  &startup, &process);
    if (!created) {
        CloseHandle(stopEvent);
        CloseHandle(readyEvent);
        return false;
    }
    CloseHandle(process.hThread);
    HANDLE waits[2] = {readyEvent, process.hProcess};
    DWORD ready = WaitForMultipleObjects(2, waits, FALSE, 5000);
    CloseHandle(readyEvent);
    if (ready != WAIT_OBJECT_0) {
        SetEvent(stopEvent);
        if (WaitForSingleObject(process.hProcess, 1000) != WAIT_OBJECT_0) {
            TerminateProcess(process.hProcess, ERROR_PROCESS_ABORTED);
            WaitForSingleObject(process.hProcess, 5000);
        }
        CloseHandle(process.hProcess);
        CloseHandle(stopEvent);
        return false;
    }
    helperProcess_ = process.hProcess;
    helperStopEvent_ = stopEvent;
    return true;
}
#endif

bool Injector::Remove() {
    ShutdownTrace trace;
    trace.Open(L"injector");
    trace.Mark("injector.remove.begin");
    bool removed = true;
#ifdef _WIN64
    trace.Mark("helper.stop.signal");
    if (helperStopEvent_) SetEvent(helperStopEvent_);
#endif
    // Start both removals before waiting for the helper process to exit.
    trace.Mark("native_hook.remove.begin");
    const DWORD hookResult = hook_.Remove();
    trace.Mark("native_hook.remove.end", 0, hookResult);
#ifdef _WIN64
    if (helperProcess_) {
        trace.Mark("helper.wait.begin");
        DWORD result = WaitForSingleObject(helperProcess_, 5000);
        trace.Mark("helper.wait.end", result, result == WAIT_FAILED ? GetLastError() : ERROR_SUCCESS);
        if (result != WAIT_OBJECT_0) {
            trace.Mark("helper.terminate.begin");
            if (!TerminateProcess(helperProcess_, ERROR_PROCESS_ABORTED) ||
                WaitForSingleObject(helperProcess_, 5000) != WAIT_OBJECT_0)
                removed = false;
            trace.Mark("helper.terminate.end", removed);
        }
        CloseHandle(helperProcess_);
        helperProcess_ = nullptr;
    }
    if (helperStopEvent_) {
        CloseHandle(helperStopEvent_);
        helperStopEvent_ = nullptr;
    }
#endif
    if (hookResult != ERROR_SUCCESS) return false;
    if (mod_) {
        trace.Mark("controller.module_release.begin");
        FreeLibrary(mod_);
        trace.Mark("controller.module_release.end");
        mod_ = nullptr;
    }
    trace.Mark("injector.remove.end", removed);
    return removed;
}

} // namespace clip
