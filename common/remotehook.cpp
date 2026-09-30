#include "remotehook.h"
#include "winutil.h"

#include <tlhelp32.h>
#include <algorithm>
#include <vector>

namespace clip {
namespace {

struct ScopedHandle {
    HANDLE value = nullptr;
    ~ScopedHandle() {
        if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value);
    }
    explicit operator bool() const {
        return value && value != INVALID_HANDLE_VALUE;
    }
};

struct ModuleRecord {
    std::wstring name;
    std::wstring path;
    ULONG_PTR base = 0;
    DWORD size = 0;
};

struct RemoteFunction {
    std::wstring ownerName;
    ULONG_PTR offset = 0;
};

enum class RemoteCallState { completed, timedOut, failed };

void NormalizePath(std::wstring& path) {
    std::replace(path.begin(), path.end(), L'/', L'\\');
    if (path.rfind(L"\\\\?\\UNC\\", 0) == 0)
        path = L"\\\\" + path.substr(8);
    else if (path.rfind(L"\\\\?\\", 0) == 0)
        path.erase(0, 4);
}

bool FullPath(const std::wstring& input, std::wstring& output) {
    std::vector<wchar_t> buffer(32768);
    const DWORD length = GetFullPathNameW(input.c_str(),
                                          static_cast<DWORD>(buffer.size()),
                                          buffer.data(), nullptr);
    if (length == 0 || length >= buffer.size()) return false;
    output.assign(buffer.data(), length);
    NormalizePath(output);
    ScopedHandle file;
    file.value = CreateFileW(output.c_str(), FILE_READ_ATTRIBUTES,
                             FILE_SHARE_READ | FILE_SHARE_WRITE |
                                 FILE_SHARE_DELETE,
                             nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
                             nullptr);
    if (file) {
        const DWORD finalLength = GetFinalPathNameByHandleW(
            file.value, buffer.data(), static_cast<DWORD>(buffer.size()),
            FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
        if (finalLength > 0 && finalLength < buffer.size()) {
            output.assign(buffer.data(), finalLength);
            NormalizePath(output);
        }
    }
    return true;
}

std::wstring BaseName(const std::wstring& path) {
    const size_t slash = path.find_last_of(L"\\/");
    return slash == std::wstring::npos ? path : path.substr(slash + 1);
}

bool SamePath(const std::wstring& left, const std::wstring& right) {
    std::wstring fullLeft;
    std::wstring fullRight;
    if (!FullPath(left, fullLeft)) fullLeft = left;
    if (!FullPath(right, fullRight)) fullRight = right;
    NormalizePath(fullLeft);
    NormalizePath(fullRight);
    return _wcsicmp(fullLeft.c_str(), fullRight.c_str()) == 0;
}

bool SnapshotModules(DWORD processId, std::vector<ModuleRecord>& modules,
                     DWORD& error) {
    modules.clear();
    ScopedHandle snapshot;
    for (int attempt = 0; attempt < 8; ++attempt) {
        snapshot.value = CreateToolhelp32Snapshot(
            TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
        if (snapshot) break;
        error = GetLastError();
        if (error != ERROR_BAD_LENGTH) return false;
        Sleep(10);
    }
    if (!snapshot) return false;

    MODULEENTRY32W entry = {sizeof(entry)};
    if (!Module32FirstW(snapshot.value, &entry)) {
        error = GetLastError();
        return false;
    }
    try {
        do {
            modules.push_back({entry.szModule, entry.szExePath,
                               reinterpret_cast<ULONG_PTR>(entry.modBaseAddr),
                               entry.modBaseSize});
        } while (Module32NextW(snapshot.value, &entry));
    } catch (...) {
        error = ERROR_OUTOFMEMORY;
        return false;
    }
    error = ERROR_SUCCESS;
    return true;
}

const ModuleRecord* FindModuleByPath(
    const std::vector<ModuleRecord>& modules, const std::wstring& path) {
    const std::wstring expectedName = BaseName(path);
    for (const auto& module : modules) {
        if (_wcsicmp(module.name.c_str(), expectedName.c_str()) == 0 &&
            SamePath(module.path, path))
            return &module;
    }
    return nullptr;
}

const ModuleRecord* FindModuleByName(
    const std::vector<ModuleRecord>& modules, const std::wstring& name) {
    for (const auto& module : modules) {
        if (_wcsicmp(module.name.c_str(), name.c_str()) == 0) return &module;
    }
    return nullptr;
}

bool LocalImageSize(HMODULE module, DWORD& size) {
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(module);
    if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0)
        return false;
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(
        reinterpret_cast<const BYTE*>(module) + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE ||
        nt->OptionalHeader.SizeOfImage == 0)
        return false;
    size = nt->OptionalHeader.SizeOfImage;
    return true;
}

bool ResolveSystemFunction(const char* name, RemoteFunction& result) {
    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    FARPROC function = kernel32 ? GetProcAddress(kernel32, name) : nullptr;
    if (!function) return false;

    HMODULE owner = nullptr;
    if (!GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(function), &owner))
        return false;
    DWORD ownerSize = 0;
    if (!LocalImageSize(owner, ownerSize)) return false;
    const ULONG_PTR address = reinterpret_cast<ULONG_PTR>(function);
    const ULONG_PTR base = reinterpret_cast<ULONG_PTR>(owner);
    if (address < base || address - base >= ownerSize) return false;

    std::wstring ownerPath;
    if (!ModulePath(owner, ownerPath)) return false;
    result.ownerName = BaseName(ownerPath);
    result.offset = address - base;
    return true;
}

bool IsCriticalProcess(HANDLE process) {
    using Function = BOOL(WINAPI*)(HANDLE, PBOOL);
    static const auto function = reinterpret_cast<Function>(GetProcAddress(
        GetModuleHandleW(L"kernel32.dll"), "IsProcessCritical"));
    BOOL critical = FALSE;
    return function && function(process, &critical) && critical;
}

bool OpenValidatedProcess(DWORD processId, ULONGLONG expectedCreationTime,
                          DWORD access, ScopedHandle& process, DWORD& error) {
    process.value = OpenProcess(access | PROCESS_QUERY_LIMITED_INFORMATION |
                                    SYNCHRONIZE,
                                FALSE, processId);
    if (!process) {
        error = GetLastError();
        return false;
    }
    ULONGLONG actualCreationTime = 0;
    if (WaitForSingleObject(process.value, 0) != WAIT_TIMEOUT ||
        GetProcessId(process.value) != processId ||
        !ProcessCreationTime(process.value, actualCreationTime) ||
        actualCreationTime != expectedCreationTime) {
        error = ERROR_PROCESS_ABORTED;
        return false;
    }
    DWORD currentSession = 0;
    DWORD targetSession = 0;
    if (!ProcessIdToSessionId(GetCurrentProcessId(), &currentSession) ||
        !ProcessIdToSessionId(processId, &targetSession) ||
        currentSession != targetSession || IsCriticalProcess(process.value)) {
        error = ERROR_ACCESS_DENIED;
        return false;
    }
    DWORD architectureError = ERROR_SUCCESS;
    if (!SameProcessArchitecture(process.value, &architectureError)) {
        error = architectureError;
        return false;
    }
    error = ERROR_SUCCESS;
    return true;
}

RemoteCallState CallRemote(HANDLE process,
                           LPTHREAD_START_ROUTINE function, void* parameter,
                           DWORD timeout, DWORD& result, DWORD& error) {
    ScopedHandle thread;
    thread.value = CreateRemoteThread(process, nullptr, 0, function, parameter,
                                      0, nullptr);
    if (!thread) {
        error = GetLastError();
        return RemoteCallState::failed;
    }
    const DWORD wait = WaitForSingleObject(thread.value, timeout);
    if (wait == WAIT_TIMEOUT) {
        error = WAIT_TIMEOUT;
        return RemoteCallState::timedOut;
    }
    if (wait != WAIT_OBJECT_0 || !GetExitCodeThread(thread.value, &result)) {
        error = wait == WAIT_FAILED ? GetLastError() : ERROR_FUNCTION_FAILED;
        return RemoteCallState::failed;
    }
    error = ERROR_SUCCESS;
    return RemoteCallState::completed;
}

bool ResolveRemoteSystemFunction(const std::vector<ModuleRecord>& modules,
                                 const RemoteFunction& local,
                                 LPTHREAD_START_ROUTINE& remote) {
    const ModuleRecord* owner = FindModuleByName(modules, local.ownerName);
    if (!owner || local.offset >= owner->size) return false;
    remote = reinterpret_cast<LPTHREAD_START_ROUTINE>(owner->base +
                                                       local.offset);
    return true;
}

bool ResolveStartOffset(const std::wstring& dllPath, ULONG_PTR& offset,
                        DWORD& error) {
    HMODULE module = LoadLibraryExW(dllPath.c_str(), nullptr,
                                    DONT_RESOLVE_DLL_REFERENCES);
    if (!module) {
        error = GetLastError();
        return false;
    }
    FARPROC start = GetProcAddress(module, "ClipHookStartRemote");
    DWORD imageSize = 0;
    const bool imageValid = LocalImageSize(module, imageSize);
    const ULONG_PTR base = reinterpret_cast<ULONG_PTR>(module);
    const ULONG_PTR address = reinterpret_cast<ULONG_PTR>(start);
    const bool valid = start && imageValid && address >= base &&
                       address - base < imageSize;
    if (valid) offset = address - base;
    FreeLibrary(module);
    if (!valid) {
        error = start ? ERROR_BAD_EXE_FORMAT : ERROR_PROC_NOT_FOUND;
        return false;
    }
    error = ERROR_SUCCESS;
    return true;
}

bool ReleaseOneReference(HANDLE process,
                         const std::vector<ModuleRecord>& modules,
                         const ModuleRecord& target, DWORD& error) {
    RemoteFunction freeLibrary;
    LPTHREAD_START_ROUTINE remoteFree = nullptr;
    if (!ResolveSystemFunction("FreeLibrary", freeLibrary) ||
        !ResolveRemoteSystemFunction(modules, freeLibrary, remoteFree)) {
        error = ERROR_PROC_NOT_FOUND;
        return false;
    }
    DWORD result = 0;
    const RemoteCallState state = CallRemote(
        process, remoteFree, reinterpret_cast<void*>(target.base), 5000,
        result, error);
    if (state != RemoteCallState::completed || result == 0) {
        if (state == RemoteCallState::completed) error = ERROR_DLL_INIT_FAILED;
        return false;
    }
    error = ERROR_SUCCESS;
    return true;
}

} // namespace

RemoteHookStartResult RemoteHookStart(DWORD processId,
                                      ULONGLONG expectedCreationTime,
                                      const std::wstring& dllPath) {
    RemoteHookStartResult result;
    if (processId == 0 || expectedCreationTime == 0 || dllPath.empty()) {
        result.error = ERROR_INVALID_PARAMETER;
        return result;
    }
    std::wstring fullDllPath;
    if (!FullPath(dllPath, fullDllPath)) {
        result.error = GetLastError();
        if (result.error == ERROR_SUCCESS) result.error = ERROR_INVALID_NAME;
        return result;
    }
    const DWORD attributes = GetFileAttributesW(fullDllPath.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES ||
        (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
        result.error = ERROR_FILE_NOT_FOUND;
        return result;
    }

    constexpr DWORD access = PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
                             PROCESS_VM_WRITE | PROCESS_VM_READ |
                             PROCESS_QUERY_INFORMATION;
    ScopedHandle process;
    if (!OpenValidatedProcess(processId, expectedCreationTime, access, process,
                              result.error))
        return result;

    std::vector<ModuleRecord> modules;
    if (!SnapshotModules(processId, modules, result.error)) return result;
    const ModuleRecord* remoteModule = FindModuleByPath(modules, fullDllPath);
    bool addedReference = false;

    if (!remoteModule) {
        RemoteFunction loadLibrary;
        LPTHREAD_START_ROUTINE remoteLoad = nullptr;
        if (!ResolveSystemFunction("LoadLibraryW", loadLibrary) ||
            !ResolveRemoteSystemFunction(modules, loadLibrary, remoteLoad)) {
            result.error = ERROR_PROC_NOT_FOUND;
            return result;
        }
        const SIZE_T pathBytes = (fullDllPath.size() + 1) * sizeof(wchar_t);
        void* remotePath = VirtualAllocEx(process.value, nullptr, pathBytes,
                                          MEM_COMMIT | MEM_RESERVE,
                                          PAGE_READWRITE);
        if (!remotePath) {
            result.error = GetLastError();
            return result;
        }
        SIZE_T written = 0;
        if (!WriteProcessMemory(process.value, remotePath,
                                fullDllPath.c_str(), pathBytes, &written) ||
            written != pathBytes) {
            result.error = GetLastError();
            VirtualFreeEx(process.value, remotePath, 0, MEM_RELEASE);
            return result;
        }
        DWORD loadResult = 0;
        const RemoteCallState loadState = CallRemote(
            process.value, remoteLoad, remotePath, 5000, loadResult,
            result.error);
        if (loadState != RemoteCallState::timedOut)
            VirtualFreeEx(process.value, remotePath, 0, MEM_RELEASE);
        if (loadState != RemoteCallState::completed) {
            // A timed-out loader may still finish and own a reference later.
            result.retainedReference = loadState == RemoteCallState::timedOut;
            return result;
        }
        modules.clear();
        if (!SnapshotModules(processId, modules, result.error)) {
            result.retainedReference = loadResult != 0;
            return result;
        }
        remoteModule = FindModuleByPath(modules, fullDllPath);
        if (!remoteModule) {
            result.error = ERROR_MOD_NOT_FOUND;
            return result;
        }
        addedReference = true;
    }

    ULONG_PTR startOffset = 0;
    if (!ResolveStartOffset(fullDllPath, startOffset, result.error) ||
        startOffset >= remoteModule->size) {
        if (result.error == ERROR_SUCCESS) result.error = ERROR_BAD_EXE_FORMAT;
    } else {
        DWORD startResult = 0;
        const RemoteCallState startState = CallRemote(
            process.value,
            reinterpret_cast<LPTHREAD_START_ROUTINE>(remoteModule->base +
                                                       startOffset),
            nullptr, 5000, startResult, result.error);
        if (startState == RemoteCallState::completed && startResult != 0) {
            result.started = true;
            result.error = ERROR_SUCCESS;
        } else if (startState == RemoteCallState::completed) {
            result.error = ERROR_DLL_INIT_FAILED;
        }
        if (startState == RemoteCallState::timedOut && addedReference) {
            // The remote thread may still be executing code in this module.
            result.retainedReference = true;
            return result;
        }
    }

    if (addedReference) {
        DWORD releaseError = ERROR_SUCCESS;
        if (!ReleaseOneReference(process.value, modules, *remoteModule,
                                 releaseError)) {
            result.retainedReference = true;
            if (result.started) result.error = releaseError;
        }
    }
    return result;
}

bool RemoteHookRelease(DWORD processId, ULONGLONG expectedCreationTime,
                       const std::wstring& dllPath, DWORD& error) {
    error = ERROR_SUCCESS;
    if (processId == 0 || expectedCreationTime == 0 || dllPath.empty()) {
        error = ERROR_INVALID_PARAMETER;
        return false;
    }
    std::wstring fullDllPath;
    if (!FullPath(dllPath, fullDllPath)) {
        error = ERROR_INVALID_NAME;
        return false;
    }
    constexpr DWORD access = PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
                             PROCESS_VM_WRITE | PROCESS_VM_READ |
                             PROCESS_QUERY_INFORMATION;
    ScopedHandle process;
    if (!OpenValidatedProcess(processId, expectedCreationTime, access, process,
                              error))
        return error == ERROR_PROCESS_ABORTED;

    std::vector<ModuleRecord> modules;
    if (!SnapshotModules(processId, modules, error)) return false;
    const ModuleRecord* target = FindModuleByPath(modules, fullDllPath);
    if (!target) {
        error = ERROR_SUCCESS;
        return true;
    }
    return ReleaseOneReference(process.value, modules, *target, error);
}

} // namespace clip
