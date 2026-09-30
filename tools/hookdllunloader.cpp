#include <windows.h>
#include <tlhelp32.h>

#include <algorithm>
#include <cwchar>
#include <string>
#include <utility>
#include <vector>

namespace {

struct Options {
    std::wstring dllPath;
    DWORD processId = 0;
    bool execute = false;
    bool includeSystem = false;
};

struct ModuleRecord {
    std::wstring name;
    std::wstring path;
    BYTE* base = nullptr;
    DWORD size = 0;
};

struct RemoteFunction {
    std::wstring ownerModule;
    ULONG_PTR offset = 0;
};

void PrintUsage() {
    fwprintf(stderr,
             L"Usage: HookDllUnloader[32].exe --dll <absolute-path> "
             L"[--pid <id>] [--execute] [--include-system]\n"
             L"Without --execute the tool only lists exact-path matches.\n");
}

bool ParseProcessId(const wchar_t* text, DWORD& value) {
    if (!text || !*text) return false;
    wchar_t* end = nullptr;
    unsigned long parsed = wcstoul(text, &end, 10);
    if (end == text || *end != L'\0' || parsed == 0) return false;
    value = static_cast<DWORD>(parsed);
    return true;
}

bool ParseOptions(int argc, wchar_t** argv, Options& options) {
    for (int i = 1; i < argc; ++i) {
        if (_wcsicmp(argv[i], L"--dll") == 0 && i + 1 < argc) {
            options.dllPath = argv[++i];
        } else if (_wcsicmp(argv[i], L"--pid") == 0 && i + 1 < argc) {
            if (!ParseProcessId(argv[++i], options.processId)) return false;
        } else if (_wcsicmp(argv[i], L"--execute") == 0) {
            options.execute = true;
        } else if (_wcsicmp(argv[i], L"--include-system") == 0) {
            options.includeSystem = true;
        } else {
            return false;
        }
    }
    return !options.dllPath.empty();
}

bool IsAbsolutePath(const std::wstring& path) {
    if (path.size() < 3) return false;
    const bool drivePath =
        ((path[0] >= L'A' && path[0] <= L'Z') ||
         (path[0] >= L'a' && path[0] <= L'z')) &&
        path[1] == L':' && (path[2] == L'\\' || path[2] == L'/');
    const bool uncPath = path[0] == L'\\' && path[1] == L'\\';
    return drivePath || uncPath;
}

void NormalizeSlashes(std::wstring& path) {
    std::replace(path.begin(), path.end(), L'/', L'\\');
    if (path.rfind(L"\\\\?\\UNC\\", 0) == 0)
        path = L"\\\\" + path.substr(8);
    else if (path.rfind(L"\\\\?\\", 0) == 0)
        path.erase(0, 4);
}

bool CanonicalPath(const std::wstring& input, std::wstring& output,
                   bool requireFile) {
    std::vector<wchar_t> full(32768);
    DWORD length = GetFullPathNameW(input.c_str(), static_cast<DWORD>(full.size()),
                                    full.data(), nullptr);
    if (length == 0 || length >= full.size()) return false;
    output.assign(full.data(), length);
    NormalizeSlashes(output);

    HANDLE file = CreateFileW(
        output.c_str(), FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return !requireFile;
    std::vector<wchar_t> finalPath(32768);
    length = GetFinalPathNameByHandleW(
        file, finalPath.data(), static_cast<DWORD>(finalPath.size()),
        FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    CloseHandle(file);
    if (length > 0 && length < finalPath.size()) {
        output.assign(finalPath.data(), length);
        NormalizeSlashes(output);
    }
    return true;
}

bool SamePath(const std::wstring& left, const std::wstring& right) {
    std::wstring canonicalLeft;
    std::wstring canonicalRight;
    if (!CanonicalPath(left, canonicalLeft, false)) canonicalLeft = left;
    if (!CanonicalPath(right, canonicalRight, false)) canonicalRight = right;
    NormalizeSlashes(canonicalLeft);
    NormalizeSlashes(canonicalRight);
    return _wcsicmp(canonicalLeft.c_str(), canonicalRight.c_str()) == 0;
}

std::wstring BaseName(const std::wstring& path) {
    const size_t slash = path.find_last_of(L"\\/");
    return slash == std::wstring::npos ? path : path.substr(slash + 1);
}

bool SnapshotModules(DWORD processId, std::vector<ModuleRecord>& modules,
                     DWORD& error) {
    modules.clear();
    HANDLE snapshot = INVALID_HANDLE_VALUE;
    for (int attempt = 0; attempt < 8; ++attempt) {
        snapshot = CreateToolhelp32Snapshot(
            TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
        if (snapshot != INVALID_HANDLE_VALUE) break;
        error = GetLastError();
        if (error != ERROR_BAD_LENGTH) return false;
        Sleep(10);
    }
    if (snapshot == INVALID_HANDLE_VALUE) return false;

    MODULEENTRY32W entry = {sizeof(entry)};
    if (!Module32FirstW(snapshot, &entry)) {
        error = GetLastError();
        CloseHandle(snapshot);
        return false;
    }
    try {
        do {
            ModuleRecord module;
            module.name = entry.szModule;
            module.path = entry.szExePath;
            module.base = entry.modBaseAddr;
            module.size = entry.modBaseSize;
            modules.push_back(std::move(module));
        } while (Module32NextW(snapshot, &entry));
    } catch (...) {
        error = ERROR_OUTOFMEMORY;
        CloseHandle(snapshot);
        return false;
    }
    CloseHandle(snapshot);
    error = ERROR_SUCCESS;
    return true;
}

const ModuleRecord* FindModuleByPath(const std::vector<ModuleRecord>& modules,
                                     const std::wstring& path) {
    const std::wstring expectedName = BaseName(path);
    for (const auto& module : modules) {
        if (_wcsicmp(module.name.c_str(), expectedName.c_str()) != 0) continue;
        if (SamePath(module.path, path)) return &module;
    }
    return nullptr;
}

const ModuleRecord* FindModuleByName(const std::vector<ModuleRecord>& modules,
                                     const std::wstring& name) {
    for (const auto& module : modules) {
        if (_wcsicmp(module.name.c_str(), name.c_str()) == 0) return &module;
    }
    return nullptr;
}

bool QueryProcessPath(HANDLE process, std::wstring& path) {
    std::vector<wchar_t> buffer(32768);
    DWORD length = static_cast<DWORD>(buffer.size());
    if (!QueryFullProcessImageNameW(process, 0, buffer.data(), &length))
        return false;
    path.assign(buffer.data(), length);
    return true;
}

bool SameArchitecture(HANDLE process, bool& same) {
    BOOL currentWow64 = FALSE;
    BOOL targetWow64 = FALSE;
    if (!IsWow64Process(GetCurrentProcess(), &currentWow64) ||
        !IsWow64Process(process, &targetWow64))
        return false;
    same = currentWow64 == targetWow64;
    return true;
}

bool EnableDebugPrivilege() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        return false;
    LUID id = {};
    if (!LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &id)) {
        CloseHandle(token);
        return false;
    }
    TOKEN_PRIVILEGES privileges = {};
    privileges.PrivilegeCount = 1;
    privileges.Privileges[0].Luid = id;
    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    SetLastError(ERROR_SUCCESS);
    const BOOL adjusted = AdjustTokenPrivileges(token, FALSE, &privileges, 0,
                                                nullptr, nullptr);
    const DWORD error = GetLastError();
    CloseHandle(token);
    return adjusted && error != ERROR_NOT_ALL_ASSIGNED;
}

bool IsCriticalProcess(HANDLE process) {
    using IsProcessCriticalFn = BOOL(WINAPI*)(HANDLE, PBOOL);
    static auto function = reinterpret_cast<IsProcessCriticalFn>(
        GetProcAddress(GetModuleHandleW(L"kernel32.dll"),
                       "IsProcessCritical"));
    BOOL critical = FALSE;
    return function && function(process, &critical) && critical;
}

bool IsWindowsProcess(const std::wstring& processPath) {
    wchar_t directory[MAX_PATH] = {};
    const UINT length = GetWindowsDirectoryW(directory, _countof(directory));
    if (length == 0 || length >= _countof(directory)) return false;
    std::wstring prefix(directory, length);
    NormalizeSlashes(prefix);
    if (prefix.empty() || prefix.back() != L'\\') prefix.push_back(L'\\');
    std::wstring normalized = processPath;
    NormalizeSlashes(normalized);
    return normalized.size() >= prefix.size() &&
           _wcsnicmp(normalized.c_str(), prefix.c_str(), prefix.size()) == 0;
}

bool ControllerRunning() {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return false;
    PROCESSENTRY32W entry = {sizeof(entry)};
    bool found = false;
    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (entry.th32ProcessID != GetCurrentProcessId() &&
                _wcsicmp(entry.szExeFile, L"ClipboardProtector.exe") == 0) {
                found = true;
                break;
            }
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return found;
}

bool LocalModuleSize(HMODULE module, DWORD& size) {
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

bool ResolveFreeLibrary(RemoteFunction& result) {
    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    FARPROC freeLibrary = kernel32 ? GetProcAddress(kernel32, "FreeLibrary")
                                   : nullptr;
    if (!freeLibrary) return false;
    HMODULE owner = nullptr;
    if (!GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(freeLibrary), &owner))
        return false;
    DWORD ownerSize = 0;
    if (!LocalModuleSize(owner, ownerSize)) return false;
    const ULONG_PTR address = reinterpret_cast<ULONG_PTR>(freeLibrary);
    const ULONG_PTR base = reinterpret_cast<ULONG_PTR>(owner);
    if (address < base || address - base >= ownerSize) return false;
    wchar_t ownerPath[32768] = {};
    const DWORD length = GetModuleFileNameW(owner, ownerPath, _countof(ownerPath));
    if (length == 0 || length >= _countof(ownerPath)) return false;
    result.ownerModule = BaseName(std::wstring(ownerPath, length));
    result.offset = address - base;
    return true;
}

bool WaitUntilModuleGone(DWORD processId, const std::wstring& dllPath,
                         DWORD timeout) {
    const ULONGLONG deadline = GetTickCount64() + timeout;
    do {
        std::vector<ModuleRecord> modules;
        DWORD error = ERROR_SUCCESS;
        if (SnapshotModules(processId, modules, error) &&
            !FindModuleByPath(modules, dllPath))
            return true;
        Sleep(20);
    } while (GetTickCount64() < deadline);
    return false;
}

bool RemoteFreeLibrary(DWORD processId, const std::wstring& dllPath,
                       const RemoteFunction& function, DWORD& error,
                       bool& processExited) {
    processExited = false;
    HANDLE process = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION |
            PROCESS_VM_WRITE | PROCESS_VM_READ | SYNCHRONIZE,
        FALSE, processId);
    if (!process) {
        error = GetLastError();
        return false;
    }
    if (WaitForSingleObject(process, 0) != WAIT_TIMEOUT) {
        processExited = true;
        error = ERROR_PROCESS_ABORTED;
        CloseHandle(process);
        return false;
    }

    std::vector<ModuleRecord> modules;
    if (!SnapshotModules(processId, modules, error)) {
        CloseHandle(process);
        return false;
    }
    const ModuleRecord* target = FindModuleByPath(modules, dllPath);
    const ModuleRecord* owner = FindModuleByName(modules, function.ownerModule);
    if (!target || !owner || function.offset >= owner->size) {
        error = ERROR_MOD_NOT_FOUND;
        CloseHandle(process);
        return false;
    }
    auto remoteFunction = reinterpret_cast<LPTHREAD_START_ROUTINE>(
        owner->base + function.offset);
    HANDLE thread = CreateRemoteThread(process, nullptr, 0, remoteFunction,
                                       target->base, 0, nullptr);
    if (!thread) {
        error = GetLastError();
        CloseHandle(process);
        return false;
    }
    const DWORD wait = WaitForSingleObject(thread, 5000);
    DWORD threadResult = 0;
    const bool completed =
        wait == WAIT_OBJECT_0 && GetExitCodeThread(thread, &threadResult);
    CloseHandle(thread);
    if (!completed || threadResult == 0) {
        error = wait == WAIT_TIMEOUT ? WAIT_TIMEOUT : ERROR_DLL_INIT_FAILED;
        processExited = WaitForSingleObject(process, 0) == WAIT_OBJECT_0;
        CloseHandle(process);
        return false;
    }
    processExited = WaitForSingleObject(process, 0) == WAIT_OBJECT_0;
    CloseHandle(process);
    if (processExited) {
        error = ERROR_PROCESS_ABORTED;
        return false;
    }
    if (!WaitUntilModuleGone(processId, dllPath, 3000)) {
        error = ERROR_BUSY;
        return false;
    }
    error = ERROR_SUCCESS;
    return true;
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    Options options;
    if (!ParseOptions(argc, argv, options) ||
        !IsAbsolutePath(options.dllPath)) {
        PrintUsage();
        return 2;
    }
    std::wstring dllPath;
    if (!CanonicalPath(options.dllPath, dllPath, true)) {
        fwprintf(stderr, L"DLL path is not an accessible file: %ls\n",
                 options.dllPath.c_str());
        return 2;
    }
    if (options.execute && ControllerRunning()) {
        fwprintf(stderr,
                 L"Refusing to execute while ClipboardProtector.exe is "
                 L"running. Stop it first.\n");
        return 3;
    }
    if (options.execute && !EnableDebugPrivilege()) {
        fwprintf(stderr,
                 L"Warning: SeDebugPrivilege is unavailable; only accessible "
                 L"processes can be modified.\n");
    }
    RemoteFunction freeLibrary;
    if (!ResolveFreeLibrary(freeLibrary)) {
        fwprintf(stderr, L"Cannot resolve the local FreeLibrary implementation.\n");
        return 4;
    }

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        fwprintf(stderr, L"Cannot enumerate processes: %lu\n", GetLastError());
        return 4;
    }
    unsigned matches = 0;
    unsigned unloaded = 0;
    unsigned skipped = 0;
    unsigned failed = 0;
    PROCESSENTRY32W entry = {sizeof(entry)};
    if (Process32FirstW(snapshot, &entry)) {
        do {
            const DWORD processId = entry.th32ProcessID;
            if (processId == 0 || processId == 4 ||
                processId == GetCurrentProcessId() ||
                (options.processId != 0 && processId != options.processId))
                continue;
            HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION |
                                             SYNCHRONIZE,
                                         FALSE, processId);
            if (!process) continue;
            bool sameArchitecture = false;
            if (!SameArchitecture(process, sameArchitecture) ||
                !sameArchitecture) {
                CloseHandle(process);
                continue;
            }
            std::wstring processPath;
            (void)QueryProcessPath(process, processPath);
            std::vector<ModuleRecord> modules;
            DWORD moduleError = ERROR_SUCCESS;
            if (!SnapshotModules(processId, modules, moduleError)) {
                CloseHandle(process);
                continue;
            }
            const ModuleRecord* target = FindModuleByPath(modules, dllPath);
            if (!target) {
                CloseHandle(process);
                continue;
            }
            ++matches;
            fwprintf(stdout, L"MATCH pid=%lu process=%ls module=%ls\n", processId,
                     processPath.empty() ? entry.szExeFile : processPath.c_str(),
                     target->path.c_str());
            if (IsCriticalProcess(process)) {
                ++skipped;
                fwprintf(stdout, L"SKIP pid=%lu reason=critical-process\n",
                         processId);
                CloseHandle(process);
                continue;
            }
            if (!options.includeSystem && IsWindowsProcess(processPath)) {
                ++skipped;
                fwprintf(stdout,
                         L"SKIP pid=%lu reason=windows-process "
                         L"(use --include-system)\n",
                         processId);
                CloseHandle(process);
                continue;
            }
            CloseHandle(process);
            if (!options.execute) continue;

            DWORD error = ERROR_SUCCESS;
            bool processExited = false;
            if (RemoteFreeLibrary(processId, dllPath, freeLibrary, error,
                                  processExited)) {
                ++unloaded;
                fwprintf(stdout, L"UNLOADED pid=%lu\n", processId);
            } else {
                ++failed;
                fwprintf(stdout,
                         L"FAILED pid=%lu error=%lu process-exited=%d\n",
                         processId, error, processExited ? 1 : 0);
            }
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);

    fwprintf(stdout,
             L"SUMMARY mode=%ls matches=%u unloaded=%u skipped=%u failed=%u\n",
             options.execute ? L"execute" : L"list", matches, unloaded,
             skipped, failed);
    if (!options.execute) return 0;
    return failed == 0 && skipped == 0 ? 0 : 5;
}
