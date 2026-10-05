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

void PrintUsage() {
    fwprintf(stderr,
             L"Usage: HookDllUnloader[32].exe --dll <absolute-path> "
             L"[--pid <id>] [--execute] [--include-system]\n"
             L"Lists exact-path matches only. --execute is rejected because safe "
             L"Detour removal cannot be verified.\n");
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
    if (options.execute) {
        fwprintf(stderr,
                 L"REFUSED: remote FreeLibrary is disabled. A stopped controller "
                 L"does not prove that Detours or in-flight calls are gone. "
                 L"Restart the target application or Windows instead.\n");
        return 3;
    }

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        fwprintf(stderr, L"Cannot enumerate processes: %lu\n", GetLastError());
        return 4;
    }
    unsigned matches = 0;
    unsigned skipped = 0;
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
                         L"(list with --include-system)\n",
                         processId);
                CloseHandle(process);
                continue;
            }
            CloseHandle(process);
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);

    fwprintf(stdout, L"SUMMARY mode=list matches=%u skipped=%u\n", matches, skipped);
    return 0;
}
