#include "shutdowntrace.h"
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <stdio.h>

namespace fs = std::filesystem;
namespace {
struct Handle {
    HANDLE value = nullptr;
    ~Handle() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); }
};
struct HeapOwner { HANDLE ready; HANDLE release; };
DWORD WINAPI HoldHeap(void* argument) {
    const auto& state = *static_cast<HeapOwner*>(argument);
    if (!HeapLock(GetProcessHeap())) return 1;
    SetEvent(state.ready);
    WaitForSingleObject(state.release, INFINITE);
    HeapUnlock(GetProcessHeap());
    return 0;
}
std::string Read(const fs::path& directory, const wchar_t* role, DWORD pid) {
    const std::wstring prefix = std::wstring(L"shutdown-") + role + L"-p" + std::to_wstring(pid) + L"-";
    for (const auto& entry : fs::directory_iterator(directory)) {
        if (entry.path().filename().wstring().find(prefix) != 0) continue;
        std::ifstream input(entry.path(), std::ios::binary);
        return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
    }
    return {};
}
bool Has(const std::string& text, const char* stage) { return text.find(stage) != std::string::npos; }

bool ChildVisibility(const fs::path& directory) {
    SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
    Handle ready{CreateEventW(&sa, TRUE, FALSE, nullptr)};
    Handle release{CreateEventW(&sa, TRUE, FALSE, nullptr)};
    if (!ready.value || !release.value) return false;
    wchar_t exe[32768] = {};
    if (!GetModuleFileNameW(nullptr, exe, _countof(exe))) return false;
    std::wstring command = L"\"" + std::wstring(exe) + L"\" --writer " +
        std::to_wstring(reinterpret_cast<ULONG_PTR>(ready.value)) + L" " +
        std::to_wstring(reinterpret_cast<ULONG_PTR>(release.value));
    STARTUPINFOW startup{sizeof(startup)};
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(exe, command.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW,
                        nullptr, nullptr, &startup, &process)) return false;
    Handle child{process.hProcess}, thread{process.hThread};
    HANDLE waits[] = {ready.value, child.value};
    bool visible = WaitForMultipleObjects(2, waits, FALSE, 3000) == WAIT_OBJECT_0 &&
        Has(Read(directory, L"child", process.dwProcessId), "stage=child.block.begin") &&
        WaitForSingleObject(child.value, 0) == WAIT_TIMEOUT;
    SetEvent(release.value);
    if (WaitForSingleObject(child.value, 3000) != WAIT_OBJECT_0) {
        TerminateProcess(child.value, 99);
        WaitForSingleObject(child.value, 3000);
        return false;
    }
    const std::string after = Read(directory, L"child", process.dwProcessId);
    return visible && Has(after, "stage=child.block.begin") && !Has(after, "stage=trace.close");
}
}

int wmain(int argc, wchar_t** argv) {
    if (argc == 4 && wcscmp(argv[1], L"--writer") == 0) {
        clip::ShutdownTrace trace;
        if (!trace.Open(L"child")) return 20;
        trace.Mark("child.block.begin");
        SetEvent(reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(_wcstoui64(argv[2], nullptr, 10))));
        WaitForSingleObject(reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(_wcstoui64(argv[3], nullptr, 10))), INFINITE);
        ExitProcess(0); // Deliberately skip Close/destructors, like an interrupted shutdown.
    }
    if (argc != 2) return 1;
    const fs::path directory = fs::path(argv[1]) / std::to_wstring(GetCurrentProcessId());
    fs::create_directories(directory);
    SetEnvironmentVariableW(L"CLIP_SHUTDOWN_LOG_DIR", directory.c_str());
    SetEnvironmentVariableW(L"CLIP_SHUTDOWN_TRACE", L"1");
    clip::ShutdownTrace trace;
    SetLastError(1234);
    if (!trace.Open(L"test") || GetLastError() != 1234) return 2;
    trace.Mark("phase.begin");
    Sleep(25);
    trace.Mark("phase.end", 77, ERROR_ACCESS_DENIED);
    std::string live = Read(directory, L"test", GetCurrentProcessId());
    if (!Has(live, "stage=phase.end value=77 error=5") || !Has(live, "utc=") ||
        !Has(live, "elapsed_us=") || Has(live, "stage=trace.close")) return 3;
    const auto stage = live.find("stage=phase.end");
    const auto delta = live.rfind("step_us=", stage);
    if (delta == std::string::npos || std::stoull(live.substr(delta + 8)) < 20000) return 4;

    Handle ready{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
    Handle release{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
    HeapOwner owner{ready.value, release.value};
    Handle holder{CreateThread(nullptr, 0, HoldHeap, &owner, 0, nullptr)};
    if (!ready.value || !release.value || !holder.value) return 5;
    HANDLE waits[] = {ready.value, holder.value};
    if (WaitForMultipleObjects(2, waits, FALSE, 3000) != WAIT_OBJECT_0) return 6;
    SetLastError(5678);
    trace.Mark("host_heap_locked", 99);
    const bool preserved = GetLastError() == 5678;
    SetEvent(release.value);
    if (WaitForSingleObject(holder.value, 3000) != WAIT_OBJECT_0 || !preserved) return 7;

    for (unsigned i = 0; i < 4200; ++i) trace.Mark("overflow", i);
    trace.Mark("overflow.latest", 4200);
    live = Read(directory, L"test", GetCurrentProcessId());
    if (!Has(live, "stage=overflow.latest") || live.size() > 1100000) return 8;
    trace.Close(); trace.Close();
    if (!Has(Read(directory, L"test", GetCurrentProcessId()), "stage=trace.close")) return 9;
    if (!ChildVisibility(directory)) return 10;

    SetEnvironmentVariableW(L"CLIP_SHUTDOWN_TRACE", L"0");
    if (trace.Open(L"disabled")) return 11;
    trace.Mark("disabled.noop");
    SetEnvironmentVariableW(L"CLIP_SHUTDOWN_TRACE", L"1");
    const fs::path invalid = directory / L"not-a-directory";
    { std::ofstream file(invalid); file << "test"; }
    SetEnvironmentVariableW(L"CLIP_SHUTDOWN_LOG_DIR", invalid.c_str());
    SetLastError(999);
    if (trace.Open(L"invalid") || GetLastError() != 999) return 12;
    puts("live-file=1 timing=1 heap-independent=1 overflow-bounded=1 child-stalled-visible=1 interrupted-exit-visible=1 failure-safe=1");
    return 0;
}
