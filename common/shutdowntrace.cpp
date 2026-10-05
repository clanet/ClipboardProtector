#include "shutdowntrace.h"
#include <stdlib.h>

namespace clip {
namespace {
struct LastErrorGuard {
    DWORD saved = GetLastError();
    ~LastErrorGuard() { SetLastError(saved); }
};

// Avoid CRT formatting/locale locks, including in diagnostic error paths.
struct Line {
    char* data;
    size_t size;
    size_t used = 0;
    void Text(const char* text) noexcept {
        while (*text && used < size - 2) data[used++] = *text++;
    }
    void Number(ULONGLONG value, unsigned width = 0) noexcept {
        char digits[24];
        unsigned count = 0;
        do { digits[count++] = static_cast<char>('0' + value % 10); value /= 10; } while (value);
        while (count < width && count < sizeof(digits)) digits[count++] = '0';
        while (count && used < size - 2) data[used++] = digits[--count];
    }
    void Finish() noexcept {
        while (used < size - 2) data[used++] = ' ';
        data[size - 2] = '\r'; data[size - 1] = '\n';
    }
};

bool Append(wchar_t* path, size_t capacity, const wchar_t* text) noexcept {
    size_t used = 0;
    while (used < capacity && path[used]) ++used;
    while (*text && used + 1 < capacity) path[used++] = *text++;
    if (used >= capacity) return false;
    path[used] = 0;
    return !*text;
}

void AppendNumber(wchar_t* path, size_t capacity, ULONGLONG value) noexcept {
    char digits[32] = {};
    Line line{digits, sizeof(digits)};
    line.Number(value);
    wchar_t wide[32] = {};
    for (size_t i = 0; i < line.used; ++i) wide[i] = digits[i];
    Append(path, capacity, wide);
}

bool Directory(const wchar_t* path) noexcept {
    if (CreateDirectoryW(path, nullptr)) return true;
    if (GetLastError() != ERROR_ALREADY_EXISTS) return false;
    const DWORD attributes = GetFileAttributesW(path);
    return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

const wchar_t* Basename(const wchar_t* path) noexcept {
    const wchar_t* name = path;
    for (; *path; ++path) if (*path == L'\\' || *path == L'/') name = path + 1;
    return name;
}
}

bool ShutdownTrace::Open(const wchar_t* role, HMODULE module) noexcept {
    LastErrorGuard saved;
    if (enabled()) return true;
    wchar_t flag[8] = {};
    if (GetEnvironmentVariableW(L"CLIP_SHUTDOWN_TRACE", flag, _countof(flag)) != 1 ||
        flag[0] != L'1') return false;
    wchar_t path[32768] = {};
    DWORD length = GetEnvironmentVariableW(L"CLIP_SHUTDOWN_LOG_DIR", path, _countof(path));
    if (length >= _countof(path)) return false;
    if (!length) {
        length = GetEnvironmentVariableW(L"LOCALAPPDATA", path, _countof(path));
        if (!length || length >= _countof(path) ||
            !Append(path, _countof(path), L"\\ClipboardProtector") || !Directory(path) ||
            !Append(path, _countof(path), L"\\Diagnostics")) return false;
    }
    if (lstrlenW(path) > 32000 || !Directory(path) || !Append(path, _countof(path), L"\\shutdown-") ||
        !Append(path, _countof(path), role) || !Append(path, _countof(path), L"-p")) return false;
    AppendNumber(path, _countof(path), GetCurrentProcessId());
    Append(path, _countof(path), L"-t");
    AppendNumber(path, _countof(path), GetCurrentThreadId());
    Append(path, _countof(path), L"-");
    FILETIME time;
    GetSystemTimeAsFileTime(&time);
    AppendNumber(path, _countof(path), (static_cast<ULONGLONG>(time.dwHighDateTime) << 32) | time.dwLowDateTime);
    static volatile LONG serial = 0;
    Append(path, _countof(path), L"-");
    AppendNumber(path, _countof(path), static_cast<DWORD>(InterlockedIncrement(&serial)));
    if (!Append(path, _countof(path), L".log")) return false;
    file_ = CreateFileW(path, GENERIC_READ | GENERIC_WRITE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file_ == INVALID_HANDLE_VALUE) return false;
    mapping_ = CreateFileMappingW(file_, nullptr, PAGE_READWRITE, 0, kFileBytes, nullptr);
    if (mapping_) view_ = static_cast<char*>(MapViewOfFile(mapping_, FILE_MAP_WRITE, 0, 0, kFileBytes));
    if (!view_) { Close(); return false; }
    // Fault in writable pages before any host threads can be suspended.
    for (DWORD offset = 0; offset < kFileBytes; ++offset) view_[offset] = ' ';
    sequence_ = 0;
    LARGE_INTEGER frequency{}, now{};
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&now);
    frequency_ = frequency.QuadPart;
    started_ = previous_ = now.QuadPart;

    char header[kHeaderBytes];
    Line line{header, sizeof(header)};
    line.Text("ClipboardProtector shutdown trace v1; build=" __DATE__ " " __TIME__);
    line.Text("; arch="); line.Number(sizeof(void*) * 8);
    line.Text("; pid="); line.Number(GetCurrentProcessId());
    line.Text("; tid="); line.Number(GetCurrentThreadId());
    SYSTEMTIME utc{};
    FileTimeToSystemTime(&time, &utc);
    line.Text("; utc="); line.Number(utc.wYear, 4); line.Text("-"); line.Number(utc.wMonth, 2);
    line.Text("-"); line.Number(utc.wDay, 2); line.Text("T"); line.Number(utc.wHour, 2);
    line.Text(":"); line.Number(utc.wMinute, 2); line.Text(":"); line.Number(utc.wSecond, 2);
    line.Text("."); line.Number(utc.wMilliseconds, 3); line.Text("Z; process=");
    wchar_t name[32768] = {};
    GetModuleFileNameW(nullptr, name, _countof(name));
    name[_countof(name) - 1] = 0;
    char utf8[1024] = {};
    WideCharToMultiByte(CP_UTF8, 0, Basename(name), -1, utf8, sizeof(utf8), nullptr, nullptr);
    line.Text(utf8);
    line.Text("; module=");
    name[0] = 0; utf8[0] = 0;
    GetModuleFileNameW(module, name, _countof(name));
    name[_countof(name) - 1] = 0;
    WideCharToMultiByte(CP_UTF8, 0, Basename(name), -1, utf8, sizeof(utf8), nullptr, nullptr);
    line.Text(utf8);
    line.Text("; capacity=4096; last slot tracks latest event on overflow");
    line.Finish();
    CopyMemory(view_, header, sizeof(header));
    Mark("trace.open");
    return true;
}

void ShutdownTrace::Mark(const char* stage, ULONGLONG value, DWORD error) noexcept {
    if (!view_) return;
    LastErrorGuard saved;
    LARGE_INTEGER now{};
    QueryPerformanceCounter(&now);
    const ULONGLONG elapsed = frequency_ > 0 ? (now.QuadPart - started_) * 1000000 / frequency_ : 0;
    const ULONGLONG delta = frequency_ > 0 ? (now.QuadPart - previous_) * 1000000 / frequency_ : 0;
    previous_ = now.QuadPart;
    char record[kLineBytes];
    Line line{record, sizeof(record)};
    line.Text("seq="); line.Number(++sequence_);
    line.Text(" tick_ms="); line.Number(GetTickCount64());
    line.Text(" elapsed_us="); line.Number(elapsed);
    line.Text(" step_us="); line.Number(delta);
    line.Text(" tid="); line.Number(GetCurrentThreadId());
    line.Text(" stage="); line.Text(stage);
    line.Text(" value="); line.Number(value);
    line.Text(" error="); line.Number(error);
    line.Finish();
    const ULONGLONG index = sequence_ <= kRecords ? sequence_ - 1 : kRecords - 1;
    CopyMemory(view_ + kHeaderBytes + index * kLineBytes, record, sizeof(record));
    MemoryBarrier();
}

void ShutdownTrace::Close() noexcept {
    LastErrorGuard saved;
    if (view_) {
        Mark("trace.close");
        UnmapViewOfFile(view_);
        view_ = nullptr;
    }
    if (mapping_) { CloseHandle(mapping_); mapping_ = nullptr; }
    if (file_ != INVALID_HANDLE_VALUE) {
        LARGE_INTEGER size;
        size.QuadPart = kHeaderBytes + (sequence_ < kRecords ? sequence_ : kRecords) * kLineBytes;
        if (SetFilePointerEx(file_, size, nullptr, FILE_BEGIN)) SetEndOfFile(file_);
        CloseHandle(file_);
        file_ = INVALID_HANDLE_VALUE;
    }
}
} // namespace clip
