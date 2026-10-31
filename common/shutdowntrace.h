#pragma once
#include <windows.h>

namespace clip {

// Single writer. Open/Close require running host threads; Mark only touches
// prefaulted mapped storage and queries clocks, with no heap or file I/O calls.
class ShutdownTrace {
public:
    ShutdownTrace() = default;
    ShutdownTrace(const ShutdownTrace&) = delete;
    ShutdownTrace& operator=(const ShutdownTrace&) = delete;
    ~ShutdownTrace() { Close(); }

    bool Open(const wchar_t* role, HMODULE module = nullptr) noexcept;
    void Mark(const char* stage, ULONGLONG value = 0, DWORD error = 0) noexcept;
    void Close() noexcept;
    bool enabled() const noexcept { return view_ != nullptr; }

private:
    // 约 128KB 的路径缓冲区单独成帧：未开启跟踪时不占用调用线程的栈。
    __declspec(noinline) bool OpenEnabled(const wchar_t* role, HMODULE module) noexcept;
    static constexpr DWORD kHeaderBytes = 2048;
    static constexpr DWORD kLineBytes = 256;
    static constexpr DWORD kRecords = 4096;
    static constexpr DWORD kFileBytes = kHeaderBytes + kLineBytes * kRecords;
    HANDLE file_ = INVALID_HANDLE_VALUE;
    HANDLE mapping_ = nullptr;
    char* view_ = nullptr;
    ULONGLONG sequence_ = 0;
    LONGLONG frequency_ = 0;
    LONGLONG started_ = 0;
    LONGLONG previous_ = 0;
};

inline void TraceMark(ShutdownTrace* trace, const char* stage,
                      ULONGLONG value = 0, DWORD error = 0) noexcept {
    if (trace) trace->Mark(stage, value, error);
}

} // namespace clip
