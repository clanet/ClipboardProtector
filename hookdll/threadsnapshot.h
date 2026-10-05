#pragma once
#include <windows.h>
#include <winternl.h>

namespace clip {

// Enumerate only this process. Retain handles to prevent thread-ID reuse.
// Enumeration during suspension does not allocate from the host heap.
class ThreadSnapshot {
public:
    ThreadSnapshot() = default;
    ThreadSnapshot(const ThreadSnapshot&) = delete;
    ThreadSnapshot& operator=(const ThreadSnapshot&) = delete;
    ~ThreadSnapshot() { Clear(); if (entries_) VirtualFree(entries_, 0, MEM_RELEASE); }

    bool Prepare() noexcept {
        next_ = reinterpret_cast<Next>(GetProcAddress(
            GetModuleHandleW(L"ntdll.dll"), "NtGetNextThread"));
        if (!next_) return false;
        entries_ = static_cast<Entry*>(VirtualAlloc(nullptr, sizeof(Entry) * kCapacity,
            MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        return entries_ && Refresh();
    }

    bool Refresh(ULONGLONG deadline = 0) noexcept {
        Clear();
        HANDLE previous = nullptr;
        for (;;) {
            if (deadline && GetTickCount64() >= deadline) return false;
            HANDLE thread = nullptr;
            const NTSTATUS status = next_(GetCurrentProcess(), previous,
                MAXIMUM_ALLOWED,
                0, 0, &thread);
            if (status == static_cast<NTSTATUS>(0x8000001AL)) return count_ != 0;
            if (status < 0) return false;
            if (count_ == kCapacity) { CloseHandle(thread); return false; }
            const DWORD id = GetThreadId(thread);
            entries_[count_++] = {thread, id};
            if (!id) return false;
            previous = thread;
        }
    }

    ULONG Count() const noexcept { return count_; }
    DWORD Id(ULONG index) const noexcept { return entries_[index].id; }
    HANDLE Take(ULONG index) noexcept {
        HANDLE thread = entries_[index].thread;
        entries_[index].thread = nullptr;
        return thread;
    }

private:
    struct Entry { HANDLE thread; DWORD id; };
    static constexpr ULONG kCapacity = 4096;
    using Next = NTSTATUS (NTAPI*)(HANDLE, HANDLE, ACCESS_MASK, ULONG, ULONG, PHANDLE);
    void Clear() noexcept {
        for (ULONG i = 0; i < count_; ++i)
            if (entries_[i].thread) CloseHandle(entries_[i].thread);
        count_ = 0;
    }
    Next next_ = nullptr;
    Entry* entries_ = nullptr;
    ULONG count_ = 0;
};

} // namespace clip
