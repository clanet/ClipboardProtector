#pragma once
#include <windows.h>
#include <cstddef>

namespace clip {
constexpr DWORD kPrivateClipMagic = 0x31564350; // PCV1
constexpr DWORD kPrivateClipVersion = 1;
constexpr DWORD kPrivateClipMaxChars = 65536;
constexpr wchar_t kPrivateClipPrefix[] = L"Local\\ClipboardProtector.Private.";
enum PrivateClipState : LONG {
    kPrivateCreated, kPrivateReady, kPrivateSending, kPrivateRunning,
    kPrivateDone, kPrivateFailed, kPrivateCancelledBeforeInput, kPrivateCancelled
};
enum PrivateClipError : DWORD {
    kPrivateOk, kPrivateNoText, kPrivateUnsupported, kPrivateTooLarge,
    kPrivateWrongTarget, kPrivateTimedOut, kPrivateInvalidData, kPrivateBusy
};
// Fixed-width, pointer-free layout shared by x86/x64. Only the random mapping
// name travels through the existing authenticated control pipe, never its text.
struct alignas(8) PrivateClipSession {
    DWORD magic;
    DWORD version;
    volatile LONG state;
    DWORD error;
    DWORD processId;
    DWORD threadId;
    DWORD operation; // 0 copy, 1 paste
    DWORD inputTag;
    ULONGLONG foreground;
    ULONGLONG focus;
    ULONGLONG deadline;
    DWORD length;
    DWORD reserved;
    wchar_t text[kPrivateClipMaxChars + 1];
};
static_assert(offsetof(PrivateClipSession, text) == 64, "cross-bitness layout");
static_assert(sizeof(PrivateClipSession) == 131144, "cross-bitness mapping size");
inline LONG PrivateState(PrivateClipSession* session) {
    return InterlockedCompareExchange(&session->state, 0, 0);
}
} // namespace clip
