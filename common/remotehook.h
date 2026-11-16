#pragma once

#include <windows.h>
#include <string>

namespace clip {

struct RemoteHookStartResult {
    bool started = false;
    // True only while the caller still owns an unsubmitted balancing release.
    // Once a release thread is submitted, never retry that reference.
    bool retainedReference = false;
    // The balancing release was submitted but did not finish in this call.
    // Never retry its decrement; a caller may still start the loaded module.
    bool releaseSubmitted = false;
    DWORD error = ERROR_SUCCESS;
};

// All operations are same-architecture and reject PID reuse by checking the
// process creation time immediately before modifying the target.
// allowLoad=false：上次 LoadLibrary 超时、可能仍挂在目标中（例如进程被冻结）时，
// 模块未出现就不再追加新的加载线程和远程缓冲区，避免泄漏和引用计数失衡。
RemoteHookStartResult RemoteHookStart(DWORD processId,
                                      ULONGLONG expectedCreationTime,
                                      const std::wstring& dllPath,
                                      bool allowLoad = true,
                                      HANDLE stopEvent = nullptr);
enum class RemoteHookReleaseState { retryable, submitted, released };
// submitted consumes the caller's release responsibility even when its remote
// thread is still pending or its result is unknown. Only retryable may retry.
RemoteHookReleaseState RemoteHookRelease(DWORD processId, ULONGLONG expectedCreationTime,
                       const std::wstring& dllPath, DWORD& error,
                       HANDLE stopEvent = nullptr);

constexpr DWORD kRemoteHelperStarted = 0;
constexpr DWORD kRemoteHelperStartedRetained = 10;
constexpr DWORD kRemoteHelperFailedRetained = 11;
constexpr DWORD kRemoteHelperFailed = 20;
constexpr DWORD kRemoteHelperStartedSubmitted = 12;
constexpr DWORD kRemoteHelperFailedSubmitted = 13;

#ifdef CLIP_TEST_REMOTE_HOOK
void RemoteHookReleaseForTest(LPTHREAD_START_ROUTINE function, DWORD timeout);
#endif

} // namespace clip
