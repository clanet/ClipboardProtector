#pragma once

#include <windows.h>
#include <string>

namespace clip {

struct RemoteHookStartResult {
    bool started = false;
    // True only when LoadLibrary added a reference that could not yet be
    // balanced. The caller must retry RemoteHookRelease for this identity.
    bool retainedReference = false;
    DWORD error = ERROR_SUCCESS;
};

// All operations are same-architecture and reject PID reuse by checking the
// process creation time immediately before modifying the target.
RemoteHookStartResult RemoteHookStart(DWORD processId,
                                      ULONGLONG expectedCreationTime,
                                      const std::wstring& dllPath);
bool RemoteHookRelease(DWORD processId, ULONGLONG expectedCreationTime,
                       const std::wstring& dllPath, DWORD& error);

constexpr DWORD kRemoteHelperStarted = 0;
constexpr DWORD kRemoteHelperStartedRetained = 10;
constexpr DWORD kRemoteHelperFailedRetained = 11;
constexpr DWORD kRemoteHelperFailed = 20;

} // namespace clip
