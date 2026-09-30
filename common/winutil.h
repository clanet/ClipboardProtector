#pragma once
#include <windows.h>
#include <string>
#include <string_view>

namespace clip {

// Keep the compile-time test surface in the caller: production targets that
// link clip_common cannot accidentally inherit environment-based overrides.
inline std::wstring ResolveObjectName(const wchar_t* testVariable,
                                      const wchar_t* productionName) {
#if defined(CLIP_TEST_OBJECT_NAMES) || defined(CLIP_TEST_EXPORTS)
    wchar_t value[512] = {};
    const DWORD length =
        GetEnvironmentVariableW(testVariable, value, _countof(value));
    if (length > 0 && length < _countof(value))
        return std::wstring(value, length);
#else
    UNREFERENCED_PARAMETER(testVariable);
#endif
    return productionName;
}

bool ModulePath(HMODULE module, std::wstring& path);
bool ModuleDirectory(HMODULE module, std::wstring& directory);
bool ProcessImagePath(HANDLE process, std::wstring& path);
bool ProcessCreationTime(HANDLE process, ULONGLONG& creationTime);
bool SameProcessArchitecture(HANDLE target, DWORD* error = nullptr);
bool WriteAll(HANDLE handle, std::string_view bytes);
bool CurrentUserSidString(std::wstring& sid);
bool CreateLocalUserSecurityDescriptor(PSECURITY_DESCRIPTOR* descriptor);
HANDLE CreateLocalUserNamedEvent(const wchar_t* name, BOOL manualReset,
                                 BOOL initialState);
HANDLE CreateLocalUserNamedMutex(const wchar_t* name, BOOL initialOwner);


} // namespace clip
