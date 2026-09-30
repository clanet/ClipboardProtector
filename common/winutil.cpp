#include "winutil.h"
#include <sddl.h>
#include <algorithm>
#include <vector>


namespace clip {

bool ModulePath(HMODULE module, std::wstring& path) {
    std::vector<wchar_t> buffer(MAX_PATH);
    for (;;) {
        const DWORD length = GetModuleFileNameW(
            module, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (length == 0) return false;
        if (length < buffer.size()) {
            path.assign(buffer.data(), length);
            return true;
        }
        if (buffer.size() >= 32768) return false;
        buffer.resize((std::min)(buffer.size() * 2, size_t{32768}));
    }
}

bool ModuleDirectory(HMODULE module, std::wstring& directory) {
    if (!ModulePath(module, directory)) return false;
    const size_t slash = directory.find_last_of(L"\\/");
    if (slash == std::wstring::npos) return false;
    directory.resize(slash + 1);
    return true;
}

bool ProcessImagePath(HANDLE process, std::wstring& path) {
    std::vector<wchar_t> buffer(32768);
    DWORD length = static_cast<DWORD>(buffer.size());
    if (!QueryFullProcessImageNameW(process, 0, buffer.data(), &length) ||
        length == 0 || length >= buffer.size())
        return false;
    path.assign(buffer.data(), length);
    return true;
}

bool ProcessCreationTime(HANDLE process, ULONGLONG& creationTime) {
    FILETIME created = {};
    FILETIME exited = {};
    FILETIME kernel = {};
    FILETIME user = {};
    if (!GetProcessTimes(process, &created, &exited, &kernel, &user))
        return false;
    creationTime = (static_cast<ULONGLONG>(created.dwHighDateTime) << 32) |
                   created.dwLowDateTime;
    return creationTime != 0;
}

bool SameProcessArchitecture(HANDLE target, DWORD* error) {
    BOOL currentWow64 = FALSE;
    BOOL targetWow64 = FALSE;
    if (!IsWow64Process(GetCurrentProcess(), &currentWow64) ||
        !IsWow64Process(target, &targetWow64)) {
        DWORD queryError = GetLastError();
        if (queryError == ERROR_SUCCESS) queryError = ERROR_INVALID_DATA;
        if (error) *error = queryError;
        return false;
    }
    if (currentWow64 != targetWow64) {
        if (error) *error = ERROR_BAD_EXE_FORMAT;
        return false;
    }
    if (error) *error = ERROR_SUCCESS;
    return true;
}

bool WriteAll(HANDLE handle, std::string_view bytes) {
    size_t sent = 0;
    while (sent < bytes.size()) {
        DWORD written = 0;
        const DWORD chunk = static_cast<DWORD>(
            (std::min)(bytes.size() - sent, size_t{MAXDWORD}));
        if (!WriteFile(handle, bytes.data() + sent, chunk, &written, nullptr) ||
            written == 0)
            return false;
        sent += written;
    }
    return true;
}

bool CurrentUserSidString(std::wstring& sid) {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        return false;
    DWORD bytes = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &bytes);
    if (bytes == 0 || GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        CloseHandle(token);
        return false;
    }
    std::vector<BYTE> buffer(bytes);
    if (!GetTokenInformation(token, TokenUser, buffer.data(), bytes, &bytes)) {
        CloseHandle(token);
        return false;
    }
    CloseHandle(token);
    auto* user = reinterpret_cast<TOKEN_USER*>(buffer.data());
    LPWSTR text = nullptr;
    if (!ConvertSidToStringSidW(user->User.Sid, &text)) return false;
    sid.assign(text);
    LocalFree(text);
    return true;
}

bool CreateLocalUserSecurityDescriptor(PSECURITY_DESCRIPTOR* descriptor) {
    if (!descriptor) return false;
    *descriptor = nullptr;
    std::wstring userSid;
    if (!CurrentUserSidString(userSid)) return false;
    const std::wstring sddl =
        L"D:P(A;;GA;;;SY)(A;;GA;;;" + userSid + L")S:(ML;;NW;;;ME)";
    return ConvertStringSecurityDescriptorToSecurityDescriptorW(
               sddl.c_str(), SDDL_REVISION_1, descriptor, nullptr) != FALSE;
}

HANDLE CreateLocalUserNamedEvent(const wchar_t* name, BOOL manualReset,
                                 BOOL initialState) {
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!CreateLocalUserSecurityDescriptor(&descriptor)) return nullptr;
    SECURITY_ATTRIBUTES security = {sizeof(security), descriptor, FALSE};
    HANDLE event = CreateEventW(&security, manualReset, initialState, name);
    const DWORD error = GetLastError();
    LocalFree(descriptor);
    SetLastError(error);
    return event;
}

HANDLE CreateLocalUserNamedMutex(const wchar_t* name, BOOL initialOwner) {
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!CreateLocalUserSecurityDescriptor(&descriptor)) return nullptr;
    SECURITY_ATTRIBUTES security = {sizeof(security), descriptor, FALSE};
    HANDLE mutex = CreateMutexW(&security, initialOwner, name);
    const DWORD error = GetLastError();
    LocalFree(descriptor);
    SetLastError(error);
    return mutex;
}


} // namespace clip
