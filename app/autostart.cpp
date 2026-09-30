#include "autostart.h"
#include "winutil.h"
#include <algorithm>
#include <cwctype>
#include <string>
#include <vector>

namespace clip {
namespace {

constexpr wchar_t kTaskName[] = L"ClipboardProtector";

bool DecodeOutput(const std::string& bytes, std::wstring& output) {
    // schtasks normally emits a BOM, but retain a conservative heuristic for
    // redirected UTF-16 output from older builds that omit it.
    if (bytes.size() >= 4 && bytes[1] == '\0' && bytes[3] == '\0') {
        size_t count = bytes.size() / 2;
        output.resize(count);
        for (size_t i = 0; i < count; ++i)
            output[i] = (wchar_t)((unsigned char)bytes[i * 2] |
                                  ((unsigned char)bytes[i * 2 + 1] << 8));
        return true;
    }
    if (bytes.size() >= 4 && bytes[0] == '\0' && bytes[2] == '\0') {
        size_t count = bytes.size() / 2;
        output.resize(count);
        for (size_t i = 0; i < count; ++i)
            output[i] = (wchar_t)(((unsigned char)bytes[i * 2] << 8) |
                                  (unsigned char)bytes[i * 2 + 1]);
        return true;
    }
    if (bytes.size() >= 2 &&
        (unsigned char)bytes[0] == 0xff && (unsigned char)bytes[1] == 0xfe) {
        size_t count = (bytes.size() - 2) / 2;
        output.resize(count);
        for (size_t i = 0; i < count; ++i) {
            output[i] = (wchar_t)((unsigned char)bytes[2 + i * 2] |
                                  ((unsigned char)bytes[3 + i * 2] << 8));
        }
        return true;
    }
    if (bytes.size() >= 2 &&
        (unsigned char)bytes[0] == 0xfe && (unsigned char)bytes[1] == 0xff) {
        size_t count = (bytes.size() - 2) / 2;
        output.resize(count);
        for (size_t i = 0; i < count; ++i) {
            output[i] = (wchar_t)(((unsigned char)bytes[2 + i * 2] << 8) |
                                  (unsigned char)bytes[3 + i * 2]);
        }
        return true;
    }
    UINT codePage = CP_OEMCP;
    size_t offset = 0;
    if (bytes.size() >= 3 && (unsigned char)bytes[0] == 0xef &&
        (unsigned char)bytes[1] == 0xbb && (unsigned char)bytes[2] == 0xbf) {
        codePage = CP_UTF8;
        offset = 3;
    } else if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                   bytes.data(), (int)bytes.size(), nullptr,
                                   0) > 0) {
        // schtasks normally uses the console code page, but XML output may be
        // UTF-8 without a BOM on newer Windows builds.
        codePage = CP_UTF8;
    }
    int chars = MultiByteToWideChar(codePage, 0, bytes.data() + offset,
                                    (int)(bytes.size() - offset), nullptr, 0);
    if (chars <= 0) return false;
    output.resize(chars);
    return MultiByteToWideChar(codePage, 0, bytes.data() + offset,
                               (int)(bytes.size() - offset), output.data(),
                               chars) == chars;
}

bool ContainsInsensitive(const std::wstring& text, const wchar_t* needle) {
    std::wstring lowered = text;
    std::transform(lowered.begin(), lowered.end(), lowered.begin(),
                   [](wchar_t c) { return (wchar_t)std::towlower(c); });
    std::wstring wanted = needle;
    std::transform(wanted.begin(), wanted.end(), wanted.begin(),
                   [](wchar_t c) { return (wchar_t)std::towlower(c); });
    return lowered.find(wanted) != std::wstring::npos;
}

bool RunSchtasks(const std::wstring& arguments, std::wstring* output = nullptr,
                 DWORD* exitCodeOut = nullptr) {
    wchar_t systemDir[MAX_PATH] = {};
    UINT length = GetSystemDirectoryW(systemDir, _countof(systemDir));
    if (length == 0 || length >= _countof(systemDir)) return false;

    std::wstring command = std::wstring(L"\"") + systemDir +
                           L"\\schtasks.exe\" " + arguments;
    std::vector<wchar_t> mutableCommand(command.begin(), command.end());
    mutableCommand.push_back(L'\0');

    STARTUPINFOW startup = {sizeof(startup)};
    SECURITY_ATTRIBUTES pipeSecurity = {sizeof(pipeSecurity), nullptr, TRUE};
    HANDLE readPipe = nullptr, writePipe = nullptr;
    if (output) {
        if (!CreatePipe(&readPipe, &writePipe, &pipeSecurity, 0)) return false;
        SetHandleInformation(readPipe, HANDLE_FLAG_INHERIT, 0);
        startup.dwFlags |= STARTF_USESTDHANDLES;
        startup.hStdOutput = writePipe;
        startup.hStdError = writePipe;
    }
    PROCESS_INFORMATION process = {};
    if (!CreateProcessW(nullptr, mutableCommand.data(), nullptr, nullptr,
                        output ? TRUE : FALSE,
                        CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process))
    {
        if (readPipe) CloseHandle(readPipe);
        if (writePipe) CloseHandle(writePipe);
        return false;
    }

    CloseHandle(process.hThread);
    if (writePipe) CloseHandle(writePipe);
    // Drain stdout while schtasks is running. Waiting first can deadlock when
    // XML output fills the inherited pipe buffer.
    std::string bytes;
    DWORD wait = WAIT_TIMEOUT;
    ULONGLONG deadline = GetTickCount64() + 10000;
    for (;;) {
        if (readPipe) {
            DWORD available = 0;
            if (PeekNamedPipe(readPipe, nullptr, 0, nullptr, &available,
                              nullptr) && available != 0) {
                char chunk[4096];
                DWORD got = 0;
                if (ReadFile(readPipe, chunk,
                             (std::min)(available, (DWORD)sizeof(chunk)),
                             &got, nullptr) && got != 0)
                    bytes.append(chunk, got);
            }
        }
        wait = WaitForSingleObject(process.hProcess, 10);
        if (wait == WAIT_OBJECT_0) break;
        if (GetTickCount64() >= deadline) {
            TerminateProcess(process.hProcess, ERROR_TIMEOUT);
            WaitForSingleObject(process.hProcess, 1000);
            wait = WAIT_TIMEOUT;
            break;
        }
    }
    // The process has closed its writer. Drain the remaining bytes without
    // blocking, then close the reader.
    if (readPipe) {
        for (;;) {
            DWORD available = 0;
            if (!PeekNamedPipe(readPipe, nullptr, 0, nullptr, &available,
                               nullptr) || available == 0)
                break;
            char chunk[4096];
            DWORD got = 0;
            if (!ReadFile(readPipe, chunk,
                          (std::min)(available, (DWORD)sizeof(chunk)), &got,
                          nullptr) || got == 0)
                break;
            bytes.append(chunk, got);
        }
        CloseHandle(readPipe);
    }
    DWORD exitCode = 1;
    if (wait == WAIT_OBJECT_0) GetExitCodeProcess(process.hProcess, &exitCode);
    CloseHandle(process.hProcess);
    if (exitCodeOut) *exitCodeOut = exitCode;
    if (output) DecodeOutput(bytes, *output);
    return wait == WAIT_OBJECT_0 && exitCode == 0;
}

bool ApplyAutostartState(bool enabled, AutostartState state) {
    if (!enabled) {
        if (state == AutostartState::Absent || state == AutostartState::Disabled)
            return true;
        return RunSchtasks(L"/Change /TN \"" + std::wstring(kTaskName) +
                           L"\" /DISABLE");
    }
    if (state == AutostartState::Enabled) return true;
    if (state == AutostartState::Disabled) {
        return RunSchtasks(L"/Change /TN \"" + std::wstring(kTaskName) +
                           L"\" /ENABLE");
    }

    std::wstring executable;
    if (!ModulePath(nullptr, executable)) return false;
    std::wstring taskCommand =
        L"/Create /TN \"" + std::wstring(kTaskName) +
        L"\" /TR \"\\\"" + executable +
        L"\\\"\" /SC ONLOGON /RL HIGHEST /F";
    return RunSchtasks(taskCommand);
}

} // namespace

bool EnableAutostart() {
    AutostartState state = AutostartState::Absent;
    return QueryAutostart(state) && ApplyAutostartState(true, state);
}

bool DisableAutostart() {
    AutostartState state = AutostartState::Absent;
    return QueryAutostart(state) && ApplyAutostartState(false, state);
}

bool RemoveAutostart() {
    AutostartState state = AutostartState::Absent;
    if (!QueryAutostart(state)) return false;
    if (state == AutostartState::Absent) return true;
    return RunSchtasks(L"/Delete /TN \"" + std::wstring(kTaskName) + L"\" /F");
}

bool SetAutostart(bool enabled) {
    AutostartState state = AutostartState::Absent;
    return QueryAutostart(state) && ApplyAutostartState(enabled, state);
}

bool SetAutostart(bool enabled, AutostartState currentState) {
    return ApplyAutostartState(enabled, currentState);
}

bool QueryAutostart(AutostartState& state) {
    std::wstring xml;
    DWORD exitCode = 1;
    if (!RunSchtasks(L"/Query /TN \"" + std::wstring(kTaskName) +
                     L"\" /XML", &xml, &exitCode)) {
        // A successful query with no task is the only expected nonzero exit;
        // access/launch/timeout failures must remain distinguishable.
        // schtasks has no stable Win32 error code for a missing named task;
        // require an explicit not-found phrase instead of treating every
        // exit code 1 (for example access denied) as Absent. Matching is
        // case-insensitive for English and accepts common Chinese output.
        if (exitCode != 1 ||
            (!ContainsInsensitive(xml, L"cannot find") &&
             !ContainsInsensitive(xml, L"not found") &&
             !ContainsInsensitive(xml, L"does not exist") &&
             !ContainsInsensitive(xml, L"找不到") &&
             !ContainsInsensitive(xml, L"不存在")))
            return false;
        state = AutostartState::Absent;
        return true;
    }
    size_t enabled = xml.find(L"<Enabled>");
    // Enabled is optional in the Task Scheduler schema and defaults to true.
    // schtasks omits it for newly-created enabled tasks on current Windows.
    if (enabled == std::wstring::npos) {
        state = AutostartState::Enabled;
        return true;
    }
    enabled += 9;
    size_t end = xml.find(L"</Enabled>", enabled);
    if (end == std::wstring::npos) return false;
    state = _wcsnicmp(xml.c_str() + enabled, L"true", 4) == 0
        ? AutostartState::Enabled : AutostartState::Disabled;
    return true;
}

} // namespace clip
