#include "i18n.h"
#include "dialog_i18n.h"
#include "dlgapi.h"
#include "app.h"
#include "resource.h"
#include "winutil.h"
#include <cwchar>
#include <string>

namespace clip {
namespace {

struct TargetDialogState {
    DWORD processId = 0;
};

bool ParsePid(HWND dialog, DWORD& processId) {
    wchar_t text[32] = {};
    GetDlgItemTextW(dialog, IDC_EDIT_TARGET_PID, text, _countof(text));
    if (text[0] == L'\0') return false;
    wchar_t* end = nullptr;
    const unsigned long long value = _wcstoui64(text, &end, 10);
    if (end == text || *end != L'\0' || value == 0 || value > MAXDWORD)
        return false;
    processId = static_cast<DWORD>(value);
    return processId != GetCurrentProcessId();
}

bool SameSession(DWORD processId) {
    DWORD currentSession = 0;
    DWORD targetSession = 0;
    return ProcessIdToSessionId(GetCurrentProcessId(), &currentSession) &&
           ProcessIdToSessionId(processId, &targetSession) &&
           currentSession == targetSession;
}

bool UpdateTargetPreview(HWND dialog, DWORD& processId) {
    std::wstring message;
    bool valid = false;
    DWORD parsedPid = 0;
    if (!ParsePid(dialog, parsedPid)) {
        message = UiText(TextId::EnterAValidPIDOtherThanThis);
    } else {
        HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
                                     FALSE, parsedPid);
        if (!process) {
            message = UiText(TextId::CouldNotOpenTheProcessCheckThe);
        } else {
            std::wstring actualPath;
            const bool running = WaitForSingleObject(process, 0) == WAIT_TIMEOUT;
            const bool pathKnown = ProcessImagePath(process, actualPath);
            if (!running) {
                message = UiText(TextId::TheTargetProcessHasExited);
            } else if (!pathKnown) {
                message = UiText(TextId::CouldNotReadTheTargetProcessPath);
            } else if (!SameSession(parsedPid)) {
                message = UiText(TextId::UnsupportedTheTargetIsNotInThe);
            } else if (!SameProcessArchitecture(process)) {
                message = UiText(TextId::UnsupportedTheTargetArchitectureDiffersUseThe);
            } else {
                const size_t slash = actualPath.find_last_of(L"\\/");
                const std::wstring processName =
                    slash == std::wstring::npos
                        ? actualPath
                        : actualPath.substr(slash + 1);
                message = UiText(TextId::Target) + processName + L"（PID " +
                          std::to_wstring(parsedPid) + L"）\r\n" + actualPath;
                valid = true;
                processId = parsedPid;
            }
            CloseHandle(process);
        }
    }
    SetDlgItemTextW(dialog, IDC_TARGET_PROCESS_INFO, message.c_str());
    EnableWindow(GetDlgItem(dialog, IDOK), valid ? TRUE : FALSE);
    return valid;
}

INT_PTR CALLBACK TargetProcessProc(HWND dialog, UINT message, WPARAM wParam,
                                   LPARAM lParam) {
    auto* state = reinterpret_cast<TargetDialogState*>(
        GetWindowLongPtrW(dialog, DWLP_USER));
    switch (message) {
    case WM_INITDIALOG:
        LocalizeDialog(dialog, IDD_TARGET_PROCESS);
        state = reinterpret_cast<TargetDialogState*>(lParam);
        SetWindowLongPtrW(dialog, DWLP_USER,
                          reinterpret_cast<LONG_PTR>(state));
        SendDlgItemMessageW(dialog, IDC_EDIT_TARGET_PID, EM_SETLIMITTEXT, 10, 0);
        if (state && state->processId != 0) {
            const std::wstring pid = std::to_wstring(state->processId);
            SetDlgItemTextW(dialog, IDC_EDIT_TARGET_PID, pid.c_str());
        }
        if (state) UpdateTargetPreview(dialog, state->processId);
        return TRUE;
    case WM_COMMAND:
        if (LOWORD(wParam) == IDC_EDIT_TARGET_PID &&
            HIWORD(wParam) == EN_CHANGE) {
            if (state) UpdateTargetPreview(dialog, state->processId);
            return TRUE;
        }
        if (LOWORD(wParam) == IDOK) {
            DWORD processId = 0;
            if (state && UpdateTargetPreview(dialog, processId)) {
                state->processId = processId;
                EndDialog(dialog, IDOK);
            }
            return TRUE;
        }
        if (LOWORD(wParam) == IDCANCEL) {
            EndDialog(dialog, IDCANCEL);
            return TRUE;
        }
        break;
    }
    return FALSE;
}

} // namespace

bool ShowTargetProcessDialog(HWND owner, DWORD& processId) {
    TargetDialogState state;
    state.processId = processId;
    const INT_PTR result = DialogBoxParamW(
        g_app.hInst, MAKEINTRESOURCEW(IDD_TARGET_PROCESS), owner,
        TargetProcessProc, reinterpret_cast<LPARAM>(&state));
    if (result != IDOK) return false;
    processId = state.processId;
    return true;
}

} // namespace clip
