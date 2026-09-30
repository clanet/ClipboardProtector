#include <windows.h>
#include <commctrl.h>
#include <tlhelp32.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include "config.h"
#include "util.h"

namespace {

constexpr UINT kCommandSingleProcess = 3010;
constexpr UINT kCommandRules = 3001;
constexpr UINT kCommandSettings = 3004;
constexpr UINT kCommandGlobalProtection = 3008;
constexpr UINT kCommandExit = 3007;
constexpr UINT kCommandShortcutOnly = 3011;
constexpr UINT kShortcutOnlyHotkeyId = 1;
constexpr int kTargetPidEdit = 230;
constexpr int kLogList = 102;
constexpr int kRuleList = 210;
constexpr int kRuleAdd = 211;
constexpr int kRulePattern = 220;
constexpr int kRuleAction = 222;
constexpr int kRuleName = 224;
constexpr int kRuleFormat = 226;
constexpr int kRuleRegex = 227;
constexpr int kRuleSourceMode = 229;
constexpr int kRuleSourcePattern = 232;
constexpr int kRuleSample = 233;
constexpr int kRuleTest = 234;
constexpr int kRuleTestResult = 235;
constexpr int kRuleTimeout = 236;
constexpr int kRuleNotification = 238;
constexpr int kConfirmationPersistDecision = 4103;
constexpr int kConfirmationBlock = 4104;
constexpr wchar_t kConfirmationClass[] = L"ClipProtectorConfirmWnd";

struct ChildProcess {
    HANDLE process = nullptr;
    HANDLE input = nullptr;
    DWORD id = 0;
};

struct WindowSearch {
    DWORD processId = 0;
    const wchar_t* className = nullptr;
    const wchar_t* title = nullptr;
    HWND excluded = nullptr;
    HWND result = nullptr;
};

BOOL CALLBACK FindTopLevelWindow(HWND window, LPARAM parameter) {
    auto* search = reinterpret_cast<WindowSearch*>(parameter);
    DWORD processId = 0;
    GetWindowThreadProcessId(window, &processId);
    if (processId != search->processId || window == search->excluded) return TRUE;
    wchar_t className[128] = {};
    wchar_t title[256] = {};
    GetClassNameW(window, className, _countof(className));
    GetWindowTextW(window, title, _countof(title));
    // EnumWindows can see a dialog before its controls and WM_INITDIALOG have
    // completed. The main window may deliberately be hidden; editors/prompts
    // must be visible before the test treats them as interactive.
    if ((wcscmp(className, L"#32770") == 0 ||
         wcscmp(className, kConfirmationClass) == 0) && !IsWindowVisible(window))
        return TRUE;
    if ((!search->className || wcscmp(className, search->className) == 0) &&
        (!search->title || wcscmp(title, search->title) == 0)) {
        search->result = window;
        return FALSE;
    }
    return TRUE;
}

HWND FindProcessWindow(DWORD processId, const wchar_t* className,
                       const wchar_t* title = nullptr,
                       HWND excluded = nullptr) {
    WindowSearch search{processId, className, title, excluded, nullptr};
    EnumWindows(FindTopLevelWindow, reinterpret_cast<LPARAM>(&search));
    return search.result;
}

bool HasMessageWindow(DWORD processId) {
    HWND window = nullptr;
    for (;;) {
        window = FindWindowExW(HWND_MESSAGE, window, L"ClipClientTestWnd", nullptr);
        if (!window) return false;
        DWORD owner = 0;
        GetWindowThreadProcessId(window, &owner);
        if (owner == processId) return true;
    }
}

bool WaitUntil(bool (*predicate)(void*), void* context, DWORD timeoutMs) {
    const ULONGLONG deadline = GetTickCount64() + timeoutMs;
    do {
        if (predicate(context)) return true;
        Sleep(20);
    } while (GetTickCount64() < deadline);
    return predicate(context);
}

struct ProcessWindowWait {
    DWORD processId = 0;
    const wchar_t* className = nullptr;
    const wchar_t* title = nullptr;
    HWND excluded = nullptr;
    HWND result = nullptr;
};

bool ProcessWindowReady(void* raw) {
    auto* wait = static_cast<ProcessWindowWait*>(raw);
    wait->result = FindProcessWindow(wait->processId, wait->className,
                                     wait->title, wait->excluded);
    return wait->result != nullptr;
}

bool WindowGone(void* raw) {
    return !IsWindow(*static_cast<HWND*>(raw));
}

struct ConfirmationWindows {
    DWORD processId = 0;
    std::vector<HWND> windows;
};

BOOL CALLBACK CollectConfirmationWindows(HWND window, LPARAM parameter) {
    auto* result = reinterpret_cast<ConfirmationWindows*>(parameter);
    DWORD processId = 0;
    GetWindowThreadProcessId(window, &processId);
    if (processId != result->processId) return TRUE;
    wchar_t className[128] = {};
    GetClassNameW(window, className, _countof(className));
    if (wcscmp(className, kConfirmationClass) == 0 && IsWindowVisible(window))
        result->windows.push_back(window);
    return TRUE;
}

bool ConfirmationCountReached(void* raw) {
    auto* result = static_cast<ConfirmationWindows*>(raw);
    result->windows.clear();
    EnumWindows(CollectConfirmationWindows, reinterpret_cast<LPARAM>(result));
    return result->windows.size() >= 2;
}

bool ClickConfirmation(HWND window, bool allow, bool persistDecision) {
    if (!window || !IsWindow(window)) return false;
    // EnumWindows can observe the top-level window while Create() is still
    // returning to ShowPendingConfirmations. Let the UI register ownership
    // before simulating a click that no human could issue this quickly.
    Sleep(150);
    if (!IsWindow(window)) return false;
    HWND checkbox = nullptr;
    HWND button = nullptr;
    const ULONGLONG deadline = GetTickCount64() + 2000;
    do {
        checkbox = GetDlgItem(window, kConfirmationPersistDecision);
        button = GetDlgItem(window, allow ? IDOK : kConfirmationBlock);
        if (checkbox && button && IsWindowEnabled(button)) break;
        Sleep(10);
    } while (IsWindow(window) && GetTickCount64() < deadline);
    if (!checkbox || !button || !IsWindowEnabled(button)) return false;
    if (persistDecision)
        SendMessageW(checkbox, BM_SETCHECK, BST_CHECKED, 0);
    // BM_CLICK may be ignored for an inactive dialog. Deliver the same button
    // notification without depending on foreground activation on the desktop.
    if (!PostMessageW(window, WM_COMMAND,
            MAKEWPARAM(allow ? IDOK : kConfirmationBlock, BN_CLICKED),
            reinterpret_cast<LPARAM>(button))) return false;
    return WaitUntil(WindowGone, &window, 3000);
}

bool MessageWindowReady(void* raw) {
    return HasMessageWindow(*static_cast<DWORD*>(raw));
}

bool ProcessExited(void* raw) {
    HANDLE process = *static_cast<HANDLE*>(raw);
    return process && WaitForSingleObject(process, 0) == WAIT_OBJECT_0;
}

bool LaunchClient(const std::wstring& path, ChildProcess& child) {
    SECURITY_ATTRIBUTES security{sizeof(security), nullptr, TRUE};
    HANDLE inputRead = nullptr;
    HANDLE inputWrite = nullptr;
    if (!CreatePipe(&inputRead, &inputWrite, &security, 0)) return false;
    SetHandleInformation(inputWrite, HANDLE_FLAG_INHERIT, 0);
    HANDLE nullOutput = CreateFileW(L"NUL", GENERIC_WRITE,
                                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                                    &security, OPEN_EXISTING, 0, nullptr);
    if (nullOutput == INVALID_HANDLE_VALUE) {
        CloseHandle(inputRead);
        CloseHandle(inputWrite);
        return false;
    }

    std::wstring command = L"\"" + path + L"\" console";
    STARTUPINFOW startup{sizeof(startup)};
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = inputRead;
    startup.hStdOutput = nullOutput;
    startup.hStdError = nullOutput;
    PROCESS_INFORMATION process = {};
    const BOOL created = CreateProcessW(
        path.c_str(), command.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW,
        nullptr, nullptr, &startup, &process);
    CloseHandle(inputRead);
    CloseHandle(nullOutput);
    if (!created) {
        CloseHandle(inputWrite);
        return false;
    }
    CloseHandle(process.hThread);
    child.process = process.hProcess;
    child.input = inputWrite;
    child.id = process.dwProcessId;
    return true;
}

bool LaunchApplication(const std::wstring& path, ChildProcess& child) {
    std::wstring command = L"\"" + path + L"\"";
    STARTUPINFOW startup{sizeof(startup)};
    PROCESS_INFORMATION process = {};
    if (!CreateProcessW(path.c_str(), command.data(), nullptr, nullptr, FALSE, 0,
                        nullptr, nullptr, &startup, &process))
        return false;
    CloseHandle(process.hThread);
    child.process = process.hProcess;
    child.id = process.dwProcessId;
    return true;
}

bool SendClientCommand(HANDLE input, const char* command) {
    const DWORD length = static_cast<DWORD>(strlen(command));
    DWORD written = 0;
    return WriteFile(input, command, length, &written, nullptr) &&
           written == length;
}

bool HasModule(DWORD processId, const wchar_t* name) {
    HANDLE snapshot = CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
    if (snapshot == INVALID_HANDLE_VALUE) return false;
    MODULEENTRY32W entry{sizeof(entry)};
    bool found = false;
    if (Module32FirstW(snapshot, &entry)) {
        do {
            if (_wcsicmp(entry.szModule, name) == 0) {
                found = true;
                break;
            }
        } while (Module32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return found;
}

struct ModuleWait {
    DWORD processId = 0;
    const wchar_t* name = nullptr;
};

bool ModuleLoaded(void* raw) {
    auto* wait = static_cast<ModuleWait*>(raw);
    return HasModule(wait->processId, wait->name);
}

bool ModuleUnloaded(void* raw) {
    auto* wait = static_cast<ModuleWait*>(raw);
    return !HasModule(wait->processId, wait->name);
}

struct TargetMenuWait {
    HWND mainWindow = nullptr;
    bool checked = false;
};

bool TargetMenuStateReached(void* raw) {
    auto* wait = static_cast<TargetMenuWait*>(raw);
    HMENU root = GetMenu(wait->mainWindow);
    HMENU protection = root ? GetSubMenu(root, 0) : nullptr;
    HMENU options = root ? GetSubMenu(root, 2) : nullptr;
    if (!protection || !options) return false;
    const UINT missing = static_cast<UINT>(-1);
    // Single-process protection remains a development command, but no longer
    // has a menu item. The normal protection toggle is disabled in that mode.
    if (GetMenuState(protection, kCommandSingleProcess, MF_BYCOMMAND) != missing)
        return false;
    const UINT settings = GetMenuState(options, kCommandSettings, MF_BYCOMMAND);
    const UINT global = GetMenuState(protection, kCommandGlobalProtection, MF_BYCOMMAND);
    // Both menus are disabled during a pending operation; wait for it to
    // finish before interpreting the disabled protection toggle as readiness.
    if (settings == missing || global == missing ||
        (settings & (MF_GRAYED | MF_DISABLED)) || (global & MF_CHECKED))
        return false;
    return ((global & (MF_GRAYED | MF_DISABLED)) != 0) == wait->checked;
}

struct ShortcutMenuWait {
    HWND mainWindow = nullptr;
    bool checked = false;
};

bool ShortcutMenuStateReached(void* raw) {
    auto* wait = static_cast<ShortcutMenuWait*>(raw);
    HMENU root = GetMenu(wait->mainWindow);
    HMENU options = root ? GetSubMenu(root, 2) : nullptr;
    if (!options) return false;
    const UINT state = GetMenuState(options, kCommandShortcutOnly,
                                    MF_BYCOMMAND);
    if (state == static_cast<UINT>(-1)) return false;
    return ((state & MF_CHECKED) != 0) == wait->checked;
}

bool ValidateShortcutModeToggle(HWND mainWindow) {
    if (!PostMessageW(mainWindow, WM_HOTKEY, kShortcutOnlyHotkeyId,
                      MAKELPARAM(MOD_CONTROL | MOD_ALT, VK_F9)))
        return false;
    ShortcutMenuWait enabled{mainWindow, true};
    if (!WaitUntil(ShortcutMenuStateReached, &enabled, 3000)) return false;
    if (!PostMessageW(mainWindow, WM_COMMAND, kCommandShortcutOnly, 0))
        return false;
    ShortcutMenuWait disabled{mainWindow, false};
    return WaitUntil(ShortcutMenuStateReached, &disabled, 3000);
}

struct RowWait {
    HWND list = nullptr;
    int minimum = 0;
};

bool RowCountReached(void* raw) {
    auto* wait = static_cast<RowWait*>(raw);
    return static_cast<int>(SendMessageW(wait->list, LVM_GETITEMCOUNT, 0, 0)) >=
           wait->minimum;
}

bool ReadListText(HWND list, int row, int column, wchar_t* text,
                  size_t capacity) {
    DWORD processId = 0;
    GetWindowThreadProcessId(list, &processId);
    if (!processId || !text || capacity == 0 || capacity > INT_MAX) return false;

    HANDLE process = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ |
                                     PROCESS_VM_WRITE,
                                 FALSE, processId);
    if (!process) return false;

    const SIZE_T textBytes = capacity * sizeof(wchar_t);
    const SIZE_T allocationBytes = sizeof(LVITEMW) + textBytes;
    auto* remote = static_cast<BYTE*>(
        VirtualAllocEx(process, nullptr, allocationBytes,
                       MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    bool ok = false;
    if (remote) {
        LVITEMW item = {};
        item.iSubItem = column;
        item.pszText = reinterpret_cast<LPWSTR>(remote + sizeof(item));
        item.cchTextMax = static_cast<int>(capacity);
        SIZE_T written = 0;
        if (WriteProcessMemory(process, remote, &item, sizeof(item), &written) &&
            written == sizeof(item)) {
            DWORD_PTR copied = 0;
            if (SendMessageTimeoutW(list, LVM_GETITEMTEXT,
                                    static_cast<WPARAM>(row),
                                    reinterpret_cast<LPARAM>(remote),
                                    SMTO_ABORTIFHUNG, 2000, &copied) && copied > 0) {
                SIZE_T read = 0;
                ok = ReadProcessMemory(process, remote + sizeof(item), text,
                                       textBytes, &read) &&
                     read == textBytes && text[0] != L'\0';
            }
        }
        VirtualFreeEx(process, remote, 0, MEM_RELEASE);
    }
    CloseHandle(process);
    return ok;
}

bool RowsPopulated(HWND list, int previousCount) {
    const int count =
        static_cast<int>(SendMessageW(list, LVM_GETITEMCOUNT, 0, 0));
    const int newRows = count - previousCount;
    if (newRows <= 0) return false;
    for (int row = 0; row < newRows; ++row) {
        wchar_t timeText[64] = {};
        if (!ReadListText(list, row, 0, timeText, _countof(timeText)))
            return false;
    }
    return true;
}

bool RowTextEquals(HWND list, int row, int column, const wchar_t* expected) {
    wchar_t text[256] = {};
    return ReadListText(list, row, column, text, _countof(text)) &&
           wcscmp(text, expected) == 0;
}

bool NewRowsContain(HWND list, int previousCount, int column,
                    const wchar_t* expected) {
    const int count =
        static_cast<int>(SendMessageW(list, LVM_GETITEMCOUNT, 0, 0));
    const int newRows = count - previousCount;
    for (int row = 0; row < newRows; ++row) {
        if (RowTextEquals(list, row, column, expected)) return true;
    }
    return false;
}

struct RowContentWait {
    HWND list = nullptr;
    int first = 0;
    int column = 0;
    const wchar_t* expected = nullptr;
};

bool RowContentReached(void* raw) {
    auto* wait = static_cast<RowContentWait*>(raw);
    return NewRowsContain(wait->list, wait->first, wait->column,
                          wait->expected);
}

void DumpRows(HWND list) {
    const int count =
        static_cast<int>(SendMessageW(list, LVM_GETITEMCOUNT, 0, 0));
    for (int row = 0; row < count; ++row) {
        fwprintf(stderr, L"row[%d]", row);
        for (int column = 0; column < 14; ++column) {
            wchar_t value[256] = {};
            if (ReadListText(list, row, column, value, _countof(value)))
                fwprintf(stderr, L" c%d=%ls", column, value);
        }
        fwprintf(stderr, L"\n");
    }
}

bool SendCommandForNewRow(HANDLE input, HWND list, const char* command,
                          int* firstNewRow = nullptr) {
    const int before =
        static_cast<int>(SendMessageW(list, LVM_GETITEMCOUNT, 0, 0));
    if (firstNewRow) *firstNewRow = before;
    for (int attempt = 0; attempt < 3; ++attempt) {
        Sleep(150);
        if (!SendClientCommand(input, command)) return false;
        RowWait rows{list, before + 1};
        if (WaitUntil(RowCountReached, &rows, 1000)) {
            Sleep(200);
            return RowsPopulated(list, before);
        }
    }
    return false;
}

bool SendCommandForPrompt(HANDLE input, ProcessWindowWait& prompt) {
    for (int attempt = 0; attempt < 3; ++attempt) {
        prompt.result = nullptr;
        if (!SendClientCommand(input, "r\r\n")) return false;
        if (WaitUntil(ProcessWindowReady, &prompt, 2000)) return true;
        Sleep(150);
    }
    return false;
}

// 让测试进程持有剪贴板：owner 为空时被保护进程读到的来源未知，
// 传入自己创建的窗口时来源会被解析成测试进程（其它已知进程）。
bool SetForeignClipboardText(HWND owner, const std::wstring& text) {
    const size_t bytes = (text.size() + 1) * sizeof(wchar_t);
    // 剪贴板可能被其它进程短暂占用，与本文件其它等待一致的有限重试。
    for (int attempt = 0; attempt < 3; ++attempt) {
        if (!OpenClipboard(owner)) {
            Sleep(100);
            continue;
        }
        bool ok = false;
        if (EmptyClipboard()) {
            HGLOBAL memory = GlobalAlloc(GMEM_MOVEABLE, bytes);
            void* data = memory ? GlobalLock(memory) : nullptr;
            if (data) {
                memcpy(data, text.c_str(), bytes);
                GlobalUnlock(memory);
                if (SetClipboardData(CF_UNICODETEXT, memory)) {
                    memory = nullptr;  // 所有权已交给剪贴板
                    ok = true;
                }
            }
            if (memory) GlobalFree(memory);
        }
        CloseClipboard();
        if (ok) return true;
        Sleep(100);
    }
    return false;
}

// 消息窗口只用于持有剪贴板，让来源可解析为测试进程自己。
HWND ForeignClipboardOwner() {
    static HWND owner = CreateWindowExW(0, L"STATIC", L"", 0, 0, 0, 0, 0,
                                        HWND_MESSAGE, nullptr, nullptr, nullptr);
    return owner;
}

std::wstring LowercasedModuleName() {
    wchar_t path[32768] = {};
    const DWORD length = GetModuleFileNameW(nullptr, path, _countof(path));
    if (length == 0 || length >= _countof(path)) return {};
    const std::wstring full(path, length);
    const size_t slash = full.find_last_of(L"\\/");
    return clip::ToLower(slash == std::wstring::npos ? full
                                                     : full.substr(slash + 1));
}

bool StartSingleProcess(HWND mainWindow, DWORD appProcessId,
                        DWORD targetProcessId) {
    if (!PostMessageW(mainWindow, WM_COMMAND, kCommandSingleProcess, 0)) {
        fwprintf(stderr, L"single-process command post failed: %lu\n",
                 GetLastError());
        return false;
    }
    ProcessWindowWait dialogWait{appProcessId, L"#32770", L"单进程保护"};
    if (!WaitUntil(ProcessWindowReady, &dialogWait, 5000)) {
        fwprintf(stderr, L"target dialog did not open\n");
        return false;
    }
    const HWND dialog = dialogWait.result;
    HWND edit = nullptr;
    HWND ok = nullptr;
    const ULONGLONG controlsDeadline = GetTickCount64() + 2000;
    do {
        edit = GetDlgItem(dialog, kTargetPidEdit);
        ok = GetDlgItem(dialog, IDOK);
        if (!edit || !ok) Sleep(10);
    } while ((!edit || !ok) && GetTickCount64() < controlsDeadline);
    if (!edit || !ok) {
        fwprintf(stderr, L"target dialog controls missing\n");
        return false;
    }
    const std::wstring pid = std::to_wstring(targetProcessId);
    SendMessageW(edit, WM_SETTEXT, 0, reinterpret_cast<LPARAM>(pid.c_str()));
    SendMessageW(dialog, WM_COMMAND, MAKEWPARAM(kTargetPidEdit, EN_CHANGE),
                 reinterpret_cast<LPARAM>(edit));
    if (!IsWindowEnabled(ok)) {
        wchar_t preview[1024] = {};
        GetDlgItemTextW(dialog, 231, preview, _countof(preview));
        fwprintf(stderr, L"target rejected: %ls\n", preview);
        return false;
    }
    SendMessageW(dialog, WM_COMMAND, MAKEWPARAM(IDOK, BN_CLICKED),
                 reinterpret_cast<LPARAM>(ok));

    TargetMenuWait active{mainWindow, true};
    if (!WaitUntil(TargetMenuStateReached, &active, 10000)) {
        fwprintf(stderr, L"target did not become active\n");
        return false;
    }
    return FindProcessWindow(appProcessId, L"#32770", L"单进程保护",
                             dialog) == nullptr;
}

bool SetComboAndNotify(HWND dialog, int id, int selection) {
    HWND combo = GetDlgItem(dialog, id);
    if (!combo || SendMessageW(combo, CB_SETCURSEL, selection, 0) == CB_ERR)
        return false;
    SendMessageW(dialog, WM_COMMAND, MAKEWPARAM(id, CBN_SELCHANGE),
                 reinterpret_cast<LPARAM>(combo));
    return true;
}

bool ValidateRuleEditor(HWND mainWindow, DWORD appProcessId) {
    if (!PostMessageW(mainWindow, WM_COMMAND, kCommandRules, 0)) return false;
    ProcessWindowWait rulesWait{appProcessId, L"#32770",
                                L"剪贴板访问规则"};
    if (!WaitUntil(ProcessWindowReady, &rulesWait, 5000)) return false;
    HWND rules = rulesWait.result;
    HWND list = nullptr;
    HWND header = nullptr;
    bool columnsReady = false;
    const ULONGLONG columnsDeadline = GetTickCount64() + 2000;
    do {
        list = GetDlgItem(rules, kRuleList);
        header = list ? reinterpret_cast<HWND>(
                            SendMessageW(list, LVM_GETHEADER, 0, 0))
                      : nullptr;
        columnsReady = list && header &&
            SendMessageW(header, HDM_GETITEMCOUNT, 0, 0) == 10;
        if (!columnsReady) Sleep(10);
    } while (!columnsReady && GetTickCount64() < columnsDeadline);
    if (!columnsReady ||
        !PostMessageW(rules, WM_COMMAND, MAKEWPARAM(kRuleAdd, BN_CLICKED),
                      reinterpret_cast<LPARAM>(GetDlgItem(rules, kRuleAdd)))) {
        fwprintf(stderr, L"rule list did not initialize\n");
        PostMessageW(rules, WM_COMMAND, IDCANCEL, 0);
        return false;
    }

    ProcessWindowWait editWait{appProcessId, L"#32770", L"编辑规则", rules};
    if (!WaitUntil(ProcessWindowReady, &editWait, 5000)) {
        PostMessageW(rules, WM_COMMAND, IDCANCEL, 0);
        return false;
    }
    HWND edit = editWait.result;
    const int required[] = {
        kRulePattern, kRuleAction, kRuleName, kRuleRegex,
        kRuleFormat, kRuleSourceMode, kRuleSourcePattern, kRuleSample,
        kRuleTest, kRuleTestResult, kRuleTimeout, kRuleNotification,
    };
    bool controlsReady = false;
    const ULONGLONG controlsDeadline = GetTickCount64() + 2000;
    do {
        controlsReady = true;
        for (int id : required)
            controlsReady = controlsReady && GetDlgItem(edit, id);
        controlsReady = controlsReady &&
            SendDlgItemMessageW(edit, kRuleSourceMode, CB_GETCOUNT, 0, 0) == 6 &&
            SendDlgItemMessageW(edit, kRuleAction, CB_GETCOUNT, 0, 0) == 3 &&
            SendDlgItemMessageW(edit, kRuleFormat, CB_GETCOUNT, 0, 0) == 5 &&
            SendDlgItemMessageW(edit, kRuleNotification, CB_GETCOUNT, 0, 0) == 2;
        if (!controlsReady) Sleep(10);
    } while (!controlsReady && GetTickCount64() < controlsDeadline);

    const bool sourceEnabled = controlsReady &&
        SetComboAndNotify(edit, kRuleSourceMode, 1) &&
        IsWindowEnabled(GetDlgItem(edit, kRuleSourcePattern));
    const bool timeoutEnabled = controlsReady &&
        SetComboAndNotify(edit, kRuleAction, 2) &&
        IsWindowEnabled(GetDlgItem(edit, kRuleTimeout));
    const bool notificationSelectable = controlsReady &&
        SetComboAndNotify(edit, kRuleNotification, 1) &&
        SendDlgItemMessageW(edit, kRuleNotification, CB_GETCURSEL, 0, 0) == 1;
    const bool nonTextDisablesContent = controlsReady &&
        SetComboAndNotify(edit, kRuleFormat, 1) &&
        !IsWindowEnabled(GetDlgItem(edit, kRuleRegex)) &&
        !IsWindowEnabled(GetDlgItem(edit, kRuleSample)) &&
        !IsWindowEnabled(GetDlgItem(edit, kRuleTest));
    const bool textEnablesContent = controlsReady &&
        SetComboAndNotify(edit, kRuleFormat, 2) &&
        IsWindowEnabled(GetDlgItem(edit, kRuleRegex)) &&
        IsWindowEnabled(GetDlgItem(edit, kRuleSample)) &&
        IsWindowEnabled(GetDlgItem(edit, kRuleTest));
    bool regexWorks = false;
    if (controlsReady) {
        SetDlgItemTextW(edit, kRuleRegex, L"secret-[0-9]+");
        SetDlgItemTextW(edit, kRuleSample, L"prefix SECRET-42 suffix");
        SendMessageW(edit, WM_COMMAND, MAKEWPARAM(kRuleTest, BN_CLICKED),
                     reinterpret_cast<LPARAM>(GetDlgItem(edit, kRuleTest)));
        wchar_t result[64] = {};
        GetDlgItemTextW(edit, kRuleTestResult, result, _countof(result));
        regexWorks = wcscmp(result, L"匹配") == 0;
    }
    PostMessageW(edit, WM_COMMAND, IDCANCEL, 0);
    const bool editClosed = WaitUntil(WindowGone, &edit, 2000);
    PostMessageW(rules, WM_COMMAND, IDCANCEL, 0);
    const bool rulesClosed = WaitUntil(WindowGone, &rules, 2000);
    if (!controlsReady || !sourceEnabled || !timeoutEnabled ||
        !notificationSelectable || !nonTextDisablesContent ||
        !textEnablesContent || !regexWorks ||
        !editClosed || !rulesClosed) {
        fwprintf(stderr,
                 L"rule editor controls=%d source=%d timeout=%d notify=%d "
                 L"nontext=%d text=%d regex=%d "
                 L"edit-closed=%d rules-closed=%d\n",
                 controlsReady, sourceEnabled, timeoutEnabled,
                 notificationSelectable, nonTextDisablesContent,
                 textEnablesContent, regexWorks,
                 editClosed, rulesClosed);
    }
    return controlsReady && sourceEnabled && timeoutEnabled &&
           notificationSelectable && nonTextDisablesContent &&
           textEnablesContent && regexWorks && editClosed && rulesClosed;
}

bool ChangeAndAcceptRules(HWND rules, DWORD appProcessId) {
    if (!rules ||
        !PostMessageW(rules, WM_COMMAND, MAKEWPARAM(kRuleAdd, BN_CLICKED),
                      reinterpret_cast<LPARAM>(GetDlgItem(rules, kRuleAdd)))) {
        fwprintf(stderr, L"merge-test add-post failed\n");
        return false;
    }
    ProcessWindowWait editWait{appProcessId, L"#32770", L"编辑规则", rules};
    if (!WaitUntil(ProcessWindowReady, &editWait, 5000)) {
        fwprintf(stderr, L"merge-test edit did not open\n");
        return false;
    }
    HWND edit = editWait.result;
    HWND ok = nullptr;
    const ULONGLONG controlsDeadline = GetTickCount64() + 2000;
    do {
        ok = GetDlgItem(edit, IDOK);
        if (!ok) Sleep(10);
    } while (!ok && GetTickCount64() < controlsDeadline);
    if (!ok) {
        fwprintf(stderr, L"merge-test edit OK missing\n");
        return false;
    }
    SendMessageW(edit, WM_COMMAND, MAKEWPARAM(IDOK, BN_CLICKED),
                 reinterpret_cast<LPARAM>(ok));
    if (!WaitUntil(WindowGone, &edit, 2000)) {
        fwprintf(stderr, L"merge-test edit did not close\n");
        return false;
    }
    PostMessageW(rules, WM_COMMAND, IDOK, 0);
    if (!WaitUntil(WindowGone, &rules, 3000)) {
        fwprintf(stderr, L"merge-test rules did not close\n");
        return false;
    }
    return true;
}

std::wstring TempRoot() {
    std::vector<wchar_t> directory(32768);
    DWORD length = GetTempPathW(static_cast<DWORD>(directory.size()),
                                directory.data());
    if (length == 0 || length >= directory.size()) return {};
    return std::wstring(directory.data(), length) +
           L"ClipboardProtector-product-smoke-" +
           std::to_wstring(GetCurrentProcessId());
}

void CloseChild(ChildProcess& child) {
    if (child.input) {
        CloseHandle(child.input);
        child.input = nullptr;
    }
    if (child.process) {
        CloseHandle(child.process);
        child.process = nullptr;
    }
}

bool WriteResultFile(const wchar_t* path, const std::string& result) {
    HANDLE file = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    DWORD written = 0;
    const bool ok = WriteFile(file, result.data(),
                              static_cast<DWORD>(result.size()), &written,
                              nullptr) &&
                    written == result.size();
    CloseHandle(file);
    return ok;
}

int RunExistingClientSmoke(const wchar_t* appPath, DWORD clientId,
                           const wchar_t* resultPath) {
    const std::wstring tempRoot = TempRoot();
    if (tempRoot.empty() ||
        (!CreateDirectoryW(tempRoot.c_str(), nullptr) &&
         GetLastError() != ERROR_ALREADY_EXISTS)) {
        WriteResultFile(resultPath, "temp-root=0\n");
        return 3;
    }

    std::vector<wchar_t> oldLocalAppData(32768);
    DWORD oldLength = GetEnvironmentVariableW(
        L"APPDATA", oldLocalAppData.data(),
        static_cast<DWORD>(oldLocalAppData.size()));
    const bool hadLocalAppData =
        oldLength > 0 && oldLength < oldLocalAppData.size();
    SetEnvironmentVariableW(L"APPDATA", tempRoot.c_str());
    const std::wstring configDir = tempRoot + L"\\ClipboardProtector";
    SetEnvironmentVariableW(L"CLIP_TEST_CONFIG_DIR", configDir.c_str());
    SetEnvironmentVariableW(L"CLIPBOARDPROTECTOR_ENABLE_GLOBAL_HOOK", nullptr);
    SetEnvironmentVariableW(L"CLIPBOARDPROTECTOR_TEST_TARGET_PID", nullptr);

    HANDLE target = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
                                FALSE, clientId);
    ChildProcess app;
    HWND mainWindow = nullptr;
    bool clientReady = target &&
        WaitForSingleObject(target, 0) == WAIT_TIMEOUT &&
        WaitUntil(MessageWindowReady, &clientId, 3000);
    bool started = false;
    bool moduleLoaded = false;
    bool eventsReceived = false;
    bool stopped = false;
    bool restarted = false;
    bool secondEventsReceived = false;
    bool stoppedAgain = false;
    bool moduleUnloaded = false;
    bool moduleUnloadedAgain = false;
    bool cleanExit = false;

    if (clientReady && LaunchApplication(appPath, app)) {
        ProcessWindowWait mainWait{app.id, L"ClipProtectorMainWnd"};
        if (WaitUntil(ProcessWindowReady, &mainWait, 5000)) {
            mainWindow = mainWait.result;
            started = StartSingleProcess(mainWindow, app.id, clientId);
        }
    }
    if (started) {
        ModuleWait moduleWait{clientId, L"HookDll.dll"};
        moduleLoaded = WaitUntil(ModuleLoaded, &moduleWait, 3000);
        if (moduleLoaded) {
            const std::wstring readyPath =
                std::wstring(resultPath) + L".ready";
            WriteResultFile(readyPath.c_str(), "ready\n");
        }
        HWND list = GetDlgItem(mainWindow, kLogList);
        if (moduleLoaded && list) {
            // The medium-integrity parent sends w/r while this elevated helper
            // waits. The final repeated GetClipboardData must create another
            // row instead of incrementing an earlier row's count.
            RowWait rows{list, 4};
            eventsReceived = WaitUntil(RowCountReached, &rows, 60000);
            if (eventsReceived) eventsReceived = RowsPopulated(list, 0);
        }
        PostMessageW(mainWindow, WM_COMMAND, kCommandSingleProcess, 0);
        TargetMenuWait inactive{mainWindow, false};
        stopped = WaitUntil(TargetMenuStateReached, &inactive, 8000);
        moduleUnloaded = WaitUntil(ModuleUnloaded, &moduleWait, 5000);
        if (stopped && moduleUnloaded)
            restarted = StartSingleProcess(mainWindow, app.id, clientId);
        if (restarted && list) {
            const int before = static_cast<int>(
                SendMessageW(list, LVM_GETITEMCOUNT, 0, 0));
            const std::wstring readyAgainPath =
                std::wstring(resultPath) + L".ready2";
            WriteResultFile(readyAgainPath.c_str(), "ready\n");
            RowWait secondRows{list, before + 1};
            secondEventsReceived =
                WaitUntil(RowCountReached, &secondRows, 60000);
            if (secondEventsReceived)
                secondEventsReceived = RowsPopulated(list, before);
            PostMessageW(mainWindow, WM_COMMAND, kCommandSingleProcess, 0);
            TargetMenuWait inactiveAgain{mainWindow, false};
            stoppedAgain =
                WaitUntil(TargetMenuStateReached, &inactiveAgain, 8000);
            if (stoppedAgain)
                moduleUnloadedAgain =
                    WaitUntil(ModuleUnloaded, &moduleWait, 5000);
        }
    }

    if (mainWindow) PostMessageW(mainWindow, WM_COMMAND, kCommandExit, 0);
    if (app.process) WaitForSingleObject(app.process, 8000);
    cleanExit = !app.process ||
                WaitForSingleObject(app.process, 0) == WAIT_OBJECT_0;
    if (app.process && !cleanExit) TerminateProcess(app.process, 21);
    CloseChild(app);
    if (target) CloseHandle(target);

    if (hadLocalAppData)
        SetEnvironmentVariableW(L"APPDATA", oldLocalAppData.data());
    else
        SetEnvironmentVariableW(L"APPDATA", nullptr);
    SetEnvironmentVariableW(L"CLIP_TEST_CONFIG_DIR", nullptr);
    DeleteFileW((configDir + L"\\config.json").c_str());
    RemoveDirectoryW(configDir.c_str());
    RemoveDirectoryW(tempRoot.c_str());

    char result[256] = {};
    sprintf_s(result,
              "client-ready=%d started=%d module=%d events=%d stopped=%d "
              "restarted=%d second-events=%d stopped-again=%d unloaded=%d "
              "unloaded-again=%d clean-exit=%d\n",
              clientReady, started, moduleLoaded, eventsReceived, stopped,
              restarted, secondEventsReceived, stoppedAgain, moduleUnloaded,
              moduleUnloadedAgain, cleanExit);
    WriteResultFile(resultPath, result);
    return clientReady && started && moduleLoaded && eventsReceived && stopped &&
                   moduleUnloaded && restarted && secondEventsReceived &&
                   stoppedAgain && moduleUnloadedAgain && cleanExit
               ? 0
               : 4;
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc == 5 && wcscmp(argv[1], L"--existing-client") == 0) {
        wchar_t* end = nullptr;
        const unsigned long parsed = wcstoul(argv[3], &end, 10);
        if (end == argv[3] || *end != L'\0' || parsed == 0)
            return 2;
        return RunExistingClientSmoke(argv[2], static_cast<DWORD>(parsed),
                                      argv[4]);
    }
    if (argc != 3) {
        fwprintf(stderr,
                 L"usage: productsingleprocesssmoke <ClipboardProtector> "
                 L"<clipclient>\n");
        return 2;
    }

    const std::wstring tempRoot = TempRoot();
    if (tempRoot.empty() ||
        (!CreateDirectoryW(tempRoot.c_str(), nullptr) &&
         GetLastError() != ERROR_ALREADY_EXISTS)) {
        fwprintf(stderr, L"temporary config root failed: %lu\n", GetLastError());
        return 3;
    }
    std::vector<wchar_t> oldLocalAppData(32768);
    DWORD oldLength = GetEnvironmentVariableW(
        L"APPDATA", oldLocalAppData.data(),
        static_cast<DWORD>(oldLocalAppData.size()));
    const bool hadLocalAppData = oldLength > 0 && oldLength < oldLocalAppData.size();
    SetEnvironmentVariableW(L"APPDATA", tempRoot.c_str());
    SetEnvironmentVariableW(L"CLIPBOARDPROTECTOR_ENABLE_GLOBAL_HOOK", nullptr);
    SetEnvironmentVariableW(L"CLIPBOARDPROTECTOR_TEST_TARGET_PID", nullptr);
    const std::wstring objectSuffix = std::to_wstring(GetCurrentProcessId());
    const std::wstring pipeName =
        L"\\\\.\\pipe\\ClipboardProtector.ProductSmoke." + objectSuffix;
    const std::wstring stopName =
        L"Local\\ClipboardProtector.ProductSmoke.Stop." + objectSuffix;
    const std::wstring mutexName =
        L"Local\\ClipboardProtector.ProductSmoke.Mutex." + objectSuffix;
    const std::wstring sourceMapName =
        L"Local\\ClipboardProtector.ProductSmoke.Source." + objectSuffix;
    const std::wstring cryptoMapName =
        L"Local\\ClipboardProtector.ProductSmoke.Crypto." + objectSuffix;
    SetEnvironmentVariableW(L"CLIP_TEST_PIPE_NAME", pipeName.c_str());
    SetEnvironmentVariableW(L"CLIP_TEST_STOP_EVENT", stopName.c_str());
    SetEnvironmentVariableW(L"CLIP_TEST_CONTROLLER_MUTEX", mutexName.c_str());
    SetEnvironmentVariableW(L"CLIP_TEST_SOURCE_MAP", sourceMapName.c_str());
    SetEnvironmentVariableW(L"CLIP_TEST_CRYPTO_MAP", cryptoMapName.c_str());
    std::wstring serverPath = argv[1];
    for (wchar_t& ch : serverPath) {
        if (ch == L'/') ch = L'\\';
    }
    SetEnvironmentVariableW(L"CLIP_TEST_SERVER_PATH", serverPath.c_str());
    wchar_t clientFullPath[32768] = {};
    const DWORD clientPathLength = GetFullPathNameW(
        argv[2], _countof(clientFullPath), clientFullPath, nullptr);
    std::wstring expectedClientPath =
        clientPathLength > 0 && clientPathLength < _countof(clientFullPath)
            ? std::wstring(clientFullPath, clientPathLength)
            : std::wstring(argv[2]);
    for (wchar_t& ch : expectedClientPath) {
        if (ch == L'/') ch = L'\\';
    }

    const std::wstring configDir = tempRoot + L"\\ClipboardProtector";
    SetEnvironmentVariableW(L"CLIP_TEST_CONFIG_DIR", configDir.c_str());
    const bool configDirReady =
        CreateDirectoryW(configDir.c_str(), nullptr) ||
        GetLastError() == ERROR_ALREADY_EXISTS;
    const std::string configJson =
        "{\"ruleModelVersion\":4,\"settings\":{"
        "\"balloonNotificationsDisabled\":true,\"shortcutOnlyMode\":false,"
        "\"maxLogEntries\":5000,"
        "\"previewEnabled\":true,\"autostart\":false,"
        "\"startGlobalProtection\":false,\"startMinimized\":true},"
        "\"rules\":[{"
        "\"name\":\"regex-write-block\","
        "\"pattern\":\"clipclient.exe\",\"isPath\":false,"
        "\"action\":3,\"showNotification\":true,\"operations\":2,\"format\":2,"
        "\"contentRegex\":\"blocked-secret-[0-9]+\","
        "\"ignoreCase\":true,\"enabled\":true,"
        "\"sourceMode\":0,\"sourcePattern\":\"\","
        "\"confirmTimeoutMs\":15000,\"timeoutBlock\":true},{"
        "\"name\":\"source-confirm-block\","
        "\"pattern\":\"clipclient.exe\",\"isPath\":false,"
        "\"action\":2,\"showNotification\":false,\"operations\":1,\"format\":2,"
        "\"contentRegex\":\"confirm-content-[0-9]+\","
        "\"ignoreCase\":true,\"enabled\":true,"
        "\"sourceMode\":3,\"sourcePattern\":\"\","
        "\"confirmTimeoutMs\":15000,\"timeoutBlock\":true},{"
        "\"name\":\"concurrent-confirm\","
        "\"pattern\":\"clipclient.exe\",\"isPath\":false,"
        "\"action\":2,\"showNotification\":false,\"operations\":1,\"format\":1,"
        "\"contentRegex\":\"\",\"ignoreCase\":true,\"enabled\":true,"
        "\"sourceMode\":0,\"sourcePattern\":\"\","
        "\"confirmTimeoutMs\":15000,\"timeoutBlock\":true},{"
        "\"name\":\"foreign-source-confirm\","
        "\"pattern\":\"clipclient.exe\",\"isPath\":false,"
        "\"action\":2,\"showNotification\":false,\"operations\":1,\"format\":2,"
        "\"contentRegex\":\"foreign-source-block\","
        "\"ignoreCase\":true,\"enabled\":true,"
        "\"sourceMode\":0,\"sourcePattern\":\"\","
        "\"confirmTimeoutMs\":15000,\"timeoutBlock\":true}]}";
    const bool configWritten =
        configDirReady &&
        WriteResultFile((configDir + L"\\config.json").c_str(), configJson);

    ChildProcess client;
    ChildProcess app;
    HWND mainWindow = nullptr;
    bool startupMinimized = false;
    bool shortcutToggleValid = false;
    bool ruleUiValid = false;
    bool started = false;
    bool moduleLoaded = false;
    bool writeEvents = false;
    bool regexBlockedWrite = false;
    bool longTextBlockedWrite = false;
    bool readSourceTracked = false;
    bool confirmBlockedRead = false;
    bool concurrentConfirmations = false;
    bool alwaysAllowRule = false;
    bool postAlwaysNoPrompt = false;
    bool alwaysBlockRule = false;
    bool postBlockNoPrompt = false;
    bool alwaysBlockNameRule = false;
    bool userRulesIntact = false;
    bool postNamedSourceNoPrompt = false;
    bool readEvent = false;
    bool repeatedReadEvent = false;
    bool stopped = false;
    bool moduleUnloaded = false;
    bool restarted = false;
    bool secondReadEvent = false;
    bool stoppedAgain = false;
    bool moduleUnloadedAgain = false;
    bool cleanExit = false;
    bool legacyStarted = false;
    bool legacyEvent = false;
    bool legacyStopped = false;
    bool legacyUnloaded = false;
    bool legacyCleanExit = false;

    SetEnvironmentVariableW(L"CLIP_TEST_CONFIRM_RESPONSE", nullptr);
    const bool clientLaunched = LaunchClient(argv[2], client);
    const bool clientReady =
        clientLaunched && WaitUntil(MessageWindowReady, &client.id, 3000);
    if (configWritten && clientReady && LaunchApplication(argv[1], app)) {
        ProcessWindowWait mainWait{app.id, L"ClipProtectorMainWnd"};
        if (WaitUntil(ProcessWindowReady, &mainWait, 5000)) {
            mainWindow = mainWait.result;
            startupMinimized = !IsWindowVisible(mainWindow);
            shortcutToggleValid = startupMinimized &&
                ValidateShortcutModeToggle(mainWindow);
            if (shortcutToggleValid)
                ruleUiValid = ValidateRuleEditor(mainWindow, app.id);
            if (ruleUiValid)
                started = StartSingleProcess(mainWindow, app.id, client.id);
        }
    }

    if (started) {
        ModuleWait moduleWait{client.id, L"HookDll.dll"};
        moduleLoaded = WaitUntil(ModuleLoaded, &moduleWait, 2000);
        HWND list = GetDlgItem(mainWindow, kLogList);
        if (moduleLoaded && list)
            writeEvents = SendCommandForNewRow(
                client.input, list,
                "w clipboardprotector-product-smoke\r\n");
        if (writeEvents) {
            int readFirst = 0;
            readEvent = SendCommandForNewRow(client.input, list, "r\r\n",
                                             &readFirst);
            readSourceTracked = readEvent &&
                NewRowsContain(list, readFirst, 3, L"clipclient.exe") &&
                NewRowsContain(list, readFirst, 4,
                               std::to_wstring(client.id).c_str());
        }
        if (readEvent) {
            int blockedFirst = 0;
            const bool blockedRow = SendCommandForNewRow(
                client.input, list, "w blocked-secret-123\r\n", &blockedFirst);
            regexBlockedWrite = blockedRow &&
                NewRowsContain(list, blockedFirst, 7, L"regex-write-block") &&
                NewRowsContain(list, blockedFirst, 8, L"阻止") &&
                NewRowsContain(list, blockedFirst, 9, L"右下角通知") &&
                NewRowsContain(list, blockedFirst, 11, L"已阻止");
            if (!regexBlockedWrite || !readSourceTracked) DumpRows(list);
        }
        if (regexBlockedWrite) {
            std::string longWrite = "w ";
            longWrite.append(5000, 'x');
            longWrite += "blocked-secret-999\r\n";
            int longFirst = 0;
            const bool longRow = SendCommandForNewRow(
                client.input, list, longWrite.c_str(), &longFirst);
            longTextBlockedWrite = longRow &&
                NewRowsContain(list, longFirst, 7, L"regex-write-block") &&
                NewRowsContain(list, longFirst, 11, L"已阻止");
        }
        if (longTextBlockedWrite) {
            const int pairFirst = static_cast<int>(
                SendMessageW(list, LVM_GETITEMCOUNT, 0, 0));
            ConfirmationWindows pairWindows{app.id};
            const bool pairSent = SendClientCommand(client.input, "rr\r\n");
            const bool pairShown = pairSent &&
                WaitUntil(ConfirmationCountReached, &pairWindows, 4000);
            bool pairClosed = pairShown && IsWindowEnabled(mainWindow);
            if (pairShown) {
                const std::vector<HWND> windows = pairWindows.windows;
                for (HWND window : windows)
                    pairClosed = ClickConfirmation(window, false, false) &&
                                 pairClosed;
            }
            RowWait pairRows{list, pairFirst + 2};
            concurrentConfirmations = pairClosed &&
                WaitUntil(RowCountReached, &pairRows, 4000) &&
                RowsPopulated(list, pairFirst);

            const int confirmWriteFirst = static_cast<int>(
                SendMessageW(list, LVM_GETITEMCOUNT, 0, 0));
            RowContentWait confirmWriteRow{
                list, confirmWriteFirst, 10, L"confirm-content-456"};
            const bool confirmWrite =
                SendClientCommand(client.input,
                                  "w confirm-content-456\r\n") &&
                WaitUntil(RowContentReached, &confirmWriteRow, 4000);
            const int confirmFirst = static_cast<int>(
                SendMessageW(list, LVM_GETITEMCOUNT, 0, 0));
            ProcessWindowWait blockPrompt{app.id, kConfirmationClass};
            const bool blockShown = confirmWrite &&
                SendCommandForPrompt(client.input, blockPrompt);
            const bool blockClosed = blockShown &&
                IsWindowEnabled(mainWindow) &&
                ClickConfirmation(blockPrompt.result, false, false);
            RowWait confirmRows{list, confirmFirst + 1};
            repeatedReadEvent = blockClosed &&
                WaitUntil(RowCountReached, &confirmRows, 4000) &&
                RowsPopulated(list, confirmFirst);
            RowContentWait confirmRow{list, confirmFirst, 7,
                                      L"source-confirm-block"};
            confirmBlockedRead = repeatedReadEvent &&
                WaitUntil(RowContentReached, &confirmRow, 3000) &&
                NewRowsContain(list, confirmFirst, 8, L"每次询问") &&
                NewRowsContain(list, confirmFirst, 9, L"静默") &&
                NewRowsContain(list, confirmFirst, 11, L"已阻止");
            if (!confirmBlockedRead) {
                fwprintf(stderr,
                         L"confirm-flow write=%d shown=%d main-enabled=%d "
                         L"closed=%d repeated=%d\n",
                         confirmWrite, blockShown,
                         IsWindowEnabled(mainWindow), blockClosed,
                         repeatedReadEvent);
                DumpRows(list);
            }

            const int alwaysFirst = static_cast<int>(
                SendMessageW(list, LVM_GETITEMCOUNT, 0, 0));
            ProcessWindowWait allowPrompt{app.id, kConfirmationClass};
            const bool allowShown = confirmBlockedRead &&
                SendCommandForPrompt(client.input, allowPrompt);
            ProcessWindowWait openRules{app.id, L"#32770",
                                        L"剪贴板访问规则"};
            const bool rulesShown = allowShown &&
                PostMessageW(mainWindow, WM_COMMAND, kCommandRules, 0) &&
                WaitUntil(ProcessWindowReady, &openRules, 4000);
            const bool allowClosed = rulesShown &&
                IsWindowEnabled(allowPrompt.result) &&
                ClickConfirmation(allowPrompt.result, true, true);
            const bool rulesMerged = allowClosed &&
                ChangeAndAcceptRules(openRules.result, app.id);
            RowWait alwaysRows{list, alwaysFirst + 1};
            const bool allowRow = rulesMerged &&
                WaitUntil(RowCountReached, &alwaysRows, 4000) &&
                RowsPopulated(list, alwaysFirst);
            clip::Config savedConfig;
            const bool configReloaded = allowRow &&
                savedConfig.Load(configDir + L"\\config.json");
            // “一直这样”按访问进程加来源进程写入规则：目标进程读取的是它自己
            // 写入的剪贴板，所以来源条件是“与访问进程相同”。
            const std::wstring expectedClientName = expectedClientPath.substr(
                expectedClientPath.find_last_of(L"\\/") + 1);
            const std::wstring expectedAllowRuleName =
                std::wstring(L"始终放行：") + expectedClientName + L"（同进程）";
            alwaysAllowRule = configReloaded && !savedConfig.rules.empty() &&
                _wcsicmp(savedConfig.rules[0].pattern.c_str(),
                         expectedClientName.c_str()) == 0 &&
                !savedConfig.rules[0].isPath &&
                savedConfig.rules[0].action == clip::kRuleAllow &&
                savedConfig.rules[0].sourceMode == clip::kSourceSameProcess &&
                savedConfig.rules[0].sourcePattern.empty() &&
                savedConfig.rules[0].name == expectedAllowRuleName;
            if (!alwaysAllowRule) {
                fwprintf(stderr,
                         L"always-allow rules-shown=%d allow-shown=%d "
                         L"allow-closed=%d rules-merged=%d row=%d reload=%d "
                         L"rule-count=%zu\n",
                         rulesShown, allowShown, allowClosed, rulesMerged,
                         allowRow, configReloaded, savedConfig.rules.size());
            }

            const bool postAlwaysRead = alwaysAllowRule &&
                SendCommandForNewRow(client.input, list, "r\r\n");
            Sleep(300);
            postAlwaysNoPrompt = postAlwaysRead &&
                FindProcessWindow(app.id, kConfirmationClass) == nullptr;

            // 同一个“一直这样”复选框在阻止方向也必须落成规则，并且记录
            // 这次实际观察到的来源（测试进程持有剪贴板，因此来源未知）。
            const int foreignFirst = static_cast<int>(
                SendMessageW(list, LVM_GETITEMCOUNT, 0, 0));
            const bool foreignWritten = SetForeignClipboardText(
                nullptr, L"foreign-source-block-1");
            ProcessWindowWait blockPersistPrompt{app.id, kConfirmationClass};
            const bool blockPersistShown = foreignWritten &&
                SendCommandForPrompt(client.input, blockPersistPrompt);
            const bool blockPersistClosed = blockPersistShown &&
                ClickConfirmation(blockPersistPrompt.result, false, true);
            RowWait blockPersistRows{list, foreignFirst + 1};
            const bool blockPersistRow = blockPersistClosed &&
                WaitUntil(RowCountReached, &blockPersistRows, 4000) &&
                NewRowsContain(list, foreignFirst, 7,
                               L"foreign-source-confirm") &&
                NewRowsContain(list, foreignFirst, 8, L"每次询问") &&
                NewRowsContain(list, foreignFirst, 11, L"已阻止");

            clip::Config blockedConfig;
            const bool blockedConfigReloaded = blockPersistRow &&
                blockedConfig.Load(configDir + L"\\config.json");
            alwaysBlockRule = blockedConfigReloaded &&
                !blockedConfig.rules.empty() &&
                _wcsicmp(blockedConfig.rules[0].pattern.c_str(),
                         expectedClientName.c_str()) == 0 &&
                !blockedConfig.rules[0].isPath &&
                blockedConfig.rules[0].action == clip::kRuleBlock &&
                blockedConfig.rules[0].sourceMode == clip::kSourceUnknown &&
                blockedConfig.rules[0].sourcePattern.empty() &&
                blockedConfig.rules[0].name.rfind(L"始终阻止：", 0) == 0;
            if (!alwaysBlockRule) {
                fwprintf(stderr,
                         L"always-block written=%d shown=%d closed=%d row=%d "
                         L"reload=%d rule-count=%zu\n",
                         foreignWritten, blockPersistShown, blockPersistClosed,
                         blockPersistRow, blockedConfigReloaded,
                         blockedConfig.rules.size());
            }

            const std::wstring expectedBlockRuleName =
                std::wstring(L"始终阻止：") + expectedClientName +
                L"（来源未知）";
            const int blockedAgainFirst = static_cast<int>(
                SendMessageW(list, LVM_GETITEMCOUNT, 0, 0));
            const bool blockedAgain = alwaysBlockRule &&
                SendCommandForNewRow(client.input, list, "r\r\n");
            RowWait blockedAgainRows{list, blockedAgainFirst + 1};
            postBlockNoPrompt = blockedAgain &&
                WaitUntil(RowCountReached, &blockedAgainRows, 3000) &&
                NewRowsContain(list, blockedAgainFirst, 7,
                               expectedBlockRuleName.c_str()) &&
                NewRowsContain(list, blockedAgainFirst, 11, L"已阻止") &&
                FindProcessWindow(app.id, kConfirmationClass) == nullptr;

            // 来源是其它已知进程时，来源条件必须退化成“按来源进程名”。
            const std::wstring expectedSourceName = LowercasedModuleName();
            const int namedSourceFirst = static_cast<int>(
                SendMessageW(list, LVM_GETITEMCOUNT, 0, 0));
            const bool namedSourceWritten = !expectedSourceName.empty() &&
                SetForeignClipboardText(ForeignClipboardOwner(),
                                        L"foreign-source-block-2");
            ProcessWindowWait namedSourcePrompt{app.id, kConfirmationClass};
            const bool namedSourceShown = namedSourceWritten &&
                SendCommandForPrompt(client.input, namedSourcePrompt);
            const bool namedSourceClosed = namedSourceShown &&
                ClickConfirmation(namedSourcePrompt.result, false, true);
            RowWait namedSourceRows{list, namedSourceFirst + 1};
            const bool namedSourceRow = namedSourceClosed &&
                WaitUntil(RowCountReached, &namedSourceRows, 4000) &&
                NewRowsContain(list, namedSourceFirst, 7,
                               L"foreign-source-confirm") &&
                NewRowsContain(list, namedSourceFirst, 11, L"已阻止");

            clip::Config namedConfig;
            const bool namedConfigReloaded = namedSourceRow &&
                namedConfig.Load(configDir + L"\\config.json");
            const std::wstring expectedNamedRuleName =
                std::wstring(L"始终阻止：") + expectedClientName +
                L"（来源：" + expectedSourceName + L"）";
            alwaysBlockNameRule = namedConfigReloaded &&
                !namedConfig.rules.empty() &&
                _wcsicmp(namedConfig.rules[0].pattern.c_str(),
                         expectedClientName.c_str()) == 0 &&
                namedConfig.rules[0].action == clip::kRuleBlock &&
                namedConfig.rules[0].sourceMode == clip::kSourceName &&
                namedConfig.rules[0].sourcePattern == expectedSourceName &&
                namedConfig.rules[0].name == expectedNamedRuleName;

            // 自动规则只应在列表最前插入或改写自己，不得改动用户手写规则。
            const struct {
                const wchar_t* name;
                int action;
            } expectedUserRules[] = {
                {L"regex-write-block", clip::kRuleBlock},
                {L"source-confirm-block", clip::kRuleConfirm},
                {L"concurrent-confirm", clip::kRuleConfirm},
                {L"foreign-source-confirm", clip::kRuleConfirm},
            };
            userRulesIntact = namedConfigReloaded;
            for (const auto& expected : expectedUserRules) {
                bool present = false;
                for (const clip::Rule& rule : namedConfig.rules) {
                    if (rule.name == expected.name &&
                        rule.action == expected.action) {
                        present = true;
                        break;
                    }
                }
                userRulesIntact = userRulesIntact && present;
            }
            if (!alwaysBlockNameRule) {
                fwprintf(stderr,
                         L"named-source written=%d shown=%d closed=%d row=%d "
                         L"reload=%d rule-count=%zu source-name=%ls\n",
                         namedSourceWritten, namedSourceShown,
                         namedSourceClosed, namedSourceRow, namedConfigReloaded,
                         namedConfig.rules.size(), expectedSourceName.c_str());
            }

            const int namedAgainFirst = static_cast<int>(
                SendMessageW(list, LVM_GETITEMCOUNT, 0, 0));
            const bool namedAgain = alwaysBlockNameRule &&
                SendCommandForNewRow(client.input, list, "r\r\n");
            RowWait namedAgainRows{list, namedAgainFirst + 1};
            postNamedSourceNoPrompt = namedAgain &&
                WaitUntil(RowCountReached, &namedAgainRows, 3000) &&
                NewRowsContain(list, namedAgainFirst, 7,
                               expectedNamedRuleName.c_str()) &&
                NewRowsContain(list, namedAgainFirst, 11, L"已阻止") &&
                FindProcessWindow(app.id, kConfirmationClass) == nullptr;
        }
        PostMessageW(mainWindow, WM_COMMAND, kCommandSingleProcess, 0);
        TargetMenuWait inactive{mainWindow, false};
        stopped = WaitUntil(TargetMenuStateReached, &inactive, 8000);
        if (stopped)
            moduleUnloaded = WaitUntil(ModuleUnloaded, &moduleWait, 5000);
        if (stopped && moduleUnloaded)
            restarted = StartSingleProcess(mainWindow, app.id, client.id);
        if (restarted && list) {
            secondReadEvent =
                SendCommandForNewRow(client.input, list, "r\r\n");
            PostMessageW(mainWindow, WM_COMMAND, kCommandSingleProcess, 0);
            TargetMenuWait inactiveAgain{mainWindow, false};
            stoppedAgain =
                WaitUntil(TargetMenuStateReached, &inactiveAgain, 8000);
            if (stoppedAgain)
                moduleUnloadedAgain =
                    WaitUntil(ModuleUnloaded, &moduleWait, 5000);
        }
    }

    if (client.input) SendClientCommand(client.input, "q\r\n");
    if (client.process) WaitForSingleObject(client.process, 5000);
    if (mainWindow) PostMessageW(mainWindow, WM_COMMAND, kCommandExit, 0);
    if (app.process) WaitForSingleObject(app.process, 8000);
    cleanExit = (!client.process ||
                 WaitForSingleObject(client.process, 0) == WAIT_OBJECT_0) &&
                (!app.process ||
                 WaitForSingleObject(app.process, 0) == WAIT_OBJECT_0);

    if (client.process && WaitForSingleObject(client.process, 0) != WAIT_OBJECT_0)
        TerminateProcess(client.process, 20);
    if (app.process && WaitForSingleObject(app.process, 0) != WAIT_OBJECT_0)
        TerminateProcess(app.process, 21);
    CloseChild(client);
    CloseChild(app);

    // A no-ACK client models the original v1 DLL. It must receive only the
    // legacy rule layout and remain usable when all configured rules can be
    // represented by that layout.
    const std::string legacyConfigJson =
        "{\"ruleModelVersion\":4,\"settings\":{"
        "\"balloonNotificationsDisabled\":true,\"shortcutOnlyMode\":false,"
        "\"maxLogEntries\":5000,"
        "\"previewEnabled\":true,\"autostart\":false},\"rules\":[]}";
    ChildProcess legacyClient;
    ChildProcess legacyApp;
    HWND legacyWindow = nullptr;
    if (cleanExit &&
        WriteResultFile((configDir + L"\\config.json").c_str(),
                        legacyConfigJson)) {
        SetEnvironmentVariableW(L"CLIP_TEST_SUPPRESS_STATE_ACK", L"1");
        const bool launched = LaunchClient(argv[2], legacyClient);
        SetEnvironmentVariableW(L"CLIP_TEST_SUPPRESS_STATE_ACK", nullptr);
        const bool ready = launched &&
            WaitUntil(MessageWindowReady, &legacyClient.id, 3000);
        if (ready && LaunchApplication(argv[1], legacyApp)) {
            ProcessWindowWait wait{legacyApp.id, L"ClipProtectorMainWnd"};
            if (WaitUntil(ProcessWindowReady, &wait, 5000)) {
                legacyWindow = wait.result;
                legacyStarted = StartSingleProcess(
                    legacyWindow, legacyApp.id, legacyClient.id);
            }
        }
        if (legacyStarted) {
            HWND list = GetDlgItem(legacyWindow, kLogList);
            legacyEvent = list && SendCommandForNewRow(
                legacyClient.input, list, "w legacy-compatible\r\n");
            PostMessageW(legacyWindow, WM_COMMAND, kCommandSingleProcess, 0);
            TargetMenuWait inactive{legacyWindow, false};
            legacyStopped = WaitUntil(TargetMenuStateReached, &inactive, 8000);
            ModuleWait moduleWait{legacyClient.id, L"HookDll.dll"};
            if (legacyStopped)
                legacyUnloaded =
                    WaitUntil(ModuleUnloaded, &moduleWait, 5000);
        }
    }
    if (legacyClient.input) SendClientCommand(legacyClient.input, "q\r\n");
    if (legacyClient.process)
        WaitForSingleObject(legacyClient.process, 5000);
    if (legacyWindow)
        PostMessageW(legacyWindow, WM_COMMAND, kCommandExit, 0);
    if (legacyApp.process) WaitForSingleObject(legacyApp.process, 8000);
    legacyCleanExit =
        (!legacyClient.process ||
         WaitForSingleObject(legacyClient.process, 0) == WAIT_OBJECT_0) &&
        (!legacyApp.process ||
         WaitForSingleObject(legacyApp.process, 0) == WAIT_OBJECT_0);
    if (legacyClient.process &&
        WaitForSingleObject(legacyClient.process, 0) != WAIT_OBJECT_0)
        TerminateProcess(legacyClient.process, 22);
    if (legacyApp.process &&
        WaitForSingleObject(legacyApp.process, 0) != WAIT_OBJECT_0)
        TerminateProcess(legacyApp.process, 23);
    CloseChild(legacyClient);
    CloseChild(legacyApp);

    if (hadLocalAppData)
        SetEnvironmentVariableW(L"APPDATA", oldLocalAppData.data());
    else
        SetEnvironmentVariableW(L"APPDATA", nullptr);
    SetEnvironmentVariableW(L"CLIP_TEST_PIPE_NAME", nullptr);
    SetEnvironmentVariableW(L"CLIP_TEST_STOP_EVENT", nullptr);
    SetEnvironmentVariableW(L"CLIP_TEST_CONTROLLER_MUTEX", nullptr);
    SetEnvironmentVariableW(L"CLIP_TEST_SOURCE_MAP", nullptr);
    SetEnvironmentVariableW(L"CLIP_TEST_CRYPTO_MAP", nullptr);
    SetEnvironmentVariableW(L"CLIP_TEST_SERVER_PATH", nullptr);
    SetEnvironmentVariableW(L"CLIP_TEST_CONFIG_DIR", nullptr);
    SetEnvironmentVariableW(L"CLIP_TEST_CONFIRM_RESPONSE", nullptr);

    DeleteFileW((configDir + L"\\config.json").c_str());
    RemoveDirectoryW(configDir.c_str());
    RemoveDirectoryW(tempRoot.c_str());

    if (!startupMinimized || !shortcutToggleValid || !ruleUiValid ||
        !started || !moduleLoaded ||
        !writeEvents || !readEvent ||
        !regexBlockedWrite || !longTextBlockedWrite || !readSourceTracked ||
        !concurrentConfirmations || !confirmBlockedRead ||
        !repeatedReadEvent || !alwaysAllowRule || !postAlwaysNoPrompt ||
        !alwaysBlockRule || !postBlockNoPrompt ||
        !alwaysBlockNameRule || !userRulesIntact || !postNamedSourceNoPrompt ||
        !stopped || !moduleUnloaded || !restarted ||
        !secondReadEvent || !stoppedAgain || !moduleUnloadedAgain ||
        !cleanExit || !legacyStarted || !legacyEvent || !legacyStopped ||
        !legacyUnloaded || !legacyCleanExit) {
        fwprintf(stderr,
                  L"startup-minimized=%d shortcut-toggle=%d rule-ui=%d "
                  L"started=%d module=%d "
                  L"write-events=%d read-event=%d "
                  L"regex-block=%d long-block=%d source=%d concurrent=%d "
                  L"confirm-block=%d repeated-read=%d always-allow=%d "
                  L"no-prompt=%d always-block=%d block-no-prompt=%d "
                  L"named-source-block=%d user-rules-intact=%d "
                  L"named-source-no-prompt=%d "
                  L"stopped=%d unloaded=%d restarted=%d second-read=%d "
                  L"stopped-again=%d unloaded-again=%d clean-exit=%d "
                  L"legacy-started=%d legacy-event=%d legacy-stopped=%d "
                  L"legacy-unloaded=%d legacy-clean=%d\n",
                  startupMinimized, shortcutToggleValid, ruleUiValid,
                  started, moduleLoaded,
                  writeEvents, readEvent,
                  regexBlockedWrite, longTextBlockedWrite, readSourceTracked,
                  concurrentConfirmations, confirmBlockedRead,
                  repeatedReadEvent, alwaysAllowRule, postAlwaysNoPrompt,
                  alwaysBlockRule, postBlockNoPrompt,
                  alwaysBlockNameRule, userRulesIntact, postNamedSourceNoPrompt,
                  stopped, moduleUnloaded, restarted,
                 secondReadEvent, stoppedAgain, moduleUnloadedAgain, cleanExit,
                 legacyStarted, legacyEvent, legacyStopped, legacyUnloaded,
                 legacyCleanExit);
        return 4;
    }
    wprintf(L"capability-handshake=1 extended-rules=1 product-menu=1 "
            L"startup-minimized=1 "
            L"shortcut-toggle=1 rule-ui=1 "
            L"write-events=1 regex-content-block=1 long-content-block=1 source-process=1 "
            L"modeless-confirm=1 concurrent-confirm=1 confirm-block=1 "
            L"always-allow-rule=1 always-block-rule=1 block-no-prompt=1 "
            L"named-source-rule=1 user-rules-intact=1 named-source-no-prompt=1 "
             L"read-events=2 individual-rows=1 unload=1 reinjection=1 "
             L"second-read=1 unload-again=1 legacy-v1=1 legacy-unload=1 "
             L"no-state-ack-compat=1 clean-exit=1\n");
    return 0;
}
