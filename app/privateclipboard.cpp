#include "i18n.h"
#include "privateclipboard.h"
#include "../common/privateclip.h"
#include "../common/winutil.h"
#include <ole2.h>
#include <UIAutomation.h>
#include <wrl/client.h>
#include <algorithm>

namespace clip {
namespace {
HWND FocusWindow(HWND foreground) {
    GUITHREADINFO info = {sizeof(info)};
    const DWORD thread = GetWindowThreadProcessId(foreground, nullptr);
    return thread && GetGUIThreadInfo(thread, &info) ? info.hwndFocus : nullptr;
}
bool SameTarget(HWND foreground, HWND focus) {
    return IsWindow(foreground) && IsWindow(focus) &&
        GetForegroundWindow() == foreground && FocusWindow(foreground) == focus;
}
bool ModifiersDown() {
    for (int key : {VK_CONTROL, VK_MENU, VK_SHIFT, VK_LWIN, VK_RWIN})
        if (GetAsyncKeyState(key) & 0x8000) return true;
    return false;
}
struct InputGuard;
thread_local InputGuard* currentInputGuard = nullptr;
struct InputGuard {
    HWND foreground, focus;
    DWORD tag;
    const std::atomic<bool>& cancelled;
    HHOOK hook = nullptr;
    bool blocked = false, controlDown = false, actionDown = false;
    InputGuard(HWND window, HWND editor, DWORD marker, const std::atomic<bool>& cancel)
        : foreground(window), focus(editor), tag(marker), cancelled(cancel) {
        currentInputGuard = this;
        hook = SetWindowsHookExW(WH_KEYBOARD_LL, Keyboard, GetModuleHandleW(nullptr), 0);
    }
    ~InputGuard() {
        if (hook) UnhookWindowsHookEx(hook);
        currentInputGuard = nullptr;
    }
    static LRESULT CALLBACK Keyboard(int code, WPARAM message, LPARAM parameter) {
        InputGuard* guard = currentInputGuard;
        const auto* key = reinterpret_cast<KBDLLHOOKSTRUCT*>(parameter);
        if (code >= 0 && guard && key && (key->flags & LLKHF_INJECTED) &&
            static_cast<DWORD>(key->dwExtraInfo) == guard->tag) {
            const bool up = (key->flags & LLKHF_UP) != 0;
            bool& down = key->vkCode == VK_LCONTROL || key->vkCode == VK_RCONTROL ||
                key->vkCode == VK_CONTROL ? guard->controlDown : guard->actionDown;
            if (up) {
                // Release only keys this batch actually pressed, even if focus
                // changed afterwards. Never leave synthetic Control held down.
                if (!down) return 1;
                down = false;
            } else {
                if (guard->blocked || guard->cancelled.load() ||
                    !SameTarget(guard->foreground, guard->focus)) {
                    guard->blocked = true;
                    return 1;
                }
                down = true;
            }
        }
        return CallNextHookEx(nullptr, code, message, parameter);
    }
    void Pump() {
        MSG message;
        while (PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE)) {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }
};
bool CopyAllowed(HWND focus) {
    wchar_t cls[64] = {};
    GetClassNameW(focus, cls, _countof(cls));
    const bool edit = _wcsicmp(cls, L"Edit") == 0 ||
        _wcsnicmp(cls, L"RichEdit", 8) == 0;
    if (edit && (GetWindowLongPtrW(focus, GWL_STYLE) & ES_PASSWORD)) return false;
    const HRESULT initialized = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(initialized)) return false;
    bool allowed = false;
    {
        Microsoft::WRL::ComPtr<IUIAutomation> automation;
        Microsoft::WRL::ComPtr<IUIAutomationElement> element;
        Microsoft::WRL::ComPtr<IUIAutomation2> timed;
        if (SUCCEEDED(CoCreateInstance(CLSID_CUIAutomation8, nullptr, CLSCTX_INPROC_SERVER,
                IID_PPV_ARGS(&automation)))) {
            if (SUCCEEDED(automation.As(&timed))) {
                timed->put_ConnectionTimeout(1000); timed->put_TransactionTimeout(1000);
            }
            BOOL password = TRUE;
            // Only metadata is read; no TextPattern or selection API is required.
            allowed = SUCCEEDED(automation->GetFocusedElement(&element)) && element &&
                SUCCEEDED(element->get_CurrentIsPassword(&password)) && !password;
        }
    }
    CoUninitialize();
    return allowed;
}
struct Session {
    HANDLE mapping = nullptr;
    PrivateClipSession* data = nullptr;
    std::wstring name;
    ~Session() {
        if (data) {
            LONG state = PrivateState(data);
            while (state == kPrivateCreated || state == kPrivateReady) {
                LONG previous = InterlockedCompareExchange(&data->state,
                    kPrivateCancelledBeforeInput, state);
                if (previous == state) break;
                state = previous;
            }
            if (state == kPrivateSending || state == kPrivateRunning)
                InterlockedExchange(&data->state, kPrivateCancelled);
            SecureZeroMemory(data->text, sizeof(data->text));
            UnmapViewOfFile(data);
        }
        if (mapping) CloseHandle(mapping);
    }
    bool Create() {
        GUID id = {};
        wchar_t guid[40] = {};
        if (FAILED(CoCreateGuid(&id)) || !StringFromGUID2(id, guid, _countof(guid))) return false;
        name = std::wstring(kPrivateClipPrefix) + guid;
        PSECURITY_DESCRIPTOR descriptor = nullptr;
        if (!CreateLocalUserSecurityDescriptor(&descriptor)) return false;
        SECURITY_ATTRIBUTES security = {sizeof(security), descriptor, FALSE};
        mapping = CreateFileMappingW(INVALID_HANDLE_VALUE, &security, PAGE_READWRITE,
            0, sizeof(PrivateClipSession), name.c_str());
        const DWORD error = GetLastError();
        LocalFree(descriptor);
        if (!mapping || error == ERROR_ALREADY_EXISTS) return false;
        data = static_cast<PrivateClipSession*>(MapViewOfFile(mapping,
            FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, sizeof(PrivateClipSession)));
        if (!data) return false;
        data->magic = kPrivateClipMagic; data->version = kPrivateClipVersion;
        data->inputTag = id.Data1 ? id.Data1 : 1;
        return true;
    }
};
const wchar_t* FailureText(DWORD error) {
    switch (error) {
    case kPrivateNoText: return UiText(TextId::TheApplicationDidNotCopyOrPaste);
    case kPrivateUnsupported: return UiText(TextId::TheApplicationUsedAnUnsupportedClipboardFormat);
    case kPrivateTooLarge: return UiText(TextId::TheSelectionIsTooLongTheLimit);
    case kPrivateWrongTarget: return UiText(TextId::TheTargetWindowOrFocusChangedThe);
    case kPrivateBusy: return UiText(TextId::TheTargetProcessStillHasAnActive);
    default: return UiText(TextId::TheTargetApplicationDidNotCompleteThe);
    }
}
} // namespace

void PrivateClipboard::Text::Clear() {
    if (!chars.empty()) SecureZeroMemory(chars.data(), chars.size() * sizeof(wchar_t));
    std::vector<wchar_t>().swap(chars);
}

PrivateClipboard::~PrivateClipboard() { Stop(); }

void PrivateClipboard::Clear() {
    cancelled_.store(true);
    std::lock_guard<std::mutex> lock(mutex_);
    text_.Clear();
}

void PrivateClipboard::Stop() {
    stopping_.store(true);
    Clear();
    if (worker_.joinable()) worker_.join();
}

bool PrivateClipboard::HasText() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return !text_.chars.empty();
}

bool PrivateClipboard::Start(Operation operation, HWND foreground, HWND notify,
                             UINT message, ArmTarget arm) {
    if (stopping_.load() || busy_.exchange(true)) return false;
    if (worker_.joinable()) worker_.join();
    ready_.store(false);
    cancelled_.store(false);
    result_.clear();
    armTarget_ = std::move(arm);
    success_ = false;
    if (operation == Operation::copy) {
        std::lock_guard<std::mutex> lock(mutex_);
        text_.Clear(); // A failed new copy must never leave stale paste content.
    }
    const HWND focus = FocusWindow(foreground);
    try {
        worker_ = std::thread([this, operation, foreground, focus, notify, message] {
            try { Run(operation, foreground, focus); }
            catch (...) { result_ = UiText(TextId::ThePrivateClipboardOperationFailedTheSystem); }
            if (cancelled_.load()) {
                success_ = false;
                result_ = UiText(TextId::ThePrivateClipboardOperationWasCancelled) + result_;
            }
            ready_.store(true);
            busy_.store(false);
            if (!stopping_.load()) PostMessageW(notify, message, 0, 0);
        });
    } catch (...) {
        result_ = UiText(TextId::CouldNotStartThePrivateClipboardTask);
        ready_.store(true);
        busy_.store(false);
        PostMessageW(notify, message, 0, 0);
    }
    return true;
}

void PrivateClipboard::Run(Operation operation, HWND foreground, HWND focus) {
    DWORD process = 0, focusProcess = 0;
    GetWindowThreadProcessId(foreground, &process);
    const DWORD thread = GetWindowThreadProcessId(focus, &focusProcess);
    if (!process || process == GetCurrentProcessId() || !focus || focusProcess != process) {
        result_ = UiText(TextId::SwitchToAnInjectedTargetApplicationFirst);
        return;
    }
    Text temporary;
    if (operation == Operation::paste) {
        std::lock_guard<std::mutex> lock(mutex_);
        temporary.chars = text_.chars;
        if (temporary.chars.empty()) {
            result_ = UiText(TextId::ThePrivateClipboardIsEmptySelectText);
            return;
        }
    }
    const ULONGLONG releaseDeadline = GetTickCount64() + 2000;
    while (ModifiersDown() && GetTickCount64() < releaseDeadline && !cancelled_.load()) Sleep(10);
    if (cancelled_.load() || ModifiersDown() || !SameTarget(foreground, focus)) {
        result_ = UiText(TextId::ReleaseTheShortcutKeysAndKeepThe);
        return;
    }
    if (operation == Operation::copy && !CopyAllowed(focus)) {
        result_ = UiText(TextId::TheFocusedInputIsAPasswordField);
        return;
    }
    Session session;
    if (!session.Create()) { result_ = UiText(TextId::CouldNotCreateThePrivateClipboardMemory); return; }
    auto* data = session.data;
    data->processId = process; data->threadId = thread;
    data->foreground = reinterpret_cast<ULONG_PTR>(foreground);
    data->focus = reinterpret_cast<ULONG_PTR>(focus);
    data->operation = operation == Operation::paste ? 1 : 0;
    data->deadline = GetTickCount64() + 8000;
    if (!temporary.chars.empty()) {
        data->length = static_cast<DWORD>(temporary.chars.size() - 1);
        std::copy(temporary.chars.begin(), temporary.chars.end(), data->text);
    }
    if (!armTarget_ || !armTarget_(process, session.name)) {
        result_ = UiText(TextId::TheProcessIsNotInjectedItsModule);
        return;
    }
    const ULONGLONG readyDeadline = GetTickCount64() + 2500;
    while (PrivateState(data) == kPrivateCreated && GetTickCount64() < readyDeadline && !cancelled_.load()) Sleep(10);
    if (cancelled_.load() || !SameTarget(foreground, focus) || ModifiersDown()) {
        result_ = UiText(TextId::TheFocusOrKeyboardStateChangedThe);
        return;
    }
    if (PrivateState(data) == kPrivateFailed) {
        result_ = FailureText(data->error);
        result_ += UiText(TextId::NoCopyOrPasteKeysWereSent);
        return;
    }
    InputGuard inputGuard(foreground, focus, data->inputTag, cancelled_);
    if (!inputGuard.hook) {
        result_ = UiText(TextId::CouldNotEstablishTheFocusGuardFor);
        return;
    }
    if (InterlockedCompareExchange(&data->state, kPrivateSending, kPrivateReady) != kPrivateReady) {
        result_ = UiText(TextId::TheTargetDidNotConfirmPrivateInterception);
        return;
    }
    INPUT keys[4] = {};
    const WORD key = operation == Operation::copy ? 'C' : 'V';
    const WORD codes[] = {VK_CONTROL, key, key, VK_CONTROL};
    for (int i = 0; i < 4; ++i) {
        keys[i].type = INPUT_KEYBOARD;
        keys[i].ki.wVk = codes[i]; keys[i].ki.dwExtraInfo = data->inputTag;
        keys[i].ki.dwFlags = i >= 2 ? KEYEVENTF_KEYUP : 0;
    }
    const UINT sent = SendInput(4, keys, sizeof(INPUT));
    if (sent != 4) {
        if (sent) SendInput(2, keys + 2, sizeof(INPUT));
        result_ = UiText(TextId::SimulatedInputWasIncompleteTheOperationWas);
        return;
    }
    LONG state;
    do {
        inputGuard.Pump();
        state = PrivateState(data);
        if (state == kPrivateDone || state == kPrivateFailed) break;
        Sleep(10);
    } while (!inputGuard.blocked && !cancelled_.load() && GetTickCount64() < data->deadline);
    if (inputGuard.blocked) {
        result_ = UiText(TextId::FocusChangedAndSimulatedInputWasBlocked);
        return;
    }
    if (state != kPrivateDone || cancelled_.load()) {
        result_ = FailureText(data->error);
        result_ += UiText(TextId::ToPreventLateWritesFromLeakingThe);
        return;
    }
    if (operation == Operation::copy) {
        if (!data->length || data->length > kMaxCharacters || data->text[data->length]) {
            result_ = UiText(TextId::TheTargetReturnedInvalidTextCopyWas); return;
        }
        temporary.chars.assign(data->text, data->text + data->length + 1);
        std::lock_guard<std::mutex> lock(mutex_);
        if (cancelled_.load()) return;
        text_.chars.swap(temporary.chars);
    }
    success_ = true;
    result_ = operation == Operation::copy
        ? UiText(TextId::TextCopiedThroughTheTargetApplicationTo)
        : UiText(TextId::PrivateTextPastedThroughTheTargetApplication);
    if (data->reserved) result_ += UiText(TextId::AnEarlierOperationDidNotCompleteThe);
}
bool PrivateClipboard::TakeResult(std::wstring& message, bool& success) {
    if (!ready_.exchange(false)) return false;
    if (worker_.joinable()) worker_.join();
    message = result_;
    success = success_;
    return true;
}
} // namespace clip
