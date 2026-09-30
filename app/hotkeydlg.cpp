#include "i18n.h"
#include "dialog_i18n.h"
#include "dlgapi.h"
#include "app.h"
#include "resource.h"
#include <commctrl.h>

namespace clip {
namespace {
struct DialogState {
    AppHotkeys keys;
    const std::function<bool(const AppHotkeys&, std::wstring&)>* apply;
};
WORD ToControl(unsigned int modifiers, unsigned int key) {
    BYTE flags = 0;
    if (modifiers & MOD_CONTROL) flags |= HOTKEYF_CONTROL;
    if (modifiers & MOD_ALT) flags |= HOTKEYF_ALT;
    if (modifiers & MOD_SHIFT) flags |= HOTKEYF_SHIFT;
    return MAKEWORD(static_cast<BYTE>(key), flags);
}
void FromControl(HWND dialog, int id, unsigned int& modifiers, unsigned int& key) {
    const WORD value = static_cast<WORD>(SendDlgItemMessageW(dialog, id, HKM_GETHOTKEY, 0, 0));
    key = LOBYTE(value);
    modifiers = 0;
    if (HIBYTE(value) & HOTKEYF_CONTROL) modifiers |= MOD_CONTROL;
    if (HIBYTE(value) & HOTKEYF_ALT) modifiers |= MOD_ALT;
    if (HIBYTE(value) & HOTKEYF_SHIFT) modifiers |= MOD_SHIFT;
}
INT_PTR CALLBACK DialogProc(HWND dialog, UINT message, WPARAM wp, LPARAM lp) {
    auto* state = reinterpret_cast<DialogState*>(GetWindowLongPtrW(dialog, DWLP_USER));
    if (message == WM_INITDIALOG) {
        LocalizeDialog(dialog, IDD_PRIVATE_HOTKEYS);
        state = reinterpret_cast<DialogState*>(lp);
        SetWindowLongPtrW(dialog, DWLP_USER, lp);
        SendDlgItemMessageW(dialog, IDC_HOTKEY_PRIVATE_COPY, HKM_SETHOTKEY,
            ToControl(state->keys.copyModifiers, state->keys.copyKey), 0);
        SendDlgItemMessageW(dialog, IDC_HOTKEY_PRIVATE_PASTE, HKM_SETHOTKEY,
            ToControl(state->keys.pasteModifiers, state->keys.pasteKey), 0);
        SendDlgItemMessageW(dialog, IDC_HOTKEY_SHORTCUT_ONLY, HKM_SETHOTKEY,
            ToControl(state->keys.shortcutOnlyModifiers, state->keys.shortcutOnlyKey), 0);
        return TRUE;
    }
    if (message == WM_COMMAND && state) {
        if (LOWORD(wp) == IDCANCEL) { EndDialog(dialog, IDCANCEL); return TRUE; }
        if (LOWORD(wp) == IDOK) {
            AppHotkeys keys;
            FromControl(dialog, IDC_HOTKEY_PRIVATE_COPY, keys.copyModifiers, keys.copyKey);
            FromControl(dialog, IDC_HOTKEY_PRIVATE_PASTE, keys.pasteModifiers, keys.pasteKey);
            FromControl(dialog, IDC_HOTKEY_SHORTCUT_ONLY, keys.shortcutOnlyModifiers, keys.shortcutOnlyKey);
            std::wstring error;
            if (!ValidHotkeys(keys)) {
                error = UiText(TextId::UseCtrlOrAltOptionallyWithShift);
            } else {
                try {
                    if ((*state->apply)(keys, error)) { EndDialog(dialog, IDOK); return TRUE; }
                } catch (...) { error = UiText(TextId::CouldNotApplyShortcutsPleaseTryAgain); }
            }
            UiMessageBox(dialog, error.c_str(), UiText(TextId::KeyboardShortcuts), MB_OK | MB_ICONWARNING);
            return TRUE;
        }
    }
    return FALSE;
}
} // namespace
void ShowHotkeyDialog(HWND owner, const AppHotkeys& keys,
    const std::function<bool(const AppHotkeys&, std::wstring&)>& apply) {
    DialogState state{keys, &apply};
    if (DialogBoxParamW(g_app.hInst, MAKEINTRESOURCEW(IDD_PRIVATE_HOTKEYS), owner,
            DialogProc, reinterpret_cast<LPARAM>(&state)) == -1)
        UiMessageBox(owner, UiText(TextId::CouldNotOpenKeyboardShortcutSettings), UiText(TextId::KeyboardShortcuts), MB_ICONERROR);
}
} // namespace clip
