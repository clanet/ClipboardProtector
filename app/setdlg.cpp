#include "i18n.h"
#include "dialog_i18n.h"
#include "dlgapi.h"
#include "app.h"
#include "resource.h"

namespace clip {

// 设置对话框：规则通知 / 剪贴板保护 / 日志与启动设置
static INT_PTR CALLBACK SettingsProc(HWND h, UINT msg, WPARAM wp, LPARAM lp) {
    static Settings* s = nullptr;
    switch (msg) {
    case WM_INITDIALOG: {
        LocalizeDialog(h, IDD_SETTINGS);
        s = reinterpret_cast<Settings*>(lp);
        SetDlgItemTextW(h, IDC_SHORTCUT_ONLY_HINT,
            (UiText(TextId::BlockAndLogOtherAccessEnableProtection) +
             HotkeyText(s->hotkeys.shortcutOnlyModifiers, s->hotkeys.shortcutOnlyKey)).c_str());
        if (s->balloonNotificationsDisabled)
            CheckDlgButton(h, IDC_CHK_DISABLE_BALLOON, BST_CHECKED);
        if (s->shortcutOnlyMode)
            CheckDlgButton(h, IDC_CHK_SHORTCUT_ONLY, BST_CHECKED);
        if (s->shortcutDirectAllow)
            CheckDlgButton(h, IDC_CHK_SHORTCUT_DIRECT_ALLOW, BST_CHECKED);
        if (s->cryptoProtection)
            CheckDlgButton(h, IDC_CHK_CRYPTO_PROTECTION, BST_CHECKED);
        wchar_t buf[16];
        swprintf_s(buf, L"%d", s->maxLogEntries);
        SetDlgItemTextW(h, IDC_EDIT_MAXLOG, buf);
        if (s->previewEnabled)
            CheckDlgButton(h, IDC_CHK_PREVIEW, BST_CHECKED);
        if (s->captureImageFileSnapshots)
            CheckDlgButton(h, IDC_CHK_CAPTURE_SNAPSHOTS, BST_CHECKED);
        if (s->ignoreCustomFormats)
            CheckDlgButton(h, IDC_CHK_IGNORE_CUSTOM_FORMATS, BST_CHECKED);
        if (s->autostart)
            CheckDlgButton(h, IDC_CHK_AUTOSTART, BST_CHECKED);
        if (s->startGlobalProtection)
            CheckDlgButton(h, IDC_CHK_START_GLOBAL, BST_CHECKED);
        if (s->startMinimized)
            CheckDlgButton(h, IDC_CHK_START_MINIMIZED, BST_CHECKED);
        return TRUE;
    }
    case WM_COMMAND:
        switch (LOWORD(wp)) {
        case IDOK: {
            wchar_t buf[16] = {};
            GetDlgItemTextW(h, IDC_EDIT_MAXLOG, buf, _countof(buf));
            long long v = wcstoll(buf, nullptr, 10);
            if (v < 100) v = 100;
            if (v > 100000) v = 100000;
            bool requestedAutostart =
                IsDlgButtonChecked(h, IDC_CHK_AUTOSTART) == BST_CHECKED;
            s->balloonNotificationsDisabled =
                IsDlgButtonChecked(h, IDC_CHK_DISABLE_BALLOON) == BST_CHECKED;
            s->shortcutOnlyMode =
                IsDlgButtonChecked(h, IDC_CHK_SHORTCUT_ONLY) == BST_CHECKED;
            s->shortcutDirectAllow =
                IsDlgButtonChecked(h, IDC_CHK_SHORTCUT_DIRECT_ALLOW) ==
                BST_CHECKED;
            s->cryptoProtection =
                IsDlgButtonChecked(h, IDC_CHK_CRYPTO_PROTECTION) == BST_CHECKED;
            s->maxLogEntries = (int)v;
            s->previewEnabled =
                IsDlgButtonChecked(h, IDC_CHK_PREVIEW) == BST_CHECKED;
            s->captureImageFileSnapshots =
                IsDlgButtonChecked(h, IDC_CHK_CAPTURE_SNAPSHOTS) == BST_CHECKED;
            s->ignoreCustomFormats =
                IsDlgButtonChecked(h, IDC_CHK_IGNORE_CUSTOM_FORMATS) ==
                BST_CHECKED;
            s->autostart = requestedAutostart;
            s->startGlobalProtection =
                IsDlgButtonChecked(h, IDC_CHK_START_GLOBAL) == BST_CHECKED;
            s->startMinimized =
                IsDlgButtonChecked(h, IDC_CHK_START_MINIMIZED) == BST_CHECKED;
            EndDialog(h, IDOK);
            return TRUE;
        }
        case IDCANCEL:
            EndDialog(h, IDCANCEL);
            return TRUE;
        }
        break;
    }
    return FALSE;
}

bool ShowSettingsDialog(HWND owner, Settings& settings) {
    INT_PTR r = DialogBoxParamW(g_app.hInst, MAKEINTRESOURCEW(IDD_SETTINGS),
                                owner, SettingsProc, (LPARAM)&settings);
    return r == IDOK;
}

} // namespace clip
