#include "i18n.h"
#include "tray.h"
#include "resource.h"

namespace clip {

// kTrayMsg 定义见 tray.h（唯一定义）

bool Tray::Init(HWND hwnd) {
    hwnd_ = hwnd;
    ZeroMemory(&nid_, sizeof(nid_));
    nid_.cbSize = sizeof(nid_);
    nid_.hWnd = hwnd;
    nid_.uID = 1;
    nid_.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
    nid_.uCallbackMessage = kTrayMsg;
    nid_.uVersion = NOTIFYICON_VERSION_4;
    nid_.hIcon = (HICON)LoadImageW(GetModuleHandleW(nullptr),
                                   MAKEINTRESOURCEW(IDI_APP_ICON), IMAGE_ICON,
                                   GetSystemMetrics(SM_CXSMICON),
                                   GetSystemMetrics(SM_CYSMICON), LR_SHARED);
    if (!nid_.hIcon) return false;
    wcscpy_s(nid_.szTip, UiText(TextId::ClipboardProtector));
    if (!Shell_NotifyIconW(NIM_ADD, &nid_)) return false;
    // VERSION_4 需要在 ADD 之后设置，消息 wParam 才携带事件/坐标
    if (!Shell_NotifyIconW(NIM_SETVERSION, &nid_)) {
        Shell_NotifyIconW(NIM_DELETE, &nid_);
        return false;
    }
    added_ = true;
    return true;
}

void Tray::Remove() {
    if (added_) {
        Shell_NotifyIconW(NIM_DELETE, &nid_);
        added_ = false;
    }
}
void Tray::ReAdd() {
    if (!hwnd_) return;
    Remove();
    if (!Shell_NotifyIconW(NIM_ADD, &nid_)) {
        added_ = false;
        return;
    }
    if (!Shell_NotifyIconW(NIM_SETVERSION, &nid_)) {
        Shell_NotifyIconW(NIM_DELETE, &nid_);
        added_ = false;
        return;
    }
    added_ = true;
}

void Tray::SetPaused(bool paused) {
    wcscpy_s(nid_.szTip, paused ? UiText(TextId::ClipboardProtectorPaused) : UiText(TextId::ClipboardProtector));
    Shell_NotifyIconW(NIM_MODIFY, &nid_);
}

void Tray::ShowBalloon(const wchar_t* title, const wchar_t* text,
                       bool respectQuietTime) {
    if (!added_ || !title || !*title || !text || !*text) return;

    // uVersion and uTimeout share storage in NOTIFYICONDATA. Do not copy the
    // versioned tray structure here or the shell receives uTimeout == 4.
    NOTIFYICONDATAW d{};
    d.cbSize = sizeof(d);
    d.hWnd = hwnd_;
    d.uID = nid_.uID;
    d.uFlags = NIF_INFO | (respectQuietTime ? NIF_REALTIME : 0);
    d.uTimeout = 10000;
    d.dwInfoFlags = NIIF_INFO |
                    (respectQuietTime ? NIIF_RESPECT_QUIET_TIME : 0);
    wcsncpy_s(d.szInfoTitle, title, _TRUNCATE);
    wcsncpy_s(d.szInfo, text, _TRUNCATE);
    Shell_NotifyIconW(NIM_MODIFY, &d);
}

} // namespace clip
