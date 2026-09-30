#pragma once
#include <windows.h>
#include <shellapi.h>

namespace clip {

// 托盘回调消息（tray.cpp 与 mainwnd.cpp 共用此唯一定义）
constexpr UINT kTrayMsg = WM_APP + 1;

// 托盘图标封装：常驻、气泡通知、状态切换（正常/暂停）
class Tray {
public:
    // hwnd：接收托盘消息的窗口；返回 false 表示初始化失败
    bool Init(HWND hwnd);
    void Remove();
    void ReAdd();   // explorer 重启后重建图标
    void SetPaused(bool paused);           // 切换提示文字与图标状态
    void ShowBalloon(const wchar_t* title, const wchar_t* text,
                     bool respectQuietTime = true);

private:
    HWND hwnd_ = nullptr;
    NOTIFYICONDATAW nid_{};
    bool added_ = false;
};

} // namespace clip
