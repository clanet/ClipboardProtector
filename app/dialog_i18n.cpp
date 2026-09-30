#include "dialog_i18n.h"
#include "i18n.h"
#include "resource.h"
#include <algorithm>

namespace clip {
void LocalizeDialog(HWND dialog, int templateId) {
    struct Label { int dialog; int control; TextId text; };
    static constexpr Label labels[] = {
#include "dialog_strings.inc"
    };
    for (const auto& label : labels) {
        if (label.dialog != templateId) continue;
        if (label.control) SetDlgItemTextW(dialog, label.control, UiText(label.text));
        else SetWindowTextW(dialog, UiText(label.text));
    }
    if (CurrentLanguage() != Language::English) return;

    // English labels need more room without increasing the UI font size.
    RECT client{}, frame{};
    if (!GetClientRect(dialog, &client) || !GetWindowRect(dialog, &frame) ||
        client.right <= 0 || client.bottom <= 0) return;
    MONITORINFO monitor{sizeof(monitor)};
    if (!GetMonitorInfoW(MonitorFromWindow(dialog, MONITOR_DEFAULTTONEAREST),
                        &monitor)) return;
    const int borderWidth = frame.right - frame.left - client.right;
    const int borderHeight = frame.bottom - frame.top - client.bottom;
    const double scaleX = (std::min)(1.2, static_cast<double>(
        monitor.rcWork.right - monitor.rcWork.left - borderWidth - 20) / client.right);
    const double scaleY = (std::min)(1.4, static_cast<double>(
        monitor.rcWork.bottom - monitor.rcWork.top - borderHeight - 20) / client.bottom);
    for (HWND control = GetWindow(dialog, GW_CHILD); control;
         control = GetWindow(control, GW_HWNDNEXT)) {
        RECT rect{};
        GetWindowRect(control, &rect);
        MapWindowPoints(nullptr, dialog, reinterpret_cast<POINT*>(&rect), 2);
        MoveWindow(control, static_cast<int>(rect.left * scaleX),
            static_cast<int>(rect.top * scaleY),
            static_cast<int>((rect.right - rect.left) * scaleX),
            static_cast<int>((rect.bottom - rect.top) * scaleY), FALSE);
        wchar_t className[32]{};
        GetClassNameW(control, className, _countof(className));
        if (_wcsicmp(className, L"Button") == 0)
            SetWindowLongPtrW(control, GWL_STYLE,
                GetWindowLongPtrW(control, GWL_STYLE) | BS_MULTILINE);
    }
    const int width = static_cast<int>(client.right * scaleX) + borderWidth;
    const int height = static_cast<int>(client.bottom * scaleY) + borderHeight;
    const int left = monitor.rcWork.left + (monitor.rcWork.right - monitor.rcWork.left - width) / 2;
    const int top = monitor.rcWork.top + (monitor.rcWork.bottom - monitor.rcWork.top - height) / 2;
    SetWindowPos(dialog, nullptr, left, top, width, height, SWP_NOZORDER | SWP_NOACTIVATE);
}
}
