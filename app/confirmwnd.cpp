#include "i18n.h"
#include "drawing.h"
#include "confirmwnd.h"
#include "messages.h"
#include "resource.h"
#include <dwmapi.h>
#include <algorithm>
#include <new>
#include <string>
#include <utility>

namespace clip {
namespace {

constexpr UINT_PTR kCountdownTimer = 1;

std::wstring OperationText(ClipOp operation) {
    return operation == kOpRead ? UiText(TextId::ReadClipboard) : UiText(TextId::WriteClipboard);
}

std::wstring FormatText(UINT format) {
    switch (format) {
    case CF_UNICODETEXT: return UiText(TextId::UnicodeText);
    case CF_TEXT: return UiText(TextId::ANSIText);
    case CF_HDROP: return UiText(TextId::FileList);
    case CF_BITMAP:
    case CF_DIB:
    case CF_DIBV5: return UiText(TextId::Image);
    default: return UiText(TextId::Format) + std::to_wstring(format);
    }
}

} // namespace

AccessConfirmationWindow::AccessConfirmationWindow(
    HWND owner, AccessConfirmationRequest request)
    : owner_(owner), request_(std::move(request)) {}

AccessConfirmationWindow::~AccessConfirmationWindow() {
    if (hwnd_ && IsWindow(hwnd_)) DestroyWindow(hwnd_);
    for (HFONT font : {titleFont_, headingFont_, uiFont_, smallFont_})
        if (font) DeleteObject(font);
}

std::unique_ptr<AccessConfirmationWindow> AccessConfirmationWindow::Create(
    HINSTANCE instance, HWND owner, AccessConfirmationRequest request,
    size_t cascadeIndex) {
    auto window = std::unique_ptr<AccessConfirmationWindow>(
        new (std::nothrow) AccessConfirmationWindow(owner, std::move(request)));
    if (!window || !window->CreateWindowInstance(instance, cascadeIndex))
        return nullptr;
    return window;
}

bool AccessConfirmationWindow::CreateWindowInstance(HINSTANCE instance,
                                                      size_t cascadeIndex) {
    WNDCLASSEXW windowClass{sizeof(windowClass)};
    windowClass.style = CS_HREDRAW | CS_VREDRAW;
    windowClass.lpfnWndProc = WndProcStatic;
    windowClass.hInstance = instance;
    windowClass.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    windowClass.hIcon = reinterpret_cast<HICON>(LoadImageW(
        instance, MAKEINTRESOURCEW(IDI_APP_ICON), IMAGE_ICON, 32, 32,
        LR_SHARED));
    windowClass.hIconSm = reinterpret_cast<HICON>(LoadImageW(
        instance, MAKEINTRESOURCEW(IDI_APP_ICON), IMAGE_ICON, 16, 16,
        LR_SHARED));
    windowClass.lpszClassName = kConfirmationWindowClass;
    if (!RegisterClassExW(&windowClass) &&
        GetLastError() != ERROR_CLASS_ALREADY_EXISTS)
        return false;

    const UINT systemDpi = owner_ ? GetDpiForWindow(owner_) : GetDpiForSystem();
    const int width = DpiScale(570, systemDpi);
    const int height = DpiScale(470, systemDpi);
    MONITORINFO monitor{sizeof(monitor)};
    GetMonitorInfoW(MonitorFromWindow(owner_, MONITOR_DEFAULTTONEAREST),
                    &monitor);
    const int offset = DpiScale(
        static_cast<int>((cascadeIndex % 8) * 24), systemDpi);
    const int x = monitor.rcWork.right - width - DpiScale(24, systemDpi) - offset;
    const int y = monitor.rcWork.bottom - height - DpiScale(24, systemDpi) - offset;
    hwnd_ = CreateWindowExW(
        WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_CONTROLPARENT,
        kConfirmationWindowClass, UiText(TextId::ConfirmClipboardAccess),
        WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_CLIPCHILDREN, x, y, width,
        height, nullptr, nullptr, instance, this);
    if (!hwnd_) return false;
    ShowWindow(hwnd_, SW_SHOWNORMAL);
    UpdateWindow(hwnd_);
    FLASHWINFO flash{sizeof(flash), hwnd_, FLASHW_TRAY | FLASHW_TIMERNOFG, 3, 0};
    FlashWindowEx(&flash);
    return true;
}

LRESULT CALLBACK AccessConfirmationWindow::WndProcStatic(
    HWND window, UINT message, WPARAM wParam, LPARAM lParam) {
    auto* self = reinterpret_cast<AccessConfirmationWindow*>(
        GetWindowLongPtrW(window, GWLP_USERDATA));
    if (message == WM_NCCREATE) {
        const auto* create = reinterpret_cast<CREATESTRUCTW*>(lParam);
        self = static_cast<AccessConfirmationWindow*>(create->lpCreateParams);
        self->hwnd_ = window;
        SetWindowLongPtrW(window, GWLP_USERDATA,
                          reinterpret_cast<LONG_PTR>(self));
    }
    return self ? self->WndProc(message, wParam, lParam)
                : DefWindowProcW(window, message, wParam, lParam);
}

void AccessConfirmationWindow::CreateFonts() {
    for (HFONT font : {titleFont_, headingFont_, uiFont_, smallFont_})
        if (font) DeleteObject(font);
    const wchar_t* family = UiFontFamily();
    auto makeFont = [this, family](int points, int weight) {
        return CreateFontW(-MulDiv(points, static_cast<int>(dpi_), 72), 0, 0,
                           0, weight, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                           OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                           CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE,
                           family);
    };
    titleFont_ = makeFont(18, FW_SEMIBOLD);
    headingFont_ = makeFont(11, FW_SEMIBOLD);
    uiFont_ = makeFont(10, FW_NORMAL);
    smallFont_ = makeFont(9, FW_NORMAL);
}

void AccessConfirmationWindow::ApplyLanguage() {
    SetWindowTextW(hwnd_, UiText(TextId::ConfirmClipboardAccess));
    SetWindowTextW(persistCheck_, UiText(TextId::RememberChoice));
    SetWindowTextW(blockButton_, UiText(TextId::Block));
    SetWindowTextW(allowButton_, UiText(TextId::Allow));
    CreateFonts();
    for (HWND control : {persistCheck_, blockButton_, allowButton_})
        SendMessageW(control, WM_SETFONT, reinterpret_cast<WPARAM>(uiFont_), TRUE);
    Layout();
    RedrawWindow(hwnd_, nullptr, nullptr, RDW_INVALIDATE | RDW_ALLCHILDREN);
}

LRESULT AccessConfirmationWindow::WndProc(UINT message, WPARAM wParam,
                                           LPARAM lParam) {
    switch (message) {
    case WM_CREATE: {
        dpi_ = GetDpiForWindow(hwnd_);
        CreateFonts();
        persistCheck_ = CreateWindowExW(
            0, L"BUTTON", UiText(TextId::RememberChoice),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX, 0, 0, 0, 0,
            hwnd_, reinterpret_cast<HMENU>(
                       static_cast<INT_PTR>(kConfirmationPersistDecision)),
            reinterpret_cast<LPCREATESTRUCT>(lParam)->hInstance, nullptr);
        blockButton_ = CreateWindowExW(
            0, L"BUTTON", UiText(TextId::Block),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW, 0, 0, 0, 0,
            hwnd_,
            reinterpret_cast<HMENU>(static_cast<INT_PTR>(kConfirmationBlock)),
            reinterpret_cast<LPCREATESTRUCT>(lParam)->hInstance, nullptr);
        allowButton_ = CreateWindowExW(
            0, L"BUTTON", UiText(TextId::Allow),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW, 0, 0, 0, 0,
            hwnd_, reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDOK)),
            reinterpret_cast<LPCREATESTRUCT>(lParam)->hInstance, nullptr);
        for (HWND control : {persistCheck_, blockButton_, allowButton_})
            SendMessageW(control, WM_SETFONT, (WPARAM)uiFont_, TRUE);
        deadline_ = GetTickCount64() + request_.timeoutMs;
        SetTimer(hwnd_, kCountdownTimer, 250, nullptr);
        constexpr DWORD kDwmWindowCornerPreference = 33;
        const DWORD roundCorners = 2;
        DwmSetWindowAttribute(hwnd_, kDwmWindowCornerPreference, &roundCorners,
                              sizeof(roundCorners));
        Layout();
        SetFocus(allowButton_);
        return 0;
    }
    case WM_SIZE:
        Layout();
        return 0;
    case WM_DPICHANGED: {
        dpi_ = HIWORD(wParam);
        CreateFonts();
        for (HWND control : {persistCheck_, blockButton_, allowButton_})
            SendMessageW(control, WM_SETFONT, (WPARAM)uiFont_, TRUE);
        const auto* suggested = reinterpret_cast<RECT*>(lParam);
        SetWindowPos(hwnd_, nullptr, suggested->left, suggested->top,
                     suggested->right - suggested->left,
                     suggested->bottom - suggested->top,
                     SWP_NOZORDER | SWP_NOACTIVATE);
        Layout();
        InvalidateRect(hwnd_, nullptr, TRUE);
        return 0;
    }
    case WM_ERASEBKGND:
        return 1;
    case WM_PAINT:
        Paint();
        return 0;
    case WM_DRAWITEM:
        DrawButton(*reinterpret_cast<DRAWITEMSTRUCT*>(lParam));
        return TRUE;
    case WM_CTLCOLORSTATIC:
        SetBkMode(reinterpret_cast<HDC>(wParam), TRANSPARENT);
        SetTextColor(reinterpret_cast<HDC>(wParam), RGB(42, 65, 62));
        return reinterpret_cast<LRESULT>(GetStockObject(WHITE_BRUSH));
    case WM_TIMER:
        if (wParam == kCountdownTimer) {
            if (GetTickCount64() >= deadline_)
                Finish(!request_.timeoutBlock, false);   // 超时不是点击
            else
                InvalidateRect(hwnd_, nullptr, FALSE);
            return 0;
        }
        break;
    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK) {
            Finish(true, true);
            return 0;
        }
        if (LOWORD(wParam) == kConfirmationBlock) {
            Finish(false, true);
            return 0;
        }
        if (LOWORD(wParam) == IDCANCEL) {
            Finish(false, false);   // Escape：只阻止本次
            return 0;
        }
        break;
    case WM_CLOSE:
        Finish(false, false);   // 关闭窗口只阻止本次，不写规则
        return 0;
    case WM_NCDESTROY:
        KillTimer(hwnd_, kCountdownTimer);
        {
            const HWND destroyed = hwnd_;
            SetWindowLongPtrW(hwnd_, GWLP_USERDATA, 0);
            hwnd_ = nullptr;
            return DefWindowProcW(destroyed, message, wParam, lParam);
        }
    }
    return DefWindowProcW(hwnd_, message, wParam, lParam);
}

void AccessConfirmationWindow::Layout() {
    if (!hwnd_) return;
    RECT client{};
    GetClientRect(hwnd_, &client);
    const int margin = DpiScale(24, dpi_);
    const int buttonHeight = DpiScale(42, dpi_);
    const int buttonWidth = DpiScale(112, dpi_);
    const int bottom = client.bottom - DpiScale(20, dpi_);
    MoveWindow(allowButton_, client.right - margin - buttonWidth,
               bottom - buttonHeight, buttonWidth, buttonHeight, TRUE);
    MoveWindow(blockButton_, client.right - margin - buttonWidth * 2 -
                                     DpiScale(10, dpi_),
               bottom - buttonHeight, buttonWidth, buttonHeight, TRUE);
    MoveWindow(persistCheck_, margin, bottom - buttonHeight,
               client.right - margin * 2 - buttonWidth * 2 - DpiScale(26, dpi_),
               buttonHeight, TRUE);
}

void AccessConfirmationWindow::Paint() {
    PAINTSTRUCT paint{};
    HDC dc = BeginPaint(hwnd_, &paint);
    RECT client{};
    GetClientRect(hwnd_, &client);
    HDC memory = CreateCompatibleDC(dc);
    HBITMAP bitmap = CreateCompatibleBitmap(dc, client.right, client.bottom);
    if (memory && bitmap) {
        HGDIOBJ old = SelectObject(memory, bitmap);
        PaintContent(memory, client);
        BitBlt(dc, 0, 0, client.right, client.bottom, memory, 0, 0, SRCCOPY);
        SelectObject(memory, old);
    } else {
        PaintContent(dc, client);
    }
    if (bitmap) DeleteObject(bitmap);
    if (memory) DeleteDC(memory);
    EndPaint(hwnd_, &paint);
}

void AccessConfirmationWindow::PaintContent(HDC dc, const RECT& client) {
    HBRUSH white = CreateSolidBrush(RGB(255, 255, 255));
    FillRect(dc, &client, white);
    DeleteObject(white);
    RECT header{0, 0, client.right, DpiScale(102, dpi_)};
    TRIVERTEX vertices[2] = {
        {header.left, header.top, 0x0F00, 0x7600, 0x6E00, 0},
        {header.right, header.bottom, 0x1640, 0x5F00, 0x5900, 0},
    };
    GRADIENT_RECT gradient{0, 1};
    GradientFill(dc, vertices, 2, &gradient, 1, GRADIENT_FILL_RECT_H);

    HICON icon = reinterpret_cast<HICON>(LoadImageW(
        reinterpret_cast<HINSTANCE>(GetWindowLongPtrW(hwnd_, GWLP_HINSTANCE)),
        MAKEINTRESOURCEW(IDI_APP_ICON), IMAGE_ICON, DpiScale(48, dpi_),
        DpiScale(48, dpi_), LR_SHARED));
    if (icon)
        DrawIconEx(dc, DpiScale(24, dpi_), DpiScale(24, dpi_), icon,
                   DpiScale(48, dpi_), DpiScale(48, dpi_), 0, nullptr, DI_NORMAL);
    RECT title{DpiScale(88, dpi_), DpiScale(17, dpi_), client.right - DpiScale(130, dpi_),
               DpiScale(51, dpi_)};
    DrawTextLine(dc, UiText(TextId::ClipboardAccessRequest), title, titleFont_, RGB(255, 255, 255),
         DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
    RECT subtitle = title;
    subtitle.top = DpiScale(51, dpi_);
    subtitle.bottom = DpiScale(78, dpi_);
    DrawTextLine(dc, UiText(TextId::AllowThisAccessToSensitiveData), subtitle, smallFont_,
         RGB(213, 242, 238), DT_LEFT | DT_VCENTER | DT_SINGLELINE);

    const ULONGLONG now = GetTickCount64();
    const DWORD seconds = now >= deadline_
                              ? 0
                              : static_cast<DWORD>((deadline_ - now + 999) /
                                                   1000);
    RECT countdown{client.right - DpiScale(112, dpi_), DpiScale(31, dpi_),
                   client.right - DpiScale(22, dpi_), DpiScale(69, dpi_)};
    FillRoundRect(dc, countdown, DpiScale(18, dpi_), RGB(11, 90, 84),
                RGB(58, 145, 136));
    DrawTextLine(dc, std::to_wstring(seconds) + UiText(TextId::S), countdown, smallFont_,
         RGB(255, 255, 255), DT_CENTER | DT_VCENTER | DT_SINGLELINE);

    const int left = DpiScale(24, dpi_);
    RECT heading{left, DpiScale(118, dpi_), client.right - left,
                 DpiScale(145, dpi_)};
    DrawTextLine(dc, OperationText(request_.operation), heading, headingFont_,
         RGB(28, 52, 49), DT_LEFT | DT_VCENTER | DT_SINGLELINE);

    RECT identity{left, DpiScale(151, dpi_), client.right - left,
                  DpiScale(235, dpi_)};
    FillRoundRect(dc, identity, DpiScale(12, dpi_), RGB(245, 249, 248),
                RGB(220, 230, 227));
    RECT line{identity.left + DpiScale(15, dpi_), identity.top + DpiScale(8, dpi_),
              identity.right - DpiScale(15, dpi_), identity.top + DpiScale(31, dpi_)};
    DrawTextLine(dc, UiText(TextId::Process), line, smallFont_, RGB(110, 129, 124),
         DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    line.left += DpiScale(82, dpi_);
    DrawTextLine(dc, request_.process + L"  (PID " +
                 std::to_wstring(request_.processId) + L")",
         line, uiFont_, RGB(31, 57, 53),
         DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
    line.left = identity.left + DpiScale(15, dpi_);
    line.top += DpiScale(24, dpi_);
    line.bottom += DpiScale(24, dpi_);
    DrawTextLine(dc, UiText(TextId::Source), line, smallFont_, RGB(110, 129, 124),
         DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    line.left += DpiScale(82, dpi_);
    std::wstring source = request_.sourceProcess.empty()
                              ? UiText(TextId::Unknown)
                              : request_.sourceProcess + L"  (PID " +
                                    std::to_wstring(request_.sourceProcessId) +
                                    L")";
    DrawTextLine(dc, source, line, uiFont_, RGB(31, 57, 53),
         DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
    line.left = identity.left + DpiScale(15, dpi_);
    line.top += DpiScale(24, dpi_);
    line.bottom += DpiScale(24, dpi_);
    DrawTextLine(dc, UiText(TextId::RuleFormat), line, smallFont_, RGB(110, 129, 124),
         DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    line.left += DpiScale(82, dpi_);
    DrawTextLine(dc,
         (request_.ruleName.empty() ? std::wstring(UiText(TextId::UnnamedRule))
                                    : request_.ruleName) +
             L"  ·  " + FormatText(request_.format),
         line, uiFont_, RGB(31, 57, 53),
         DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);

    RECT preview{left, DpiScale(250, dpi_), client.right - left,
                 DpiScale(348, dpi_)};
    FillRoundRect(dc, preview, DpiScale(12, dpi_), RGB(252, 248, 240),
                RGB(235, 220, 191));
    RECT previewLabel = preview;
    previewLabel.left += DpiScale(15, dpi_);
    previewLabel.top += DpiScale(7, dpi_);
    previewLabel.bottom = previewLabel.top + DpiScale(22, dpi_);
    DrawTextLine(dc, UiText(TextId::ContentPreview), previewLabel, smallFont_, RGB(145, 98, 24),
         DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    RECT previewText = preview;
    InflateRect(&previewText, -DpiScale(15, dpi_), -DpiScale(10, dpi_));
    previewText.top += DpiScale(22, dpi_);
    DrawTextLine(dc, DisplayPreview(request_.preview, request_.previewKind), previewText, uiFont_, RGB(72, 59, 36),
         DT_LEFT | DT_TOP | DT_WORDBREAK | DT_END_ELLIPSIS);
}

void AccessConfirmationWindow::DrawButton(
    const DRAWITEMSTRUCT& draw) const {
    RECT rect = draw.rcItem;
    HBRUSH background = CreateSolidBrush(RGB(255, 255, 255));
    FillRect(draw.hDC, &rect, background);
    DeleteObject(background);
    InflateRect(&rect, -1, -1);
    const bool allow = draw.CtlID == IDOK;
    const bool pressed = (draw.itemState & ODS_SELECTED) != 0;
    COLORREF fill = allow ? RGB(15, 118, 110) : RGB(255, 247, 247);
    COLORREF border = allow ? RGB(15, 118, 110) : RGB(220, 94, 94);
    COLORREF textColor = allow ? RGB(255, 255, 255) : RGB(177, 47, 47);
    if (pressed)
        fill = allow ? RGB(10, 91, 85) : RGB(250, 229, 229);
    FillRoundRect(draw.hDC, rect, DpiScale(10, dpi_), fill, border);
    wchar_t label[32] = {};
    GetWindowTextW(draw.hwndItem, label, _countof(label));
    DrawTextLine(draw.hDC, label, rect, uiFont_, textColor,
         DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    if (draw.itemState & ODS_FOCUS) {
        InflateRect(&rect, -DpiScale(5, dpi_), -DpiScale(5, dpi_));
        DrawFocusRect(draw.hDC, &rect);
    }
}

void AccessConfirmationWindow::Finish(bool allow, bool persistDecision) {
    if (completed_) return;
    completed_ = true;
    KillTimer(hwnd_, kCountdownTimer);
    const bool persist = persistDecision &&
        SendMessageW(persistCheck_, BM_GETCHECK, 0, 0) == BST_CHECKED;
    EnableWindow(allowButton_, FALSE);
    EnableWindow(blockButton_, FALSE);
    EnableWindow(persistCheck_, FALSE);
    const LPARAM flags = (allow ? 1 : 0) | (persist ? 2 : 0);
    if (!PostMessageW(owner_, kMsgConfirmationDecision, request_.id, flags))
        DestroyWindow(hwnd_);
}

} // namespace clip
