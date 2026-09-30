#pragma once
#include <windows.h>
#include <cstddef>
#include <memory>
#include "pipeserver.h"

namespace clip {

constexpr wchar_t kConfirmationWindowClass[] =
    L"ClipProtectorConfirmWnd";
// “一直这样”复选框：勾选后按钮点击的决策会写成长久规则（放行或阻止）。
constexpr int kConfirmationPersistDecision = 4103;
// 阻止按钮。与 Escape（IDCANCEL）区分：只有按钮点击才写规则，
// 超时和关闭窗口只作用于本次访问。
constexpr int kConfirmationBlock = 4104;

class AccessConfirmationWindow {
public:
    static std::unique_ptr<AccessConfirmationWindow> Create(
        HINSTANCE instance, HWND owner, AccessConfirmationRequest request,
        size_t cascadeIndex);
    ~AccessConfirmationWindow();

    HWND hwnd() const { return hwnd_; }
    void ApplyLanguage();
    const AccessConfirmationRequest& request() const { return request_; }

private:
    AccessConfirmationWindow(HWND owner, AccessConfirmationRequest request);
    bool CreateWindowInstance(HINSTANCE instance, size_t cascadeIndex);
    static LRESULT CALLBACK WndProcStatic(HWND, UINT, WPARAM, LPARAM);
    LRESULT WndProc(UINT message, WPARAM wParam, LPARAM lParam);
    void CreateFonts();
    void Layout();
    void Paint();
    void PaintContent(HDC dc, const RECT& client);
    void DrawButton(const DRAWITEMSTRUCT& draw) const;
    void Finish(bool allow, bool persistDecision);

    HWND hwnd_ = nullptr;
    HWND owner_ = nullptr;
    HWND allowButton_ = nullptr;
    HWND blockButton_ = nullptr;
    HWND persistCheck_ = nullptr;
    AccessConfirmationRequest request_;
    UINT dpi_ = 96;
    ULONGLONG deadline_ = 0;
    bool completed_ = false;
    HFONT titleFont_ = nullptr;
    HFONT headingFont_ = nullptr;
    HFONT uiFont_ = nullptr;
    HFONT smallFont_ = nullptr;
};

} // namespace clip
