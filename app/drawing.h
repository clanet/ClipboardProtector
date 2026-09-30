#pragma once
#include <windows.h>
#include <string_view>

namespace clip {

inline int DpiScale(int value, UINT dpi) {
    return MulDiv(value, static_cast<int>(dpi), 96);
}

inline void FillRoundRect(HDC dc, const RECT& rect, int radius,
                          COLORREF fill, COLORREF border) {
    HBRUSH brush = CreateSolidBrush(fill);
    HPEN pen = CreatePen(PS_SOLID, 1, border);
    HGDIOBJ oldBrush = SelectObject(dc, brush);
    HGDIOBJ oldPen = SelectObject(dc, pen);
    RoundRect(dc, rect.left, rect.top, rect.right, rect.bottom, radius, radius);
    SelectObject(dc, oldPen);
    SelectObject(dc, oldBrush);
    DeleteObject(pen);
    DeleteObject(brush);
}

inline void DrawTextLine(HDC dc, std::wstring_view text, RECT rect,
                         HFONT font, COLORREF color, UINT format) {
    HGDIOBJ oldFont = SelectObject(dc, font);
    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, color);
    DrawTextW(dc, text.data(), static_cast<int>(text.size()), &rect,
              format | DT_NOPREFIX);
    SelectObject(dc, oldFont);
}

} // namespace clip
