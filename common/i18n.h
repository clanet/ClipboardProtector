#pragma once
#include <windows.h>
#include <string>
#include <initializer_list>
#include "eventtext.h"

namespace clip {
enum class Language { Chinese, English };
enum class TextId {
#define UI_TEXT(id, chinese, english) id,
#include "ui_strings.inc"
#undef UI_TEXT
    TextCount
};

Language SystemLanguage() noexcept;
Language CurrentLanguage() noexcept;
void SetLanguage(Language language) noexcept;
const wchar_t* LanguageCode(Language language) noexcept;
Language ParseLanguage(const std::wstring& code) noexcept;
const wchar_t* UiText(TextId id) noexcept;
const wchar_t* UiText(TextId id, Language language) noexcept;
std::wstring UiFormat(TextId id, std::initializer_list<std::wstring> arguments);
const wchar_t* UiFontFamily() noexcept;
int UiMessageBox(HWND owner, const wchar_t* text, const wchar_t* caption, UINT type);
std::wstring DisplayRuleName(const std::wstring& name, BuiltinRule kind);
std::wstring DisplayPreview(const std::wstring& text, PreviewKind kind);
} // namespace clip
