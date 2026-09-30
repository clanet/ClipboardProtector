#include "i18n.h"
#include <atomic>

namespace clip {
namespace {
std::atomic<Language> current{Language::Chinese};
struct Translation { const wchar_t* chinese; const wchar_t* english; };
constexpr Translation strings[] = {
#define UI_TEXT(id, chinese, english) {chinese, english},
#include "ui_strings.inc"
#undef UI_TEXT
};
static_assert(_countof(strings) == static_cast<size_t>(TextId::TextCount));
}

Language SystemLanguage() noexcept {
    return PRIMARYLANGID(GetUserDefaultUILanguage()) == LANG_CHINESE
        ? Language::Chinese : Language::English;
}
Language CurrentLanguage() noexcept { return current.load(); }
void SetLanguage(Language language) noexcept { current.store(language); }
const wchar_t* LanguageCode(Language language) noexcept {
    return language == Language::English ? L"en" : L"zh-CN";
}
Language ParseLanguage(const std::wstring& code) noexcept {
    return code == L"en" ? Language::English : Language::Chinese;
}
const wchar_t* UiText(TextId id, Language language) noexcept {
    const auto index = static_cast<size_t>(id);
    if (index >= _countof(strings)) return L"";
    return language == Language::English ? strings[index].english : strings[index].chinese;
}
const wchar_t* UiText(TextId id) noexcept { return UiText(id, CurrentLanguage()); }
std::wstring UiFormat(TextId id, std::initializer_list<std::wstring> arguments) {
    const std::wstring pattern = UiText(id);
    std::wstring result;
    for (size_t i = 0; i < pattern.size(); ++i) {
        if (i + 2 < pattern.size() && pattern[i] == L'{' && pattern[i + 2] == L'}' &&
            pattern[i + 1] >= L'0' && pattern[i + 1] <= L'9') {
            const size_t index = pattern[i + 1] - L'0';
            if (index < arguments.size()) {
                result += *(arguments.begin() + index);
                i += 2;
                continue;
            }
        }
        result += pattern[i];
    }
    return result;
}
const wchar_t* UiFontFamily() noexcept {
    return CurrentLanguage() == Language::English ? L"Segoe UI" : L"Microsoft YaHei UI";
}
int UiMessageBox(HWND owner, const wchar_t* text, const wchar_t* caption, UINT type) {
    const WORD language = CurrentLanguage() == Language::English
        ? MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US)
        : MAKELANGID(LANG_CHINESE, SUBLANG_CHINESE_SIMPLIFIED);
    return MessageBoxExW(owner, text, caption, type, language);
}
std::wstring DisplayRuleName(const std::wstring& name, BuiltinRule kind) {
    switch (kind) {
    case BuiltinRule::ShortcutProtection: return UiText(TextId::BuiltinShortcutProtection);
    case BuiltinRule::CopyAllowed: return UiText(TextId::BuiltinCopyAllowed);
    case BuiltinRule::PasteAllowed: return UiText(TextId::BuiltinPasteAllowed);
    case BuiltinRule::CryptoReplacement: return UiText(TextId::BuiltinCryptoReplacement);
    case BuiltinRule::IgnoreCustomFormat: return UiText(TextId::BuiltinIgnoreCustom);
    default: return name;
    }
}
std::wstring DisplayPreview(const std::wstring& text, PreviewKind kind) {
    switch (kind) {
    case PreviewKind::CryptoAddress: return UiText(TextId::CryptoAddressHidden);
    case PreviewKind::Sensitive: return UiText(TextId::SensitiveContentHidden);
    case PreviewKind::Empty: return UiText(TextId::NoTextToDisplay);
    case PreviewKind::Truncated: return text + UiText(TextId::ContentTruncated);
    default: return text;
    }
}
} // namespace clip
