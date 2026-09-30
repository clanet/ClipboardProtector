#pragma once
#include <string>

namespace clip {
struct AppHotkeys {
    unsigned int copyModifiers = 5; // MOD_ALT | MOD_SHIFT
    unsigned int copyKey = 'C';
    unsigned int pasteModifiers = 5;
    unsigned int pasteKey = 'V';
    unsigned int shortcutOnlyModifiers = 3; // MOD_CONTROL | MOD_ALT
    unsigned int shortcutOnlyKey = 0x78; // F9
};

inline bool ValidHotkey(unsigned int modifiers, unsigned int key) {
    const bool supportedKey = (key >= 'A' && key <= 'Z') ||
                              (key >= '0' && key <= '9') ||
                              (key >= 0x70 && key <= 0x87); // F1..F24
    // Require Ctrl/Alt so ordinary typing cannot be swallowed by a hotkey.
    return supportedKey && !(modifiers & ~7u) && (modifiers & 3u);
}

inline bool ValidHotkeys(const AppHotkeys& keys) {
    return ValidHotkey(keys.copyModifiers, keys.copyKey) &&
           ValidHotkey(keys.pasteModifiers, keys.pasteKey) &&
           ValidHotkey(keys.shortcutOnlyModifiers, keys.shortcutOnlyKey) &&
           (keys.copyModifiers != keys.pasteModifiers || keys.copyKey != keys.pasteKey) &&
           (keys.copyModifiers != keys.shortcutOnlyModifiers || keys.copyKey != keys.shortcutOnlyKey) &&
           (keys.pasteModifiers != keys.shortcutOnlyModifiers || keys.pasteKey != keys.shortcutOnlyKey);
}

inline std::wstring HotkeyText(unsigned int modifiers, unsigned int key) {
    std::wstring text;
    if (modifiers & 2) text += L"Ctrl+";
    if (modifiers & 1) text += L"Alt+";
    if (modifiers & 4) text += L"Shift+";
    if (key >= 0x70 && key <= 0x87) text += L"F" + std::to_wstring(key - 0x70 + 1);
    else text += static_cast<wchar_t>(key);
    return text;
}
} // namespace clip
