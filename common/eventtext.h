#pragma once
#include <cstdint>

namespace clip {
// Wire IDs are independent of UI language and cannot collide with user text.
enum class BuiltinRule : uint8_t {
    None, ShortcutProtection, CopyAllowed, PasteAllowed, CryptoReplacement,
    IgnoreCustomFormat
};
enum class PreviewKind : uint8_t { Text, CryptoAddress, Sensitive, Empty, Truncated };
}
