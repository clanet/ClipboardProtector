#pragma once

#include <string>
#include <string_view>
#include <vector>

namespace clip {

class SafeRegexCompiler;

// A Thompson-NFA regex matcher. Matching time is linear in input length and
// compiled state count; unsupported constructs are rejected during compile.
// \\d, \\w, \\s and word boundaries are ASCII-only.
class SafeRegex {
public:
    bool Compile(std::wstring_view pattern, bool ignoreCase,
                 std::wstring* error = nullptr);
    bool Search(std::wstring_view text, bool* completed = nullptr,
                size_t* workBudget = nullptr) const noexcept;

    bool valid() const noexcept { return valid_; }
    size_t stateCount() const noexcept { return states_.size(); }

private:
    friend class SafeRegexCompiler;

    enum class Op : unsigned char {
        Jump,
        Split,
        Character,
        Any,
        CharacterClass,
        Begin,
        End,
        WordBoundary,
        NotWordBoundary,
        Match,
    };

    enum class ClassKind : unsigned char { Range, Digit, Word, Space };

    struct ClassTerm {
        ClassKind kind = ClassKind::Range;
        wchar_t first = 0;
        wchar_t last = 0;
        bool inverted = false;
    };

    struct State {
        Op op = Op::Jump;
        int out = -1;
        int out1 = -1;
        wchar_t character = 0;
        bool classNegated = false;
        std::vector<ClassTerm> classTerms;
    };

    std::vector<State> states_;
    int start_ = -1;
    bool ignoreCase_ = false;
    bool valid_ = false;
};

} // namespace clip
