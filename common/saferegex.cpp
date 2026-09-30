#include "saferegex.h"

#include <algorithm>
#include <cwctype>
#include <limits>
#include <memory>
#include <utility>

namespace clip {
namespace {

constexpr unsigned int kUnlimited = (std::numeric_limits<unsigned int>::max)();
constexpr unsigned int kMaxRepeat = 256;
constexpr size_t kMaxStates = 8192;

struct ClassTermNode {
    enum class Kind { Range, Digit, Word, Space } kind = Kind::Range;
    wchar_t first = 0;
    wchar_t last = 0;
    bool inverted = false;
};

struct Node {
    enum class Kind {
        Empty,
        Character,
        Any,
        CharacterClass,
        Concat,
        Alternate,
        Repeat,
        Begin,
        End,
        WordBoundary,
        NotWordBoundary,
    } kind = Kind::Empty;

    wchar_t character = 0;
    bool classNegated = false;
    std::vector<ClassTermNode> classTerms;
    std::vector<std::unique_ptr<Node>> children;
    std::unique_ptr<Node> child;
    unsigned int repeatMin = 0;
    unsigned int repeatMax = 0;
};

using NodePtr = std::unique_ptr<Node>;

NodePtr MakeNode(Node::Kind kind) {
    auto node = std::make_unique<Node>();
    node->kind = kind;
    return node;
}

class Parser {
public:
    explicit Parser(std::wstring_view pattern) : pattern_(pattern) {}

    NodePtr Parse() {
        NodePtr result = ParseExpression();
        if (!result || !error_.empty()) return nullptr;
        if (position_ != pattern_.size()) {
            SetError("unexpected closing parenthesis");
            return nullptr;
        }
        return result;
    }

    const std::wstring& error() const { return error_; }

private:
    struct ParsedClassTerm {
        ClassTermNode term;
        bool singleCharacter = false;
    };

    std::wstring_view pattern_;
    size_t position_ = 0;
    unsigned int captureGroups_ = 0;
    std::wstring error_;

    bool AtEnd() const { return position_ >= pattern_.size(); }
    wchar_t Peek(size_t offset = 0) const {
        return position_ + offset < pattern_.size()
                   ? pattern_[position_ + offset]
                   : L'\0';
    }
    wchar_t Take() { return AtEnd() ? L'\0' : pattern_[position_++]; }

    void SetError(const wchar_t* message) {
        if (error_.empty()) error_ = message;
    }

    void SetError(const char* message) {
        if (!error_.empty()) return;
        while (*message) error_.push_back(static_cast<unsigned char>(*message++));
    }

    NodePtr ParseExpression() {
        std::vector<NodePtr> alternatives;
        NodePtr first = ParseConcat();
        if (!first) return nullptr;
        alternatives.push_back(std::move(first));
        while (Peek() == L'|') {
            Take();
            NodePtr next = ParseConcat();
            if (!next) return nullptr;
            alternatives.push_back(std::move(next));
        }
        if (alternatives.size() == 1) return std::move(alternatives.front());
        NodePtr result = MakeNode(Node::Kind::Alternate);
        result->children = std::move(alternatives);
        return result;
    }

    NodePtr ParseConcat() {
        std::vector<NodePtr> sequence;
        while (!AtEnd() && Peek() != L')' && Peek() != L'|') {
            NodePtr item = ParseRepeated();
            if (!item) return nullptr;
            sequence.push_back(std::move(item));
        }
        if (sequence.empty()) return MakeNode(Node::Kind::Empty);
        if (sequence.size() == 1) return std::move(sequence.front());
        NodePtr result = MakeNode(Node::Kind::Concat);
        result->children = std::move(sequence);
        return result;
    }

    bool IsAssertion(const Node& node) const {
        return node.kind == Node::Kind::Begin || node.kind == Node::Kind::End ||
               node.kind == Node::Kind::WordBoundary ||
               node.kind == Node::Kind::NotWordBoundary;
    }

    NodePtr ParseRepeated() {
        NodePtr atom = ParseAtom();
        if (!atom) return nullptr;

        unsigned int minimum = 0;
        unsigned int maximum = 0;
        bool repeated = true;
        if (Peek() == L'*') {
            Take();
            maximum = kUnlimited;
        } else if (Peek() == L'+') {
            Take();
            minimum = 1;
            maximum = kUnlimited;
        } else if (Peek() == L'?') {
            Take();
            maximum = 1;
        } else if (Peek() == L'{') {
            if (!ParseBoundedRepeat(minimum, maximum)) return nullptr;
        } else {
            repeated = false;
        }
        if (!repeated) return atom;
        if (IsAssertion(*atom)) {
            SetError("assertions cannot be repeated");
            return nullptr;
        }
        if (Peek() == L'?') Take(); // Lazy and greedy forms are equivalent here.
        if (Peek() == L'*' || Peek() == L'+' || Peek() == L'?' ||
            Peek() == L'{') {
            SetError("stacked quantifiers are not supported");
            return nullptr;
        }
        NodePtr result = MakeNode(Node::Kind::Repeat);
        result->child = std::move(atom);
        result->repeatMin = minimum;
        result->repeatMax = maximum;
        return result;
    }

    bool ParseDecimal(unsigned int& value) {
        if (Peek() < L'0' || Peek() > L'9') return false;
        unsigned int parsed = 0;
        while (Peek() >= L'0' && Peek() <= L'9') {
            const unsigned int digit = static_cast<unsigned int>(Take() - L'0');
            if (parsed > (kMaxRepeat - digit) / 10) {
                SetError("repeat count exceeds 256");
                return false;
            }
            parsed = parsed * 10 + digit;
        }
        value = parsed;
        return true;
    }

    bool ParseBoundedRepeat(unsigned int& minimum, unsigned int& maximum) {
        Take();
        if (!ParseDecimal(minimum)) {
            if (error_.empty()) SetError("missing repeat count");
            return false;
        }
        maximum = minimum;
        if (Peek() == L',') {
            Take();
            if (Peek() == L'}') {
                maximum = kUnlimited;
            } else if (!ParseDecimal(maximum)) {
                if (error_.empty()) SetError("invalid repeat range");
                return false;
            }
        }
        if (Peek() != L'}') {
            SetError("unterminated repeat range");
            return false;
        }
        Take();
        if (maximum != kUnlimited && maximum < minimum) {
            SetError("repeat maximum is smaller than minimum");
            return false;
        }
        return true;
    }

    NodePtr ParseAtom() {
        if (AtEnd()) {
            SetError("missing expression");
            return nullptr;
        }
        const wchar_t value = Take();
        switch (value) {
        case L'(':
            return ParseGroup();
        case L'[':
            return ParseCharacterClass();
        case L'.':
            return MakeNode(Node::Kind::Any);
        case L'^':
            return MakeNode(Node::Kind::Begin);
        case L'$':
            return MakeNode(Node::Kind::End);
        case L'\\':
            return ParseEscape(false);
        case L')':
        case L'|':
        case L'*':
        case L'+':
        case L'?':
        case L'{':
        case L'}':
            SetError("unexpected regex metacharacter");
            return nullptr;
        default: {
            NodePtr node = MakeNode(Node::Kind::Character);
            node->character = value;
            return node;
        }
        }
    }

    NodePtr ParseGroup() {
        bool capturing = true;
        if (Peek() == L'?') {
            if (Peek(1) != L':') {
                SetError("lookaround and special groups are not supported");
                return nullptr;
            }
            Take();
            Take();
            capturing = false;
        }
        if (capturing && ++captureGroups_ > 64) {
            SetError("too many capture groups");
            return nullptr;
        }
        NodePtr result = ParseExpression();
        if (!result) return nullptr;
        if (Peek() != L')') {
            SetError("unterminated group");
            return nullptr;
        }
        Take();
        return result;
    }

    static bool IsHex(wchar_t value) {
        return (value >= L'0' && value <= L'9') ||
               (value >= L'a' && value <= L'f') ||
               (value >= L'A' && value <= L'F');
    }

    bool ParseHex(unsigned int digits, wchar_t& value) {
        unsigned int parsed = 0;
        for (unsigned int i = 0; i < digits; ++i) {
            const wchar_t current = Peek();
            if (!IsHex(current)) {
                SetError("invalid hexadecimal escape");
                return false;
            }
            Take();
            parsed *= 16;
            if (current >= L'0' && current <= L'9') parsed += current - L'0';
            else if (current >= L'a' && current <= L'f') parsed += current - L'a' + 10;
            else parsed += current - L'A' + 10;
        }
        value = static_cast<wchar_t>(parsed);
        return true;
    }

    NodePtr ClassNode(ClassTermNode::Kind kind, bool inverted = false) {
        NodePtr node = MakeNode(Node::Kind::CharacterClass);
        ClassTermNode term;
        term.kind = kind;
        term.inverted = inverted;
        node->classTerms.push_back(term);
        return node;
    }

    NodePtr ParseEscape(bool inClass) {
        if (AtEnd()) {
            SetError("trailing backslash");
            return nullptr;
        }
        const wchar_t escaped = Take();
        switch (escaped) {
        case L'd': return ClassNode(ClassTermNode::Kind::Digit);
        case L'D': return ClassNode(ClassTermNode::Kind::Digit, true);
        case L'w': return ClassNode(ClassTermNode::Kind::Word);
        case L'W': return ClassNode(ClassTermNode::Kind::Word, true);
        case L's': return ClassNode(ClassTermNode::Kind::Space);
        case L'S': return ClassNode(ClassTermNode::Kind::Space, true);
        case L'b':
            if (!inClass) return MakeNode(Node::Kind::WordBoundary);
            break;
        case L'B':
            if (!inClass) return MakeNode(Node::Kind::NotWordBoundary);
            SetError("unsupported escape in character class");
            return nullptr;
        case L'n': return LiteralNode(L'\n');
        case L'r': return LiteralNode(L'\r');
        case L't': return LiteralNode(L'\t');
        case L'f': return LiteralNode(L'\f');
        case L'v': return LiteralNode(L'\v');
        case L'x': {
            wchar_t value = 0;
            return ParseHex(2, value) ? LiteralNode(value) : nullptr;
        }
        case L'u': {
            wchar_t value = 0;
            return ParseHex(4, value) ? LiteralNode(value) : nullptr;
        }
        default:
            if (escaped >= L'0' && escaped <= L'9') {
                SetError("backreferences are not supported");
                return nullptr;
            }
            if ((escaped >= L'a' && escaped <= L'z') ||
                (escaped >= L'A' && escaped <= L'Z')) {
                SetError("unsupported escape sequence");
                return nullptr;
            }
            return LiteralNode(escaped);
        }
        return LiteralNode(L'\b');
    }

    NodePtr LiteralNode(wchar_t value) {
        NodePtr node = MakeNode(Node::Kind::Character);
        node->character = value;
        return node;
    }

    bool ClassTermFromNode(NodePtr node, ParsedClassTerm& parsed) {
        if (!node) return false;
        if (node->kind == Node::Kind::Character) {
            parsed.term.kind = ClassTermNode::Kind::Range;
            parsed.term.first = node->character;
            parsed.term.last = node->character;
            parsed.singleCharacter = true;
            return true;
        }
        if (node->kind != Node::Kind::CharacterClass ||
            node->classTerms.size() != 1)
            return false;
        parsed.term = node->classTerms.front();
        return true;
    }

    bool ParseClassTerm(ParsedClassTerm& parsed) {
        if (AtEnd()) return false;
        if (Peek() == L'\\') {
            Take();
            return ClassTermFromNode(ParseEscape(true), parsed);
        }
        parsed.term.kind = ClassTermNode::Kind::Range;
        parsed.term.first = Take();
        parsed.term.last = parsed.term.first;
        parsed.singleCharacter = true;
        return true;
    }

    NodePtr ParseCharacterClass() {
        NodePtr result = MakeNode(Node::Kind::CharacterClass);
        if (Peek() == L'^') {
            Take();
            result->classNegated = true;
        }
        bool hasTerm = false;
        while (!AtEnd()) {
            if (Peek() == L']' && hasTerm) {
                Take();
                return result;
            }
            ParsedClassTerm first;
            if (!ParseClassTerm(first)) {
                if (error_.empty()) SetError("invalid character class");
                return nullptr;
            }
            hasTerm = true;
            if (Peek() == L'-' && Peek(1) != L']' && Peek(1) != L'\0') {
                Take();
                ParsedClassTerm last;
                if (!ParseClassTerm(last) || !first.singleCharacter ||
                    !last.singleCharacter || first.term.first > last.term.first) {
                    SetError("invalid character class range");
                    return nullptr;
                }
                first.term.last = last.term.first;
            }
            result->classTerms.push_back(first.term);
        }
        SetError("unterminated character class");
        return nullptr;
    }
};

struct PatchRef {
    int state = -1;
    bool second = false;
};

struct Fragment {
    int start = -1;
    std::vector<PatchRef> exits;
};

} // namespace

class SafeRegexCompiler {
public:
    explicit SafeRegexCompiler(SafeRegex& output) : output_(output) {}

    bool Compile(const Node& root, std::wstring& error) {
        Fragment expression = CompileNode(root);
        if (!ok_) {
            error = L"regular expression expands beyond the safe state limit";
            return false;
        }
        const int match = AddState(SafeRegex::Op::Match);
        if (match < 0) {
            error = L"regular expression expands beyond the safe state limit";
            return false;
        }
        Patch(expression.exits, match);
        output_.start_ = expression.start;
        return true;
    }

private:
    SafeRegex& output_;
    bool ok_ = true;

    int AddState(SafeRegex::Op op) {
        if (!ok_ || output_.states_.size() >= kMaxStates) {
            ok_ = false;
            return -1;
        }
        SafeRegex::State state;
        state.op = op;
        output_.states_.push_back(std::move(state));
        return static_cast<int>(output_.states_.size() - 1);
    }

    void Patch(const std::vector<PatchRef>& exits, int target) {
        for (const PatchRef& patch : exits) {
            if (patch.state < 0 ||
                static_cast<size_t>(patch.state) >= output_.states_.size()) {
                ok_ = false;
                return;
            }
            if (patch.second)
                output_.states_[patch.state].out1 = target;
            else
                output_.states_[patch.state].out = target;
        }
    }

    Fragment Epsilon() {
        const int state = AddState(SafeRegex::Op::Jump);
        return {state, {{state, false}}};
    }

    Fragment Concatenate(Fragment left, Fragment right) {
        Patch(left.exits, right.start);
        return {left.start, std::move(right.exits)};
    }

    Fragment Optional(const Node& child) {
        Fragment body = CompileNode(child);
        const int split = AddState(SafeRegex::Op::Split);
        if (split >= 0) output_.states_[split].out = body.start;
        body.exits.push_back({split, true});
        return {split, std::move(body.exits)};
    }

    Fragment Star(const Node& child) {
        Fragment body = CompileNode(child);
        const int split = AddState(SafeRegex::Op::Split);
        if (split >= 0) output_.states_[split].out = body.start;
        Patch(body.exits, split);
        return {split, {{split, true}}};
    }

    Fragment CompileRepeat(const Node& node) {
        Fragment result = Epsilon();
        for (unsigned int i = 0; i < node.repeatMin && ok_; ++i)
            result = Concatenate(std::move(result), CompileNode(*node.child));
        if (node.repeatMax == kUnlimited) {
            result = Concatenate(std::move(result), Star(*node.child));
        } else {
            for (unsigned int i = node.repeatMin;
                 i < node.repeatMax && ok_; ++i)
                result = Concatenate(std::move(result), Optional(*node.child));
        }
        return result;
    }

    Fragment CompileNode(const Node& node) {
        switch (node.kind) {
        case Node::Kind::Empty:
            return Epsilon();
        case Node::Kind::Character: {
            const int state = AddState(SafeRegex::Op::Character);
            if (state >= 0) output_.states_[state].character = node.character;
            return {state, {{state, false}}};
        }
        case Node::Kind::Any: {
            const int state = AddState(SafeRegex::Op::Any);
            return {state, {{state, false}}};
        }
        case Node::Kind::CharacterClass: {
            const int state = AddState(SafeRegex::Op::CharacterClass);
            if (state >= 0) {
                auto& compiled = output_.states_[state];
                compiled.classNegated = node.classNegated;
                try {
                    compiled.classTerms.reserve(node.classTerms.size());
                    for (const ClassTermNode& term : node.classTerms) {
                        SafeRegex::ClassTerm converted;
                        converted.kind =
                            term.kind == ClassTermNode::Kind::Range
                                ? SafeRegex::ClassKind::Range
                                : term.kind == ClassTermNode::Kind::Digit
                                      ? SafeRegex::ClassKind::Digit
                                      : term.kind == ClassTermNode::Kind::Word
                                            ? SafeRegex::ClassKind::Word
                                            : SafeRegex::ClassKind::Space;
                        converted.first = term.first;
                        converted.last = term.last;
                        converted.inverted = term.inverted;
                        compiled.classTerms.push_back(converted);
                    }
                } catch (...) {
                    ok_ = false;
                }
            }
            return {state, {{state, false}}};
        }
        case Node::Kind::Concat: {
            Fragment result = Epsilon();
            for (const auto& child : node.children)
                result = Concatenate(std::move(result), CompileNode(*child));
            return result;
        }
        case Node::Kind::Alternate: {
            Fragment result = CompileNode(*node.children.front());
            for (size_t i = 1; i < node.children.size(); ++i) {
                Fragment right = CompileNode(*node.children[i]);
                const int split = AddState(SafeRegex::Op::Split);
                if (split >= 0) {
                    output_.states_[split].out = result.start;
                    output_.states_[split].out1 = right.start;
                }
                result.start = split;
                result.exits.insert(result.exits.end(), right.exits.begin(),
                                    right.exits.end());
            }
            return result;
        }
        case Node::Kind::Repeat:
            return CompileRepeat(node);
        case Node::Kind::Begin:
        case Node::Kind::End:
        case Node::Kind::WordBoundary:
        case Node::Kind::NotWordBoundary: {
            const SafeRegex::Op op =
                node.kind == Node::Kind::Begin
                    ? SafeRegex::Op::Begin
                    : node.kind == Node::Kind::End
                          ? SafeRegex::Op::End
                          : node.kind == Node::Kind::WordBoundary
                                ? SafeRegex::Op::WordBoundary
                                : SafeRegex::Op::NotWordBoundary;
            const int state = AddState(op);
            return {state, {{state, false}}};
        }
        }
        ok_ = false;
        return {};
    }
};

bool SafeRegex::Compile(std::wstring_view pattern, bool ignoreCase,
                        std::wstring* error) {
    states_.clear();
    start_ = -1;
    ignoreCase_ = ignoreCase;
    valid_ = false;
    try {
        Parser parser(pattern);
        NodePtr root = parser.Parse();
        if (!root) {
            if (error) *error = parser.error();
            return false;
        }
        std::wstring compileError;
        SafeRegexCompiler compiler(*this);
        if (!compiler.Compile(*root, compileError)) {
            states_.clear();
            start_ = -1;
            if (error) *error = std::move(compileError);
            return false;
        }
        valid_ = true;
        if (error) error->clear();
        return true;
    } catch (...) {
        states_.clear();
        start_ = -1;
        if (error) *error = L"not enough memory to compile expression";
        return false;
    }
}

namespace {

wchar_t Fold(wchar_t value, bool ignoreCase) noexcept {
    return ignoreCase ? static_cast<wchar_t>(std::towlower(value)) : value;
}

bool IsWord(wchar_t value) noexcept {
    return (value >= L'a' && value <= L'z') ||
           (value >= L'A' && value <= L'Z') ||
           (value >= L'0' && value <= L'9') || value == L'_';
}

bool IsSpace(wchar_t value) noexcept {
    return value == L' ' || value == L'\f' || value == L'\n' ||
           value == L'\r' || value == L'\t' || value == L'\v';
}

} // namespace

bool SafeRegex::Search(std::wstring_view text, bool* completed,
                       size_t* workBudget) const noexcept {
    if (completed) *completed = false;
    if (!valid_ || start_ < 0) return false;
    auto consume = [&]() -> bool {
        if (!workBudget) return true;
        if (*workBudget == 0) return false;
        --*workBudget;
        return true;
    };
    try {
        std::vector<int> current;
        std::vector<int> next;
        std::vector<int> stack;
        std::vector<unsigned char> currentSeen(states_.size(), 0);
        std::vector<unsigned char> nextSeen(states_.size(), 0);
        current.reserve(states_.size());
        next.reserve(states_.size());
        stack.reserve(states_.size());

        auto addState = [&](int initial, size_t position,
                            std::vector<int>& output,
                            std::vector<unsigned char>& seen) -> bool {
            stack.clear();
            stack.push_back(initial);
            while (!stack.empty()) {
                if (!consume()) return false;
                const int index = stack.back();
                stack.pop_back();
                if (index < 0 || static_cast<size_t>(index) >= states_.size())
                    continue;
                if (seen[static_cast<size_t>(index)]) continue;
                seen[static_cast<size_t>(index)] = 1;
                const State& state = states_[static_cast<size_t>(index)];
                switch (state.op) {
                case Op::Jump:
                    stack.push_back(state.out);
                    break;
                case Op::Split:
                    stack.push_back(state.out1);
                    stack.push_back(state.out);
                    break;
                case Op::Begin:
                    if (position == 0) stack.push_back(state.out);
                    break;
                case Op::End:
                    if (position == text.size()) stack.push_back(state.out);
                    break;
                case Op::WordBoundary:
                case Op::NotWordBoundary: {
                    const bool before = position > 0 && IsWord(text[position - 1]);
                    const bool after = position < text.size() && IsWord(text[position]);
                    const bool boundary = before != after;
                    if ((state.op == Op::WordBoundary && boundary) ||
                        (state.op == Op::NotWordBoundary && !boundary))
                        stack.push_back(state.out);
                    break;
                }
                case Op::Match:
                    return true;
                default:
                    output.push_back(index);
                    break;
                }
            }
            return false;
        };

        auto classMatches = [&](const State& state, wchar_t value) noexcept {
            bool matched = false;
            for (const ClassTerm& term : state.classTerms) {
                bool termMatched = false;
                switch (term.kind) {
                case ClassKind::Range: {
                    const wchar_t folded = Fold(value, ignoreCase_);
                    const wchar_t first = Fold(term.first, ignoreCase_);
                    const wchar_t last = Fold(term.last, ignoreCase_);
                    termMatched = folded >= first && folded <= last;
                    break;
                }
                case ClassKind::Digit:
                    termMatched = value >= L'0' && value <= L'9';
                    break;
                case ClassKind::Word:
                    termMatched = IsWord(value);
                    break;
                case ClassKind::Space:
                    termMatched = IsSpace(value);
                    break;
                }
                if (term.inverted) termMatched = !termMatched;
                if (termMatched) {
                    matched = true;
                    break;
                }
            }
            return state.classNegated ? !matched : matched;
        };

        if (addState(start_, 0, current, currentSeen)) {
            if (completed) *completed = true;
            return true;
        }
        for (size_t position = 0;; ++position) {
            if (!consume()) return false;
            if (position > 0 &&
                addState(start_, position, current, currentSeen))
            {
                if (completed) *completed = true;
                return true;
            }
            if (position == text.size()) break;

            next.clear();
            std::fill(nextSeen.begin(), nextSeen.end(),
                      static_cast<unsigned char>(0));
            for (int index : current) {
                if (!consume()) return false;
                const State& state = states_[static_cast<size_t>(index)];
                bool matches = false;
                if (state.op == Op::Character) {
                    matches = Fold(state.character, ignoreCase_) ==
                              Fold(text[position], ignoreCase_);
                } else if (state.op == Op::Any) {
                    const wchar_t value = text[position];
                    matches = value != L'\r' && value != L'\n' &&
                              value != static_cast<wchar_t>(0x2028) &&
                              value != static_cast<wchar_t>(0x2029);
                } else if (state.op == Op::CharacterClass) {
                    matches = classMatches(state, text[position]);
                }
                if (matches &&
                    addState(state.out, position + 1, next, nextSeen))
                {
                    if (completed) *completed = true;
                    return true;
                }
            }
            current.swap(next);
            currentSeen.swap(nextSeen);
        }
        if (completed) *completed = true;
        return false;
    } catch (...) {
        return false;
    }
}


} // namespace clip
