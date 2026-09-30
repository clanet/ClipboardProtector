#include "minjson.h"
#include <charconv>
#include <cwchar>
#include <string_view>

namespace minjson {

namespace {

class Parser {
public:
    explicit Parser(const std::wstring& s) : s_(s) {}

    Value Run() {
        SkipWs();
        Value v = ParseValue();
        if (!ok_) return Value();
        SkipWs();
        if (pos_ != s_.size()) return Value();   // 尾部有多余内容视为损坏
        return v;
    }

private:
    const std::wstring& s_;
    size_t pos_ = 0;
    bool ok_ = true;
    int depth_ = 0;

    class DepthScope {
    public:
        explicit DepthScope(Parser& parser) : parser_(parser) {
            if (parser_.depth_ >= 64) {
                parser_.Fail();
            } else {
                ++parser_.depth_;
                entered_ = true;
            }
        }
        ~DepthScope() {
            if (entered_) --parser_.depth_;
        }
        bool entered() const { return entered_; }

    private:
        Parser& parser_;
        bool entered_ = false;
    };

    void Fail() { ok_ = false; }
    bool Eof() const { return pos_ >= s_.size(); }
    wchar_t Cur() const { return Eof() ? L'\0' : s_[pos_]; }

    void SkipWs() {
        while (!Eof()) {
            wchar_t c = Cur();
            if (c == L' ' || c == L'\t' || c == L'\n' || c == L'\r') ++pos_;
            else break;
        }
    }

    bool Eat(wchar_t c) {
        if (Cur() == c) { ++pos_; return true; }
        Fail();
        return false;
    }

    Value ParseValue() {
        if (Eof()) { Fail(); return Value(); }
        switch (Cur()) {
        case L'{': return ParseObject();
        case L'[': return ParseArray();
        case L'"': return Value::Str(ParseString());
        case L't': Expect(L"true");  return Value::Bool(true);
        case L'f': Expect(L"false"); return Value::Bool(false);
        case L'n': Expect(L"null");  return Value();
        default:   return ParseNumber();
        }
    }

    void Expect(std::wstring_view word) {
        if (s_.compare(pos_, word.size(), word.data(), word.size()) != 0) {
            Fail();
            return;
        }
        pos_ += word.size();
    }

    Value ParseObject() {
        DepthScope depth(*this);
        if (!depth.entered()) return Value();
        ++pos_;   // {
        Object obj;
        SkipWs();
        if (Cur() == L'}') { ++pos_; return Value::Obj(); }
        while (ok_) {
            SkipWs();
            std::wstring key = ParseString();
            if (!ok_) break;
            SkipWs();
            Eat(L':');
            if (!ok_) break;
            SkipWs();
            Value val = ParseValue();
            if (!ok_) break;
            obj[key] = std::move(val);
            SkipWs();
            if (Cur() == L',') { ++pos_; continue; }
            if (Cur() == L'}') { ++pos_; break; }
            Fail();
        }
        if (!ok_) return Value();
        auto o = Value::Obj();
        o.obj() = std::move(obj);
        return o;
    }

    Value ParseArray() {
        DepthScope depth(*this);
        if (!depth.entered()) return Value();
        ++pos_;   // [
        Array arr;
        SkipWs();
        if (Cur() == L']') { ++pos_; return Value::Arr(); }
        while (ok_) {
            Value v = ParseValue();
            if (!ok_) break;
            arr.push_back(std::move(v));
            SkipWs();
            if (Cur() == L',') {
                ++pos_;
                // JSON permits whitespace between a comma and the next item.
                SkipWs();
                continue;
            }
            if (Cur() == L']') { ++pos_; break; }
            Fail();
        }
        if (!ok_) return Value();
        auto a = Value::Arr();
        a.array() = std::move(arr);
        return a;
    }

    std::wstring ParseString() {
        std::wstring out;
        if (!Eat(L'"')) return out;
        while (ok_) {
            if (Eof()) { Fail(); break; }
            wchar_t c = Cur();
            if (c == L'"') { ++pos_; break; }
            if (c == L'\\') {
                ++pos_;
                wchar_t e = Cur();
                ++pos_;
                switch (e) {
                case L'"': case L'\\': case L'/': out.push_back(e); break;
                case L'b': out.push_back(L'\b'); break;
                case L'f': out.push_back(L'\f'); break;
                case L'n': out.push_back(L'\n'); break;
                case L'r': out.push_back(L'\r'); break;
                case L't': out.push_back(L'\t'); break;
                case L'u': out.push_back(ParseU16()); break;
                default: Fail(); break;
                }
            } else if (c < 0x20) {
                // JSON requires every control character in a string to be escaped.
                Fail();
            } else {
                out.push_back(c);
                ++pos_;
            }
        }
        return out;
    }

    // 解析 \uXXXX；代理对自动合并为一个码点
    wchar_t ParseU16() {
        unsigned v = 0;
        for (int i = 0; i < 4 && ok_; ++i) {
            wchar_t c = Cur();
            unsigned d;
            if (c >= L'0' && c <= L'9') d = (unsigned)(c - L'0');
            else if (c >= L'a' && c <= L'f') d = (unsigned)(c - L'a' + 10);
            else if (c >= L'A' && c <= L'F') d = (unsigned)(c - L'A' + 10);
            else { Fail(); return L'?'; }
            v = v * 16 + d;
            ++pos_;
        }
        return (wchar_t)v;
    }

    Value ParseNumber() {
        size_t start = pos_;
        if (Cur() == L'-') ++pos_;
        if (Cur() == L'0') {
            ++pos_;
            // A zero may not be followed by another integer digit.
            if (Cur() >= L'0' && Cur() <= L'9') {
                Fail();
                return Value();
            }
        } else if (Cur() >= L'1' && Cur() <= L'9') {
            while (Cur() >= L'0' && Cur() <= L'9') ++pos_;
        } else {
            Fail();
            return Value();
        }
        if (Cur() == L'.') {
            ++pos_;
            const size_t fractionStart = pos_;
            while (Cur() >= L'0' && Cur() <= L'9') ++pos_;
            if (pos_ == fractionStart) {
                Fail();
                return Value();
            }
        }
        if (Cur() == L'e' || Cur() == L'E') {
            ++pos_;
            if (Cur() == L'+' || Cur() == L'-') ++pos_;
            const size_t exponentStart = pos_;
            while (Cur() >= L'0' && Cur() <= L'9') ++pos_;
            if (pos_ == exponentStart) {
                Fail();
                return Value();
            }
        }
        if (pos_ == start) { Fail(); return Value(); }
        std::wstring num = s_.substr(start, pos_ - start);
        wchar_t* end = nullptr;
        double d = wcstod(num.c_str(), &end);
        if (end != num.c_str() + num.size() || !std::isfinite(d)) {
            Fail();
            return Value();
        }
        return Value::Num(d);
    }
};

void DumpString(const std::wstring& s, std::wstring& out) {
    out.push_back(L'"');
    for (wchar_t c : s) {
        switch (c) {
        case L'"':  out += L"\\\""; break;
        case L'\\': out += L"\\\\"; break;
        case L'\b': out += L"\\b"; break;
        case L'\f': out += L"\\f"; break;
        case L'\n': out += L"\\n"; break;
        case L'\r': out += L"\\r"; break;
        case L'\t': out += L"\\t"; break;
        default:
            if (c < 0x20) {
                wchar_t buf[8];
                swprintf(buf, 8, L"\\u%04x", (unsigned)c);
                out += buf;
            } else {
                out.push_back(c);
            }
        }
    }
    out.push_back(L'"');
}

void DumpIndent(int depth, std::wstring& out) {
    out.append((size_t)depth * 2, L' ');
}

bool IsCompound(const Value& v) {
    auto t = v.type();
    return t == Value::T::Obj || t == Value::T::Arr;
}

bool DumpValue(const Value& v, int depth, std::wstring& out);

// 复合类型输出为多行缩进格式，便于人工编辑配置
bool DumpCompound(const Value& v, int depth, std::wstring& out) {
    out.push_back(v.type() == Value::T::Obj ? L'{' : L'[');
    bool first = true;
    if (v.type() == Value::T::Obj) {
        for (const auto& [key, val] : v.asObject()) {
            if (!first) out.push_back(L',');
            first = false;
            out.push_back(L'\n');
            DumpIndent(depth + 1, out);
            DumpString(key, out);
            out += L": ";
            if (!DumpValue(val, depth + 1, out)) return false;
        }
    } else {
        for (const auto& val : v.arr()) {
            if (!first) out.push_back(L',');
            first = false;
            out.push_back(L'\n');
            DumpIndent(depth + 1, out);
            if (!DumpValue(val, depth + 1, out)) return false;
        }
    }
    if (!first) out.push_back(L'\n');
    DumpIndent(depth, out);
    out.push_back(v.type() == Value::T::Obj ? L'}' : L']');
    return true;
}

bool DumpValue(const Value& v, int depth, std::wstring& out) {
    switch (v.type()) {
    case Value::T::Null: out += L"null"; return true;
    case Value::T::Bool: out += v.asBool() ? L"true" : L"false"; return true;
    case Value::T::Num: {
        const double number = v.asDouble();
        if (!std::isfinite(number)) return false;
        char buffer[64] = {};
        auto result = std::to_chars(buffer, buffer + sizeof(buffer), number,
                                    std::chars_format::general, 17);
        if (result.ec != std::errc()) return false;
        for (char* p = buffer; p != result.ptr; ++p)
            out.push_back((wchar_t)(unsigned char)*p);
        return true;
    }
    case Value::T::Str: DumpString(v.asStr(), out); return true;
    default: return DumpCompound(v, depth, out);
    }
}

} // namespace

Value Parse(const std::wstring& text) { return Parser(text).Run(); }

std::wstring Dump(const Value& v) {
    std::wstring out;
    if (!DumpValue(v, 0, out)) return {};
    out.push_back(L'\n');
    return out;
}

} // namespace minjson
