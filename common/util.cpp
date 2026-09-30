#include "util.h"


namespace clip {

std::wstring ToLower(std::wstring_view s) {
    std::wstring out;
    out.reserve(s.size());
    for (wchar_t c : s) {
        if (c >= L'A' && c <= L'Z') c = static_cast<wchar_t>(c - L'A' + L'a');
        out.push_back(c);
    }
    return out;
}


bool WildcardMatchBounded(std::wstring_view pat, std::wstring_view str,
                          size_t& budget, bool& exhausted) {
    exhausted = false;
    size_t p = 0, s = 0;
    size_t starP = std::wstring_view::npos, starS = 0;
    while (s < str.size()) {
        if (budget == 0) {
            exhausted = true;
            return false;
        }
        --budget;
        if (p < pat.size() && (pat[p] == L'?' || pat[p] == str[s])) {
            ++p;
            ++s;
        } else if (p < pat.size() && pat[p] == L'*') {
            starP = p++;
            starS = s;
        } else if (starP != std::wstring_view::npos) {
            p = starP + 1;
            s = ++starS;
        } else {
            return false;
        }
    }
    while (p < pat.size() && pat[p] == L'*') {
        if (budget == 0) {
            exhausted = true;
            return false;
        }
        --budget;
        ++p;
    }
    return p == pat.size();
}

bool WildcardMatch(std::wstring_view pattern, std::wstring_view str) {
    size_t budget = 1000000;
    bool exhausted = false;
    return WildcardMatchBounded(pattern, str, budget, exhausted) && !exhausted;
}

unsigned long long FnvHash64(std::wstring_view s) {
    unsigned long long h = 14695981039346656037ull;
    for (wchar_t c : s) {
        // 按字节混合，保证同一内容跨进程一致
        const auto* bytes = reinterpret_cast<const unsigned char*>(&c);
        for (int i = 0; i < 2; ++i) {
            h ^= bytes[i];
            h *= 1099511628211ull;
        }
    }
    return h;
}

} // namespace clip
