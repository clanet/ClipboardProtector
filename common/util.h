#pragma once
#include <string>
#include <string_view>

namespace clip {

// 小写化拷贝（ASCII + 简单映射即可满足进程名匹配场景）
std::wstring ToLower(std::wstring_view s);

// 有界匹配：budget 为剩余工作量；耗尽时 exhausted=true，调用方应 fail-open。
bool WildcardMatchBounded(std::wstring_view pattern, std::wstring_view str,
                          size_t& budget, bool& exhausted);

// 兼容旧调用的通配符匹配。
bool WildcardMatch(std::wstring_view pattern, std::wstring_view str);

// FNV-1a 64 位哈希，用于剪贴板内容去重
unsigned long long FnvHash64(std::wstring_view s);

} // namespace clip
