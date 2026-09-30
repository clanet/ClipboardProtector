#pragma once
// 极简 JSON：仅覆盖本项目 config.json 所需子集（对象/数组/字符串/数字/布尔）。
// 不追求通用性，遵循 KISS；文件为 UTF-8。
#include <map>
#include <cmath>
#include <limits>
#include <memory>
#include <string>
#include <vector>

namespace minjson {

class Value;
using Object = std::map<std::wstring, Value>;
using Array = std::vector<Value>;

class Value {
public:
    enum class T { Null, Bool, Num, Str, Arr, Obj };

    Value() : t_(T::Null) {}
    static Value Obj() { Value v; v.t_ = T::Obj; return v; }
    static Value Arr() { Value v; v.t_ = T::Arr; return v; }
    static Value Num(double d) { Value v; v.t_ = T::Num; v.num_ = d; return v; }
    static Value Bool(bool b) { Value v; v.t_ = T::Bool; v.b_ = b; return v; }
    static Value Str(std::wstring s) { Value v; v.t_ = T::Str; v.str_ = std::move(s); return v; }

    T type() const { return t_; }
    bool isNull() const { return t_ == T::Null; }

    // 类型不匹配时返回缺省值，绝不抛异常
    bool asBool(bool def = false) const { return t_ == T::Bool ? b_ : def; }
    double asDouble(double def = 0) const {
        return t_ == T::Num ? num_ : def;
    }
    long long asInt(long long def = 0) const {
        if (t_ != T::Num || !std::isfinite(num_)) return def;
        long double value = num_;
        if (value < (long double)(std::numeric_limits<long long>::min)() ||
            value > (long double)(std::numeric_limits<long long>::max)())
            return def;
        return static_cast<long long>(num_);
    }
    const std::wstring& asStr() const { return str_; }
    const Object& asObject() const { return obj_; }
    const Value& get(const wchar_t* key) const {
        static const Value missing;
        if (t_ != T::Obj) return missing;
        const auto it = obj_.find(key);
        return it != obj_.end() ? it->second : missing;
    }
    Object& obj() { return obj_; }
    const Array& arr() const { return arr_; }
    Array& array() { return arr_; }

private:
    T t_;
    bool b_ = false;
    double num_ = 0;
    std::wstring str_;
    Object obj_;
    Array arr_;
};

// 解析失败返回 Null 值（调用方用 isNull() 判断），不抛异常
Value Parse(const std::wstring& text);
std::wstring Dump(const Value& v);   // 输出带 2 空格缩进

} // namespace minjson
