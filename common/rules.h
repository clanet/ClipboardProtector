#pragma once
// 规则匹配核心：主程序与 Hook.dll 共用的唯一实现。
#include <string>
#include <vector>
#include "config.h"
#include "crypto.h"
#include "saferegex.h"
#include "util.h"

namespace clip {

struct RuleLite {
    std::wstring patternLower;  // 已小写的匹配串
    bool isPath = false;
    int action = kRuleAllow;
    bool showNotification = false;
    bool hideFromLogList = false;
    std::wstring name;
    unsigned char operations = kRuleReadWrite;
    unsigned char format = kFormatAny;
    std::wstring contentPattern;
    bool ignoreCase = true;
    bool enabled = true;
    unsigned char sourceMode = kSourceAny;
    std::wstring sourcePatternLower;
    unsigned int confirmTimeoutMs = 15000;
    bool timeoutBlock = true;
    SafeRegex contentRegex;
    bool contentRegexReady = false;
};

struct RuleSourceIdentity {
    bool known = false;
    unsigned int pid = 0;
    std::wstring nameLower;
    std::wstring pathLower;
};

struct RuleMatch {
    int action = kRuleAllow;
    bool showNotification = false;
    bool hideFromLogList = false;
    bool redactContent = false;
    unsigned int confirmTimeoutMs = 15000;
    bool timeoutBlock = true;
    std::wstring name;
};

constexpr size_t kMaxContentRegexLength = 512;
constexpr size_t kMaxRegexContentLength = 4096;
constexpr size_t kMaxRegexWork = 1000000;
constexpr size_t kMaxRegexWorkPerRule = 250000;

inline bool IsContentRegexSupported(const std::wstring& pattern,
                                    bool ignoreCase = true) {
    if (pattern.size() > kMaxContentRegexLength ||
        pattern.find(L'\0') != std::wstring::npos)
        return false;
    if (pattern.empty()) return true;
    SafeRegex compiled;
    return compiled.Compile(pattern, ignoreCase);
}

inline bool CompileRuleContentRegex(RuleLite& rule) {
    rule.contentRegexReady = false;
    if (rule.contentPattern.empty()) return true;
    if (!IsContentRegexSupported(rule.contentPattern, rule.ignoreCase))
        return false;
    if (!rule.contentRegex.Compile(rule.contentPattern, rule.ignoreCase))
        return false;
    rule.contentRegexReady = true;
    return true;
}

inline bool IsRuleSetSupported(const std::vector<RuleLite>& rules) {
    if (rules.size() > 4096) return false;
    // Extended payload: count + marker, then four length-prefixed strings,
    // ten bytes of flags/actions and one u32 timeout per rule.
    size_t bytes = 8;
    for (const auto& rule : rules) {
        if (rule.patternLower.empty() || rule.patternLower.size() > 32768 ||
            rule.name.size() > 128 || rule.sourcePatternLower.size() > 32768 ||
            !IsContentRegexSupported(rule.contentPattern, rule.ignoreCase) ||
            (rule.operations & kRuleReadWrite) == 0 ||
            rule.action < kRuleSilent || rule.action > kRuleBlock ||
            rule.format > kFormatPrivateKeyMnemonic ||
            (rule.format == kFormatNonText &&
             !rule.contentPattern.empty()) ||
            rule.sourceMode > kSourceUnknown ||
            ((rule.sourceMode == kSourceName ||
              rule.sourceMode == kSourcePath) &&
             rule.sourcePatternLower.empty()) ||
            rule.confirmTimeoutMs < 1000 || rule.confirmTimeoutMs > 60000)
            return false;
        size_t item = 30 +
                      (rule.patternLower.size() + rule.contentPattern.size() +
                       rule.sourcePatternLower.size() + rule.name.size()) *
                          sizeof(wchar_t);
        if (item > (1u << 20) || bytes > (1u << 20) - item) return false;
        bytes += item;
    }
    return true;
}
inline bool IsRuleSetSupported(const std::vector<Rule>& rules) {
    if (rules.size() > 4096) return false;
    size_t bytes = 8;
    for (const auto& rule : rules) {
        if (rule.pattern.empty() || rule.pattern.size() > 32768 ||
            rule.name.size() > 128 || rule.sourcePattern.size() > 32768 ||
            !IsContentRegexSupported(rule.contentRegex, rule.ignoreCase) ||
            (rule.operations & kRuleReadWrite) == 0 ||
            !IsRuleDecision(rule.action) ||
            rule.format > kFormatPrivateKeyMnemonic ||
            (rule.format == kFormatNonText &&
             !rule.contentRegex.empty()) ||
            rule.sourceMode > kSourceUnknown ||
            ((rule.sourceMode == kSourceName ||
              rule.sourceMode == kSourcePath) &&
             rule.sourcePattern.empty()) ||
            rule.confirmTimeoutMs < 1000 || rule.confirmTimeoutMs > 60000)
            return false;
        size_t item = 30 +
                      (rule.pattern.size() + rule.contentRegex.size() +
                       rule.sourcePattern.size() + rule.name.size()) *
                          sizeof(wchar_t);
        if (item > (1u << 20) || bytes > (1u << 20) - item) return false;
        bytes += item;
    }
    return true;
}

// The original v1 DLL only understands process/path patterns and silent or
// blocking actions. Disabled rules can be omitted from its snapshot.
inline bool IsLegacyRuleSetCompatible(const std::vector<Rule>& rules) {
    if (!IsRuleSetSupported(rules)) return false;
    int commonAction = -1;
    for (const auto& rule : rules) {
        if (!rule.enabled) continue;
        if (rule.operations != kRuleReadWrite || rule.format != kFormatAny ||
            !rule.contentRegex.empty() || rule.sourceMode != kSourceAny ||
            rule.showNotification || rule.hideFromLogList ||
            (rule.action != kRuleSilent && rule.action != kRuleBlock))
            return false;
        if (commonAction != -1 && commonAction != rule.action)
            return false;
        commonAction = rule.action;
    }
    return true;
}

// 生产路径与 README 一致：从上到下首条命中。未命中返回 def。
inline int MatchRules(const std::vector<RuleLite>& rules,
                      const std::wstring& nameLower,
                      const std::wstring& pathLower, int def = 0) {
    size_t budget = 250000;
    size_t examined = 0;
    for (const auto& r : rules) {
        if (examined++ >= 4096) return def;
        if (r.patternLower.size() > 32768) continue;
        bool exhausted = false;
        std::wstring_view candidate = r.isPath ? std::wstring_view(pathLower)
                                               : std::wstring_view(nameLower);
        bool hit = WildcardMatchBounded(r.patternLower, candidate, budget, exhausted);
        if (exhausted) return def;
        if (hit) return r.action;
    }
    return def;
}


inline bool RuleFormatMatches(unsigned char selector, bool textFormat) {
    switch (selector) {
    case kFormatAny: return true;
    case kFormatNonText: return !textFormat;
    case kFormatText:
    case kFormatCryptoAddress:
    case kFormatPrivateKeyMnemonic:
        return textFormat;
    default: return false;
    }
}

inline bool RuleSemanticFormatMatches(unsigned char selector,
                                      const std::wstring& content) {
    if (selector == kFormatCryptoAddress) {
        CryptoAddressKind kind = kCryptoAddressNone;
        std::wstring canonical;
        return ParseCryptoAddress(content, kind, canonical);
    }
    if (selector == kFormatPrivateKeyMnemonic)
        return IsPrivateKeyOrMnemonicContent(content);
    return true;
}

inline bool FindClipboardRule(const std::vector<RuleLite>& rules,
                              const std::wstring& nameLower,
                              const std::wstring& pathLower,
                              unsigned int processId,
                              unsigned char operation,
                              bool textFormat,
                              const RuleSourceIdentity& source,
                              const std::wstring* content,
                              bool contentComplete,
                              RuleMatch& match) {
    size_t budget = 250000;
    size_t regexBudget = kMaxRegexWork;
    size_t examined = 0;
    for (const auto& rule : rules) {
        if (examined++ >= 4096) return false;
        if (!rule.enabled || !(rule.operations & operation) ||
            !RuleFormatMatches(rule.format, textFormat) ||
            rule.patternLower.size() > 32768)
            continue;
        bool exhausted = false;
        const std::wstring_view candidate =
            rule.isPath ? std::wstring_view(pathLower)
                        : std::wstring_view(nameLower);
        if (!WildcardMatchBounded(rule.patternLower, candidate, budget,
                                  exhausted)) {
            if (exhausted) return false;
            continue;
        }
        bool sourceMatches = false;
        switch (rule.sourceMode) {
        case kSourceAny:
            sourceMatches = true;
            break;
        case kSourceName:
        case kSourcePath: {
            if (!source.known) break;
            const std::wstring_view sourceCandidate =
                rule.sourceMode == kSourcePath
                    ? std::wstring_view(source.pathLower)
                    : std::wstring_view(source.nameLower);
            sourceMatches = WildcardMatchBounded(
                rule.sourcePatternLower, sourceCandidate, budget, exhausted);
            if (exhausted) return false;
            break;
        }
        case kSourceSameProcess:
            sourceMatches = source.known && source.pid == processId;
            break;
        case kSourceDifferentProcess:
            sourceMatches = source.known && source.pid != processId;
            break;
        case kSourceUnknown:
            sourceMatches = !source.known;
            break;
        }
        if (!sourceMatches) continue;
        if ((rule.format == kFormatCryptoAddress ||
             rule.format == kFormatPrivateKeyMnemonic) &&
            (!content || !contentComplete ||
             !RuleSemanticFormatMatches(rule.format, *content)))
            continue;
        if (!rule.contentPattern.empty()) {
            if (!content || content->size() > kMaxRegexContentLength ||
                !rule.contentRegexReady)
                continue;
            bool regexCompleted = false;
            const size_t ruleBudgetStart =
                (std::min)(regexBudget, kMaxRegexWorkPerRule);
            size_t ruleBudget = ruleBudgetStart;
            if (!rule.contentRegex.Search(*content, &regexCompleted,
                                          &ruleBudget)) {
                regexBudget -= ruleBudgetStart - ruleBudget;
                if ((regexCompleted && contentComplete) ||
                    (rule.action != kRuleBlock &&
                     rule.action != kRuleConfirm)) {
                    if (regexBudget == 0) return false;
                    continue;
                }
            } else {
                regexBudget -= ruleBudgetStart - ruleBudget;
            }
        }

        match.action = rule.action;
        match.showNotification = rule.showNotification;
        match.hideFromLogList = rule.hideFromLogList;
        match.redactContent = rule.format == kFormatPrivateKeyMnemonic;
        match.confirmTimeoutMs = rule.confirmTimeoutMs;
        match.timeoutBlock = rule.timeoutBlock;
        match.name = rule.name;
        return true;
    }
    return false;
}

// Content-aware rules are evaluated top-to-bottom. This compatibility helper
// intentionally supplies an unknown source and an arbitrary text format.
inline int MatchClipboardRules(const std::vector<RuleLite>& rules,
                               const std::wstring& nameLower,
                               const std::wstring& pathLower,
                               unsigned char operation,
                               const std::wstring* content, int def = 0) {
    RuleMatch match;
    RuleSourceIdentity source;
    return FindClipboardRule(rules, nameLower, pathLower, 0, operation, true,
                             source, content, true, match)
               ? match.action
               : def;
}

} // namespace clip
