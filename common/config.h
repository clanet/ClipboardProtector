#pragma once
// 配置模型与读写。存储位置：%APPDATA%\ClipboardProtector\config.json
#include <string>
#include <vector>
#include <algorithm>
#include <utility>
#include "hotkeys.h"
#include "i18n.h"

namespace clip {

enum RuleAction : int {
    kRuleAllow   = 0,  // 放行；通知方式由 Rule::showNotification 决定
    kRuleSilent  = kRuleAllow,
    kRuleShow    = 1,  // 旧版线协议：放行并显示，配置模型不再存储此值
    kRuleConfirm = 2,  // 由用户确认本次访问是否放行
    kRuleBlock   = 3,  // 阻止；通知方式由 Rule::showNotification 决定
};

inline bool IsRuleDecision(int action) {
    return action == kRuleAllow || action == kRuleConfirm ||
           action == kRuleBlock;
}

// Keep source compatibility for older smoke tools and stored action values.
constexpr int kAllowRecord = kRuleSilent;
constexpr int kLogOnly = kRuleSilent;
constexpr int kBlockRead = kRuleBlock;
constexpr int kBlockAlert = kRuleBlock;

enum RuleOperation : unsigned char {
    kRuleRead = 1,
    kRuleWrite = 2,
    kRuleReadWrite = kRuleRead | kRuleWrite,
};

enum RuleSourceMode : unsigned char {
    kSourceAny = 0,
    kSourceName = 1,
    kSourcePath = 2,
    kSourceSameProcess = 3,
    kSourceDifferentProcess = 4,
    kSourceUnknown = 5,
};

enum RuleFormat : unsigned char {
    kFormatAny = 0,
    kFormatNonText = 1,
    kFormatText = 2,
    kFormatCryptoAddress = 3,
    kFormatPrivateKeyMnemonic = 4,
};

constexpr int kMinRulePriority = 0;   // 0 matches first
constexpr int kMaxRulePriority = 9;
constexpr int kDefaultRulePriority = 5;

constexpr unsigned int kDefaultShortcutAuthorizationWindowMs = 1000;
constexpr unsigned int kMinShortcutAuthorizationWindowMs = 100;
constexpr unsigned int kMaxShortcutAuthorizationWindowMs = 5000;

struct Settings {
    Language language = Language::Chinese;
    AppHotkeys hotkeys;
    bool balloonNotificationsDisabled = false;
    bool shortcutOnlyMode = false;
    bool shortcutDirectAllow = true;
    unsigned int shortcutAuthorizationWindowMs =
        kDefaultShortcutAuthorizationWindowMs;
    bool cryptoProtection = true;
    int maxLogEntries = 5000;
    bool previewEnabled = true;
    bool captureImageFileSnapshots = false;
    bool ignoreCustomFormats = true;
    bool autostart = false;
    bool startGlobalProtection = false;
    bool startMinimized = false;
    // 主窗口外框的 96-DPI 逻辑尺寸；0 表示使用首次启动默认值。
    int windowWidth = 0;
    int windowHeight = 0;
};

struct Rule {
    std::wstring pattern;  // 进程名（如 wechat.exe）或路径通配（如 D:\tools\*.exe）
    bool isPath = false;   // true=按完整路径匹配，false=按进程名匹配
    int action = kRuleAllow;
    bool showNotification = false;
    bool hideFromLogList = false;
    std::wstring name;
    unsigned char operations = kRuleReadWrite;
    unsigned char format = kFormatAny;
    std::wstring contentRegex; // 为空时匹配所有内容，否则搜索已解码文本
    bool ignoreCase = true;
    bool enabled = true;
    unsigned char sourceMode = kSourceAny;
    std::wstring sourcePattern;
    unsigned int confirmTimeoutMs = 15000;
    bool timeoutBlock = true;
    unsigned char priority = kDefaultRulePriority;
};

// Rules match top-to-bottom. Keep stored rules sorted by ascending priority
// (0 first) and preserve insertion order within a priority. Returns a map from
// each rule's old index to its new index for list selection.
inline std::vector<size_t> SortRulesByPriority(std::vector<Rule>& rules) {
    std::vector<size_t> order(rules.size());
    for (size_t i = 0; i < order.size(); ++i) order[i] = i;
    std::stable_sort(order.begin(), order.end(),
                     [&rules](size_t a, size_t b) {
                         return rules[a].priority < rules[b].priority;
                     });
    std::vector<size_t> newIndex(rules.size());
    std::vector<Rule> sorted;
    sorted.reserve(rules.size());
    for (size_t next = 0; next < order.size(); ++next) {
        newIndex[order[next]] = next;
        sorted.push_back(std::move(rules[order[next]]));
    }
    rules = std::move(sorted);
    return newIndex;
}

// Requires rules already sorted by SortRulesByPriority. Returns the first slot
// of the priority group so an inserted rule precedes equal-priority rules.
inline size_t RulePriorityGroupBegin(const std::vector<Rule>& rules,
                                     unsigned char priority) {
    size_t index = 0;
    while (index < rules.size() && rules[index].priority < priority) ++index;
    return index;
}

struct Config {
    Settings settings;
    std::vector<Rule> rules;

    // 返回值：false 表示文件不存在或损坏（已生成默认内容备份 .bak）
    bool Load(const std::wstring& path);
    bool Save(const std::wstring& path) const;

    // 兼容调用：仅按进程匹配第一条启用的规则。
    int MatchAction(const std::wstring& processNameLower,
                    const std::wstring& fullPathLower) const;
};

// Used only when the application starts without a configuration file.
Config MakeFirstRunConfig(Language language);

std::wstring DefaultConfigDir();          // %APPDATA%\ClipboardProtector
std::wstring DefaultConfigPath();         // ...\config.json

} // namespace clip
