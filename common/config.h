#pragma once
// 配置模型与读写。存储位置：%APPDATA%\ClipboardProtector\config.json
#include <string>
#include <vector>
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

constexpr unsigned int kDefaultShortcutAuthorizationWindowMs = 1000;
constexpr unsigned int kMinShortcutAuthorizationWindowMs = 100;
constexpr unsigned int kMaxShortcutAuthorizationWindowMs = 5000;

struct Settings {
    Language language = Language::Chinese;
    AppHotkeys hotkeys;
    bool balloonNotificationsDisabled = false;
    bool shortcutOnlyMode = false;
    bool shortcutDirectAllow = false;
    unsigned int shortcutAuthorizationWindowMs =
        kDefaultShortcutAuthorizationWindowMs;
    bool cryptoProtection = false;
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
};

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

std::wstring DefaultConfigDir();          // %APPDATA%\ClipboardProtector
std::wstring DefaultConfigPath();         // ...\config.json

} // namespace clip
