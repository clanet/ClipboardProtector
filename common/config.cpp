#include "config.h"
#include "minjson.h"
#include "util.h"
#include "rules.h"
#include <shlobj.h>
#include <algorithm>
#include <utility>

namespace clip {

// ---------- JSON <-> 模型 ----------

static int ValidWindowDimension(long long value, int minimum) {
    return value >= minimum && value <= 8192 ? static_cast<int>(value) : 0;
}

static minjson::Value RulesToJson(const std::vector<Rule>& rules) {
    auto arr = minjson::Value::Arr();
    for (const auto& r : rules) {
        auto o = minjson::Value::Obj();
        o.obj()[L"name"] = minjson::Value::Str(r.name);
        o.obj()[L"pattern"] = minjson::Value::Str(r.pattern);
        o.obj()[L"isPath"] = minjson::Value::Bool(r.isPath);
        o.obj()[L"action"] = minjson::Value::Num(r.action);
        o.obj()[L"showNotification"] =
            minjson::Value::Bool(r.showNotification);
        o.obj()[L"hideFromLogList"] =
            minjson::Value::Bool(r.hideFromLogList);
        o.obj()[L"operations"] = minjson::Value::Num(r.operations);
        o.obj()[L"format"] = minjson::Value::Num(r.format);
        o.obj()[L"contentRegex"] = minjson::Value::Str(r.contentRegex);
        o.obj()[L"ignoreCase"] = minjson::Value::Bool(r.ignoreCase);
        o.obj()[L"enabled"] = minjson::Value::Bool(r.enabled);
        o.obj()[L"sourceMode"] = minjson::Value::Num(r.sourceMode);
        o.obj()[L"sourcePattern"] = minjson::Value::Str(r.sourcePattern);
        o.obj()[L"confirmTimeoutMs"] =
            minjson::Value::Num(r.confirmTimeoutMs);
        o.obj()[L"timeoutBlock"] = minjson::Value::Bool(r.timeoutBlock);
        arr.array().push_back(std::move(o));
    }
    return arr;
}

static bool RulesFromJson(const minjson::Value& arr, int ruleModelVersion,
                          std::vector<Rule>& out) {
    out.clear();
    if (arr.type() != minjson::Value::T::Arr || arr.arr().size() > 4096)
        return false;
    for (const auto& o : arr.arr()) {
        if (o.type() != minjson::Value::T::Obj) continue;
        Rule r;
        r.name = o.get(L"name").asStr();
        r.pattern = o.get(L"pattern").asStr();
        if (r.pattern.size() > 32768) return false;
        r.isPath = o.get(L"isPath").asBool(false);
        const long long a = o.get(L"action").asInt(kRuleSilent);
        if (ruleModelVersion >= 3) {
            // Version 3 stores the access decision and notification policy
            // independently. Tolerate the retired value 1 as an allow rule.
            r.action = a == kRuleShow
                           ? kRuleAllow
                           : (a == kRuleAllow || a == kRuleConfirm ||
                              a == kRuleBlock)
                                 ? static_cast<int>(a)
                                 : kRuleAllow;
        } else if (ruleModelVersion >= 2) {
            // Version 2 encoded "allow + notification" as action 1.
            r.action = a == kRuleShow
                           ? kRuleAllow
                           : (a >= kRuleSilent && a <= kRuleBlock)
                                 ? static_cast<int>(a)
                                 : kRuleAllow;
            r.showNotification = a == kRuleShow;
        } else {
            // Legacy 0/1 actions both allowed access; legacy 2/3 both blocked.
            // Migrate conservatively without introducing surprise dialogs.
            r.action = a >= 2 ? kRuleBlock : kRuleSilent;
        }
        const long long operations =
            o.get(L"operations").asInt(kRuleReadWrite);
        r.operations = static_cast<unsigned char>(operations) & kRuleReadWrite;
        if (r.operations == 0) r.operations = kRuleReadWrite;
        const long long storedFormat =
            o.get(L"format").asInt(kFormatAny);
        bool splitLegacyBlockchain = false;
        if (ruleModelVersion >= 4) {
            r.format = storedFormat >= kFormatAny &&
                               storedFormat <= kFormatPrivateKeyMnemonic
                           ? static_cast<unsigned char>(storedFormat)
                           : 0xff;
        } else {
            switch (storedFormat) {
            case 0:
                r.format = kFormatAny;
                break;
            case 1: // Legacy: all text.
            case 2: // Legacy: Unicode text.
            case 3: // Legacy: ANSI text.
                r.format = kFormatText;
                break;
            case 4: // Legacy: addresses, private keys, and mnemonics.
                r.format = kFormatCryptoAddress;
                splitLegacyBlockchain = true;
                break;
            default:
                r.format = 0xff;
                break;
            }
        }
        r.contentRegex = o.get(L"contentRegex").asStr();
        r.ignoreCase = o.get(L"ignoreCase").asBool(true);
        r.enabled = o.get(L"enabled").asBool(true);
        if (ruleModelVersion >= 3) {
            r.showNotification =
                o.get(L"showNotification").asBool(false);
            if (ruleModelVersion >= 5)
                r.hideFromLogList =
                    o.get(L"hideFromLogList").asBool(false);
        }
        r.sourceMode = static_cast<unsigned char>(
            o.get(L"sourceMode").asInt(kSourceAny));
        r.sourcePattern = o.get(L"sourcePattern").asStr();
        r.confirmTimeoutMs = static_cast<unsigned int>(
            o.get(L"confirmTimeoutMs").asInt(15000));
        r.timeoutBlock = o.get(L"timeoutBlock").asBool(true);
        if (!r.pattern.empty()) {
            if (out.size() >= 4096) return false;
            if (splitLegacyBlockchain) {
                Rule secretRule = r;
                secretRule.format = kFormatPrivateKeyMnemonic;
                out.push_back(std::move(r));
                if (out.size() >= 4096) return false;
                out.push_back(std::move(secretRule));
            } else {
                out.push_back(std::move(r));
            }
        }
    }
    return true;
}

bool Config::Load(const std::wstring& path) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;   // 首次运行：文件不存在

    // 读全文（配置很小，一次读完）
    std::string utf8;
    char buf[4096];
    DWORD n = 0;
    bool readOk = true;
    for (;;) {
        if (!ReadFile(h, buf, sizeof(buf), &n, nullptr)) {
            readOk = false;
            break;
        }
        if (n == 0) break;
        utf8.append(buf, n);
        if (utf8.size() > (4u << 20)) {
            readOk = false;
            break;
        }
    }
    CloseHandle(h);
    if (!readOk) return false;

    // UTF-8 -> UTF-16
    int wlen = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                   utf8.data(), (int)utf8.size(), nullptr, 0);
    if (wlen <= 0) return false;
    std::wstring text(wlen, L'\0');
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                            utf8.data(), (int)utf8.size(), &text[0], wlen) != wlen)
        return false;

    // 容忍 BOM
    if (!text.empty() && text.front() == L'\uFEFF') text.erase(0, 1);

    minjson::Value root = minjson::Parse(text);
    bool ok = root.type() == minjson::Value::T::Obj;
    if (!ok) {
        // 损坏：备份后重建默认
        MoveFileExW(path.c_str(), (path + L".bak").c_str(),
                    MOVEFILE_REPLACE_EXISTING);
        return false;
    }

    const int ruleModelVersion = static_cast<int>(
        root.get(L"ruleModelVersion").asInt(0));
    Settings loadedSettings = settings;
    std::vector<Rule> loadedRules = rules;
    const auto& settingsValue = root.get(L"settings");
    if (settingsValue.type() == minjson::Value::T::Obj) {
        Settings parsedSettings;
        parsedSettings.language = ParseLanguage(settingsValue.get(L"language").asStr());
        const auto& s = settingsValue.asObject();
        auto balloonSetting = s.find(L"balloonNotificationsDisabled");
        if (balloonSetting != s.end()) {
            parsedSettings.balloonNotificationsDisabled =
                balloonSetting->second.asBool(false);
        } else {
            // Legacy notifyLevel 2 meant that all tray balloons were disabled.
            parsedSettings.balloonNotificationsDisabled =
                settingsValue.get(L"notifyLevel").asInt(1) == 2;
        }
        parsedSettings.shortcutOnlyMode =
            settingsValue.get(L"shortcutOnlyMode").asBool(false);
        parsedSettings.shortcutDirectAllow =
            settingsValue.get(L"shortcutDirectAllow").asBool(false);
        const long long shortcutWindowMs = settingsValue
            .get(L"shortcutAuthorizationWindowMs")
            .asInt(kDefaultShortcutAuthorizationWindowMs);
        parsedSettings.shortcutAuthorizationWindowMs =
            static_cast<unsigned int>(std::clamp<long long>(
                shortcutWindowMs, kMinShortcutAuthorizationWindowMs,
                kMaxShortcutAuthorizationWindowMs));
        parsedSettings.cryptoProtection =
            settingsValue.get(L"cryptoProtection").asBool(false);
        const long long ml =
            settingsValue.get(L"maxLogEntries").asInt(5000);
        parsedSettings.maxLogEntries = (int)std::clamp<long long>(ml, 100, 100000);
        parsedSettings.previewEnabled =
            settingsValue.get(L"previewEnabled").asBool(true);
        parsedSettings.captureImageFileSnapshots =
            settingsValue.get(L"captureImageFileSnapshots").asBool(false);
        parsedSettings.ignoreCustomFormats =
            settingsValue.get(L"ignoreCustomFormats").asBool(true);
        parsedSettings.autostart =
            settingsValue.get(L"autostart").asBool(false);
        parsedSettings.startGlobalProtection =
            settingsValue.get(L"startGlobalProtection").asBool(false);
        parsedSettings.startMinimized =
            settingsValue.get(L"startMinimized").asBool(false);
        // Invalid or duplicate bindings fall back to usable defaults.
        AppHotkeys hotkeys;
        const auto readHotkeyNumber = [&](const wchar_t* name, unsigned int fallback) {
            const long long number = settingsValue.get(name).asInt(fallback);
            return number >= 0 && number <= 255 ? static_cast<unsigned int>(number) : 0u;
        };
        hotkeys.copyModifiers = readHotkeyNumber(L"privateCopyModifiers", 5);
        hotkeys.copyKey = readHotkeyNumber(L"privateCopyKey", 'C');
        hotkeys.pasteModifiers = readHotkeyNumber(L"privatePasteModifiers", 5);
        hotkeys.pasteKey = readHotkeyNumber(L"privatePasteKey", 'V');
        hotkeys.shortcutOnlyModifiers = readHotkeyNumber(L"shortcutOnlyModifiers", 3);
        hotkeys.shortcutOnlyKey = readHotkeyNumber(L"shortcutOnlyKey", 0x78);
        if (ValidHotkeys(hotkeys)) parsedSettings.hotkeys = hotkeys;
        parsedSettings.windowWidth = ValidWindowDimension(
            settingsValue.get(L"windowWidth").asInt(0), 860);
        parsedSettings.windowHeight = ValidWindowDimension(
            settingsValue.get(L"windowHeight").asInt(0), 600);
        loadedSettings = parsedSettings;
    }
    const auto& rulesValue = root.get(L"rules");
    if (!rulesValue.isNull()) {
        std::vector<Rule> parsedRules;
        if (!RulesFromJson(rulesValue, ruleModelVersion, parsedRules) ||
            !IsRuleSetSupported(parsedRules)) {
            MoveFileExW(path.c_str(), (path + L".bak").c_str(),
                        MOVEFILE_REPLACE_EXISTING);
            return false;
        }
        loadedRules = std::move(parsedRules);
    }
    settings = std::move(loadedSettings);
    rules = std::move(loadedRules);
    return true;
}

bool Config::Save(const std::wstring& path) const {
    if (!ValidHotkeys(settings.hotkeys)) return false;
    minjson::Value root = minjson::Value::Obj();
    root.obj()[L"ruleModelVersion"] = minjson::Value::Num(5);
    auto s = minjson::Value::Obj();
    s.obj()[L"language"] = minjson::Value::Str(LanguageCode(settings.language));
    s.obj()[L"balloonNotificationsDisabled"] =
        minjson::Value::Bool(settings.balloonNotificationsDisabled);
    s.obj()[L"shortcutOnlyMode"] =
        minjson::Value::Bool(settings.shortcutOnlyMode);
    s.obj()[L"shortcutDirectAllow"] =
        minjson::Value::Bool(settings.shortcutDirectAllow);
    s.obj()[L"shortcutAuthorizationWindowMs"] = minjson::Value::Num(
        std::clamp(settings.shortcutAuthorizationWindowMs,
                   kMinShortcutAuthorizationWindowMs,
                   kMaxShortcutAuthorizationWindowMs));
    s.obj()[L"cryptoProtection"] =
        minjson::Value::Bool(settings.cryptoProtection);
    s.obj()[L"maxLogEntries"] = minjson::Value::Num(settings.maxLogEntries);
    s.obj()[L"previewEnabled"] = minjson::Value::Bool(settings.previewEnabled);
    s.obj()[L"captureImageFileSnapshots"] =
        minjson::Value::Bool(settings.captureImageFileSnapshots);
    s.obj()[L"ignoreCustomFormats"] =
        minjson::Value::Bool(settings.ignoreCustomFormats);
    s.obj()[L"autostart"] = minjson::Value::Bool(settings.autostart);
    s.obj()[L"startGlobalProtection"] =
        minjson::Value::Bool(settings.startGlobalProtection);
    s.obj()[L"startMinimized"] =
        minjson::Value::Bool(settings.startMinimized);
    const auto& hotkeys = settings.hotkeys;
    s.obj()[L"privateCopyModifiers"] = minjson::Value::Num(hotkeys.copyModifiers);
    s.obj()[L"privateCopyKey"] = minjson::Value::Num(hotkeys.copyKey);
    s.obj()[L"privatePasteModifiers"] = minjson::Value::Num(hotkeys.pasteModifiers);
    s.obj()[L"privatePasteKey"] = minjson::Value::Num(hotkeys.pasteKey);
    s.obj()[L"shortcutOnlyModifiers"] = minjson::Value::Num(hotkeys.shortcutOnlyModifiers);
    s.obj()[L"shortcutOnlyKey"] = minjson::Value::Num(hotkeys.shortcutOnlyKey);
    s.obj()[L"windowWidth"] = minjson::Value::Num(
        ValidWindowDimension(settings.windowWidth, 860));
    s.obj()[L"windowHeight"] = minjson::Value::Num(
        ValidWindowDimension(settings.windowHeight, 600));
    root.obj()[L"settings"] = std::move(s);
    root.obj()[L"rules"] = RulesToJson(rules);

    std::wstring text = minjson::Dump(root);

    // UTF-16 -> UTF-8
    int ulen = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
                                   text.data(), (int)text.size(),
                                   nullptr, 0, nullptr, nullptr);
    if (ulen <= 0) return false;
    std::string utf8(ulen, '\0');
    int converted = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
                                        text.data(), (int)text.size(),
                                        &utf8[0], ulen, nullptr, nullptr);
    if (converted != ulen) return false;

    const std::wstring tempPath = path + L".tmp";
    HANDLE h = CreateFileW(tempPath.c_str(), GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD written = 0;
    BOOL ok = WriteFile(h, utf8.data(), (DWORD)utf8.size(), &written, nullptr) &&
              written == utf8.size() && FlushFileBuffers(h);
    CloseHandle(h);
    if (!ok) {
        DeleteFileW(tempPath.c_str());
        return false;
    }
    if (!MoveFileExW(tempPath.c_str(), path.c_str(),
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DeleteFileW(tempPath.c_str());
        return false;
    }
    return true;
}

int Config::MatchAction(const std::wstring& nameLower,
                        const std::wstring& pathLower) const {
    for (const auto& r : rules) {
        if (!r.enabled || !r.contentRegex.empty()) continue;
        const std::wstring patLower = ToLower(r.pattern);
        bool hit = r.isPath ? WildcardMatch(patLower, pathLower)
                            : WildcardMatch(patLower, nameLower);
        if (hit) return r.action;
    }
    return kRuleSilent;
}

std::wstring DefaultConfigDir() {
    PWSTR appdata = nullptr;
    std::wstring dir;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &appdata))) {
        dir = std::wstring(appdata) + L"\\ClipboardProtector";
        CoTaskMemFree(appdata);
    }
    return dir;
}

std::wstring DefaultConfigPath() {
    const std::wstring dir = DefaultConfigDir();
    return dir.empty() ? std::wstring() : dir + L"\\config.json";
}

} // namespace clip
