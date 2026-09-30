#include "../common/ipc.h"
#include "../common/minjson.h"
#include "../common/rules.h"
#include "../common/config.h"
#include "../common/crypto.h"
#include "../common/remotehook.h"
#include "../common/winutil.h"
#include <windows.h>
#include <cmath>
#include <limits>
#include <string>
#include <utility>
#include <vector>

namespace {

bool WriteUtf8BomFile(const std::wstring& path, const std::string& text) {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    const std::string bytes = "\xEF\xBB\xBF" + text;
    DWORD written = 0;
    const BOOL ok = WriteFile(file, bytes.data(), (DWORD)bytes.size(),
                              &written, nullptr);
    CloseHandle(file);
    return ok && written == bytes.size();
}

bool ReadFileBytes(const std::wstring& path, std::string& bytes) {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
                              nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    bytes.clear();
    char buffer[1024];
    DWORD read = 0;
    bool ok = true;
    for (;;) {
        if (!ReadFile(file, buffer, sizeof(buffer), &read, nullptr)) {
            ok = false;
            break;
        }
        if (read == 0) break;
        bytes.append(buffer, read);
    }
    CloseHandle(file);
    return ok;
}

bool IsConfigValue(const minjson::Value& root) {
    if (root.type() != minjson::Value::T::Obj) return false;
    const auto& rootObject = root.asObject();
    auto settings = rootObject.find(L"settings");
    auto rules = rootObject.find(L"rules");
    if (settings == rootObject.end() || rules == rootObject.end() ||
        settings->second.type() != minjson::Value::T::Obj ||
        rules->second.type() != minjson::Value::T::Arr) return false;

    const auto& settingsObject = settings->second.asObject();
    auto balloonNotificationsDisabled =
        settingsObject.find(L"balloonNotificationsDisabled");
    auto shortcutOnlyMode = settingsObject.find(L"shortcutOnlyMode");
    auto shortcutDirectAllow =
        settingsObject.find(L"shortcutDirectAllow");
    auto shortcutAuthorizationWindowMs =
        settingsObject.find(L"shortcutAuthorizationWindowMs");
    auto cryptoProtection = settingsObject.find(L"cryptoProtection");
    auto maxLogEntries = settingsObject.find(L"maxLogEntries");
    auto previewEnabled = settingsObject.find(L"previewEnabled");
    auto captureImageFileSnapshots =
        settingsObject.find(L"captureImageFileSnapshots");
    auto ignoreCustomFormats =
        settingsObject.find(L"ignoreCustomFormats");
    auto autostart = settingsObject.find(L"autostart");
    auto startGlobalProtection =
        settingsObject.find(L"startGlobalProtection");
    auto startMinimized = settingsObject.find(L"startMinimized");
    if (balloonNotificationsDisabled == settingsObject.end() ||
        shortcutOnlyMode == settingsObject.end() ||
        shortcutDirectAllow == settingsObject.end() ||
        shortcutAuthorizationWindowMs == settingsObject.end() ||
        cryptoProtection == settingsObject.end() ||
        maxLogEntries == settingsObject.end() ||
        previewEnabled == settingsObject.end() ||
        captureImageFileSnapshots == settingsObject.end() ||
        ignoreCustomFormats == settingsObject.end() ||
        autostart == settingsObject.end() ||
        startGlobalProtection == settingsObject.end() ||
        startMinimized == settingsObject.end() ||
        balloonNotificationsDisabled->second.asBool(true) ||
        shortcutOnlyMode->second.asBool(true) ||
        shortcutDirectAllow->second.asBool(true) ||
        shortcutAuthorizationWindowMs->second.asInt(-1) != 1000 ||
        cryptoProtection->second.asBool(true) ||
        maxLogEntries->second.asInt(-1) != 5000 ||
        !previewEnabled->second.asBool(false) ||
        captureImageFileSnapshots->second.asBool(true) ||
        !ignoreCustomFormats->second.asBool(false) ||
        autostart->second.asBool(true) ||
        !startGlobalProtection->second.asBool(false) ||
        !startMinimized->second.asBool(false))
        return false;

    const auto& ruleArray = rules->second.arr();
    if (ruleArray.size() != 1 || ruleArray[0].type() != minjson::Value::T::Obj)
        return false;
    const auto& rule = ruleArray[0].asObject();
    auto pattern = rule.find(L"pattern");
    auto isPath = rule.find(L"isPath");
    auto action = rule.find(L"action");
    return pattern != rule.end() && isPath != rule.end() && action != rule.end() &&
           pattern->second.asStr() == L"clipclient.exe" &&
           !isPath->second.asBool(true) && action->second.asInt(-1) == 3;
}

bool CheckStateAcks() {
    // Literal wire markers also cover the non-numeric CAP9 -> CA10 transition.
    const char* markers[] = {
        "CAP2", "CAP3", "CAP4", "CAP5", "CAP6", "CAP7",
        "CAP8", "CAP9", "CA10", "CA11", "CA12"
    };
    for (unsigned i = 0; i < _countof(markers); ++i) {
        const unsigned version = i + 2;
        for (BYTE applied : {BYTE{0}, BYTE{1}}) {
            for (unsigned flags = 0; flags < 256; ++flags) {
                std::string payload(markers[i], 4);
                payload.push_back(static_cast<char>(applied));
                if (version >= 5) payload.push_back(static_cast<char>(flags));
                clip::StateAck ack;
                const bool expected = version < 5 || flags < 8;
                if (clip::ParseStateAck(payload.data(), payload.size(), ack) != expected)
                    return false;
                if (!expected) {
                    if (ack.version || ack.extendedApplied || ack.flags) return false;
                    continue;
                }
                const BYTE expectedFlags = version < 5 ? 0 : static_cast<BYTE>(flags);
                if (ack.version != version || ack.extendedApplied != (applied != 0) ||
                    ack.flags != expectedFlags ||
                    ack.HasCryptoMapping() != (version == 4 || (version >= 5 && (flags & 1))) ||
                    ack.HasTextMetadata() != (version == 12 && (flags & 4)))
                    return false;
                for (size_t length = 0; length < payload.size(); ++length) {
                    if (clip::ParseStateAck(payload.data(), length, ack) ||
                        ack.version || ack.extendedApplied || ack.flags) return false;
                }
                std::string invalid = payload;
                invalid[4] = 2;
                if (clip::ParseStateAck(invalid.data(), invalid.size(), ack)) return false;
                invalid = payload + '\0';
                if (clip::ParseStateAck(invalid.data(), invalid.size(), ack)) return false;
            }
        }
    }
    for (const char* marker : {"CAP1", "CAP0", "CA13", "XXXX"}) {
        std::string payload(marker, 4);
        payload.append(2, '\0');
        clip::StateAck ack;
        if (clip::ParseStateAck(payload.data(), payload.size(), ack)) return false;
    }
    return true;
}

bool CheckIpcStrings() {
    const std::wstring samples[] = {
        L"", L"plain text", L"\u4e2d\u6587\U0001f600",
        std::wstring(L"a\0b", 3), std::wstring(32768, L'X')
    };
    for (const auto& expected : samples) {
        std::string payload;
        clip::PutWStr(payload, expected);
        for (size_t offset : {size_t{0}, size_t{1}}) {
            std::string bytes(offset, 'x');
            bytes += payload;
            clip::PutU8(bytes, 0x5a);
            clip::Reader reader(bytes.data() + offset, bytes.size() - offset);
            std::wstring actual = L"previous value";
            BYTE sentinel = 0;
            if (!reader.GetWStr(actual) || actual != expected ||
                !reader.GetU8(sentinel) || sentinel != 0x5a || reader.n || reader.bad)
                return false;
        }
        for (size_t length : {size_t{0}, size_t{3}, payload.size() - 1}) {
            clip::Reader reader(payload.data(), length);
            std::wstring actual = L"previous value";
            if (reader.GetWStr(actual) || !reader.incomplete || reader.invalid ||
                actual != L"previous value") return false;
        }
    }
    std::string oversized;
    clip::PutU32(oversized, 32769);
    clip::Reader reader(oversized.data(), oversized.size());
    std::wstring actual = L"previous value";
    return !reader.GetWStr(actual) && reader.invalid && !reader.incomplete &&
        actual == L"previous value";
}

} // namespace

int wmain() {
    if (!CheckStateAcks()) return 123;
    if (!CheckIpcStrings()) return 124;
    clip::CryptoAddressKind cryptoKind = clip::kCryptoAddressNone;
    std::wstring canonicalAddress;
    // Synthetic Base58 fixtures: embedded NUL is never a valid alphabet digit.
    std::wstring nulAddress(32, L'1');
    nulAddress.back() = L'\0';
    if (clip::ParseCryptoAddress(nulAddress, cryptoKind, canonicalAddress))
        return 121;
    std::wstring nulPrivateKey(64, L'1');
    nulPrivateKey.back() = L'\0';
    if (clip::IsPrivateKeyOrMnemonicContent(nulPrivateKey)) return 122;
    if (!clip::ParseCryptoAddress(
            L"1BoatSLRHtKNngkdXEeobR76b53LETtpyT", cryptoKind,
            canonicalAddress) ||
        cryptoKind != clip::kCryptoAddressBitcoin ||
        canonicalAddress != L"1BoatSLRHtKNngkdXEeobR76b53LETtpyT" ||
        clip::ParseCryptoAddress(
            L"1BoatSLRHtKNngkdXEeobR76b53LETtpyU", cryptoKind,
            canonicalAddress))
        return 96;
    if (!clip::ParseCryptoAddress(
            L"3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", cryptoKind,
            canonicalAddress) ||
        cryptoKind != clip::kCryptoAddressBitcoin)
        return 100;
    if (!clip::ParseCryptoAddress(
            L"BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4", cryptoKind,
            canonicalAddress) ||
        cryptoKind != clip::kCryptoAddressBitcoin ||
        canonicalAddress !=
            L"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4" ||
        clip::ParseCryptoAddress(
            L"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5", cryptoKind,
            canonicalAddress))
        return 99;
    if (!clip::ParseCryptoAddress(
            L"  0x52908400098527886E0F7030069857D2E4169EE7\r\n",
            cryptoKind, canonicalAddress) ||
        cryptoKind != clip::kCryptoAddressEthereum ||
        canonicalAddress != L"0x52908400098527886e0f7030069857d2e4169ee7" ||
        clip::ParseCryptoAddress(
            L"pay 0x52908400098527886E0F7030069857D2E4169EE7",
            cryptoKind, canonicalAddress))
        return 97;
    if (!clip::ParseCryptoAddress(
            L"11111111111111111111111111111111", cryptoKind,
            canonicalAddress) ||
        cryptoKind != clip::kCryptoAddressSolana ||
        canonicalAddress != L"11111111111111111111111111111111" ||
        clip::ParseCryptoAddress(
            L"11111111111111111111111111111110", cryptoKind,
            canonicalAddress))
        return 98;

    const std::wstring ethA = L"0x52908400098527886e0f7030069857d2e4169ee7";
    const std::wstring ethB = L"0xde709f2102306220921060314715629080e2fb77";
    const std::wstring btc = L"1BoatSLRHtKNngkdXEeobR76b53LETtpyT";
    const std::wstring sol = L"11111111111111111111111111111111";
    const auto replaced = [](const std::wstring& before, const std::wstring& after) {
        std::vector<clip::CryptoAddress> oldAddresses, newAddresses;
        return clip::ExtractCryptoAddresses(before, oldAddresses) &&
               clip::ExtractCryptoAddresses(after, newAddresses) &&
               clip::HasCryptoAddressReplacement(oldAddresses, newAddresses);
    };
    if (!replaced(ethA, ethB) ||
        !replaced(L"收款地址：" + ethA + L"，金额 10", L"收款地址：" + ethB + L"，金额 10") ||
        !replaced(btc + L"\n" + sol, btc + L"\n" + ethB) ||
        !replaced(ethA + L" " + ethB, ethB + L" " + ethB) ||
        replaced(ethA, L"普通文字") || replaced(L"普通文字", ethB) ||
        replaced(ethA, L"") || replaced(L"", ethA) ||
        replaced(L"原说明：" + ethA, L"新说明：" + ethA) ||
        replaced(ethA + L" " + ethB, ethB + L" " + ethA) ||
        replaced(ethA, ethA + L" " + ethB) ||
        replaced(ethA + L" " + ethB, ethA) ||
        replaced(ethA, L"0x52908400098527886E0F7030069857D2E4169EE7") ||
        !replaced(std::wstring(5000, L'文') + ethA,
                  std::wstring(5000, L'文') + ethB)) return 111;
    std::vector<clip::CryptoAddress> extracted;
    if (!clip::ExtractCryptoAddresses(L"BTC（" + btc + L"）；ETH：" + ethA +
                                      L"；SOL：" + sol, extracted) || extracted.size() != 3 ||
        !clip::ExtractCryptoAddresses(L"prefix" + ethA + L" " + ethA + L"_suffix", extracted) ||
        !extracted.empty() ||
        clip::ExtractCryptoAddresses(std::wstring(clip::kMaxCryptoTextLength + 1, L'文'), extracted))
        return 112;
    std::wstring manyAddresses;
    for (size_t index = 0; index < clip::kMaxProtectedCryptoAddresses; ++index)
        manyAddresses += ethA + L"\n";
    if (!clip::ExtractCryptoAddresses(manyAddresses, extracted) ||
        extracted.size() != clip::kMaxProtectedCryptoAddresses ||
        clip::ExtractCryptoAddresses(manyAddresses + ethB, extracted) ||
        !extracted.empty()) return 113;

    const std::wstring mnemonic12 =
        L"abandon abandon abandon abandon abandon abandon abandon abandon "
        L"abandon abandon abandon about";
    const std::wstring mnemonic24 =
        L"abandon abandon abandon abandon abandon abandon abandon abandon "
        L"abandon abandon abandon abandon abandon abandon abandon abandon "
        L"abandon abandon abandon abandon abandon abandon abandon art";
    if (!clip::IsPrivateKeyOrMnemonicContent(mnemonic12) ||
        !clip::IsPrivateKeyOrMnemonicContent(mnemonic24) ||
        clip::IsPrivateKeyOrMnemonicContent(
            L"abandon abandon abandon abandon abandon abandon abandon abandon "
            L"abandon abandon abandon zoo"))
        return 101;
    if (!clip::IsPrivateKeyOrMnemonicContent(
            L"0000000000000000000000000000000000000000000000000000000000000001") ||
        clip::IsPrivateKeyOrMnemonicContent(
            L"0000000000000000000000000000000000000000000000000000000000000000"))
        return 102;
    if (!clip::IsPrivateKeyOrMnemonicContent(
            L"5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf") ||
        clip::IsPrivateKeyOrMnemonicContent(
            L"5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDe"))
        return 103;
    std::wstring solanaJson = L"[1";
    for (int index = 1; index < 64; ++index) solanaJson += L",0";
    solanaJson += L"]";
    if (!clip::IsPrivateKeyOrMnemonicContent(solanaJson) ||
        clip::IsPrivateKeyOrMnemonicContent(L"ordinary clipboard text"))
        return 104;

    if (minjson::Value::Num((std::numeric_limits<double>::infinity)()).asInt(17) != 17)
        return 1;
    const std::wstring fractionalText = minjson::Dump(minjson::Value::Num(1.5));
    const minjson::Value fractional = minjson::Parse(fractionalText);
    if (fractional.type() != minjson::Value::T::Num ||
        std::abs(fractional.asDouble() - 1.5) > 1e-12)
        return 16;
    if (!minjson::Dump(minjson::Value::Num(
            (std::numeric_limits<double>::infinity)())).empty())
        return 17;
    if (!minjson::Parse(L"[\"raw\ncontrol\"]").isNull()) return 24;
    const wchar_t* invalidNumbers[] = {
        L"01", L"-01", L"1.", L"1e", L"1e+", L"1e-", L"1..0",
        L"--1", L"+1", L"1+2", L"1e2e3", L"1e9999",
    };
    for (const wchar_t* text : invalidNumbers)
        if (!minjson::Parse(text).isNull()) return 25;

    std::wstring nested64(64, L'[');
    nested64 += L'0';
    nested64.append(64, L']');
    if (minjson::Parse(nested64).type() != minjson::Value::T::Arr) return 2;

    std::wstring nested65(65, L'[');
    nested65 += L'0';
    nested65.append(65, L']');
    if (!minjson::Parse(nested65).isNull()) return 3;

    // Pretty-printed arrays commonly put whitespace after each comma.  Keep
    // this covered independently of the one-rule config fixture below.
    const std::wstring prettyArray =
        L"{\r\n"
        L"  \"rules\": [\r\n"
        L"    {\"pattern\": \"first.exe\", \"isPath\": false, \"action\": 1},\r\n"
        L"    {\"pattern\": \"second.exe\", \"isPath\": false, \"action\": 3}\r\n"
        L"  ]\r\n"
        L"}\r\n";
    const minjson::Value prettyArrayValue = minjson::Parse(prettyArray);
    if (prettyArrayValue.type() != minjson::Value::T::Obj ||
        !prettyArrayValue.asObject().count(L"rules") ||
        prettyArrayValue.asObject().at(L"rules").type() != minjson::Value::T::Arr ||
        prettyArrayValue.asObject().at(L"rules").arr().size() != 2)
        return 4;

    std::string encoded;
    clip::PutU32(encoded, 0xC123u);
    clip::Reader reader(encoded.data(), encoded.size());
    DWORD format = 0;
    if (!reader.GetU32(format) || format != 0xC123u || reader.n != 0) return 5;

    std::string frameBytes;
    clip::PutFrame(frameBytes, clip::kIpcPause, encoded);
    clip::IpcFrameView frame;
    if (clip::ParseFrame(frameBytes.data(), clip::kIpcFrameHeaderSize - 1,
                         frame) != clip::IpcFrameResult::incomplete ||
        frame.consumed != 0)
        return 86;
    if (clip::ParseFrame(frameBytes.data(), frameBytes.size(), frame) !=
            clip::IpcFrameResult::complete ||
        frame.type != clip::kIpcPause || frame.payloadSize != encoded.size() ||
        frame.consumed != frameBytes.size())
        return 87;
    std::string invalidVersion = frameBytes;
    invalidVersion[1] = static_cast<char>(clip::kIpcVersion + 1);
    if (clip::ParseFrame(invalidVersion.data(), invalidVersion.size(), frame) !=
            clip::IpcFrameResult::invalid ||
        frame.consumed != 1)
        return 88;
    std::string oversized;
    clip::PutHeader(oversized, clip::kIpcPause);
    clip::PutU32(oversized, clip::kIpcMaxPayload + 1);
    if (clip::ParseFrame(oversized.data(), oversized.size(), frame) !=
            clip::IpcFrameResult::invalid ||
        frame.consumed != clip::kIpcFrameHeaderSize)
        return 89;

    auto objectValue = minjson::Value::Obj();
    objectValue.obj()[L"known"] = minjson::Value::Num(42);
    if (objectValue.get(L"known").asInt() != 42 ||
        !objectValue.get(L"missing").isNull())
        return 90;

    std::vector<clip::RuleLite> rules = {
        {L"*.exe", false, 1},
        {L"c:\\trusted\\*.exe", true, 3},
    };
    if (clip::MatchRules(rules, L"sample.exe", L"c:\\trusted\\sample.exe") != 1)
        return 6;
    std::vector<clip::RuleLite> pathFirst = {
        {L"c:\\trusted\\*.exe", true, 3},
        {L"*.exe", false, 1},
    };
    if (clip::MatchRules(pathFirst, L"sample.exe", L"c:\\trusted\\sample.exe") != 3)
        return 91;


    clip::RuleLite contentRule;
    contentRule.name = L"source-and-content";
    contentRule.patternLower = L"reader.exe";
    contentRule.action = clip::kRuleBlock;
    contentRule.operations = clip::kRuleRead;
    contentRule.format = clip::kFormatText;
    contentRule.contentPattern = L"secret-[0-9]+";
    contentRule.ignoreCase = true;
    contentRule.sourceMode = clip::kSourceName;
    contentRule.sourcePatternLower = L"writer.exe";
    if (!clip::CompileRuleContentRegex(contentRule)) return 60;
    clip::RuleSourceIdentity source;
    source.known = true;
    source.pid = 42;
    source.nameLower = L"writer.exe";
    source.pathLower = L"c:\\tools\\writer.exe";
    const std::wstring matchingContent = L"prefix SECRET-123 suffix";
    clip::RuleMatch contentMatch;
    if (!clip::FindClipboardRule(
            std::vector<clip::RuleLite>{contentRule}, L"reader.exe",
            L"c:\\apps\\reader.exe", 84, clip::kRuleRead, true, source,
            &matchingContent, true, contentMatch) ||
        contentMatch.action != clip::kRuleBlock ||
        contentMatch.name != L"source-and-content")
        return 61;
    source.nameLower = L"other.exe";
    if (clip::FindClipboardRule(
            std::vector<clip::RuleLite>{contentRule}, L"reader.exe",
            L"c:\\apps\\reader.exe", 84, clip::kRuleRead, true, source,
            &matchingContent, true, contentMatch))
        return 62;
    if (clip::IsContentRegexSupported(L"(", true)) return 63;

    clip::RuleLite privateRule;
    privateRule.name = L"private-content";
    privateRule.patternLower = L"reader.exe";
    privateRule.action = clip::kRuleBlock;
    privateRule.operations = clip::kRuleRead;
    privateRule.format = clip::kFormatPrivateKeyMnemonic;
    clip::RuleMatch privateMatch;
    if (!clip::FindClipboardRule(
            std::vector<clip::RuleLite>{privateRule}, L"reader.exe",
            L"c:\\apps\\reader.exe", 84, clip::kRuleRead, true, source,
            &mnemonic12, true, privateMatch) ||
        privateMatch.name != L"private-content" ||
        !privateMatch.redactContent ||
        clip::FindClipboardRule(
            std::vector<clip::RuleLite>{privateRule}, L"reader.exe",
            L"c:\\apps\\reader.exe", 84, clip::kRuleRead, true, source,
            &matchingContent, true, privateMatch) ||
        clip::FindClipboardRule(
            std::vector<clip::RuleLite>{privateRule}, L"reader.exe",
            L"c:\\apps\\reader.exe", 84, clip::kRuleRead, true, source,
            &mnemonic12, false, privateMatch))
        return 105;

    clip::RuleLite addressRule = privateRule;
    addressRule.name = L"address-content";
    addressRule.format = clip::kFormatCryptoAddress;
    const std::wstring ethAddress =
        L"0x52908400098527886E0F7030069857D2E4169EE7";
    clip::RuleMatch addressMatch;
    if (!clip::FindClipboardRule(
            std::vector<clip::RuleLite>{addressRule}, L"reader.exe",
            L"c:\\apps\\reader.exe", 84, clip::kRuleRead, true, source,
            &ethAddress, true, addressMatch) ||
        addressMatch.redactContent ||
        clip::FindClipboardRule(
            std::vector<clip::RuleLite>{addressRule}, L"reader.exe",
            L"c:\\apps\\reader.exe", 84, clip::kRuleRead, true, source,
            &mnemonic12, true, addressMatch))
        return 106;

    clip::RuleLite nonTextRule = privateRule;
    nonTextRule.name = L"non-text";
    nonTextRule.format = clip::kFormatNonText;
    clip::RuleMatch nonTextMatch;
    if (!clip::FindClipboardRule(
            std::vector<clip::RuleLite>{nonTextRule}, L"reader.exe",
            L"c:\\apps\\reader.exe", 84, clip::kRuleRead, false, source,
            nullptr, false, nonTextMatch) ||
        clip::FindClipboardRule(
            std::vector<clip::RuleLite>{nonTextRule}, L"reader.exe",
            L"c:\\apps\\reader.exe", 84, clip::kRuleRead, true, source,
            &matchingContent, true, nonTextMatch))
        return 107;

    clip::RuleLite firstRule = contentRule;
    firstRule.name = L"first-rule";
    firstRule.action = clip::kRuleSilent;
    source.nameLower = L"writer.exe";
    clip::RuleMatch firstMatch;
    if (!clip::FindClipboardRule(
            std::vector<clip::RuleLite>{firstRule, contentRule}, L"reader.exe",
            L"c:\\apps\\reader.exe", 84, clip::kRuleRead, true, source,
            &matchingContent, true, firstMatch) ||
        firstMatch.action != clip::kRuleSilent ||
        firstMatch.name != L"first-rule")
        return 64;

    clip::SafeRegex safeRegex;
    if (!safeRegex.Compile(L"^(?:token|secret)-[a-z]{2,4}\\d+$", true) ||
        !safeRegex.Search(L"SECRET-AbC42") ||
        safeRegex.Search(L"prefix-secret-ab42") ||
        !safeRegex.Compile(L"\\bcat(?:s)?\\b", false) ||
        !safeRegex.Search(L"two cats here") ||
        safeRegex.Search(L"concatenate"))
        return 65;
    if (safeRegex.Compile(L"(a)\\1", false) ||
        safeRegex.Compile(L"(?=a)a", false) ||
        safeRegex.Compile(L"a{257}", false))
        return 66;
    if (!safeRegex.Compile(L"(a+)+$", false)) return 67;
    std::wstring pathological(50000, L'a');
    pathological.push_back(L'b');
    if (safeRegex.Search(pathological)) return 68;
    size_t workBudget = 8;
    bool completed = true;
    if (safeRegex.Search(pathological, &completed, &workBudget) || completed)
        return 92;

    clip::SafeRegex emptyRegex;
    if (!emptyRegex.Compile(L"", false)) return 114;
    size_t probeBudget = 64;
    completed = false;
    if (!emptyRegex.Search(L"", &completed, &probeBudget) || !completed)
        return 115;
    const size_t exactWork = 64 - probeBudget;
    if (exactWork == 0) return 116;
    size_t exactBudget = exactWork;
    completed = false;
    if (!emptyRegex.Search(L"", &completed, &exactBudget) || !completed ||
        exactBudget != 0)
        return 117;

    std::wstring expensivePattern;
    for (size_t i = 0; i < 240; ++i) expensivePattern += L"a?";
    expensivePattern += L"z";
    clip::RuleLite budgetAllow;
    budgetAllow.name = L"budget-heavy-allow";
    budgetAllow.patternLower = L"reader.exe";
    budgetAllow.action = clip::kRuleAllow;
    budgetAllow.operations = clip::kRuleRead;
    budgetAllow.format = clip::kFormatText;
    budgetAllow.contentPattern = expensivePattern;
    if (!clip::CompileRuleContentRegex(budgetAllow)) return 119;
    clip::RuleLite budgetNoMatch = budgetAllow;
    budgetNoMatch.name = L"budget-block-no-match";
    budgetNoMatch.action = clip::kRuleBlock;
    budgetNoMatch.contentPattern = L"^z$";
    if (!clip::CompileRuleContentRegex(budgetNoMatch)) return 120;
    clip::RuleLite budgetMatch = budgetNoMatch;
    budgetMatch.name = L"budget-block-match";
    budgetMatch.contentPattern = L"a+$";
    if (!clip::CompileRuleContentRegex(budgetMatch)) return 121;
    const std::wstring budgetContent(clip::kMaxRegexContentLength, L'a');
    size_t perRuleBudget = clip::kMaxRegexWorkPerRule;
    completed = true;
    if (budgetAllow.contentRegex.Search(budgetContent, &completed,
                                        &perRuleBudget) ||
        completed)
        return 122;
    clip::RuleMatch budgetMatchResult;
    if (!clip::FindClipboardRule(
            std::vector<clip::RuleLite>{budgetAllow, budgetNoMatch,
                                        budgetMatch},
            L"reader.exe", L"c:\\apps\\reader.exe", 84, clip::kRuleRead,
            true, source, &budgetContent, true, budgetMatchResult) ||
        budgetMatchResult.name != L"budget-block-match")
        return 123;

    const std::wstring mutexName =
        L"Local\\ClipboardProtector.CommonSmoke.Mutex." +
        std::to_wstring(GetCurrentProcessId()) + L"." +
        std::to_wstring(GetTickCount64());
    HANDLE firstMutex =
        clip::CreateLocalUserNamedMutex(mutexName.c_str(), FALSE);
    HANDLE secondMutex = firstMutex
        ? clip::CreateLocalUserNamedMutex(mutexName.c_str(), FALSE)
        : nullptr;
    const DWORD secondMutexError = GetLastError();
    if (secondMutex) CloseHandle(secondMutex);
    if (firstMutex) CloseHandle(firstMutex);
    if (!firstMutex || !secondMutex ||
        secondMutexError != ERROR_ALREADY_EXISTS)
        return 118;


    clip::RuleLite truncatedBlock = contentRule;
    truncatedBlock.sourceMode = clip::kSourceAny;
    truncatedBlock.sourcePatternLower.clear();
    truncatedBlock.contentPattern = L"needle-at-end";
    truncatedBlock.action = clip::kRuleBlock;
    if (!clip::CompileRuleContentRegex(truncatedBlock)) return 69;
    const std::wstring capturedPrefix(clip::kMaxRegexContentLength, L'x');
    clip::RuleMatch truncatedMatch;
    if (!clip::FindClipboardRule(
            std::vector<clip::RuleLite>{truncatedBlock}, L"reader.exe",
            L"c:\\apps\\reader.exe", 84, clip::kRuleRead, true, source,
            &capturedPrefix, false,
            truncatedMatch) ||
        truncatedMatch.action != clip::kRuleBlock)
        return 70;
    if (clip::FindClipboardRule(
            std::vector<clip::RuleLite>{truncatedBlock}, L"reader.exe",
            L"c:\\apps\\reader.exe", 84, clip::kRuleRead, true, source,
            &capturedPrefix, true,
            truncatedMatch))
        return 71;
    truncatedBlock.action = clip::kRuleShow;
    if (clip::FindClipboardRule(
            std::vector<clip::RuleLite>{truncatedBlock}, L"reader.exe",
            L"c:\\apps\\reader.exe", 84, clip::kRuleRead, true, source,
            &capturedPrefix, false,
            truncatedMatch))
        return 72;
    truncatedBlock.action = clip::kRuleConfirm;
    if (!clip::FindClipboardRule(
            std::vector<clip::RuleLite>{truncatedBlock}, L"reader.exe",
            L"c:\\apps\\reader.exe", 84, clip::kRuleRead, true, source,
            &capturedPrefix, false,
            truncatedMatch))
        return 73;

    clip::Rule boundaryRule;
    boundaryRule.pattern.assign(113, L'a');
    clip::Rule invalidNonTextRule;
    invalidNonTextRule.pattern = L"binary.exe";
    invalidNonTextRule.format = clip::kFormatNonText;
    invalidNonTextRule.contentRegex = L"text";
    if (clip::IsRuleSetSupported(
            std::vector<clip::Rule>{invalidNonTextRule}))
        return 110;
    std::vector<clip::Rule> boundaryRules(4095, boundaryRule);
    if (!clip::IsRuleSetSupported(boundaryRules)) return 74;
    boundaryRules.push_back(boundaryRule);
    if (clip::IsRuleSetSupported(boundaryRules)) return 75;
    clip::Rule legacyRule;
    legacyRule.pattern = L"legacy.exe";
    legacyRule.action = clip::kRuleBlock;
    if (!clip::IsLegacyRuleSetCompatible(
            std::vector<clip::Rule>{legacyRule}))
        return 76;
    legacyRule.contentRegex = L"secret";
    if (clip::IsLegacyRuleSetCompatible(
            std::vector<clip::Rule>{legacyRule}))
        return 77;
    legacyRule.contentRegex.clear();
    clip::Rule legacyAllow = legacyRule;
    legacyAllow.pattern = L"allow.exe";
    legacyAllow.action = clip::kRuleSilent;
    if (clip::IsLegacyRuleSetCompatible(
            std::vector<clip::Rule>{legacyRule, legacyAllow}))
        return 78;
    legacyRule.showNotification = true;
    if (clip::IsLegacyRuleSetCompatible(
            std::vector<clip::Rule>{legacyRule}))
        return 82;
    legacyRule.showNotification = false;
    legacyRule.hideFromLogList = true;
    if (clip::IsLegacyRuleSetCompatible(
            std::vector<clip::Rule>{legacyRule}))
        return 111;

    // Known-folder lookup must work before any explicit COM initialization;
    // this is the order used by ClipboardProtector at process startup.
    const std::wstring configPath = clip::DefaultConfigPath();
    if (configPath.empty()) return 7;
    wchar_t tempDir[MAX_PATH] = {};
    DWORD tempLength = GetTempPathW(_countof(tempDir), tempDir);
    if (tempLength == 0 || tempLength >= _countof(tempDir)) return 8;
    wchar_t tempName[MAX_PATH] = {};
    if (!GetTempFileNameW(tempDir, L"cps", 0, tempName)) return 9;

    const std::string powershellJson =
        "{\r\n"
        "    \"settings\":  {\r\n"
        "                     \"balloonNotificationsDisabled\":  false,\r\n"
        "                     \"shortcutOnlyMode\":  false,\r\n"
        "                     \"shortcutDirectAllow\":  false,\r\n"
        "                     \"shortcutAuthorizationWindowMs\":  1000,\r\n"
        "                     \"cryptoProtection\":  false,\r\n"
        "                     \"maxLogEntries\":  5000,\r\n"
        "                     \"previewEnabled\":  true,\r\n"
        "                     \"captureImageFileSnapshots\":  false,\r\n"
        "                     \"ignoreCustomFormats\":  true,\r\n"
        "                     \"autostart\":  false,\r\n"
        "                     \"startGlobalProtection\":  true,\r\n"
        "                     \"startMinimized\":  true\r\n"
        "                 },\r\n"
        "    \"rules\":  [\r\n"
        "                  {\r\n"
        "                      \"pattern\":  \"clipclient.exe\",\r\n"
        "                      \"isPath\":  false,\r\n"
        "                      \"action\":  3\r\n"
        "                  }\r\n"
        "              ]\r\n"
        "}\r\n";
    if (!WriteUtf8BomFile(tempName, powershellJson)) {
        DeleteFileW(tempName);
        return 9;
    }
    clip::Config config;
    HANDLE verifyFile = CreateFileW(tempName, GENERIC_READ, FILE_SHARE_READ,
                                    nullptr, OPEN_EXISTING,
                                    FILE_ATTRIBUTE_NORMAL, nullptr);
    if (verifyFile == INVALID_HANDLE_VALUE) {
        DeleteFileW(tempName);
        return 10;
    }
    std::string verifyBytes;
    char verifyBuffer[1024];
    DWORD verifyRead = 0;
    while (ReadFile(verifyFile, verifyBuffer, sizeof(verifyBuffer),
                    &verifyRead, nullptr) && verifyRead != 0)
        verifyBytes.append(verifyBuffer, verifyRead);
    CloseHandle(verifyFile);
    if (verifyBytes.size() < 3 ||
        (unsigned char)verifyBytes[0] != 0xEF ||
        (unsigned char)verifyBytes[1] != 0xBB ||
        (unsigned char)verifyBytes[2] != 0xBF) {
        DeleteFileW(tempName);
        return 11;
    }
    int wideLength = MultiByteToWideChar(
        CP_UTF8, 0, verifyBytes.data(), (int)verifyBytes.size(), nullptr, 0);
    if (wideLength <= 0) {
        DeleteFileW(tempName);
        return 12;
    }
    std::wstring verifyText(wideLength, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, verifyBytes.data(),
                        (int)verifyBytes.size(), verifyText.data(),
                        wideLength);
    if (!verifyText.empty() && verifyText.front() == L'\uFEFF')
        verifyText.erase(0, 1);
    auto roundtripSource = minjson::Value::Obj();
    auto roundtripSettings = minjson::Value::Obj();
    roundtripSettings.obj()[L"balloonNotificationsDisabled"] =
        minjson::Value::Bool(false);
    roundtripSettings.obj()[L"shortcutOnlyMode"] =
        minjson::Value::Bool(false);
    roundtripSettings.obj()[L"shortcutDirectAllow"] =
        minjson::Value::Bool(false);
    roundtripSettings.obj()[L"shortcutAuthorizationWindowMs"] =
        minjson::Value::Num(1000);
    roundtripSettings.obj()[L"cryptoProtection"] =
        minjson::Value::Bool(false);
    roundtripSettings.obj()[L"maxLogEntries"] = minjson::Value::Num(5000);
    roundtripSettings.obj()[L"previewEnabled"] = minjson::Value::Bool(true);
    roundtripSettings.obj()[L"captureImageFileSnapshots"] =
        minjson::Value::Bool(false);
    roundtripSettings.obj()[L"ignoreCustomFormats"] =
        minjson::Value::Bool(true);
    roundtripSettings.obj()[L"autostart"] = minjson::Value::Bool(false);
    roundtripSettings.obj()[L"startGlobalProtection"] =
        minjson::Value::Bool(true);
    roundtripSettings.obj()[L"startMinimized"] = minjson::Value::Bool(true);
    auto roundtripRules = minjson::Value::Arr();
    auto roundtripRule = minjson::Value::Obj();
    roundtripRule.obj()[L"pattern"] = minjson::Value::Str(L"clipclient.exe");
    roundtripRule.obj()[L"isPath"] = minjson::Value::Bool(false);
    roundtripRule.obj()[L"action"] = minjson::Value::Num(3);
    roundtripRules.array().push_back(std::move(roundtripRule));
    roundtripSource.obj()[L"settings"] = std::move(roundtripSettings);
    roundtripSource.obj()[L"rules"] = std::move(roundtripRules);
    if (!IsConfigValue(minjson::Parse(minjson::Dump(roundtripSource)))) {
        DeleteFileW(tempName);
        return 13;
    }
    if (!IsConfigValue(minjson::Parse(verifyText))) {
        DeleteFileW(tempName);
        return 14;
    }
    const bool loaded = config.Load(tempName);
    DeleteFileW((std::wstring(tempName) + L".bak").c_str());
    DeleteFileW(tempName);
    if (!loaded) return 15;
    if (config.rules.size() != 1 ||
        config.rules[0].pattern != L"clipclient.exe" ||
        config.rules[0].action != clip::kBlockAlert ||
        config.rules[0].isPath ||
        !config.settings.startGlobalProtection ||
        !config.settings.startMinimized ||
        !config.settings.ignoreCustomFormats)
        return 11;

    wchar_t legacySettingsName[MAX_PATH] = {};
    if (!GetTempFileNameW(tempDir, L"cps", 0, legacySettingsName)) return 79;
    const std::string legacySettingsJson =
        "{\"settings\":{\"notifyLevel\":2}}";
    if (!WriteUtf8BomFile(legacySettingsName, legacySettingsJson)) {
        DeleteFileW(legacySettingsName);
        return 80;
    }
    clip::Config legacySettings;
    const bool legacySettingsLoaded = legacySettings.Load(legacySettingsName);
    DeleteFileW((std::wstring(legacySettingsName) + L".bak").c_str());
    DeleteFileW(legacySettingsName);
    if (!legacySettingsLoaded ||
        !legacySettings.settings.balloonNotificationsDisabled ||
        legacySettings.settings.shortcutOnlyMode ||
        legacySettings.settings.shortcutDirectAllow ||
        legacySettings.settings.shortcutAuthorizationWindowMs != 1000 ||
        legacySettings.settings.cryptoProtection ||
        !legacySettings.settings.ignoreCustomFormats ||
        legacySettings.settings.startGlobalProtection ||
        legacySettings.settings.startMinimized ||
        legacySettings.settings.windowWidth != 0 ||
        legacySettings.settings.windowHeight != 0)
        return 81;

    wchar_t windowSizeName[MAX_PATH] = {};
    if (!GetTempFileNameW(tempDir, L"cps", 0, windowSizeName)) return 91;
    clip::Config savedWindowSize;
    if (!clip::ValidHotkeys({}) ||
        clip::ValidHotkeys({3, 'C', 3, 'C'}) ||
        clip::ValidHotkeys({3, VK_F9, 3, 'V'}) ||
        !clip::ValidHotkeys({3, VK_F9, 3, 'V', 5, VK_F8}) ||
        clip::ValidHotkeys({5, 'C', 5, 'V', 5, 'V'}) ||
        clip::ValidHotkeys({0, 'C', 3, 'V'}) ||
        clip::ValidHotkeys({MOD_WIN, 'C', 3, 'V'})) return 120;
    savedWindowSize.settings.windowWidth = 1234;
    savedWindowSize.settings.hotkeys = {MOD_CONTROL | MOD_SHIFT, VK_F6,
        MOD_ALT | MOD_SHIFT, 'P', MOD_CONTROL | MOD_SHIFT, VK_F12};
    savedWindowSize.settings.windowHeight = 777;
    savedWindowSize.settings.startGlobalProtection = true;
    savedWindowSize.settings.startMinimized = true;
    savedWindowSize.settings.cryptoProtection = true;
    savedWindowSize.settings.captureImageFileSnapshots = true;
    savedWindowSize.settings.shortcutDirectAllow = true;
    savedWindowSize.settings.shortcutAuthorizationWindowMs = 1750;
    savedWindowSize.settings.ignoreCustomFormats = false;
    const bool windowSizeSaved = savedWindowSize.Save(windowSizeName);
    clip::Config loadedWindowSize;
    const bool windowSizeLoaded =
        windowSizeSaved && loadedWindowSize.Load(windowSizeName);
    DeleteFileW((std::wstring(windowSizeName) + L".bak").c_str());
    DeleteFileW(windowSizeName);
    if (!windowSizeLoaded || loadedWindowSize.settings.windowWidth != 1234 ||
        loadedWindowSize.settings.hotkeys.copyModifiers != (MOD_CONTROL | MOD_SHIFT) ||
        loadedWindowSize.settings.hotkeys.copyKey != VK_F6 ||
        loadedWindowSize.settings.hotkeys.pasteModifiers != (MOD_ALT | MOD_SHIFT) ||
        loadedWindowSize.settings.hotkeys.pasteKey != 'P' ||
        loadedWindowSize.settings.hotkeys.shortcutOnlyModifiers != (MOD_CONTROL | MOD_SHIFT) ||
        loadedWindowSize.settings.hotkeys.shortcutOnlyKey != VK_F12 ||
        loadedWindowSize.settings.windowHeight != 777 ||
        !loadedWindowSize.settings.startGlobalProtection ||
        !loadedWindowSize.settings.startMinimized ||
        !loadedWindowSize.settings.cryptoProtection ||
        !loadedWindowSize.settings.captureImageFileSnapshots ||
        loadedWindowSize.settings.ignoreCustomFormats ||
        !loadedWindowSize.settings.shortcutDirectAllow ||
        loadedWindowSize.settings.shortcutAuthorizationWindowMs != 1750)
        return 92;

    wchar_t invalidWindowSizeName[MAX_PATH] = {};
    if (!GetTempFileNameW(tempDir, L"cps", 0, invalidWindowSizeName)) return 93;
    const std::string invalidWindowSizeJson =
        "{\"settings\":{\"windowWidth\":859,\"windowHeight\":9000,"
        "\"shortcutAuthorizationWindowMs\":1,\"privateCopyKey\":-1,"
        "\"privatePasteModifiers\":999}}";
    if (!WriteUtf8BomFile(invalidWindowSizeName, invalidWindowSizeJson)) {
        DeleteFileW(invalidWindowSizeName);
        return 94;
    }
    clip::Config invalidWindowSize;
    const bool invalidWindowSizeLoaded =
        invalidWindowSize.Load(invalidWindowSizeName);
    DeleteFileW((std::wstring(invalidWindowSizeName) + L".bak").c_str());
    DeleteFileW(invalidWindowSizeName);
    if (!invalidWindowSizeLoaded || invalidWindowSize.settings.windowWidth != 0 ||
        invalidWindowSize.settings.hotkeys.copyKey != 'C' ||
        invalidWindowSize.settings.hotkeys.copyModifiers != 5 ||
        invalidWindowSize.settings.hotkeys.pasteKey != 'V' ||
        invalidWindowSize.settings.hotkeys.pasteModifiers != 5 ||
        invalidWindowSize.settings.hotkeys.shortcutOnlyModifiers != 3 ||
        invalidWindowSize.settings.hotkeys.shortcutOnlyKey != VK_F9 ||
        invalidWindowSize.settings.windowHeight != 0 ||
        invalidWindowSize.settings.shortcutAuthorizationWindowMs !=
            clip::kMinShortcutAuthorizationWindowMs)
        return 95;

    wchar_t splitRuleName[MAX_PATH] = {};
    if (!GetTempFileNameW(tempDir, L"cps", 0, splitRuleName)) return 83;
    const std::string version2ShowJson =
        "{\"ruleModelVersion\":2,\"rules\":[{"
        "\"name\":\"migrated-show\",\"pattern\":\"reader.exe\","
        "\"isPath\":false,\"action\":1}]}";
    if (!WriteUtf8BomFile(splitRuleName, version2ShowJson)) {
        DeleteFileW(splitRuleName);
        return 84;
    }
    clip::Config splitRule;
    const bool splitLoaded = splitRule.Load(splitRuleName);
    const bool showMigrated =
        splitLoaded && splitRule.rules.size() == 1 &&
        splitRule.rules[0].action == clip::kRuleAllow &&
        splitRule.rules[0].showNotification;
    if (showMigrated) {
        splitRule.rules[0].action = clip::kRuleBlock;
        splitRule.rules[0].showNotification = true;
        splitRule.rules[0].hideFromLogList = true;
    }
    const bool splitSaved = showMigrated && splitRule.Save(splitRuleName);
    clip::Config splitReloaded;
    const bool splitReloadedOk = splitSaved && splitReloaded.Load(splitRuleName);
    DeleteFileW((std::wstring(splitRuleName) + L".bak").c_str());
    DeleteFileW(splitRuleName);
    if (!splitReloadedOk || splitReloaded.rules.size() != 1 ||
        splitReloaded.rules[0].action != clip::kRuleBlock ||
        !splitReloaded.rules[0].showNotification ||
        !splitReloaded.rules[0].hideFromLogList)
        return 85;

    wchar_t formatMigrationName[MAX_PATH] = {};
    if (!GetTempFileNameW(tempDir, L"cps", 0, formatMigrationName)) return 108;
    const std::string version3FormatsJson =
        "{\"ruleModelVersion\":3,\"rules\":["
        "{\"name\":\"all-text\",\"pattern\":\"a.exe\",\"format\":1},"
        "{\"name\":\"unicode\",\"pattern\":\"b.exe\",\"format\":2},"
        "{\"name\":\"ansi\",\"pattern\":\"c.exe\",\"format\":3},"
        "{\"name\":\"blockchain\",\"pattern\":\"d.exe\",\"format\":4}]}";
    if (!WriteUtf8BomFile(formatMigrationName, version3FormatsJson)) {
        DeleteFileW(formatMigrationName);
        return 108;
    }
    clip::Config migratedFormats;
    const bool formatsLoaded = migratedFormats.Load(formatMigrationName);
    const bool formatsMigrated =
        formatsLoaded && migratedFormats.rules.size() == 5 &&
        migratedFormats.rules[0].format == clip::kFormatText &&
        migratedFormats.rules[1].format == clip::kFormatText &&
        migratedFormats.rules[2].format == clip::kFormatText &&
        migratedFormats.rules[3].format == clip::kFormatCryptoAddress &&
        migratedFormats.rules[4].format == clip::kFormatPrivateKeyMnemonic &&
        migratedFormats.rules[3].name == L"blockchain" &&
        migratedFormats.rules[4].name == L"blockchain";
    const bool formatsSaved =
        formatsMigrated && migratedFormats.Save(formatMigrationName);
    clip::Config reloadedFormats;
    const bool formatsReloaded =
        formatsSaved && reloadedFormats.Load(formatMigrationName) &&
        reloadedFormats.rules.size() == 5 &&
        reloadedFormats.rules[3].format == clip::kFormatCryptoAddress &&
        reloadedFormats.rules[4].format == clip::kFormatPrivateKeyMnemonic;
    DeleteFileW((std::wstring(formatMigrationName) + L".bak").c_str());
    DeleteFileW(formatMigrationName);
    if (!formatsReloaded) return 109;

    clip::Config preserved;
    preserved.settings.balloonNotificationsDisabled = true;
    preserved.settings.shortcutOnlyMode = true;
    preserved.settings.shortcutDirectAllow = true;
    preserved.settings.shortcutAuthorizationWindowMs = 1750;
    preserved.settings.cryptoProtection = true;
    preserved.settings.maxLogEntries = 321;
    preserved.settings.previewEnabled = false;
    preserved.settings.captureImageFileSnapshots = true;
    preserved.settings.autostart = true;
    preserved.settings.startGlobalProtection = true;
    preserved.settings.startMinimized = true;
    preserved.settings.windowWidth = 1234;
    preserved.settings.windowHeight = 777;
    preserved.rules.push_back({L"keep.exe", false, clip::kBlockRead});
    wchar_t oversizedName[MAX_PATH] = {};
    if (!GetTempFileNameW(tempDir, L"cps", 0, oversizedName)) return 18;
    const std::string oversizedPattern(32769, 'x');
    const std::string oversizedJson =
        "{\"rules\":[{\"pattern\":\"" + oversizedPattern +
        "\",\"isPath\":false,\"action\":3}]}";
    if (!WriteUtf8BomFile(oversizedName, oversizedJson)) {
        DeleteFileW(oversizedName);
        return 19;
    }
    const bool oversizedRejected = !preserved.Load(oversizedName);
    const bool preservedAfterOversized =
        preserved.settings.balloonNotificationsDisabled &&
        preserved.settings.shortcutOnlyMode &&
        preserved.settings.shortcutDirectAllow &&
        preserved.settings.shortcutAuthorizationWindowMs == 1750 &&
        preserved.settings.cryptoProtection &&
        preserved.settings.maxLogEntries == 321 &&
        !preserved.settings.previewEnabled &&
        preserved.settings.captureImageFileSnapshots &&
        preserved.settings.autostart &&
        preserved.settings.startGlobalProtection &&
        preserved.settings.startMinimized &&
        preserved.settings.windowWidth == 1234 &&
        preserved.settings.windowHeight == 777 &&
        preserved.rules.size() == 1 &&
        preserved.rules[0].pattern == L"keep.exe" &&
        preserved.rules[0].action == clip::kBlockRead;
    DeleteFileW((std::wstring(oversizedName) + L".bak").c_str());
    DeleteFileW(oversizedName);
    if (!oversizedRejected || !preservedAfterOversized) return 20;

    wchar_t tooManyName[MAX_PATH] = {};
    if (!GetTempFileNameW(tempDir, L"cps", 0, tooManyName)) return 21;
    std::string tooManyJson = "{\"rules\":[";
    for (int i = 0; i < 4097; ++i) {
        if (i != 0) tooManyJson += ',';
        tooManyJson += "{\"pattern\":\"rule" + std::to_string(i) +
                       ".exe\",\"isPath\":false,\"action\":1}";
    }
    tooManyJson += "]}";
    if (!WriteUtf8BomFile(tooManyName, tooManyJson)) {
        DeleteFileW(tooManyName);
        return 22;
    }
    const bool tooManyRejected = !preserved.Load(tooManyName);
    const bool preservedAfterTooMany =
        preserved.settings.balloonNotificationsDisabled &&
        preserved.settings.shortcutOnlyMode &&
        preserved.settings.shortcutDirectAllow &&
        preserved.settings.shortcutAuthorizationWindowMs == 1750 &&
        preserved.settings.cryptoProtection &&
        preserved.settings.maxLogEntries == 321 &&
        !preserved.settings.previewEnabled &&
        preserved.settings.captureImageFileSnapshots &&
        preserved.settings.autostart &&
        preserved.settings.startGlobalProtection &&
        preserved.settings.startMinimized &&
        preserved.settings.windowWidth == 1234 &&
        preserved.settings.windowHeight == 777 &&
        preserved.rules.size() == 1 &&
        preserved.rules[0].pattern == L"keep.exe" &&
        preserved.rules[0].action == clip::kBlockRead;
    DeleteFileW((std::wstring(tooManyName) + L".bak").c_str());
    DeleteFileW(tooManyName);
    if (!tooManyRejected || !preservedAfterTooMany) return 23;

    wchar_t invalidSaveName[MAX_PATH] = {};
    if (!GetTempFileNameW(tempDir, L"cps", 0, invalidSaveName)) return 26;
    const std::string originalBytes = "{\"sentinel\":true}\r\n";
    if (!WriteUtf8BomFile(invalidSaveName, originalBytes)) {
        DeleteFileW(invalidSaveName);
        return 27;
    }
    std::string beforeInvalidSave;
    if (!ReadFileBytes(invalidSaveName, beforeInvalidSave)) {
        DeleteFileW(invalidSaveName);
        return 28;
    }
    clip::Config invalidSave = preserved;
    invalidSave.rules[0].pattern = L"bad";
    invalidSave.rules[0].pattern.push_back((wchar_t)0xD800);
    const bool saveRejected = !invalidSave.Save(invalidSaveName);
    std::string afterInvalidSave;
    const bool originalPreserved = ReadFileBytes(invalidSaveName, afterInvalidSave) &&
                                   afterInvalidSave == beforeInvalidSave;
    DeleteFileW((std::wstring(invalidSaveName) + L".tmp").c_str());
    DeleteFileW(invalidSaveName);
    if (!saveRejected || !originalPreserved) return 29;

    // A directory occupying the temporary path simulates an exclusive
    // config.json.tmp collision. Save must fail before replacing the original
    // file, and the caller can safely roll its in-memory working copy back.
    wchar_t blockedSaveName[MAX_PATH] = {};
    if (!GetTempFileNameW(tempDir, L"cps", 0, blockedSaveName)) return 30;
    const std::string blockedPayload = "{\"sentinel\":\"unchanged\"}\r\n";
    const std::string blockedOriginal = "\xEF\xBB\xBF" + blockedPayload;
    if (!WriteUtf8BomFile(blockedSaveName, blockedPayload)) {
        DeleteFileW(blockedSaveName);
        return 31;
    }
    const std::wstring blockedTemp = std::wstring(blockedSaveName) + L".tmp";
    if (!CreateDirectoryW(blockedTemp.c_str(), nullptr)) {
        DeleteFileW(blockedSaveName);
        return 32;
    }
    clip::Config blockedSave = preserved;
    blockedSave.rules[0].pattern = L"must-not-replace.exe";
    const bool collisionRejected = !blockedSave.Save(blockedSaveName);
    std::string afterCollision;
    const bool collisionPreserved = ReadFileBytes(blockedSaveName, afterCollision) &&
                                    afterCollision == blockedOriginal;
    const bool blockerStillPresent =
        GetFileAttributesW(blockedTemp.c_str()) != INVALID_FILE_ATTRIBUTES;
    RemoveDirectoryW(blockedTemp.c_str());
    DeleteFileW(blockedSaveName);
    if (!collisionRejected || !collisionPreserved || !blockerStillPresent)
        return 33;

    ULONGLONG creationTime = 0;
    std::wstring executablePath;
    if (!clip::ProcessCreationTime(GetCurrentProcess(), creationTime) ||
        !clip::ModulePath(nullptr, executablePath))
        return 34;
    const ULONGLONG wrongCreationTime =
        creationTime == MAXULONGLONG ? creationTime - 1 : creationTime + 1;
    const clip::RemoteHookStartResult staleIdentity = clip::RemoteHookStart(
        GetCurrentProcessId(), wrongCreationTime, executablePath);
    if (staleIdentity.started || staleIdentity.retainedReference ||
        staleIdentity.error != ERROR_PROCESS_ABORTED)
        return 35;
    return 0;
}
