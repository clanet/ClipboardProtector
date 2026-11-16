#include "config.h"
#include "i18n.h"
#include "ipc.h"
#include "rules.h"
#include "../app/resource.h"
#include <windows.h>
#include <commctrl.h>
#include <atomic>
#include <algorithm>
#include <cstdio>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace {
using namespace clip;
#define CHECK(condition) do { if (!(condition)) throw std::runtime_error( \
    "line " + std::to_string(__LINE__) + ": " #condition); } while (false)

template<class Predicate> bool Wait(Predicate predicate, DWORD ms = 5000) {
    const auto deadline = GetTickCount64() + ms;
    do { if (predicate()) return true; Sleep(20); } while (GetTickCount64() < deadline);
    return predicate();
}

struct TempConfig {
    std::wstring directory, file;
    TempConfig() {
        wchar_t temp[MAX_PATH]{}, name[MAX_PATH]{};
        CHECK(GetTempPathW(MAX_PATH, temp));
        CHECK(GetTempFileNameW(temp, L"cpl", 0, name));
        CHECK(DeleteFileW(name));
        CHECK(CreateDirectoryW(name, nullptr));
        directory = name;
        file = directory + L"\\config.json";
    }
    ~TempConfig() {
        RemoveDirectoryW((file + L".tmp").c_str());
        DeleteFileW((file + L".tmp").c_str());
        DeleteFileW((file + L".bak").c_str());
        DeleteFileW(file.c_str());
        RemoveDirectoryW(directory.c_str());
    }
    void Write(const std::string& data) {
        HANDLE handle = CreateFileW(file.c_str(), GENERIC_WRITE, 0, nullptr,
                                    CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        CHECK(handle != INVALID_HANDLE_VALUE);
        DWORD written = 0;
        const bool ok = WriteFile(handle, data.data(), static_cast<DWORD>(data.size()), &written, nullptr) &&
            written == data.size();
        CloseHandle(handle);
        CHECK(ok);
    }
};

std::vector<RuleLite> CompiledRules(const Config& config) {
    std::vector<RuleLite> rules;
    rules.reserve(config.rules.size());
    for (const auto& rule : config.rules) {
        RuleLite lite;
        lite.patternLower = ToLower(rule.pattern);
        lite.isPath = rule.isPath;
        lite.action = rule.action;
        lite.showNotification = rule.showNotification;
        lite.hideFromLogList = rule.hideFromLogList;
        lite.name = rule.name;
        lite.operations = rule.operations;
        lite.format = rule.format;
        lite.contentPattern = rule.contentRegex;
        lite.ignoreCase = rule.ignoreCase;
        lite.enabled = rule.enabled;
        lite.sourceMode = rule.sourceMode;
        lite.sourcePatternLower = ToLower(rule.sourcePattern);
        lite.confirmTimeoutMs = rule.confirmTimeoutMs;
        lite.timeoutBlock = rule.timeoutBlock;
        CHECK(CompileRuleContentRegex(lite));
        rules.push_back(std::move(lite));
    }
    return rules;
}

void FirstRunConfigTests() {
    for (Language language : {Language::Chinese, Language::English}) {
        TempConfig temp;
        const Config initial = MakeFirstRunConfig(language);
        CHECK(initial.Save(temp.file));
        Config loaded;
        CHECK(loaded.Load(temp.file));
        CHECK(loaded.settings.language == language);
        CHECK(loaded.settings.shortcutDirectAllow && loaded.settings.cryptoProtection);
        CHECK(loaded.rules.size() == 2 && IsRuleSetSupported(loaded.rules));
        CHECK(loaded.rules[0].name == UiText(TextId::DefaultNonTextSilentRule, language));
        CHECK(loaded.rules[1].name == UiText(TextId::DefaultClipboardNotifyRule, language));

        const auto rules = CompiledRules(loaded);
        for (const unsigned char operation : {kRuleRead, kRuleWrite}) {
            for (bool text : {false, true}) {
                RuleMatch match;
                CHECK(FindClipboardRule(rules, L"example.exe", L"c:\\example.exe",
                                        123, operation, text, {}, nullptr, false, match));
                CHECK(match.action == kRuleAllow && !match.hideFromLogList);
                CHECK(match.showNotification == text);
                CHECK(match.name == loaded.rules[text ? 1 : 0].name);
            }
        }

        loaded.rules.resize(1);
        loaded.rules[0].name = L"My custom rule";
        loaded.rules[0].enabled = false;
        CHECK(loaded.Save(temp.file));
        Config customized;
        CHECK(customized.Load(temp.file) && customized.rules.size() == 1);
        CHECK(customized.rules[0].name == L"My custom rule" && !customized.rules[0].enabled);
        customized.rules.clear();
        CHECK(customized.Save(temp.file));
        Config empty;
        CHECK(empty.Load(temp.file) && empty.rules.empty());
        temp.Write("{}");
        Config legacy;
        CHECK(legacy.Load(temp.file) && legacy.rules.empty());
    }
}

void UnitTests() {
    FirstRunConfigTests();
    for (int i = 0; i < static_cast<int>(TextId::TextCount); ++i) {
        const auto id = static_cast<TextId>(i);
        CHECK(*UiText(id, Language::Chinese));
        CHECK(*UiText(id, Language::English));
    }
    TempConfig temp;
    Config config;
    CHECK(config.settings.cryptoProtection);
    CHECK(config.settings.shortcutDirectAllow);
    Rule rule;
    rule.pattern = L"example.exe";
    rule.name = UiText(TextId::BuiltinCryptoReplacement, Language::Chinese);
    config.rules.push_back(rule);
    for (Language language : {Language::English, Language::Chinese}) {
        SetLanguage(language);
        config.settings.language = language;
        CHECK(config.Save(temp.file));
        Config loaded;
        CHECK(loaded.Load(temp.file));
        CHECK(loaded.settings.language == language && loaded.rules[0].name == rule.name);
        CHECK(loaded.settings.cryptoProtection);
        CHECK(loaded.settings.shortcutDirectAllow);
        CHECK(DisplayRuleName(rule.name, BuiltinRule::None) == rule.name);
        CHECK(DisplayRuleName(rule.name, BuiltinRule::CryptoReplacement) == UiText(TextId::BuiltinCryptoReplacement));
        const std::wstring userText = UiText(TextId::CryptoAddressHidden, Language::Chinese);
        CHECK(DisplayPreview(userText, PreviewKind::Text) == userText);
        CHECK(DisplayPreview(userText, PreviewKind::CryptoAddress) == UiText(TextId::CryptoAddressHidden));
        CHECK(DisplayPreview(L"literal {0}", PreviewKind::Truncated) ==
              std::wstring(L"literal {0}") + UiText(TextId::ContentTruncated));
        CHECK(UiFormat(TextId::RememberRuleFailedDetail, {L"{1}", L"user {0}"}).find(L"user {0}") != std::wstring::npos);
    }
    for (const char* value : {"{}", "{\"language\":\"unsupported\"}", "{\"language\":9}"}) {
        temp.Write(std::string("{\"settings\":") + value + ",\"rules\":[]}");
        Config legacy;
        legacy.settings.language = Language::English;
        CHECK(legacy.Load(temp.file));
        CHECK(legacy.settings.language == Language::Chinese);
        CHECK(legacy.settings.cryptoProtection);
        CHECK(legacy.settings.shortcutDirectAllow);
    }
    temp.Write("{\"settings\":{\"cryptoProtection\":false,\"shortcutDirectAllow\":false},\"rules\":[]}");
    Config disabledCrypto;
    CHECK(disabledCrypto.Load(temp.file) && !disabledCrypto.settings.cryptoProtection);
    CHECK(!disabledCrypto.settings.shortcutDirectAllow);
    CHECK(disabledCrypto.Save(temp.file));
    Config disabledReloaded;
    CHECK(disabledReloaded.Load(temp.file) && !disabledReloaded.settings.cryptoProtection);
    CHECK(!disabledReloaded.settings.shortcutDirectAllow);
    temp.Write("{\"settings\":{\"language\":\"en\"},\"rules\":[]}");
    Config english;
    CHECK(english.Load(temp.file) && english.settings.language == Language::English);
    CHECK(CreateDirectoryW((temp.file + L".tmp").c_str(), nullptr));
    english.settings.language = Language::Chinese;
    CHECK(!english.Save(temp.file));
    Config preserved;
    CHECK(preserved.Load(temp.file) && preserved.settings.language == Language::English);
}

std::wstring WindowText(HWND window) {
    wchar_t text[2048]{};
    DWORD_PTR result = 0;
    if (!SendMessageTimeoutW(window, WM_GETTEXT, _countof(text), reinterpret_cast<LPARAM>(text),
                             SMTO_ABORTIFHUNG, 1000, &result)) return L"";
    return text;
}
struct Search { DWORD pid; const wchar_t* cls; HWND result = nullptr; };
BOOL CALLBACK FindWindowForPid(HWND window, LPARAM param) {
    auto& search = *reinterpret_cast<Search*>(param);
    DWORD pid = 0;
    GetWindowThreadProcessId(window, &pid);
    wchar_t cls[128]{};
    GetClassNameW(window, cls, _countof(cls));
    if (pid == search.pid && wcscmp(cls, search.cls) == 0 &&
        (wcscmp(cls, L"#32770") != 0 || IsWindowVisible(window))) {
        search.result = window;
        return FALSE;
    }
    return TRUE;
}
HWND Find(DWORD pid, const wchar_t* cls) {
    Search search{pid, cls};
    EnumWindows(FindWindowForPid, reinterpret_cast<LPARAM>(&search));
    return search.result;
}

struct AppProcess {
    PROCESS_INFORMATION process{};
    HWND window = nullptr;
    ~AppProcess() { Stop(); }
    void Start(const wchar_t* path) {
        STARTUPINFOW startup{sizeof(startup)};
        std::wstring command = L"\"" + std::wstring(path) + L"\"";
        CHECK(CreateProcessW(path, command.data(), nullptr, nullptr, FALSE, 0,
                             nullptr, nullptr, &startup, &process));
        CHECK(Wait([&] { window = Find(process.dwProcessId, L"ClipProtectorMainWnd"); return window != nullptr; }));
        CHECK(Wait([&] { return GetMenu(window) && GetDlgItem(window, 102); }));
    }
    void Stop(bool requireCleanExit = false) {
        if (!process.hProcess) return;
        if (window) PostMessageW(window, WM_COMMAND, 3007, 0);
        const bool exited = WaitForSingleObject(process.hProcess, 15000) == WAIT_OBJECT_0;
        if (!exited) {
            TerminateProcess(process.hProcess, 1);
            WaitForSingleObject(process.hProcess, 1000);
        }
        DWORD exitCode = 1;
        GetExitCodeProcess(process.hProcess, &exitCode);
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
        process = {};
        window = nullptr;
        if (requireCleanExit) CHECK(exited && exitCode == 0);
    }
    std::wstring Cell(int row, int column) {
        const SIZE_T bytes = sizeof(LVITEMW) + 2048 * sizeof(wchar_t);
        void* remote = VirtualAllocEx(process.hProcess, nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        CHECK(remote);
        LVITEMW item{};
        item.iSubItem = column;
        item.pszText = reinterpret_cast<wchar_t*>(static_cast<BYTE*>(remote) + sizeof(item));
        item.cchTextMax = 2048;
        wchar_t text[2048]{};
        const bool written = WriteProcessMemory(process.hProcess, remote, &item, sizeof(item), nullptr) != 0;
        DWORD_PTR result = 0;
        const bool sent = written && SendMessageTimeoutW(GetDlgItem(window, 102), LVM_GETITEMTEXTW, row,
            reinterpret_cast<LPARAM>(remote), SMTO_ABORTIFHUNG, 1000, &result);
        const bool read = sent && ReadProcessMemory(process.hProcess, item.pszText, text, sizeof(text), nullptr);
        VirtualFreeEx(process.hProcess, remote, 0, MEM_RELEASE);
        CHECK(read);
        return text;
    }
};

struct MockClient {
    HANDLE pipe = INVALID_HANDLE_VALUE;
    std::atomic<bool> stop{false}, ready{false};
    std::atomic<unsigned long long> responseToken{0};
    std::atomic<int> responseAllow{-1};
    std::thread worker;
    ~MockClient() {
        stop.store(true);
        if (worker.joinable()) worker.join();
        if (pipe != INVALID_HANDLE_VALUE) CloseHandle(pipe);
    }
    void Send(BYTE type, const std::string& payload) {
        std::string frame;
        PutFrame(frame, type, payload);
        DWORD written = 0;
        CHECK(WriteFile(pipe, frame.data(), static_cast<DWORD>(frame.size()), &written, nullptr) && written == frame.size());
    }
    void Connect(const std::wstring& name) {
        DWORD connectError = ERROR_SUCCESS;
        const bool connected = Wait([&] {
            pipe = CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
            if (pipe == INVALID_HANDLE_VALUE) connectError = GetLastError();
            return pipe != INVALID_HANDLE_VALUE;
        });
        if (!connected)
            throw std::runtime_error("Mock pipe connection failed, Win32=" + std::to_string(connectError));
        worker = std::thread([this] {
            std::string input;
            bool extended = false;
            while (!stop.load()) {
                DWORD available = 0, read = 0;
                if (!PeekNamedPipe(pipe, nullptr, 0, nullptr, &available, nullptr)) break;
                if (!available) { Sleep(10); continue; }
                char buffer[4096];
                if (!ReadFile(pipe, buffer, (std::min)(available, DWORD(sizeof(buffer))), &read, nullptr)) break;
                input.append(buffer, read);
                IpcFrameView frame;
                while (ParseFrame(input.data(), input.size(), frame) == IpcFrameResult::complete) {
                    if (frame.type == kIpcRulesExtended) extended = true;
                    if (frame.type == kIpcSettings) {
                        std::string ack;
                        PutU32(ack, kStateAckCapabilityMarkerV13);
                        PutU8(ack, extended ? 1 : 0);
                        PutU8(ack, kStateAckTextMetadataAvailable | kStateAckCryptoMappingAvailable);
                        try { Send(kIpcStateAck, ack); } catch (...) { return; }
                        if (frame.payloadSize == 12 && frame.payload[10] == 1 &&
                            frame.payload[11] == 1)
                            ready.store(true);
                    }
                    if (frame.type == kIpcConfirmResponse) {
                        Reader reader(frame.payload, frame.payloadSize);
                        unsigned long long token = 0;
                        BYTE allow = 0;
                        if (!reader.GetU64(token) || !reader.GetU8(allow) ||
                            reader.n != 0)
                            return;
                        responseAllow.store(allow);
                        responseToken.store(token);
                    }
                    input.erase(0, frame.consumed);
                }
            }
        });
        CHECK(Wait([&] { return ready.load(); }));
    }
    void Event(unsigned long long hash, BuiltinRule builtin, PreviewKind kind) {
        std::string payload;
        PutU32(payload, GetCurrentProcessId());
        PutU64(payload, hash);
        PutU8(payload, kOpRead);
        PutU32(payload, CF_UNICODETEXT);
        PutU8(payload, kRuleBlock);
        PutU8(payload, 1);
        PutWStr(payload, UiText(TextId::CryptoAddressHidden, Language::Chinese));
        PutU32(payload, 1); PutU32(payload, 0);
        PutWStr(payload, L""); PutWStr(payload, L"");
        PutWStr(payload, UiText(TextId::BuiltinCryptoReplacement, Language::Chinese));
        PutU64(payload, 0); PutU8(payload, 0);
        PutU8(payload, kSnapshotNone); PutU32(payload, 0); PutU32(payload, 0);
        PutU8(payload, static_cast<BYTE>(builtin)); PutU8(payload, static_cast<BYTE>(kind));
        Send(kIpcEvent, payload);
    }
    void Confirmation(unsigned long long token = 7, DWORD timeoutMs = 60000,
                      ULONGLONG deadline = 0) {
        std::string payload;
        PutU64(payload, token); PutU8(payload, kOpRead); PutU32(payload, CF_UNICODETEXT);
        PutU32(payload, 0); PutWStr(payload, L""); PutWStr(payload, L"");
        PutWStr(payload, L"user rule"); PutWStr(payload, L"");
        PutU32(payload, timeoutMs); PutU8(payload, 1);
        PutU8(payload, static_cast<BYTE>(PreviewKind::Empty));
        PutU64(payload, deadline ? deadline : GetTickCount64() + timeoutMs);
        Send(kIpcConfirmRequest, payload);
    }
};

void RememberedDecisionTests(const wchar_t* path, const TempConfig& temp,
                             const std::wstring& pipeName) {
    Config config;
    config.settings.language = Language::English;
    config.settings.startMinimized = true;
    config.settings.balloonNotificationsDisabled = true;
    config.settings.cryptoProtection = false;
    Rule ask;
    ask.name = L"Highest-priority confirmation";
    ask.pattern = L"*";
    ask.action = kRuleConfirm;
    ask.priority = kMinRulePriority;
    config.rules.push_back(ask);
    CHECK(config.Save(temp.file));

    const auto FindConfirmation = [&](AppProcess& app) {
        HWND window = nullptr;
        CHECK(Wait([&] {
            window = Find(app.process.dwProcessId, L"ClipProtectorConfirmWnd");
            return window && GetDlgItem(window, 4103);
        }));
        SendMessageW(GetDlgItem(window, 4103), BM_SETCHECK, BST_CHECKED, 0);
        return window;
    };
    const auto Decision = [&](const Config& saved, const std::wstring& process) {
        RuleMatch match;
        CHECK(FindClipboardRule(CompiledRules(saved), ToLower(process), L"",
                                GetCurrentProcessId(), kRuleRead, true, {},
                                nullptr, true, match));
        return match.action;
    };

    AppProcess app;
    Config remembered;
    app.Start(path);
    {
        MockClient client;
        client.Connect(pipeName);
        CHECK(Decision(config, L"languagesmoke.exe") == kRuleConfirm);
        client.Confirmation(101);
        HWND window = FindConfirmation(app);
        CHECK(WindowText(GetDlgItem(window, 4103)) ==
              UiText(TextId::RememberChoice, Language::English));
        PostMessageW(window, WM_COMMAND, IDOK, 0);
        CHECK(Wait([&] {
            return client.responseToken.load() == 101 && !IsWindow(window);
        }));
        CHECK(client.responseAllow.load() == 1);
        CHECK(remembered.Load(temp.file) && remembered.rules.size() == 2);
        CHECK(remembered.rules[0].priority == kMinRulePriority);
        CHECK(remembered.rules[1].name == ask.name);
        CHECK(Decision(remembered, remembered.rules[0].pattern) == kRuleAllow);
    }
    app.Stop(true);

    // Editing the first remembered rule must not make Upsert return before
    // restoring its actual decision and the other generated-rule fields.
    remembered.rules[0].action = kRuleBlock;
    remembered.rules[0].showNotification = true;
    remembered.rules[0].hideFromLogList = true;
    remembered.rules[0].ignoreCase = false;
    CHECK(remembered.Save(temp.file));
    app.Start(path);
    {
        MockClient client;
        client.Connect(pipeName);
        const std::wstring process = remembered.rules[0].pattern;
        CHECK(Decision(remembered, process) == kRuleBlock);

        const ULONGLONG deadline = GetTickCount64() + 1000;
        client.Confirmation(102, 1000, deadline);
        HWND lateWindow = FindConfirmation(app);
        CHECK(GetTickCount64() < deadline);
        DWORD_PTR result = 0;
        // Finish posts a genuine remembered Allow before expiry. The fixture
        // holds the main thread until that message is stale, with no timer
        // dispatch between the click and CompleteConfirmation.
        CHECK(SendMessageTimeoutW(app.window, WM_APP + 63, 1200, 0,
                                  SMTO_ABORTIFHUNG, 3000, &result));
        CHECK(result == 1);
        CHECK(Wait([&] {
            return client.responseToken.load() == 102 && !IsWindow(lateWindow);
        }));
        CHECK(client.responseAllow.load() == 0);
        Config expired;
        CHECK(expired.Load(temp.file) && expired.rules.size() == 2);
        CHECK(Decision(expired, process) == kRuleBlock);
        CHECK(expired.rules[0].showNotification &&
              expired.rules[0].hideFromLogList && !expired.rules[0].ignoreCase);

        client.Confirmation(103);
        HWND window = FindConfirmation(app);
        PostMessageW(window, WM_COMMAND, IDOK, 0);
        CHECK(Wait([&] {
            return client.responseToken.load() == 103 && !IsWindow(window);
        }));
        CHECK(client.responseAllow.load() == 1);
        Config updated;
        CHECK(updated.Load(temp.file) && updated.rules.size() == 2);
        CHECK(updated.rules[0].priority == kMinRulePriority);
        CHECK(updated.rules[0].name == remembered.rules[0].name);
        CHECK(!updated.rules[0].showNotification &&
              !updated.rules[0].hideFromLogList && updated.rules[0].ignoreCase);
        CHECK(Decision(updated, process) == kRuleAllow);
        CHECK(updated.rules[1].name == ask.name);
    }
    app.Stop(true);
}

void UiTests(const wchar_t* path) {
    TempConfig temp;
    Config config;
    config.settings.language = Language::Chinese;
    config.settings.startMinimized = true;
    config.settings.balloonNotificationsDisabled = true;
    config.settings.cryptoProtection = false;
    Rule existing;
    existing.name = L"Existing rule";
    existing.pattern = L"existing.exe";
    config.rules.push_back(existing);
    CHECK(config.Save(temp.file));
    const std::wstring suffix = std::to_wstring(GetCurrentProcessId());
    const std::wstring pipeName = L"\\\\.\\pipe\\ClipboardProtector.LanguageSmoke." + suffix;
    SetEnvironmentVariableW(L"CLIP_TEST_CONFIG_DIR", temp.directory.c_str());
    SetEnvironmentVariableW(L"CLIP_TEST_PIPE_NAME", pipeName.c_str());
    for (const wchar_t* variable : {L"CLIP_TEST_STOP_EVENT", L"CLIP_TEST_CONTROLLER_MUTEX",
                                    L"CLIP_TEST_SOURCE_MAP", L"CLIP_TEST_CRYPTO_MAP"})
        SetEnvironmentVariableW(variable, (L"Local\\ClipboardProtector.LanguageSmoke." + suffix + variable).c_str());
    SetEnvironmentVariableW(L"CLIPBOARDPROTECTOR_ENABLE_GLOBAL_HOOK", nullptr);
    SetEnvironmentVariableW(L"CLIPBOARDPROTECTOR_TEST_TARGET_PID", nullptr);
    AppProcess app;
    app.Start(path);
    MockClient client;
    client.Connect(pipeName);
    client.Event(1, BuiltinRule::None, PreviewKind::Text);
    client.Event(2, BuiltinRule::CryptoReplacement, PreviewKind::CryptoAddress);
    HWND list = GetDlgItem(app.window, 102);
    CHECK(Wait([&] { return ListView_GetItemCount(list) == 2; }));
    CHECK(SendMessageW(app.window, WM_APP + 62, 123, 0) == 1);
    CHECK(ListView_GetItemCount(list) == 3);
    client.Confirmation();
    HWND confirmation = nullptr;
    CHECK(Wait([&] { confirmation = Find(app.process.dwProcessId, L"ClipProtectorConfirmWnd"); return confirmation != nullptr; }));
    CHECK(Wait([&] { return GetDlgItem(confirmation, 4103) != nullptr; }));
    SendMessageW(GetDlgItem(confirmation, 4103), BM_SETCHECK, BST_CHECKED, 0);
    const auto Switch = [&](Language language) {
        const UINT command = language == Language::English ? IDM_LANGUAGE_ENGLISH : IDM_LANGUAGE_CHINESE;
        PostMessageW(app.window, WM_COMMAND, command, 0);
        CHECK(Wait([&] { return WindowText(app.window) == UiText(TextId::ClipboardProtector, language); }));
        CHECK(WindowText(confirmation) == UiText(TextId::ConfirmClipboardAccess, language));
        CHECK(WindowText(GetDlgItem(confirmation, 4103)) == UiText(TextId::RememberChoice, language));
        CHECK(SendMessageW(GetDlgItem(confirmation, 4103), BM_GETCHECK, 0, 0) == BST_CHECKED);
        HMENU menu = GetSubMenu(GetSubMenu(GetMenu(app.window), 2), 4);
        CHECK((GetMenuState(menu, command, MF_BYCOMMAND) & MF_CHECKED) != 0);
        CHECK(app.Cell(0, 5) == UiText(TextId::ClipboardContentChanged, language));
        CHECK(app.Cell(0, 7) == UiText(TextId::CryptoClipboardMonitor, language));
        CHECK(app.Cell(0, 8) == UiText(TextId::ChangeAlert, language));
        CHECK(app.Cell(0, 10) == UiText(TextId::CryptoClipboardChangedContent, language));
        CHECK(app.Cell(0, 11) == UiText(TextId::CryptoChanged, language));
        CHECK(app.Cell(1, 7) == UiText(TextId::BuiltinCryptoReplacement, language));
        CHECK(app.Cell(1, 10) == UiText(TextId::CryptoAddressHidden, language));
        CHECK(app.Cell(2, 7) == UiText(TextId::BuiltinCryptoReplacement, Language::Chinese));
        CHECK(app.Cell(2, 10) == UiText(TextId::CryptoAddressHidden, Language::Chinese));
        Config saved;
        CHECK(saved.Load(temp.file) && saved.settings.language == language);
        CHECK(!saved.settings.startGlobalProtection);
    };
    Switch(Language::English);
    Switch(Language::Chinese);
    Switch(Language::English);
    PostMessageW(confirmation, WM_COMMAND, IDCANCEL, 0);
    CHECK(Wait([&] { return !IsWindow(confirmation); }));
    for (auto pair : {std::pair<UINT, TextId>{3004, TextId::Settings},
                     {3012, TextId::KeyboardShortcuts}, {3001, TextId::ClipboardAccessRules},
                     {3010, TextId::SingleProcessProtection}}) {
        PostMessageW(app.window, WM_COMMAND, pair.first, 0);
        HWND dialog = nullptr;
        CHECK(Wait([&] { dialog = Find(app.process.dwProcessId, L"#32770");
                        return dialog && WindowText(dialog) == UiText(pair.second, Language::English); }));
        CHECK(WindowText(GetDlgItem(dialog, IDCANCEL)) == L"Cancel");
        if (pair.first == 3001) {
            PostMessageW(dialog, WM_COMMAND, IDC_BTN_ADD, 0);
            HWND editor = nullptr;
            CHECK(Wait([&] { editor = Find(app.process.dwProcessId, L"#32770");
                            return editor && WindowText(editor) == L"Edit rule"; }));
            CHECK(WindowText(GetDlgItem(editor, IDOK)) == L"Save");
            CHECK(Wait([&] {
                HWND name = GetDlgItem(editor, IDC_ED_RULE_NAME);
                return name && WindowText(name) == L"New rule";
            }));
            HWND nameEdit = GetDlgItem(editor, IDC_ED_RULE_NAME);
            DWORD_PTR sentResult = 0;
            CHECK(SendMessageTimeoutW(nameEdit, WM_SETTEXT, 0,
                                      reinterpret_cast<LPARAM>(L"Newest rule"),
                                      SMTO_ABORTIFHUNG, 2000, &sentResult));
            HWND priorityCombo = GetDlgItem(editor, IDC_CMB_PRIORITY);
            CHECK(priorityCombo != nullptr);
            CHECK(SendMessageW(priorityCombo, CB_GETCOUNT, 0, 0) ==
                  clip::kMaxRulePriority - clip::kMinRulePriority + 1);
            CHECK(SendMessageW(priorityCombo, CB_GETCURSEL, 0, 0) ==
                  clip::kDefaultRulePriority);
            CHECK(SendMessageW(priorityCombo, CB_SETCURSEL,
                               clip::kMinRulePriority, 0) != CB_ERR);
            PostMessageW(editor, WM_COMMAND, IDOK, 0);
            CHECK(Wait([&] { return !IsWindow(editor); }));
            HWND ruleList = GetDlgItem(dialog, IDC_LIST_RULES);
            CHECK(ListView_GetItemCount(ruleList) == 2);
            CHECK(ListView_GetNextItem(ruleList, -1, LVNI_SELECTED) == 0);
            PostMessageW(dialog, WM_COMMAND, IDOK, 0);
            CHECK(Wait([&] { return !IsWindow(dialog); }));
            Config savedRules;
            CHECK(Wait([&] {
                return savedRules.Load(temp.file) &&
                       savedRules.rules.size() == 2;
            }));
            CHECK(savedRules.rules[0].name == L"Newest rule");
            CHECK(savedRules.rules[0].priority == clip::kMinRulePriority);
            CHECK(savedRules.rules[1].name == L"Existing rule");
            continue;
        }
        PostMessageW(dialog, WM_COMMAND, IDCANCEL, 0);
        CHECK(Wait([&] { return !IsWindow(dialog); }));
    }
    CHECK(CreateDirectoryW((temp.file + L".tmp").c_str(), nullptr));
    PostMessageW(app.window, WM_COMMAND, IDM_LANGUAGE_CHINESE, 0);
    HWND error = nullptr;
    CHECK(Wait([&] { error = Find(app.process.dwProcessId, L"#32770"); return error != nullptr; }));
    CHECK(WindowText(error) == L"Save failed");
    CHECK(WindowText(app.window) == L"Clipboard Protector");
    PostMessageW(error, WM_CLOSE, 0, 0);
    CHECK(Wait([&] { return !IsWindow(error); }));
    CHECK(RemoveDirectoryW((temp.file + L".tmp").c_str()));
    client.stop.store(true);
    client.worker.join();
    CloseHandle(client.pipe); client.pipe = INVALID_HANDLE_VALUE;
    app.Stop(true);
    app.Start(path);
    CHECK(Wait([&] { return WindowText(app.window) == L"Clipboard Protector"; }));
    app.Stop(true);
    RememberedDecisionTests(path, temp, pipeName);
}
}

int wmain(int argc, wchar_t** argv) {
    try {
        if (argc > 1) UiTests(argv[1]);
        else UnitTests();
        std::puts(argc > 1 ? "Language UI: menus, dialogs, live confirmation, remembered decisions, late-decision expiry, IPC metadata, user text, rollback and restart passed."
                          : "Language: catalogs, persistence, legacy fallback and user text preservation passed.");
        return 0;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "Language smoke failed: %s\n", error.what());
        return 1;
    }
}
