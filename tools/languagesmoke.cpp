#include "config.h"
#include "i18n.h"
#include "ipc.h"
#include "../app/resource.h"
#include <windows.h>
#include <commctrl.h>
#include <atomic>
#include <algorithm>
#include <cstdio>
#include <stdexcept>
#include <string>
#include <thread>
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

void UnitTests() {
    for (int i = 0; i < static_cast<int>(TextId::TextCount); ++i) {
        const auto id = static_cast<TextId>(i);
        CHECK(*UiText(id, Language::Chinese));
        CHECK(*UiText(id, Language::English));
    }
    TempConfig temp;
    Config config;
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
    }
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
        CHECK(Wait([&] {
            pipe = CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
            return pipe != INVALID_HANDLE_VALUE;
        }));
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
                        PutU32(ack, kStateAckCapabilityMarkerV12);
                        PutU8(ack, extended ? 1 : 0);
                        PutU8(ack, kStateAckTextMetadataAvailable | kStateAckCryptoMappingAvailable);
                        try { Send(kIpcStateAck, ack); } catch (...) { return; }
                        if (frame.payloadSize == 11 && frame.payload[10] == 1) ready.store(true);
                    }
                    input.erase(0, frame.consumed);
                }
            }
        });
        CHECK(Wait([&] { return ready.load(); }));
    }
    void Event(BuiltinRule builtin, PreviewKind kind) {
        std::string payload;
        PutU32(payload, GetCurrentProcessId());
        PutU64(payload, 0);
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
    void Confirmation() {
        std::string payload;
        PutU64(payload, 7); PutU8(payload, kOpRead); PutU32(payload, CF_UNICODETEXT);
        PutU32(payload, 0); PutWStr(payload, L""); PutWStr(payload, L"");
        PutWStr(payload, L"user rule"); PutWStr(payload, L"");
        PutU32(payload, 60000); PutU8(payload, 1);
        PutU8(payload, static_cast<BYTE>(PreviewKind::Empty));
        Send(kIpcConfirmRequest, payload);
    }
};

void UiTests(const wchar_t* path) {
    TempConfig temp;
    Config config;
    config.settings.language = Language::Chinese;
    config.settings.startMinimized = true;
    config.settings.balloonNotificationsDisabled = true;
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
    client.Event(BuiltinRule::None, PreviewKind::Text);
    client.Event(BuiltinRule::CryptoReplacement, PreviewKind::CryptoAddress);
    HWND list = GetDlgItem(app.window, 102);
    CHECK(Wait([&] { return ListView_GetItemCount(list) == 2; }));
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
        CHECK(app.Cell(0, 7) == UiText(TextId::BuiltinCryptoReplacement, language));
        CHECK(app.Cell(0, 10) == UiText(TextId::CryptoAddressHidden, language));
        CHECK(app.Cell(1, 7) == UiText(TextId::BuiltinCryptoReplacement, Language::Chinese));
        CHECK(app.Cell(1, 10) == UiText(TextId::CryptoAddressHidden, Language::Chinese));
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
            PostMessageW(editor, WM_COMMAND, IDCANCEL, 0);
            CHECK(Wait([&] { return !IsWindow(editor); }));
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
}
}

int wmain(int argc, wchar_t** argv) {
    try {
        if (argc > 1) UiTests(argv[1]);
        else UnitTests();
        std::puts(argc > 1 ? "Language UI: menus, dialogs, live confirmation, IPC metadata, user text, rollback and restart passed."
                          : "Language: catalogs, persistence, legacy fallback and user text preservation passed.");
        return 0;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "Language smoke failed: %s\n", error.what());
        return 1;
    }
}
