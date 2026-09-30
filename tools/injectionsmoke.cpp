#include <windows.h>
#include <shlobj.h>
#include "../common/config.h"
#include "../common/crypto.h"
#include "../common/ipc.h"
#include <algorithm>
#include <atomic>
#include <cstring>
#include <cstdio>
#include <cwctype>
#include <string>
#include <thread>
#include <vector>

namespace {

enum Command : LONG {
    kCommandNone = 0,
    kCommandGet = 1,
    kCommandSet = 2,
    kCommandEmpty = 3,
    kCommandExit = 4,
    kCommandStressStart = 5,
    kCommandStressStop = 6,
    kCommandShortcutGet = 7,
    kCommandShortcutSet = 8,
    kCommandSetText = 9,
    kCommandShortcutSetText = 10,
    kCommandSetDib = 11,
    kCommandSetFiles = 12,
    kCommandCopyShortcutGet = 13,
    kCommandPasteShortcutSet = 14,
    kCommandDelayedShortcutGet = 15,
    kCommandDelayedShortcutSet = 16,
    kCommandShiftInsertGet = 17,
    kCommandShiftInsertSet = 18,
    kCommandControlInsertSet = 19,
    kCommandControlInsertGet = 20,
    kCommandCopyText = 21,
    kCommandReadText = 22,
    kCommandClearClipboard = 23,
};

struct SharedState {
    volatile LONG command = kCommandNone;
    UINT format = 0;
    ULONG_PTR value = 0;
    DWORD error = ERROR_SUCCESS;
    volatile LONG stressRunning = 0;
    volatile LONG stressCalls = 0;
    volatile LONG stressThreadsCreated = 0;
    volatile LONG stressThreadFailures = 0;
    volatile LONG stressWorkers = 0;
    wchar_t text[clip::kMaxCryptoTextLength + 2] = {};
};

struct CommandResult {
    ULONG_PTR value = 0;
    DWORD error = ERROR_SUCCESS;
};

struct PipeEvent {
    DWORD pid = 0;
    unsigned long long hash = 0;
    bool cryptoContent = false;
    BYTE op = 0;
    DWORD format = 0;
    BYTE action = 0;
    bool showNotification = false;
    bool hideFromLogList = false;
    BYTE blocked = 0;
    std::wstring preview;
    bool gap = false;
    unsigned long long missingEvents = 0;
    DWORD sourcePid = 0;
    std::wstring sourceName;
    std::wstring sourcePath;
    std::wstring ruleName;
    BYTE snapshotKind = clip::kSnapshotNone;
    DWORD snapshotOriginalBytes = 0;
    std::vector<BYTE> snapshot;
};

bool g_logVisibilityEvents = false;

unsigned long long ParseHandle(const wchar_t* text) {
    return _wcstoui64(text, nullptr, 10);
}

bool WriteAll(HANDLE pipe, const std::string& bytes) {
    size_t offset = 0;
    while (offset < bytes.size()) {
        DWORD written = 0;
        DWORD chunk = (DWORD)(std::min)(bytes.size() - offset, (size_t)MAXDWORD);
        if (!WriteFile(pipe, bytes.data() + offset, chunk, &written, nullptr) ||
            written == 0)
            return false;
        offset += written;
    }
    return true;
}

bool ReadExact(HANDLE pipe, void* data, DWORD bytes) {
    BYTE* output = static_cast<BYTE*>(data);
    DWORD total = 0;
    while (total < bytes) {
        DWORD read = 0;
        if (!ReadFile(pipe, output + total, bytes - total, &read, nullptr) || read == 0)
            return false;
        total += read;
    }
    return true;
}

bool WaitForPipeData(HANDLE pipe, DWORD timeoutMs) {
    ULONGLONG deadline = GetTickCount64() + timeoutMs;
    do {
        DWORD available = 0;
        if (!PeekNamedPipe(pipe, nullptr, 0, nullptr, &available, nullptr)) return false;
        if (available > 0) return true;
        Sleep(10);
    } while (GetTickCount64() < deadline);
    return false;
}

bool ParseEventPayload(const char* data, size_t size, PipeEvent& event) {
    event = PipeEvent{};
    clip::Reader reader(data, size);
    if (!reader.GetU32(event.pid) || !reader.GetU64(event.hash) ||
        !reader.GetU8(event.op) || !reader.GetU32(event.format) ||
        !reader.GetU8(event.action) || !reader.GetU8(event.blocked) ||
        !reader.GetWStr(event.preview) ||
        event.preview.size() > 64)
        return false;
    event.cryptoContent =
        (event.hash & clip::kEventCryptoContentFlag) != 0;
    event.hash &= ~clip::kEventCryptoContentFlag;
    if (reader.n != 0) {
        DWORD sequence = 0;
        if (!reader.GetU32(sequence) || !reader.GetU32(event.sourcePid) ||
            !reader.GetWStr(event.sourceName) ||
            !reader.GetWStr(event.sourcePath) ||
            !reader.GetWStr(event.ruleName))
            return false;
        if (reader.n != 0 && !reader.GetU64(event.missingEvents)) return false;
        if (reader.n != 0 && g_logVisibilityEvents) {
            BYTE hidden = 0;
            if (!reader.GetU8(hidden) || hidden > 1) return false;
            event.hideFromLogList = hidden != 0;
        }
        if (reader.n != 0) {
            DWORD snapshotBytes = 0;
            if (!reader.GetU8(event.snapshotKind) ||
                !reader.GetU32(event.snapshotOriginalBytes) ||
                !reader.GetU32(snapshotBytes) ||
                snapshotBytes > clip::kMaxClipboardSnapshotBytes ||
                reader.n != snapshotBytes)
                return false;
            event.snapshot.assign(
                reinterpret_cast<const BYTE*>(reader.p),
                reinterpret_cast<const BYTE*>(reader.p) + snapshotBytes);
            reader.p += snapshotBytes;
            reader.n -= snapshotBytes;
        }
    }
    if (reader.n != 0) return false;
    event.showNotification =
        (event.action & clip::kEventNotificationFlag) != 0;
    event.action &= static_cast<BYTE>(~clip::kEventNotificationFlag);
    if (event.action == clip::kRuleShow) {
        event.action = clip::kRuleAllow;
        event.showNotification = true;
    }
    return event.op <= clip::kOpOpen && event.action <= clip::kBlockAlert &&
           event.blocked <= 1;
}

bool ReadEvent(HANDLE pipe, PipeEvent& event, DWORD timeoutMs,
               bool* stateAcknowledged = nullptr) {
    const ULONGLONG deadline = GetTickCount64() + timeoutMs;
    for (;;) {
        const ULONGLONG now = GetTickCount64();
        if (now >= deadline) break;
        const DWORD remaining = static_cast<DWORD>(
            (std::min)(deadline - now,
                       static_cast<ULONGLONG>(MAXDWORD)));
        if (!WaitForPipeData(pipe, remaining)) return false;
        BYTE header[6] = {};
        if (!ReadExact(pipe, header, (DWORD)sizeof(header)) ||
            header[1] != clip::kIpcVersion)
            return false;
        DWORD payloadLength = (DWORD)header[2] | ((DWORD)header[3] << 8) |
                              ((DWORD)header[4] << 16) |
                              ((DWORD)header[5] << 24);
        if (payloadLength > clip::kIpcMaxPayload) return false;
        std::string payload(payloadLength, '\0');
        if (payloadLength &&
            !ReadExact(pipe, &payload[0], payloadLength))
            return false;
        if (header[0] == clip::kIpcStateAck) {
            clip::StateAck ack;
            if (payloadLength != 0 &&
                !clip::ParseStateAck(payload.data(), payload.size(), ack)) return false;
            if (stateAcknowledged) *stateAcknowledged = true;
            continue;
        }
        if (header[0] == clip::kIpcEventGap) {
            clip::Reader gap(payload.data(), payload.size());
            event = PipeEvent{};
            event.gap = gap.GetU32(event.pid) &&
                        gap.GetU64(event.missingEvents) &&
                        gap.n == 0 && event.missingEvents != 0;
            return event.gap;
        }
        return header[0] == clip::kIpcEvent &&
               ParseEventPayload(payload.data(), payload.size(), event);
    }
    return false;
}

bool VerifyPreviewFrame() {
    std::string payload;
    clip::PutU32(payload, 1234);
    clip::PutU64(payload, 0x1122334455667788ull);
    clip::PutU8(payload, clip::kOpRead);
    clip::PutU32(payload, CF_UNICODETEXT);
    clip::PutU8(payload, clip::kAllowRecord);
    clip::PutU8(payload, 0);
    clip::PutWStr(payload, L"synthetic-preview");
    std::string frame;
    clip::PutFrame(frame, clip::kIpcEvent, payload);
    if (frame.size() < clip::kIpcFrameHeaderSize ||
        (BYTE)frame[0] != clip::kIpcEvent || (BYTE)frame[1] != clip::kIpcVersion)
        return false;
    DWORD length = (DWORD)(BYTE)frame[2] | ((DWORD)(BYTE)frame[3] << 8) |
                   ((DWORD)(BYTE)frame[4] << 16) | ((DWORD)(BYTE)frame[5] << 24);
    PipeEvent parsed;
    return length == payload.size() &&
           ParseEventPayload(frame.data() + clip::kIpcFrameHeaderSize, length, parsed) &&
           parsed.preview == L"synthetic-preview";
}

std::string RulesMessage(const std::wstring& processName, BYTE action) {
    std::string payload;
    clip::PutU32(payload, processName.empty() ? 0 : 1);
    if (!processName.empty()) {
        clip::PutWStr(payload, processName);
        clip::PutU8(payload, 0);
        clip::PutU8(payload, action);
    }
    std::string message;
    clip::PutFrame(message, clip::kIpcRules, payload);
    return message;
}

bool SendState(HANDLE pipe, const std::wstring& processName, BYTE action,
               bool paused = false, int shortcutOnly = -1) {
    std::string begin;
    clip::PutFrame(begin, clip::kIpcStateBegin);
    std::string pause;
    std::string pausePayload;
    clip::PutU8(pausePayload, paused ? 1 : 0);
    clip::PutFrame(pause, clip::kIpcPause, pausePayload);
    std::string settings;
    std::string settingsPayload;
    // Enable preview in the protocol snapshot. The target still makes no
    // OpenClipboard call; non-empty Unicode serialization is tested locally.
    clip::PutU8(settingsPayload, 1);
    if (shortcutOnly >= 0)
        clip::PutU8(settingsPayload, shortcutOnly ? 1 : 0);
    clip::PutFrame(settings, clip::kIpcSettings, settingsPayload);
    const bool sent =
        WriteAll(pipe, begin) &&
        WriteAll(pipe, RulesMessage(processName, action)) &&
        WriteAll(pipe, pause) && WriteAll(pipe, settings);
    if (sent) g_logVisibilityEvents = false;
    return sent;
}

bool SendExtendedState(HANDLE pipe, bool paused = false,
                       int snapshots = -1) {
    std::string begin;
    clip::PutFrame(begin, clip::kIpcStateBegin);
    std::string rulesPayload;
    clip::PutU32(rulesPayload, 0);
    clip::PutU32(rulesPayload, clip::kRulePayloadMarker);
    std::string rules;
    clip::PutFrame(rules, clip::kIpcRulesExtended, rulesPayload);
    std::string pausePayload;
    clip::PutU8(pausePayload, paused ? 1 : 0);
    std::string pause;
    clip::PutFrame(pause, clip::kIpcPause, pausePayload);
    std::string settingsPayload;
    clip::PutU8(settingsPayload, 0);
    clip::PutU8(settingsPayload, 0);
    if (snapshots >= 0) {
        clip::PutU8(settingsPayload, 0);
        clip::PutU8(settingsPayload, snapshots ? 1 : 0);
    }
    std::string settings;
    clip::PutFrame(settings, clip::kIpcSettings, settingsPayload);
    const bool sent = WriteAll(pipe, begin) && WriteAll(pipe, rules) &&
                      WriteAll(pipe, pause) && WriteAll(pipe, settings);
    if (sent) g_logVisibilityEvents = false;
    return sent;
}

bool SendNotificationState(HANDLE pipe, const std::wstring& processName,
                           BYTE action, bool showNotification,
                            BYTE format = clip::kFormatAny,
                            const std::wstring& ruleName =
                                L"split-notification",
                            int crypto = -1,
                            int shortcutDirectAllow = -1,
                            DWORD shortcutWindowMs =
                                clip::kDefaultShortcutAuthorizationWindowMs,
                            int ignoreCustom = -1,
                            bool hideFromLogList = false) {
    std::string begin;
    clip::PutFrame(begin, clip::kIpcStateBegin);
    std::string rulesPayload;
    const bool includeLogVisibility = hideFromLogList || ignoreCustom >= 0;
    clip::PutU32(rulesPayload, 1);
    clip::PutU32(rulesPayload, includeLogVisibility
                                   ? clip::kRulePayloadMarkerV4
                                   : clip::kRulePayloadMarkerV3);
    clip::PutWStr(rulesPayload, ruleName);
    clip::PutWStr(rulesPayload, processName);
    clip::PutU8(rulesPayload, 0);
    clip::PutU8(rulesPayload, action);
    clip::PutU8(rulesPayload, showNotification ? 1 : 0);
    if (includeLogVisibility)
        clip::PutU8(rulesPayload, hideFromLogList ? 1 : 0);
    clip::PutU8(rulesPayload, clip::kRuleReadWrite);
    clip::PutU8(rulesPayload, format);
    clip::PutWStr(rulesPayload, L"");
    clip::PutU8(rulesPayload, 1);
    clip::PutU8(rulesPayload, 1);
    clip::PutU8(rulesPayload, clip::kSourceAny);
    clip::PutWStr(rulesPayload, L"");
    clip::PutU32(rulesPayload, 15000);
    clip::PutU8(rulesPayload, 1);
    std::string rules;
    clip::PutFrame(rules, clip::kIpcRulesExtended, rulesPayload);
    std::string pausePayload;
    clip::PutU8(pausePayload, 0);
    std::string pause;
    clip::PutFrame(pause, clip::kIpcPause, pausePayload);
    std::string settingsPayload;
    clip::PutU8(settingsPayload, 0);
    clip::PutU8(settingsPayload, 0);
    if (crypto >= 0 || shortcutDirectAllow >= 0 || ignoreCustom >= 0)
        clip::PutU8(settingsPayload, crypto > 0 ? 1 : 0);
    if (shortcutDirectAllow >= 0 || ignoreCustom >= 0) {
        clip::PutU8(settingsPayload, 0);
        clip::PutU8(settingsPayload, shortcutDirectAllow > 0 ? 1 : 0);
        clip::PutU32(settingsPayload, shortcutWindowMs);
    }
    if (ignoreCustom >= 0)
        clip::PutU8(settingsPayload, ignoreCustom ? 1 : 0);
    std::string settings;
    clip::PutFrame(settings, clip::kIpcSettings, settingsPayload);
    const bool sent = WriteAll(pipe, begin) && WriteAll(pipe, rules) &&
                      WriteAll(pipe, pause) && WriteAll(pipe, settings);
    if (sent) g_logVisibilityEvents = includeLogVisibility;
    return sent;
}

void StressTriplet(SharedState* state, UINT format) {
    // Deliberately omit OpenClipboard: these calls fail without touching the
    // user's clipboard, while still entering each Detours target when hooked.
    (void)GetClipboardData(format);
    InterlockedIncrement(&state->stressCalls);
    (void)SetClipboardData(format, nullptr);
    InterlockedIncrement(&state->stressCalls);
    (void)EmptyClipboard();
    InterlockedIncrement(&state->stressCalls);
}

void StopTargetStress(SharedState* state, std::vector<std::thread>& workers) {
    InterlockedExchange(&state->stressRunning, 0);
    for (auto& worker : workers) {
        if (worker.joinable()) worker.join();
    }
    workers.clear();
    InterlockedExchange(&state->stressWorkers, 0);
}

bool WaitForStressReady(SharedState* state) {
    const ULONGLONG deadline = GetTickCount64() + 3000;
    LONG calls = 0, threads = 0, failures = 0;
    do {
        calls = InterlockedCompareExchange(&state->stressCalls, 0, 0);
        threads = InterlockedCompareExchange(&state->stressThreadsCreated, 0, 0);
        failures = InterlockedCompareExchange(&state->stressThreadFailures, 0, 0);
        if (failures) break;
        if (calls >= 300 && threads >= 2) return true;
        Sleep(10);
    } while (GetTickCount64() < deadline);
    std::fprintf(stderr, "stress-start-failed calls=%ld threads=%ld failures=%ld\n",
                 calls, threads, failures);
    return false;
}

bool StartTargetStress(SharedState* state, std::vector<std::thread>& workers,
                       UINT format) {
    if (InterlockedCompareExchange(&state->stressRunning, 1, 0) != 0)
        return false;
    InterlockedExchange(&state->stressCalls, 0);
    InterlockedExchange(&state->stressThreadsCreated, 0);
    InterlockedExchange(&state->stressThreadFailures, 0);
    try {
        // Long-lived callers keep all three API entry points busy while a
        // Detours transaction snapshots and updates the target process.
        for (int i = 0; i < 6; ++i) {
            workers.emplace_back([state, format] {
                while (InterlockedCompareExchange(&state->stressRunning, 0, 0))
                    StressTriplet(state, format);
            });
        }
        // Churners continuously create and join short-lived callers. This
        // exercises thread creation/exit at the transaction boundary.
        for (int i = 0; i < 2; ++i) {
            workers.emplace_back([state, format] {
                while (InterlockedCompareExchange(&state->stressRunning, 0, 0)) {
                    try {
                        std::thread ephemeral([state, format] {
                            for (int n = 0; n < 8 &&
                                 InterlockedCompareExchange(&state->stressRunning, 0, 0);
                                 ++n)
                                StressTriplet(state, format);
                        });
                        InterlockedIncrement(&state->stressThreadsCreated);
                        ephemeral.join();
                    } catch (...) {
                        InterlockedIncrement(&state->stressThreadFailures);
                        InterlockedExchange(&state->stressRunning, 0);
                        return;
                    }
                }
            });
        }
    } catch (...) {
        InterlockedIncrement(&state->stressThreadFailures);
        StopTargetStress(state, workers);
        return false;
    }
    InterlockedExchange(&state->stressWorkers, (LONG)workers.size());
    return true;
}

bool RunCommand(HANDLE commandEvent, HANDLE doneEvent, SharedState* state,
                Command command, UINT format, CommandResult& result,
                DWORD timeoutMs = 5000) {
    state->format = format;
    MemoryBarrier();
    InterlockedExchange(&state->command, command);
    if (!SetEvent(commandEvent) ||
        WaitForSingleObject(doneEvent, timeoutMs) != WAIT_OBJECT_0)
        return false;
    MemoryBarrier();
    result.value = state->value;
    result.error = state->error;
    return true;
}

bool RunTextCommand(HANDLE commandEvent, HANDLE doneEvent, SharedState* state,
                    Command command, const wchar_t* text,
                    CommandResult& result,
                    UINT format = CF_UNICODETEXT) {
    if (wcslen(text) >= _countof(state->text)) return false;
    wcscpy_s(state->text, text);
    return RunCommand(commandEvent, doneEvent, state, command, format, result);
}

std::vector<BYTE> TestDibSnapshot() {
    std::vector<BYTE> data(sizeof(BITMAPINFOHEADER) + 16, 0);
    auto* header = reinterpret_cast<BITMAPINFOHEADER*>(data.data());
    header->biSize = sizeof(BITMAPINFOHEADER);
    header->biWidth = 2;
    header->biHeight = 2;
    header->biPlanes = 1;
    header->biBitCount = 32;
    header->biCompression = BI_RGB;
    header->biSizeImage = 16;
    for (size_t index = sizeof(BITMAPINFOHEADER); index < data.size(); ++index)
        data[index] = static_cast<BYTE>(index);
    return data;
}

std::vector<BYTE> TestFileSnapshot() {
    static constexpr wchar_t paths[] =
        L"C:\\snapshot-a.txt\0D:\\snapshot-b.bin\0";
    std::vector<BYTE> data(sizeof(DROPFILES) + sizeof(paths), 0);
    DROPFILES drop = {};
    drop.pFiles = sizeof(DROPFILES);
    drop.fWide = TRUE;
    memcpy(data.data(), &drop, sizeof(drop));
    memcpy(data.data() + sizeof(drop), paths, sizeof(paths));
    return data;
}

std::wstring CurrentExecutablePath() {
    std::wstring path(32768, L'\0');
    DWORD length = GetModuleFileNameW(nullptr, &path[0], (DWORD)path.size());
    if (length == 0 || length >= path.size()) return {};
    path.resize(length);
    return path;
}

std::wstring BaseNameLower(std::wstring path) {
    size_t slash = path.find_last_of(L"\\/");
    if (slash != std::wstring::npos) path.erase(0, slash + 1);
    for (wchar_t& c : path) c = (wchar_t)towlower(c);
    return path;
}

int TargetMain(int argc, wchar_t** argv) {
    if (argc != 6) return 20;
    HANDLE readyEvent = (HANDLE)(ULONG_PTR)ParseHandle(argv[2]);
    HANDLE commandEvent = (HANDLE)(ULONG_PTR)ParseHandle(argv[3]);
    HANDLE doneEvent = (HANDLE)(ULONG_PTR)ParseHandle(argv[4]);
    HANDLE mapping = (HANDLE)(ULONG_PTR)ParseHandle(argv[5]);
    auto* state = static_cast<SharedState*>(
        MapViewOfFile(mapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, sizeof(SharedState)));
    if (!state) return 21;

    MSG message;
    PeekMessageW(&message, nullptr, 0, 0, PM_NOREMOVE);
    SetEvent(readyEvent);
    std::vector<std::thread> stressWorkers;
    auto pumpShortcut = [](UINT modifier, UINT key, bool pressed) {
        const UINT message = pressed ? WM_KEYDOWN : WM_KEYUP;
        if (pressed) {
            PostThreadMessageW(GetCurrentThreadId(), message, modifier, 0);
            PostThreadMessageW(GetCurrentThreadId(), message, key, 0);
        } else {
            PostThreadMessageW(GetCurrentThreadId(), message, key, 0);
            PostThreadMessageW(GetCurrentThreadId(), message, modifier, 0);
        }
        MSG queued;
        while (PeekMessageW(&queued, nullptr, 0, 0, PM_REMOVE)) {
            TranslateMessage(&queued);
            DispatchMessageW(&queued);
        }
    };
    auto setText = [state]() -> ULONG_PTR {
        const UINT format = state->format;
        std::string encoded;
        const void* source = state->text;
        size_t bytes = (wcslen(state->text) + 1) * sizeof(wchar_t);
        if (format != CF_UNICODETEXT) {
            const UINT codePage = format == CF_TEXT || format == CF_DSPTEXT
                                      ? CP_ACP
                                      : format == CF_OEMTEXT ? CP_OEMCP
                                                             : CP_UTF8;
            const DWORD flags = codePage == CP_UTF8 ? WC_ERR_INVALID_CHARS : 0;
            const int required = WideCharToMultiByte(
                codePage, flags, state->text, -1, nullptr, 0, nullptr,
                nullptr);
            if (required <= 0) return 0;
            encoded.resize(static_cast<size_t>(required));
            if (WideCharToMultiByte(codePage, flags, state->text, -1,
                                    encoded.data(), required, nullptr,
                                    nullptr) != required)
                return 0;
            source = encoded.data();
            bytes = encoded.size();
        }
        HGLOBAL memory = GlobalAlloc(GMEM_MOVEABLE, bytes);
        if (!memory) {
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            return 0;
        }
        void* data = GlobalLock(memory);
        if (!data) {
            GlobalFree(memory);
            return 0;
        }
        memcpy(data, source, bytes);
        GlobalUnlock(memory);
        HANDLE result = SetClipboardData(format, memory);
        const DWORD resultError = GetLastError();
        if (!result) GlobalFree(memory);
        SetLastError(resultError);
        return reinterpret_cast<ULONG_PTR>(result);
    };
    auto setGlobalData = [](UINT format,
                            const std::vector<BYTE>& bytes) -> ULONG_PTR {
        HGLOBAL memory = GlobalAlloc(GMEM_MOVEABLE, bytes.size());
        if (!memory) return 0;
        void* output = GlobalLock(memory);
        if (!output) {
            GlobalFree(memory);
            return 0;
        }
        memcpy(output, bytes.data(), bytes.size());
        GlobalUnlock(memory);
        HANDLE result = SetClipboardData(format, memory);
        const DWORD error = GetLastError();
        if (!result) GlobalFree(memory);
        SetLastError(error);
        return reinterpret_cast<ULONG_PTR>(result);
    };
    bool running = true;
    while (running) {
        DWORD wait = MsgWaitForMultipleObjects(1, &commandEvent, FALSE, INFINITE,
                                               QS_ALLINPUT);
        if (wait == WAIT_OBJECT_0) {
            Command command = (Command)InterlockedExchange(&state->command,
                                                            kCommandNone);
            SetLastError(0x12345678u);
            // These calls intentionally do not OpenClipboard: this smoke test
            // validates the Detours/API decision path without touching the
            // user's real clipboard.  Clipboard E2E belongs to Sandbox.
            switch (command) {
            case kCommandGet:
                state->value = (ULONG_PTR)GetClipboardData(state->format);
                break;
            case kCommandSet:
                state->value = (ULONG_PTR)SetClipboardData(state->format, nullptr);
                break;
            case kCommandEmpty:
                state->value = (ULONG_PTR)EmptyClipboard();
                break;
            case kCommandExit:
                StopTargetStress(state, stressWorkers);
                running = false;
                state->value = 0;
                break;
            case kCommandStressStart:
                state->value = StartTargetStress(state, stressWorkers,
                                                 state->format) ? 1 : 0;
                break;
            case kCommandStressStop:
                StopTargetStress(state, stressWorkers);
                state->value = 1;
                break;
            case kCommandShortcutGet:
            case kCommandShiftInsertGet: {
                const bool insertAlias = command == kCommandShiftInsertGet;
                const UINT modifier = insertAlias ? VK_SHIFT : VK_CONTROL;
                const UINT key = insertAlias ? VK_INSERT : L'V';
                pumpShortcut(modifier, key, true);
                ULONG_PTR resultValue = 0;
                DWORD resultError = ERROR_SUCCESS;
                std::thread reader([&] {
                    SetLastError(0x12345678u);
                    resultValue =
                        (ULONG_PTR)GetClipboardData(state->format);
                    resultError = GetLastError();
                });
                reader.join();
                state->value = resultValue;
                pumpShortcut(modifier, key, false);
                SetLastError(resultError);
                break;
            }
            case kCommandShortcutSet:
            case kCommandControlInsertSet: {
                const UINT key = command == kCommandControlInsertSet
                                     ? VK_INSERT
                                     : L'C';
                pumpShortcut(VK_CONTROL, key, true);
                SetLastError(0x12345678u);
                state->value =
                    (ULONG_PTR)SetClipboardData(state->format, nullptr);
                const DWORD resultError = GetLastError();
                pumpShortcut(VK_CONTROL, key, false);
                SetLastError(resultError);
                break;
            }
        case kCommandSetText:
            state->value = setText();
            break;
        case kCommandCopyText:
        case kCommandReadText:
        case kCommandClearClipboard: {
            // The controller and target run on a private window station, so
            // these native clipboard transactions cannot touch user content.
            HWND owner = CreateWindowExW(0, L"STATIC", L"Crypto smoke", 0,
                                         0, 0, 0, 0, HWND_MESSAGE, nullptr,
                                         GetModuleHandleW(nullptr), nullptr);
            state->value = 0;
            DWORD error = GetLastError();
            if (owner && OpenClipboard(owner)) {
                if (command == kCommandReadText) {
                    HANDLE data = GetClipboardData(CF_UNICODETEXT);
                    if (data) {
                        const auto* text = static_cast<const wchar_t*>(GlobalLock(data));
                        if (text) {
                            wcsncpy_s(state->text, text, _TRUNCATE);
                            GlobalUnlock(data);
                            state->value = 1;
                        }
                    }
                } else if (EmptyClipboard()) {
                    state->value = command == kCommandCopyText ? setText() : 1;
                }
                error = GetLastError();
                CloseClipboard();
            } else {
                error = GetLastError();
            }
            if (owner) DestroyWindow(owner);
            SetLastError(error);
            break;
        }
            case kCommandShortcutSetText: {
                pumpShortcut(VK_CONTROL, L'C', true);
                SetLastError(0x12345678u);
                state->value = setText();
                const DWORD resultError = GetLastError();
                pumpShortcut(VK_CONTROL, L'C', false);
                SetLastError(resultError);
                break;
            }
            case kCommandSetDib:
                state->value = setGlobalData(CF_DIB, TestDibSnapshot());
                break;
            case kCommandSetFiles:
                state->value = setGlobalData(CF_HDROP, TestFileSnapshot());
                break;
            case kCommandCopyShortcutGet:
            case kCommandControlInsertGet: {
                const UINT key = command == kCommandControlInsertGet
                                     ? VK_INSERT
                                     : L'C';
                pumpShortcut(VK_CONTROL, key, true);
                state->value =
                    (ULONG_PTR)GetClipboardData(state->format);
                const DWORD resultError = GetLastError();
                pumpShortcut(VK_CONTROL, key, false);
                SetLastError(resultError);
                break;
            }
            case kCommandPasteShortcutSet:
            case kCommandShiftInsertSet: {
                const bool insertAlias = command == kCommandShiftInsertSet;
                const UINT modifier = insertAlias ? VK_SHIFT : VK_CONTROL;
                const UINT key = insertAlias ? VK_INSERT : L'V';
                pumpShortcut(modifier, key, true);
                state->value =
                    (ULONG_PTR)SetClipboardData(state->format, nullptr);
                const DWORD resultError = GetLastError();
                pumpShortcut(modifier, key, false);
                SetLastError(resultError);
                break;
            }
            case kCommandDelayedShortcutGet: {
                pumpShortcut(VK_CONTROL, L'V', true);
                Sleep(300);
                state->value =
                    (ULONG_PTR)GetClipboardData(state->format);
                const DWORD resultError = GetLastError();
                pumpShortcut(VK_CONTROL, L'V', false);
                SetLastError(resultError);
                break;
            }
            case kCommandDelayedShortcutSet: {
                pumpShortcut(VK_CONTROL, L'C', true);
                Sleep(300);
                state->value =
                    (ULONG_PTR)SetClipboardData(state->format, nullptr);
                const DWORD resultError = GetLastError();
                pumpShortcut(VK_CONTROL, L'C', false);
                SetLastError(resultError);
                break;
            }
            default:
                state->value = 0;
                break;
            }
            state->error = GetLastError();
            MemoryBarrier();
            SetEvent(doneEvent);
        } else if (wait == WAIT_OBJECT_0 + 1) {
            while (PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE)) {
                if (message.message == WM_QUIT) running = false;
                TranslateMessage(&message);
                DispatchMessageW(&message);
            }
        } else {
            break;
        }
    }
    StopTargetStress(state, stressWorkers);
    UnmapViewOfFile(state);
    return 0;
}

bool MatchEvent(const PipeEvent& event, DWORD pid, BYTE op, DWORD format,
                BYTE action, BYTE blocked, bool showNotification = false) {
    return event.pid == pid && event.op == op && event.format == format &&
           event.action == action && event.blocked == blocked &&
           event.showNotification == showNotification &&
           event.preview.empty();
}

bool WaitForClientDisconnect(HANDLE pipe, DWORD timeoutMs) {
    std::atomic<bool> done{false};
    std::atomic<DWORD> terminalError{ERROR_SUCCESS};
    std::thread reader([&] {
        BYTE discard[4096];
        for (;;) {
            DWORD got = 0;
            if (ReadFile(pipe, discard, (DWORD)sizeof(discard), &got, nullptr)) {
                if (got == 0) {
                    terminalError.store(ERROR_BROKEN_PIPE, std::memory_order_release);
                    break;
                }
                // Drain events queued immediately before the worker closes.
                continue;
            }
            terminalError.store(GetLastError(), std::memory_order_release);
            break;
        }
        done.store(true, std::memory_order_release);
    });

    ULONGLONG deadline = GetTickCount64() + timeoutMs;
    while (!done.load(std::memory_order_acquire) &&
           GetTickCount64() < deadline)
        Sleep(10);
    if (!done.load(std::memory_order_acquire)) {
        // A timeout is a failed detach observation, never a successful one.
        CancelSynchronousIo((HANDLE)reader.native_handle());
        reader.join();
        return false;
    }
    reader.join();
    DWORD error = terminalError.load(std::memory_order_acquire);
    return error == ERROR_BROKEN_PIPE || error == ERROR_PIPE_NOT_CONNECTED;
}

class PrivateClipboardDesktop {
public:
    PrivateClipboardDesktop() {
        originalStation_ = GetProcessWindowStation();
        originalDesktop_ = GetThreadDesktop(GetCurrentThreadId());
        const std::wstring stationName = L"ClipCryptoSmoke" + std::to_wstring(GetCurrentProcessId());
        station_ = CreateWindowStationW(stationName.c_str(), 0, WINSTA_ALL_ACCESS, nullptr);
        if (!station_ || !SetProcessWindowStation(station_)) {
            std::fwprintf(stderr, L"private-station-error=%lu\n", GetLastError());
            return;
        }
        desktop_ = CreateDesktopW(L"Default", nullptr, nullptr, 0, GENERIC_ALL, nullptr);
        if (!desktop_ || !SetThreadDesktop(desktop_)) {
            std::fwprintf(stderr, L"private-desktop-error=%lu\n", GetLastError());
            return;
        }
        path = stationName + L"\\Default";
    }
    ~PrivateClipboardDesktop() {
        SetProcessWindowStation(originalStation_);
        SetThreadDesktop(originalDesktop_);
        if (desktop_) CloseDesktop(desktop_);
        if (station_) CloseWindowStation(station_);
    }
    std::wstring path;
private:
    HWINSTA originalStation_ = nullptr, station_ = nullptr;
    HDESK originalDesktop_ = nullptr, desktop_ = nullptr;
};

int ControllerMain(const wchar_t* dllPath) {
    int result = 1;
    PrivateClipboardDesktop clipboardDesktop;

    if (!VerifyPreviewFrame()) return 26;
    DWORD pid = GetCurrentProcessId();
    std::wstring suffix = std::to_wstring(pid);
    std::wstring pipeName = L"\\\\.\\pipe\\ClipboardProtector.InjectionSmoke." + suffix;
    std::wstring stopName = L"Local\\ClipboardProtector.InjectionSmoke.Stop." + suffix;
    std::wstring mutexName = L"Local\\ClipboardProtector.InjectionSmoke.Mutex." + suffix;
    std::wstring cryptoMapName =
        L"Local\\ClipboardProtector.InjectionSmoke.Crypto." + suffix;
    std::wstring exePath = CurrentExecutablePath();
    if (exePath.empty()) return 2;

    SetEnvironmentVariableW(L"CLIP_TEST_PIPE_NAME", pipeName.c_str());
    SetEnvironmentVariableW(L"CLIP_TEST_STOP_EVENT", stopName.c_str());
    SetEnvironmentVariableW(L"CLIP_TEST_CONTROLLER_MUTEX", mutexName.c_str());
    SetEnvironmentVariableW(L"CLIP_TEST_SERVER_PATH", exePath.c_str());
    SetEnvironmentVariableW(L"CLIP_TEST_CRYPTO_MAP", cryptoMapName.c_str());

    HANDLE stopEvent = CreateEventW(nullptr, TRUE, FALSE, stopName.c_str());
    HANDLE controllerMutex = CreateMutexW(nullptr, TRUE, mutexName.c_str());
    HANDLE pipe = CreateNamedPipeW(
        pipeName.c_str(), PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
        1, 64 * 1024, 64 * 1024, 0, nullptr);
    if (!stopEvent || !controllerMutex || pipe == INVALID_HANDLE_VALUE) return 3;

    SECURITY_ATTRIBUTES security = {sizeof(security), nullptr, TRUE};
    HANDLE readyEvent = CreateEventW(&security, TRUE, FALSE, nullptr);
    HANDLE commandEvent = CreateEventW(&security, FALSE, FALSE, nullptr);
    HANDLE doneEvent = CreateEventW(&security, FALSE, FALSE, nullptr);
    HANDLE mapping = CreateFileMappingW(INVALID_HANDLE_VALUE, &security,
                                        PAGE_READWRITE, 0, sizeof(SharedState), nullptr);
    HANDLE cryptoMapping = CreateFileMappingW(
        INVALID_HANDLE_VALUE, &security, PAGE_READWRITE, 0,
        sizeof(clip::SharedCryptoProtection), cryptoMapName.c_str());
    if (!readyEvent || !commandEvent || !doneEvent || !mapping ||
        !cryptoMapping)
        return 4;
    auto* state = static_cast<SharedState*>(
        MapViewOfFile(mapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, sizeof(SharedState)));
    if (!state) return 5;
    ZeroMemory(state, sizeof(*state));
    auto* cryptoState = static_cast<clip::SharedCryptoProtection*>(
        MapViewOfFile(cryptoMapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0,
                      sizeof(clip::SharedCryptoProtection)));
    if (!cryptoState) return 5;
    ZeroMemory(cryptoState, sizeof(*cryptoState));
    cryptoState->structureVersion = clip::kCryptoProtectionVersion;

    std::wstring command = L"\"" + exePath + L"\" --target " +
                           std::to_wstring((ULONG_PTR)readyEvent) + L" " +
                           std::to_wstring((ULONG_PTR)commandEvent) + L" " +
                           std::to_wstring((ULONG_PTR)doneEvent) + L" " +
                           std::to_wstring((ULONG_PTR)mapping);
    STARTUPINFOW startup = {sizeof(startup)};
    if (!clipboardDesktop.path.empty()) startup.lpDesktop = clipboardDesktop.path.data();
    PROCESS_INFORMATION process = {};
    if (!CreateProcessW(exePath.c_str(), &command[0], nullptr, nullptr, TRUE,
                        CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process))
        return 6;

    HMODULE dll = nullptr;
    HHOOK hook = nullptr;
    bool mutexOwned = true;
    auto connectTarget = [&]() -> bool {
        std::atomic<bool> connectDone{false};
        std::atomic<bool> connected{false};
        std::thread connector([&] {
            BOOL ok = ConnectNamedPipe(pipe, nullptr);
            connected.store(ok || GetLastError() == ERROR_PIPE_CONNECTED,
                            std::memory_order_release);
            connectDone.store(true, std::memory_order_release);
        });
        if (!PostThreadMessageW(process.dwThreadId, WM_APP + 77, 0, 0)) {
            CancelSynchronousIo((HANDLE)connector.native_handle());
        }
        ULONGLONG connectDeadline = GetTickCount64() + 8000;
        while (!connectDone.load(std::memory_order_acquire) &&
               GetTickCount64() < connectDeadline)
            Sleep(10);
        if (!connectDone.load(std::memory_order_acquire))
            CancelSynchronousIo((HANDLE)connector.native_handle());
        connector.join();
        if (!connected.load(std::memory_order_acquire)) return false;
        ULONG clientPid = 0;
        return GetNamedPipeClientProcessId(pipe, &clientPid) &&
               clientPid == process.dwProcessId;
    };
    auto disconnectTarget = [&]() {
        // The worker closes its client handle after a successful detach. The
        // server-side disconnect is also safe if the client is already gone.
        (void)DisconnectNamedPipe(pipe);
    };
    auto waitPipeClosed = [&]() -> bool {
        return WaitForClientDisconnect(pipe, 8000);
    };
    do {
        if (WaitForSingleObject(readyEvent, 5000) != WAIT_OBJECT_0) {
            result = 7;
            break;
        }

        CommandResult baselineGet, baselineSet, baselineEmpty;
        if (!RunCommand(commandEvent, doneEvent, state, kCommandGet, 0xC123u,
                        baselineGet) ||
            !RunCommand(commandEvent, doneEvent, state, kCommandSet, 0xC123u,
                        baselineSet) ||
            !RunCommand(commandEvent, doneEvent, state, kCommandEmpty, 0,
                        baselineEmpty)) {
            result = 8;
            break;
        }

        dll = LoadLibraryW(dllPath);
        auto getMsgProc = dll ? reinterpret_cast<HOOKPROC>(
                                  GetProcAddress(dll, "GetMsgProc"))
                              : nullptr;
        if (!dll || !getMsgProc) {
            result = 9;
            break;
        }
        hook = SetWindowsHookExW(WH_GETMESSAGE, getMsgProc, dll, process.dwThreadId);
        if (!hook) {
            result = 10;
            break;
        }

        if (!connectTarget()) {
            result = 11;
            break;
        }

        std::wstring processName = BaseNameLower(exePath);
        if (!SendState(pipe, processName, clip::kBlockAlert)) {
            result = 13;
            break;
        }
        Sleep(250);

        CommandResult blockedGet;
        if (!RunCommand(commandEvent, doneEvent, state, kCommandGet, 0xC123u,
                        blockedGet) ||
            blockedGet.value != 0 || blockedGet.error != ERROR_ACCESS_DENIED) {
            result = 14;
            break;
        }
        PipeEvent event;
        bool stateAcknowledged = false;
        if (!ReadEvent(pipe, event, 5000, &stateAcknowledged) ||
            !stateAcknowledged ||
            !MatchEvent(event, process.dwProcessId, clip::kOpRead, 0xC123u,
                        2, 1)) {
            result = 15;
            break;
        }

        if (!SendState(pipe, L"", clip::kAllowRecord)) {
            result = 16;
            break;
        }
        Sleep(250);
        CommandResult allowedGet;
        if (!RunCommand(commandEvent, doneEvent, state, kCommandGet, 0xC123u,
                        allowedGet) ||
            allowedGet.value != baselineGet.value ||
            allowedGet.error != baselineGet.error ||
            !ReadEvent(pipe, event, 5000) ||
            !MatchEvent(event, process.dwProcessId, clip::kOpRead, 0xC123u,
                        clip::kAllowRecord, 0)) {
            result = 17;
            break;
        }

        CommandResult hookedSet, hookedEmpty;
        if (!RunCommand(commandEvent, doneEvent, state, kCommandSet, 0xC123u,
                        hookedSet) ||
            hookedSet.value != baselineSet.value || hookedSet.error != baselineSet.error ||
            !ReadEvent(pipe, event, 5000) ||
            !MatchEvent(event, process.dwProcessId, clip::kOpWrite, 0xC123u,
                        clip::kAllowRecord, 0) ||
            !RunCommand(commandEvent, doneEvent, state, kCommandEmpty, 0,
                        hookedEmpty) ||
            hookedEmpty.value != baselineEmpty.value ||
            hookedEmpty.error != baselineEmpty.error ||
            ReadEvent(pipe, event, 250)) {
            result = 18;
            break;
        }

        if (!SendExtendedState(pipe, false, true)) {
            result = 53;
            break;
        }
        Sleep(250);
        const std::vector<BYTE> expectedDib = TestDibSnapshot();
        CommandResult dibResult;
        if (!RunCommand(commandEvent, doneEvent, state, kCommandSetDib, CF_DIB,
                        dibResult) ||
            !ReadEvent(pipe, event, 5000) ||
            !MatchEvent(event, process.dwProcessId, clip::kOpWrite, CF_DIB,
                        clip::kRuleAllow, 0) ||
            event.snapshotKind != clip::kSnapshotImage ||
            event.snapshotOriginalBytes != expectedDib.size() ||
            event.snapshot != expectedDib) {
            result = 54;
            break;
        }
        const std::vector<BYTE> expectedFiles = TestFileSnapshot();
        CommandResult filesResult;
        if (!RunCommand(commandEvent, doneEvent, state, kCommandSetFiles,
                        CF_HDROP, filesResult) ||
            !ReadEvent(pipe, event, 5000) ||
            !MatchEvent(event, process.dwProcessId, clip::kOpWrite, CF_HDROP,
                        clip::kRuleAllow, 0) ||
            event.snapshotKind != clip::kSnapshotFiles ||
            event.snapshotOriginalBytes != expectedFiles.size() ||
            event.snapshot != expectedFiles) {
            result = 55;
            break;
        }
        if (!SendExtendedState(pipe, false, 0)) {
            result = 56;
            break;
        }
        Sleep(100);
        CommandResult snapshotsDisabled;
        if (!RunTextCommand(commandEvent, doneEvent, state, kCommandSetText,
                            L"snapshots disabled", snapshotsDisabled) ||
            !ReadEvent(pipe, event, 5000) ||
            !MatchEvent(event, process.dwProcessId, clip::kOpWrite,
                        CF_UNICODETEXT, clip::kRuleAllow, 0) ||
            event.snapshotKind != clip::kSnapshotNone ||
            event.snapshotOriginalBytes != 0 || !event.snapshot.empty()) {
            result = 56;
            break;
        }

        if (!SendNotificationState(pipe, processName, clip::kRuleBlock, false,
                                   clip::kFormatAny, L"ignore-custom", -1, -1,
                                   clip::kDefaultShortcutAuthorizationWindowMs,
                                   1)) {
            result = 68;
            break;
        }
        Sleep(250);
        CommandResult ignoredCustom;
        if (!RunCommand(commandEvent, doneEvent, state, kCommandGet, 0xC123u,
                        ignoredCustom) ||
            ignoredCustom.error == ERROR_ACCESS_DENIED ||
            !ReadEvent(pipe, event, 5000) ||
            !MatchEvent(event, process.dwProcessId, clip::kOpRead, 0xC123u,
                        clip::kRuleAllow, 0) ||
            !event.hideFromLogList ||
            event.ruleName != L"忽略自定义格式") {
            result = 69;
            break;
        }
        CommandResult ignoredCustomWrite;
        if (!RunCommand(commandEvent, doneEvent, state, kCommandSet, 0xC123u,
                        ignoredCustomWrite) ||
            !ReadEvent(pipe, event, 5000) ||
            !MatchEvent(event, process.dwProcessId, clip::kOpWrite, 0xC123u,
                        clip::kRuleAllow, 0) ||
            !event.hideFromLogList ||
            event.ruleName != L"忽略自定义格式") {
            result = 69;
            break;
        }
        CommandResult customStillRuled;
        if (!RunCommand(commandEvent, doneEvent, state, kCommandGet,
                        CF_UNICODETEXT, customStillRuled) ||
            customStillRuled.value != 0 ||
            customStillRuled.error != ERROR_ACCESS_DENIED ||
            !ReadEvent(pipe, event, 5000) ||
            !MatchEvent(event, process.dwProcessId, clip::kOpRead,
                        CF_UNICODETEXT, clip::kRuleBlock, 1)) {
            result = 70;
            break;
        }

        // The versioned rule snapshot carries the access decision,
        // notification policy, and main-list visibility independently.
        if (!SendNotificationState(pipe, processName, clip::kRuleBlock, true)) {
            result = 35;
            break;
        }
        Sleep(250);
        CommandResult notifiedBlock;
        if (!RunCommand(commandEvent, doneEvent, state, kCommandGet, 0xC123u,
                        notifiedBlock) ||
            notifiedBlock.value != 0 ||
            notifiedBlock.error != ERROR_ACCESS_DENIED ||
            !ReadEvent(pipe, event, 5000) ||
            !MatchEvent(event, process.dwProcessId, clip::kOpRead, 0xC123u,
                        clip::kRuleBlock, 1, true)) {
            result = 36;
            break;
        }
        if (!SendNotificationState(pipe, processName, clip::kRuleAllow, true)) {
            result = 37;
            break;
        }
        Sleep(250);
        CommandResult notifiedAllow;
        if (!RunCommand(commandEvent, doneEvent, state, kCommandGet, 0xC123u,
                        notifiedAllow) ||
            notifiedAllow.value != baselineGet.value ||
            notifiedAllow.error != baselineGet.error ||
            !ReadEvent(pipe, event, 5000) ||
            !MatchEvent(event, process.dwProcessId, clip::kOpRead, 0xC123u,
                        clip::kRuleAllow, 0, true)) {
            result = 38;
            break;
        }

        if (!SendNotificationState(
                pipe, processName, clip::kRuleAllow, false,
                clip::kFormatAny, L"hidden-rule", -1, -1,
                clip::kDefaultShortcutAuthorizationWindowMs, -1, true)) {
            result = 112;
            break;
        }
        Sleep(250);
        CommandResult hiddenRule;
        if (!RunCommand(commandEvent, doneEvent, state, kCommandGet, 0xC123u,
                        hiddenRule) ||
            hiddenRule.value != baselineGet.value ||
            hiddenRule.error != baselineGet.error ||
            !ReadEvent(pipe, event, 5000) ||
            !MatchEvent(event, process.dwProcessId, clip::kOpRead, 0xC123u,
                        clip::kRuleAllow, 0) ||
            !event.hideFromLogList || event.ruleName != L"hidden-rule") {
            result = 113;
            break;
        }

        if (!SendNotificationState(pipe, processName, clip::kRuleBlock, true,
                                   clip::kFormatPrivateKeyMnemonic,
                                   L"private-sensitive")) {
            result = 44;
            break;
        }
        Sleep(250);
        constexpr wchar_t mnemonic[] =
            L"abandon abandon abandon abandon abandon abandon abandon abandon "
            L"abandon abandon abandon about";
        CommandResult privateBlocked;
        if (!RunTextCommand(commandEvent, doneEvent, state, kCommandSetText,
                            mnemonic, privateBlocked) ||
            privateBlocked.value != 0 ||
            privateBlocked.error != ERROR_ACCESS_DENIED ||
            !ReadEvent(pipe, event, 5000) ||
            event.op != clip::kOpWrite || event.format != CF_UNICODETEXT ||
            event.action != clip::kRuleBlock || event.blocked != 1 ||
            !event.showNotification || event.cryptoContent ||
            event.hash != 0 ||
            !event.preview.empty() ||
            event.ruleName != L"private-sensitive") {
            result = 45;
            break;
        }

        const UINT utf8Format = RegisterClipboardFormatW(L"UTF8_STRING");
        if (utf8Format == 0 ||
            !SendNotificationState(pipe, processName, clip::kRuleBlock, true,
                                   clip::kFormatCryptoAddress,
                                   L"address-visible")) {
            result = 46;
            break;
        }
        Sleep(250);
        constexpr wchar_t visibleAddress[] =
            L"0x52908400098527886E0F7030069857D2E4169EE7";
        CommandResult addressBlocked;
        if (!RunTextCommand(commandEvent, doneEvent, state, kCommandSetText,
                            visibleAddress, addressBlocked, utf8Format) ||
            addressBlocked.value != 0 ||
            addressBlocked.error != ERROR_ACCESS_DENIED ||
            !ReadEvent(pipe, event, 5000) ||
            event.op != clip::kOpWrite || event.format != utf8Format ||
            event.action != clip::kRuleBlock || event.blocked != 1 ||
            !event.showNotification || event.hash == 0 ||
            event.preview != visibleAddress ||
            event.ruleName != L"address-visible") {
            result = 47;
            break;
        }

        if (!SendNotificationState(pipe, processName, clip::kRuleBlock, true,
                                   clip::kFormatText, L"all-text")) {
            result = 48;
            break;
        }
        Sleep(250);
        const UINT plainTextFormats[] = {
            CF_TEXT, CF_DSPTEXT, CF_OEMTEXT, CF_UNICODETEXT, utf8Format};
        for (UINT textFormat : plainTextFormats) {
            CommandResult textBlocked;
            if (!RunTextCommand(commandEvent, doneEvent, state,
                                kCommandSetText, L"plain text", textBlocked,
                                textFormat) ||
                textBlocked.value != 0 ||
                textBlocked.error != ERROR_ACCESS_DENIED ||
                !ReadEvent(pipe, event, 5000) ||
                event.op != clip::kOpWrite || event.format != textFormat ||
                event.action != clip::kRuleBlock || event.blocked != 1 ||
                event.ruleName != L"all-text") {
                result = 49;
                break;
            }
        }
        if (result == 49) break;

        // Sensitive content stays redacted even when it is selected by a
        // generic text rule rather than the private-key/mnemonic format.
        CommandResult genericPrivateBlocked;
        if (!RunTextCommand(commandEvent, doneEvent, state, kCommandSetText,
                            mnemonic, genericPrivateBlocked) ||
            genericPrivateBlocked.value != 0 ||
            genericPrivateBlocked.error != ERROR_ACCESS_DENIED ||
            !ReadEvent(pipe, event, 5000) ||
            event.op != clip::kOpWrite || event.format != CF_UNICODETEXT ||
            event.action != clip::kRuleBlock || event.blocked != 1 ||
            !event.showNotification || event.cryptoContent ||
            event.hash != 0 ||
            !event.preview.empty() || event.ruleName != L"all-text") {
            result = 52;
            break;
        }

        if (!SendNotificationState(pipe, processName, clip::kRuleBlock, false,
                                   clip::kFormatNonText, L"non-text")) {
            result = 50;
            break;
        }
        Sleep(250);
        CommandResult nonTextBlocked;
        if (!RunCommand(commandEvent, doneEvent, state, kCommandGet, 0xC123u,
                        nonTextBlocked) ||
            nonTextBlocked.value != 0 ||
            nonTextBlocked.error != ERROR_ACCESS_DENIED ||
            !ReadEvent(pipe, event, 5000) ||
            !MatchEvent(event, process.dwProcessId, clip::kOpRead, 0xC123u,
                        clip::kRuleBlock, 1) ||
            event.ruleName != L"non-text") {
            result = 51;
            break;
        }

        // Exclusive shortcut mode blocks background API calls before rule
        // evaluation. Copy/paste tokens still reach the ordinary allow rule.
        if (!SendState(pipe, L"", clip::kAllowRecord, false, 1)) {
            result = 30;
            break;
        }
        Sleep(250);
        CommandResult backgroundGet;
        if (!RunCommand(commandEvent, doneEvent, state, kCommandGet, 0xC123u,
                        backgroundGet) ||
            backgroundGet.value != 0 ||
            backgroundGet.error != ERROR_ACCESS_DENIED ||
            !ReadEvent(pipe, event, 5000) ||
            !MatchEvent(event, process.dwProcessId, clip::kOpRead, 0xC123u,
                        2, 1)) {
            result = 31;
            break;
        }
        CommandResult shortcutGet;
        if (!RunCommand(commandEvent, doneEvent, state, kCommandShortcutGet,
                        0xC123u, shortcutGet) ||
            shortcutGet.value != baselineGet.value ||
            shortcutGet.error != baselineGet.error ||
            !ReadEvent(pipe, event, 5000) ||
            !MatchEvent(event, process.dwProcessId, clip::kOpRead, 0xC123u,
                        clip::kAllowRecord, 0)) {
            result = 32;
            break;
        }
        CommandResult backgroundSet;
        if (!RunCommand(commandEvent, doneEvent, state, kCommandSet, 0xC123u,
                        backgroundSet) ||
            backgroundSet.value != 0 ||
            backgroundSet.error != ERROR_ACCESS_DENIED ||
            !ReadEvent(pipe, event, 5000) ||
            !MatchEvent(event, process.dwProcessId, clip::kOpWrite, 0xC123u,
                        2, 1)) {
            result = 33;
            break;
        }
        CommandResult shortcutSet;
        if (!RunCommand(commandEvent, doneEvent, state, kCommandShortcutSet,
                        0xC123u, shortcutSet) ||
            shortcutSet.value != baselineSet.value ||
            shortcutSet.error != baselineSet.error ||
            !ReadEvent(pipe, event, 5000) ||
            !MatchEvent(event, process.dwProcessId, clip::kOpWrite, 0xC123u,
                        clip::kAllowRecord, 0)) {
            result = 34;
            break;
        }

        CommandResult shiftInsertGet;
        if (!RunCommand(commandEvent, doneEvent, state, kCommandShiftInsertGet,
                        0xC123u, shiftInsertGet) ||
            shiftInsertGet.value != baselineGet.value ||
            shiftInsertGet.error != baselineGet.error ||
            !ReadEvent(pipe, event, 5000) ||
            !MatchEvent(event, process.dwProcessId, clip::kOpRead, 0xC123u,
                        clip::kAllowRecord, 0)) {
            result = 114;
            break;
        }
        CommandResult controlInsertSet;
        if (!RunCommand(commandEvent, doneEvent, state, kCommandControlInsertSet,
                        0xC123u, controlInsertSet) ||
            controlInsertSet.value != baselineSet.value ||
            controlInsertSet.error != baselineSet.error ||
            !ReadEvent(pipe, event, 5000) ||
            !MatchEvent(event, process.dwProcessId, clip::kOpWrite, 0xC123u,
                        clip::kAllowRecord, 0)) {
            result = 115;
            break;
        }

        // Direct shortcut authorization is directional and independent from
        // exclusive mode. With it disabled, shortcut-originated calls still
        // hit the blocking rule.
        constexpr DWORD shortcutWindowMs = 150;
        if (!SendNotificationState(
                pipe, processName, clip::kRuleBlock, false, clip::kFormatAny,
                L"shortcut-policy-block", -1, 0, shortcutWindowMs)) {
            result = 59;
            break;
        }
        Sleep(250);
        CommandResult ruleBlockedShortcutGet, ruleBlockedShortcutSet;
        if (!RunCommand(commandEvent, doneEvent, state, kCommandShortcutGet,
                        0xC123u, ruleBlockedShortcutGet) ||
            ruleBlockedShortcutGet.value != 0 ||
            ruleBlockedShortcutGet.error != ERROR_ACCESS_DENIED ||
            !ReadEvent(pipe, event, 5000) ||
            !MatchEvent(event, process.dwProcessId, clip::kOpRead, 0xC123u,
                        clip::kRuleBlock, 1) ||
            event.ruleName != L"shortcut-policy-block") {
            result = 60;
            break;
        }
        if (!RunCommand(commandEvent, doneEvent, state, kCommandShortcutSet,
                        0xC123u, ruleBlockedShortcutSet) ||
            ruleBlockedShortcutSet.value != 0 ||
            ruleBlockedShortcutSet.error != ERROR_ACCESS_DENIED ||
            !ReadEvent(pipe, event, 5000) ||
            !MatchEvent(event, process.dwProcessId, clip::kOpWrite, 0xC123u,
                        clip::kRuleBlock, 1) ||
            event.ruleName != L"shortcut-policy-block") {
            result = 67;
            break;
        }

        if (!SendNotificationState(
                pipe, processName, clip::kRuleBlock, false, clip::kFormatAny,
                L"shortcut-policy-block", -1, 1, shortcutWindowMs)) {
            result = 61;
            break;
        }
        Sleep(250);
        CommandResult directGet, directSet;
        if (!RunCommand(commandEvent, doneEvent, state, kCommandShortcutGet,
                        0xC123u, directGet) ||
            directGet.value != baselineGet.value ||
            directGet.error != baselineGet.error ||
            !ReadEvent(pipe, event, 5000) ||
            !MatchEvent(event, process.dwProcessId, clip::kOpRead, 0xC123u,
                        clip::kRuleAllow, 0) ||
            event.ruleName != L"粘贴快捷键直接放行" ||
            !RunCommand(commandEvent, doneEvent, state, kCommandShortcutSet,
                        0xC123u, directSet) ||
            directSet.value != baselineSet.value ||
            directSet.error != baselineSet.error ||
            !ReadEvent(pipe, event, 5000) ||
            !MatchEvent(event, process.dwProcessId, clip::kOpWrite, 0xC123u,
                        clip::kRuleAllow, 0) ||
            event.ruleName != L"复制快捷键直接放行") {
            result = 62;
            break;
        }

        CommandResult directShiftInsertGet, directControlInsertSet;
        if (!RunCommand(commandEvent, doneEvent, state, kCommandShiftInsertGet,
                        0xC123u, directShiftInsertGet) ||
            directShiftInsertGet.value != baselineGet.value ||
            directShiftInsertGet.error != baselineGet.error ||
            !ReadEvent(pipe, event, 5000) ||
            !MatchEvent(event, process.dwProcessId, clip::kOpRead, 0xC123u,
                        clip::kRuleAllow, 0) ||
            event.ruleName != L"粘贴快捷键直接放行" ||
            !RunCommand(commandEvent, doneEvent, state, kCommandControlInsertSet,
                        0xC123u, directControlInsertSet) ||
            directControlInsertSet.value != baselineSet.value ||
            directControlInsertSet.error != baselineSet.error ||
            !ReadEvent(pipe, event, 5000) ||
            !MatchEvent(event, process.dwProcessId, clip::kOpWrite, 0xC123u,
                        clip::kRuleAllow, 0) ||
            event.ruleName != L"复制快捷键直接放行") {
            result = 116;
            break;
        }

        // Let the preceding copy token expire before testing ordinary and
        // opposite-direction calls.
        Sleep(250);
        CommandResult ordinaryGet, ordinarySet;
        if (!RunCommand(commandEvent, doneEvent, state, kCommandGet, 0xC123u,
                        ordinaryGet) ||
            ordinaryGet.value != 0 ||
            ordinaryGet.error != ERROR_ACCESS_DENIED ||
            !ReadEvent(pipe, event, 5000) ||
            !MatchEvent(event, process.dwProcessId, clip::kOpRead, 0xC123u,
                        clip::kRuleBlock, 1) ||
            !RunCommand(commandEvent, doneEvent, state, kCommandSet, 0xC123u,
                        ordinarySet) ||
            ordinarySet.value != 0 ||
            ordinarySet.error != ERROR_ACCESS_DENIED ||
            !ReadEvent(pipe, event, 5000) ||
            !MatchEvent(event, process.dwProcessId, clip::kOpWrite, 0xC123u,
                        clip::kRuleBlock, 1)) {
            result = 63;
            break;
        }

        CommandResult copyDoesNotAllowRead;
        if (!RunCommand(commandEvent, doneEvent, state, kCommandCopyShortcutGet,
                        0xC123u, copyDoesNotAllowRead) ||
            copyDoesNotAllowRead.value != 0 ||
            copyDoesNotAllowRead.error != ERROR_ACCESS_DENIED ||
            !ReadEvent(pipe, event, 5000) ||
            !MatchEvent(event, process.dwProcessId, clip::kOpRead, 0xC123u,
                        clip::kRuleBlock, 1)) {
            result = 64;
            break;
        }
        Sleep(250);
        CommandResult pasteDoesNotAllowWrite;
        if (!RunCommand(commandEvent, doneEvent, state, kCommandPasteShortcutSet,
                        0xC123u, pasteDoesNotAllowWrite) ||
            pasteDoesNotAllowWrite.value != 0 ||
            pasteDoesNotAllowWrite.error != ERROR_ACCESS_DENIED ||
            !ReadEvent(pipe, event, 5000) ||
            !MatchEvent(event, process.dwProcessId, clip::kOpWrite, 0xC123u,
                        clip::kRuleBlock, 1)) {
            result = 65;
            break;
        }

        Sleep(250);
        CommandResult controlInsertDoesNotAllowRead;
        if (!RunCommand(commandEvent, doneEvent, state, kCommandControlInsertGet,
                        0xC123u, controlInsertDoesNotAllowRead) ||
            controlInsertDoesNotAllowRead.value != 0 ||
            controlInsertDoesNotAllowRead.error != ERROR_ACCESS_DENIED ||
            !ReadEvent(pipe, event, 5000) ||
            !MatchEvent(event, process.dwProcessId, clip::kOpRead, 0xC123u,
                        clip::kRuleBlock, 1)) {
            result = 117;
            break;
        }
        Sleep(250);
        CommandResult shiftInsertDoesNotAllowWrite;
        if (!RunCommand(commandEvent, doneEvent, state, kCommandShiftInsertSet,
                        0xC123u, shiftInsertDoesNotAllowWrite) ||
            shiftInsertDoesNotAllowWrite.value != 0 ||
            shiftInsertDoesNotAllowWrite.error != ERROR_ACCESS_DENIED ||
            !ReadEvent(pipe, event, 5000) ||
            !MatchEvent(event, process.dwProcessId, clip::kOpWrite, 0xC123u,
                        clip::kRuleBlock, 1)) {
            result = 118;
            break;
        }

        Sleep(250);
        CommandResult expiredGet, expiredSet;
        if (!RunCommand(commandEvent, doneEvent, state,
                        kCommandDelayedShortcutGet, 0xC123u, expiredGet) ||
            expiredGet.value != 0 || expiredGet.error != ERROR_ACCESS_DENIED ||
            !ReadEvent(pipe, event, 5000) ||
            !MatchEvent(event, process.dwProcessId, clip::kOpRead, 0xC123u,
                        clip::kRuleBlock, 1) ||
            !RunCommand(commandEvent, doneEvent, state,
                        kCommandDelayedShortcutSet, 0xC123u, expiredSet) ||
            expiredSet.value != 0 || expiredSet.error != ERROR_ACCESS_DENIED ||
            !ReadEvent(pipe, event, 5000) ||
            !MatchEvent(event, process.dwProcessId, clip::kOpWrite, 0xC123u,
                        clip::kRuleBlock, 1)) {
            result = 66;
            break;
        }

        // Crypto guard runs before ordinary allow rules. A protected ETH
        // address cannot be replaced by another address by a background caller.
        // Ordinary text and clearing must pass through; copy tokens authorize
        // intentional address changes.
        if (!SendNotificationState(pipe, processName, clip::kRuleAllow,
                                   false, clip::kFormatAny,
                                   L"split-notification", 1)) {
            result = 39;
            break;
        }
        constexpr wchar_t protectedAddress[] =
            L"0x52908400098527886e0f7030069857d2e4169ee7";
        constexpr wchar_t replacementAddress[] =
            L"0xde709f2102306220921060314715629080e2fb77";
        InterlockedExchange(&cryptoState->guard, 1);
        cryptoState->structureVersion = clip::kCryptoProtectionVersion;
        cryptoState->active = 1;
        cryptoState->addressCount = 1;
        cryptoState->addresses[0].kind = clip::kCryptoAddressEthereum;
        cryptoState->writerProcessId = pid;
        cryptoState->clipboardSequence = 1;
        cryptoState->expiresAt = GetTickCount64() + 60000;
        wcscpy_s(cryptoState->addresses[0].canonical, protectedAddress);
        InterlockedExchange(&cryptoState->enabled, 1);
        MemoryBarrier();
        InterlockedExchange(&cryptoState->guard, 0);
        // Let any default one-second copy token expire before exercising a
        // background replacement.
        Sleep(1100);
        PipeEvent drainedEvent;
        while (ReadEvent(pipe, drainedEvent, 100)) {
        }

        CommandResult cryptoReplacement;
        if (!RunTextCommand(commandEvent, doneEvent, state, kCommandSetText,
                            replacementAddress, cryptoReplacement) ||
            cryptoReplacement.value != 0 ||
            cryptoReplacement.error != ERROR_ACCESS_DENIED ||
            !ReadEvent(pipe, event, 5000) ||
            event.pid != process.dwProcessId ||
            event.op != clip::kOpWrite || event.format != CF_UNICODETEXT ||
            event.action != clip::kRuleBlock || event.blocked != 1 ||
            !event.showNotification || event.hash != 0 ||
            !event.preview.empty() ||
            event.ruleName != L"Crypto 保护：地址替换") {

            std::fwprintf(stderr,
                          L"crypto-replacement value=%llu error=%lu "
                          L"event(pid=%lu op=%u fmt=%lu action=%u blocked=%u "
                          L"notify=%u rule=%ls preview=%ls)\n",
                          static_cast<unsigned long long>(cryptoReplacement.value),
                          cryptoReplacement.error, event.pid, event.op,
                          event.format, event.action, event.blocked,
                          event.showNotification ? 1u : 0u,
                          event.ruleName.c_str(), event.preview.c_str());
            result = 40;
            break;
        }
        // These commands deliberately do not open the desktop clipboard: the
        // native API may fail, but Crypto must not turn them into access denial.
        const auto checkCryptoWrite = [&](const std::wstring& text, bool blocked,
                                           UINT format = CF_UNICODETEXT) {
            CommandResult written;
            PipeEvent logged;
            return RunTextCommand(commandEvent, doneEvent, state, kCommandSetText,
                                  text.c_str(), written, format) &&
                   (blocked ? written.value == 0 && written.error == ERROR_ACCESS_DENIED
                            : written.error != ERROR_ACCESS_DENIED) &&
                   ReadEvent(pipe, logged, 5000) &&
                   logged.pid == process.dwProcessId && logged.op == clip::kOpWrite &&
                   logged.format == format && logged.blocked == (blocked ? 1 : 0) &&
                   logged.action == (blocked ? clip::kRuleBlock : clip::kRuleAllow) &&
                   (!blocked || (logged.ruleName == L"Crypto 保护：地址替换" &&
                                 logged.cryptoContent && logged.hash == 0 && logged.preview.empty()));
        };
        if (!checkCryptoWrite(L"ordinary text", false) ||
            !checkCryptoWrite(L"", false) ||
            !checkCryptoWrite(std::wstring(L"新说明，收款：") + protectedAddress, false) ||
            !checkCryptoWrite(std::wstring(L"收款：") + replacementAddress + L"，金额 10", true) ||
            !checkCryptoWrite(std::wstring(5000, L'文') + replacementAddress, true) ||
            !checkCryptoWrite(std::wstring(5000, L'文') + replacementAddress, true, utf8Format) ||
            !checkCryptoWrite(std::wstring(L"收款：") + replacementAddress, true, utf8Format) ||
            !checkCryptoWrite(replacementAddress, true, CF_TEXT) ||
            !checkCryptoWrite(replacementAddress, true, CF_OEMTEXT)) {
            result = 43;
            break;
        }
        CommandResult cryptoClear;
        if (!RunCommand(commandEvent, doneEvent, state,
                        kCommandEmpty, 0, cryptoClear) ||
            cryptoClear.value != baselineEmpty.value ||
            cryptoClear.error != baselineEmpty.error) {
            result = 41;
            break;
        }

        InterlockedExchange(&cryptoState->guard, 1);
        CommandResult unavailableWrite;
        if (!RunTextCommand(commandEvent, doneEvent, state, kCommandSetText,
                            L"crypto state unavailable", unavailableWrite) ||
            unavailableWrite.error == ERROR_ACCESS_DENIED ||
            !ReadEvent(pipe, event, 5000) ||
            !MatchEvent(event, process.dwProcessId, clip::kOpWrite,
                        CF_UNICODETEXT, clip::kRuleAllow, 0)) {
            InterlockedExchange(&cryptoState->guard, 0);
            result = 57;
            break;
        }
        CommandResult unavailableClear;
        if (!RunCommand(commandEvent, doneEvent, state, kCommandEmpty, 0,
                        unavailableClear) ||
            unavailableClear.value != baselineEmpty.value ||
            unavailableClear.error != baselineEmpty.error) {
            InterlockedExchange(&cryptoState->guard, 0);
            result = 58;
            break;
        }
        InterlockedExchange(&cryptoState->guard, 0);

        CommandResult cryptoShortcutReplacement;
        if (!RunTextCommand(commandEvent, doneEvent, state,
                            kCommandShortcutSetText, replacementAddress,
                            cryptoShortcutReplacement) ||
            cryptoShortcutReplacement.error == ERROR_ACCESS_DENIED ||
            !ReadEvent(pipe, event, 5000) ||
            event.pid != process.dwProcessId || event.op != clip::kOpWrite ||
            event.format != CF_UNICODETEXT ||
            event.action != clip::kRuleAllow || event.blocked != 0 ||
            event.showNotification || !event.cryptoContent || event.hash != 0 ||
            event.preview != L"（区块链地址已隐藏）") {
            std::fwprintf(
                stderr,
                L"crypto-log value=%llu error=%lu op=%u fmt=%lu action=%u "
                L"blocked=%u marked=%u hash=%llu preview=%ls\n",
                static_cast<unsigned long long>(cryptoShortcutReplacement.value),
                cryptoShortcutReplacement.error, event.op, event.format,
                event.action, event.blocked, event.cryptoContent ? 1u : 0u,
                event.hash, event.preview.c_str());
            result = 42;
            break;
        }
        if (!clipboardDesktop.path.empty()) {
            // Exercise the complete Empty -> Set -> Close path on the isolated
            // clipboard, including actual baseline publication and retirement.
            Sleep(1100);
            InterlockedExchange(&cryptoState->active, 0);
            const auto copyText = [&](const std::wstring& text, bool blocked) {
                CommandResult copied;
                PipeEvent logged;
                return RunTextCommand(commandEvent, doneEvent, state, kCommandCopyText,
                                      text.c_str(), copied) &&
                       (blocked ? copied.value == 0 && copied.error == ERROR_ACCESS_DENIED
                                : copied.value != 0) &&
                       ReadEvent(pipe, logged, 5000) &&
                       logged.pid == process.dwProcessId && logged.op == clip::kOpWrite &&
                       logged.format == CF_UNICODETEXT && logged.blocked == (blocked ? 1 : 0) &&
                       logged.action == (blocked ? clip::kRuleBlock : clip::kRuleAllow);
            };
            const auto readText = [&](const std::wstring& expected, bool blocked = false) {
                CommandResult read;
                PipeEvent logged;
                return RunCommand(commandEvent, doneEvent, state, kCommandReadText,
                                  CF_UNICODETEXT, read) &&
                       (blocked ? read.value == 0 && read.error == ERROR_ACCESS_DENIED
                                : read.value != 0 && expected == state->text) &&
                       ReadEvent(pipe, logged, 5000) &&
                       logged.pid == process.dwProcessId && logged.op == clip::kOpRead &&
                       logged.format == CF_UNICODETEXT && logged.blocked == (blocked ? 1 : 0) &&
                       logged.action == (blocked ? clip::kRuleBlock : clip::kRuleAllow);
            };
            const std::wstring paragraph = std::wstring(L"收款：") + protectedAddress +
                L"；备用：1BoatSLRHtKNngkdXEeobR76b53LETtpyT。";
            const std::wstring changed = std::wstring(L"收款：") + replacementAddress +
                L"；备用：1BoatSLRHtKNngkdXEeobR76b53LETtpyT。";
            if (!copyText(paragraph, false) || cryptoState->addressCount != 2 ||
                !readText(paragraph) ||
                !copyText(L"修改说明：" + paragraph, false) ||
                !copyText(changed, true) ||
                !copyText(paragraph, false) ||
                !copyText(L"普通内容复写", false) || cryptoState->active != 0 ||
                !readText(L"普通内容复写") ||
                !copyText(replacementAddress, false) || cryptoState->addressCount != 1) {
                result = 71;
                break;
            }
            // A changed address introduced outside the hook is caught on read.
            InterlockedExchange(&cryptoState->guard, 1);
            wcscpy_s(cryptoState->addresses[0].canonical, protectedAddress);
            InterlockedExchange(&cryptoState->guard, 0);
            if (!readText(L"", true) ||
                !copyText(L"普通内容复写", false) || !readText(L"普通内容复写")) {
                result = 72;
                break;
            }
            CommandResult cleared;
            if (!copyText(protectedAddress, false) ||
                !RunCommand(commandEvent, doneEvent, state, kCommandClearClipboard, 0, cleared) ||
                !cleared.value || cryptoState->active != 0 ||
                !copyText(replacementAddress, false) ||
                !copyText(L"", false) || cryptoState->active != 0 ||
                !copyText(std::wstring(5000, L'文') + protectedAddress, false) ||
                !copyText(std::wstring(5000, L'文') + replacementAddress, true)) {
                result = 73;
                break;
            }
        } else {
            std::printf("crypto-transactions-skipped=private-window-station-unavailable\n");
        }
        InterlockedExchange(&cryptoState->enabled, 0);
        InterlockedExchange(&cryptoState->active, 0);

        // Hold off pipe reads while the target produces more events than the
        // bounded queue can retain, then require an explicit non-zero gap.
        if (!SendExtendedState(pipe, false)) {
            result = 26;
            break;
        }
        Sleep(100);
        CommandResult queueStressStart;
        if (!RunCommand(commandEvent, doneEvent, state, kCommandStressStart,
                        CF_UNICODETEXT, queueStressStart) ||
            queueStressStart.value != 1) {
            result = 27;
            break;
        }
        const ULONGLONG queueDeadline = GetTickCount64() + 3000;
        while (InterlockedCompareExchange(&state->stressCalls, 0, 0) < 20000 &&
               GetTickCount64() < queueDeadline)
            Sleep(10);
        CommandResult queueStressStop;
        const LONG queueStressCalls =
            InterlockedCompareExchange(&state->stressCalls, 0, 0);
        if (!RunCommand(commandEvent, doneEvent, state, kCommandStressStop, 0,
                        queueStressStop) || queueStressStop.value != 1 ||
            queueStressCalls < 20000) {
            result = 28;
            break;
        }
        bool gapReported = false;
        const ULONGLONG gapDeadline = GetTickCount64() + 10000;
        while (!gapReported && GetTickCount64() < gapDeadline) {
            PipeEvent queuedEvent;
            if (!ReadEvent(pipe, queuedEvent, 1000)) break;
            gapReported = queuedEvent.gap && queuedEvent.missingEvents != 0;
        }
        if (!gapReported) {
            result = 29;
            break;
        }

        // Pause event production for the detach/restart stress below. The APIs
        // remain hooked and execute fail-open without flooding the pipe again.
        if (!SendState(pipe, L"", clip::kAllowRecord, true)) {
            result = 18;
            break;
        }
        Sleep(100);
        CommandResult stressStart;
        if (!RunCommand(commandEvent, doneEvent, state, kCommandStressStart,
                        CF_UNICODETEXT, stressStart) || stressStart.value != 1) {
            result = 19;
            break;
        }
        if (!WaitForStressReady(state)) {
            result = 20;
            break;
        }

        auto stopStress = [&]() -> bool {
            CommandResult stressStop;
            return RunCommand(commandEvent, doneEvent, state, kCommandStressStop, 0,
                              stressStop) &&
                   stressStop.value == 1 &&
                   InterlockedCompareExchange(&state->stressWorkers, 0, 0) == 0;
        };
        auto restartWorker = [&]() -> bool {
            if (!waitPipeClosed()) return false;
            disconnectTarget();
            ResetEvent(stopEvent);
            Sleep(50);
            if (!connectTarget() ||
                !SendState(pipe, L"", clip::kAllowRecord, true))
                return false;
            Sleep(100);
            CommandResult stressStart;
            if (!RunCommand(commandEvent, doneEvent, state, kCommandStressStart,
                            CF_UNICODETEXT, stressStart) || stressStart.value != 1)
                return false;
            return WaitForStressReady(state);
        };

        // Repeated stop-event cycles force the injected worker to detach and
        // then re-enter through the same target thread's hook callback.
        for (int cycle = 0; cycle < 3; ++cycle) {
            if (cycle == 0) {
                SetEvent(stopEvent);
            } else if (mutexOwned) {
                if (cycle == 2) {
                    // Leave the stop event clear: this cycle is terminated
                    // solely by controller loss, exercising the mutex wait
                    // branch.
                    ReleaseMutex(controllerMutex);
                    mutexOwned = false;
                } else {
                    SetEvent(stopEvent);
                }
            }
            bool pipeClosed = waitPipeClosed();
            bool stressStopped = stopStress();
            if (!pipeClosed || !stressStopped) {
                std::fprintf(stderr, "stress-detach-failed cycle=%d calls=%ld threads=%ld failures=%ld\n",
                             cycle,
                             InterlockedCompareExchange(&state->stressCalls, 0, 0),
                             InterlockedCompareExchange(&state->stressThreadsCreated, 0, 0),
                             InterlockedCompareExchange(&state->stressThreadFailures, 0, 0));
                std::fprintf(stderr, "pipe-closed=%d stress-stopped=%d\n",
                             pipeClosed ? 1 : 0, stressStopped ? 1 : 0);
                result = 21;
                break;
            }
            disconnectTarget();
            if (cycle == 2) {
                // The worker must fail open and close its pipe on its own.
                break;
            }
            if (!restartWorker()) {
                result = 24;
                break;
            }
        }
        if (result != 1) break;
        // Three cycles above include two worker restarts and a final
        // controller-loss detach. The common cleanup below then exits the
        // synthetic target process without touching the product host.
        result = 0;
    } while (false);

    SetEvent(stopEvent);
    if (hook && !UnhookWindowsHookEx(hook) && result == 0) result = 25;
    CommandResult ignored;
    RunCommand(commandEvent, doneEvent, state, kCommandExit, 0, ignored, 1000);
    if (WaitForSingleObject(process.hProcess, 3000) != WAIT_OBJECT_0) {
        TerminateProcess(process.hProcess, 99);
        WaitForSingleObject(process.hProcess, 3000);
        if (result == 0) result = 22;
    } else if (result == 0) {
        DWORD exitCode = 0;
        if (!GetExitCodeProcess(process.hProcess, &exitCode) || exitCode != 0)
            result = 23;
    }
    if (dll) FreeLibrary(dll);
    if (mutexOwned) ReleaseMutex(controllerMutex);
    DisconnectNamedPipe(pipe);
    UnmapViewOfFile(state);
    UnmapViewOfFile(cryptoState);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    CloseHandle(mapping);
    CloseHandle(cryptoMapping);
    CloseHandle(doneEvent);
    CloseHandle(commandEvent);
    CloseHandle(readyEvent);
    CloseHandle(pipe);
    CloseHandle(controllerMutex);
    CloseHandle(stopEvent);
    if (result == 0)
        std::printf("targeted-injection=1 block=1 hot-update=1 events=4 "
                    "empty-ignored=1 ca10=1 snapshots=1 "
                    "shortcut-direct=1 directional=1 expiry=1 "
                    "preview-frame=1 event-gap=1 targeted-concurrent=1 "
                    "crypto-guard=1 text-formats=1 address-format=1 "
                    "private-format=1 sensitive-redaction=1 "
                    "api-triplets-no-openclipboard=1 worker-restarts=2 "
                    "controller-loss-detach=1 clean-exit=1\n");
    else
        std::printf("injection-smoke-failed=%d\n", result);
    return result;
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc >= 2 && wcscmp(argv[1], L"--target") == 0)
        return TargetMain(argc, argv);
    if (argc != 2) return 24;
    return ControllerMain(argv[1]);
}
