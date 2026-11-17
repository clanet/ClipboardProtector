#include <windows.h>
#include <atomic>
#include <cstdio>
#include <string>
#include <thread>
#include "app.h"
#include "pipeserver.h"
#include "confirmwnd.h"
#include "messages.h"

namespace clip { App g_app; }

namespace {
bool Check(bool condition, const char* message) {
    if (!condition) fprintf(stderr, "%s (error=%lu)\n", message, GetLastError());
    return condition;
}
struct Handle {
    HANDLE value = nullptr;
    ~Handle() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); }
};
struct PipePair {
    Handle server, client;
    PipePair() {
        static unsigned next = 0;
        const std::wstring name = L"\\\\.\\pipe\\ClipboardProtector.PipeRegression." +
            std::to_wstring(GetCurrentProcessId()) + L"." + std::to_wstring(++next);
        server.value = CreateNamedPipeW(name.c_str(), PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, 1, 4096, 4096, 0, nullptr);
        client.value = CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0,
            nullptr, OPEN_EXISTING, 0, nullptr);
        if (client.value != INVALID_HANDLE_VALUE) ConnectNamedPipe(server.value, nullptr);
    }
    bool valid() const { return server.value != INVALID_HANDLE_VALUE &&
                               client.value != INVALID_HANDLE_VALUE; }
};
bool Send(HANDLE pipe, BYTE type, const std::string& payload) {
    std::string frame;
    clip::PutFrame(frame, type, payload);
    DWORD sent = 0;
    return WriteFile(pipe, frame.data(), static_cast<DWORD>(frame.size()), &sent,
                     nullptr) && sent == frame.size();
}
struct Incoming {
    std::string bytes;
    bool Next(HANDLE pipe, BYTE& type, std::string& payload, DWORD timeout = 2000) {
        const ULONGLONG deadline = GetTickCount64() + timeout;
        do {
            clip::IpcFrameView frame;
            const auto parsed = clip::ParseFrame(bytes.data(), bytes.size(), frame);
            if (parsed == clip::IpcFrameResult::complete) {
                type = frame.type;
                payload.assign(frame.payload, frame.payloadSize);
                bytes.erase(0, frame.consumed);
                return true;
            }
            if (parsed == clip::IpcFrameResult::invalid) return false;
            DWORD available = 0;
            if (!PeekNamedPipe(pipe, nullptr, 0, nullptr, &available, nullptr)) return false;
            if (available) {
                char buffer[4096];
                DWORD got = 0;
                if (!ReadFile(pipe, buffer, sizeof(buffer), &got, nullptr) || !got) return false;
                bytes.append(buffer, got);
            } else {
                Sleep(5);
            }
        } while (GetTickCount64() < deadline);
        return false;
    }
};
std::atomic<LPARAM> decision{-1};
LRESULT CALLBACK OwnerProc(HWND window, UINT message, WPARAM wp, LPARAM lp) {
    if (message == clip::kMsgConfirmationDecision) { decision = lp; return 0; }
    return DefWindowProcW(window, message, wp, lp);
}
void Pump() {
    MSG message;
    while (PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE)) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
}
}

namespace clip {
struct PipeServerTestAccess {
    static bool Deduplication() {
        PipeServer server;
        LogRow row;
        row.pid = 42;
        row.blocked = true;
        row.action = kRuleBlock;
        row.fmt = CF_DIB;
        row.previewKind = PreviewKind::Truncated;
        // No hash is proof of no identity, even when previews/sequence match.
        row.snapshot = {1, 2, 3};
        if (!server.QueueLogRow(row)) return false;
        row.snapshot = {4, 5, 6};
        if (!server.QueueLogRow(row)) return false;
        row.fmt = CF_UNICODETEXT;
        row.previewKind = PreviewKind::Sensitive;
        row.preview = L"redacted";
        if (!server.QueueLogRow(row) || !server.QueueLogRow(row)) return false;
        row.hash = 123;
        row.previewKind = PreviewKind::Text;
        if (!server.QueueLogRow(row) || server.QueueLogRow(row)) return false;
        row.builtinRule = BuiltinRule::ShortcutProtection;
        if (!server.QueueLogRow(row)) return false;
        row.previewKind = PreviewKind::Sensitive;
        if (!server.QueueLogRow(row)) return false;
        row.missingEvents = 7;
        if (!server.QueueLogRow(row)) return false;
        row.missingEvents = 11;
        if (!server.QueueLogRow(row)) return false;
        unsigned count = 0;
        unsigned long long missing = 0;
        LogRow event;
        while (server.PopEvent(event)) { ++count; missing += event.missingEvents; }
        return Check(count == 9 && missing == 18, "deduplication lost rows or gap counts");
    }

    static bool BlockedReadRetries() {
        PipeServer server;
        LogRow row;
        row.pid = 42;
        row.op = kOpRead;
        row.fmt = CF_DIB;
        row.blocked = true;
        row.action = kRuleBlock;
        row.clipboardSequence = 61;
        row.ruleName = L"deny reads";
        if (!Check(server.QueueLogRow(row) && !server.QueueLogRow(row),
                   "repeated hashless reads were not collapsed")) return false;
        const ULONGLONG beforeRetry = GetTickCount64();
        server.blockedLogState_.at(row.pid).tick = beforeRetry - 900;
        if (!Check(!server.QueueLogRow(row) &&
                   server.blockedLogState_.at(row.pid).tick >= beforeRetry,
                   "read retry did not extend the quiet interval")) return false;
        server.blockedLogState_.at(row.pid).tick = GetTickCount64() - 1001;
        if (!Check(server.QueueLogRow(row), "read after quiet interval was hidden")) return false;
        ++row.clipboardSequence;
        if (!Check(server.QueueLogRow(row), "new clipboard revision was hidden")) return false;
        row.fmt = CF_UNICODETEXT;
        if (!Check(server.QueueLogRow(row), "different read format was hidden")) return false;
        row.ruleName = L"another rule";
        if (!Check(server.QueueLogRow(row), "different read rule was hidden")) return false;
        row.sourcePid = 99;
        if (!Check(server.QueueLogRow(row), "different read source was hidden")) return false;
        ++row.pid;
        if (!Check(server.QueueLogRow(row), "different reading process was hidden")) return false;
        row.missingEvents = 7;
        if (!Check(server.QueueLogRow(row), "read retry lost a gap report")) return false;
        row.missingEvents = 0;
        row.op = kOpWrite;
        if (!Check(server.QueueLogRow(row) && server.QueueLogRow(row),
                   "independent hashless writes were collapsed")) return false;
        row.op = kOpOpen;
        row.fmt = 0;
        if (!Check(server.QueueLogRow(row) && !server.QueueLogRow(row),
                   "repeated blocked opens were not collapsed")) return false;
        row.clipboardSequence = 0;
        if (!Check(server.QueueLogRow(row) && server.QueueLogRow(row),
                   "reads with no revision or hash were collapsed")) return false;
        unsigned count = 0;
        unsigned long long missing = 0;
        LogRow event;
        while (server.PopEvent(event)) { ++count; missing += event.missingEvents; }
        return Check(count == 13 && missing == 7,
                     "read retry filtering lost distinct records or gap counts");
    }

    struct Connection {
        PipeServer server;
        PipePair pair;
        PipeServer::ClientCtx* ctx = nullptr;
        Incoming input;
        HWND notification = nullptr;
        bool Start(unsigned version = 13, bool metadata = true) {
            if (!pair.valid()) return false;
            notification = CreateWindowExW(0, L"STATIC", L"", 0, 0, 0, 0, 0,
                HWND_MESSAGE, nullptr, GetModuleHandleW(nullptr), nullptr);
            if (!notification) return false;
            server.wnd_ = notification;
            server.BroadcastRules({});
            server.BroadcastSettings(g_app.cfg.settings);
            server.BroadcastPause(false);
            ctx = new PipeServer::ClientCtx;
            ctx->self = &server;
            ctx->pipe = pair.server.value;
            pair.server.value = nullptr;
            ctx->pid = GetCurrentProcessId();
            ctx->connectionId = 1;
            ctx->extendedCapable = true;
            ctx->notificationCapable = true;
            ctx->formatModelCapable = true;
            ctx->cryptoSettingsCapable = true;
            ctx->snapshotCapable = true;
            ctx->shortcutPolicyCapable = true;
            ctx->ignoreCustomCapable = true;
            ctx->logVisibilityCapable = version >= 12;
            ctx->textMetadataCapable = metadata;
            ctx->confirmationDeadlineCapable = version >= 13;
            // Force precisely the post-ACK interleaving: ACK invalidates the
            // queued version, then the old writer publishes the same version.
            server.clients_.push_back(ctx);
            ctx->queuedStateVersion = 0;
            ctx->deliveredVersion = server.stateVersion_;
            ctx->writerWake = CreateEventW(nullptr, FALSE, FALSE, nullptr);
            ctx->writerStop = CreateEventW(nullptr, TRUE, FALSE, nullptr);
            if (!ctx->writerWake || !ctx->writerStop) return false;
            ctx->writerThread = CreateThread(nullptr, 0, PipeServer::WriterThreadStatic,
                                             ctx, 0, nullptr);
            ctx->thread = CreateThread(nullptr, 0, PipeServer::ClientThreadStatic,
                                       ctx, 0, nullptr);
            return ctx->writerThread && ctx->thread;
        }
        ~Connection() {
            server.wnd_ = nullptr;
            if (ctx) {
                fprintf(stderr, "protocol connection joining workers\n");
                server.stop_ = true;
                server.JoinClient(ctx, 0);
                fprintf(stderr, "protocol connection workers joined\n");
                {
                    std::lock_guard<std::mutex> lock(server.clientsMu_);
                    server.clients_.clear();
                }
                server.DeleteClient(ctx);
            }
            if (notification) DestroyWindow(notification);
        }
        bool Snapshot(unsigned settingsLength) {
            unsigned rules = 0, settings = 0;
            for (unsigned i = 0; i < 4; ++i) {
                BYTE type = 0;
                std::string payload;
                if (!input.Next(pair.client.value, type, payload)) return false;
                if (type == kIpcRulesExtended) ++rules;
                if (type == kIpcSettings) {
                    ++settings;
                    if (payload.size() != settingsLength) return false;
                    if (settingsLength == 12 && payload[11] != 1) return false;
                    if (settingsLength >= 11 && payload[10] !=
                        (ctx->textMetadataCapable.load() ? 1 : 0)) return false;
                }
            }
            BYTE extraType = 0;
            std::string extraPayload;
            return rules == 1 && settings == 1 &&
                !input.Next(pair.client.value, extraType, extraPayload, 150);
        }
        bool Confirmation(unsigned long long token, ULONGLONG deadline,
                          bool timeoutBlock, bool includeDeadline = true) {
            std::string payload;
            PutU64(payload, token);
            PutU8(payload, kOpRead);
            PutU32(payload, CF_UNICODETEXT);
            PutU32(payload, 0);
            PutWStr(payload, L""); PutWStr(payload, L"");
            PutWStr(payload, L"confirm"); PutWStr(payload, L"preview");
            PutU32(payload, 1000);
            PutU8(payload, timeoutBlock ? 1 : 0);
            if (ctx->textMetadataCapable.load()) PutU8(payload, static_cast<BYTE>(PreviewKind::Text));
            if (includeDeadline) PutU64(payload, deadline);
            return Send(pair.client.value, kIpcConfirmRequest, payload);
        }
        bool Response(unsigned long long expectedToken, bool expectedAllow) {
            BYTE type = 0, allow = 0;
            std::string payload;
            if (!input.Next(pair.client.value, type, payload) || type != kIpcConfirmResponse) return false;
            Reader reader(payload.data(), payload.size());
            unsigned long long token = 0;
            return reader.GetU64(token) && reader.GetU8(allow) && reader.n == 0 &&
                token == expectedToken && (allow != 0) == expectedAllow;
        }
    };

    static bool Protocol() {
        struct Phase {
            unsigned version;
            bool metadata;
            const char* name = "connection startup and extended snapshot";
            bool passed = false;
            ~Phase() {
                if (!passed)
                    fprintf(stderr, "protocol CA%u metadata=%d phase=%s failed (error=%lu)\n",
                            version, metadata, name, GetLastError());
            }
        };
        for (unsigned version : {11u, 12u, 13u}) {
            for (bool metadata : {false, true}) {
                if (version == 11 && metadata) continue;
                Phase phase{version, metadata};
                fprintf(stderr, "protocol CA%u metadata=%d starting\n", version, metadata);
                Connection connection;
                if (!connection.Start(version, metadata) ||
                    !Check(connection.Snapshot(version >= 13 ? 12 : metadata ? 11 : 10),
                           "ACK race, legacy settings length, or snapshot storm")) return false;
                phase.name = "ACK parsing and send";
                std::string ack;
                PutU32(ack, version == 13 ? kStateAckCapabilityMarkerV13 :
                            version == 12 ? kStateAckCapabilityMarkerV12 :
                                            kStateAckCapabilityMarkerV11);
                PutU8(ack, 1);
                PutU8(ack, kStateAckCryptoMappingAvailable |
                           (metadata ? kStateAckTextMetadataAvailable : 0));
                StateAck parsed;
                if (!ParseStateAck(ack.data(), ack.size(), parsed) ||
                    parsed.version != version ||
                    !Send(connection.pair.client.value, kIpcStateAck, ack)) return false;
                phase.name = "state readiness";
                const ULONGLONG readyBy = GetTickCount64() + 1000;
                while (!connection.ctx->stateReady && GetTickCount64() < readyBy) Sleep(5);
                if (!connection.ctx->stateReady) return false;
                BYTE extraType = 0;
                std::string extraPayload;
                phase.name = "duplicate snapshot after ACK";
                if (connection.input.Next(connection.pair.client.value, extraType,
                                          extraPayload, 150)) return false;
                // Completion of an older queued frame must not lower a newer
                // delivered version (including the shutdown publication).
                phase.name = "monotonic delivered version";
                connection.ctx->deliveredVersion = 100;
                std::string probe;
                PutFrame(probe, kIpcPause, std::string(1, '\0'));
                if (!connection.server.QueueOutbound(connection.ctx, std::move(probe), 1) ||
                    !connection.input.Next(connection.pair.client.value, extraType, extraPayload) ||
                    extraType != kIpcPause) return false;
                Sleep(40);
                if (connection.ctx->deliveredVersion != 100) return false;
                if (version != 13) {
                    phase.name = "legacy confirmation round trip";
                    const ULONGLONG sentAt = GetTickCount64();
                    if (!connection.Confirmation(9, 0, true, false)) return false;
                    AccessConfirmationRequest legacy;
                    const ULONGLONG popBy = sentAt + 500;
                    bool popped = false;
                    while (GetTickCount64() < popBy) {
                        if (connection.server.PopConfirmation(legacy)) { popped = true; break; }
                        Sleep(5);
                    }
                    if (!popped || legacy.deadline < sentAt + 1000 ||
                        !connection.server.ResolveConfirmation(legacy.id, true) ||
                        !connection.Response(9, true)) return false;
                    phase.passed = true;
                    continue;
                }
                const ULONGLONG expired = GetTickCount64() - 1;
                phase.name = "expired confirmation response";
                if (!connection.Confirmation(1, expired, true) ||
                    !connection.Response(1, false) ||
                    !connection.Confirmation(2, expired, false) ||
                    !connection.Response(2, true)) return false;
                AccessConfirmationRequest request;
                if (connection.server.PopConfirmation(request)) return false;
                // Queue before expiry, consume after expiry; Pop must resolve
                // the timeout without handing an obsolete request to the UI.
                phase.name = "confirmation queued before expiry";
                const ULONGLONG deadline = GetTickCount64() + 200;
                if (!connection.Confirmation(3, deadline, true)) return false;
                const ULONGLONG queuedBy = GetTickCount64() + 150;
                bool queued = false;
                while (GetTickCount64() < queuedBy) {
                    {
                        std::lock_guard<std::mutex> lock(connection.server.confirmationsMu_);
                        queued = !connection.server.confirmations_.empty();
                    }
                    if (queued) break;
                    Sleep(5);
                }
                if (!queued) return false;
                Sleep(220);
                phase.name = "expired confirmation popped";
                if (connection.server.PopConfirmation(request) ||
                    !connection.Response(3, false)) return false;
                // A late UI decision must use timeout policy even if Pop had
                // handed the request to the UI while it was still timely.
                if (!connection.Confirmation(4, GetTickCount64() + 200, false)) return false;
                phase.name = "late UI decision uses timeout policy";
                const ULONGLONG popBy = GetTickCount64() + 150;
                bool popped = false;
                while (GetTickCount64() < popBy) {
                    if (connection.server.PopConfirmation(request)) { popped = true; break; }
                    Sleep(5);
                }
                if (!popped) return false;
                Sleep(220);
                if (!connection.server.ResolveConfirmation(request.id, false) ||
                    !connection.Response(4, true)) return false;
                phase.passed = true;
            }
        }
        return true;
    }

    static DWORD WINAPI DelayedClient(LPVOID value) {
        auto* ctx = static_cast<PipeServer::ClientCtx*>(value);
        Sleep(3300); // Outlive StopClients' bounded three-second cancellation.
        ctx->self->QueueLogRow(LogRow{});
        ctx->self->ClientFinished(ctx);
        return 0;
    }
    static DWORD WINAPI LateWriter(LPVOID value) {
        auto* ctx = static_cast<PipeServer::ClientCtx*>(value);
        Sleep(100); // The first CancelSynchronousIo happens before WriteFile.
        std::string bytes(1u << 20, 'x');
        DWORD sent = 0;
        WriteFile(ctx->pipe.load(), bytes.data(), static_cast<DWORD>(bytes.size()),
                  &sent, nullptr); // The unread 4 KiB pipe forces cancellation.
        ctx->self->QueueLogRow(LogRow{});
        return 0;
    }
    static bool Destruction() {
        PipePair pair;
        if (!pair.valid()) return false;
        auto* server = new PipeServer;
        auto* ctx = new PipeServer::ClientCtx;
        ctx->self = server;
        ctx->pipe = pair.server.value;
        pair.server.value = nullptr;
        ctx->shutdownAck = true;
        ctx->deliveredVersion = 1;
        ctx->thread = CreateThread(nullptr, 0, DelayedClient, ctx, 0, nullptr);
        ctx->writerThread = CreateThread(nullptr, 0, LateWriter, ctx, 0, nullptr);
        server->clients_.push_back(ctx);
        Handle client, writer;
        DuplicateHandle(GetCurrentProcess(), ctx->thread, GetCurrentProcess(),
                        &client.value, SYNCHRONIZE, FALSE, 0);
        DuplicateHandle(GetCurrentProcess(), ctx->writerThread, GetCurrentProcess(),
                        &writer.value, SYNCHRONIZE, FALSE, 0);
        delete server;
        return Check(client.value && writer.value &&
            WaitForSingleObject(client.value, 0) == WAIT_OBJECT_0 &&
            WaitForSingleObject(writer.value, 0) == WAIT_OBJECT_0,
            "destructor returned while a worker still referenced self");
    }
};
}

int wmain() {
    clip::g_app.cfg.settings.ignoreCustomFormats = false;
    fprintf(stderr, "deduplication starting\n");
    if (!Check(clip::PipeServerTestAccess::Deduplication(), "deduplication stage failed")) return 1;
    fprintf(stderr, "blocked read retries starting\n");
    if (!Check(clip::PipeServerTestAccess::BlockedReadRetries(), "blocked read retry stage failed")) return 9;
    fprintf(stderr, "protocol starting\n");
    if (!Check(clip::PipeServerTestAccess::Protocol(), "protocol stage failed")) return 2;
    fprintf(stderr, "destruction starting\n");
    if (!Check(clip::PipeServerTestAccess::Destruction(), "destruction stage failed")) return 3;
    fprintf(stderr, "confirmation windows starting\n");
    WNDCLASSW ownerClass{};
    ownerClass.hInstance = GetModuleHandleW(nullptr);
    ownerClass.lpfnWndProc = OwnerProc;
    ownerClass.lpszClassName = L"ClipboardProtector.ConfirmationRegression";
    if (!Check(RegisterClassW(&ownerClass) != 0, "confirmation owner class failed")) return 4;
    HWND owner = CreateWindowW(ownerClass.lpszClassName, L"", 0, 0, 0, 0, 0,
                               HWND_MESSAGE, nullptr, ownerClass.hInstance, nullptr);
    if (!Check(owner != nullptr, "confirmation owner window failed")) return 5;
    clip::AccessConfirmationRequest request;
    request.deadline = GetTickCount64() - 1;
    if (!Check(!clip::AccessConfirmationWindow::Create(ownerClass.hInstance, owner, request, 0),
               "expired confirmation created a window")) return 6;
    for (bool timeoutBlock : {false, true}) {
        request.timeoutBlock = timeoutBlock;
        request.deadline = GetTickCount64() + 1000;
        auto window = clip::AccessConfirmationWindow::Create(ownerClass.hInstance, owner, request, 0);
        if (!Check(window != nullptr, "timely confirmation window failed")) return 7;
        SendDlgItemMessageW(window->hwnd(), clip::kConfirmationPersistDecision,
                            BM_SETCHECK, BST_CHECKED, 0);
        decision = -1;
        const ULONGLONG now = GetTickCount64();
        if (now < request.deadline)
            Sleep(static_cast<DWORD>(request.deadline - now + 10));
        // Deliver click synchronously before pumping the expired WM_TIMER.
        SendMessageW(window->hwnd(), WM_COMMAND, timeoutBlock ? IDOK : clip::kConfirmationBlock, 0);
        Pump();
        if (!Check(decision.load() == (timeoutBlock ? 0 : 1),
                   "late click escaped timeout policy or persisted a decision")) return 8;
    }
    DestroyWindow(owner);
    puts("pipe and confirmation regression smoke passed");
    return 0;
}
