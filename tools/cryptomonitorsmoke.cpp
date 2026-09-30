#include "../app/cryptomonitor.h"
#include <atomic>
#include <cstdio>
#include <functional>
#include <mutex>
#include <stdexcept>
#include <string>

namespace {
#define CHECK(value) do { if (!(value)) throw std::runtime_error(#value); } while (0)
const std::wstring a = L"0x1111111111111111111111111111111111111111";
const std::wstring b = L"0x2222222222222222222222222222222222222222";

bool Wait(const std::function<bool()>& predicate, DWORD timeout = 3000) {
    const ULONGLONG deadline = GetTickCount64() + timeout;
    do {
        if (predicate()) return true;
        Sleep(10);
    } while (GetTickCount64() < deadline);
    return predicate();
}

class Reader final : public clip::CryptoClipboardReader {
public:
    ~Reader() override { CloseHandle(release); }
    DWORD Sequence() override { return sequence.load(); }
    bool Read(std::wstring& text, DWORD& sampledSequence) override {
        ++reads;
        if (stall.exchange(false)) {
            stalled.store(true);
            WaitForSingleObject(release, INFINITE);
        }
        if (fail.load()) return false;
        std::lock_guard<std::mutex> lock(mutex);
        text = value;
        sampledSequence = sequence.load();
        ++completed;
        return true;
    }
    void Write(const std::wstring& text, bool advanceSequence = true) {
        std::lock_guard<std::mutex> lock(mutex);
        value = text;
        if (advanceSequence) ++sequence;
    }
    std::atomic<DWORD> sequence{1};
    std::atomic<unsigned> reads{0}, completed{0};
    std::atomic<bool> fail{false}, stall{false}, stalled{false};
    HANDLE release = CreateEventW(nullptr, TRUE, FALSE, nullptr);
private:
    std::mutex mutex;
    std::wstring value = a;
};

void Run() {
    auto reader = std::make_shared<Reader>();
    clip::CryptoClipboardMonitor monitor;
    CHECK(monitor.Start(reader));
    clip::CryptoClipboardChange change;
    Sleep(50);
    CHECK(reader->reads == 0); // Disabled monitors must never read clipboard data.
    monitor.SetEnabled(true);
    CHECK(Wait([&] { return reader->completed >= 1; }));
    CHECK(!monitor.PopChange(change));
    reader->Write(b);
    monitor.Wake();
    CHECK(Wait([&] { return monitor.PopChange(change); }));
    CHECK(change.sequence == reader->sequence && change.time.wYear >= 2026);
    const unsigned before = reader->completed;
    CHECK(Wait([&] { return reader->completed > before; }));
    CHECK(!monitor.PopChange(change));

    // Detect a modified allocation even if Windows sends no change notification.
    reader->Write(a, false);
    CHECK(Wait([&] { return monitor.PopChange(change); }));
    reader->fail = true;
    reader->Write(b);
    monitor.Wake();
    const unsigned failedRead = reader->reads;
    CHECK(Wait([&] { return reader->reads > failedRead; }));
    CHECK(!monitor.PopChange(change));
    reader->fail = false;
    CHECK(Wait([&] { return monitor.PopChange(change); }));

    reader->Write(L"");
    monitor.Wake();
    CHECK(Wait([&] { return monitor.PopChange(change); }));
    const unsigned emptyReads = reader->completed;
    Sleep(600);
    CHECK(reader->completed == emptyReads && !monitor.PopChange(change));

    monitor.SetEnabled(false);
    reader->Write(a);
    monitor.SetEnabled(true);
    CHECK(Wait([&] { return reader->completed > emptyReads; }));
    CHECK(!monitor.PopChange(change));

    // Discard a read that began before pause, even after immediate re-enable.
    reader->stall = true;
    reader->Write(b);
    monitor.Wake();
    CHECK(Wait([&] { return reader->stalled.load(); }));
    monitor.SetEnabled(false);
    monitor.SetEnabled(true);
    const unsigned inFlight = reader->completed;
    SetEvent(reader->release);
    CHECK(Wait([&] { return reader->completed >= inFlight + 2; }));
    CHECK(!monitor.PopChange(change));
    ResetEvent(reader->release);
    reader->stalled = false;
    reader->stall = true;
    reader->Write(a);
    monitor.Wake();
    CHECK(Wait([&] { return reader->stalled.load(); }));
    monitor.SetEnabled(false);
    const ULONGLONG stopped = GetTickCount64();
    monitor.Stop();
    CHECK(GetTickCount64() - stopped < 1500);
    SetEvent(reader->release);
    CHECK(Wait([&] { return reader.use_count() == 1; }));
    CHECK(!monitor.PopChange(change));

    // Stop/start must not carry an old baseline into a new monitoring session.
    CHECK(monitor.Start(reader));
    const unsigned oldCompleted = reader->completed;
    monitor.SetEnabled(true);
    CHECK(Wait([&] { return reader->completed > oldCompleted; }));
    CHECK(!monitor.PopChange(change));
    reader->Write(b);
    monitor.Wake();
    CHECK(Wait([&] { return monitor.PopChange(change); }));
    monitor.Stop();
}
} // namespace

int wmain() {
    try {
        Run();
        std::puts("crypto monitor: change detection, retries, pause/reset and bounded shutdown passed; system clipboard untouched");
        return 0;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "%s\n", error.what());
        return 1;
    }
}
