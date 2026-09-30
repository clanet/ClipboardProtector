#include "cryptomonitor.h"
#include "crypto.h"
#include <algorithm>
#include <deque>
#include <mutex>
#include <string>

namespace clip {
namespace {
constexpr DWORD kPollIntervalMs = 500;
constexpr size_t kMaxPendingChanges = 128;

struct ClipboardLock {
    ~ClipboardLock() { CloseClipboard(); }
};

struct ClipboardText {
    std::wstring value;
    ~ClipboardText() {
        if (!value.empty()) SecureZeroMemory(value.data(), value.size() * sizeof(wchar_t));
    }
};

class SystemClipboardReader final : public CryptoClipboardReader {
public:
    DWORD Sequence() override { return GetClipboardSequenceNumber(); }
    bool Read(std::wstring& text, DWORD& sequence) override;
};

bool SystemClipboardReader::Read(std::wstring& text, DWORD& sequence) {
    if (!OpenClipboard(nullptr)) return false;
    ClipboardLock close;
    const DWORD before = GetClipboardSequenceNumber();
    if (IsClipboardFormatAvailable(CF_UNICODETEXT)) {
        HANDLE memory = GetClipboardData(CF_UNICODETEXT);
        if (!memory) return false;
        const SIZE_T bytes = GlobalSize(memory);
        if (bytes < sizeof(wchar_t) || bytes % sizeof(wchar_t) != 0) return false;
        const auto* data = static_cast<const wchar_t*>(GlobalLock(memory));
        if (!data) return false;
        const size_t capacity = (std::min)(static_cast<size_t>(bytes / sizeof(wchar_t)),
                                           kMaxCryptoTextLength + 1);
        const auto* end = std::find(data, data + capacity, L'\0');
        bool complete = end != data + capacity;
        try {
            if (complete) text.assign(data, end);
        } catch (...) {
            complete = false;
        }
        GlobalUnlock(memory);
        if (!complete) return false;
    }
    sequence = GetClipboardSequenceNumber();
    // Delayed rendering can change the sequence even while the clipboard is
    // open. Retry a stable snapshot rather than comparing different revisions.
    return sequence != 0 && sequence == before;
}
} // namespace

struct CryptoClipboardMonitor::State {
    HANDLE stop = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    HANDLE wake = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    std::mutex mutex;
    bool enabled = false;
    unsigned long long generation = 0;
    std::deque<CryptoClipboardChange> changes;
    std::shared_ptr<CryptoClipboardReader> reader;
    ~State() {
        if (stop) CloseHandle(stop);
        if (wake) CloseHandle(wake);
    }
};

CryptoClipboardMonitor::~CryptoClipboardMonitor() { Stop(); }

bool CryptoClipboardMonitor::Start(std::shared_ptr<CryptoClipboardReader> reader) {
    if (thread_) return true;
    try {
        auto state = std::make_shared<State>();
        if (!state->stop || !state->wake) return false;
        state->reader = reader ? std::move(reader) : std::make_shared<SystemClipboardReader>();
        auto context = std::make_unique<std::shared_ptr<State>>(state);
        thread_ = CreateThread(nullptr, 0, Run, context.get(), 0, nullptr);
        if (!thread_) return false;
        context.release();
        state_ = std::move(state);
        return true;
    } catch (...) {
        return false;
    }
}

void CryptoClipboardMonitor::SetEnabled(bool enabled) {
    if (!state_) return;
    std::lock_guard<std::mutex> lock(state_->mutex);
    if (state_->enabled == enabled) return;
    state_->enabled = enabled;
    ++state_->generation;
    state_->changes.clear();
    SetEvent(state_->wake);
}

void CryptoClipboardMonitor::Wake() {
    if (state_) SetEvent(state_->wake);
}

bool CryptoClipboardMonitor::PopChange(CryptoClipboardChange& change) {
    if (!state_) return false;
    std::lock_guard<std::mutex> lock(state_->mutex);
    if (state_->changes.empty()) return false;
    change = state_->changes.front();
    state_->changes.pop_front();
    return true;
}

void CryptoClipboardMonitor::Stop() {
    if (!state_) return;
    SetEnabled(false);
    SetEvent(state_->stop);
    // A foreign clipboard owner can stall delayed rendering. The worker owns
    // its state and never touches the UI, so shutdown need not wait for it.
    WaitForSingleObject(thread_, 500);
    CloseHandle(thread_);
    thread_ = nullptr;
    state_.reset();
}

DWORD WINAPI CryptoClipboardMonitor::Run(void* parameter) {
    std::unique_ptr<std::shared_ptr<State>> context(
        static_cast<std::shared_ptr<State>*>(parameter));
    const auto state = *context;
    context.reset();
    CryptoAddressTracker tracker;
    unsigned long long generation = 0;
    DWORD lastSequence = 0;
    bool sampled = false;
    const HANDLE waits[] = {state->stop, state->wake};
    for (;;) {
        if (WaitForSingleObject(state->stop, 0) != WAIT_TIMEOUT) return 0;
        bool enabled = false;
        {
            std::lock_guard<std::mutex> lock(state->mutex);
            enabled = state->enabled;
            if (generation != state->generation) {
                generation = state->generation;
                tracker.Reset();
                sampled = false;
            }
        }
        try {
            // Re-read active addresses even without a sequence change; writes
            // to an existing clipboard allocation need not send a notification.
            if (enabled && (!sampled || tracker.active() ||
                            state->reader->Sequence() != lastSequence)) {
                ClipboardText text;
                DWORD sequence = 0;
                if (state->reader->Read(text.value, sequence)) {
                    std::lock_guard<std::mutex> lock(state->mutex);
                    if (state->enabled && generation == state->generation) {
                        if (tracker.Update(text.value)) {
                            CryptoClipboardChange change;
                            change.sequence = sequence;
                            GetLocalTime(&change.time);
                            if (state->changes.size() == kMaxPendingChanges)
                                state->changes.pop_front();
                            state->changes.push_back(change);
                        }
                        lastSequence = sequence;
                        sampled = true;
                    }
                }
            }
        } catch (...) {
            // Keep the last complete baseline and retry transient read failures.
        }
        const DWORD wait = WaitForMultipleObjects(
            2, waits, FALSE, enabled ? kPollIntervalMs : INFINITE);
        if (wait == WAIT_OBJECT_0 || wait == WAIT_FAILED) return 0;
    }
}

} // namespace clip
