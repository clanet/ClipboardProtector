#pragma once
#include <windows.h>
#include <memory>
#include <string>

namespace clip {

struct CryptoClipboardChange {
    DWORD sequence = 0;
    SYSTEMTIME time{};
};

class CryptoClipboardReader {
public:
    virtual ~CryptoClipboardReader() = default;
    virtual DWORD Sequence() = 0;
    virtual bool Read(std::wstring& text, DWORD& sequence) = 0;
};

// Reads the clipboard off the UI thread. Events never retain clipboard text or
// attribute a write to a process based solely on the clipboard owner window.
class CryptoClipboardMonitor {
public:
    CryptoClipboardMonitor() = default;
    CryptoClipboardMonitor(const CryptoClipboardMonitor&) = delete;
    CryptoClipboardMonitor& operator=(const CryptoClipboardMonitor&) = delete;
    ~CryptoClipboardMonitor();
    bool Start(std::shared_ptr<CryptoClipboardReader> reader = {});
    void SetEnabled(bool enabled);
    void Wake();
    bool PopChange(CryptoClipboardChange& change);
    void Stop();

private:
    struct State;
    static DWORD WINAPI Run(void* parameter);
    std::shared_ptr<State> state_;
    HANDLE thread_ = nullptr;
};

} // namespace clip
