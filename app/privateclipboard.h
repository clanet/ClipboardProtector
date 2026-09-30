#pragma once
#include <windows.h>
#include <atomic>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#include <functional>
#include "i18n.h"

namespace clip {

// Text stays in memory; a hooked target handles a tagged Ctrl+C/Ctrl+V command.
class PrivateClipboard {
public:
    enum class Operation { copy, paste };
    static constexpr size_t kMaxCharacters = 65536;
    using ArmTarget = std::function<bool(DWORD, const std::wstring&)>;
    ~PrivateClipboard();
    bool Start(Operation operation, HWND foreground, HWND notify, UINT message,
               ArmTarget arm = {});
    bool TakeResult(std::wstring& message, bool& success);
    void Clear();
    void Stop();
    bool HasText() const;
    bool Busy() const { return busy_.load(); }
#ifdef CLIP_TEST_OBJECT_NAMES
    const wchar_t* DiagnosticStatusForTest() const {
        return busy_.load() ? UiText(TextId::PrivateOperationInProgress) : result_.c_str();
    }
#endif

private:
    struct Text {
        std::vector<wchar_t> chars;
        ~Text() { Clear(); }
        void Clear();
    };
    void Run(Operation operation, HWND foreground, HWND focus);
    mutable std::mutex mutex_;
    Text text_;
    std::thread worker_;
    std::atomic<bool> cancelled_{false};
    std::atomic<bool> stopping_{false};
    std::atomic<bool> busy_{false};
    std::atomic<bool> ready_{false};
    std::wstring result_;
    bool success_ = false;
    ArmTarget armTarget_;
};

} // namespace clip
