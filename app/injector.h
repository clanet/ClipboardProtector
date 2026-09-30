#pragma once
#include <windows.h>
#include <string>

namespace clip {

// 通过全局 WH_GETMESSAGE 钩子把当前协议版 Hook DLL 注入 GUI 进程。
class Injector {
public:
    // 正式模式使用全局注入；单进程模式只向目标的消息线程注入。
    bool Install(const std::wstring& hookDllPath);
    bool InstallForThread(const std::wstring& hookDllPath, DWORD threadId);
    // The process path is checked again while the process/thread handles are
    // held, immediately before SetWindowsHookExW.
    bool InstallForProcess(const std::wstring& hookDllPath, DWORD processId);
    bool InstallForProcess(const std::wstring& hookDllPath, DWORD processId,
                           const std::wstring& expectedTargetPath);
#ifdef _WIN64
    bool Install32BitHelper(const std::wstring& helperPath,
                            const std::wstring& hookDllPath);
#endif
    bool Remove();
    bool installed() const { return hook_ != nullptr; }
    DWORD lastError() const { return lastError_; }
    const std::wstring& lastErrorText() const { return lastErrorText_; }

private:
    bool InstallForThreadImpl(const std::wstring& hookDllPath, DWORD threadId,
                              HANDLE targetProcess, HANDLE targetThread,
                              const std::wstring& expectedTargetPath);
    HMODULE mod_ = nullptr;
    HHOOK hook_ = nullptr;
    DWORD lastError_ = ERROR_SUCCESS;
    std::wstring lastErrorText_;
#ifdef _WIN64
    HANDLE helperProcess_ = nullptr;
    HANDLE helperStopEvent_ = nullptr;
#endif
};

} // namespace clip
