#include "hookthread.h"
#include "shutdowntrace.h"
#include <new>
#include <utility>

namespace clip {

struct HookThread::State {
    HANDLE thread = nullptr;
    HANDLE stop = nullptr;
    HANDLE completed = nullptr;
    HMODULE module = nullptr;
    HOOKPROC procedure = nullptr;
    DWORD targetThreadId = 0;
    std::atomic<DWORD> result{ERROR_SUCCESS};
#ifdef CLIP_TEST_HOOK_THREAD
    HWND window = nullptr;
    std::atomic<bool> failRemoval{false};
#endif

    ~State() {
        if (thread) CloseHandle(thread);
        if (stop) CloseHandle(stop);
        if (completed) CloseHandle(completed);
        if (module) FreeLibrary(module);
    }
};

HookThread::~HookThread() { Remove(); }

DWORD HookThread::Install(HOOKPROC procedure, HMODULE module, DWORD targetThreadId) {
    if (installed()) return ERROR_SUCCESS;
    if (state_) return ERROR_INVALID_STATE;
    std::shared_ptr<State> state;
    try {
        state = std::make_shared<State>();
    } catch (...) {
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    state->procedure = procedure;
    state->targetThreadId = targetThreadId;
    // The worker owns a reference even if a failed unhook outlives its caller.
    if (module && !GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                                    reinterpret_cast<LPCWSTR>(module),
                                    &state->module))
        return GetLastError();
    state->stop = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    if (!state->stop) return GetLastError();
    state->completed = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    if (!state->completed) return GetLastError();
    auto* argument = new (std::nothrow) std::shared_ptr<State>(state);
    if (!argument) return ERROR_NOT_ENOUGH_MEMORY;
    state->thread = CreateThread(nullptr, 0, Run, argument, 0, nullptr);
    if (!state->thread) {
        const DWORD error = GetLastError();
        delete argument;
        return error;
    }
    state_ = std::move(state);
    if (WaitForSingleObject(state_->completed, INFINITE) != WAIT_OBJECT_0)
        return GetLastError();
    const DWORD result = state_->result.load(std::memory_order_acquire);
    if (result != ERROR_SUCCESS) {
        WaitForSingleObject(state_->thread, INFINITE);
        state_.reset();
        return result;
    }
    installed_.store(true, std::memory_order_release);
    return ERROR_SUCCESS;
}

DWORD HookThread::Remove() {
    if (!state_) return ERROR_SUCCESS;
    if (!SetEvent(state_->stop)) return GetLastError();
    if (WaitForSingleObject(state_->completed, INFINITE) != WAIT_OBJECT_0)
        return GetLastError();
    const DWORD result = state_->result.load(std::memory_order_acquire);
    if (result != ERROR_SUCCESS) return result;
    WaitForSingleObject(state_->thread, INFINITE);
    installed_.store(false, std::memory_order_release);
    state_.reset();
    return ERROR_SUCCESS;
}

DWORD WINAPI HookThread::Run(void* argument) {
    std::shared_ptr<State> state =
        std::move(*static_cast<std::shared_ptr<State>*>(argument));
    delete static_cast<std::shared_ptr<State>*>(argument);
    ShutdownTrace trace;
    trace.Open(L"hook-owner", state->module);
    MSG message;
    PeekMessageW(&message, nullptr, 0, 0, PM_NOREMOVE);
    HHOOK hook = SetWindowsHookExW(WH_GETMESSAGE, state->procedure,
                                 state->module, state->targetThreadId);
    state->result.store(hook ? ERROR_SUCCESS : GetLastError(),
                        std::memory_order_release);
#ifdef CLIP_TEST_HOOK_THREAD
    state->window = CreateWindowExW(0, L"STATIC", L"", 0, 0, 0, 0, 0,
                                   HWND_MESSAGE, nullptr, nullptr, nullptr);
#endif
    SetEvent(state->completed);
    while (hook) {
        const DWORD wait = MsgWaitForMultipleObjectsEx(
            1, &state->stop, INFINITE, QS_ALLINPUT, MWMO_INPUTAVAILABLE);
        if (wait == WAIT_OBJECT_0) {
            trace.Mark("UnhookWindowsHookEx.begin");
            DWORD error = ERROR_SUCCESS;
#ifdef CLIP_TEST_HOOK_THREAD
            if (state->failRemoval.exchange(false)) error = ERROR_ACCESS_DENIED;
            else
#endif
            if (!UnhookWindowsHookEx(hook)) error = GetLastError();
            trace.Mark("UnhookWindowsHookEx.end", 0, error);
            state->result.store(error,
                                std::memory_order_release);
            SetEvent(state->completed);
            if (error == ERROR_SUCCESS) break;
            // Failed removal retains the module and message pump for a retry.
        } else if (wait == WAIT_OBJECT_0 + 1) {
            for (int count = 0; count < 64 &&
                 PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE); ++count) {
                TranslateMessage(&message);
                DispatchMessageW(&message);
            }
        }
    }
#ifdef CLIP_TEST_HOOK_THREAD
    if (state->window) DestroyWindow(state->window);
#endif
    trace.Mark("hook_owner.thread_exit.next");
    return 0;
}

#ifdef CLIP_TEST_HOOK_THREAD
HWND HookThread::windowForTest() const { return state_ ? state_->window : nullptr; }
void HookThread::failNextRemovalForTest() { state_->failRemoval.store(true); }
#endif

} // namespace clip
