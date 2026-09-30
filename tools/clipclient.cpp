// clipclient：M2/M3 端到端验证用测试客户端（非交付组件）。
// 用法：
//   clipclient console        交互模式：r 读取，w [内容] 写入，q 退出
//   clipclient wait <ms> [text [signal-dir]]
//                              保持消息循环并输出 PID；传 text 时执行
//                              Sandbox 探针，signal-dir 用于分阶段 GUI 验收
//   clipclient set <text>     写入剪贴板
//   clipclient get            读取剪贴板，stdout 输出 READ <字符数>；被阻止时 READ -1
//   clipclient roundtrip <text>  写入后读取并输出结果
// 内部创建隐藏窗口并泵消息，保证全局钩子能注入本进程。
#include <windows.h>
#include <shellapi.h>
#include <fcntl.h>
#include <io.h>
#include <stdio.h>
#include <atomic>
#include <cwctype>
#include <iostream>
#include <string>
#include <thread>

using DebugFn = void (*)(long[8]);
using ReadyFn = long (*)();

static bool QueryHookState(bool& installed, bool& ready) {
    HMODULE module = GetModuleHandleW(L"HookDll.dll");
    if (!module) module = GetModuleHandleW(L"HookDll32.dll");
    if (!module) return false;
    auto debug = reinterpret_cast<DebugFn>(GetProcAddress(module, "ClipHookDebug"));
    if (!debug) return false;
    long state[8] = {};
    debug(state);
    installed = state[1] != 0;
    auto readyFunction = reinterpret_cast<ReadyFn>(
        GetProcAddress(module, "ClipHookReadyForTest"));
    ready = readyFunction && readyFunction() == 7;
    return true;
}

static bool QueryHookInstalled(bool& installed) {
    bool ready = false;
    return QueryHookState(installed, ready);
}

static bool TouchFile(const wchar_t* path) {
    HANDLE file = CreateFileW(path, GENERIC_WRITE,
                              FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    CloseHandle(file);
    return true;
}

static std::wstring SignalPath(const wchar_t* directory, const wchar_t* name) {
    std::wstring path = directory ? directory : L"";
    if (!path.empty() && path.back() != L'\\' && path.back() != L'/')
        path.push_back(L'\\');
    path += name;
    return path;
}

static bool SignalExists(const wchar_t* directory, const wchar_t* name) {
    return GetFileAttributesW(SignalPath(directory, name).c_str()) !=
           INVALID_FILE_ATTRIBUTES;
}

static bool WriteSignal(const wchar_t* directory, const wchar_t* name) {
    HANDLE file = CreateFileW(SignalPath(directory, name).c_str(), GENERIC_WRITE,
                              FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    CloseHandle(file);
    return true;
}

static void Pump(DWORD ms) {
    DWORD start = GetTickCount();
    MSG msg;
    while (GetTickCount() - start < ms) {
        while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        Sleep(10);
    }
}

static bool SetClip(const std::wstring& text) {
    if (!OpenClipboard(nullptr)) return false;
    HGLOBAL g = GlobalAlloc(GMEM_MOVEABLE, (text.size() + 1) * sizeof(wchar_t));
    if (!g) { CloseClipboard(); return false; }
    void* data = GlobalLock(g);
    if (!data) {
        GlobalFree(g);
        CloseClipboard();
        return false;
    }
    memcpy(data, text.c_str(), (text.size() + 1) * sizeof(wchar_t));
    GlobalUnlock(g);
    if (!EmptyClipboard()) {
        GlobalFree(g);
        CloseClipboard();
        return false;
    }
    HANDLE ok = SetClipboardData(CF_UNICODETEXT, g);
    if (!ok) GlobalFree(g);   // 成功后所有权转移给系统，失败时仍由调用方释放
    CloseClipboard();
    return ok != nullptr;
}

static std::wstring ProbeText(const wchar_t* fallback) {
    // The Sandbox CSV probe needs commas, quotes, newlines and Unicode in one
    // clipboard payload; an environment value avoids command-line escaping.
    wchar_t buffer[4096] = {};
    DWORD length = GetEnvironmentVariableW(L"CLIPCLIENT_TEST_TEXT", buffer,
                                           (DWORD)_countof(buffer));
    if (length != 0 && length < _countof(buffer)) return std::wstring(buffer, length);
    return fallback ? fallback : L"SandboxProbe";
}

// 返回读取到的字符数；-1 表示读取失败（可能被阻止）
static long GetClip(DWORD* apiError = nullptr) {
    if (!OpenClipboard(nullptr)) {
        if (apiError) *apiError = GetLastError();
        return -1;
    }
    SetLastError(ERROR_SUCCESS);
    HANDLE h = GetClipboardData(CF_UNICODETEXT);
    DWORD getError = GetLastError();
    long len = -1;
    if (h) {
        const wchar_t* p = (const wchar_t*)GlobalLock(h);
        if (p) {
            SIZE_T chars = GlobalSize(h) / sizeof(wchar_t);
            len = 0;
            while ((SIZE_T)len < chars && p[len]) ++len;
            GlobalUnlock(h);
        }
    }
    CloseClipboard();
    if (apiError) *apiError = getError;
    return len;
}

static bool ReadClipText(std::wstring& text, DWORD& apiError) {
    text.clear();
    apiError = ERROR_SUCCESS;
    if (!OpenClipboard(nullptr)) {
        apiError = GetLastError();
        return false;
    }
    SetLastError(ERROR_SUCCESS);
    HANDLE handle = GetClipboardData(CF_UNICODETEXT);
    if (!handle) {
        apiError = GetLastError();
        CloseClipboard();
        return false;
    }
    const wchar_t* data = static_cast<const wchar_t*>(GlobalLock(handle));
    if (!data) {
        apiError = GetLastError();
        CloseClipboard();
        return false;
    }
    const SIZE_T capacity = GlobalSize(handle) / sizeof(wchar_t);
    SIZE_T length = 0;
    while (length < capacity && data[length] != L'\0') ++length;
    try {
        text.assign(data, length);
    } catch (...) {
        apiError = ERROR_NOT_ENOUGH_MEMORY;
    }
    GlobalUnlock(handle);
    CloseClipboard();
    return apiError == ERROR_SUCCESS;
}

static int RunConsoleMode() {
    DWORD consoleMode = 0;
    if (GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &consoleMode))
        _setmode(_fileno(stdin), _O_U16TEXT);
    if (GetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), &consoleMode))
        _setmode(_fileno(stdout), _O_U16TEXT);

    wprintf(L"PID %lu\n", GetCurrentProcessId());
    wprintf(L"命令：r 读取剪贴板，w [内容] 写入剪贴板，q 退出\n> ");
    fflush(stdout);

    std::atomic<bool> finished{false};
    std::thread inputThread;
    try {
        inputThread = std::thread([&finished] {
            std::wstring line;
            while (std::getline(std::wcin, line)) {
                if (!line.empty() && line.back() == L'\r') line.pop_back();
                const size_t commandStart = line.find_first_not_of(L" \t");
                if (commandStart == std::wstring::npos) {
                    wprintf(L"> ");
                    fflush(stdout);
                    continue;
                }
                const wchar_t command =
                    static_cast<wchar_t>(towlower(line[commandStart]));
                const size_t afterCommand = commandStart + 1;
                const bool commandOnly =
                    afterCommand == line.size() ||
                    iswspace(line[afterCommand]) != 0;
                if (command == L'q' && commandOnly) {
                    finished.store(true, std::memory_order_release);
                    break;
                }
                if (_wcsicmp(line.c_str() + commandStart, L"rr") == 0) {
                    // Product smoke helper: issue two overlapping hooked API
                    // calls on a non-text format so modeless confirmation
                    // windows and the non-text selector can be verified.
                    std::thread first([] { GetClipboardData(CF_BITMAP); });
                    Sleep(150);
                    std::thread second([] { GetClipboardData(CF_BITMAP); });
                    first.join();
                    second.join();
                    wprintf(L"READ pair complete\n");
                } else if (command == L'r' && commandOnly) {
                    std::wstring text;
                    DWORD error = ERROR_SUCCESS;
                    if (ReadClipText(text, error))
                        wprintf(L"READ ok (%zu 字符)\n%ls\n", text.size(),
                                text.c_str());
                    else
                        wprintf(L"READ fail ERROR %lu\n", error);
                } else if (command == L'w' && commandOnly) {
                    const size_t contentStart =
                        line.find_first_not_of(L" \t", afterCommand);
                    const std::wstring content =
                        contentStart == std::wstring::npos
                            ? L"test"
                            : line.substr(contentStart);
                    const bool written = SetClip(content);
                    wprintf(L"WRITE %ls (%zu 字符)\n",
                            written ? L"ok" : L"fail", content.size());
                } else {
                    wprintf(L"未知命令。请输入 r、w [内容] 或 q。\n");
                }
                wprintf(L"> ");
                fflush(stdout);
            }
            finished.store(true, std::memory_order_release);
        });
    } catch (...) {
        fwprintf(stderr, L"无法启动控制台输入线程\n");
        return 5;
    }

    while (!finished.load(std::memory_order_acquire)) Pump(50);
    inputThread.join();
    return 0;
}

int wmain(int argc, wchar_t** argv) {
    std::wstring cmd = argc < 2 ? L"console" : argv[1];

    if (cmd == L"nopump" && argc >= 3) {
        wchar_t* end = nullptr;
        const unsigned long duration = wcstoul(argv[2], &end, 10);
        if (end == argv[2] || *end != L'\0') return 3;
        wprintf(L"PID %lu\n", GetCurrentProcessId());
        fflush(stdout);
        bool installed = false;
        bool ready = false;
        bool inspected = false;
        bool readySeen = false;
        const ULONGLONG deadline = GetTickCount64() + duration;
        do {
            inspected = QueryHookState(installed, ready);
            if (inspected && installed && ready) {
                if (argc >= 4) TouchFile(argv[3]);
                readySeen = true;
            }
            Sleep(50);
        } while (GetTickCount64() < deadline);
        wprintf(L"NO_PUMP inspected=%d installed=%d ready=%d\n",
                inspected ? 1 : 0, installed ? 1 : 0,
                ready ? 1 : 0);
        return readySeen ? 0 : 4;
    }

    // 隐藏消息窗口 + 泵消息，让全局钩子注入本进程
    WNDCLASSW wc = {sizeof(wc)};
    wc.lpfnWndProc = DefWindowProcW;
    wc.lpszClassName = L"ClipClientTestWnd";
    RegisterClassW(&wc);
    HWND w = CreateWindowExW(0, wc.lpszClassName, L"", 0, 0, 0, 0, 0,
                             HWND_MESSAGE, nullptr, nullptr, nullptr);
    (void)w;
    if (cmd == L"console" || cmd == L"interactive")
        return RunConsoleMode();
    if (cmd == L"wait" && argc >= 3) {
        wchar_t* end = nullptr;
        unsigned long duration = wcstoul(argv[2], &end, 10);
        if (end == argv[2] || *end != L'\0') return 3;
        wprintf(L"PID %lu\n", GetCurrentProcessId());
        fflush(stdout);
        if (argc < 4) {
            Pump(duration);
            return 0;
        }

        // With signal-dir, SandboxProbe validates block -> pause allow ->
        // resume block -> app-exit fail-open. Without it, retain the simpler
        // allow/detach probe for manual isolated use.
        const wchar_t* signalDir = argc >= 5 ? argv[4] : nullptr;
        const bool stagedProbe = signalDir != nullptr;
        const ULONGLONG deadline = GetTickCount64() + duration;
        bool installedSeen = false;
        bool initialAttempted = false;
        bool initialProbe = false;
        bool pauseAttempted = false;
        bool pauseProbe = false;
        bool resumeAttempted = false;
        bool resumeProbe = false;
        bool detachedSeen = false;
        bool postExitProbe = false;
        bool uiProbeAttempted[8] = {};
        while (GetTickCount64() < deadline) {
            bool installed = false;
            if (QueryHookInstalled(installed)) {
                if (installed) installedSeen = true;
                if (installedSeen && !installed) detachedSeen = true;
            } else if (installedSeen) {
                // A clean unload can remove the module between two polling
                // iterations, so the exported debug function is no longer
                // callable. Module absence after a confirmed install is the
                // strongest possible detach signal.
                detachedSeen = true;
            }

            if (installedSeen && !initialAttempted) {
                initialAttempted = true;
                // Detours can be installed a few message-pump turns before the
                // complete rules/pause/settings snapshot is applied. Give the
                // local pipe worker time to publish g_connected before probing.
                Pump(500);
                bool setOk = SetClip(ProbeText(argv[3]));
                Pump(300);
                DWORD error = ERROR_SUCCESS;
                long len = GetClip(&error);
                initialProbe = stagedProbe
                    ? setOk && len < 0 && error == ERROR_ACCESS_DENIED
                    : setOk && len >= 0;
                wprintf(stagedProbe
                            ? L"BLOCKED SET %s READ %ld ERROR %lu\n"
                            : L"HOOKED SET %s READ %ld ERROR %lu\n",
                        setOk ? L"ok" : L"fail", len, error);
                fflush(stdout);
                if (stagedProbe && initialProbe)
                    (void)WriteSignal(signalDir, L"block.done");
            }

            if (stagedProbe && initialProbe && !pauseAttempted &&
                SignalExists(signalDir, L"pause.request")) {
                pauseAttempted = true;
                Pump(500);
                DWORD error = ERROR_SUCCESS;
                long len = GetClip(&error);
                pauseProbe = len >= 0;
                wprintf(L"PAUSED READ %ld ERROR %lu\n", len, error);
                fflush(stdout);
                (void)WriteSignal(signalDir, L"pause.done");
            }

            if (stagedProbe && pauseAttempted && !resumeAttempted &&
                SignalExists(signalDir, L"resume.request")) {
                resumeAttempted = true;
                Pump(500);
                DWORD error = ERROR_SUCCESS;
                long len = GetClip(&error);
                resumeProbe = len < 0 && error == ERROR_ACCESS_DENIED;
                wprintf(L"RESUMED READ %ld ERROR %lu\n", len, error);
                fflush(stdout);
                (void)WriteSignal(signalDir, L"resume.done");
            }

            // Optional Sandbox UI probes let the controller trigger another
            // read after changing rules, pause state, or notification policy.
            // They do not affect the lifecycle probe's pass/fail contract.
            if (stagedProbe) {
                for (int i = 0; i < 8; ++i) {
                    wchar_t requestName[32] = {};
                    wchar_t doneName[32] = {};
                    swprintf_s(requestName, L"ui-%d.request", i + 1);
                    swprintf_s(doneName, L"ui-%d.done", i + 1);
                    if (uiProbeAttempted[i] ||
                        !SignalExists(signalDir, requestName))
                        continue;
                    uiProbeAttempted[i] = true;
                    Pump(300);
                    DWORD error = ERROR_SUCCESS;
                    long len = GetClip(&error);
                    wprintf(L"UI%d READ %ld ERROR %lu\n", i + 1, len,
                            error);
                    fflush(stdout);
                    (void)WriteSignal(signalDir, doneName);
                }
            }

            bool appExited = !stagedProbe ||
                SignalExists(signalDir, L"app-exited.signal");
            if (detachedSeen && appExited && !postExitProbe) {
                bool setOk = SetClip(ProbeText(argv[3]));
                Pump(300);
                long len = GetClip();
                postExitProbe = setOk && len >= 0;
                wprintf(L"POST_EXIT SET %s READ %ld\n",
                        setOk ? L"ok" : L"fail", len);
                fflush(stdout);
                break;
            }
            Pump(50);
        }
        if (stagedProbe) {
            wprintf(L"SANDBOX installed=%d blocked=%d paused=%d resumed=%d "
                    L"detached=%d post-exit=%d\n",
                    installedSeen ? 1 : 0, initialProbe ? 1 : 0,
                    pauseProbe ? 1 : 0, resumeProbe ? 1 : 0,
                    detachedSeen ? 1 : 0, postExitProbe ? 1 : 0);
            return installedSeen && initialProbe && pauseProbe && resumeProbe &&
                           detachedSeen && postExitProbe
                       ? 0
                       : 4;
        }
        wprintf(L"SANDBOX installed=%d hooked=%d detached=%d post-exit=%d\n",
                installedSeen ? 1 : 0, initialProbe ? 1 : 0,
                detachedSeen ? 1 : 0, postExitProbe ? 1 : 0);
        return installedSeen && initialProbe && detachedSeen && postExitProbe ? 0 : 4;
    }

    Pump(600);   // 等待 Hook.dll 注入并完成挂钩

    if (cmd == L"set" && argc >= 3) {
        Pump(200);
        bool ok = SetClip(argv[2]);
        Pump(300);   // 给上报留时间
        wprintf(L"SET %s\n", ok ? L"ok" : L"fail");
        return ok ? 0 : 1;
    }
    if (cmd == L"get") {
        Pump(200);
        long len = GetClip();
        Pump(300);
        wprintf(L"READ %ld\n", len);
        return len >= 0 ? 0 : 2;
    }
    if (cmd == L"roundtrip" && argc >= 3) {
        Pump(200);
        SetClip(argv[2]);
        Pump(500);
        long len = GetClip();
        Pump(300);
        wprintf(L"READ %ld\n", len);
        return 0;
    }
    fwprintf(stderr,
             L"usage: clipclient [console]|nopump <ms> [ready-file]|"
             L"wait <ms> [text [signal-dir]]|"
             L"set|get|roundtrip [text]\n");
    return 3;
}
