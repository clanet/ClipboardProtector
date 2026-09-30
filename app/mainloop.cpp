#include "i18n.h"
#include <objbase.h>
#include "mainloop.h"
#include "app.h"
#include "tray.h"
#include "mainwnd.h"
#include "pipeserver.h"
#include "injector.h"
#include "coveragemonitor.h"
#include "ipc.h"
#include "rules.h"
#include "winutil.h"
#include <shellapi.h>
#include <aclapi.h>
#include <atomic>
#include <vector>
#include <cwchar>

namespace clip {

namespace {
Tray g_tray;
MainWindow g_wnd;
PipeServer g_server;
Injector g_injector;
CoverageMonitor g_coverage;
bool g_comInit = false;
std::atomic<bool> g_globalInjectionEnabled{false};
std::atomic<bool> g_targetedInjectionMode{false};
std::atomic<DWORD> g_targetedInjectionPid{0};
bool g_pipeServerRunning = false;

// 单实例互斥体：第二个进程启动时聚焦已有窗口后退出
HANDLE g_singleMutex = nullptr;

bool QueryTargetPath(DWORD pid, std::wstring& path) {
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
                                 FALSE, pid);
    if (!process) return false;
    const bool ok = WaitForSingleObject(process, 0) == WAIT_TIMEOUT &&
                    ProcessImagePath(process, path);
    CloseHandle(process);
    return ok;
}

void ReadTargetEnvironment(bool& specified, bool& invalid, DWORD& processId) {
    specified = false;
    invalid = false;
    processId = 0;
    wchar_t targetValue[32] = {};
    SetLastError(ERROR_SUCCESS);
    const DWORD targetLength = GetEnvironmentVariableW(
        L"CLIPBOARDPROTECTOR_TEST_TARGET_PID", targetValue,
        _countof(targetValue));
    const DWORD targetError = GetLastError();
    if (targetLength > 0 && targetLength < _countof(targetValue)) {
        specified = true;
        wchar_t* end = nullptr;
        const unsigned long long parsed = _wcstoui64(targetValue, &end, 10);
        if (end != targetValue && *end == L'\0' && parsed != 0 &&
            parsed <= MAXDWORD) {
            processId = static_cast<DWORD>(parsed);
        } else {
            invalid = true;
        }
    } else if (targetLength != 0 || targetError != ERROR_ENVVAR_NOT_FOUND) {
        // An invalid/empty test variable still selects fail-closed targeted
        // mode, so startup can never fall back to a global hook.
        specified = true;
        invalid = true;
    }
}

bool InjectionPath(std::wstring& hookDll, std::wstring& error) {
    std::wstring directory;
    if (!ModuleDirectory(nullptr, directory)) {
        error = UiText(TextId::CouldNotLocateTheApplicationDirectory);
        return false;
    }
    hookDll = directory + L"HookDll.dll";
    return true;
}

bool AllowCurrentUserProcessQuery() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        return false;
    DWORD bytes = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &bytes);
    if (bytes == 0 || GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        CloseHandle(token);
        return false;
    }
    std::vector<BYTE> buffer(bytes);
    if (!GetTokenInformation(token, TokenUser, buffer.data(), bytes, &bytes)) {
        CloseHandle(token);
        return false;
    }
    CloseHandle(token);
    auto* user = reinterpret_cast<TOKEN_USER*>(buffer.data());

    PSECURITY_DESCRIPTOR descriptor = nullptr;
    PACL oldDacl = nullptr;
    DWORD result = GetSecurityInfo(
        GetCurrentProcess(), SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION,
        nullptr, nullptr, &oldDacl, nullptr, &descriptor);
    if (result != ERROR_SUCCESS) return false;

    EXPLICIT_ACCESSW access = {};
    access.grfAccessPermissions = PROCESS_QUERY_LIMITED_INFORMATION;
    access.grfAccessMode = GRANT_ACCESS;
    access.grfInheritance = NO_INHERITANCE;
    access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    access.Trustee.TrusteeType = TRUSTEE_IS_USER;
    access.Trustee.ptstrName = static_cast<LPWSTR>(user->User.Sid);

    PACL newDacl = nullptr;
    result = SetEntriesInAclW(1, &access, oldDacl, &newDacl);
    if (result == ERROR_SUCCESS) {
        result = SetSecurityInfo(
            GetCurrentProcess(), SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION,
            nullptr, nullptr, newDacl, nullptr);
    }
    if (newDacl) LocalFree(newDacl);
    LocalFree(descriptor);
    return result == ERROR_SUCCESS;
}

struct HookRemovalResult {
    bool removed = false;
    bool serverRestarted = false;
    bool coverageRestarted = true;
};

HookRemovalResult RemoveHooksAndRestartServer(bool restrictOnFailure,
                                              DWORD targetPid = 0) {
    const bool coverageWasRunning = g_coverage.running();
    if (coverageWasRunning) g_coverage.Pause();
    g_server.Stop();
    g_pipeServerRunning = false;
    HookRemovalResult result;
    result.removed = g_injector.Remove();
    if (result.removed) {
        g_coverage.ReleaseRetainedReferences();
        g_coverage.Clear();
    }
    const bool restricted = restrictOnFailure && !result.removed;
    result.serverRestarted =
        g_server.Start(g_wnd.hwnd(), restricted,
                       restricted ? targetPid : 0);
    g_pipeServerRunning = result.serverRestarted;
    if (!result.removed && coverageWasRunning && result.serverRestarted)
        result.coverageRestarted = g_coverage.Resume();
    return result;
}

void CleanupCreateFailure() {
    // Startup can fail after any of these objects has been initialized. Tear
    // them down in the same dependency order used by normal exit so no worker
    // can post into a destroyed window or execute an unloaded hook DLL.
    if (g_app.server) {
        g_coverage.Pause();
        g_server.Stop();
        g_pipeServerRunning = false;
    }
    if (g_app.injector) {
        g_injector.Remove();
        g_coverage.ReleaseRetainedReferences();
        g_coverage.Clear();
    }
    g_tray.Remove();
    if (g_wnd.hwnd()) DestroyWindow(g_wnd.hwnd());
    if (g_comInit) {
        CoUninitialize();
        g_comInit = false;
    }
    if (g_singleMutex) {
        ReleaseMutex(g_singleMutex);
        CloseHandle(g_singleMutex);
        g_singleMutex = nullptr;
    }
}
} // namespace

static bool EnsureSingleInstance() {
    const std::wstring mutexName = ResolveObjectName(
        L"CLIP_TEST_CONTROLLER_MUTEX", kSingleInstanceMutexName);
    g_singleMutex = CreateLocalUserNamedMutex(mutexName.c_str(), TRUE);

    if (!g_singleMutex) return false;
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        // 上一实例异常退出后，注入 DLL 可能还短暂持有对象句柄；无所有者时
        // 当前线程可以接管该互斥体，不应把仅“对象仍存在”误判成实例仍存活。
        DWORD acquired = WaitForSingleObject(g_singleMutex, 0);
        if (acquired == WAIT_OBJECT_0 || acquired == WAIT_ABANDONED) return true;
        // 找到已运行实例的主窗口并前置
        HWND exist = FindWindowW(L"ClipProtectorMainWnd", nullptr);
        if (exist) {
            ShowWindow(exist, SW_RESTORE);
            SetForegroundWindow(exist);
        }
        CloseHandle(g_singleMutex);
        g_singleMutex = nullptr;
        return false;
    }
    return true;
}

bool IsGlobalInjectionEnabled() { return g_globalInjectionEnabled; }

bool IsTargetedInjectionMode() { return g_targetedInjectionMode; }

DWORD TargetedInjectionPid() { return g_targetedInjectionPid; }
bool TargetMonitorReady(DWORD processId) {
    const ULONGLONG readyDeadline = GetTickCount64() + 8000;
    ULONGLONG stateDeliveredSince = 0;
    bool compatibleReady = false;
    const bool legacyRulesCompatible =
        IsLegacyRuleSetCompatible(g_app.cfg.rules) &&
        !g_app.cfg.settings.shortcutOnlyMode &&
        !g_app.cfg.settings.cryptoProtection;
    while (!g_server.IsTargetReady(processId) && !compatibleReady &&
           GetTickCount64() < readyDeadline) {
        if (g_server.IsTargetStateDelivered(processId)) {
            if (stateDeliveredSince == 0)
                stateDeliveredSince = GetTickCount64();
            compatibleReady = legacyRulesCompatible &&
                GetTickCount64() - stateDeliveredSince >= 500;
        } else {
            stateDeliveredSince = 0;
        }
        Sleep(20);
    }
    return g_server.IsTargetReady(processId) || compatibleReady;
}

std::wstring TargetMonitorFailureText(DWORD processId) {
    const bool legacyRulesCompatible =
        IsLegacyRuleSetCompatible(g_app.cfg.rules) &&
        !g_app.cfg.settings.shortcutOnlyMode &&
        !g_app.cfg.settings.cryptoProtection;
    std::wstring currentPath;
    if (!QueryTargetPath(processId, currentPath))
        return UiText(TextId::TheTargetProcessExitedBeforeMonitoringFinished);
    if (!g_server.IsTargetConnected(processId)) {
        return UiText(TextId::TheHookWasInstalledButTheTarget);
    }
    if (!legacyRulesCompatible &&
        g_server.IsTargetStateDelivered(processId)) {
        return UiText(TextId::AnOlderHookDLLConnectedButIt);
    }
    return UiText(TextId::TheTargetConnectedWithoutConfirmingTheCurrent);
}


bool StartSingleProcessTest(DWORD processId, std::wstring& error) {
    error.clear();
    if (processId == 0 || processId == GetCurrentProcessId()) {
        error = UiText(TextId::TheTargetPIDIsInvalidOrRefers2);
        return false;
    }
    if (g_globalInjectionEnabled) {
        error = UiText(TextId::TurnOffGlobalInjectionBeforeStartingSingle);
        return false;
    }
    if (g_targetedInjectionMode) {
        error = UiText(TextId::SingleProcessProtectionIsAlreadyRunningStop);
        return false;
    }

    std::wstring hookDll;
    std::wstring targetPath;
    if (!InjectionPath(hookDll, error)) return false;
    if (!QueryTargetPath(processId, targetPath)) {
        error = UiText(TextId::TheTargetPIDDoesNotExistHas);
        return false;
    }

    g_server.Stop();
    g_pipeServerRunning = false;
    if (!g_server.Start(g_wnd.hwnd(), true, processId)) {
        const bool restored = g_server.Start(g_wnd.hwnd());
        g_pipeServerRunning = restored;
        error = UiText(TextId::CouldNotStartTheNamedPipeService);
        if (!restored) error += UiText(TextId::TheOriginalNamedPipeServiceCouldNot);
        return false;
    }
    g_pipeServerRunning = true;

    const bool installed =
        g_injector.InstallForProcess(hookDll, processId, targetPath);
    if (installed) {
        if (TargetMonitorReady(processId)) {
            g_targetedInjectionMode = true;
            g_targetedInjectionPid = processId;
            return true;
        }
        error = TargetMonitorFailureText(processId);
    } else {
        error = UiText(TextId::SingleProcessInjectionFailed) + g_injector.lastErrorText() +
                L" (Win32 " + std::to_wstring(g_injector.lastError()) + L")";
    }
    const HookRemovalResult cleanup =
        RemoveHooksAndRestartServer(true, processId);
    const bool keepRestricted = !cleanup.removed;
    g_targetedInjectionMode = keepRestricted;
    g_targetedInjectionPid = keepRestricted ? processId : 0;
    if (!cleanup.removed)
        error += UiText(TextId::HookRollbackFailedThePipeRemainsRestricted);
    if (!cleanup.serverRestarted) error += UiText(TextId::TheNamedPipeServiceCouldNotBe);
    return false;
}

bool StartPreparedSingleProcessTest(DWORD processId, std::wstring& error) {
    error.clear();
    if (processId == 0 || processId == GetCurrentProcessId()) {
        error = UiText(TextId::TheTargetPIDIsInvalidOrRefers2);
        return false;
    }

    std::wstring hookDll;
    if (!InjectionPath(hookDll, error)) return false;
    const bool installed = g_injector.InstallForProcess(hookDll, processId);
    if (installed && TargetMonitorReady(processId)) return true;
    if (!installed) {
        error = UiText(TextId::SingleProcessInjectionFailed) + g_injector.lastErrorText() +
                L" (Win32 " + std::to_wstring(g_injector.lastError()) + L")";
        // The environment-selected server remains restricted to this PID.
        // The user can explicitly stop the failed target mode from the menu.
        return false;
    }

    error = TargetMonitorFailureText(processId);
    const HookRemovalResult cleanup =
        RemoveHooksAndRestartServer(true, processId);
    const bool keepRestricted = !cleanup.removed;
    g_targetedInjectionMode = keepRestricted;
    g_targetedInjectionPid = keepRestricted ? processId : 0;
    if (!cleanup.removed)
        error += UiText(TextId::HookRollbackFailedThePipeRemainsRestricted2);
    if (!cleanup.serverRestarted)
        error += UiText(TextId::TheNamedPipeServiceCouldNotBe);
    return false;
}

bool StopSingleProcessTest(std::wstring& error) {
    error.clear();
    if (!g_targetedInjectionMode) return true;

    const DWORD previousPid = g_targetedInjectionPid;
    const HookRemovalResult cleanup =
        RemoveHooksAndRestartServer(true, previousPid);
    const bool keepRestricted = !cleanup.removed;
    g_targetedInjectionMode = keepRestricted;
    g_targetedInjectionPid = keepRestricted ? previousPid : 0;
    if (!cleanup.removed)
        error = UiText(TextId::TheSingleProcessHookCouldNotBe);
    if (!cleanup.serverRestarted) {
        if (!error.empty()) error += L"\n";
        error += UiText(TextId::TheNamedPipeServiceCouldNotBe2);
    }
    return cleanup.removed && cleanup.serverRestarted;
}

bool SetGlobalInjectionEnabled(bool enabled, std::wstring& error) {
    error.clear();
    if (g_targetedInjectionMode) {
        error = UiText(TextId::GlobalInjectionCannotBeChangedWhileSingle);
        return false;
    }
    if (enabled == g_globalInjectionEnabled) return true;

    std::wstring baseDir;
    if (!ModuleDirectory(nullptr, baseDir)) {
        error = UiText(TextId::CouldNotLocateTheApplicationDirectory);
        return false;
    }

    if (enabled) {
        if (!g_pipeServerRunning) {
            g_pipeServerRunning = g_server.Start(g_wnd.hwnd());
            if (!g_pipeServerRunning) {
                error = UiText(TextId::GlobalInjectionRequiresTheNamedPipeService);
                return false;
            }
        }
        const bool nativeInstalled =
            g_injector.Install(baseDir + L"HookDll.dll");
#ifdef _WIN64
        const bool helperInstalled = g_injector.Install32BitHelper(
            baseDir + L"HookHost32.exe", baseDir + L"HookDll32.dll");
#else
        const bool helperInstalled = true;
#endif
        bool coverageStarted = false;
        if (nativeInstalled && helperInstalled) {
#ifdef _WIN64
            coverageStarted = g_coverage.Start(
                g_server, baseDir + L"HookDll.dll",
                baseDir + L"HookHost32.exe", baseDir + L"HookDll32.dll");
#else
            coverageStarted =
                g_coverage.Start(g_server, baseDir + L"HookDll.dll");
#endif
        }
        if (nativeInstalled && helperInstalled && coverageStarted) {
            g_globalInjectionEnabled = true;
            return true;
        }

        if (!nativeInstalled) {
            error = UiText(TextId::HookInstallationFailedForThisArchitecture) + g_injector.lastErrorText() +
                    L" (Win32 " + std::to_wstring(g_injector.lastError()) + L")";
        }
#ifdef _WIN64
        if (!helperInstalled) {
            if (!error.empty()) error += L"\n";
            error += UiText(TextId::CouldNotStartThe32BitHookHost);
        }
#endif
        if (nativeInstalled && helperInstalled && !coverageStarted) {
            if (!error.empty()) error += L"\n";
            error += UiText(TextId::CouldNotStartTheProcessCoverageMonitor);
        }

        // A partially installed global hook may already have loaded the DLL
        // into a process. Shut clients down before unhooking, then reopen the
        // server so a later menu retry starts from a clean state.
        const HookRemovalResult cleanup =
            RemoveHooksAndRestartServer(false);
        g_globalInjectionEnabled = !cleanup.removed;
        if (!cleanup.removed)
            error += UiText(TextId::SomeHooksCouldNotBeRolledBack);
        if (!cleanup.serverRestarted)
            error += UiText(TextId::TheNamedPipeServiceCouldNotBe);
        if (!cleanup.coverageRestarted)
            error += UiText(TextId::TheProcessCoverageMonitorCouldNotBe);
        return false;
    }

    const HookRemovalResult cleanup = RemoveHooksAndRestartServer(false);
    g_globalInjectionEnabled = !cleanup.removed;
    if (!cleanup.removed)
        error = UiText(TextId::SomeGlobalHooksCouldNotBeUnloaded);
    if (!cleanup.serverRestarted) {
        if (!error.empty()) error += L"\n";
        error += UiText(TextId::TheNamedPipeServiceCouldNotBe2);
    }
    if (!cleanup.coverageRestarted) {
        if (!error.empty()) error += L"\n";
        error += UiText(TextId::TheProcessCoverageMonitorCouldNotBe2);
    }
    return cleanup.removed && cleanup.serverRestarted;
}

bool CreateMainWindow() {
    // 工具栏/列表视图/状态栏依赖的公共控件类必须显式注册
    INITCOMMONCONTROLSEX icc = {sizeof(icc),
                                ICC_BAR_CLASSES | ICC_LISTVIEW_CLASSES | ICC_HOTKEY_CLASS |
                                    ICC_STANDARD_CLASSES};
    InitCommonControlsEx(&icc);
    if (!EnsureSingleInstance()) return false;
    if (!AllowCurrentUserProcessQuery()) {
        UiMessageBox(nullptr,
                    UiText(TextId::CouldNotAllowTheCurrentUserTo),
                    UiText(TextId::ClipboardProtector), MB_ICONERROR);
        ReleaseMutex(g_singleMutex);
        CloseHandle(g_singleMutex);
        g_singleMutex = nullptr;
        return false;
    }
    if (FAILED(CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED |
                                            COINIT_DISABLE_OLE1DDE)))
    {
        ReleaseMutex(g_singleMutex);
        CloseHandle(g_singleMutex);
        g_singleMutex = nullptr;
        return false;
    }
    g_comInit = true;
    g_app.tray = &g_tray;
    g_app.wnd = &g_wnd;
    g_app.server = &g_server;
    g_app.injector = &g_injector;
    if (!g_wnd.Create(g_app.hInst)) {
        CleanupCreateFailure();
        return false;
    }
    g_wnd.StartAutostartQuery();
    if (!g_tray.Init(g_wnd.hwnd())) {
        UiMessageBox(nullptr, UiText(TextId::CouldNotCreateTheTrayIcon), UiText(TextId::ClipboardProtector), MB_ICONERROR);
        CleanupCreateFailure();
        return false;
    }
    DWORD targetPid = 0;
    bool targetSpecified = false;
    bool targetInvalid = false;
    ReadTargetEnvironment(targetSpecified, targetInvalid, targetPid);
    const bool singleTarget =
        targetSpecified && !targetInvalid && targetPid != 0;
    g_targetedInjectionMode = targetSpecified;
    g_targetedInjectionPid = singleTarget ? targetPid : 0;
    g_globalInjectionEnabled = false;

    // The server restriction is selected before any hook is installed. An
    // invalid environment target starts a reject-all server (PID 0).
    if (!g_server.Start(g_wnd.hwnd(), targetSpecified,
                        singleTarget ? targetPid : 0)) {
        CleanupCreateFailure();
        return false;
    }
    g_pipeServerRunning = true;
    wchar_t globalValue[8] = {};
    DWORD globalLength = GetEnvironmentVariableW(
        L"CLIPBOARDPROTECTOR_ENABLE_GLOBAL_HOOK", globalValue,
        _countof(globalValue));
    const bool globalOptIn = globalLength == 1 && globalValue[0] == L'1';
    if (targetInvalid) {
        UiMessageBox(nullptr, UiText(TextId::TheTestTargetPIDIsInvalidAll),
                    UiText(TextId::ClipboardProtector), MB_ICONWARNING);
    } else if (singleTarget) {
        g_wnd.StartInitialSingleProcessTest(targetPid);
    }
    const bool enableGlobalAtStartup =
        g_app.cfg.settings.startGlobalProtection || globalOptIn;
    if (!targetSpecified && enableGlobalAtStartup) {
        g_wnd.StartInitialGlobalInjection();
    }
    g_wnd.SyncProtectionState();
    return true;
}

void RunMessageLoop() {
    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        if (g_wnd.TranslateConfirmationMessage(msg)) continue;
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
}

void RequestExit() {
    g_wnd.BeginExit();
}

void StopProtectionForExit() {
    // 先让 DLL 收到 fail-open/shutdown，再移除系统 Hook 和销毁窗口。
    g_coverage.Pause();
    if (g_app.server) {
        g_app.server->Stop();
        g_pipeServerRunning = false;
    }
    if (g_app.injector) {
        g_app.injector->Remove();
        g_coverage.ReleaseRetainedReferences();
        g_coverage.Clear();
    }
}

} // namespace clip

int APIENTRY wWinMain(HINSTANCE hInst, HINSTANCE, LPWSTR, int) {
    using namespace clip;
    g_app.hInst = hInst;
    SetLanguage(SystemLanguage());
    std::wstring configDir;
#ifdef CLIP_TEST_OBJECT_NAMES
    wchar_t testConfigDir[32768] = {};
    const DWORD testConfigLength = GetEnvironmentVariableW(
        L"CLIP_TEST_CONFIG_DIR", testConfigDir, _countof(testConfigDir));
    if (testConfigLength > 0 && testConfigLength < _countof(testConfigDir))
        configDir.assign(testConfigDir, testConfigLength);
#endif
    if (configDir.empty()) configDir = DefaultConfigDir();
    if (configDir.empty()) {
        UiMessageBox(nullptr, UiText(TextId::CouldNotLocateTheConfigurationDirectoryThe),
                    UiText(TextId::ClipboardProtector), MB_ICONERROR);
        return 1;
    }
    if (!CreateDirectoryW(configDir.c_str(), nullptr) &&
        GetLastError() != ERROR_ALREADY_EXISTS) {
        UiMessageBox(nullptr, UiText(TextId::CouldNotCreateTheConfigurationDirectoryThe),
                    UiText(TextId::ClipboardProtector), MB_ICONERROR);
        return 1;
    }
    DWORD configDirAttributes = GetFileAttributesW(configDir.c_str());
    if (configDirAttributes == INVALID_FILE_ATTRIBUTES ||
        !(configDirAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
        UiMessageBox(nullptr, UiText(TextId::TheConfigurationPathIsUnavailableTheApplication),
                    UiText(TextId::ClipboardProtector), MB_ICONERROR);
        return 1;
    }
    g_app.cfgPath = configDir + L"\\config.json";
    if (GetFileAttributesW(g_app.cfgPath.c_str()) == INVALID_FILE_ATTRIBUTES &&
        GetLastError() == ERROR_FILE_NOT_FOUND)
        g_app.cfg.settings.language = SystemLanguage();
    g_app.cfg.Load(g_app.cfgPath);
    SetLanguage(g_app.cfg.settings.language);
    if (!CreateMainWindow()) return 1;
    RunMessageLoop();

    if (g_app.server) {
        g_app.server->Stop();   // 兜底：异常退出路径也停线程
        g_pipeServerRunning = false;
    }
    if (g_app.injector) g_app.injector->Remove();
    if (g_app.wnd) g_app.wnd->JoinAutostartQuery();
    g_app.tray->Remove();
    if (g_comInit) CoUninitialize();
    if (g_singleMutex) { ReleaseMutex(g_singleMutex); CloseHandle(g_singleMutex); }
    return 0;
}
