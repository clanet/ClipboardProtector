[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$InputDir,
    [Parameter(Mandatory = $true)]
    [string]$ResultDir,
    [ValidateSet("Lifecycle", "Ui", "Uia")]
    [string]$Scenario = "Lifecycle",
    [ValidateRange(20, 300)]
    [int]$ClientDurationSeconds = 30,
    [ValidateRange(5, 120)]
    [int]$ObservationDelaySeconds = 6,
    # Reuse keeps this harness-created guest alive and enables the mapped
    # result directory command queue. SingleRun is used by that queue's child
    # workers and must never request a guest shutdown.
    [switch]$ReuseSession,
    [switch]$SingleRun,
    [string]$ReuseRoot,
    [string]$RunNonce
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ([Environment]::UserName -ne "WDAGUtilityAccount") {
    throw "sandbox-entry.ps1 may run only inside Windows Sandbox."
}
if ($ObservationDelaySeconds -ge ($ClientDurationSeconds - 3)) {
    throw "The observation delay leaves no time for post-exit validation."
}
if ([string]::IsNullOrWhiteSpace($RunNonce)) {
    $RunNonce = [Guid]::NewGuid().ToString("N")
}

$nativeTypeDefinition = @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

public static class ClipboardProtectorSandboxNative
{
    private delegate bool EnumWindowsProc(IntPtr window, IntPtr parameter);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr FindWindow(string className, string windowName);

    [DllImport("user32.dll", SetLastError = true)]
    public static extern uint GetWindowThreadProcessId(IntPtr window, out uint processId);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool PostThreadMessage(uint threadId, uint message, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool PostMessage(IntPtr window, uint message, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll", SetLastError = true)]
    public static extern IntPtr GetDlgItem(IntPtr parent, int id);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool SetDlgItemText(IntPtr parent, int id, string text);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool SetWindowText(IntPtr window, string text);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr SendMessageTimeout(
        IntPtr window, uint message, IntPtr wParam, IntPtr lParam,
        uint flags, uint timeoutMilliseconds, out IntPtr result);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true,
        EntryPoint = "SendMessageTimeoutW")]
    private static extern IntPtr SendMessageTimeoutString(
        IntPtr window, uint message, IntPtr wParam, string lParam,
        uint flags, uint timeoutMilliseconds, out IntPtr result);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true,
        EntryPoint = "SendMessageTimeoutW")]
    private static extern IntPtr SendMessageTimeoutBuffer(
        IntPtr window, uint message, IntPtr wParam, StringBuilder lParam,
        uint flags, uint timeoutMilliseconds, out IntPtr result);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EnumWindows(EnumWindowsProc callback, IntPtr parameter);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EnumThreadWindows(uint threadId, EnumWindowsProc callback, IntPtr parameter);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int GetClassName(IntPtr window, StringBuilder className, int capacity);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int GetWindowText(IntPtr window, StringBuilder text, int capacity);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool IsWindowVisible(IntPtr window);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool IsWindow(IntPtr window);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EnumChildWindows(IntPtr parent, EnumWindowsProc callback, IntPtr parameter);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern int GetDlgCtrlID(IntPtr window);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetDlgItemText(
        IntPtr dialog, int controlId, StringBuilder text, int capacity);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr GetThreadDesktop(uint threadId);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetUserObjectInformation(
        IntPtr handle, int index, StringBuilder information,
        uint length, out uint needed);

    private static string DescribeWindow(IntPtr window)
    {
        uint processId;
        uint threadId = GetWindowThreadProcessId(window, out processId);
        StringBuilder className = new StringBuilder(256);
        StringBuilder title = new StringBuilder(512);
        GetClassName(window, className, className.Capacity);
        GetWindowText(window, title, title.Capacity);
        return String.Format("hwnd=0x{0:X} pid={1} tid={2} visible={3} class={4} title={5}",
            window.ToInt64(), processId, threadId, IsWindowVisible(window),
            className, title);
    }

    public static string WindowText(IntPtr window)
    {
        StringBuilder text = new StringBuilder(32768);
        GetWindowText(window, text, text.Capacity);
        return text.ToString();
    }

    public static bool SetControlText(IntPtr window, string value)
    {
        IntPtr result;
        return SendMessageTimeoutString(window, 0x000C, IntPtr.Zero, value,
                                        0x0002, 1000, out result) != IntPtr.Zero;
    }

    public static string ControlText(IntPtr window)
    {
        StringBuilder text = new StringBuilder(32770);
        IntPtr result;
        if (SendMessageTimeoutBuffer(window, 0x000D,
                                     new IntPtr(text.Capacity), text,
                                     0x0002, 1000, out result) == IntPtr.Zero)
            return null;
        return text.ToString();
    }

    public static string[] DescribeWindowsForProcess(uint wantedProcessId)
    {
        List<string> windows = new List<string>();
        EnumWindows(delegate(IntPtr window, IntPtr parameter) {
            uint processId;
            GetWindowThreadProcessId(window, out processId);
            if (processId == wantedProcessId) windows.Add(DescribeWindow(window));
            return true;
        }, IntPtr.Zero);
        return windows.ToArray();
    }

    public static IntPtr FindWindowForProcessByClass(uint wantedProcessId, string wantedClass)
    {
        IntPtr found = IntPtr.Zero;
        EnumWindows(delegate(IntPtr window, IntPtr parameter) {
            uint processId;
            GetWindowThreadProcessId(window, out processId);
            if (processId != wantedProcessId) return true;
            StringBuilder className = new StringBuilder(256);
            GetClassName(window, className, className.Capacity);
            if (String.Equals(className.ToString(), wantedClass,
                              StringComparison.Ordinal)) {
                found = window;
                return false;
            }
            return true;
        }, IntPtr.Zero);
        return found;
    }

    public static IntPtr FindWindowForProcessByClassAndTitle(
        uint wantedProcessId, string wantedClass, string wantedTitle)
    {
        IntPtr found = IntPtr.Zero;
        EnumWindows(delegate(IntPtr window, IntPtr parameter) {
            uint processId;
            GetWindowThreadProcessId(window, out processId);
            if (processId != wantedProcessId) return true;
            StringBuilder className = new StringBuilder(256);
            StringBuilder title = new StringBuilder(512);
            GetClassName(window, className, className.Capacity);
            GetWindowText(window, title, title.Capacity);
            if (IsWindowVisible(window) &&
                String.Equals(className.ToString(), wantedClass,
                              StringComparison.Ordinal) &&
                String.Equals(title.ToString(), wantedTitle,
                              StringComparison.Ordinal)) {
                found = window;
                return false;
            }
            return true;
        }, IntPtr.Zero);
        return found;
    }

    public static IntPtr FindDialogForProcessWithControl(
        uint wantedProcessId, int wantedControlId)
    {
        IntPtr found = IntPtr.Zero;
        EnumWindows(delegate(IntPtr window, IntPtr parameter) {
            uint processId;
            GetWindowThreadProcessId(window, out processId);
            if (processId != wantedProcessId) return true;
            StringBuilder className = new StringBuilder(256);
            GetClassName(window, className, className.Capacity);
            if (String.Equals(className.ToString(), "#32770",
                              StringComparison.Ordinal) &&
                IsWindowVisible(window) &&
                GetDlgItem(window, wantedControlId) != IntPtr.Zero) {
                found = window;
                return false;
            }
            return true;
        }, IntPtr.Zero);
        return found;
    }

    public static IntPtr FindDescendantControl(
        IntPtr parent, int wantedControlId, string wantedClass)
    {
        IntPtr found = IntPtr.Zero;
        EnumChildWindows(parent, delegate(IntPtr window, IntPtr parameter) {
            if (GetDlgCtrlID(window) != wantedControlId) return true;
            StringBuilder className = new StringBuilder(256);
            GetClassName(window, className, className.Capacity);
            if (String.IsNullOrEmpty(wantedClass) ||
                String.Equals(className.ToString(), wantedClass,
                              StringComparison.Ordinal)) {
                found = window;
                return false;
            }
            return true;
        }, IntPtr.Zero);
        return found;
    }

    public static IntPtr FindVisibleDescendantByClassAndTitle(
        IntPtr parent, string wantedClass, string wantedTitle)
    {
        IntPtr found = IntPtr.Zero;
        EnumChildWindows(parent, delegate(IntPtr window, IntPtr parameter) {
            if (!IsWindowVisible(window)) return true;
            StringBuilder className = new StringBuilder(256);
            StringBuilder title = new StringBuilder(512);
            GetClassName(window, className, className.Capacity);
            GetWindowText(window, title, title.Capacity);
            if (String.Equals(className.ToString(), wantedClass,
                              StringComparison.Ordinal) &&
                String.Equals(title.ToString(), wantedTitle,
                              StringComparison.Ordinal)) {
                found = window;
                return false;
            }
            return true;
        }, IntPtr.Zero);
        return found;
    }

    private static bool HasDescendantClass(IntPtr parent, string wantedClass)
    {
        bool found = false;
        EnumChildWindows(parent, delegate(IntPtr window, IntPtr parameter) {
            StringBuilder className = new StringBuilder(256);
            GetClassName(window, className, className.Capacity);
            if (String.Equals(className.ToString(), wantedClass,
                              StringComparison.Ordinal)) {
                found = true;
                return false;
            }
            return true;
        }, IntPtr.Zero);
        return found;
    }

    public static IntPtr FindSaveDialogForProcess(uint wantedProcessId)
    {
        IntPtr found = IntPtr.Zero;
        EnumWindows(delegate(IntPtr window, IntPtr parameter) {
            uint processId;
            GetWindowThreadProcessId(window, out processId);
            if (processId != wantedProcessId) return true;
            StringBuilder className = new StringBuilder(256);
            GetClassName(window, className, className.Capacity);
            if (!String.Equals(className.ToString(), "#32770",
                               StringComparison.Ordinal) ||
                !IsWindowVisible(window) ||
                GetDlgItem(window, 1) == IntPtr.Zero) return true;
            if (FindDescendantControl(window, 1001, "Edit") != IntPtr.Zero ||
                FindDescendantControl(window, 0x47c, "Edit") != IntPtr.Zero) {
                found = window;
                return false;
            }
            return true;
        }, IntPtr.Zero);
        return found;
    }

    public static IntPtr FindMessageBoxForProcess(uint wantedProcessId)
    {
        IntPtr found = IntPtr.Zero;
        EnumWindows(delegate(IntPtr window, IntPtr parameter) {
            uint processId;
            GetWindowThreadProcessId(window, out processId);
            if (processId != wantedProcessId) return true;
            StringBuilder className = new StringBuilder(256);
            GetClassName(window, className, className.Capacity);
            if (String.Equals(className.ToString(), "#32770",
                              StringComparison.Ordinal) &&
                IsWindowVisible(window) &&
                (GetDlgItem(window, 1) != IntPtr.Zero ||
                 GetDlgItem(window, 6) != IntPtr.Zero) &&
                !HasDescendantClass(window, "Edit") &&
                !HasDescendantClass(window, "ComboBox") &&
                !HasDescendantClass(window, "SysListView32")) {
                found = window;
                return false;
            }
            return true;
        }, IntPtr.Zero);
        return found;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NotifyIconIdentifier
    {
        public uint cbSize;
        public IntPtr hWnd;
        public uint uID;
        public Guid guidItem;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Rect
    {
        public int left;
        public int top;
        public int right;
        public int bottom;
    }

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetWindowRect(IntPtr window, out Rect rectangle);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetForegroundWindow(IntPtr window);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetCursorPos(int x, int y);

    [DllImport("user32.dll")]
    private static extern void mouse_event(
        uint flags, uint x, uint y, uint data, UIntPtr extraInfo);

    [DllImport("user32.dll")]
    private static extern void keybd_event(
        byte virtualKey, byte scanCode, uint flags, UIntPtr extraInfo);

    public static bool ClickControlByInput(IntPtr dialog, IntPtr control)
    {
        Rect rectangle;
        if (dialog == IntPtr.Zero || control == IntPtr.Zero ||
            !IsWindowVisible(control) || !GetWindowRect(control, out rectangle) ||
            rectangle.right <= rectangle.left || rectangle.bottom <= rectangle.top)
            return false;
        SetForegroundWindow(dialog);
        int x = rectangle.left + (rectangle.right - rectangle.left) / 2;
        int y = rectangle.top + (rectangle.bottom - rectangle.top) / 2;
        if (!SetCursorPos(x, y)) return false;
        mouse_event(0x0002, 0, 0, 0, UIntPtr.Zero);
        mouse_event(0x0004, 0, 0, 0, UIntPtr.Zero);
        return true;
    }

    public static bool PressEnterByInput(IntPtr dialog)
    {
        if (dialog == IntPtr.Zero || !IsWindowVisible(dialog)) return false;
        SetForegroundWindow(dialog);
        keybd_event(0x0D, 0, 0, UIntPtr.Zero);
        keybd_event(0x0D, 0, 0x0002, UIntPtr.Zero);
        return true;
    }

    [DllImport("shell32.dll")]
    private static extern int Shell_NotifyIconGetRect(
        ref NotifyIconIdentifier identifier, out Rect iconLocation);

    public static bool TrayIconHasRect(IntPtr owner, uint iconId)
    {
        NotifyIconIdentifier identifier = new NotifyIconIdentifier();
        identifier.cbSize = (uint)Marshal.SizeOf(typeof(NotifyIconIdentifier));
        identifier.hWnd = owner;
        identifier.uID = iconId;
        Rect iconLocation;
        return Shell_NotifyIconGetRect(ref identifier, out iconLocation) == 0 &&
               iconLocation.right > iconLocation.left &&
               iconLocation.bottom > iconLocation.top;
    }

    public static string[] DescribeChildWindows(IntPtr parent)
    {
        List<string> windows = new List<string>();
        EnumChildWindows(parent, delegate(IntPtr window, IntPtr parameter) {
            int controlId = GetDlgCtrlID(window);
            StringBuilder dialogText = new StringBuilder(512);
            GetDlgItemText(parent, controlId, dialogText, dialogText.Capacity);
            windows.Add(String.Format("controlId={0} dlgItemText={1} {2}",
                                      controlId, dialogText, DescribeWindow(window)));
            return true;
        }, IntPtr.Zero);
        return windows.ToArray();
    }

    public static string[] DescribeWindowsForThread(uint threadId)
    {
        List<string> windows = new List<string>();
        EnumThreadWindows(threadId, delegate(IntPtr window, IntPtr parameter) {
            windows.Add(DescribeWindow(window));
            return true;
        }, IntPtr.Zero);
        return windows.ToArray();
    }

    public static string DesktopNameForThread(uint threadId)
    {
        IntPtr desktop = GetThreadDesktop(threadId);
        if (desktop == IntPtr.Zero) return "<GetThreadDesktop failed>";
        StringBuilder name = new StringBuilder(256);
        uint needed;
        if (!GetUserObjectInformation(desktop, 2, name,
                                      (uint)(name.Capacity * sizeof(char)), out needed))
            return "<GetUserObjectInformation failed>";
        return name.ToString();
    }
}
"@

$localRoot = Join-Path $env:SystemDrive ("ClipboardProtectorSandboxRun-" + $RunNonce)
[void](New-Item -ItemType Directory -Path $localRoot -Force)
$logPath = Join-Path $localRoot "run.log"
$clientOutPath = Join-Path $localRoot "clipclient.stdout.log"
$clientErrorPath = Join-Path $localRoot "clipclient.stderr.log"
$appOutPath = Join-Path $localRoot "app.stdout.log"
$appErrorPath = Join-Path $localRoot "app.stderr.log"
$signalDir = Join-Path $localRoot "signals"
$configEvidencePath = Join-Path $localRoot "sandbox-config.json"
$csvPath = Join-Path $localRoot "clipboard-export.csv"
[void](New-Item -ItemType Directory -Path $signalDir -Force)

function Write-RunLog([string]$Message) {
    $line = "{0} {1}" -f [DateTime]::UtcNow.ToString("o"), $Message
    Add-Content -LiteralPath $logPath -Value $line -Encoding UTF8
}

function Save-CompletedOutput($Task, [string]$Path) {
    if ($null -eq $Task -or -not $Task.IsCompleted) {
        return $null
    }
    try {
        $output = [string]$Task.Result
        [IO.File]::WriteAllText($Path, $output, [Text.UTF8Encoding]::new($false))
        return $output
    }
    catch {
        Write-RunLog ("Could not capture redirected output for " + $Path +
            ": " + $_.Exception.Message)
        return $null
    }
}

function Start-RedirectedProcess(
    [string]$FilePath, [string]$Arguments, [string]$WorkingDirectory) {
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $FilePath
    $startInfo.Arguments = $Arguments
    $startInfo.WorkingDirectory = $WorkingDirectory
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    if (-not $process.Start()) {
        $process.Dispose()
        throw "Process.Start returned false for: $FilePath"
    }
    return $process
}

function Test-HookModuleLoaded([int]$ProcessId) {
    try {
        $process = Get-Process -Id $ProcessId -ErrorAction Stop
        foreach ($module in $process.Modules) {
            if ($module.ModuleName -ieq "HookDll.dll") {
                return $true
            }
        }
    }
    catch {
        Write-RunLog ("Module enumeration failed: " + $_.Exception.Message)
        return $null
    }
    return $false
}

function Wait-SignalFile([string]$Path, [int]$TimeoutMilliseconds) {
    $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMilliseconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            return $true
        }
        Start-Sleep -Milliseconds 100
    }
    return $false
}

function Send-MainCommand([IntPtr]$Window, [int]$Command) {
    [IntPtr]$commandResult = [IntPtr]::Zero
    $sent = [ClipboardProtectorSandboxNative]::SendMessageTimeout(
        $Window, 0x0111, [IntPtr]$Command, [IntPtr]::Zero,
        0x0002, 1000, [ref]$commandResult)
    return $sent -ne [IntPtr]::Zero
}

function Send-DialogCommand([IntPtr]$Dialog, [int]$Command) {
    [IntPtr]$commandResult = [IntPtr]::Zero
    $sent = [ClipboardProtectorSandboxNative]::SendMessageTimeout(
        $Dialog, 0x0111, [IntPtr]$Command, [IntPtr]::Zero,
        0x0002, 1000, [ref]$commandResult)
    return $sent -ne [IntPtr]::Zero
}

function Post-WindowCommand([IntPtr]$Window, [int]$Command) {
    return [ClipboardProtectorSandboxNative]::PostMessage(
        $Window, 0x0111, [IntPtr]$Command, [IntPtr]::Zero)
}

function Wait-AppDialog(
    [int]$ProcessId, [string]$Title, [int]$TimeoutMilliseconds) {
    $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMilliseconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        $dialog = [ClipboardProtectorSandboxNative]::FindWindowForProcessByClassAndTitle(
            [uint32]$ProcessId, "#32770", $Title)
        if ($dialog -ne [IntPtr]::Zero) { return $dialog }
        Start-Sleep -Milliseconds 50
    }
    return [IntPtr]::Zero
}

function ConvertFrom-Utf16Codes([int[]]$CodeUnits) {
    return -join @($CodeUnits | ForEach-Object { [char]$_ })
}

function Wait-AppDialogWithControl(
    [int]$ProcessId, [int]$ControlId, [int]$TimeoutMilliseconds) {
    $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMilliseconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        $dialog =
            [ClipboardProtectorSandboxNative]::FindDialogForProcessWithControl(
                [uint32]$ProcessId, $ControlId)
        if ($dialog -ne [IntPtr]::Zero) { return $dialog }
        Start-Sleep -Milliseconds 50
    }
    return [IntPtr]::Zero
}

function Wait-AppSaveDialog([int]$ProcessId, [int]$TimeoutMilliseconds) {
    $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMilliseconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        $dialog = [ClipboardProtectorSandboxNative]::FindSaveDialogForProcess(
            [uint32]$ProcessId)
        if ($dialog -ne [IntPtr]::Zero) {
            $filename = [ClipboardProtectorSandboxNative]::FindDescendantControl(
                $dialog, 1001, "Edit")
            if ($filename -eq [IntPtr]::Zero) {
                $filename =
                    [ClipboardProtectorSandboxNative]::FindDescendantControl(
                        $dialog, 0x47c, "Edit")
            }
            if ($filename -ne [IntPtr]::Zero) {
                return [ordered]@{ window = $dialog; filename = $filename }
            }
        }
        Start-Sleep -Milliseconds 50
    }
    return [ordered]@{
        window = [IntPtr]::Zero
        filename = [IntPtr]::Zero
    }
}

function Wait-AppMessageBox([int]$ProcessId, [int]$TimeoutMilliseconds) {
    $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMilliseconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        $dialog = [ClipboardProtectorSandboxNative]::FindMessageBoxForProcess(
            [uint32]$ProcessId)
        if ($dialog -ne [IntPtr]::Zero) { return $dialog }
        Start-Sleep -Milliseconds 50
    }
    return [IntPtr]::Zero
}

function Wait-WindowDismissed([IntPtr]$Window, [int]$TimeoutMilliseconds) {
    $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMilliseconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        # EndDialog hides a modal dialog before its HWND is destroyed. Hidden
        # is therefore the reliable cross-process completion signal.
        if (-not [ClipboardProtectorSandboxNative]::IsWindow($Window) -or
            -not [ClipboardProtectorSandboxNative]::IsWindowVisible($Window)) {
            return $true
        }
        Start-Sleep -Milliseconds 50
    }
    return $false
}

function Send-ControlMessage(
    [IntPtr]$Window, [uint32]$Message, [IntPtr]$WParam, [IntPtr]$LParam) {
    [IntPtr]$messageResult = [IntPtr]::Zero
    $sent = [ClipboardProtectorSandboxNative]::SendMessageTimeout(
        $Window, $Message, $WParam, $LParam, 0x0002, 1000,
        [ref]$messageResult)
    return [ordered]@{
        sent = $sent -ne [IntPtr]::Zero
        result = $messageResult
    }
}

function Click-DialogControl([IntPtr]$Dialog, [int]$ControlId) {
    $control = [ClipboardProtectorSandboxNative]::GetDlgItem(
        $Dialog, $ControlId)
    if ($control -eq [IntPtr]::Zero) { return $false }
    $response = Send-ControlMessage $control 0x00F5 ([IntPtr]::Zero) ([IntPtr]::Zero)
    return [bool]$response.sent
}

function Post-DialogControlClick([IntPtr]$Dialog, [int]$ControlId) {
    $control = [ClipboardProtectorSandboxNative]::GetDlgItem(
        $Dialog, $ControlId)
    if ($control -eq [IntPtr]::Zero) { return $false }
    return [ClipboardProtectorSandboxNative]::PostMessage(
        $control, 0x00F5, [IntPtr]::Zero, [IntPtr]::Zero)
}

function Invoke-DialogControlAndWait(
    [IntPtr]$Dialog, [int]$ControlId, [int]$TimeoutMilliseconds) {
    $control = [ClipboardProtectorSandboxNative]::GetDlgItem(
        $Dialog, $ControlId)
    if ($control -eq [IntPtr]::Zero) { return $false }

    $clicked = [ClipboardProtectorSandboxNative]::ClickControlByInput(
        $Dialog, $control)
    if ($clicked -and (Wait-WindowDismissed $Dialog $TimeoutMilliseconds)) {
        return $true
    }
    if ((Invoke-ControlUia $control) -and
        (Wait-WindowDismissed $Dialog $TimeoutMilliseconds)) {
        return $true
    }
    $sent = Send-ControlMessage $Dialog 0x0111 `
        ([IntPtr]$ControlId) $control
    if (Wait-WindowDismissed $Dialog $TimeoutMilliseconds) {
        return $true
    }
    $posted = [ClipboardProtectorSandboxNative]::PostMessage(
        $Dialog, 0x0111, [IntPtr]$ControlId, $control)
    return $posted -and
        (Wait-WindowDismissed $Dialog $TimeoutMilliseconds)
}

function Invoke-DialogButtonByTitleAndWait(
    [IntPtr]$Dialog, [string]$Title, [int]$TimeoutMilliseconds) {
    $control =
        [ClipboardProtectorSandboxNative]::FindVisibleDescendantByClassAndTitle(
            $Dialog, "Button", $Title)
    if ($control -eq [IntPtr]::Zero) { return $false }

    $clicked = [ClipboardProtectorSandboxNative]::ClickControlByInput(
        $Dialog, $control)
    if ($clicked -and (Wait-WindowDismissed $Dialog $TimeoutMilliseconds)) {
        return $true
    }
    if ((Invoke-ControlUia $control) -and
        (Wait-WindowDismissed $Dialog $TimeoutMilliseconds)) {
        return $true
    }
    $posted = [ClipboardProtectorSandboxNative]::PostMessage(
        $control, 0x00F5, [IntPtr]::Zero, [IntPtr]::Zero)
    return $posted -and
        (Wait-WindowDismissed $Dialog $TimeoutMilliseconds)
}

function Set-ControlValueUia([IntPtr]$Window, [string]$Value) {
    if ($Window -eq [IntPtr]::Zero) { return $false }
    try {
        $element = [Windows.Automation.AutomationElement]::FromHandle($Window)
        $pattern = $element.GetCurrentPattern(
            [Windows.Automation.ValuePattern]::Pattern)
        $pattern.SetValue($Value)
        return $true
    }
    catch { return $false }
}

function Invoke-ControlUia([IntPtr]$Window) {
    if ($Window -eq [IntPtr]::Zero) { return $false }
    try {
        $element = [Windows.Automation.AutomationElement]::FromHandle($Window)
        $pattern = $element.GetCurrentPattern(
            [Windows.Automation.InvokePattern]::Pattern)
        $pattern.Invoke()
        return $true
    }
    catch { return $false }
}

function Get-ControlValueUia([IntPtr]$Window) {
    if ($Window -eq [IntPtr]::Zero) { return $null }
    try {
        $element = [Windows.Automation.AutomationElement]::FromHandle($Window)
        $pattern = $element.GetCurrentPattern(
            [Windows.Automation.ValuePattern]::Pattern)
        return [string]$pattern.Current.Value
    }
    catch { return $null }
}

function Set-ControlValueByKeyboard([IntPtr]$Window, [string]$Value) {
    if ($Window -eq [IntPtr]::Zero -or $Value -match '[+^%~(){}\[\]]') {
        return $false
    }
    try {
        $element = [Windows.Automation.AutomationElement]::FromHandle($Window)
        $element.SetFocus()
        [Windows.Forms.SendKeys]::SendWait("^a")
        [Windows.Forms.SendKeys]::SendWait($Value)
        Start-Sleep -Milliseconds 100
        return $true
    }
    catch { return $false }
}

function Set-ComboSelection(
    [IntPtr]$Dialog, [int]$ControlId, [int]$Selection) {
    $control = [ClipboardProtectorSandboxNative]::GetDlgItem(
        $Dialog, $ControlId)
    if ($control -eq [IntPtr]::Zero) { return $false }
    $response = Send-ControlMessage $control 0x014E ([IntPtr]$Selection) ([IntPtr]::Zero)
    return [bool]$response.sent -and $response.result.ToInt64() -ne -1
}

function Get-ListViewCount([IntPtr]$ListView) {
    if ($ListView -eq [IntPtr]::Zero) { return -1 }
    $response = Send-ControlMessage $ListView 0x1004 ([IntPtr]::Zero) ([IntPtr]::Zero)
    if (-not $response.sent) { return -1 }
    return [int]$response.result.ToInt64()
}

function Get-ListViewSelectedCount([IntPtr]$ListView) {
    if ($ListView -eq [IntPtr]::Zero) { return -1 }
    $response = Send-ControlMessage $ListView 0x1032 ([IntPtr]::Zero) ([IntPtr]::Zero)
    if (-not $response.sent) { return -1 }
    return [int]$response.result.ToInt64()
}

function Select-RuleRow([IntPtr]$Dialog, [ValidateSet(0, 1)][int]$Edge) {
    $listView = [ClipboardProtectorSandboxNative]::GetDlgItem($Dialog, 210)
    if ($listView -eq [IntPtr]::Zero) { return $false }
    # Ask the dialog manager to move keyboard focus, then use Home/End. This
    # avoids sending cross-process LVITEM pointers to the common control.
    $focus = Send-ControlMessage $Dialog 0x0028 $listView ([IntPtr]1)
    if (-not $focus.sent) { return $false }
    $virtualKey = if ($Edge -eq 0) { 0x24 } else { 0x23 }
    $key = Send-ControlMessage $listView 0x0100 ([IntPtr]$virtualKey) ([IntPtr]::Zero)
    Start-Sleep -Milliseconds 100
    return [bool]$key.sent -and (Get-ListViewSelectedCount $listView) -eq 1
}

function Test-ConfigRule(
    [string]$Path, [string]$Pattern, [bool]$IsPath, [int]$Action) {
    try {
        $expectedDecision = switch ($Action) {
            1 { 0 }
            2 { 2 }
            3 { 3 }
            4 { 3 }
            default { 0 }
        }
        $expectedNotification = $Action -eq 1 -or $Action -eq 4
        $json = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
        return @($json.rules | Where-Object {
            $_.pattern -ceq $Pattern -and [bool]$_.isPath -eq $IsPath -and
            [int]$_.action -eq $expectedDecision -and
            [bool]$_.showNotification -eq $expectedNotification
        }).Count -gt 0
    }
    catch { return $false }
}

function Get-ConfigRuleCount([string]$Path) {
    try {
        $json = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
        return @($json.rules).Count
    }
    catch { return -1 }
}

function Get-ConfigBalloonNotificationsDisabled([string]$Path) {
    try {
        $json = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
        return [bool]$json.settings.balloonNotificationsDisabled
    }
    catch { return $null }
}

function Open-AppDialog(
    [IntPtr]$MainWindow, [int]$ProcessId, [int]$Command,
    [int]$IdentifyingControlId) {
    if (-not (Post-WindowCommand $MainWindow $Command)) {
        return [IntPtr]::Zero
    }
    return Wait-AppDialogWithControl $ProcessId $IdentifyingControlId 5000
}

function Complete-RuleEdit(
    [int]$ProcessId, [string]$Pattern, [int]$Action) {
    $editDialog = Wait-AppDialogWithControl $ProcessId 220 5000
    if ($editDialog -eq [IntPtr]::Zero) {
        Write-RunLog ("UI-STEP edit-open=false pattern=" + $Pattern)
        return $false
    }
    $patternControl =
        [ClipboardProtectorSandboxNative]::GetDlgItem($editDialog, 220)
    $textSet =
        [ClipboardProtectorSandboxNative]::SetControlText(
            $patternControl, $Pattern)
    $observedPattern =
        [ClipboardProtectorSandboxNative]::ControlText($patternControl)
    $typeSet = Set-ComboSelection $editDialog 221 0
    $decisionSelection = switch ($Action) {
        1 { 0 }
        2 { 2 }
        3 { 1 }
        4 { 1 }
        default { 0 }
    }
    $actionSet = Set-ComboSelection $editDialog 222 $decisionSelection
    $notificationSet = Set-ComboSelection $editDialog 238 `
        $(if ($Action -eq 1 -or $Action -eq 4) { 1 } else { 0 })
    # Send one scalar WM_COMMAND and observe the real EndDialog transition.
    # Retrying through mouse/UIA while validation is modal only nests more
    # message boxes on the same UI thread and obscures the first failure.
    $okControl = [ClipboardProtectorSandboxNative]::GetDlgItem($editDialog, 1)
    $submitted = [ClipboardProtectorSandboxNative]::PostMessage(
        $editDialog, 0x0111, [IntPtr]1, $okControl)
    $dismissed = $submitted -and (Wait-WindowDismissed $editDialog 2000)
    if (-not $dismissed) {
        $result.uiDiagnostics += @(
            [ClipboardProtectorSandboxNative]::DescribeChildWindows($editDialog))
        # Validation failures open a separate top-level message box. Capture
        # every process window before cancelling so the actual blocker is not
        # hidden behind the still-visible edit dialog.
        $result.uiDiagnostics += @(
            [ClipboardProtectorSandboxNative]::DescribeWindowsForProcess(
                [uint32]$ProcessId))
        $validationTitle = ConvertFrom-Utf16Codes @(0x63d0, 0x793a)
        $validationDialog = Wait-AppDialog $ProcessId $validationTitle 200
        if ($validationDialog -ne [IntPtr]::Zero) {
            $result.uiDiagnostics += @(
                [ClipboardProtectorSandboxNative]::DescribeChildWindows(
                    $validationDialog))
            $okTitle = ConvertFrom-Utf16Codes @(0x786e, 0x5b9a)
            [void](Invoke-DialogButtonByTitleAndWait `
                $validationDialog $okTitle 1500)
        }
        [void][ClipboardProtectorSandboxNative]::PostMessage(
            $editDialog, 0x0111, [IntPtr]2,
            [ClipboardProtectorSandboxNative]::GetDlgItem($editDialog, 2))
        [void](Wait-WindowDismissed $editDialog 1500)
    }
    Write-RunLog ("UI-STEP edit pattern=" + $Pattern +
        " text=" + $textSet + " observed=" + $observedPattern +
        " type=" + $typeSet +
        " action=" + $actionSet + " notification=" + $notificationSet +
        " submitted=" + $submitted + " dismissed=" + $dismissed)
    return $textSet -and $observedPattern -ceq $Pattern -and $typeSet -and
        $actionSet -and $notificationSet -and $dismissed
}

function Add-RuleInDialog(
    [IntPtr]$RulesDialog, [int]$ProcessId, [string]$Pattern,
    [int]$Action) {
    $posted = Post-DialogControlClick $RulesDialog 211
    if (-not $posted) { return $false }
    return Complete-RuleEdit $ProcessId $Pattern $Action
}

function Edit-SelectedRuleInDialog(
    [IntPtr]$RulesDialog, [int]$ProcessId, [string]$Pattern,
    [int]$Action) {
    if (-not (Post-DialogControlClick $RulesDialog 212)) { return $false }
    return Complete-RuleEdit $ProcessId $Pattern $Action
}

function Set-SoleClipclientRuleAction(
    [IntPtr]$MainWindow, [int]$ProcessId, [string]$ConfigPath,
    [ValidateRange(0, 4)][int]$Action) {
    $dialog = Open-AppDialog $MainWindow $ProcessId 3001 210
    if ($dialog -eq [IntPtr]::Zero) { return $false }
    $edited = $false
    if (Select-RuleRow $dialog 0) {
        $edited = Edit-SelectedRuleInDialog $dialog $ProcessId `
            "clipclient.exe" $Action
    }
    [void](Invoke-DialogControlAndWait $dialog 1 1500)
    if (-not $edited) { return $false }
    $deadline = [DateTime]::UtcNow.AddSeconds(3)
    while ([DateTime]::UtcNow -lt $deadline) {
        if ((Get-ConfigRuleCount $ConfigPath) -eq 1 -and
            (Test-ConfigRule $ConfigPath "clipclient.exe" $false $Action)) {
            return $true
        }
        Start-Sleep -Milliseconds 100
    }
    return $false
}

function Set-BalloonNotificationsDisabled(
    [IntPtr]$MainWindow, [int]$ProcessId, [string]$ConfigPath,
    [bool]$Disabled) {
    $dialog = Open-AppDialog $MainWindow $ProcessId 3004 200
    if ($dialog -eq [IntPtr]::Zero) {
        Write-RunLog ("UI-STEP settings-open=false disabled=" + $Disabled)
        return $false
    }
    $checkbox = [ClipboardProtectorSandboxNative]::GetDlgItem($dialog, 200)
    $checked = Send-ControlMessage $checkbox 0x00F0 `
        ([IntPtr]::Zero) ([IntPtr]::Zero)
    if (-not $checked.sent) {
        Write-RunLog ("UI-STEP settings-state=false disabled=" + $Disabled)
        [void](Post-DialogControlClick $dialog 2)
        return $false
    }
    $isChecked = $checked.result.ToInt64() -eq 1
    if ($isChecked -ne $Disabled) {
        if (-not (Click-DialogControl $dialog 200)) {
            Write-RunLog ("UI-STEP settings-checkbox=false disabled=" + $Disabled)
            [void](Post-DialogControlClick $dialog 2)
            return $false
        }
        $checked = Send-ControlMessage $checkbox 0x00F0 `
            ([IntPtr]::Zero) ([IntPtr]::Zero)
        if (-not $checked.sent -or
            (($checked.result.ToInt64() -eq 1) -ne $Disabled)) {
            Write-RunLog ("UI-STEP settings-checked=false disabled=" + $Disabled)
            [void](Post-DialogControlClick $dialog 2)
            return $false
        }
    }
    $posted = Post-DialogControlClick $dialog 1
    $closed = $posted -and (Wait-WindowDismissed $dialog 5000)
    if (-not $closed) {
        Write-RunLog ("UI-STEP settings-close=false disabled=" + $Disabled)
        return $false
    }
    $deadline = [DateTime]::UtcNow.AddSeconds(3)
    while ([DateTime]::UtcNow -lt $deadline) {
        if ((Get-ConfigBalloonNotificationsDisabled $ConfigPath) -eq $Disabled) {
            Write-RunLog ("UI-STEP settings-saved=true disabled=" + $Disabled)
            return $true
        }
        Start-Sleep -Milliseconds 100
    }
    Write-RunLog ("UI-STEP settings-saved=false disabled=" + $Disabled)
    return $false
}

function Set-AutostartCheckbox(
    [IntPtr]$MainWindow, [int]$ProcessId, [string]$ConfigPath,
    [bool]$Enabled) {
    $dialog = Open-AppDialog $MainWindow $ProcessId 3004 200
    if ($dialog -eq [IntPtr]::Zero) {
        Write-RunLog ("TASK-STEP settings-open=false enabled=" + $Enabled)
        return $false
    }
    $check = [ClipboardProtectorSandboxNative]::GetDlgItem($dialog, 205)
    if ($check -eq [IntPtr]::Zero) {
        [void](Post-DialogControlClick $dialog 2)
        return $false
    }
    $value = if ($Enabled) { 1 } else { 0 }
    $response = Send-ControlMessage $check 0x00F1 ([IntPtr]$value) ([IntPtr]::Zero)
    $checked = Send-ControlMessage $check 0x00F0 ([IntPtr]::Zero) ([IntPtr]::Zero)
    if (-not $response.sent -or -not $checked.sent -or
        $checked.result.ToInt64() -ne $value) {
        [void](Post-DialogControlClick $dialog 2)
        Write-RunLog ("TASK-STEP checkbox-set=false enabled=" + $Enabled)
        return $false
    }
    $posted = Post-DialogControlClick $dialog 1
    $closed = $posted -and (Wait-WindowDismissed $dialog 5000)
    if (-not $closed) {
        Write-RunLog ("TASK-STEP settings-close=false enabled=" + $Enabled)
        return $false
    }
    $deadline = [DateTime]::UtcNow.AddSeconds(4)
    while ([DateTime]::UtcNow -lt $deadline) {
        try {
            $json = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
            if ([bool]$json.settings.autostart -eq $Enabled) {
                Write-RunLog ("TASK-STEP settings-saved=true enabled=" + $Enabled)
                return $true
            }
        } catch {}
        Start-Sleep -Milliseconds 100
    }
    Write-RunLog ("TASK-STEP settings-saved=false enabled=" + $Enabled)
    $settingsFailureTitle = ConvertFrom-Utf16Codes `
        @(0x8bbe, 0x7f6e, 0x5931, 0x8d25)
    $errorDialog = Wait-AppDialog $ProcessId $settingsFailureTitle 1000
    if ($errorDialog -eq [IntPtr]::Zero) {
        $saveFailureTitle = ConvertFrom-Utf16Codes `
            @(0x4fdd, 0x5b58, 0x5931, 0x8d25)
        $errorDialog = Wait-AppDialog $ProcessId $saveFailureTitle 1000
    }
    if ($errorDialog -ne [IntPtr]::Zero) {
        $result.uiDiagnostics += @(
            [ClipboardProtectorSandboxNative]::DescribeChildWindows($errorDialog))
        $okTitle = ConvertFrom-Utf16Codes @(0x786e, 0x5b9a)
        [void](Invoke-DialogButtonByTitleAndWait `
            $errorDialog $okTitle 1500)
    } else {
        $result.uiDiagnostics += ("Autostart save failed without a detected " +
            "message box; requested=" + $Enabled)
        $result.uiDiagnostics += @(
            [ClipboardProtectorSandboxNative]::DescribeWindowsForProcess(
                [uint32]$ProcessId))
    }
    return $false
}

function Invoke-Schtasks([string]$Arguments) {
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = Join-Path $env:SystemRoot "System32\schtasks.exe"
    $startInfo.Arguments = $Arguments
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    if (-not $process.Start()) { throw "schtasks could not be started" }
    $stdout = $process.StandardOutput.ReadToEnd()
    $stderr = $process.StandardError.ReadToEnd()
    $process.WaitForExit()
    return [ordered]@{
        exitCode = $process.ExitCode
        stdout = $stdout
        stderr = $stderr
    }
}

function Get-AutostartTaskState {
    $task = Get-ScheduledTask -TaskName "ClipboardProtector" `
        -ErrorAction SilentlyContinue
    if ($null -eq $task) { return "Absent" }
    if ([string]$task.State -eq "Disabled") { return "Disabled" }
    return "Enabled"
}

function Invoke-CsvExportProbe(
    [IntPtr]$MainWindow, [int]$ProcessId, [string]$OutputPath) {
    $pickerDefaultPath = Join-Path $env:USERPROFILE `
        "Documents\clipboard_log.csv"
    foreach ($stalePath in @($OutputPath, $pickerDefaultPath)) {
        if (Test-Path -LiteralPath $stalePath -PathType Leaf) {
            Remove-Item -LiteralPath $stalePath -Force
        }
    }
    if (-not (Post-WindowCommand $MainWindow 3003)) { return $false }
    $saveDialog = Wait-AppSaveDialog $ProcessId 5000
    $dialog = [IntPtr]$saveDialog.window
    if ($dialog -eq [IntPtr]::Zero) {
        Write-RunLog "CSV-STEP save-dialog=false"
        return $false
    }
    $filename = [IntPtr]$saveDialog.filename
    $set = Set-ControlValueUia $filename $OutputPath
    if (-not $set) {
        $set = Set-ControlValueByKeyboard $filename $OutputPath
    }
    if (-not $set) {
        $set = [ClipboardProtectorSandboxNative]::SetWindowText($filename, $OutputPath)
    }
    $requestedValue = Get-ControlValueUia $filename
    if ($null -eq $requestedValue) {
        $requestedValue = [ClipboardProtectorSandboxNative]::WindowText($filename)
    }
    Start-Sleep -Milliseconds 200
    $saveButton = [ClipboardProtectorSandboxNative]::GetDlgItem($dialog, 1)
    $clicked = $set -and
        [ClipboardProtectorSandboxNative]::ClickControlByInput($dialog, $saveButton)
    if (-not $clicked) {
        $clicked = $set -and (Invoke-ControlUia $saveButton)
    }
    $closed = $clicked -and (Wait-WindowDismissed $dialog 5000)
    if (-not $closed) {
        Write-RunLog ("CSV-STEP save-dialog-closed=false set=" + $set)
        $result.uiDiagnostics += @(
            [ClipboardProtectorSandboxNative]::DescribeChildWindows($dialog))
        [void](Post-DialogControlClick $dialog 2)
        [void](Wait-WindowDismissed $dialog 3000)
        return $false
    }
    # ExportCsv reports success/failure with a message box. Dismiss it only
    # after the file has been written so the resulting bytes remain evidence.
    $successTitle = ConvertFrom-Utf16Codes @(0x5bfc, 0x51fa, 0x5b8c, 0x6210)
    $message = Wait-AppDialog $ProcessId $successTitle 5000
    $messageSeen = $message -ne [IntPtr]::Zero
    $messageTexts = @()
    if ($messageSeen) {
        $messageTexts = @(
            [ClipboardProtectorSandboxNative]::DescribeChildWindows($message))
        $okTitle = ConvertFrom-Utf16Codes @(0x786e, 0x5b9a)
        [void](Invoke-DialogButtonByTitleAndWait $message $okTitle 1500)
    } else {
        $result.uiDiagnostics += "CSV success message was not found."
        $result.uiDiagnostics += @(
            [ClipboardProtectorSandboxNative]::DescribeWindowsForProcess(
                [uint32]$ProcessId))
    }
    $actualOutputPath = $OutputPath
    if (-not (Test-Path -LiteralPath $actualOutputPath -PathType Leaf)) {
        $leafName = [IO.Path]::GetFileName($OutputPath)
        $candidateRoots = @(
            (Split-Path -Parent $OutputPath),
            (Join-Path $env:USERPROFILE "Documents"),
            (Join-Path $env:USERPROFILE "Desktop"))
        $candidate = @($candidateRoots | ForEach-Object {
            Join-Path $_ $leafName
        } | Where-Object {
            Test-Path -LiteralPath $_ -PathType Leaf
        }) | Select-Object -First 1
        if (-not [string]::IsNullOrWhiteSpace([string]$candidate)) {
            $actualOutputPath = [string]$candidate
        }
    }
    $csvCandidates = @()
    if (-not (Test-Path -LiteralPath $actualOutputPath -PathType Leaf)) {
        $csvCandidates = @(Get-ChildItem -LiteralPath @($localRoot, $env:USERPROFILE) `
            -Filter "*.csv" -File -Recurse -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTimeUtc -Descending |
            Select-Object -First 20)
        $recentCandidate = @($csvCandidates | Where-Object {
            $_.LastWriteTimeUtc -ge ([DateTime]$result.startedUtc).ToUniversalTime()
        }) | Select-Object -First 1
        if ($null -ne $recentCandidate) {
            $actualOutputPath = $recentCandidate.FullName
        }
    }
    if (-not (Test-Path -LiteralPath $actualOutputPath -PathType Leaf)) {
        $result.csvEvidence = [ordered]@{
            requestedPath = $OutputPath
            filenameValue = $requestedValue
            messageTexts = $messageTexts
            candidates = @($csvCandidates | ForEach-Object FullName)
            error = "No exported file was found at the requested or common-dialog locations."
        }
        Write-RunLog "CSV-STEP output=false"
        return $false
    }
    try {
        $bytes = [IO.File]::ReadAllBytes($actualOutputPath)
        $utf8 = [Text.UTF8Encoding]::new($false, $true)
        $text = $utf8.GetString($bytes)
        if ($text.Length -gt 0 -and $text[0] -eq [char]0xFEFF) {
            $text = $text.Substring(1)
        }
        $rows = @(ConvertFrom-Csv $text)
        $header = @($text -split "`r`n")[0]
        $headerFields = @($header -split ',')
        $dataColumnCounts = @($rows | ForEach-Object {
            @($_.PSObject.Properties).Count
        })
        # SetClipboardData is logged after EmptyClipboard, so the special
        # preview is not guaranteed to be the first data row.
        $previews = @($rows | ForEach-Object {
            $properties = @($_.PSObject.Properties)
            if ($properties.Count -gt 7) { [string]$properties[7].Value }
        })
        $preview = @($previews | Where-Object {
            -not [string]::IsNullOrEmpty($_) -and
                $_.StartsWith("'=FORMULA,", [StringComparison]::Ordinal)
        }) | Select-Object -First 1
        $bom = $bytes.Length -ge 3 -and $bytes[0] -eq 0xef -and
            $bytes[1] -eq 0xbb -and $bytes[2] -eq 0xbf
        $tenColumns = $headerFields.Count -eq 10 -and
            $dataColumnCounts.Count -gt 0 -and
            (@($dataColumnCounts | Where-Object { $_ -ne 10 }).Count -eq 0)
        $unicodeSample = [string]([char]0x4e2d) + [string]([char]0x6587)
        $escaped = -not [string]::IsNullOrEmpty($preview) -and
            $preview.IndexOf('"quoted"', [StringComparison]::Ordinal) -ge 0 -and
            $preview.IndexOf($unicodeSample, [StringComparison]::Ordinal) -ge 0 -and
            $preview.IndexOf("`r`n", [StringComparison]::Ordinal) -ge 0 -and
            $text.IndexOf('""quoted""', [StringComparison]::Ordinal) -ge 0
        $result.csvEvidence = [ordered]@{
            path = $actualOutputPath
            requestedPath = $OutputPath
            filenameValue = $requestedValue
            messageTexts = $messageTexts
            exists = $true
            length = $bytes.Length
            bom = if ($bom) { "UTF-8" } else { "invalid" }
            headerColumnCount = $headerFields.Count
            dataColumnCounts = $dataColumnCounts
            preview = $preview
            previewContainsCrLf = if ($null -eq $preview) { $false } else {
                $preview.IndexOf("`r`n", [StringComparison]::Ordinal) -ge 0
            }
            messageBoxSeen = $messageSeen
        }
        $result.checks.csvExportDialogCompleted = $set -and $clicked -and
            $closed -and $messageSeen
        $result.checks.csvUtf8Bom = $bom
        $result.checks.csvTenColumns = $tenColumns
        $result.checks.csvEscapingAndFormulaProtection = $escaped
        if (-not [IO.Path]::GetFullPath($actualOutputPath).Equals(
                [IO.Path]::GetFullPath($OutputPath),
                [StringComparison]::OrdinalIgnoreCase)) {
            Copy-Item -LiteralPath $actualOutputPath -Destination $OutputPath -Force
            $result.csvEvidence.evidenceCopyPath = $OutputPath
        }
        Write-RunLog ("CSV-CHECK bom=" + $bom + " columns=" + $tenColumns +
            " escaping=" + $escaped + " message=" + $messageSeen)
        return $result.checks.csvExportDialogCompleted -and $bom -and
            $tenColumns -and $escaped
    }
    catch {
        $result.csvEvidence = [ordered]@{ path = $OutputPath; error = $_.Exception.Message }
        Write-RunLog ("CSV-STEP parse-error=" + $_.Exception.Message)
        return $false
    }
}

function Invoke-CsvCreationFailureProbe(
    [IntPtr]$MainWindow, [int]$ProcessId, [string]$DeniedPath) {
    if (Test-Path -LiteralPath $DeniedPath -PathType Leaf) {
        Remove-Item -LiteralPath $DeniedPath -Force
    }
    [IO.File]::WriteAllText($DeniedPath, "locked")
    $lock = [IO.File]::Open($DeniedPath, [IO.FileMode]::Open,
        [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    $errorMessageSeen = $false
    $failureDialogTexts = [Collections.Generic.List[string]]::new()
    if (-not (Post-WindowCommand $MainWindow 3003)) {
        $lock.Dispose()
        return $false
    }
    $saveDialog = Wait-AppSaveDialog $ProcessId 5000
    $dialog = [IntPtr]$saveDialog.window
    if ($dialog -eq [IntPtr]::Zero) {
        $lock.Dispose()
        return $false
    }
    $filename = [IntPtr]$saveDialog.filename
    $set = Set-ControlValueByKeyboard $filename $DeniedPath
    if (-not $set) {
        $set = Set-ControlValueUia $filename $DeniedPath
    }
    if (-not $set) {
        $set = [ClipboardProtectorSandboxNative]::SetWindowText($filename, $DeniedPath)
    }
    Start-Sleep -Milliseconds 200
    $saveButton = [ClipboardProtectorSandboxNative]::GetDlgItem($dialog, 1)
    $clicked = $set -and
        [ClipboardProtectorSandboxNative]::ClickControlByInput($dialog, $saveButton)
    if (-not $clicked) {
        $clicked = $set -and (Invoke-ControlUia $saveButton)
    }
    if (-not $clicked) {
        $lock.Dispose()
        return $false
    }
    # OFN_OVERWRITEPROMPT appears before ExportCsv reaches CreateFile. Match
    # the observed system title exactly, then require the product's own error
    # title; both strings are code units so Windows PowerShell 5.1 can parse
    # this UTF-8-without-BOM script safely.
    $confirmTitle = ConvertFrom-Utf16Codes `
        @(0x786e, 0x8ba4, 0x53e6, 0x5b58, 0x4e3a)
    $confirm = Wait-AppDialog $ProcessId $confirmTitle 3000
    if ($confirm -ne [IntPtr]::Zero) {
        $children = @(
            [ClipboardProtectorSandboxNative]::DescribeChildWindows($confirm))
        $result.uiDiagnostics += $children
        $failureDialogTexts.Add(($children -join " "))
        $yesTitle = ConvertFrom-Utf16Codes @(0x662f, 0x28, 0x26, 0x59, 0x29)
        $confirmDismissed =
            Invoke-DialogButtonByTitleAndWait $confirm $yesTitle 1000
        if (-not $confirmDismissed) {
            $posted = [ClipboardProtectorSandboxNative]::PostMessage(
                $confirm, 0x0111, [IntPtr]6, [IntPtr]::Zero)
            $confirmDismissed = $posted -and
                (Wait-WindowDismissed $confirm 1500)
        }
        if (-not $confirmDismissed) {
            # Keep the rest of the scenario clean even if the shell refuses
            # the affirmative automation path.
            $posted = [ClipboardProtectorSandboxNative]::PostMessage(
                $confirm, 0x0111, [IntPtr]7, [IntPtr]::Zero)
            [void]($posted -and (Wait-WindowDismissed $confirm 1500))
        }
        Write-RunLog ("CSV-STEP overwrite-dismissed=" + $confirmDismissed)
    }
    $errorTitle = ConvertFrom-Utf16Codes @(0x5bfc, 0x51fa, 0x5931, 0x8d25)
    $message = Wait-AppDialog $ProcessId $errorTitle 5000
    if ($message -ne [IntPtr]::Zero) {
        $children = @(
            [ClipboardProtectorSandboxNative]::DescribeChildWindows($message))
        $result.uiDiagnostics += $children
        $failureDialogTexts.Add(($children -join " "))
        $errorMessageSeen = $true
        $okTitle = ConvertFrom-Utf16Codes @(0x786e, 0x5b9a)
        [void](Invoke-DialogButtonByTitleAndWait $message $okTitle 1500)
    } else {
        # If the picker ignored the requested locked path, ExportCsv can
        # succeed against its default file. Dismiss that unexpected success
        # so later UI checks remain isolated, but keep this probe failed.
        $successTitle = ConvertFrom-Utf16Codes `
            @(0x5bfc, 0x51fa, 0x5b8c, 0x6210)
        $unexpectedSuccess = Wait-AppDialog `
            $ProcessId $successTitle 1000
        if ($unexpectedSuccess -ne [IntPtr]::Zero) {
            $result.uiDiagnostics += "CSV failure probe unexpectedly succeeded."
            $okTitle = ConvertFrom-Utf16Codes @(0x786e, 0x5b9a)
            [void](Invoke-DialogButtonByTitleAndWait `
                $unexpectedSuccess $okTitle 1500)
        }
    }
    $closed = Wait-WindowDismissed $dialog 5000
    if (-not $closed) {
        [void](Post-DialogControlClick $dialog 2)
        [void](Wait-WindowDismissed $dialog 3000)
    }
    $lock.Dispose()
    $stillPresent = Test-Path -LiteralPath $DeniedPath -PathType Leaf
    $result.csvCreationFailureEvidence = [ordered]@{
        path = $DeniedPath
        dialogTexts = $failureDialogTexts.ToArray()
        productErrorTextMatched = $errorMessageSeen
        fileStillPresent = $stillPresent
    }
    if (-not $errorMessageSeen) {
        $result.uiDiagnostics += "CSV product error message was not found."
        $result.uiDiagnostics += @(
            [ClipboardProtectorSandboxNative]::DescribeWindowsForProcess(
                [uint32]$ProcessId))
    }
    $result.checks.csvCreationFailureDialogShown = $set -and $clicked -and
        $closed -and $errorMessageSeen -and $stillPresent
    Write-RunLog ("CSV-CHECK creation-failure-dialog=" +
        $result.checks.csvCreationFailureDialogShown)
    return $result.checks.csvCreationFailureDialogShown
}

function Request-UiRead(
    [string]$Signals, [int]$ProbeNumber, [int]$TimeoutMilliseconds) {
    $request = Join-Path $Signals ("ui-{0}.request" -f $ProbeNumber)
    $done = Join-Path $Signals ("ui-{0}.done" -f $ProbeNumber)
    Set-Content -LiteralPath $request -Value "read" -Encoding ASCII
    if (-not (Wait-SignalFile $done $TimeoutMilliseconds)) { return $false }
    # Let the pipe and UI threads consume the event before inspecting rows.
    Start-Sleep -Milliseconds 300
    return $true
}

function Get-MainListCount([IntPtr]$MainWindow) {
    $listView = [ClipboardProtectorSandboxNative]::GetDlgItem($MainWindow, 102)
    return Get-ListViewCount $listView
}

function Invoke-NotificationClick([IntPtr]$MainWindow) {
    if (-not [ClipboardProtectorSandboxNative]::PostMessage(
            $MainWindow, 0x8001, [IntPtr]::Zero, [IntPtr]0x0405)) {
        return -1
    }
    Start-Sleep -Milliseconds 200
    $listView = [ClipboardProtectorSandboxNative]::GetDlgItem($MainWindow, 102)
    return Get-ListViewSelectedCount $listView
}

function Invoke-TrayToggle([IntPtr]$MainWindow) {
    # NOTIFYICON_VERSION_4 delivers the mouse event in the low word of lParam.
    return [ClipboardProtectorSandboxNative]::PostMessage(
        $MainWindow, 0x8001, [IntPtr]::Zero, [IntPtr]0x0203)
}

function Get-ConfigEvidence([string]$Path) {
    $evidence = [ordered]@{
        path = $Path
        exists = $false
        length = 0
        sha256 = $null
        bom = "missing"
        content = $null
        blockingRuleValid = $false
        ruleCount = -1
        balloonNotificationsDisabled = $null
        shortcutOnlyMode = $null
        parseError = $null
    }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $evidence
    }
    try {
        $bytes = [IO.File]::ReadAllBytes($Path)
        $evidence.exists = $true
        $evidence.length = $bytes.Length
        $evidence.sha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
        if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and
            $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
            $evidence.bom = "UTF-8"
        } elseif ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and
                  $bytes[1] -eq 0xFE) {
            $evidence.bom = "UTF-16LE"
        } elseif ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFE -and
                  $bytes[1] -eq 0xFF) {
            $evidence.bom = "UTF-16BE"
        } else {
            $evidence.bom = "none"
        }
        if ($bytes.Length -gt 65536) {
            $evidence.parseError = "File exceeds the 64 KiB evidence limit."
            return $evidence
        }
        $content = [IO.File]::ReadAllText($Path)
        $evidence.content = $content
        $json = $content | ConvertFrom-Json
        $evidence.ruleCount = @($json.rules).Count
        $evidence.balloonNotificationsDisabled =
            [bool]$json.settings.balloonNotificationsDisabled
        $evidence.shortcutOnlyMode = [bool]$json.settings.shortcutOnlyMode
        $matchingRules = @($json.rules | Where-Object {
            $_.pattern -ieq "clipclient.exe" -and
            [bool]$_.isPath -eq $false -and [int]$_.action -eq 3
        })
        $evidence.blockingRuleValid = $matchingRules.Count -gt 0
    }
    catch {
        $evidence.parseError = $_.Exception.Message
    }
    return $evidence
}

function Save-ConfigSnapshot([string]$Source, [string]$Destination) {
    if (Test-Path -LiteralPath $Source -PathType Leaf) {
        Copy-Item -LiteralPath $Source -Destination $Destination -Force
    }
}

function Get-AppDiagnostics($Process, [string]$Stage) {
    $lines = [Collections.Generic.List[string]]::new()
    try {
        $Process.Refresh()
        $lines.Add("stage=$Stage pid=$($Process.Id) hasExited=$($Process.HasExited)")
        if (-not $Process.HasExited) {
            foreach ($thread in $Process.Threads) {
                $waitReason = ""
                try {
                    if ($thread.ThreadState -eq [Diagnostics.ThreadState]::Wait) {
                        $waitReason = " waitReason=$($thread.WaitReason)"
                    }
                } catch {}
                $desktop = [ClipboardProtectorSandboxNative]::DesktopNameForThread(
                    [uint32]$thread.Id)
                $lines.Add("thread tid=$($thread.Id) state=$($thread.ThreadState)$waitReason desktop=$desktop")
                foreach ($window in [ClipboardProtectorSandboxNative]::DescribeWindowsForThread(
                             [uint32]$thread.Id)) {
                    $lines.Add("thread-window $window")
                }
            }
            foreach ($window in [ClipboardProtectorSandboxNative]::DescribeWindowsForProcess(
                         [uint32]$Process.Id)) {
                $lines.Add("desktop-window $window")
            }
        }
    }
    catch {
        $lines.Add("stage=$Stage diagnostic-error=$($_.Exception.Message)")
    }
    return $lines.ToArray()
}

$result = [ordered]@{
    schemaVersion = 1
    scenario = $Scenario
    startedUtc = [DateTime]::UtcNow.ToString("o")
    finishedUtc = $null
    passed = $false
    checks = [ordered]@{
        inputHashesVerified = $false
        blockRuleConfigWritten = $false
        blockingConfigVerifiedAfterAppStart = $false
        blockingConfigVerifiedBeforeAppExit = $false
        targetWasSelfBuiltClipclient = $false
        globalHookOptInAbsent = $false
        startupErrorDialogAbsent = $true
        mainWindowOwnedByApp = $false
        mainListReceivedEvent = $false
        hookDllObservedInClient = $false
        blockedReadObserved = $false
        pauseCommandProcessed = $false
        pausedReadAllowed = $false
        resumeCommandProcessed = $false
        resumedReadBlocked = $false
        gracefulQuitPosted = $false
        appExitedAfterQuit = $false
        targetAliveAfterAppExit = $false
        hookDetachObservedByClient = $false
        hookDllReleasedAfterAppExit = $false
        postExitClipboardProbeCompleted = $false
        clientExitedNaturally = $false
        notificationBlockedSuppressed = $false
        ruleDialogCancelRollback = $false
        ruleDialogAddPersisted = $false
        ruleDialogEditPersisted = $false
        ruleDialogDeletePersisted = $false
        balloonDisabledShowSuppressed = $false
        balloonEnabledShowSelectedRow = $false
        balloonEnabledSilentSuppressed = $false
        balloonEnabledBlockSuppressed = $false
        configSaveFailureDialogShown = $false
        configSaveFailureRollback = $false
        csvExportDialogCompleted = $false
        csvUtf8Bom = $false
        csvTenColumns = $false
        csvEscapingAndFormulaProtection = $false
        csvCreationFailureDialogShown = $false
        autostartTaskCreated = $false
        autostartTaskDisabled = $false
        autostartTaskEnabled = $false
        autostartTaskDeleted = $false
        explorerTrayIconPresentBeforeRestart = $false
        explorerRestarted = $false
        explorerTrayIconRecovered = $false
        mainWindowHidden = $false
        mainWindowRestored = $false
        corruptConfigBackedUp = $false
        corruptConfigAppStarted = $false
        corruptConfigAppExited = $false
    }
    clientPid = $null
    appPid = $null
    mainListItemCount = 0
    clientArgumentLine = $null
    clientExitedEarly = $false
    appExitedEarly = $false
    clientHasExitedAtFinish = $null
    appHasExitedAtFinish = $null
    inputIdleAfterStart = $null
    inputIdleAtWindowTimeout = $null
    appDiagnostics = @()
    startupDialogDiagnostics = @()
    startupErrorDialogDismissed = $false
    configBeforeAppStart = $null
    configAfterAppStart = $null
    configBeforeAppExit = $null
    configAtFinish = $null
    configBackupAfterAppStart = $null
    configBackupBeforeAppExit = $null
    configBackupAtFinish = $null
    uiConfigAfterCancel = $null
    uiConfigAfterAdd = $null
    uiConfigAfterEdit = $null
    uiConfigAfterDelete = $null
    uiConfigAfterSaveFailure = $null
    csvEvidence = $null
    csvCreationFailureEvidence = $null
    autostartEvidence = @()
    corruptConfigEvidence = $null
    corruptConfigBackupEvidence = $null
    uiDiagnostics = @()
    appExitCode = $null
    clientExitCode = $null
    error = $null
}

$client = $null
$app = $null
$clientOutTask = $null
$clientErrorTask = $null
$appOutTask = $null
$appErrorTask = $null
$corruptClient = $null
$corruptApp = $null
$corruptClientOutTask = $null
$corruptClientErrorTask = $null
$corruptAppOutTask = $null
$corruptAppErrorTask = $null
$corruptClientOutPath = Join-Path $localRoot "corrupt-clipclient.stdout.log"
$corruptClientErrorPath = Join-Path $localRoot "corrupt-clipclient.stderr.log"
$corruptAppOutPath = Join-Path $localRoot "corrupt-app.stdout.log"
$corruptAppErrorPath = Join-Path $localRoot "corrupt-app.stderr.log"
try {
    Add-Type -TypeDefinition $nativeTypeDefinition
    Add-Type -AssemblyName UIAutomationClient
    Add-Type -AssemblyName UIAutomationTypes
    Add-Type -AssemblyName System.Windows.Forms
    Write-RunLog "Copying read-only mapped artifacts to the Sandbox-local working directory."
    foreach ($name in @("ClipboardProtector.exe", "HookDll.dll", "clipclient.exe", "input.json")) {
        $source = Join-Path $InputDir $name
        if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
            throw "Missing mapped input: $source"
        }
        Copy-Item -LiteralPath $source -Destination $localRoot -Force
    }

    $manifest = Get-Content -LiteralPath (Join-Path $localRoot "input.json") -Raw |
        ConvertFrom-Json
    $hashesValid = $true
    foreach ($artifact in $manifest.artifacts) {
        $localArtifact = Join-Path $localRoot $artifact.name
        if (-not (Test-Path -LiteralPath $localArtifact -PathType Leaf) -or
            (Get-FileHash -LiteralPath $localArtifact -Algorithm SHA256).Hash -ne $artifact.sha256) {
            $hashesValid = $false
            break
        }
    }
    $result.checks.inputHashesVerified = $hashesValid
    if (-not $hashesValid) {
        throw "A Sandbox-local artifact does not match the host-generated input manifest."
    }

    $configDir = Join-Path $env:APPDATA "ClipboardProtector"
    [void](New-Item -ItemType Directory -Path $configDir -Force)
    $sandboxConfig = [ordered]@{
        ruleModelVersion = 4
        settings = [ordered]@{
            balloonNotificationsDisabled = $false
            shortcutOnlyMode = $false
            maxLogEntries = 5000
            previewEnabled = $true
            autostart = $false
        }
        rules = @(
            [ordered]@{
                pattern = "clipclient.exe"
                isPath = $false
                action = 3
                # The client must first seed the clipboard, then prove that a
                # read-only blocking rule denies the following read.
                operations = 1
                showNotification = $false
            }
        )
    } | ConvertTo-Json -Depth 5
    # Write deterministic UTF-8 without a BOM; Config::Load accepts a BOM too,
    # but byte-stable evidence makes encoding failures unambiguous.
    [IO.File]::WriteAllText($configEvidencePath, $sandboxConfig,
                            [Text.UTF8Encoding]::new($false))
    $runtimeConfigPath = Join-Path $configDir "config.json"
    $runtimeBackupPath = $runtimeConfigPath + ".bak"
    Copy-Item -LiteralPath $configEvidencePath -Destination $runtimeConfigPath -Force
    $result.checks.blockRuleConfigWritten =
        Test-Path -LiteralPath $runtimeConfigPath -PathType Leaf
    $result.configBeforeAppStart = Get-ConfigEvidence $runtimeConfigPath

    $clientPath = Join-Path $localRoot "clipclient.exe"
    $appPath = Join-Path $localRoot "ClipboardProtector.exe"
    $durationMs = $ClientDurationSeconds * 1000
    # Exercise CSV quoting and spreadsheet formula mitigation with an actual
    # clipboard payload; clipclient consumes this only in the test build.
    $unicodeSample = [string]([char]0x4e2d) + [string]([char]0x6587)
    [Environment]::SetEnvironmentVariable(
        "CLIPCLIENT_TEST_TEXT", ('=FORMULA,"quoted"' + [char]13 +
            [char]10 + $unicodeSample), "Process")
    $clientArgumentLine = 'wait {0} SandboxProbe "{1}"' -f $durationMs, $signalDir
    $result.clientArgumentLine = $clientArgumentLine
    Write-RunLog ("clipclient arguments: " + $clientArgumentLine)
    $client = Start-RedirectedProcess $clientPath $clientArgumentLine $localRoot
    $clientOutTask = $client.StandardOutput.ReadToEndAsync()
    $clientErrorTask = $client.StandardError.ReadToEndAsync()
    $result.clientPid = $client.Id
    Start-Sleep -Milliseconds 300
    $client.Refresh()
    if ($client.HasExited) {
        $client.WaitForExit()
        $result.clientExitCode = [int]$client.ExitCode
        $result.clientExitedEarly = $true
        [void](Save-CompletedOutput $clientOutTask $clientOutPath)
        [void](Save-CompletedOutput $clientErrorTask $clientErrorPath)
        throw "clipclient exited before the controller started (exit=$($result.clientExitCode))."
    }
    $runningClient = Get-Process -Id $client.Id -ErrorAction Stop
    $result.checks.targetWasSelfBuiltClipclient =
        (-not [string]::IsNullOrWhiteSpace($runningClient.Path)) -and
        ([IO.Path]::GetFullPath($runningClient.Path) -ieq
         [IO.Path]::GetFullPath($clientPath))
    Write-RunLog ("Started clipclient PID " + $client.Id)

    [Environment]::SetEnvironmentVariable(
        "CLIPBOARDPROTECTOR_ENABLE_GLOBAL_HOOK", $null, "Process")
    [Environment]::SetEnvironmentVariable(
        "CLIPBOARDPROTECTOR_TEST_TARGET_PID", $client.Id.ToString(), "Process")
    $result.checks.globalHookOptInAbsent =
        [string]::IsNullOrEmpty([Environment]::GetEnvironmentVariable(
            "CLIPBOARDPROTECTOR_ENABLE_GLOBAL_HOOK", "Process"))

    $app = Start-RedirectedProcess $appPath "" $localRoot
    $appOutTask = $app.StandardOutput.ReadToEndAsync()
    $appErrorTask = $app.StandardError.ReadToEndAsync()
    $result.appPid = $app.Id
    Write-RunLog ("Started ClipboardProtector PID " + $app.Id + " with only the targeted PID variable.")
    Start-Sleep -Milliseconds 300
    $app.Refresh()
    if ($app.HasExited) {
        $app.WaitForExit()
        $result.appExitCode = [int]$app.ExitCode
        $result.appExitedEarly = $true
        [void](Save-CompletedOutput $appOutTask $appOutPath)
        [void](Save-CompletedOutput $appErrorTask $appErrorPath)
        throw "ClipboardProtector exited before creating its main window (exit=$($result.appExitCode))."
    }
    try {
        $result.inputIdleAfterStart = [bool]$app.WaitForInputIdle(1000)
    }
    catch {
        $result.inputIdleAfterStart = $false
        Write-RunLog ("WaitForInputIdle after start failed: " + $_.Exception.Message)
    }
    $initialDiagnostics = @(Get-AppDiagnostics $app "after-start")
    foreach ($line in $initialDiagnostics) { Write-RunLog ("APPDIAG " + $line) }

    $startupDialog = [ClipboardProtectorSandboxNative]::FindWindowForProcessByClass(
        [uint32]$app.Id, "#32770")
    if ($startupDialog -ne [IntPtr]::Zero) {
        $result.checks.startupErrorDialogAbsent = $false
        $dialogDiagnostics = @(
            [ClipboardProtectorSandboxNative]::DescribeChildWindows($startupDialog))
        $result.startupDialogDiagnostics = $dialogDiagnostics
        foreach ($line in $dialogDiagnostics) { Write-RunLog ("DIALOG " + $line) }
        # Startup MessageBoxes use MB_OK. Try cancel first for future dialogs,
        # then IDOK if it remains. A dismissed injection error still fails the run.
        [void](Send-DialogCommand $startupDialog 2)
        Start-Sleep -Milliseconds 100
        if ([ClipboardProtectorSandboxNative]::IsWindow($startupDialog)) {
            [void](Send-DialogCommand $startupDialog 1)
        }
        Start-Sleep -Milliseconds 100
        $result.startupErrorDialogDismissed =
            -not [ClipboardProtectorSandboxNative]::IsWindow($startupDialog)
    }

    $window = [IntPtr]::Zero
    $threadId = [uint32]0
    $windowDeadline = [DateTime]::UtcNow.AddSeconds(10)
    while ([DateTime]::UtcNow -lt $windowDeadline -and -not $app.HasExited) {
        $window = [ClipboardProtectorSandboxNative]::FindWindowForProcessByClass(
            [uint32]$app.Id, "ClipProtectorMainWnd")
        if ($window -ne [IntPtr]::Zero) {
            [uint32]$windowPid = 0
            $threadId = [ClipboardProtectorSandboxNative]::GetWindowThreadProcessId($window, [ref]$windowPid)
            if ($windowPid -eq $app.Id -and $threadId -ne 0) {
                $result.checks.mainWindowOwnedByApp = $true
                break
            }
            $window = [IntPtr]::Zero
        }
        Start-Sleep -Milliseconds 200
    }
    $app.Refresh()
    $client.Refresh()
    if (-not $result.checks.mainWindowOwnedByApp) {
        try {
            $result.inputIdleAtWindowTimeout = [bool]$app.WaitForInputIdle(1000)
        }
        catch {
            $result.inputIdleAtWindowTimeout = $false
            Write-RunLog ("WaitForInputIdle at timeout failed: " + $_.Exception.Message)
        }
        $timeoutDiagnostics = @(Get-AppDiagnostics $app "window-timeout")
        $result.appDiagnostics = @($initialDiagnostics + $timeoutDiagnostics)
        foreach ($line in $timeoutDiagnostics) { Write-RunLog ("APPDIAG " + $line) }
        if ($app.HasExited) {
            $app.WaitForExit()
            $result.appExitCode = [int]$app.ExitCode
            $result.appExitedEarly = $true
        }
        throw "ClipboardProtector did not create an owned main window within 10 seconds."
    }
    if ($client.HasExited) {
        $client.WaitForExit()
        $result.clientExitCode = [int]$client.ExitCode
        $result.clientExitedEarly = $true
        throw "clipclient exited while waiting for the main window (exit=$($client.ExitCode))."
    }
    $result.configAfterAppStart = Get-ConfigEvidence $runtimeConfigPath
    $result.configBackupAfterAppStart = Get-ConfigEvidence $runtimeBackupPath
    $result.checks.blockingConfigVerifiedAfterAppStart =
        [bool]$result.configAfterAppStart.blockingRuleValid
    Save-ConfigSnapshot $runtimeConfigPath (Join-Path $localRoot "config-after-start.json")
    Save-ConfigSnapshot $runtimeBackupPath (Join-Path $localRoot "config-after-start.json.bak")

    if ($Scenario -eq "Ui") {
        # WM_CLOSE is the product's hide-to-tray path; verify that it hides the
        # existing window without terminating the application, then synthesize
        # the tray double-click callback and verify restoration.
        [IntPtr]$closeResult = [IntPtr]::Zero
        $closeSent = [ClipboardProtectorSandboxNative]::SendMessageTimeout(
            $window, 0x0010, [IntPtr]::Zero, [IntPtr]::Zero,
            0x0002, 1000, [ref]$closeResult)
        $hiddenDeadline = [DateTime]::UtcNow.AddSeconds(3)
        while ([DateTime]::UtcNow -lt $hiddenDeadline) {
            if (-not [ClipboardProtectorSandboxNative]::IsWindowVisible($window)) {
                $result.checks.mainWindowHidden = $closeSent -ne [IntPtr]::Zero
                break
            }
            Start-Sleep -Milliseconds 50
        }
        if ($result.checks.mainWindowHidden -and (Invoke-TrayToggle $window)) {
            $restoreDeadline = [DateTime]::UtcNow.AddSeconds(3)
            while ([DateTime]::UtcNow -lt $restoreDeadline) {
                if ([ClipboardProtectorSandboxNative]::IsWindowVisible($window)) {
                    $result.checks.mainWindowRestored = $true
                    break
                }
                Start-Sleep -Milliseconds 50
            }
        }
        Write-RunLog ("UI-CHECK mainWindowHidden=" +
            $result.checks.mainWindowHidden + " mainWindowRestored=" +
            $result.checks.mainWindowRestored)
    }

    $observeDeadline = [DateTime]::UtcNow.AddSeconds($ObservationDelaySeconds)
    while ([DateTime]::UtcNow -lt $observeDeadline -and -not $client.HasExited) {
        if (Test-HookModuleLoaded $client.Id) {
            $result.checks.hookDllObservedInClient = $true
        }
        if ($window -ne [IntPtr]::Zero) {
            $listView = [ClipboardProtectorSandboxNative]::GetDlgItem($window, 102)
            if ($listView -ne [IntPtr]::Zero) {
                # LVM_GETITEMCOUNT carries no cross-process pointer.
                [IntPtr]$itemCountResult = [IntPtr]::Zero
                $sendResult = [ClipboardProtectorSandboxNative]::SendMessageTimeout(
                    $listView, 0x1004, [IntPtr]::Zero, [IntPtr]::Zero,
                    0x0002, 500, [ref]$itemCountResult)
                if ($sendResult -ne [IntPtr]::Zero) {
                    $itemCount = $itemCountResult.ToInt64()
                    if ($itemCount -gt $result.mainListItemCount) {
                        $result.mainListItemCount = $itemCount
                    }
                    # Ordinary EmptyClipboard calls are intentionally not
                    # logged; the write and blocked read remain distinct.
                    if ($itemCount -ge 2) {
                        $result.checks.mainListReceivedEvent = $true
                    }
                }
            }
        }
        Start-Sleep -Milliseconds 250
    }
    Write-RunLog ("HookDll observed in target: " + $result.checks.hookDllObservedInClient)
    Write-RunLog ("Main ListView item count: " + $result.mainListItemCount)

    if ($Scenario -eq "Ui") {
        [void](Invoke-CsvExportProbe $window $app.Id $csvPath)
        # The modern picker starts in Documents and can display an absolute
        # ValuePattern without committing it internally. Lock the product's
        # actual default filename so either picker behavior reaches CreateFile.
        $csvDeniedPath = Join-Path $env:USERPROFILE `
            "Documents\clipboard_log.csv"
        [void](Invoke-CsvCreationFailureProbe $window $app.Id $csvDeniedPath)
        $result.checks.notificationBlockedSuppressed =
            (Invoke-NotificationClick $window) -eq 0
        Write-RunLog ("Direct-block notification suppressed: " +
            $result.checks.notificationBlockedSuppressed)
    }

    $blockDone = Test-Path -LiteralPath (Join-Path $signalDir "block.done") -PathType Leaf
    if ($blockDone -and $result.checks.mainListReceivedEvent -and
        $window -ne [IntPtr]::Zero -and -not $client.HasExited) {
        $result.checks.pauseCommandProcessed = Send-MainCommand $window 3000
        if ($result.checks.pauseCommandProcessed) {
            Set-Content -LiteralPath (Join-Path $signalDir "pause.request") `
                -Value "pause" -Encoding ASCII
            $pauseDone = Wait-SignalFile (Join-Path $signalDir "pause.done") 6000
            if ($pauseDone -and -not $client.HasExited) {
                $result.checks.resumeCommandProcessed = Send-MainCommand $window 3000
                if ($result.checks.resumeCommandProcessed) {
                    Set-Content -LiteralPath (Join-Path $signalDir "resume.request") `
                        -Value "resume" -Encoding ASCII
                    [void](Wait-SignalFile (Join-Path $signalDir "resume.done") 6000)
                }
            }
        }
    }

    if ($Scenario -eq "Ui") {
        try {
            $originalConfigHash =
                (Get-FileHash -LiteralPath $runtimeConfigPath -Algorithm SHA256).Hash

            # Add a rule to the working copy, then cancel the outer dialog.
            $rulesDialog = Open-AppDialog $window $app.Id 3001 210
            $cancelEditOk = $rulesDialog -ne [IntPtr]::Zero -and
                (Add-RuleInDialog $rulesDialog $app.Id "cancelled.exe" 1)
            $cancelList = if ($rulesDialog -ne [IntPtr]::Zero) {
                [ClipboardProtectorSandboxNative]::GetDlgItem($rulesDialog, 210)
            } else { [IntPtr]::Zero }
            $cancelListCount = Get-ListViewCount $cancelList
            if ($rulesDialog -ne [IntPtr]::Zero) {
                [void](Invoke-DialogControlAndWait $rulesDialog 2 1500)
            }
            $result.uiConfigAfterCancel = Get-ConfigEvidence $runtimeConfigPath
            $hashAfterCancel =
                (Get-FileHash -LiteralPath $runtimeConfigPath -Algorithm SHA256).Hash
            $result.checks.ruleDialogCancelRollback =
                $cancelEditOk -and $cancelListCount -eq 2 -and
                $hashAfterCancel -eq $originalConfigHash -and
                $result.uiConfigAfterCancel.ruleCount -eq 1 -and
                [bool]$result.uiConfigAfterCancel.blockingRuleValid

            # Persist an added rule and verify the serialized model.
            $rulesDialog = Open-AppDialog $window $app.Id 3001 210
            $addOk = $rulesDialog -ne [IntPtr]::Zero -and
                (Add-RuleInDialog $rulesDialog $app.Id "sandbox-added.exe" 1)
            if ($rulesDialog -ne [IntPtr]::Zero) {
                [void](Invoke-DialogControlAndWait $rulesDialog 1 1500)
            }
            Start-Sleep -Milliseconds 300
            $result.uiConfigAfterAdd = Get-ConfigEvidence $runtimeConfigPath
            $result.checks.ruleDialogAddPersisted =
                $addOk -and $result.uiConfigAfterAdd.ruleCount -eq 2 -and
                (Test-ConfigRule $runtimeConfigPath "sandbox-added.exe" $false 1)

            # Select the last row with keyboard messages, edit it, and persist.
            $rulesDialog = Open-AppDialog $window $app.Id 3001 210
            $editOk = $false
            if ($rulesDialog -ne [IntPtr]::Zero -and
                (Select-RuleRow $rulesDialog 1)) {
                $editOk = Edit-SelectedRuleInDialog $rulesDialog $app.Id `
                    "sandbox-edited.exe" 2
            }
            if ($rulesDialog -ne [IntPtr]::Zero) {
                [void](Invoke-DialogControlAndWait $rulesDialog 1 1500)
            }
            Start-Sleep -Milliseconds 300
            $result.uiConfigAfterEdit = Get-ConfigEvidence $runtimeConfigPath
            $result.checks.ruleDialogEditPersisted =
                $editOk -and $result.uiConfigAfterEdit.ruleCount -eq 2 -and
                (Test-ConfigRule $runtimeConfigPath "sandbox-edited.exe" $false 2) -and
                -not (Test-ConfigRule $runtimeConfigPath "sandbox-added.exe" $false 1)

            # Delete the edited second row and restore the original one-rule set.
            $rulesDialog = Open-AppDialog $window $app.Id 3001 210
            $deleteOk = $false
            if ($rulesDialog -ne [IntPtr]::Zero -and
                (Select-RuleRow $rulesDialog 1)) {
                $deleteOk = Post-DialogControlClick $rulesDialog 213
                Start-Sleep -Milliseconds 200
                $deleteList = [ClipboardProtectorSandboxNative]::GetDlgItem(
                    $rulesDialog, 210)
                $deleteOk = $deleteOk -and
                    (Get-ListViewCount $deleteList) -eq 1
            }
            if ($rulesDialog -ne [IntPtr]::Zero) {
                [void](Invoke-DialogControlAndWait $rulesDialog 1 1500)
            }
            Start-Sleep -Milliseconds 300
            $result.uiConfigAfterDelete = Get-ConfigEvidence $runtimeConfigPath
            $result.checks.ruleDialogDeletePersisted =
                $deleteOk -and $result.uiConfigAfterDelete.ruleCount -eq 1 -and
                [bool]$result.uiConfigAfterDelete.blockingRuleValid

            # The total switch suppresses a rule's right-corner notification
            # without changing its allow decision.
            $showRule = Set-SoleClipclientRuleAction `
                $window $app.Id $runtimeConfigPath 1
            $disabledSet = Set-BalloonNotificationsDisabled `
                $window $app.Id $runtimeConfigPath $true
            [void](Send-MainCommand $window 3002)
            $disabledRead = Request-UiRead $signalDir 1 5000
            $disabledRows = Get-MainListCount $window
            $disabledSelected = Invoke-NotificationClick $window
            $result.checks.balloonDisabledShowSuppressed =
                $showRule -and $disabledSet -and $disabledRead -and
                $disabledRows -ge 1 -and $disabledSelected -eq 0

            # With the total switch enabled again, the same action must create
            # a balloon whose click selects the matching log row.
            $enabledSet = Set-BalloonNotificationsDisabled `
                $window $app.Id $runtimeConfigPath $false
            [void](Send-MainCommand $window 3002)
            $showRead = Request-UiRead $signalDir 2 5000
            $showRows = Get-MainListCount $window
            $showSelected = Invoke-NotificationClick $window
            $result.checks.balloonEnabledShowSelectedRow =
                $showRule -and $enabledSet -and $showRead -and
                $showRows -ge 1 -and $showSelected -eq 1

            # Silent allow remains silent even when rule balloons are enabled.
            $silentRule = Set-SoleClipclientRuleAction `
                $window $app.Id $runtimeConfigPath 0
            [void](Send-MainCommand $window 3002)
            $silentRead = Request-UiRead $signalDir 3 5000
            $silentRows = Get-MainListCount $window
            $silentSelected = Invoke-NotificationClick $window
            $result.checks.balloonEnabledSilentSuppressed =
                $silentRule -and $enabledSet -and $silentRead -and
                $silentRows -ge 1 -and $silentSelected -eq 0

            # Direct block also records without producing a rule balloon.
            $blockRestore = Set-SoleClipclientRuleAction `
                $window $app.Id $runtimeConfigPath 3
            [void](Send-MainCommand $window 3002)
            $blockRead = Request-UiRead $signalDir 4 5000
            $blockRows = Get-MainListCount $window
            $blockSelected = Invoke-NotificationClick $window
            $result.checks.balloonEnabledBlockSuppressed =
                $blockRestore -and $enabledSet -and $blockRead -and
                $blockRows -ge 1 -and $blockSelected -eq 0

            # Notification is independent from the block decision.
            $blockNotifyRule = Set-SoleClipclientRuleAction `
                $window $app.Id $runtimeConfigPath 4
            [void](Send-MainCommand $window 3002)
            $blockNotifyRead = Request-UiRead $signalDir 41 5000
            $blockNotifyRows = Get-MainListCount $window
            $blockNotifySelected = Invoke-NotificationClick $window
            $result.checks.balloonEnabledBlockSelectedRow =
                $blockNotifyRule -and $enabledSet -and $blockNotifyRead -and
                $blockNotifyRows -ge 1 -and $blockNotifySelected -eq 1
            $blockRestore = Set-SoleClipclientRuleAction `
                $window $app.Id $runtimeConfigPath 3
            Start-Sleep -Milliseconds 500

            # Drive the real settings path through schtasks. Keep the fixed
            # application task name isolated to this disposable Sandbox and
            # leave it absent before the app exits.
            [void](Invoke-Schtasks '/Delete /TN "ClipboardProtector" /F')
            $taskCreateUi = Set-AutostartCheckbox $window $app.Id `
                $runtimeConfigPath $true
            $taskStateAfterCreate = Get-AutostartTaskState
            $result.autostartEvidence += [ordered]@{
                operation = "create"
                ui = $taskCreateUi
                state = $taskStateAfterCreate
            }
            $result.checks.autostartTaskCreated = $taskCreateUi -and
                $taskStateAfterCreate -eq "Enabled"
            $taskXmlQuery = Invoke-Schtasks `
                '/Query /TN "ClipboardProtector" /XML'
            $result.autostartEvidence += [ordered]@{
                operation = "query-after-create-environment-control"
                exitCode = $taskXmlQuery.exitCode
                stdoutLength = $taskXmlQuery.stdout.Length
                enabledTagIndex = $taskXmlQuery.stdout.IndexOf(
                    "<Enabled>", [StringComparison]::Ordinal)
                stdout = $taskXmlQuery.stdout
            }

            $taskDisableUi = Set-AutostartCheckbox $window $app.Id `
                $runtimeConfigPath $false
            $taskStateAfterDisable = Get-AutostartTaskState
            $result.autostartEvidence += [ordered]@{
                operation = "disable"
                ui = $taskDisableUi
                state = $taskStateAfterDisable
            }
            $result.checks.autostartTaskDisabled = $taskDisableUi -and
                $taskStateAfterDisable -eq "Disabled"

            if (-not $result.checks.autostartTaskDisabled) {
                # Environment control only: prove whether this Sandbox permits
                # schtasks disable/enable without crediting the product path.
                $controlDisable = Invoke-Schtasks `
                    '/Change /TN "ClipboardProtector" /DISABLE'
                $controlDisabledState = Get-AutostartTaskState
                $controlEnable = Invoke-Schtasks `
                    '/Change /TN "ClipboardProtector" /ENABLE'
                $controlRestoredState = Get-AutostartTaskState
                $result.autostartEvidence += [ordered]@{
                    operation = "disable-environment-control"
                    disableExitCode = $controlDisable.exitCode
                    disableStdout = $controlDisable.stdout
                    disabledState = $controlDisabledState
                    restoreExitCode = $controlEnable.exitCode
                    restoreStdout = $controlEnable.stdout
                    restoredState = $controlRestoredState
                }
            }

            $taskEnableUi = Set-AutostartCheckbox $window $app.Id `
                $runtimeConfigPath $true
            $taskStateAfterEnable = Get-AutostartTaskState
            $result.autostartEvidence += [ordered]@{
                operation = "enable"
                ui = $taskEnableUi
                state = $taskStateAfterEnable
            }
            $result.checks.autostartTaskEnabled = $taskEnableUi -and
                $taskStateAfterEnable -eq "Enabled"

            $taskDelete = Invoke-Schtasks '/Delete /TN "ClipboardProtector" /F'
            $taskStateAfterDelete = Get-AutostartTaskState
            $result.autostartEvidence += [ordered]@{
                operation = "delete"
                exitCode = $taskDelete.exitCode
                state = $taskStateAfterDelete
            }
            $result.checks.autostartTaskDeleted = $taskDelete.exitCode -eq 0 -and
                $taskStateAfterDelete -eq "Absent"
            # Synchronize config back to the final no-task state before the
            # later save-failure probe, without creating another task.
            [void](Set-AutostartCheckbox $window $app.Id `
                $runtimeConfigPath $false)
            Write-RunLog ("TASK-CHECK create=" +
                $result.checks.autostartTaskCreated + " disable=" +
                $result.checks.autostartTaskDisabled + " enable=" +
                $result.checks.autostartTaskEnabled + " delete=" +
                $result.checks.autostartTaskDeleted)

            # A directory at config.json.tmp makes the atomic save fail without
            # changing ACLs. The UI must report the failure and roll memory back.
            $configHashBeforeFailure =
                (Get-FileHash -LiteralPath $runtimeConfigPath -Algorithm SHA256).Hash
            $saveBlocker = $runtimeConfigPath + ".tmp"
            [void][IO.Directory]::CreateDirectory($saveBlocker)
            $rulesDialog = Open-AppDialog $window $app.Id 3001 210
            $failureEdit = $rulesDialog -ne [IntPtr]::Zero -and
                (Add-RuleInDialog $rulesDialog $app.Id "should-rollback.exe" 1)
            if ($rulesDialog -ne [IntPtr]::Zero) {
                [void](Invoke-DialogControlAndWait $rulesDialog 1 1500)
            }
            $saveFailureTitle = ConvertFrom-Utf16Codes `
                @(0x4fdd, 0x5b58, 0x5931, 0x8d25)
            $saveErrorDialog = Wait-AppDialog `
                $app.Id $saveFailureTitle 5000
            if ($saveErrorDialog -ne [IntPtr]::Zero) {
                $result.checks.configSaveFailureDialogShown = $true
                $result.uiDiagnostics += @(
                    [ClipboardProtectorSandboxNative]::DescribeChildWindows(
                        $saveErrorDialog))
                $okTitle = ConvertFrom-Utf16Codes @(0x786e, 0x5b9a)
                [void](Invoke-DialogButtonByTitleAndWait `
                    $saveErrorDialog $okTitle 1500)
            }
            # The exact blocker target is an empty directory created above.
            if (Test-Path -LiteralPath $saveBlocker -PathType Container) {
                Remove-Item -LiteralPath $saveBlocker -Force
            }
            $result.uiConfigAfterSaveFailure = Get-ConfigEvidence $runtimeConfigPath
            $configHashAfterFailure =
                (Get-FileHash -LiteralPath $runtimeConfigPath -Algorithm SHA256).Hash
            $failureConfigRolledBack =
                $failureEdit -and $configHashAfterFailure -eq $configHashBeforeFailure -and
                $result.uiConfigAfterSaveFailure.ruleCount -eq 1 -and
                [bool]$result.uiConfigAfterSaveFailure.blockingRuleValid -and
                -not (Test-ConfigRule $runtimeConfigPath "should-rollback.exe" $false 1)
            [void](Send-MainCommand $window 3002)
            $failureRead = Request-UiRead $signalDir 5 5000
            $result.checks.configSaveFailureRollback =
                $result.checks.configSaveFailureDialogShown -and
                $failureConfigRolledBack -and $failureRead

            # Verify the tray registration before and after restarting only the
            # disposable Sandbox shell. The app and target remain alive.
            $result.checks.explorerTrayIconPresentBeforeRestart =
                [ClipboardProtectorSandboxNative]::TrayIconHasRect($window, 1)
            $oldExplorerIds = @(
                Get-Process explorer -ErrorAction SilentlyContinue |
                    ForEach-Object Id)
            Get-Process explorer -ErrorAction SilentlyContinue |
                Stop-Process -Force
            $explorerDeadline = [DateTime]::UtcNow.AddSeconds(12)
            $newExplorerIds = @()
            while ([DateTime]::UtcNow -lt $explorerDeadline) {
                $newExplorerIds = @(
                    Get-Process explorer -ErrorAction SilentlyContinue |
                        Where-Object { $_.Id -notin $oldExplorerIds } |
                        ForEach-Object Id)
                if ($newExplorerIds.Count -gt 0) { break }
                Start-Sleep -Milliseconds 250
            }
            if ($newExplorerIds.Count -eq 0) {
                # Explorer must create the visible Sandbox shell for this test.
                [void](Start-Process -FilePath `
                    (Join-Path $env:SystemRoot "explorer.exe") -PassThru)
                $explorerDeadline = [DateTime]::UtcNow.AddSeconds(12)
                while ([DateTime]::UtcNow -lt $explorerDeadline) {
                    $newExplorerIds = @(
                        Get-Process explorer -ErrorAction SilentlyContinue |
                            Where-Object { $_.Id -notin $oldExplorerIds } |
                            ForEach-Object Id)
                    if ($newExplorerIds.Count -gt 0) { break }
                    Start-Sleep -Milliseconds 250
                }
            }
            $result.checks.explorerRestarted = $newExplorerIds.Count -gt 0
            $trayDeadline = [DateTime]::UtcNow.AddSeconds(12)
            while ([DateTime]::UtcNow -lt $trayDeadline) {
                if ([ClipboardProtectorSandboxNative]::TrayIconHasRect($window, 1)) {
                    $result.checks.explorerTrayIconRecovered = $true
                    break
                }
                Start-Sleep -Milliseconds 250
            }
            foreach ($checkName in @(
                "ruleDialogCancelRollback", "ruleDialogAddPersisted",
                "ruleDialogEditPersisted", "ruleDialogDeletePersisted",
                "balloonDisabledShowSuppressed",
                "balloonEnabledShowSelectedRow",
                "balloonEnabledSilentSuppressed",
                "balloonEnabledBlockSuppressed",
                "csvExportDialogCompleted", "csvUtf8Bom", "csvTenColumns",
                "csvEscapingAndFormulaProtection",
                "csvCreationFailureDialogShown",
                "autostartTaskCreated", "autostartTaskDisabled",
                "autostartTaskEnabled", "autostartTaskDeleted",
                "configSaveFailureDialogShown", "configSaveFailureRollback",
                "explorerTrayIconPresentBeforeRestart", "explorerRestarted",
                "explorerTrayIconRecovered", "mainWindowHidden",
                "mainWindowRestored")) {
                Write-RunLog ("UI-CHECK " + $checkName + "=" +
                    $result.checks[$checkName])
            }
        }
        catch {
            $result.uiDiagnostics += $_.Exception.ToString()
            Write-RunLog ("UI scenario error: " + $_.Exception.Message)
            foreach ($controlId in @(220, 210, 200, 1)) {
                $dialog = Wait-AppDialogWithControl $app.Id $controlId 100
                if ($dialog -ne [IntPtr]::Zero) {
                    [void](Post-DialogControlClick $dialog 2)
                }
            }
        }
    }

    $result.configBeforeAppExit = Get-ConfigEvidence $runtimeConfigPath
    $result.configBackupBeforeAppExit = Get-ConfigEvidence $runtimeBackupPath
    $result.checks.blockingConfigVerifiedBeforeAppExit =
        [bool]$result.configBeforeAppExit.blockingRuleValid
    Save-ConfigSnapshot $runtimeConfigPath (Join-Path $localRoot "config-before-exit.json")
    Save-ConfigSnapshot $runtimeBackupPath (Join-Path $localRoot "config-before-exit.json.bak")

    if ($threadId -ne 0 -and -not $app.HasExited) {
        # WM_QUIT makes the normal message loop return; mainloop then stops the
        # pipe, removes the Hook, releases COM, and closes the single-instance handle.
        $result.checks.gracefulQuitPosted =
            [ClipboardProtectorSandboxNative]::PostThreadMessage(
                $threadId, 0x0012, [IntPtr]::Zero, [IntPtr]::Zero)
    }
    Write-RunLog ("Graceful WM_QUIT posted: " + $result.checks.gracefulQuitPosted)

    if ($result.checks.gracefulQuitPosted) {
        $result.checks.appExitedAfterQuit = $app.WaitForExit(10000)
    }
    if ($result.checks.appExitedAfterQuit) {
        $result.appExitCode = $app.ExitCode
        if (-not $client.HasExited) {
            $result.checks.targetAliveAfterAppExit = $true
            $unloadDeadline = [DateTime]::UtcNow.AddSeconds(5)
            while ([DateTime]::UtcNow -lt $unloadDeadline) {
                $moduleLoaded = Test-HookModuleLoaded $client.Id
                if ($moduleLoaded -eq $false) {
                    $result.checks.hookDllReleasedAfterAppExit = $true
                    break
                }
                Start-Sleep -Milliseconds 50
            }
            Set-Content -LiteralPath (Join-Path $signalDir "app-exited.signal") `
                -Value "app-exited" -Encoding ASCII
        }
    }
    Write-RunLog ("Application exited after quit: " + $result.checks.appExitedAfterQuit)
    Write-RunLog ("HookDll released after app exit: " +
        $result.checks.hookDllReleasedAfterAppExit)

    $clientWaitMs = ($ClientDurationSeconds + 5) * 1000
    $result.checks.clientExitedNaturally = $client.WaitForExit($clientWaitMs)
    if ($result.checks.clientExitedNaturally) {
        $client.WaitForExit()
        $result.clientExitCode = [int]$client.ExitCode
        [void](Save-CompletedOutput $clientOutTask $clientOutPath)
        [void](Save-CompletedOutput $clientErrorTask $clientErrorPath)
    }
    if (Test-Path -LiteralPath $clientOutPath) {
        $clientOutput = Get-Content -LiteralPath $clientOutPath -Raw
        $result.checks.blockedReadObserved = [bool](
            $clientOutput -match "BLOCKED SET ok READ -1 ERROR 5")
        $result.checks.pausedReadAllowed = [bool](
            $clientOutput -match "PAUSED READ [0-9]+ ERROR [0-9]+")
        $result.checks.resumedReadBlocked = [bool](
            $clientOutput -match "RESUMED READ -1 ERROR 5")
        $result.checks.hookDetachObservedByClient = [bool](
            $clientOutput -match "SANDBOX installed=1 blocked=1 paused=1 resumed=1 detached=1 post-exit=1")
        $result.checks.postExitClipboardProbeCompleted = [bool](
            $clientOutput -match "POST_EXIT SET ok READ [0-9]+")
        if ($Scenario -eq "Ui") {
            $result.checks.balloonDisabledShowSuppressed =
                $result.checks.balloonDisabledShowSuppressed -and [bool](
                    $clientOutput -match "UI1 READ [0-9]+ ERROR [0-9]+")
            $result.checks.balloonEnabledShowSelectedRow =
                $result.checks.balloonEnabledShowSelectedRow -and [bool](
                    $clientOutput -match "UI2 READ [0-9]+ ERROR [0-9]+")
            $result.checks.balloonEnabledSilentSuppressed =
                $result.checks.balloonEnabledSilentSuppressed -and [bool](
                    $clientOutput -match "UI3 READ [0-9]+ ERROR [0-9]+")
            $result.checks.balloonEnabledBlockSuppressed =
                $result.checks.balloonEnabledBlockSuppressed -and [bool](
                    $clientOutput -match "UI4 READ -1 ERROR 5")
            $result.checks.configSaveFailureRollback =
                $result.checks.configSaveFailureRollback -and [bool](
                    $clientOutput -match "UI5 READ -1 ERROR 5")
        }
    }

    if ($Scenario -eq "Ui") {
        try {
            # A second, sequential app instance verifies corrupt-config startup
            # without weakening the first instance's lifecycle assertions.
            $corruptText = '{"settings":'
            if (Test-Path -LiteralPath $runtimeBackupPath) {
                Remove-Item -LiteralPath $runtimeBackupPath -Force
            }
            [IO.File]::WriteAllText(
                $runtimeConfigPath, $corruptText,
                [Text.UTF8Encoding]::new($false))
            $result.corruptConfigEvidence = Get-ConfigEvidence $runtimeConfigPath

            $corruptClient = Start-RedirectedProcess $clientPath `
                "wait 12000" $localRoot
            $corruptClientOutTask = $corruptClient.StandardOutput.ReadToEndAsync()
            $corruptClientErrorTask = $corruptClient.StandardError.ReadToEndAsync()
            Start-Sleep -Milliseconds 300
            [Environment]::SetEnvironmentVariable(
                "CLIPBOARDPROTECTOR_ENABLE_GLOBAL_HOOK", $null, "Process")
            [Environment]::SetEnvironmentVariable(
                "CLIPBOARDPROTECTOR_TEST_TARGET_PID",
                $corruptClient.Id.ToString(), "Process")
            $corruptApp = Start-RedirectedProcess $appPath "" $localRoot
            $corruptAppOutTask = $corruptApp.StandardOutput.ReadToEndAsync()
            $corruptAppErrorTask = $corruptApp.StandardError.ReadToEndAsync()

            $corruptWindow = [IntPtr]::Zero
            $corruptThreadId = [uint32]0
            $corruptDeadline = [DateTime]::UtcNow.AddSeconds(8)
            while ([DateTime]::UtcNow -lt $corruptDeadline -and
                   -not $corruptApp.HasExited) {
                $corruptWindow =
                    [ClipboardProtectorSandboxNative]::FindWindowForProcessByClass(
                        [uint32]$corruptApp.Id, "ClipProtectorMainWnd")
                if ($corruptWindow -ne [IntPtr]::Zero) {
                    [uint32]$corruptWindowPid = 0
                    $corruptThreadId =
                        [ClipboardProtectorSandboxNative]::GetWindowThreadProcessId(
                            $corruptWindow, [ref]$corruptWindowPid)
                    if ($corruptWindowPid -eq $corruptApp.Id -and
                        $corruptThreadId -ne 0) { break }
                    $corruptWindow = [IntPtr]::Zero
                }
                Start-Sleep -Milliseconds 100
            }
            $result.checks.corruptConfigAppStarted =
                $corruptWindow -ne [IntPtr]::Zero -and -not $corruptApp.HasExited
            $result.corruptConfigBackupEvidence =
                Get-ConfigEvidence $runtimeBackupPath
            $backupText = if (Test-Path -LiteralPath $runtimeBackupPath) {
                [IO.File]::ReadAllText($runtimeBackupPath)
            } else { $null }
            $result.checks.corruptConfigBackedUp =
                -not (Test-Path -LiteralPath $runtimeConfigPath) -and
                $backupText -ceq $corruptText

            if ($corruptThreadId -ne 0 -and -not $corruptApp.HasExited) {
                [void][ClipboardProtectorSandboxNative]::PostThreadMessage(
                    $corruptThreadId, 0x0012, [IntPtr]::Zero, [IntPtr]::Zero)
            }
            $corruptExited = $corruptApp.WaitForExit(10000)
            if ($corruptExited) { $corruptApp.WaitForExit() }
            $result.checks.corruptConfigAppExited =
                $corruptExited -and $corruptApp.ExitCode -eq 0
            [void]$corruptClient.WaitForExit(15000)
            if ($corruptClient.HasExited) { $corruptClient.WaitForExit() }
            [void](Save-CompletedOutput $corruptClientOutTask $corruptClientOutPath)
            [void](Save-CompletedOutput $corruptClientErrorTask $corruptClientErrorPath)
            [void](Save-CompletedOutput $corruptAppOutTask $corruptAppOutPath)
            [void](Save-CompletedOutput $corruptAppErrorTask $corruptAppErrorPath)
        }
        catch {
            $result.uiDiagnostics += ("Corrupt config scenario: " +
                $_.Exception.ToString())
            Write-RunLog ("Corrupt config scenario error: " +
                $_.Exception.Message)
        }
    }

    $result.passed =
        $result.checks.inputHashesVerified -and
        $result.checks.blockRuleConfigWritten -and
        $result.checks.blockingConfigVerifiedAfterAppStart -and
        $result.checks.blockingConfigVerifiedBeforeAppExit -and
        $result.checks.targetWasSelfBuiltClipclient -and
        $result.checks.globalHookOptInAbsent -and
        $result.checks.startupErrorDialogAbsent -and
        $result.checks.mainWindowOwnedByApp -and
        $result.checks.mainListReceivedEvent -and
        $result.checks.hookDllObservedInClient -and
        $result.checks.blockedReadObserved -and
        $result.checks.pauseCommandProcessed -and
        $result.checks.pausedReadAllowed -and
        $result.checks.resumeCommandProcessed -and
        $result.checks.resumedReadBlocked -and
        $result.checks.gracefulQuitPosted -and
        $result.checks.appExitedAfterQuit -and
        ($result.appExitCode -eq 0) -and
        $result.checks.targetAliveAfterAppExit -and
        $result.checks.hookDetachObservedByClient -and
        $result.checks.hookDllReleasedAfterAppExit -and
        $result.checks.postExitClipboardProbeCompleted -and
        $result.checks.clientExitedNaturally -and
        ($result.clientExitCode -eq 0)
    if ($Scenario -eq "Ui") {
        $result.passed = $result.passed -and
            $result.checks.notificationBlockedSuppressed -and
            $result.checks.ruleDialogCancelRollback -and
            $result.checks.ruleDialogAddPersisted -and
            $result.checks.ruleDialogEditPersisted -and
            $result.checks.ruleDialogDeletePersisted -and
            $result.checks.balloonDisabledShowSuppressed -and
            $result.checks.balloonEnabledShowSelectedRow -and
            $result.checks.balloonEnabledSilentSuppressed -and
            $result.checks.balloonEnabledBlockSuppressed -and
            $result.checks.mainWindowHidden -and
            $result.checks.mainWindowRestored -and
            $result.checks.csvExportDialogCompleted -and
            $result.checks.csvUtf8Bom -and
            $result.checks.csvTenColumns -and
            $result.checks.csvEscapingAndFormulaProtection -and
            $result.checks.csvCreationFailureDialogShown -and
            $result.checks.autostartTaskCreated -and
            $result.checks.autostartTaskDisabled -and
            $result.checks.autostartTaskEnabled -and
            $result.checks.autostartTaskDeleted -and
            $result.checks.configSaveFailureDialogShown -and
            $result.checks.configSaveFailureRollback -and
            $result.checks.explorerTrayIconPresentBeforeRestart -and
            $result.checks.explorerRestarted -and
            $result.checks.explorerTrayIconRecovered -and
            $result.checks.corruptConfigBackedUp -and
            $result.checks.corruptConfigAppStarted -and
            $result.checks.corruptConfigAppExited
    }
}
catch {
    $result.error = $_.Exception.ToString()
    Write-RunLog ("ERROR " + $_.Exception.Message)
}
finally {
    $result.finishedUtc = [DateTime]::UtcNow.ToString("o")
    if (Get-Variable runtimeConfigPath -ErrorAction SilentlyContinue) {
        $result.configAtFinish = Get-ConfigEvidence $runtimeConfigPath
        $result.configBackupAtFinish = Get-ConfigEvidence $runtimeBackupPath
        Save-ConfigSnapshot $runtimeConfigPath (Join-Path $localRoot "config-at-finish.json")
        Save-ConfigSnapshot $runtimeBackupPath (Join-Path $localRoot "config-at-finish.json.bak")
    }
    foreach ($processInfo in @(
        @{ process = $client; kind = "client" },
        @{ process = $app; kind = "app" }
    )) {
        $process = $processInfo.process
        if ($null -eq $process) { continue }
        try {
            $process.Refresh()
            $hasExited = [bool]$process.HasExited
            if ($processInfo.kind -eq "client") {
                $result.clientHasExitedAtFinish = $hasExited
                if ($hasExited) {
                    $process.WaitForExit()
                    $result.clientExitCode = [int]$process.ExitCode
                }
            } else {
                $result.appHasExitedAtFinish = $hasExited
                if ($hasExited) {
                    $process.WaitForExit()
                    $result.appExitCode = [int]$process.ExitCode
                }
            }
        }
        catch {
            Write-RunLog ("Could not snapshot " + $processInfo.kind +
                " process state: " + $_.Exception.Message)
        }
    }
    [void](Save-CompletedOutput $clientOutTask $clientOutPath)
    [void](Save-CompletedOutput $clientErrorTask $clientErrorPath)
    [void](Save-CompletedOutput $appOutTask $appOutPath)
    [void](Save-CompletedOutput $appErrorTask $appErrorPath)
    [void](Save-CompletedOutput $corruptClientOutTask $corruptClientOutPath)
    [void](Save-CompletedOutput $corruptClientErrorTask $corruptClientErrorPath)
    [void](Save-CompletedOutput $corruptAppOutTask $corruptAppOutPath)
    [void](Save-CompletedOutput $corruptAppErrorTask $corruptAppErrorPath)
    try {
        [void](New-Item -ItemType Directory -Path $ResultDir -Force)
        $resultFile = Join-Path $localRoot "result.json"
        $result | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $resultFile -Encoding UTF8
        foreach ($path in @($resultFile, $logPath, $clientOutPath, $clientErrorPath,
                             $appOutPath, $appErrorPath,
                             $corruptClientOutPath, $corruptClientErrorPath,
                             $corruptAppOutPath, $corruptAppErrorPath,
                             $configEvidencePath,
                             $csvPath,
                             (Join-Path $localRoot "input.json"),
                             (Join-Path $localRoot "config-after-start.json"),
                             (Join-Path $localRoot "config-after-start.json.bak"),
                             (Join-Path $localRoot "config-before-exit.json"),
                             (Join-Path $localRoot "config-before-exit.json.bak"),
                             (Join-Path $localRoot "config-at-finish.json"),
                             (Join-Path $localRoot "config-at-finish.json.bak"))) {
            if (Test-Path -LiteralPath $path -PathType Leaf) {
                Copy-Item -LiteralPath $path -Destination $ResultDir -Force
            }
        }
    }
    finally {
        # A failed graceful-exit check is recorded as a failure; no process is
        # force-killed to make the lifecycle test appear successful. Shutting
        # down the disposable Sandbox happens only after the copy-out attempt.
        if (-not $ReuseSession -and -not $SingleRun) {
            Start-Process -FilePath (Join-Path $env:SystemRoot "System32\shutdown.exe") `
                -ArgumentList @("/s", "/t", "0", "/f") -WindowStyle Hidden
        }
    }
}

# In explicit reuse mode the first run remains the only long-lived controller.
# Subsequent host invocations submit one command at a time through the mapped
# result directory; each worker has an isolated local root and result folder.
if ($ReuseSession -and -not $SingleRun) {
    if ([string]::IsNullOrWhiteSpace($ReuseRoot)) {
        throw "ReuseRoot is required with ReuseSession."
    }
    $heartbeatPath = Join-Path $ReuseRoot "reuse-heartbeat.json"
    $commandPrefix = "reuse-command-"
    $controllerPid = [Diagnostics.Process]::GetCurrentProcess().Id
    $controllerStart = [Diagnostics.Process]::GetCurrentProcess().StartTime.ToUniversalTime().ToString("o")
    function Write-ReuseHeartbeat {
        $heartbeat = [ordered]@{
            schemaVersion = 1
            pid = $controllerPid
            startUtc = $controllerStart
            nonce = $RunNonce
            utc = [DateTime]::UtcNow.ToString("o")
        }
        try {
            # Mapped-folder replace operations can fail transiently after many
            # iterations. A direct heartbeat write plus tolerant host parsing
            # keeps that I/O hiccup from terminating the guest controller.
            $heartbeat | ConvertTo-Json -Depth 4 |
                Set-Content -LiteralPath $heartbeatPath -Encoding UTF8
            return $true
        }
        catch {
            Write-RunLog ("Reuse heartbeat write failed: " + $_.Exception.Message)
            return $false
        }
    }
    function Write-ReuseFailure([string]$ResultPath, [string]$Message) {
        [void](New-Item -ItemType Directory -Path $ResultPath -Force)
        [ordered]@{
            schemaVersion = 1
            scenario = "ReuseController"
            startedUtc = [DateTime]::UtcNow.ToString("o")
            finishedUtc = [DateTime]::UtcNow.ToString("o")
            passed = $false
            checks = [ordered]@{}
            error = $Message
        } | ConvertTo-Json -Depth 6 |
            Set-Content -LiteralPath (Join-Path $ResultPath "result.json") -Encoding UTF8
    }
    function Test-ReuseProcessClean {
        $leftovers = @(
            Get-Process -Name "ClipboardProtector", "clipclient", "HookHost32" `
                -ErrorAction SilentlyContinue)
        if ($leftovers.Count -ne 0) {
            Write-RunLog ("Reuse refused: leftover project process(es): " +
                (($leftovers | ForEach-Object { $_.Id }) -join ","))
            return $false
        }
        # The test configuration disables autostart, but remove a stale task
        # left by an interrupted iteration in this disposable guest.
        try {
            $task = Get-ScheduledTask -TaskName "ClipboardProtector" `
                -ErrorAction SilentlyContinue
            if ($null -ne $task) {
                Unregister-ScheduledTask -TaskName "ClipboardProtector" -Confirm:$false
            }
        }
        catch {
            Write-RunLog ("Reuse task cleanup failed: " + $_.Exception.Message)
            return $false
        }
        try {
            $configDir = Join-Path $env:APPDATA "ClipboardProtector"
            foreach ($configPath in @(
                (Join-Path $configDir "config.json"),
                (Join-Path $configDir "config.json.bak"),
                (Join-Path $configDir "config.json.tmp"))) {
                Remove-Item -LiteralPath $configPath -Force -ErrorAction SilentlyContinue
            }
            # Per-run roots contain only harness-created signal/config/log
            # state. Remove them after confirming no project process remains.
            $sandboxDriveRoot = [IO.Directory]::GetDirectoryRoot($env:SystemDrive)
            if ([IO.Path]::GetFullPath($sandboxDriveRoot) -ne
                [IO.Path]::GetFullPath(([string]$env:SystemDrive + "\"))) {
                throw "Unexpected Sandbox drive root while cleaning run state."
            }
            Get-ChildItem -LiteralPath $sandboxDriveRoot `
                -Filter "ClipboardProtectorSandboxRun-*" -Directory `
                -ErrorAction SilentlyContinue |
                Where-Object {
                    $_.Parent.FullName -eq $sandboxDriveRoot -and
                    $_.Name.StartsWith("ClipboardProtectorSandboxRun-",
                        [StringComparison]::Ordinal) -and
                    $_.FullName -ne $localRoot
                } |
                Remove-Item -Recurse -Force -ErrorAction Stop
        }
        catch {
            Write-RunLog ("Reuse state cleanup failed: " + $_.Exception.Message)
            return $false
        }
        return $true
    }
    if (Test-Path -LiteralPath $heartbeatPath -PathType Leaf) {
        Remove-Item -LiteralPath $heartbeatPath -Force
    }
    Write-ReuseHeartbeat
    try {
        while ($true) {
            Write-ReuseHeartbeat
            $commands = @(
                Get-ChildItem -LiteralPath $ReuseRoot -Filter ($commandPrefix + "*.json") `
                    -File -ErrorAction SilentlyContinue |
                    Sort-Object Name)
            foreach ($command in $commands) {
                $request = $null
                try {
                    if ($command.Name -notmatch "^reuse-command-([0-9a-f]{32})\.json$") {
                        throw "Reuse command filename is invalid."
                    }
                    $commandId = $Matches[1]
                    $request = Get-Content -LiteralPath $command.FullName -Raw |
                        ConvertFrom-Json
                    if ([int]$request.schemaVersion -ne 1 -or
                        [string]$request.sessionNonce -ne $RunNonce -or
                        [string]$request.nonce -cne $commandId -or
                        [string]$request.nonce -notmatch "^[0-9a-f]{32}$") {
                        throw "Reuse command has an invalid schema or session nonce."
                    }
                    $resultName = [string]$request.resultName
                    if ($resultName -notmatch "^[A-Za-z0-9][A-Za-z0-9._-]{0,80}$") {
                        throw "Invalid resultName in reuse command."
                    }
                    $resultPath = Join-Path $ReuseRoot $resultName
                    if ($request.kind -eq "close") {
                        if ($resultName -cne ("close-" + $commandId)) {
                            throw "Reuse close resultName does not match its command id."
                        }
                        Remove-Item -LiteralPath $command.FullName -Force
                        Remove-Item -LiteralPath $heartbeatPath -Force -ErrorAction SilentlyContinue
                        Start-Process -FilePath (Join-Path $env:SystemRoot "System32\shutdown.exe") `
                            -ArgumentList @("/s", "/t", "0", "/f") -WindowStyle Hidden
                        return
                    }
                    if ($request.kind -ne "run" -or
                        $resultName -cne $commandId -or
                        [string]$request.scenario -notin @("Lifecycle", "Ui", "Uia") -or
                        [int]$request.clientDurationSeconds -lt 20 -or
                        [int]$request.clientDurationSeconds -gt 300 -or
                        [int]$request.observationDelaySeconds -lt 5 -or
                        [int]$request.observationDelaySeconds -gt 120 -or
                        [int]$request.observationDelaySeconds -ge
                            ([int]$request.clientDurationSeconds - 3) -or
                        -not (Test-ReuseProcessClean)) {
                        throw "Reuse run rejected because guest state is not clean."
                    }
                    $inputSubdir = [string]$request.inputSubdir
                    if ($inputSubdir -notmatch "^versions\\version-[A-Za-z0-9]{32}$") {
                        throw "Reuse command has an invalid inputSubdir."
                    }
                    $childInputDir = Join-Path $InputDir $inputSubdir
                    if (-not (Test-Path -LiteralPath $childInputDir -PathType Container)) {
                        throw "Reuse command input version is missing."
                    }
                    $childArgs = @(
                        "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
                        (Join-Path $childInputDir "sandbox-entry.ps1"),
                        "-InputDir", $childInputDir, "-ResultDir", $resultPath,
                        "-Scenario", ([string]$request.scenario),
                        "-ClientDurationSeconds", ([string][int]$request.clientDurationSeconds),
                        "-ObservationDelaySeconds", ([string][int]$request.observationDelaySeconds),
                        "-RunNonce", ([string]$request.nonce), "-SingleRun")
                    $worker = Start-Process -FilePath "powershell.exe" `
                        -ArgumentList $childArgs -PassThru -WindowStyle Hidden
                    if (-not $worker.WaitForExit(1000 * 900)) {
                        throw "Reuse worker exceeded the 900 second safety limit."
                    }
                    if ($worker.ExitCode -ne 0 -or
                        -not (Test-Path -LiteralPath (Join-Path $resultPath "result.json") -PathType Leaf)) {
                        throw "Reuse worker failed (exit=$($worker.ExitCode)) or did not write result.json."
                    }
                    Remove-Item -LiteralPath $command.FullName -Force
                }
                catch {
                    $errorName = if ($null -ne $request -and
                        -not [string]::IsNullOrWhiteSpace([string]$request.resultName)) {
                        [string]$request.resultName
                    } else { "reuse-error-$([Guid]::NewGuid().ToString('N'))" }
                    if ($errorName -notmatch "^[A-Za-z0-9][A-Za-z0-9._-]{0,80}$") {
                        $errorName = "reuse-error-$([Guid]::NewGuid().ToString('N'))"
                    }
                    $errorResult = Join-Path $ReuseRoot $errorName
                    Write-ReuseFailure $errorResult $_.Exception.Message
                    Remove-Item -LiteralPath $command.FullName -Force -ErrorAction SilentlyContinue
                }
            }
            Start-Sleep -Seconds 1
        }
    }
    finally {
        Remove-Item -LiteralPath $heartbeatPath -Force -ErrorAction SilentlyContinue
    }
}
