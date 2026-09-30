[CmdletBinding()]
param(
    [string]$BuildDir = "build\dev\x64\bin\Release",
    [string]$ResultDir,
    [ValidateSet("Lifecycle", "Ui", "Uia")]
    [string]$Scenario = "Lifecycle",
    [ValidateRange(20, 300)]
    [int]$ClientDurationSeconds = 30,
    [ValidateRange(5, 120)]
    [int]$ObservationDelaySeconds = 6,
    [ValidateRange(30, 900)]
    [int]$SandboxTimeoutSeconds = 180,
    [switch]$GenerateOnly,
    # Reuse is deliberately opt-in. The default remains one fresh Sandbox
    # whose guest shuts itself down after the result is copied out.
    [switch]$ReuseSession,
    [switch]$CloseReuseSession
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\.."))
$reuseStatePath = Join-Path $repoRoot "sandbox-results\.reuse-session.json"

function Resolve-RepoPath([string]$Path) {
    if ([IO.Path]::IsPathRooted($Path)) {
        return [IO.Path]::GetFullPath($Path)
    }
    return [IO.Path]::GetFullPath((Join-Path $repoRoot $Path))
}

function ConvertTo-UtcDateTime($Value, [string]$FieldName) {
    if ($Value -is [DateTime]) {
        return ([DateTime]$Value).ToUniversalTime()
    }
    try {
        return [DateTime]::Parse(
            [string]$Value,
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
    }
    catch {
        throw "Reuse state has an invalid $FieldName timestamp."
    }
}

$requiredFiles = @("ClipboardProtector.exe", "HookDll.dll", "clipclient.exe")

function Update-ReuseStaging($State, [string]$BuildDirectory) {
    $buildPath = Resolve-RepoPath $BuildDirectory
    if (-not (Test-Path -LiteralPath $buildPath -PathType Container)) {
        throw "Build directory does not exist: $buildPath"
    }
    $staging = [IO.Path]::GetFullPath([string]$State.stagingRoot)
    $versionName = "version-" + [Guid]::NewGuid().ToString("N")
    $versionRoot = Join-Path $staging (Join-Path "versions" $versionName)
    [void](New-Item -ItemType Directory -Path $versionRoot -Force)
    foreach ($name in $requiredFiles) {
        $source = Join-Path $buildPath $name
        if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
            throw "Missing Sandbox test artifact: $source. Configure with BUILD_TESTING=ON."
        }
        $temporary = Join-Path $versionRoot ("." + $name + "." + [Guid]::NewGuid().ToString("N") + ".new")
        Copy-Item -LiteralPath $source -Destination $temporary
        Move-Item -LiteralPath $temporary -Destination (Join-Path $versionRoot $name) -Force
    }
    $scriptSource = Join-Path $PSScriptRoot "sandbox-entry.ps1"
    $scriptTemporary = Join-Path $versionRoot (".sandbox-entry." + [Guid]::NewGuid().ToString("N") + ".new")
    Copy-Item -LiteralPath $scriptSource -Destination $scriptTemporary
    Move-Item -LiteralPath $scriptTemporary -Destination (Join-Path $versionRoot "sandbox-entry.ps1") -Force
    $manifest = foreach ($name in $requiredFiles) {
        $item = Get-Item -LiteralPath (Join-Path $versionRoot $name)
        [ordered]@{ name = $name; length = $item.Length
            sha256 = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash }
    }
    $inputTemporary = Join-Path $versionRoot (".input." + [Guid]::NewGuid().ToString("N") + ".new")
    [ordered]@{
        schemaVersion = 1
        runId = [Guid]::NewGuid().ToString("N")
        generatedUtc = [DateTime]::UtcNow.ToString("o")
        sourceBuildDirectory = $buildPath
        artifacts = $manifest
    } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $inputTemporary -Encoding UTF8
    Move-Item -LiteralPath $inputTemporary -Destination (Join-Path $versionRoot "input.json") -Force
    return (Join-Path "versions" $versionName)
}

if ($ObservationDelaySeconds -ge ($ClientDurationSeconds - 3)) {
    throw "ObservationDelaySeconds must leave at least three seconds for post-exit validation."
}

function Remove-ValidatedStaging([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { return }
    $resolvedTemp = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    $resolvedPath = [IO.Path]::GetFullPath($Path)
    if (-not $resolvedPath.StartsWith($resolvedTemp, [StringComparison]::OrdinalIgnoreCase) -or
        -not [IO.Path]::GetFileName($resolvedPath).StartsWith(
            "ClipboardProtectorSandbox-", [StringComparison]::Ordinal)) {
        throw "Refusing to remove an unvalidated Sandbox staging path: $resolvedPath"
    }
    if (Test-Path -LiteralPath $resolvedPath) {
        Remove-Item -LiteralPath $resolvedPath -Recurse -Force
    }
}

function Complete-ReuseCleanup($State) {
    $stagingRemoved = $false
    for ($attempt = 0; $attempt -lt 10 -and -not $stagingRemoved; ++$attempt) {
        try {
            Remove-ValidatedStaging ([string]$State.stagingRoot)
            $stagingRemoved = $true
        }
        catch {
            if ($attempt -lt 9) { Start-Sleep -Milliseconds 500 }
        }
    }
    if (-not $stagingRemoved) {
        Write-Warning ("Reusable Sandbox is closed, but its temporary staging " +
            "directory is still busy and was retained: " + [string]$State.stagingRoot)
    }
    Remove-Item -LiteralPath $reuseStatePath -Force -ErrorAction SilentlyContinue
}

function Get-ValidatedReuseState([switch]$AllowMissingHeartbeat) {
    if (-not (Test-Path -LiteralPath $reuseStatePath -PathType Leaf)) {
        throw "No active reusable Sandbox session was found at $reuseStatePath."
    }
    $state = Get-Content -LiteralPath $reuseStatePath -Raw | ConvertFrom-Json
    foreach ($property in @("stagingRoot", "resultRoot", "sessionPid", "sessionStartUtc", "nonce")) {
        if ($null -eq $state.$property) { throw "Reuse state is missing $property." }
    }
    $staging = [IO.Path]::GetFullPath([string]$state.stagingRoot)
    $resultRoot = [IO.Path]::GetFullPath([string]$state.resultRoot)
    $tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    if (-not $staging.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase) -or
        -not [IO.Path]::GetFileName($staging).StartsWith(
            "ClipboardProtectorSandbox-", [StringComparison]::Ordinal)) {
        throw "Reuse state staging is outside the validated temporary root."
    }
    if (-not (Test-Path -LiteralPath $staging -PathType Container) -or
        -not (Test-Path -LiteralPath $resultRoot -PathType Container)) {
        throw "Reusable Sandbox staging or result root no longer exists."
    }
    $session = Get-Process -Id ([int]$state.sessionPid) -ErrorAction SilentlyContinue
    if ($null -eq $session) {
        if (-not $AllowMissingHeartbeat) {
            throw "Reuse refused: the recorded Sandbox session is no longer running."
        }
        return [ordered]@{
            state = $state; session = $null; resultRoot = $resultRoot
            heartbeatValid = $false; sessionMissing = $true
        }
    }
    if ($session.ProcessName -ne "WindowsSandboxRemoteSession") {
        throw "Reuse refused: the recorded PID no longer belongs to Windows Sandbox."
    }
    $actualStart = $session.StartTime.ToUniversalTime()
    $expectedStart = ConvertTo-UtcDateTime $state.sessionStartUtc "sessionStartUtc"
    if ($actualStart.Ticks -ne $expectedStart.Ticks) {
        throw "Reuse refused: RemoteSession PID was recycled."
    }
    $heartbeatPath = Join-Path $resultRoot "reuse-heartbeat.json"
    if (-not (Test-Path -LiteralPath $heartbeatPath -PathType Leaf)) {
        if (-not $AllowMissingHeartbeat) {
            throw "Reuse refused: guest heartbeat is missing."
        }
        return [ordered]@{
            state = $state; session = $session; resultRoot = $resultRoot
            heartbeatValid = $false; sessionMissing = $false
        }
    }
    $heartbeat = $null
    for ($attempt = 0; $attempt -lt 5 -and $null -eq $heartbeat; ++$attempt) {
        try {
            $heartbeat = Get-Content -LiteralPath $heartbeatPath -Raw |
                ConvertFrom-Json
        }
        catch {
            if ($attempt -lt 4) { Start-Sleep -Milliseconds 100 }
        }
    }
    if ($null -eq $heartbeat) {
        if (-not $AllowMissingHeartbeat) {
            throw "Reuse refused: guest heartbeat could not be parsed."
        }
        return [ordered]@{
            state = $state; session = $session; resultRoot = $resultRoot
            heartbeatValid = $false; sessionMissing = $false
        }
    }
    if ([int]$heartbeat.schemaVersion -ne 1 -or
        [int]$heartbeat.pid -le 0 -or
        [string]::IsNullOrWhiteSpace([string]$heartbeat.startUtc) -or
        [string]::IsNullOrWhiteSpace([string]$heartbeat.utc)) {
        throw "Reuse refused: guest heartbeat schema is invalid."
    }
    $heartbeatStart = ConvertTo-UtcDateTime $heartbeat.startUtc "heartbeat startUtc"
    $heartbeatTime = ConvertTo-UtcDateTime $heartbeat.utc "heartbeat utc"
    if ($heartbeatStart -gt [DateTime]::UtcNow.AddMinutes(1)) {
        throw "Reuse refused: guest heartbeat start time is in the future."
    }
    if ($heartbeat.nonce -ne [string]$state.nonce -or
        ([DateTime]::UtcNow - $heartbeatTime).TotalSeconds -gt 15) {
        if (-not $AllowMissingHeartbeat) {
            throw "Reuse refused: guest heartbeat is stale or belongs to another session."
        }
        return [ordered]@{
            state = $state; session = $session; resultRoot = $resultRoot
            heartbeatValid = $false; sessionMissing = $false
        }
    }
    return [ordered]@{
        state = $state; session = $session; resultRoot = $resultRoot
        heartbeatValid = $true; sessionMissing = $false
    }
}

function Invoke-ReuseCommand {
    param([bool]$Close, [string]$InputSubdir = "")
    $validated = Get-ValidatedReuseState -AllowMissingHeartbeat:$Close
    $state = $validated.state
    $resultRoot = $validated.resultRoot
    $commandId = [Guid]::NewGuid().ToString("N")
    $resultName = if ($Close) { "close-$commandId" } else { $commandId }
    $resultPath = Join-Path $resultRoot $resultName
    if (-not $Close) { [void](New-Item -ItemType Directory -Path $resultPath -Force) }
    if ($Close -and $validated.sessionMissing) {
        Complete-ReuseCleanup $state
        Write-Host "Reusable Sandbox had already closed; stale state was cleaned."
        return
    }
    if ($Close -and -not $validated.heartbeatValid) {
        # A dead controller cannot consume a close command. The session PID
        # and start time were already validated above, so this is the bounded
        # recovery path for an orphaned guest controller.
        Stop-Process -Id $validated.session.Id -Force
        $recoveryDeadline = [DateTime]::UtcNow.AddSeconds(30)
        do {
            $recoveryLive = @(Get-Process -Id $validated.session.Id -ErrorAction SilentlyContinue)
            if ($recoveryLive.Count -eq 0) { break }
            Start-Sleep -Milliseconds 250
        } while ([DateTime]::UtcNow -lt $recoveryDeadline)
        if ($recoveryLive.Count -ne 0) { throw "Orphaned reusable Sandbox did not close after exact-PID recovery." }
        Complete-ReuseCleanup $state
        Write-Host "Orphaned reusable Sandbox session closed: $($state.sessionPid)"
        return
    }
    $command = [ordered]@{
        schemaVersion = 1
        kind = if ($Close) { "close" } else { "run" }
        sessionNonce = [string]$state.nonce
        nonce = $commandId
        resultName = $resultName
        scenario = $Scenario
        clientDurationSeconds = $ClientDurationSeconds
        observationDelaySeconds = $ObservationDelaySeconds
        inputSubdir = $InputSubdir
    }
    $commandPath = Join-Path $resultRoot ("reuse-command-" + $commandId + ".json")
    $tempCommand = $commandPath + ".tmp"
    $command | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $tempCommand -Encoding UTF8
    Move-Item -LiteralPath $tempCommand -Destination $commandPath -Force
    if ($Close) {
        # Windows Sandbox can take over a minute to tear down its VM after the
        # guest shutdown request; keep observing only the recorded session.
        $deadline = [DateTime]::UtcNow.AddSeconds(120)
        do {
            $live = @(Get-Process -Id $validated.session.Id -ErrorAction SilentlyContinue)
            if ($live.Count -eq 0) { break }
            # The guest removes heartbeat immediately before requesting
            # shutdown. Do not wait the full VM timeout once that transition
            # is observable; the exact-PID recovery below is then safe.
            if (-not (Test-Path -LiteralPath (Join-Path $resultRoot "reuse-heartbeat.json") -PathType Leaf)) {
                Start-Sleep -Seconds 2
                if (-not (Test-Path -LiteralPath (Join-Path $resultRoot "reuse-heartbeat.json") -PathType Leaf)) {
                    break
                }
            }
            Start-Sleep -Milliseconds 250
        } while ([DateTime]::UtcNow -lt $deadline)
        if ($live.Count -ne 0) {
            # If the controller heartbeat had already disappeared, the guest
            # cannot consume another command. Stop only the exact recorded
            # PID after rechecking its start time; never enumerate/stop a
            # user's unrelated Sandbox.
            $recorded = Get-Process -Id $validated.session.Id -ErrorAction SilentlyContinue
            if ((-not $validated.heartbeatValid -or
                    -not (Test-Path -LiteralPath (Join-Path $resultRoot "reuse-heartbeat.json") -PathType Leaf)) -and
                $null -ne $recorded -and
                $recorded.StartTime.ToUniversalTime().Ticks -eq
                    (ConvertTo-UtcDateTime $state.sessionStartUtc "sessionStartUtc").Ticks) {
                Stop-Process -Id $recorded.Id -Force
                $deadline = [DateTime]::UtcNow.AddSeconds(30)
                do {
                    $live = @(Get-Process -Id $recorded.Id -ErrorAction SilentlyContinue)
                    if ($live.Count -eq 0) { break }
                    Start-Sleep -Milliseconds 250
                } while ([DateTime]::UtcNow -lt $deadline)
            }
        }
        if ($live.Count -ne 0) { throw "Guest did not close the reusable Sandbox within 120 seconds." }
        Complete-ReuseCleanup $state
        Write-Host "Reusable Sandbox session closed: $($state.sessionPid)"
        return
    }
    $resultFile = Join-Path $resultPath "result.json"
    $deadline = [DateTime]::UtcNow.AddSeconds($SandboxTimeoutSeconds)
    while ([DateTime]::UtcNow -lt $deadline -and
           -not (Test-Path -LiteralPath $resultFile -PathType Leaf)) {
        if (@(Get-Process -Id $validated.session.Id -ErrorAction SilentlyContinue).Count -eq 0) {
            throw "Reusable Sandbox closed before writing $resultFile."
        }
        Start-Sleep -Milliseconds 250
    }
    if (-not (Test-Path -LiteralPath $resultFile -PathType Leaf)) {
        throw "Reusable Sandbox did not produce a result within $SandboxTimeoutSeconds seconds."
    }
    $result = Get-Content -LiteralPath $resultFile -Raw | ConvertFrom-Json
    $updatedState = [ordered]@{}
    foreach ($property in $state.PSObject.Properties) {
        $updatedState[$property.Name] = $property.Value
    }
    $updatedState.lastRun = $commandId
    $updatedState.lastResult = $resultPath
    $updatedState.updatedUtc = [DateTime]::UtcNow.ToString("o")
    $stateTemp = $reuseStatePath + ".tmp"
    $updatedState | ConvertTo-Json -Depth 8 |
        Set-Content -LiteralPath $stateTemp -Encoding UTF8
    Move-Item -LiteralPath $stateTemp -Destination $reuseStatePath -Force
    Write-Host ("Sandbox reuse result: passed={0}, appExit={1}, clientExit={2}" -f
        $result.passed, $result.appExitCode, $result.clientExitCode)
    Write-Host "Results: $resultPath"
    if (-not $result.passed) { throw "Sandbox validation failed. See result.json and run.log." }
}

if (-not $GenerateOnly -and ($ReuseSession -or $CloseReuseSession) -and
    (Test-Path -LiteralPath $reuseStatePath -PathType Leaf)) {
    $harnessMutex = [Threading.Mutex]::new($false, "Local\ClipboardProtectorSandboxHarness")
    $owned = $false
    try {
        try { $owned = $harnessMutex.WaitOne(0) }
        catch [Threading.AbandonedMutexException] { $owned = $true }
        if (-not $owned) { throw "Another ClipboardProtector Sandbox validation is already running." }
        $validatedState = Get-ValidatedReuseState -AllowMissingHeartbeat:$CloseReuseSession.IsPresent
        if (-not $CloseReuseSession) {
            $inputSubdir = Update-ReuseStaging $validatedState.state $BuildDir
        } else {
            $inputSubdir = ""
        }
        Invoke-ReuseCommand $CloseReuseSession.IsPresent $inputSubdir
    }
    finally {
        if ($owned) { $harnessMutex.ReleaseMutex() }
        $harnessMutex.Dispose()
    }
    return
}
if (-not $GenerateOnly -and -not $ReuseSession -and -not $CloseReuseSession -and
    (Test-Path -LiteralPath $reuseStatePath -PathType Leaf)) {
    throw "An active reusable Sandbox exists. Use -ReuseSession or -CloseReuseSession; refusing to start another session."
}
if ($CloseReuseSession) {
    throw "-CloseReuseSession requires an active -ReuseSession state."
}

$buildPath = Resolve-RepoPath $BuildDir
if (-not (Test-Path -LiteralPath $buildPath -PathType Container)) {
    throw "Build directory does not exist: $buildPath"
}

foreach ($name in $requiredFiles) {
    $candidate = Join-Path $buildPath $name
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
        throw "Missing Sandbox test artifact: $candidate. Configure with BUILD_TESTING=ON."
    }
}

if ([string]::IsNullOrWhiteSpace($ResultDir)) {
    $stamp = Get-Date -Format "yyyyMMdd-HHmmss-fff"
    $ResultDir = Join-Path "sandbox-results" $stamp
}
$resultPath = Resolve-RepoPath $ResultDir
if (Test-Path -LiteralPath (Join-Path $resultPath "result.json")) {
    throw "Result directory already contains result.json: $resultPath"
}
[void](New-Item -ItemType Directory -Path $resultPath -Force)

$sandboxExe = Join-Path $env:WINDIR "System32\WindowsSandbox.exe"
if (-not $GenerateOnly -and -not (Test-Path -LiteralPath $sandboxExe -PathType Leaf)) {
    throw "Windows Sandbox is unavailable. Enable the Windows-Sandbox optional feature first."
}

$runId = [Guid]::NewGuid().ToString("N")
$stagingRoot = Join-Path ([IO.Path]::GetTempPath()) "ClipboardProtectorSandbox-$runId"
$keepStaging = $GenerateOnly.IsPresent -or $ReuseSession.IsPresent
$harnessMutex = [Threading.Mutex]::new(
    $false, "Local\ClipboardProtectorSandboxHarness")
$harnessMutexOwned = $false

try {
    if (-not $GenerateOnly) {
        try {
            $harnessMutexOwned = $harnessMutex.WaitOne(0)
        }
        catch [Threading.AbandonedMutexException] {
            $harnessMutexOwned = $true
        }
        if (-not $harnessMutexOwned) {
            throw "Another ClipboardProtector Sandbox validation is already running."
        }
    }
    [void](New-Item -ItemType Directory -Path $stagingRoot)

    foreach ($name in $requiredFiles) {
        Copy-Item -LiteralPath (Join-Path $buildPath $name) -Destination $stagingRoot
    }
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot "sandbox-entry.ps1") -Destination $stagingRoot

    $artifacts = foreach ($name in $requiredFiles) {
        $item = Get-Item -LiteralPath (Join-Path $stagingRoot $name)
        [ordered]@{
            name = $name
            length = $item.Length
            sha256 = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash
        }
    }
    [ordered]@{
        schemaVersion = 1
        runId = $runId
        generatedUtc = [DateTime]::UtcNow.ToString("o")
        sourceBuildDirectory = $buildPath
        artifacts = $artifacts
    } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $stagingRoot "input.json") -Encoding UTF8

    $escapedInput = [Security.SecurityElement]::Escape($stagingRoot)
    $escapedResult = [Security.SecurityElement]::Escape($resultPath)
    $guestResultDir = "C:\ClipboardProtectorResults"
    if ($ReuseSession) {
        $guestResultDir = Join-Path $guestResultDir $runId
    }
    $entryCommand = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\ClipboardProtectorInput\sandbox-entry.ps1 -InputDir C:\ClipboardProtectorInput -ResultDir $guestResultDir -Scenario $Scenario -ClientDurationSeconds $ClientDurationSeconds -ObservationDelaySeconds $ObservationDelaySeconds"
    if ($ReuseSession) {
        $entryCommand += " -ReuseSession -ReuseRoot C:\ClipboardProtectorResults -RunNonce $runId"
    }
    $escapedCommand = [Security.SecurityElement]::Escape($entryCommand)
    $wsb = @"
<Configuration>
  <VGpu>Disable</VGpu>
  <Networking>Disable</Networking>
  <AudioInput>Disable</AudioInput>
  <VideoInput>Disable</VideoInput>
  <PrinterRedirection>Disable</PrinterRedirection>
  <ClipboardRedirection>Disable</ClipboardRedirection>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>$escapedInput</HostFolder>
      <SandboxFolder>C:\ClipboardProtectorInput</SandboxFolder>
      <ReadOnly>true</ReadOnly>
    </MappedFolder>
    <MappedFolder>
      <HostFolder>$escapedResult</HostFolder>
      <SandboxFolder>C:\ClipboardProtectorResults</SandboxFolder>
      <ReadOnly>false</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>$escapedCommand</Command>
  </LogonCommand>
</Configuration>
"@
    $wsbPath = Join-Path $stagingRoot "ClipboardProtector.wsb"
    Set-Content -LiteralPath $wsbPath -Value $wsb -Encoding UTF8

    if ($GenerateOnly) {
        Write-Host "Generated Sandbox configuration without launching it."
        Write-Host "WSB: $wsbPath"
        Write-Host "Results: $resultPath"
        Write-Host "The temporary input directory is intentionally retained for this generated WSB."
        return
    }

    $resultRootPath = $resultPath
    if ($ReuseSession) {
        $resultRootPath = Join-Path $resultPath $runId
        [void](New-Item -ItemType Directory -Path $resultRootPath -Force)
    }
    $resultFile = Join-Path $resultRootPath "result.json"
    Write-Host "Launching an isolated Windows Sandbox test. No project executable runs on the host."
    $existingSessionIds = @(
        Get-Process WindowsSandboxRemoteSession -ErrorAction SilentlyContinue |
            ForEach-Object Id
    )
    $launcher = Start-Process -FilePath $sandboxExe `
        -ArgumentList ('"{0}"' -f $wsbPath) -PassThru
    $deadline = [DateTime]::UtcNow.AddSeconds($SandboxTimeoutSeconds)
    $launchDeadline = [DateTime]::UtcNow.AddSeconds(20)
    $sandboxSessionIds = @()
    $sessionObserved = $false
    while ([DateTime]::UtcNow -lt $deadline -and
           -not (Test-Path -LiteralPath $resultFile -PathType Leaf)) {
        $currentSessions = @(
            Get-Process WindowsSandboxRemoteSession -ErrorAction SilentlyContinue
        )
        $sandboxSessionIds = @(
            $currentSessions | Where-Object { $_.Id -notin $existingSessionIds } |
                ForEach-Object Id
        )
        if ($sandboxSessionIds.Count -gt 1) {
            $keepStaging = $true
            throw "Multiple new Windows Sandbox sessions were observed; no session will be controlled. Input remains at: $stagingRoot"
        }
        if ($sandboxSessionIds.Count -gt 0) {
            $sessionObserved = $true
        } elseif ($sessionObserved) {
            $keepStaging = $true
            throw "Windows Sandbox closed before writing result.json. Inspect: $resultPath. Input remains at: $stagingRoot"
        } elseif ([DateTime]::UtcNow -ge $launchDeadline -and $launcher.HasExited) {
            $keepStaging = $true
            throw "Windows Sandbox did not create a remote session. Launcher exit code: $($launcher.ExitCode). Input remains at: $stagingRoot"
        }
        Start-Sleep -Milliseconds 250
    }
    if (-not (Test-Path -LiteralPath $resultFile -PathType Leaf)) {
        $keepStaging = $true
        throw "Windows Sandbox did not produce a result within $SandboxTimeoutSeconds seconds. It was not force-terminated; input remains at: $stagingRoot"
    }
    if (-not $ReuseSession -and $sessionObserved -and $sandboxSessionIds.Count -gt 0) {
        # The guest entry script requests its own shutdown after copying the
        # result. Only observe that lifecycle here so an unrelated Sandbox
        # session can never be closed by this harness.
        $closeDeadline = [DateTime]::UtcNow.AddSeconds(30)
        do {
            $liveSessionIds = @(
                Get-Process -Id $sandboxSessionIds -ErrorAction SilentlyContinue |
                    ForEach-Object Id
            )
            if ($liveSessionIds.Count -eq 0) { break }
            Start-Sleep -Milliseconds 250
        } while ([DateTime]::UtcNow -lt $closeDeadline)
        if ($liveSessionIds.Count -gt 0) {
            $keepStaging = $true
            Write-Warning "Sandbox wrote its result but did not close itself; staging is retained at: $stagingRoot"
        }
    }
    $result = Get-Content -LiteralPath $resultFile -Raw | ConvertFrom-Json
    if ($ReuseSession) {
        $heartbeatPath = Join-Path $resultPath "reuse-heartbeat.json"
        $heartbeatDeadline = [DateTime]::UtcNow.AddSeconds(15)
        while ([DateTime]::UtcNow -lt $heartbeatDeadline -and
               -not (Test-Path -LiteralPath $heartbeatPath -PathType Leaf)) {
            Start-Sleep -Milliseconds 100
        }
        if (-not (Test-Path -LiteralPath $resultPath -PathType Container) -or
            $sandboxSessionIds.Count -ne 1 -or
            -not (Test-Path -LiteralPath $heartbeatPath -PathType Leaf)) {
            throw "Reusable Sandbox identity could not be established safely."
        }
        $session = Get-Process -Id $sandboxSessionIds[0] -ErrorAction Stop
        $sessionStartUtc = $session.StartTime.ToUniversalTime().ToString("o")
        $reuseState = [ordered]@{
            schemaVersion = 1
            createdUtc = [DateTime]::UtcNow.ToString("o")
            nonce = $runId
            stagingRoot = $stagingRoot
            resultRoot = $resultPath
            sessionPid = [int]$session.Id
            sessionStartUtc = $sessionStartUtc
            lastRun = $runId
            lastResult = $resultRootPath
        }
        $reuseStateTemp = $reuseStatePath + ".tmp"
        $reuseState | ConvertTo-Json -Depth 8 |
            Set-Content -LiteralPath $reuseStateTemp -Encoding UTF8
        Move-Item -LiteralPath $reuseStateTemp -Destination $reuseStatePath -Force
        Write-Host "Reusable Sandbox session retained. State: $reuseStatePath"
    }
    Write-Host ("Sandbox result: passed={0}, appExit={1}, clientExit={2}" -f
        $result.passed, $result.appExitCode, $result.clientExitCode)
    Write-Host "Results: $resultPath"
    if (-not $result.passed) {
        throw "Sandbox validation failed. See result.json and run.log."
    }
}
finally {
    if (-not $keepStaging -and (Test-Path -LiteralPath $stagingRoot)) {
        $resolvedTemp = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
        $resolvedStaging = [IO.Path]::GetFullPath($stagingRoot)
        if ($resolvedStaging.StartsWith($resolvedTemp, [StringComparison]::OrdinalIgnoreCase) -and
            [IO.Path]::GetFileName($resolvedStaging).StartsWith("ClipboardProtectorSandbox-", [StringComparison]::Ordinal)) {
            try {
                Remove-Item -LiteralPath $resolvedStaging -Recurse -Force
            }
            catch {
                Write-Warning "Could not remove Sandbox staging; retained at: $resolvedStaging"
            }
        }
    }
    if ($harnessMutexOwned) {
        $harnessMutex.ReleaseMutex()
    }
    $harnessMutex.Dispose()
}
