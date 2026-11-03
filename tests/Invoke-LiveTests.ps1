$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
if ($env:COMPUTERNAME -ine 'W11Test') { throw 'Unexpected live-test VM' }
$pocRoot = 'C:\dev\WfpFtpGuard-Poc'
$runRoot = 'C:\dev\tmp-scripts\wfp-live-' + (Get-Date -Format 'yyyyMMdd-HHmmss')
New-Item -ItemType Directory -Path $runRoot | Out-Null
$statePath = 'C:\dev\tmp-scripts\wfp-live-state.json'
$liveState = [ordered]@{Hostname=$env:COMPUTERNAME; Stage='Starting'; RunDirectory=$runRoot; Cases=@(); Error=$null; DriverSummary=$null; EtwSummary=$null; EtwOnlyFtpSpecific=$false}
$ownedProcesses = New-Object System.Collections.ArrayList
function Save-LiveState {
    $stateJson = $liveState | ConvertTo-Json -Depth 6
    for ($attempt = 0; $attempt -lt 10; $attempt++) {
        try { [IO.File]::WriteAllText($statePath, $stateJson, [Text.UTF8Encoding]::new($false)); return }
        catch [IO.IOException] { if ($attempt -eq 9) { throw }; Start-Sleep -Milliseconds 50 }
    }
}
function Start-LabProcess([string]$Name,[string]$Executable,[string[]]$Arguments) {
    $process = Start-Process -WindowStyle Hidden -FilePath $Executable -ArgumentList $Arguments -PassThru -RedirectStandardOutput "$runRoot\$Name.log" -RedirectStandardError "$runRoot\$Name.err.log"
    $null = $process.Handle
    $null = $ownedProcesses.Add($process)
    return $process
}
function Wait-Ready([System.Diagnostics.Process]$Process,[string]$Log,[string]$Marker) {
    $deadline = (Get-Date).AddSeconds(12)
    do {
        if ($Process.HasExited) { throw ('Process exited before ready: ' + $Log + ' output=' + (Get-Content -LiteralPath $Log -Raw -ErrorAction SilentlyContinue)) }
        if ((Test-Path -LiteralPath $Log) -and (Select-String -LiteralPath $Log -SimpleMatch $Marker -Quiet)) { return }
        Start-Sleep -Milliseconds 100
    } while ((Get-Date) -lt $deadline)
    throw ('Ready timeout: ' + $Log)
}
function Run-Client([string]$Name,[string[]]$Arguments) {
    $liveState.Stage = $Name
    Save-LiveState
    # Neutral file names prevent redirected diagnostics from becoming a "secret" file handle themselves.
    $clientLog = Join-Path $runRoot ('client-' + $liveState.Cases.Count.ToString('D2') + '.log')
    & "$pocRoot\ftp-traffic.exe" @Arguments > $clientLog 2> ($clientLog + '.err')
    $exitCode = $LASTEXITCODE
    $liveState.Cases += [pscustomobject]@{Name=$Name; ExitCode=$exitCode; Log=$clientLog; Output=[IO.File]::ReadAllText($clientLog)}
    Save-LiveState
    if ($exitCode -ne 0) { throw ("Traffic case $Name failed with exit code $exitCode") }
    Write-Output ("CASE PASSED: " + $Name)
}
function Start-Server([string]$Name,[string[]]$Arguments) {
    $server = Start-LabProcess $Name "$pocRoot\ftp-traffic.exe" (@('--server','--seconds','180') + $Arguments)
    Wait-Ready $server "$runRoot\$Name.log" 'SERVER_READY'
    return $server
}
try {
    Save-LiveState
    Set-Content -LiteralPath "$runRoot\public.txt" -Value 'Public document' -Encoding UTF8
    Set-Content -LiteralPath "$runRoot\secret-name.txt" -Value 'Public document' -Encoding UTF8
    Set-Content -LiteralPath "$runRoot\innocent.txt" -Value 'A SeCrEt appears in this document.' -Encoding UTF8
    [IO.File]::WriteAllBytes("$runRoot\utf16le.txt", [Text.Encoding]::Unicode.GetBytes('A SeCrEt is here.'))
    [IO.File]::WriteAllBytes("$runRoot\utf16be.txt", [Text.Encoding]::BigEndianUnicode.GetBytes('A SeCrEt is here.'))
    [IO.File]::WriteAllBytes("$runRoot\boundary.txt", [Text.Encoding]::ASCII.GetBytes(('a' * 65533) + 'secret at a chunk boundary'))
    $null = Start-Server 'server-2121' @('--port','2121')
    $null = Start-Server 'server-high' @('--port','49237')
    $null = Start-Server 'server-v6' @('--port','49238','--ipv6')
    $httpServer = Start-Server 'server-http21' @('--port','21','--http')
    $liveState.Stage = 'Starting driver and ETW'
    Save-LiveState
    $guard = Start-LabProcess 'guard' "$pocRoot\ftp-guard.exe" @('--driver',"$pocRoot\driver\WfpFtpGuard.sys",'--app',"$pocRoot\ftp-traffic.exe",'--seconds','65')
    Wait-Ready $guard "$runRoot\guard.log" '[READY]'
    Run-Client 'no-open-file' @('--port','2121','--expect','allowed')
    Run-Client 'public-file' @('--port','2121','--file',"$runRoot\public.txt",'--expect','allowed')
    Run-Client 'secret-filename' @('--port','2121','--file',"$runRoot\secret-name.txt",'--expect','blocked')
    Run-Client 'secret-content-high-port' @('--port','49237','--file',"$runRoot\innocent.txt",'--expect','blocked')
    Run-Client 'secret-utf16-le' @('--port','49237','--file',"$runRoot\utf16le.txt",'--expect','blocked')
    Run-Client 'secret-utf16-be' @('--port','49237','--file',"$runRoot\utf16be.txt",'--expect','blocked')
    Run-Client 'secret-cross-chunk' @('--port','49237','--file',"$runRoot\boundary.txt",'--expect','blocked')
    Run-Client 'fragmented-public' @('--port','2121','--fragment','--file',"$runRoot\public.txt",'--expect','allowed')
    Run-Client 'fragmented-secret' @('--port','2121','--fragment','--file',"$runRoot\secret-name.txt",'--expect','blocked')
    Run-Client 'closed-secret-handle' @('--port','2121','--close-file','--file',"$runRoot\secret-name.txt",'--expect','allowed')
    Run-Client 'ipv6-public' @('--port','49238','--ipv6','--file',"$runRoot\public.txt",'--expect','allowed')
    Run-Client 'ipv6-secret' @('--port','49238','--ipv6','--file',"$runRoot\secret-name.txt",'--expect','blocked')
    Run-Client 'http-port21-secret' @('--port','21','--http','--file',"$runRoot\secret-name.txt",'--expect','allowed')
    $httpServer.Kill()
    $httpServer.WaitForExit()
    $null = Start-Server 'server-ftp21' @('--port','21')
    Run-Client 'ftp-port21-secret' @('--port','21','--file',"$runRoot\secret-name.txt",'--expect','blocked')
    $liveState.Stage = 'Waiting for normal driver unload'
    Save-LiveState
    if (-not $guard.WaitForExit(45000)) { throw 'Driver console did not unload in time' }
    $guardLog = Get-Content -LiteralPath "$runRoot\guard.log" -Raw
    if ($guardLog -notmatch '\[DRIVER SUMMARY\] (?:ftp_inspections|ftp)=13 (?:blocked_flows|blocked)=8 (?:allowed_decisions|allowed)=5') { throw ('Unexpected driver totals: ' + $guardLog) }
    if ($guardLog -notmatch '\[CORRELATED\]') { throw 'ETW and WFP correlation was not observed' }
    if ($guardLog -notmatch 'rule=secret-filename' -or $guardLog -notmatch 'rule=secret-content') { throw 'Required secret diagnostics were missing' }
    if ($guardLog -notmatch '\[DRIVER\] unloaded') { throw 'Driver unload diagnostic missing' }
    if (Get-Service WfpFtpGuardPoc -ErrorAction SilentlyContinue) { throw 'Driver service remained loaded' }
    $liveState.DriverSummary = ($guardLog -split "`r?`n" | Where-Object { $_ -like '[[]DRIVER SUMMARY]*' }) -join ''
    $liveState.EtwSummary = ($guardLog -split "`r?`n" | Where-Object { $_ -like '[[]ETW SUMMARY]*' }) -join ''
    $liveState.Stage = 'ETW-only WinINet FTP test'
    Save-LiveState
    $etw = Start-LabProcess 'etw-only' "$pocRoot\ftp-guard.exe" @('--etw-only','--app',"$pocRoot\ftp-traffic.exe",'--seconds','7')
    Wait-Ready $etw "$runRoot\etw-only.log" '[READY]'
    if (Get-Service WfpFtpGuardPoc -ErrorAction SilentlyContinue) { throw 'ETW-only mode unexpectedly loaded a driver' }
    Run-Client 'etw-only-wininet' @('--port','2121','--wininet','--expect','allowed')
    if (-not $etw.WaitForExit(15000)) { throw 'ETW-only console did not stop' }
    $etwLog = Get-Content -LiteralPath "$runRoot\etw-only.log" -Raw
    if ($etwLog -notmatch '\[CONNECTION\].*ETW/TCPIP') { throw ('ETW-only TCP metadata was not observed: ' + $etwLog) }
    $liveState.EtwOnlyFtpSpecific = $etwLog -match '\[ETW FTP\].*service=FTP'
    if (-not $liveState.EtwOnlyFtpSpecific) { Write-Output 'INFO: This WinINet FTP client emitted TCP metadata but no FTP-specific WinINet event.' }
    $liveState.Stage = 'Completed'
} catch {
    $liveState.Stage = 'Failed'
    $liveState.Error = $_.Exception.Message
} finally {
    foreach ($process in $ownedProcesses) {
        if (-not $process.HasExited) {
            # Only test fixtures or ETW-only consumers are killed here. Let the driver console exit normally.
            if ($process.ProcessName -ne 'ftp-guard') { $process.Kill() }
            else { $null = $process.WaitForExit(45000) }
        }
    }
    Save-LiveState
}

if ($liveState.Stage -ne 'Completed') { throw $liveState.Error }
