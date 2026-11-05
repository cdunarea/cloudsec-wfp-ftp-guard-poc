param(
 [Parameter(Mandatory=$true)][string]$BinaryRoot,
 [Parameter(Mandatory=$true)][string]$WorkRoot,
 [Parameter(Mandatory=$true)][string]$ResultRoot,
 [ValidateSet('Debug','Release')][string]$Configuration='Debug',
 [string]$CaseFilter='',
 [ValidateRange(1,20)][int]$Repeat=1,
 [ValidateRange(0,2048)][int]$FileSizeMiB=0,
 [ValidateSet('filler','dense')][string]$FilePattern='filler',
 [ValidateRange(10,1800)][int]$ClientTimeoutSeconds=20,
 [string]$CurlPath='C:\Windows\System32\curl.exe',
 [string]$LiveViewState='',
 [string]$CaptureHelper='',
 [switch]$NoEtw,
 [switch]$ExpectIncomplete
)
$ErrorActionPreference='Stop'
trap {
 $message=$_.Exception.Message
 if($password){$message=$message.Replace($password,'[redacted]')}
 [IO.File]::WriteAllText(($WorkRoot+'-fatal.txt'),$message)
 exit 1
}
if($env:COMPUTERNAME -ine 'W11Test'){throw 'Run only on W11Test'}
if(-not ([IO.Path]::GetFullPath($WorkRoot)).StartsWith('C:\dev\tmp-scripts\',[StringComparison]::OrdinalIgnoreCase)){throw 'Unexpected work directory'}
if(-not ([IO.Path]::GetFullPath($ResultRoot)).StartsWith('C:\dev\tests\',[StringComparison]::OrdinalIgnoreCase)){throw 'Unexpected results directory'}
[IO.Directory]::CreateDirectory($WorkRoot)|Out-Null
if((Test-Path -LiteralPath $ResultRoot) -and @(Get-ChildItem -LiteralPath $ResultRoot -Force).Count -ne 0){throw 'Choose an empty results directory for a new run'}
[IO.Directory]::CreateDirectory($ResultRoot)|Out-Null
$utf8=[Text.UTF8Encoding]::new($false)
$statePath=Join-Path $WorkRoot 'progress.json'
$server='C:\Program Files\SFTPGo\sftpgo.exe'
$serverHome='C:\dev\SFTPGoData\root'
$cert='C:\ProgramData\SFTPGo\tls\ftp-lab-cert.pem'
$curl=(Resolve-Path -LiteralPath $CurlPath).Path
$curlVersion=@(& $curl --version)[0]
if($LASTEXITCODE -ne 0){throw 'Could not identify the selected curl client'}
$ftp='C:\Windows\System32\ftp.exe'
$guard=Join-Path $BinaryRoot ($Configuration+'\ftp-guard.exe')
$driver=Join-Path $BinaryRoot 'driver\WfpFtpGuard.sys'
$account=[IO.File]::ReadAllLines('C:\Users\qauser\Downloads\SFTPGo-root-credentials.txt')
$password=@($account|Where-Object {$_.StartsWith('Password: ')})[0].Substring(10)
$account=$null
$results=[Collections.Generic.List[object]]::new()
$runToken=[Guid]::NewGuid().ToString('N').Substring(0,12)
$caseState=[ordered]@{Hostname=$env:COMPUTERNAME;Stage='starting';Current=$null;Completed=0;Passed=0;Failed=0;Error=$null}
function Save-State { [IO.File]::WriteAllText($statePath,($caseState|ConvertTo-Json),$utf8) }
function Read-LiveLog([string]$path){
 $stream=[IO.FileStream]::new($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
 $reader=[IO.StreamReader]::new($stream)
 try{return $reader.ReadToEnd()}finally{$reader.Dispose()}
}
function Sanitize([string]$value){
 $value=$value.Replace($password,'[redacted]').Replace($WorkRoot,'<test files>').Replace($BinaryRoot,'<PoC binaries>')
 return [regex]::Replace($value,'(?im)^.*\.(?:ps1|psm1|bat|cmd|py)\b.*(?:\r?\n|$)','')
}
function Run-Client([string]$exe,[string]$arguments,[string]$inputText){
 $s=[Diagnostics.ProcessStartInfo]::new()
 $s.FileName=$exe;$s.Arguments=$arguments;$s.WorkingDirectory=$WorkRoot
 $s.UseShellExecute=$false;$s.CreateNoWindow=$true;$s.WindowStyle=[Diagnostics.ProcessWindowStyle]::Hidden
 $s.RedirectStandardInput=$true;$s.RedirectStandardOutput=$true;$s.RedirectStandardError=$true
 $p=[Diagnostics.Process]::Start($s);$out=$p.StandardOutput.ReadToEndAsync();$err=$p.StandardError.ReadToEndAsync()
 try{
  $p.StandardInput.Write($inputText);$p.StandardInput.Close()
  $timeout=-not $p.WaitForExit(($ClientTimeoutSeconds+5)*1000)
  if($timeout){$p.Kill();$p.WaitForExit()}
  return [pscustomobject]@{Code=$p.ExitCode;TimedOut=$timeout;Output=(Sanitize ($out.Result+$err.Result))}
 }finally{$p.Dispose()}
}
function Run-DotNetDownload([int]$port,[string]$remote,[string]$destination){
 if(-not ('NetFtpPinnedTls' -as [type])){
  Add-Type -TypeDefinition @'
using System;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
public static class NetFtpPinnedTls {
 private static RemoteCertificateValidationCallback previous;
 public static void Enable(byte[] certificate) {
  previous = ServicePointManager.ServerCertificateValidationCallback;
  string expected = Convert.ToBase64String(certificate);
  ServicePointManager.ServerCertificateValidationCallback = (sender, cert, chain, errors) =>
   cert != null && (errors & SslPolicyErrors.RemoteCertificateNameMismatch) == 0 &&
   Convert.ToBase64String(cert.GetRawCertData()) == expected &&
   DateTime.UtcNow >= new X509Certificate2(cert).NotBefore.ToUniversalTime() &&
   DateTime.UtcNow <= new X509Certificate2(cert).NotAfter.ToUniversalTime();
 }
 public static void Restore() { ServicePointManager.ServerCertificateValidationCallback = previous; }
}
'@
 }
 $pem=[IO.File]::ReadAllText($cert)
 $der=[Convert]::FromBase64String(($pem -replace '-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s',''))
 [NetFtpPinnedTls]::Enable($der)
 $response=$null;$stream=$null;$file=$null
 try{
  $request=[Net.FtpWebRequest][Net.WebRequest]::Create(('ftp://localhost:'+$port+'/'+$remote))
  $request.Credentials=[Net.NetworkCredential]::new('root',$password)
  $request.Method=[Net.WebRequestMethods+Ftp]::DownloadFile
  $request.EnableSsl=$true;$request.UseBinary=$true;$request.UsePassive=$true
  $request.KeepAlive=$false;$request.Timeout=$ClientTimeoutSeconds*1000;$request.ReadWriteTimeout=$ClientTimeoutSeconds*1000;$request.Proxy=$null
  $response=$request.GetResponse()
  $stream=$response.GetResponseStream();$file=[IO.File]::Create($destination)
  $stream.CopyTo($file)
  return [pscustomobject]@{Code=0;TimedOut=$false;Output='FtpWebRequest explicit TLS download completed'}
 }catch{
  return [pscustomobject]@{Code=1;TimedOut=$false;Output=(Sanitize $_.Exception.Message)}
 }finally{
  if($file){$file.Dispose()};if($stream){$stream.Dispose()};if($response){$response.Close()}
  [NetFtpPinnedTls]::Restore()
 }
}
function Invoke-Case($case){
 $caseState.Stage='running';$caseState.Current=$case.Id;Save-State
 $source=Join-Path $WorkRoot ($case.Fixture+'.bin')
 $remote='netguard-'+$runToken+'-'+$case.Id+'-'+$case.Fixture+'.bin'
 $serverFile=Join-Path $serverHome $remote
 $download=Join-Path $WorkRoot ($case.Id+'-received.bin')
 $destination=if($case.Role -eq 'server'){$download}else{$serverFile}
 if($case.Role -eq 'server'){Copy-Item -LiteralPath $source -Destination $serverFile}
 if(Test-Path -LiteralPath $destination){Remove-Item -LiteralPath $destination}
 $log=Join-Path $WorkRoot ($case.Id+'-guard.log')
 $err=Join-Path $WorkRoot ($case.Id+'-guard.err')
 $eventName='Local\NetFtpCase-'+[Guid]::NewGuid().ToString('N')
 $stop=[Threading.EventWaitHandle]::new($false,[Threading.EventResetMode]::ManualReset,$eventName)
 $application=if($case.Role -eq 'server'){$server}elseif($case.Client -eq 'native'){$ftp}else{$curl}
 $arguments='--driver "'+$driver+'" --app "'+$application+'" --seconds '+($ClientTimeoutSeconds+45)+' --stop-event "'+$eventName+'"'
 if($NoEtw){$arguments+=' --no-etw'}
 $process=$null;$client=$null;$fatal=$null;$captureError=$null;$transfer=[Diagnostics.Stopwatch]::new()
 try{
  $process=Start-Process -FilePath $guard -ArgumentList $arguments -WorkingDirectory $WorkRoot -WindowStyle Hidden -PassThru -RedirectStandardOutput $log -RedirectStandardError $err
  $null=$process.Handle
  $deadline=[DateTime]::UtcNow.AddSeconds(20)
  do{
   if(Test-Path -LiteralPath $log){$text=Read-LiveLog $log;if($text.Contains('[READY]')){break}}
   if($process.HasExited){throw 'Guard exited before readiness'}
   if([DateTime]::UtcNow -ge $deadline){throw 'Guard readiness timed out'}
   $null=$stop.WaitOne(50)
  }while($true)
  if($LiveViewState){[IO.File]::WriteAllText($LiveViewState,(@{Log=$log;Case=$case.Id;Client=$case.Client;Protocol=$case.Protocol;Role=$case.Role;Stop=$false}|ConvertTo-Json),$utf8)}
  $transfer.Start()
  if($case.Client -eq 'native'){
   $operation=if($case.Role -eq 'server'){'get "'+$remote+'" "'+$download+'"'}else{'put "'+$source+'" "'+$remote+'"'}
   $inputText="open 127.0.0.1 "+$case.Port+"`r`nuser root "+$password+"`r`nbinary`r`n"+$operation+"`r`nquit`r`n"
   $client=Run-Client $ftp '-n -i' $inputText
   $inputText=$null
  }elseif($case.Client -eq 'dotnet'){
   $client=Run-DotNetDownload $case.Port $remote $download
  }else{
   $request='--config - --silent --show-error --connect-timeout 5 --max-time '+$ClientTimeoutSeconds+' --disable-epsv '
   if($case.Mode -eq 'active'){$request+='--ftp-port - --disable-eprt '}else{$request+='--ftp-pasv '}
   if($case.Protocol -eq 'FTPS'){$request+='--ssl-reqd --cacert "'+$cert+'" --ssl-no-revoke '}
   # Read through TLS close_notify instead of ending Schannel reads at FTP SIZE.
   if($case.Protocol -eq 'FTPS' -and $case.Role -eq 'server'){$request+='--ignore-content-length '}
   if($case.Protocol -eq 'FTPS-C'){$request+='--ftp-ssl-control --cacert "'+$cert+'" --ssl-no-revoke '}
   if($case.Role -eq 'server'){$request+='--output "'+$download+'" '}else{$request+='--upload-file "'+$source+'" '}
   $request+='"ftp://127.0.0.1:'+$case.Port+'/'+$remote+'"'
   $escaped=$password.Replace('\','\\').Replace('"','\"')
   $client=Run-Client $curl $request ('user = "root:'+$escaped+"`"`r`n")
   $escaped=$null
  }
  $transfer.Stop()
  if($CaptureHelper){
   try{
    $marker=if($case.Fixture -eq 'public'){'[ALLOW]'}else{'[BLOCK]'}
    $null=& $CaptureHelper ctl --session 1 post-action log --path $log --marker $marker --timeout-ms 5000
    if($LiveViewState){
     $deadline=[DateTime]::UtcNow.AddSeconds(6)
     do{
      $rendered=if(Test-Path -LiteralPath ($LiveViewState+'.rendered')){[IO.File]::ReadAllText($LiveViewState+'.rendered')|ConvertFrom-Json}else{$null}
      $position=(Read-LiveLog $log).LastIndexOf($marker,[StringComparison]::Ordinal)
      if($rendered -and $rendered.Case -eq $case.Id -and $position -ge 0 -and $rendered.Length -ge $position+$marker.Length){break}
      if([DateTime]::UtcNow -gt $deadline){throw 'Live output viewer did not render the detection'}
      $null=$stop.WaitOne(50)
     }while($true)
    }
    $windows=(& $CaptureHelper ctl --session 1 window list --visible --title-contains ('FTP GUARD LIVE - '+$case.Id))|ConvertFrom-Json
    if(-not $windows.ok -or $windows.count -ne 1){throw 'Could not uniquely identify the live guard console window'}
    $capture=(& $CaptureHelper ctl --session 1 capture window --hwnd $windows.windows[0].hwnd --out (Join-Path $ResultRoot ($case.Id+'-live.png')) --overwrite)|ConvertFrom-Json
    if(-not $capture.ok){throw 'Live console capture failed'}
   }catch{$captureError=Sanitize $_.Exception.Message}
  }
 }catch{$fatal=Sanitize $_.Exception.Message}
 finally{
  $transfer.Stop()
  $null=$stop.Set()
  if($process){
   if(-not $process.WaitForExit(20000)){$fatal='Guard did not drain/unload within 20 seconds';$process.Kill();$process.WaitForExit()}
   $guardExit=$process.ExitCode
   $process.Dispose()
  }else{$guardExit=-1}
  $stop.Dispose()
 }
 $text=if(Test-Path -LiteralPath $log){[IO.File]::ReadAllText($log)}else{''}
 $text=Sanitize $text
 if(Test-Path -LiteralPath $err){$stderr=Sanitize ([IO.File]::ReadAllText($err));if($stderr.Trim()){$text+="`r`n"+$stderr}}
 $blocked=$text -match '(?m)^\[BLOCK\].*rule=secret-(?:filename|content).*decision=accepted'
 $incomplete=$text -match '(?m)^\[BLOCK\].*rule=inspection-incomplete.*decision=accepted'
 $sourceMatched=@([regex]::Matches($text,'(?m)^\[BLOCK\].*rule=secret-(?:filename|content) file="([^"]+)".*decision=accepted') |
     Where-Object {$_.Groups[1].Value.EndsWith(($case.Fixture+'.bin'),[StringComparison]::OrdinalIgnoreCase)}).Count -gt 0
 $confirmed=$text.Contains('[FTP CONFIRMED]')
 $tlsRecognized=$text.Contains('explicit-ftps=recognized')
 $dataInspection=$text.Contains('[TRANSFER INSPECTION]')
 $bytes=if(Test-Path -LiteralPath $destination){(Get-Item -LiteralPath $destination).Length}else{0L}
 $hash=if(Test-Path -LiteralPath $destination){(Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash}else{$null}
 $expected=(Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
 $sourceBytes=(Get-Item -LiteralPath $source).Length
 $scannedBytes=0L
 foreach($match in [regex]::Matches($text,'scanned_bytes=(\d+)')){$scannedBytes+=[int64]$match.Groups[1].Value}
 $cacheHits=0L
 foreach($match in [regex]::Matches($text,'cached_files=(\d+)')){$cacheHits+=[int64]$match.Groups[1].Value}
 $etwWaits=@([regex]::Matches($text,'(?m)^\[ETW SYNC\].*elapsed_ms=(\d+)')|ForEach-Object {[int64]$_.Groups[1].Value})
 $isBlock=$ExpectIncomplete -or $case.Fixture -ne 'public'
 $pass=($null -eq $fatal) -and ($null -eq $captureError) -and $guardExit -eq 0 -and $confirmed -and $dataInspection -and
       ($case.Protocol -eq 'FTP' -or $tlsRecognized) -and
       (($isBlock -and $(if($ExpectIncomplete){$incomplete}else{$blocked -and $sourceMatched}) -and $bytes -eq 0) -or (-not $isBlock -and -not $blocked -and $hash -eq $expected -and $client.Code -eq 0)) -and
       $text.Contains('[DRIVER] unloaded') -and -not $text.Contains('[DRIVER ERROR]')
 $result=[pscustomobject][ordered]@{
  Id=$case.Id;Configuration=$Configuration;Role=$case.Role;Protocol=$case.Protocol;ProtectedApplication=[IO.Path]::GetFileName($application)
  TransferClient=if($case.Client -eq 'native'){'ftp.exe'}elseif($case.Client -eq 'dotnet'){'System.Net.FtpWebRequest'}else{'curl.exe'}
  TransferClientVersion=if($case.Client -eq 'curl'){$curlVersion}else{$null}
  Operation=if($case.Role -eq 'server'){'RETR remote pull'}else{'STOR upload'}
  DataMode=$case.Mode;Port=$case.Port;Fixture=$case.Fixture
  DownloadLengthMode=if($case.Client -eq 'curl' -and $case.Protocol -eq 'FTPS' -and $case.Role -eq 'server'){'read-to-EOF; receiver hash required'}else{'client default'}
  SourceBytes=$sourceBytes;SourceSHA256=$expected;SourcePattern=$FilePattern
  SensitiveContentOffset=if($FileSizeMiB -gt 0 -and $case.Fixture -in 'content','banner-content'){[int64]$FileSizeMiB*1MB-65536-3}else{$null}
  TransferMilliseconds=$transfer.ElapsedMilliseconds;ClientTimeLimitSeconds=$ClientTimeoutSeconds
  InspectionCount=[regex]::Matches($text,'(?m)^\[TRANSFER INSPECTION\]').Count;TotalScannedBytes=$scannedBytes
  CachedFileChecks=$cacheHits;EtwWaitTotalMilliseconds=($etwWaits|Measure-Object -Sum).Sum;EtwWaitMaximumMilliseconds=($etwWaits|Measure-Object -Maximum).Maximum
  TlsNegotiation=if($case.Protocol -eq 'FTP'){'none'}elseif($case.Client -eq 'dotnet'){'AUTH TLS (FtpWebRequest.EnableSsl)'}else{'curl default; AUTH SSL compatibility uses TLS'}
  Expected=if($ExpectIncomplete){'block-incomplete'}elseif($isBlock){'block'}else{'allow'};Passed=$pass
  FtpRecognized=$confirmed;ExplicitTlsRecognized=$tlsRecognized;OnDemandScan=$dataInspection
  SecretDecision=$blocked;IncompleteDecision=$incomplete;SourceFileMatched=$sourceMatched;ReceiverBytes=$bytes;ReceiverSHA256=$hash
  ReceiverExists=($null -ne $hash);ReceiverState=if($null -eq $hash){'absent'}elseif($bytes -eq 0){'empty'}else{'contains-data'}
  SHA256Matched=($hash -eq $expected);ClientExit=if($client){$client.Code}else{-1}
  ClientTimedOut=if($client){$client.TimedOut -or ($case.Client -eq 'curl' -and $client.Code -eq 28)}else{$false}
  WatchdogKilledClient=if($client){$client.TimedOut}else{$false};GuardExit=$guardExit
  Unloaded=$text.Contains('[DRIVER] unloaded');Error=$fatal;CaptureError=$captureError
 }
 [IO.File]::WriteAllText((Join-Path $ResultRoot ($case.Id+'-console.txt')),$text,$utf8)
 if($client -and $client.Output){[IO.File]::WriteAllText((Join-Path $WorkRoot ($case.Id+'-client.txt')),$client.Output,$utf8)}
 if(Test-Path -LiteralPath $serverFile){Remove-Item -LiteralPath $serverFile}
 if(Test-Path -LiteralPath $download){Remove-Item -LiteralPath $download}
 return $result
}
try{
 Save-State
 if(Get-Service WfpFtpGuardPoc -ErrorAction SilentlyContinue){throw 'A PoC driver service already exists; preserve it'}
 $cases=@()
 $groups=@(
  @('server','FTP','native','active',21),@('server','FTP','curl','passive',49237),
  @('server','FTPS','curl','passive',21),@('server','FTPS','curl','active',49237),
  @('client','FTP','native','active',21),@('client','FTP','curl','passive',49237),
  @('client','FTPS','curl','passive',21),@('client','FTPS','curl','active',49237),
  @('server','FTPS-C','curl','passive',49237),@('client','FTPS-C','curl','passive',49237),
  @('server','FTPS','dotnet','passive',21)
 )
 $number=0
 foreach($g in $groups){foreach($fixture in @('public','secret-name','content')){
  $number++
  $cases += [pscustomobject]@{Id=('{0:D2}' -f $number);Role=$g[0];Protocol=$g[1];Client=$g[2];Mode=$g[3];Port=$g[4];Fixture=$fixture}
 }}
 $cases+=@(
  [pscustomobject]@{Id='34';Role='server';Protocol='FTP';Client='native';Mode='active';Port=21;Fixture='banner-content'},
  [pscustomobject]@{Id='35';Role='client';Protocol='FTP';Client='curl';Mode='passive';Port=49237;Fixture='banner-content'},
  [pscustomobject]@{Id='36';Role='server';Protocol='FTPS-C';Client='curl';Mode='passive';Port=49237;Fixture='banner-content'}
 )
 if($CaseFilter){$selected=$CaseFilter.Split(',');$cases=@($cases|Where-Object {$selected -contains $_.Id})}
 if($Repeat -gt 1){
  $expanded=@()
  for($iteration=1;$iteration -le $Repeat;$iteration++){
   foreach($case in $cases){$copy=$case.PSObject.Copy();$copy.Id=$case.Id+('-r{0:D2}' -f $iteration);$expanded+=$copy}
  }
  $cases=$expanded
 }
 if($FileSizeMiB -gt 0){
  $block=[Text.Encoding]::ASCII.GetBytes('P'*1MB)
  if($FilePattern -eq 'dense'){
   $seed='xxSxSecreX'+'S'+[char]0+'S'+[char]0
   $dense=[Text.Encoding]::ASCII.GetBytes($seed * [int][Math]::Ceiling(1MB / $seed.Length))
   [Array]::Copy($dense,$block,$block.Length)
  }
  $length=[int64]$FileSizeMiB*1MB
  $file=[IO.FileStream]::new((Join-Path $WorkRoot 'public.bin'),[IO.FileMode]::Create,[IO.FileAccess]::Write,[IO.FileShare]::None,1MB,[IO.FileOptions]::SequentialScan)
  try{for($written=0L;$written -lt $length;$written+=$block.Length){$file.Write($block,0,[int][Math]::Min($block.Length,$length-$written))}}finally{$file.Dispose()}
  Copy-Item -LiteralPath (Join-Path $WorkRoot 'public.bin') -Destination (Join-Path $WorkRoot 'secret-name.bin')
  Copy-Item -LiteralPath (Join-Path $WorkRoot 'public.bin') -Destination (Join-Path $WorkRoot 'content.bin')
  $file=[IO.File]::Open((Join-Path $WorkRoot 'content.bin'),[IO.FileMode]::Open,[IO.FileAccess]::Write,[IO.FileShare]::None)
  try{$file.Position=$length-65536-3;$marker=[Text.Encoding]::ASCII.GetBytes('SeCrEt');$file.Write($marker,0,$marker.Length)}finally{$file.Dispose()}
  Copy-Item -LiteralPath (Join-Path $WorkRoot 'content.bin') -Destination (Join-Path $WorkRoot 'banner-content.bin')
  $file=[IO.File]::Open((Join-Path $WorkRoot 'banner-content.bin'),[IO.FileMode]::Open,[IO.FileAccess]::Write,[IO.FileShare]::None)
  try{$header=[Text.Encoding]::ASCII.GetBytes('220 Public-looking data header');$file.Write($header,0,$header.Length)}finally{$file.Dispose()}
 }else{
  [IO.File]::WriteAllBytes((Join-Path $WorkRoot 'public.bin'),[Text.Encoding]::UTF8.GetBytes(('Public business transfer data. '+[Environment]::NewLine)*4096))
  Copy-Item -LiteralPath (Join-Path $WorkRoot 'public.bin') -Destination (Join-Path $WorkRoot 'secret-name.bin')
  [IO.File]::WriteAllBytes((Join-Path $WorkRoot 'content.bin'),[Text.Encoding]::UTF8.GetBytes(('A'*65533)+'SeCrEt'+('Z'*65536)))
  [IO.File]::WriteAllBytes((Join-Path $WorkRoot 'banner-content.bin'),[Text.Encoding]::UTF8.GetBytes('220 Public-looking data header'+"`r`n"+('A'*65533)+'SeCrEt'))
 }
 foreach($case in $cases){
  $result=Invoke-Case $case
  $results.Add($result)
  $caseState.Completed++;if($result.Passed){$caseState.Passed++}else{$caseState.Failed++}
  Save-State
  [IO.File]::WriteAllText((Join-Path $ResultRoot 'results.json'),($results.ToArray()|ConvertTo-Json -Depth 6),$utf8)
 }
 $caseState.Stage='completed'
}catch{$caseState.Stage='failed';$caseState.Error=Sanitize $_.Exception.Message}
finally{
 Save-State
 $summary=[ordered]@{Hostname=$env:COMPUTERNAME;CompletedUtc=[DateTime]::UtcNow.ToString('o');Configuration=$Configuration;FileSizeMiB=$FileSizeMiB;ClientTimeLimitSeconds=$ClientTimeoutSeconds;Completed=$caseState.Completed;Passed=$caseState.Passed;Failed=$caseState.Failed;Error=$caseState.Error;DriverSHA256=(Get-FileHash -LiteralPath $driver).Hash;ConsoleSHA256=(Get-FileHash -LiteralPath $guard).Hash;CurlVersion=$curlVersion;CurlSHA256=(Get-FileHash -LiteralPath $curl).Hash;TlsCertificatePolicy='Explicit FTPS requires the configured lab CA; no insecure certificate bypass';TlsDecryptedByWfp=$false;Cases=$results.ToArray()}
 $json=$summary|ConvertTo-Json -Depth 7
 if($json.Contains($password) -or $json -match '(?i)\.(?:ps1|psm1|bat|cmd|py)\b'){throw 'Results sanitization failed'}
 [IO.File]::WriteAllText((Join-Path $ResultRoot 'summary.json'),$json,$utf8)
 if($LiveViewState){[IO.File]::WriteAllText($LiveViewState,'{"Stop":true}',$utf8)}
 $password=$null
}
