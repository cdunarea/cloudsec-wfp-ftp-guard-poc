param([Parameter(Mandatory=$true)][string]$StatePath)
$ErrorActionPreference='Stop'
if($env:COMPUTERNAME -ine 'W11Test'){exit 81}
if(-not ([IO.Path]::GetFullPath($StatePath)).StartsWith('C:\dev\tmp-scripts\',[StringComparison]::OrdinalIgnoreCase)){throw 'Unexpected live-view state path'}
$utf8=[Text.UTF8Encoding]::new($false)
$caseId='';$shown=0
$pause=[Threading.ManualResetEvent]::new($false)
$host.UI.RawUI.WindowTitle='FTP GUARD LIVE'
try{
 $buffer=$host.UI.RawUI.BufferSize;$buffer.Width=190;$buffer.Height=3000;$host.UI.RawUI.BufferSize=$buffer
 $window=$host.UI.RawUI.WindowSize;$window.Width=185;$window.Height=55;$host.UI.RawUI.WindowSize=$window
}catch{}
[IO.File]::WriteAllText($StatePath+'.viewer',(@{Pid=$PID;Session=(Get-Process -Id $PID).SessionId}|ConvertTo-Json),$utf8)
try{
 while($true){
  try{
   if(Test-Path -LiteralPath $StatePath){
    $state=[IO.File]::ReadAllText($StatePath)|ConvertFrom-Json
    if($state.Stop){break}
    if($state.Case -ne $caseId){
     Clear-Host
     $caseId=$state.Case;$shown=0
     $host.UI.RawUI.WindowTitle='FTP GUARD LIVE - '+$caseId
     Write-Host ('LIVE TRANSFER | W11Test | '+$state.Protocol+' | protected '+$state.Role+' | case '+$caseId) -ForegroundColor Cyan
     Write-Host ('Real transfer client: '+$(if($state.Client -eq 'native'){'Windows ftp.exe'}elseif($state.Client -eq 'dotnet'){'System.Net.FtpWebRequest'}else{'Windows curl.exe'}))
     Write-Host 'Live ftp-guard.exe output below. The elevated driver loader runs in Session 0.'
     Write-Host ''
    }
    if(Test-Path -LiteralPath $state.Log){
     $file=[IO.FileStream]::new($state.Log,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
     $reader=[IO.StreamReader]::new($file)
     try{$text=$reader.ReadToEnd()}finally{$reader.Dispose()}
     if($text.Length -gt $shown){[Console]::Write($text.Substring($shown));$shown=$text.Length}
     [IO.File]::WriteAllText($StatePath+'.rendered',(@{Case=$caseId;Length=$shown}|ConvertTo-Json),$utf8)
    }
   }
  }catch [IO.IOException]{}catch [ArgumentException]{}
  $null=$pause.WaitOne(50)
 }
}finally{$pause.Dispose()}
