param(
    [Parameter(Mandatory=$true)][string]$DriverPath,
    [Parameter(Mandatory=$true)][string]$CertificatePath,
    [Parameter(Mandatory=$true)][string]$SignTool
)
$ErrorActionPreference = 'Stop'
$subject = 'CN=WfpFtpGuard Lab Test Signing'
$certificate = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Where-Object { $_.Subject -eq $subject -and $_.NotAfter -gt (Get-Date).AddDays(7) } | Select-Object -First 1
if (-not $certificate) {
    $certificate = New-SelfSignedCertificate -Type CodeSigningCert -Subject $subject -CertStoreLocation Cert:\CurrentUser\My -HashAlgorithm SHA256 -KeyAlgorithm RSA -KeyLength 3072 -KeyExportPolicy NonExportable -NotAfter (Get-Date).AddMonths(6)
}
Export-Certificate -Cert $certificate -FilePath $CertificatePath -Force | Out-Null
& $SignTool sign /fd SHA256 /sha1 $certificate.Thumbprint /s My $DriverPath
if ($LASTEXITCODE -ne 0) { throw 'Driver signing failed' }
Write-Output ('Driver signed with test certificate ' + $certificate.Thumbprint)
