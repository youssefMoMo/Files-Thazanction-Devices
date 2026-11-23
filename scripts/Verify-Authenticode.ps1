[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path $_ -PathType Container })]
    [string]$Directory,

    [string]$ExpectedSignerSubject
)

$ErrorActionPreference = 'Stop'
$Directory = (Resolve-Path $Directory).Path
$executableExtensions = @('.exe', '.dll', '.msi', '.sys', '.ocx', '.cpl', '.scr', '.ps1', '.psm1', '.psd1')
$files = Get-ChildItem -LiteralPath $Directory -File -Recurse |
    Where-Object { $executableExtensions -contains $_.Extension.ToLowerInvariant() }

if (-not $files) {
    throw "No executable artifacts were found in '$Directory'. Refusing to treat an empty package as signed."
}

$failed = @()
foreach ($file in $files) {
    $signature = Get-AuthenticodeSignature -LiteralPath $file.FullName
    $subject = if ($signature.SignerCertificate) { $signature.SignerCertificate.Subject } else { '<no signer>' }

    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
        $failed += ("{0}: signature status is {1} ({2})" -f $file.FullName, $signature.Status, $signature.StatusMessage)
        continue
    }

    if ($ExpectedSignerSubject -and $subject -notlike "*$ExpectedSignerSubject*") {
        $failed += ("{0}: signer '{1}' does not match expected subject '{2}'" -f $file.FullName, $subject, $ExpectedSignerSubject)
        continue
    }

    Write-Host "VALID: $($file.FullName)"
    Write-Host "       Signer: $subject"
}

if ($failed.Count -gt 0) {
    $failed | ForEach-Object { Write-Host $_ -ForegroundColor Red }
    throw 'One or more executable/code artifacts are not validly Authenticode-signed. Release blocked.'
}

Write-Host "Verified $($files.Count) Authenticode-signed executable artifact(s)." -ForegroundColor Green
