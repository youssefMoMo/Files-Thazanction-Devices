[CmdletBinding()]
param()

$ErrorActionPreference = 'Continue'
$policyId = '{0283ac0f-fff1-49ae-ada1-8a933130cad6}'
$policyPath = Join-Path $env:windir "System32\CodeIntegrity\CiPolicies\Active\$policyId.cip"

Write-Host 'Smart App Control diagnostic (read-only)' -ForegroundColor Cyan
Write-Host 'This script does not change Windows Security settings.'
Write-Host "Enforcement policy file present: $(Test-Path -LiteralPath $policyPath)"

try {
    $events = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-CodeIntegrity/Operational'
        Id = 3077
        StartTime = (Get-Date).AddDays(-2)
    } -ErrorAction Stop | Select-Object -First 10 TimeCreated, Id, Message

    if ($events) {
        $events | Format-List
    } else {
        Write-Host 'No Code Integrity enforcement event 3077 found in the last 48 hours.'
    }
} catch {
    Write-Warning "Could not read Code Integrity events: $($_.Exception.Message)"
}
