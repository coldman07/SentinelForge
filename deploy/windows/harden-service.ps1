param(
    [Parameter(Mandatory = $true)]
    [string]$ServiceName = "SentinelForgeWindowsSensor"
)

$service = Get-Service -Name $ServiceName -ErrorAction Stop
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script from an elevated PowerShell session."
}

# Give the service a stable SID so administrators can grant narrowly scoped
# access to its resources and security products can identify its process.
& sc.exe sidtype $ServiceName unrestricted | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Could not enable the service SID (sc.exe exit $LASTEXITCODE)." }

# Restart after crashes; do not hide persistent failures from service monitors.
& sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/15000/restart/60000 | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Could not configure service recovery (sc.exe exit $LASTEXITCODE)." }

Write-Host "Configured service SID and restart recovery for $($service.Name)."
Write-Warning "This hardens service identity and recovery. It does not prevent a local administrator or kernel driver from stopping or replacing the sensor."
