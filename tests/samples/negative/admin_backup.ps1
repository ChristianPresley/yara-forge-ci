# Benign IT administration script - legitimate goodware sample.
# Backs up a folder and writes a timestamped log. No encoded commands,
# no download cradle, no AMSI tampering.

param(
    [string]$Source = "C:\Data",
    [string]$Dest   = "D:\Backups"
)

$stamp = Get-Date -Format "yyyy-MM-dd_HHmmss"
$target = Join-Path $Dest "backup_$stamp"
New-Item -ItemType Directory -Path $target -Force | Out-Null
Copy-Item -Path $Source -Destination $target -Recurse
Write-Host "Backup completed to $target"
