$ErrorActionPreference = "Stop"
$Source = Split-Path -Parent $MyInvocation.MyCommand.Path
$SkillsRoot = Join-Path $HOME ".agents\skills"
$Destination = Join-Path $SkillsRoot "safe-reclaim"
New-Item -ItemType Directory -Path $SkillsRoot -Force | Out-Null
$SourceFull = [IO.Path]::GetFullPath($Source).TrimEnd('\')
$DestinationFull = [IO.Path]::GetFullPath($Destination).TrimEnd('\')
if ($SourceFull -ieq $DestinationFull) {
    Write-Host "SafeReclaim is already installed at $Destination"
    exit 0
}
if (Test-Path $Destination) {
    $Stamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $Backup = "$Destination.backup-$Stamp"
    Move-Item -Path $Destination -Destination $Backup
    Write-Host "Backed up existing skill to $Backup"
}
Copy-Item -Path $Source -Destination $Destination -Recurse -Force
Write-Host "Installed SafeReclaim to $Destination"
Write-Host "Restart Codex if the skill does not appear immediately."
