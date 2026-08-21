param(
    [string]$LogPath = '',
    [string]$ElfPath = '',
    [string]$SymbolPath = '',
    [switch]$NoOpenOcd
)

$ErrorActionPreference = 'Stop'
$toolDirectory = $PSScriptRoot
$gui = Join-Path $toolDirectory 'rtt_gui.py'
$projectRoot = (Resolve-Path (Join-Path $toolDirectory '..\..')).Path
$arguments = @($gui)

if($LogPath -ne '') { $arguments += @('--log', $LogPath) }
if($ElfPath -eq '' -and $SymbolPath -eq '') {
    $ElfPath = @(
        (Join-Path $projectRoot 'tools\validation\artifacts\production\GASChanger_Rev3.elf'),
        (Join-Path $projectRoot 'Release\GASChanger_Rev3.elf')
    ) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    if($null -eq $ElfPath) { $ElfPath = '' }
}
if($ElfPath -ne '') { $arguments += @('--elf', (Resolve-Path -LiteralPath $ElfPath).Path) }
elseif($SymbolPath -ne '') { $arguments += @('--symbols', (Resolve-Path -LiteralPath $SymbolPath).Path) }
if($NoOpenOcd) { $arguments += '--no-openocd' }

& python @arguments
exit $LASTEXITCODE
