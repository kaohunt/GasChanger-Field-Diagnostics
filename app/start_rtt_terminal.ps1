param(
    [string]$LogPath = '',
    [string]$ElfPath = '',
    [string]$SymbolPath = '',
    [string]$SymbolUrl = 'https://raw.githubusercontent.com/kaohunt/GasChanger-Field-Diagnostics/main/symbols',
    [string[]]$Command = @()
)

$ErrorActionPreference = 'Stop'
$toolDirectory = $PSScriptRoot
Write-Host '[1/3] Locating STM32CubeIDE OpenOCD...'
$openOcdCandidates = @(Resolve-Path 'C:\ST\STM32CubeIDE_*\STM32CubeIDE\plugins\com.st.stm32cube.ide.mcu.externaltools.openocd.win32_*\tools\bin\openocd.exe' -ErrorAction SilentlyContinue |
    ForEach-Object { Get-Item -LiteralPath $_.Path } |
    Sort-Object LastWriteTime -Descending)
$scriptCandidates = @(Resolve-Path 'C:\ST\STM32CubeIDE_*\STM32CubeIDE\plugins\com.st.stm32cube.ide.mcu.debug.openocd_*\resources\openocd\st_scripts' -ErrorAction SilentlyContinue |
    ForEach-Object { Get-Item -LiteralPath $_.Path } |
    Sort-Object LastWriteTime -Descending)

if($openOcdCandidates.Count -eq 0) {
    throw 'STM32CubeIDE OpenOCD was not found under C:\ST.'
}
if($scriptCandidates.Count -eq 0) {
    throw 'STM32CubeIDE OpenOCD st_scripts directory was not found under C:\ST.'
}

$openOcd = $openOcdCandidates[0].FullName
$scripts = $scriptCandidates[0].FullName
$configuration = Join-Path $toolDirectory 'gaschanger_rtt.cfg'
$terminal = Join-Path $toolDirectory 'rtt_terminal.py'
$projectRoot = (Resolve-Path (Join-Path $toolDirectory '..\..')).Path
if(($ElfPath -eq '') -and ($SymbolPath -eq '')) {
    $defaultElfCandidates = @(
        (Join-Path $projectRoot 'tools\validation\artifacts\production\GASChanger_Rev3.elf'),
        (Join-Path $projectRoot 'Release\GASChanger_Rev3.elf')
    )
    $ElfPath = $defaultElfCandidates | Where-Object { Test-Path -LiteralPath $_ } |
        Select-Object -First 1
    if($null -eq $ElfPath) { $ElfPath = '' }
}
$symbolCache = Join-Path $env:LOCALAPPDATA 'GasChanger\symbols'
if(($SymbolUrl -eq '') -and ($null -ne $env:GASCHANGER_SYMBOL_URL)) {
    $SymbolUrl = $env:GASCHANGER_SYMBOL_URL
}
$stdoutPath = Join-Path $env:TEMP ('gaschanger-openocd-' + [guid]::NewGuid().ToString('N') + '.out.log')
$stderrPath = Join-Path $env:TEMP ('gaschanger-openocd-' + [guid]::NewGuid().ToString('N') + '.err.log')
$process = $null

function Test-RttPort {
    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $result = $client.BeginConnect('127.0.0.1', 9090, $null, $null)
        if(-not $result.AsyncWaitHandle.WaitOne(200)) { return $false }
        $client.EndConnect($result)
        return $true
    }
    catch { return $false }
    finally { $client.Dispose() }
}

try {
    Write-Host '[2/3] Attaching ST-LINK without reset or halt...'
    $process = Start-Process -FilePath $openOcd -ArgumentList @('-s', $scripts, '-f', $configuration) `
        -WindowStyle Hidden -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath -PassThru

    $deadline = [DateTime]::UtcNow.AddSeconds(12)
    $rttReady = $false
    while(([DateTime]::UtcNow -lt $deadline) -and -not $rttReady) {
        $rttReady = Test-RttPort
        if($process.HasExited) { break }
        if(-not $rttReady) { Start-Sleep -Milliseconds 150 }
    }

    if(-not $rttReady) {
        $details = (Get-Content -LiteralPath $stderrPath -Raw -ErrorAction SilentlyContinue)
        throw "RTT server did not start. Close any CubeIDE debug/CubeProgrammer session using ST-LINK.`n$details"
    }

    Write-Host '[3/3] RTT connected. Starting terminal...'
    $arguments = @($terminal)
    if($LogPath -ne '') { $arguments += @('--log', $LogPath) }
    if($ElfPath -ne '') {
        $resolvedElf = (Resolve-Path -LiteralPath $ElfPath).Path
        Write-Host "      ELF identity check: $resolvedElf"
        $arguments += @('--elf', $resolvedElf)
    }
    elseif($SymbolPath -ne '') {
        $resolvedSymbols = (Resolve-Path -LiteralPath $SymbolPath).Path
        Write-Host "      Signed symbol bundle: $resolvedSymbols"
        $arguments += @('--symbols', $resolvedSymbols)
    }
    else {
        Write-Host "      Signed symbol cache: $symbolCache"
        $arguments += @('--symbol-cache', $symbolCache)
        if($SymbolUrl -ne '') {
            Write-Host "      Public symbol URL: $SymbolUrl"
            $arguments += @('--symbol-url', $SymbolUrl)
        }
    }
    foreach($item in $Command) {
        foreach($singleCommand in ($item -split ',')) {
            $singleCommand = $singleCommand.Trim()
            if($singleCommand -ne '') {
                $arguments += @('--command', $singleCommand)
            }
        }
    }
    & python @arguments
    exit $LASTEXITCODE
}
finally {
    if(($null -ne $process) -and -not $process.HasExited) {
        Stop-Process -Id $process.Id
        $process.WaitForExit(2000) | Out-Null
    }
}
