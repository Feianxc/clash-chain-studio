[CmdletBinding()]
param(
    [int]$Port = 4328,
    [switch]$NoBrowser,
    [switch]$ForceRestart
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$serverScript = Join-Path $projectRoot 'src\server.mjs'
$url = "http://127.0.0.1:$Port"
$healthUrl = "$url/api/health"

function Get-StudioHealth {
    try {
        $resp = Invoke-RestMethod -Uri $healthUrl -Method Get -NoProxy -TimeoutSec 2
        if ($null -ne $resp -and $resp.ok -eq $true) { return $resp }
    } catch {}
    return $null
}

function Get-LatestBackendWriteUtc {
    $srcDir = Join-Path $projectRoot 'src'
    $files = Get-ChildItem -LiteralPath $srcDir -Recurse -File -Filter '*.mjs'
    if (-not $files) { return [DateTime]::MinValue }
    return ($files | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1).LastWriteTimeUtc
}

function Stop-ExistingStudioServer {
    $escaped = [regex]::Escape($serverScript)
    $procs = Get-CimInstance -ClassName Win32_Process -Filter "Name = 'node.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -and $_.CommandLine -match $escaped }
    foreach ($p in $procs) {
        try { Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue } catch {}
    }
    Start-Sleep -Milliseconds 350
}

$health = Get-StudioHealth
$needStart = $false

if ($null -eq $health) {
    $needStart = $true
} elseif ($ForceRestart) {
    Stop-ExistingStudioServer
    $needStart = $true
} else {
    $latestCodeUtc = Get-LatestBackendWriteUtc
    $isStale = $false
    if (-not $health.PSObject.Properties['startedAt'] -or -not $health.startedAt) {
        # 旧版服务未返回 startedAt，自动重启升级到最新版
        $isStale = $true
    } else {
        try {
            $startedUtc = [DateTime]::Parse($health.startedAt).ToUniversalTime()
            if ($latestCodeUtc -gt $startedUtc) { $isStale = $true }
        } catch {
            $isStale = $true
        }
    }
    if ($isStale) {
        Write-Output '检测到后台代码已更新，正在自动重启 Chain Studio 服务...'
        Stop-ExistingStudioServer
        $needStart = $true
    }
}

if ($needStart) {
    $nodeCmd = Get-Command node.exe -ErrorAction SilentlyContinue
    if (-not $nodeCmd) {
        throw '未找到 node.exe，请先安装 Node.js 20 或以上版本。'
    }
    $env:PORT = "$Port"
    $env:HOST = '127.0.0.1'
    Start-Process -FilePath $nodeCmd.Source -ArgumentList @($serverScript) -WorkingDirectory $projectRoot -WindowStyle Hidden

    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    while ([DateTime]::UtcNow -lt $deadline) {
        if ($null -ne (Get-StudioHealth)) { break }
        Start-Sleep -Milliseconds 200
    }
    if ($null -eq (Get-StudioHealth)) {
        throw "Clash Chain Studio 启动超时，未能连接到 $healthUrl"
    }
}

if (-not $NoBrowser) {
    $edgeCandidates = @(
        "$env:ProgramFiles(x86)\Microsoft\Edge\Application\msedge.exe",
        "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe"
    )
    $edgePath = $edgeCandidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
    if ($edgePath) {
        Start-Process -FilePath $edgePath -ArgumentList @("--app=$url")
    } else {
        Start-Process $url
    }
}

Write-Output "Clash Chain Studio 已就绪: $url"
