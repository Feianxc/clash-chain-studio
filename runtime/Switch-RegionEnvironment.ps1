[CmdletBinding()]
param(
    [ValidateSet('ProxyRegion', 'Local', 'Restore')][string]$Mode = 'ProxyRegion',
    [string]$RuntimeConfigPath = '',
    [string]$SettingsPath = (Join-Path $env:USERPROFILE '.claude\settings.json')
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
if (-not $RuntimeConfigPath) {
    $RuntimeConfigPath = Join-Path $projectRoot 'output\latest\chain-runtime.json'
}
$backupDir = Join-Path $projectRoot 'data\env-snapshots'
$backupFile = Join-Path $backupDir 'BeforeLastSwitch.json'

$ianaToWin = @{
    'America/Chicago'     = @{ winTz = 'Central Standard Time';  culture = 'en-US'; locale = 'en_US.UTF-8' }
    'America/New_York'    = @{ winTz = 'Eastern Standard Time';  culture = 'en-US'; locale = 'en_US.UTF-8' }
    'America/Los_Angeles' = @{ winTz = 'Pacific Standard Time';  culture = 'en-US'; locale = 'en_US.UTF-8' }
    'America/Denver'      = @{ winTz = 'Mountain Standard Time'; culture = 'en-US'; locale = 'en_US.UTF-8' }
    'Europe/London'       = @{ winTz = 'GMT Standard Time';      culture = 'en-GB'; locale = 'en_GB.UTF-8' }
    'Europe/Berlin'       = @{ winTz = 'W. Europe Standard Time';culture = 'de-DE'; locale = 'de_DE.UTF-8' }
    'Asia/Tokyo'          = @{ winTz = 'Tokyo Standard Time';    culture = 'ja-JP'; locale = 'ja_JP.UTF-8' }
    'Asia/Singapore'      = @{ winTz = 'Singapore Standard Time';culture = 'en-SG'; locale = 'en_SG.UTF-8' }
    'Asia/Shanghai'       = @{ winTz = 'China Standard Time';    culture = 'zh-CN'; locale = 'zh_CN.UTF-8' }
}

function Write-AtomicUtf8([string]$Path, [string]$Text) {
    [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($Path)) | Out-Null
    $tmp = "$Path.$PID.tmp"
    [IO.File]::WriteAllText($tmp, $Text, [Text.UTF8Encoding]::new($false))
    [IO.File]::Move($tmp, $Path, $true)
}

function Read-CurrentSnapshot {
    return [ordered]@{
        savedAt         = [DateTime]::UtcNow.ToString('o')
        windowsTimeZone = (Get-TimeZone).Id
        culture         = (Get-ItemProperty -LiteralPath 'HKCU:\Control Panel\International' -Name LocaleName).LocaleName
        TZ              = [Environment]::GetEnvironmentVariable('TZ', 'User')
        LANG            = [Environment]::GetEnvironmentVariable('LANG', 'User')
        LC_ALL          = [Environment]::GetEnvironmentVariable('LC_ALL', 'User')
    }
}

function Update-ClaudeCodeSettings([string]$Iana, [string]$Locale, [string]$ProxyUrl) {
    if (-not (Test-Path -LiteralPath $SettingsPath -PathType Leaf)) { return }
    $obj = Get-Content -LiteralPath $SettingsPath -Raw | ConvertFrom-Json -AsHashtable -NoEnumerate
    if ($obj -isnot [Collections.IDictionary]) { throw '~/.claude/settings.json 不是有效的 JSON 对象' }
    $obj['timeZone'] = $Iana
    if (-not $obj.Contains('env') -or $obj['env'] -isnot [Collections.IDictionary]) { $obj['env'] = @{} }
    $obj['env']['TZ'] = $Iana
    $obj['env']['LANG'] = $Locale
    $obj['env']['LC_ALL'] = $Locale
    if ($ProxyUrl) {
        $obj['env']['HTTP_PROXY'] = $ProxyUrl
        $obj['env']['HTTPS_PROXY'] = $ProxyUrl
        $obj['env']['NO_PROXY'] = 'localhost,127.0.0.1,::1'
        $obj['env']['CLAUDE_CODE_PROXY_RESOLVES_HOSTS'] = '1'
    }
    Write-AtomicUtf8 $SettingsPath ($obj | ConvertTo-Json -Depth 40)
}

# 安全保护：切回本地环境前提醒活跃 Claude 进程
if ($Mode -eq 'Local') {
    $running = @(Get-Process -Name 'claude' -ErrorAction SilentlyContinue)
    if ($running.Count -gt 0) {
        throw "检测到 $($running.Count) 个正在运行的 Claude 进程，请先正常退出客户端后再切回本地环境。"
    }
}

if ($Mode -eq 'Restore') {
    if (-not (Test-Path -LiteralPath $backupFile -PathType Leaf)) {
        throw "未找到环境备份快照: $backupFile"
    }
    $snap = Get-Content -LiteralPath $backupFile -Raw | ConvertFrom-Json -AsHashtable
    Set-TimeZone -Id $snap.windowsTimeZone
    if ($snap.culture) { Set-Culture -CultureInfo $snap.culture }
    foreach ($k in @('TZ', 'LANG', 'LC_ALL')) {
        [Environment]::SetEnvironmentVariable($k, $snap[$k], 'User')
    }
    Write-Output "已恢复至切换前环境: $($snap.windowsTimeZone) / $($snap.culture)"
    exit 0
}

# 保存切换前快照
$before = Read-CurrentSnapshot
Write-AtomicUtf8 $backupFile ($before | ConvertTo-Json -Depth 10)

$targetIana = 'Asia/Shanghai'
$proxyUrl = $null
if ($Mode -eq 'ProxyRegion') {
    $targetIana = 'America/Chicago'
    if (Test-Path -LiteralPath $RuntimeConfigPath -PathType Leaf) {
        $rt = Get-Content -LiteralPath $RuntimeConfigPath -Raw | ConvertFrom-Json -AsHashtable
        if ($rt.timeZone -and $ianaToWin.ContainsKey($rt.timeZone)) { $targetIana = $rt.timeZone }
        if ($rt.windows -and $rt.windows.ruleProxyUrl) { $proxyUrl = $rt.windows.ruleProxyUrl }
    }
}

$target = $ianaToWin[$targetIana]
Set-TimeZone -Id $target.winTz
Set-Culture -CultureInfo $target.culture
[Environment]::SetEnvironmentVariable('TZ', $targetIana, 'User')
[Environment]::SetEnvironmentVariable('LANG', $target.locale, 'User')
[Environment]::SetEnvironmentVariable('LC_ALL', $target.locale, 'User')
Update-ClaudeCodeSettings -Iana $targetIana -Locale $target.locale -ProxyUrl $proxyUrl

Write-Output "环境已切换 ($Mode): $targetIana / $($target.winTz) / $($target.culture)"
