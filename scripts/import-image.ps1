<#
.SYNOPSIS
    Загружает образ local-triage:latest из архива, сохранённого export-image.ps1, – для машины без интернета.

.DESCRIPTION
    Если рядом с архивом лежит файл .sha256, сначала сверяет контрольную сумму. После загрузки запускайте
    приложение обычным start.ps1 (без -Build: сборка без интернета невозможна).

.PARAMETER Path
    Путь к архиву образа (.tar).

.EXAMPLE
    .\scripts\import-image.ps1 -Path E:\перенос\local-triage-image.tar
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Path
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
    Write-Host "Архив не найден: $Path" -ForegroundColor Red
    exit 1
}

$sumFile = "$Path.sha256"
if (Test-Path -LiteralPath $sumFile -PathType Leaf) {
    $expected = ((Get-Content -LiteralPath $sumFile -TotalCount 1) -split '\s+')[0].ToLowerInvariant()
    # средствами .NET: Get-FileHash доступен не при любом окружении Windows PowerShell
    $sha = [Security.Cryptography.SHA256]::Create()
    $stream = [IO.File]::OpenRead((Resolve-Path -LiteralPath $Path).Path)
    $actual = ([BitConverter]::ToString($sha.ComputeHash($stream)) -replace '-', '').ToLowerInvariant()
    $stream.Dispose()
    $sha.Dispose()
    if ($expected -ne $actual) {
        Write-Host "Контрольная сумма не совпала: ожидалась $expected, получена $actual. Архив повреждён." -ForegroundColor Red
        exit 1
    }
    Write-Host 'Контрольная сумма совпала.'
} else {
    Write-Host 'Файла .sha256 рядом нет – контрольная сумма не проверена.' -ForegroundColor Yellow
}

$manifestFile = "$Path.manifest.json"
if (-not (Test-Path -LiteralPath $manifestFile -PathType Leaf)) {
    Write-Host 'Файла .manifest.json рядом нет: образы не с чем сверить.' -ForegroundColor Red
    exit 1
}
$manifest = Get-Content -LiteralPath $manifestFile -Raw -Encoding UTF8 | ConvertFrom-Json
if (-not $manifest.app.layers -or -not $manifest.db.layers) {
    Write-Host 'В манифесте нет слоёв образов: комплект собран прежней сборкой. Выгрузите его заново: .\scripts\export-image.ps1' -ForegroundColor Red
    exit 1
}
docker load -i $Path
if ($LASTEXITCODE -ne 0) {
    Write-Host 'docker load завершился с ошибкой.' -ForegroundColor Red
    exit 1
}
$appLayers = (docker image inspect $manifest.app.image --format '{{json .RootFS.Layers}}').Trim()
if ($appLayers -ne $manifest.app.layers) {
    Write-Host "Слои образа $($manifest.app.image) отличаются от манифеста." -ForegroundColor Red
    exit 1
}
$dbLayers = (docker image inspect $manifest.db.tag --format '{{json .RootFS.Layers}}').Trim()
if ($dbLayers -ne $manifest.db.layers) {
    Write-Host "Слои образа $($manifest.db.tag) отличаются от манифеста." -ForegroundColor Red
    exit 1
}
# docker load может не сохранить дайджест: тогда Compose не найдёт образ по закреплённой ссылке. Содержимое уже сверено по слоям
$saved = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
docker image inspect $manifest.db.image --format '{{.Id}}' *> $null
$pinned = $LASTEXITCODE -eq 0
$ErrorActionPreference = $saved
if (-not $pinned) {
    $appDir = Split-Path -Parent $PSScriptRoot
    $envFile = Join-Path $appDir '.env'
    if (-not (Test-Path -LiteralPath $envFile)) {
        . (Join-Path $appDir 'start.ps1')  # только функции: .env создаётся так же, как при первом запуске, с папкой для клонов
        Initialize-EnvFile $appDir '' | Out-Null
    }
    $lines = @([IO.File]::ReadAllLines($envFile, (New-Object Text.UTF8Encoding($false))) | Where-Object { $_ -notmatch '^\s*TRIAGE_DB_IMAGE\s*=' })
    $lines += "TRIAGE_DB_IMAGE=$($manifest.db.tag)"
    [IO.File]::WriteAllLines($envFile, [string[]]$lines, (New-Object Text.UTF8Encoding($false)))
    Write-Host "Образ базы задан в .env по тегу: TRIAGE_DB_IMAGE=$($manifest.db.tag)."
}
Write-Host 'Образы загружены и сверены с манифестом. Запуск: .\start.ps1 (модели Ollama переносятся отдельно, см. README).'
