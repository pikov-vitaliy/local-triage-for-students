<#
.SYNOPSIS
    Комплект образов для закрытого контура: приложение и база в одном архиве с манифестом.

.DESCRIPTION
    Если образа приложения нет, собирает его (нужен интернет для пакетов Python). Рядом с архивом – .sha256 и .manifest.json: версия,
    платформа, ссылки на образы, их слои. По ним import-image.ps1 проверит, что всё перенеслось без повреждений. Модели Ollama сюда не
    входят: их переносят отдельно (см. README, раздел «Закрытый контур»).

.PARAMETER Out
    Путь к архиву. По умолчанию dist\local-triage-image.tar в папке репозитория.

.PARAMETER Image
    Образ приложения. По умолчанию local-triage:latest; другой тег на целевой машине задаётся в .env как TRIAGE_IMAGE.

.EXAMPLE
    .\scripts\export-image.ps1
#>
[CmdletBinding()]
param(
    [string]$Out = '',
    [string]$Image = 'local-triage:latest'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $root
$app = $Image

if (-not $Out) { $Out = Join-Path $root 'dist\local-triage-image.tar' }
$folder = Split-Path -Parent $Out
if ($folder) { New-Item -ItemType Directory -Force -Path $folder | Out-Null }

# Compose требует пароль базы уже при чтении файла, а для сборки и списка образов значение не важно: в комплект оно не попадает
$env:POSTGRES_PASSWORD = 'not-used-for-build'
if (-not (docker image ls --quiet $app)) {
    Write-Host "Образа $app нет – собираю..."
    $env:TRIAGE_IMAGE = $app
    docker compose -f docker-compose.yml build
    if ($LASTEXITCODE -ne 0) { Write-Host 'Образ не собрался.' -ForegroundColor Red; exit 1 }
    Remove-Item Env:TRIAGE_IMAGE
    if (-not (docker image ls --quiet $app)) { Write-Host "После сборки нет образа $app." -ForegroundColor Red; exit 1 }
}
$db = @(docker compose -f docker-compose.yml config --images) | Where-Object { $_ -match '^postgres:' } | Select-Object -First 1
if (-not $db) { Write-Host 'В docker-compose.yml нет образа базы.' -ForegroundColor Red; exit 1 }
Remove-Item Env:POSTGRES_PASSWORD
$saved = $ErrorActionPreference
$ErrorActionPreference = 'Continue'  # сообщение docker в stderr при 'Stop' оборвало бы Windows PowerShell 5.1 раньше проверки кода
docker image inspect $db --format '{{.Id}}' *> $null
$missing = $LASTEXITCODE -ne 0
$ErrorActionPreference = $saved
if ($missing) {
    Write-Host "Образа базы $db нет – загружаю..."
    docker pull $db
    if ($LASTEXITCODE -ne 0) { Write-Host 'Образ базы не загрузился.' -ForegroundColor Red; exit 1 }
}
$dbTag = ($db -split '@')[0]
docker tag $db $dbTag
if ($LASTEXITCODE -ne 0) { Write-Host 'Образ базы не получил тег.' -ForegroundColor Red; exit 1 }

Write-Host "Сохраняю $app и $dbTag в $Out ..."
docker save -o $Out $app $dbTag
if ($LASTEXITCODE -ne 0) { Write-Host 'docker save завершился с ошибкой.' -ForegroundColor Red; exit 1 }

$sha = [Security.Cryptography.SHA256]::Create()
$stream = [IO.File]::OpenRead((Resolve-Path -LiteralPath $Out).Path)
$hash = ([BitConverter]::ToString($sha.ComputeHash($stream)) -replace '-', '').ToLowerInvariant()
$stream.Dispose()
$sha.Dispose()
Set-Content -LiteralPath "$Out.sha256" -Value "$hash  $(Split-Path -Leaf $Out)" -Encoding ASCII
$manifest = [ordered]@{
    # слои, а не .Id: с хранилищем containerd и overlay2 .Id одного образа разный
    app = [ordered]@{ image = $app; layers = (docker image inspect $app --format '{{json .RootFS.Layers}}').Trim() }
    db = [ordered]@{ image = $db; tag = $dbTag; layers = (docker image inspect $db --format '{{json .RootFS.Layers}}').Trim() }
    platform = (docker image inspect $app --format '{{.Os}}/{{.Architecture}}').Trim()
    version = (docker run --rm --network none --entrypoint python $app -c 'import app; print(app.__version__)').Trim()
    sha256 = $hash
}
[IO.File]::WriteAllText("$Out.manifest.json", ($manifest | ConvertTo-Json -Depth 4), (New-Object Text.UTF8Encoding($false)))
$sizeMb = [math]::Round((Get-Item -LiteralPath $Out).Length / 1MB)
Write-Host "Готово: $Out ($sizeMb МБ), SHA-256: $hash"
Write-Host 'Перенесите архив, файлы .sha256 и .manifest.json и папку репозитория; на целевой машине: .\scripts\import-image.ps1 -Path <архив>, затем .\start.ps1.'
