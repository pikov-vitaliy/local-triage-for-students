<#
.SYNOPSIS
    Копия основной базы: pg_dump из образа базы в backups (ADR-0128, раздел 9, ADR-0133).

.DESCRIPTION
    Файл пишется под временным именем и получает своё только после успешного окончания; прежние копии не перезаписываются, а
    удаляет их только правило хранения -Keep. Рядом – сопроводительный .json: версия приложения, схема, время, размер, SHA-256,
    строки таблиц, последовательности, наибольшие номера операций и попыток Hub (граница копии). Хранится вне тома базы.

    После пройденной проверки (-Check) копия отмечается в базе приложения командой backup-note: по отметке /healthz показывает возраст
    последней проверенной копии. Сбой отметки или удаления старых копий – предупреждение, копия остаётся успешной.

.PARAMETER OutDir
    Папка копий. По умолчанию backups в папке приложения.

.PARAMETER Check
    После копии сразу проверить восстановление (restore-check.ps1).

.PARAMETER Keep
    Сколько самых новых проверенных копий оставить в папке копий; копии старше самой старой из них удаляются вместе с
    сопроводительными файлами. Действует только после пройденной проверки (-Check). По умолчанию 0 – ничего не удалять.

.PARAMETER DbContainer
    Контейнер базы. По умолчанию сервис db этой установки. Копия из контейнера, заданного параметром, в базе приложения не
    отмечается: это может быть база не этой установки.

.EXAMPLE
    .\scripts\backup-db.ps1 -Check
.EXAMPLE
    .\scripts\backup-db.ps1 -Check -Keep 14
#>
[CmdletBinding()]
param(
    [string]$OutDir = '',
    [switch]$Check,
    [int]$Keep = 0,
    [string]$DbContainer = '',
    [string]$Database = 'triage',
    [string]$User = 'triage'
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'db-common.ps1')
$root = Split-Path -Parent $PSScriptRoot
if (-not $OutDir) { $OutDir = Join-Path $root 'backups' }
if (-not (Test-DbName $Database)) { Write-Host "Имя базы: строчные латинские буквы, цифры и подчёркивание, до 30 знаков: $Database" -ForegroundColor Red; exit 1 }
if ($Keep -lt 0) { Write-Host "-Keep – число копий, которые нужно оставить; 0 – ничего не удалять: $Keep" -ForegroundColor Red; exit 1 }
$ownContainer = -not $DbContainer  # контейнер базы этой установки: только её копия отмечается в базе приложения
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss')
$name = "triage-$stamp.dump"
$final = Join-Path $OutDir $name
if (Test-Path -LiteralPath $final) { throw "Копия уже есть: $final" }
# временные файлы в папке копий – свои у каждого процесса: вторая копия с тем же именем (та же секунда, та же папка)
# не пишет в файлы первой и при отказе не удаляет её сопроводительный файл (ревью 10.11)
$partial = "$final.$PID.partial"
$metaPartial = "$final.json.$PID.partial"
# имя базы и номер процесса: две копии, начатые в одну секунду (задача по расписанию и ручной запуск, параллельные
# прогоны тестов на общем контейнере), не пишут один файл в контейнере (бэклог 122)
$inner = "/tmp/${Database}_${PID}_$name"
$version = ''
$versionFile = Join-Path $root 'app\__init__.py'
if (Test-Path -LiteralPath $versionFile) {
    $match = Select-String -LiteralPath $versionFile -Pattern '__version__\s*=\s*"([^"]+)"' | Select-Object -First 1
    if ($match) { $version = $match.Matches[0].Groups[1].Value }
}

try {
    # внутри try: Docker и база чаще всего недоступны именно здесь, а причина должна попасть в журнал задачи
    if (-not $DbContainer) { $DbContainer = Get-DbContainer $root }
    $databaseBytes = Get-DbSize $DbContainer $User $Database
    Assert-FolderSpace $OutDir $databaseBytes
    Assert-DbSpace $DbContainer $databaseBytes '/tmp'
    $before = Get-DbWalPosition $DbContainer $User
    $summary = Get-DbSummary $DbContainer $User $Database
    Invoke-InDb $DbContainer @('pg_dump', '-Fc', '-U', $User, '-d', $Database, '-f', $inner) | Out-Null
    # строки в сводке точны, только если за это время журнал не сдвинулся; иначе проверка восстановления берёт их из самой копии
    $exact = $before -eq (Get-DbWalPosition $DbContainer $User)
    $server = (Invoke-InDb $DbContainer @('psql', '-X', '-A', '-t', '-q', '-U', $User, '-d', $Database, '-c', 'SHOW server_version')) -join ''
    # бинарный файл копируется docker cp, без текстового перенаправления
    Invoke-DockerCopy "${DbContainer}:$inner" $partial
    $size = (Get-Item -LiteralPath $partial).Length
    if ($size -le 0) { throw 'Файл копии пуст.' }
    $hash = (Get-Sha256 $partial)
    $meta = [ordered]@{
        app_version = $version; postgresql = $server.Trim(); schema = $summary.schema; created_utc = $stamp
        size = $size; sha256 = $hash; tables = $summary.tables; sequences = $summary.sequences
        max_hub_op = $summary.max_hub_op; max_hub_attempt = $summary.max_hub_attempt; summary_exact = $exact; database_bytes = $databaseBytes; restore_check = $null
    }
    Write-Utf8File $metaPartial ($meta | ConvertTo-Json -Depth 5)
    # своё имя копия получает первой: Move-Item не перезаписывает – если его уже заняла другая копия, эта завершается ошибкой
    Move-Item -LiteralPath $partial -Destination $final
    Move-Item -LiteralPath $metaPartial -Destination "$final.json"
} catch {
    if (Test-Path -LiteralPath $partial) { Remove-Item -LiteralPath $partial -Force }
    if (Test-Path -LiteralPath $metaPartial) { Remove-Item -LiteralPath $metaPartial -Force }
    Write-Host "Копия не создана: $_" -ForegroundColor Red
    exit 1
} finally {
    try { Invoke-InDb $DbContainer @('rm', '-f', $inner) | Out-Null } catch { Write-Verbose "$_" }
}

Write-Host "Копия: $final ($([math]::Round($size / 1MB, 1)) МБ), SHA-256: $hash"
if (-not $Check) {
    if ($Keep -gt 0) { Write-Host 'Правило хранения (-Keep) действует только после проверенной копии: добавьте -Check. Старые копии не удалялись.' -ForegroundColor Yellow }
    exit 0
}
& (Join-Path $PSScriptRoot 'restore-check.ps1') -Dump $final -DbContainer $DbContainer -User $User
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

# Копия снята и проверена: дальше – отметка для приложения и хранение. Их сбой копию неуспешной не делает: код выхода остаётся 0,
# предупреждение попадает в вывод и вместе с ним в журнал задачи.
if ($ownContainer) {
    $checkedAt = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", [Globalization.CultureInfo]::InvariantCulture)
    $problem = ''
    try { $problem = Send-BackupNote $root $Database $name $checkedAt } catch { $problem = "$_" }
    if ($problem) {
        Write-Host "Предупреждение: копия проверена, но отметка о ней в базе приложения не записана – $problem. /healthz покажет прежний возраст проверенной копии." -ForegroundColor Yellow
    } else {
        Write-Host "Отметка о проверенной копии записана в базу приложения: $name"
    }
} else {
    Write-Host 'Контейнер базы задан параметром -DbContainer: отметка о копии в базу приложения не записывается.'
}
if ($Keep -gt 0) {
    try { Remove-OldBackups $OutDir $Keep } catch { Write-Host "Предупреждение: старые копии не разобраны – $_" -ForegroundColor Yellow }
}
exit 0
