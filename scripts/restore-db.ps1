<#
.SYNOPSIS
    Аварийное восстановление основной базы из проверенной копии (ADR-0128, раздел 9).

.DESCRIPTION
    Всё, что сделано после копии, теряется. Приложение должно быть остановлено: docker compose stop triage; исполнитель Hub тоже.
    Копия восстанавливается в отдельную базу и проверяется; там же ставится пауза выдачи записи, незавершённая запись снимается: Hub мог уже
    выполнить её после копии. Только потом базы меняются именами, прежняя остаётся. Сбой до замены имён рабочую
    базу не меняет; если при замене пропал ответ сервера, исход проверяется новым подключением. Сверка – общая синхронизация с Hub и принятие её результата; запись снимается с паузы только после неё.

.PARAMETER Dump
    Файл копии, прошедшей restore-check.ps1.

.PARAMETER Confirm
    Подтверждение замены базы: без него сценарий ничего не меняет.

.PARAMETER NoAfterRestore
    Не выполнять шаг после восстановления. Для проверок: шаг выполняет образ приложения.

.EXAMPLE
    .\scripts\restore-db.ps1 -Dump backups\triage-20261104-210000.dump -Confirm
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Dump,
    [switch]$Confirm,
    [switch]$NoAfterRestore,
    [string]$DbContainer = '',
    [string]$Database = 'triage',
    [string]$User = 'triage'
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'db-common.ps1')
$root = Split-Path -Parent $PSScriptRoot
function Stop-Restore([string]$Message) { Write-Host $Message -ForegroundColor Red; exit 1 }

if (-not (Test-Path -LiteralPath $Dump -PathType Leaf)) { Stop-Restore "Нет файла копии: $Dump" }
$sidecar = "$Dump.json"
if (-not (Test-Path -LiteralPath $sidecar)) { Stop-Restore "Нет сопроводительного файла: $sidecar" }
$meta = Get-Content -LiteralPath $sidecar -Raw -Encoding UTF8 | ConvertFrom-Json
if ($meta.restore_check -ne 'пройдена') { Stop-Restore "Копия не проверена. Сначала: .\scripts\restore-check.ps1 -Dump $Dump" }
if ((Get-Sha256 $Dump) -ne $meta.sha256) { Stop-Restore 'Контрольная сумма копии не совпала.' }
if (-not $Confirm) { Stop-Restore 'Всё, что сделано после копии, будет потеряно. Запустите с -Confirm, если это решение принято.' }
if (-not (Test-DbName $Database)) { Stop-Restore "Имя базы: строчные латинские буквы, цифры и подчёркивание, до 30 знаков: $Database" }
if (-not $DbContainer) { $DbContainer = Get-DbContainer $root }

# краткое подключение служебной проверки не считается: приложение держит соединения постоянно
$busy = $true
for ($i = 0; $i -lt 3 -and $busy; $i++) {
    $busy = (Get-DbSessions $DbContainer $User $Database) -gt 0
    if ($busy) { Start-Sleep -Seconds 2 }
}
if ($busy) { Stop-Restore 'К базе подключено приложение. Остановите его: docker compose stop triage' }

$stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddHHmmss')
$fresh = "${Database}_restore_$stamp"
$previous = "${Database}_before_restore_$stamp"
$inner = "/tmp/restore_$PID.dump"
$created = $false
$switching = $false
# базы может не быть вовсе: тогда копия просто получает рабочее имя
$hadBase = ((Invoke-InDb $DbContainer @('psql', '-X', '-A', '-t', '-q', '-U', $User, '-d', 'postgres', '-c', "SELECT COUNT(*) FROM pg_database WHERE datname = '$Database'")) -join '').Trim() -eq '1'
function Invoke-Admin([string]$Sql) {
    Invoke-InDb $DbContainer @('psql', '-X', '-q', '-v', 'ON_ERROR_STOP=1', '-U', $User, '-d', 'postgres', '-c', $Sql) | Out-Null
}
try {
    # рабочая база не трогается, пока копия не восстановлена и не проверена в отдельной
    Assert-DbSpace $DbContainer (Get-DumpDatabaseBytes $meta)
    Invoke-DockerCopy $Dump "${DbContainer}:$inner"
    Invoke-Admin "CREATE DATABASE $fresh"
    $created = $true
    Invoke-InDb $DbContainer @('pg_restore', '--exit-on-error', '--single-transaction', '--no-owner', '-U', $User, '-d', $fresh, $inner) | Out-Null
    $differences = Compare-DbSummary $meta (Get-DbSummary $DbContainer $User $fresh)
    if ($differences.Count) { throw "база после восстановления отличается от сводки копии: $($differences -join '; ')" }
    if (-not $NoAfterRestore) {
        Push-Location -LiteralPath $root
        try {
            # шаг выполняется в восстановленной базе, поэтому подключение задаётся явно
            & docker compose -f docker-compose.yml run --rm --no-deps -T -e "PGDATABASE=$fresh" triage python -m app.storage.tools after-restore
            if ($LASTEXITCODE -ne 0) { throw 'шаг после восстановления не выполнен' }
        } finally {
            Pop-Location
        }
    }
    # оба имени меняются одной транзакцией: база под рабочим именем есть всегда
    $switching = $true
    if ($hadBase) {
        Invoke-Admin "BEGIN; ALTER DATABASE $Database RENAME TO $previous; ALTER DATABASE $fresh RENAME TO $Database; COMMIT;"
    } else {
        Invoke-Admin "ALTER DATABASE $fresh RENAME TO $Database"
    }
} catch {
    $failure = "$_"
    # ответ на COMMIT мог потеряться: «не изменилась» можно сказать, только дождавшись конца замены новым подключением
    $outcome = if ($switching) { Get-DbSwitchOutcome $DbContainer $User $Database $fresh $previous $hadBase } else { 'unchanged' }
    if ($outcome -eq 'unknown') {
        $how = if ($hadBase) { "есть $previous – под именем $Database восстановленная копия; нет – замены не было, под этим именем прежняя база" }
        else { "есть $Database – это восстановленная копия; нет – замены не было" }
        Stop-Restore ("Исход замены баз неизвестен: $failure. Приложение не запускайте. Когда база ответит, сначала выполните в контейнере базы " +
            "DROP DATABASE IF EXISTS ${fresh}: команда дождётся конца замены. Только после неё смотрите список баз: $how. Если замены не было, запустите восстановление заново.")
    }
    if ($outcome -eq 'switched') {
        Write-Host "Ответ сервера при замене баз пропал, но замена выполнена: $failure" -ForegroundColor Yellow
    } else {
        if ($created) { try { Invoke-Admin "DROP DATABASE IF EXISTS $fresh" } catch { Write-Host "Временная база $fresh не удалена: $_" -ForegroundColor Yellow } }
        Stop-Restore "Восстановление не прошло, рабочая база не изменилась: $failure"
    }
} finally {
    try { Invoke-InDb $DbContainer @('rm', '-f', $inner) | Out-Null } catch { Write-Verbose "$_" }
}
Write-Host 'База восстановлена, запись в Hub на паузе.' -ForegroundColor Yellow
if ($hadBase) { Write-Host "Прежняя база сохранена как ${previous}: удалите её, когда восстановленная проверена." -ForegroundColor Yellow }
Write-Host 'Дальше: запуск приложения и исполнителя, «Синхронизировать» и «Принять состояние Hub» по каждому проекту с приложением Hub; снять паузу на странице настроек (раздел Hub).' -ForegroundColor Yellow
exit 0
