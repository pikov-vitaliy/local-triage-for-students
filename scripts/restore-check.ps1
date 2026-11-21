<#
.SYNOPSIS
    Проверка копии: восстановление в отдельную базу и сверка со сводкой копии (ADR-0128, раздел 9).

.DESCRIPTION
    Проверочная база создаётся рядом с рабочей и удаляется в конце; рабочая база не меняется. Результат записывается в сопроводительный
    файл копии. pg_restore --list восстановление не заменяет, поэтому копия восстанавливается целиком.

.PARAMETER Dump
    Файл копии. Без параметра – последняя копия в backups.

.EXAMPLE
    .\scripts\restore-check.ps1
#>
[CmdletBinding()]
param(
    [string]$Dump = '',
    [string]$DbContainer = '',
    [string]$User = 'triage'
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'db-common.ps1')
$root = Split-Path -Parent $PSScriptRoot
if (-not $Dump) {
    $Dump = Get-ChildItem -LiteralPath (Join-Path $root 'backups') -Filter 'triage-*.dump' -ErrorAction SilentlyContinue |
        Sort-Object Name | Select-Object -Last 1 -ExpandProperty FullName
    if (-not $Dump) { Write-Host 'Копий нет.' -ForegroundColor Red; exit 1 }
}
if (-not $DbContainer) { $DbContainer = Get-DbContainer $root }
$sidecar = "$Dump.json"
if (-not (Test-Path -LiteralPath $sidecar)) { Write-Host "Нет сопроводительного файла: $sidecar" -ForegroundColor Red; exit 1 }
$meta = Get-Content -LiteralPath $sidecar -Raw -Encoding UTF8 | ConvertFrom-Json
$hash = (Get-Sha256 $Dump)
if ($hash -ne $meta.sha256) { Write-Host "Контрольная сумма копии не совпала: $Dump" -ForegroundColor Red; exit 1 }

$check = "restore_check_$((Get-Date).ToUniversalTime().ToString('yyyyMMddHHmmss'))_$PID"
$inner = "/tmp/$check.dump"
$result = 'не пройдена'
$code = 1
$created = $false
try {
    Assert-DbSpace $DbContainer (Get-DumpDatabaseBytes $meta)
    Invoke-DockerCopy $Dump "${DbContainer}:$inner"
    Invoke-InDb $DbContainer @('psql', '-X', '-q', '-v', 'ON_ERROR_STOP=1', '-U', $User, '-d', 'postgres', '-c', "CREATE DATABASE $check") | Out-Null
    $created = $true
    Invoke-InDb $DbContainer @('pg_restore', '--exit-on-error', '--single-transaction', '--no-owner', '-U', $User, '-d', $check, $inner) | Out-Null
    $restored = Get-DbSummary $DbContainer $User $check
    $differences = @()
    if ($meta.summary_exact -eq $false) {
        # база менялась во время копии: сравнивать не с чем, точная сводка и граница операций Hub – из самой копии
        foreach ($name in 'tables', 'sequences', 'max_hub_op', 'max_hub_attempt', 'schema') {
            $meta | Add-Member -NotePropertyName $name -NotePropertyValue $restored.$name -Force
        }
        $meta | Add-Member -NotePropertyName summary_exact -NotePropertyValue $true -Force
    } else {
        # выдача номера из запаса последовательности в журнал не пишется: равенство позиций журнала её не исключает, значения – из копии
        $meta | Add-Member -NotePropertyName sequences -NotePropertyValue $restored.sequences -Force
        $differences = Compare-DbSummary $meta $restored
    }
    if ($differences.Count) {
        $result = "не пройдена: $($differences -join '; ')"
        Write-Host "Копия отличается от сводки: $($differences -join '; ')" -ForegroundColor Red
    } else {
        $result = 'пройдена'
        $code = 0
        Write-Host "Проверка восстановления пройдена: $Dump"
    }
} catch {
    $result = "не пройдена: $_"
    Write-Host "Восстановление не прошло: $_" -ForegroundColor Red
} finally {
    if ($created) {
        try {
            Invoke-InDb $DbContainer @('psql', '-X', '-q', '-U', $User, '-d', 'postgres', '-c', "DROP DATABASE IF EXISTS $check WITH (FORCE)") | Out-Null
        } catch {
            Write-Host "Проверочная база $check не удалена: $_" -ForegroundColor Yellow
        }
    }
    try { Invoke-InDb $DbContainer @('rm', '-f', $inner) | Out-Null } catch { Write-Verbose "$_" }
}
$meta | Add-Member -NotePropertyName restore_check -NotePropertyValue $result -Force
$meta | Add-Member -NotePropertyName restore_check_utc -NotePropertyValue ((Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss')) -Force
Write-Utf8File $sidecar ($meta | ConvertTo-Json -Depth 5)
exit $code
