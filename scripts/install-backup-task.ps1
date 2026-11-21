<#
.SYNOPSIS
    Ежедневная копия основной базы в Планировщике заданий Windows (ADR-0128, раздел 9).

.DESCRIPTION
    Задача выполняет backup-db.ps1 и проверку восстановления. Пропущенный из-за выключенного компьютера запуск выполняется при следующей
    возможности, поэтому суточный предел потери при длительном простое не обещается. Без -Keep старые копии задача не удаляет: место на
    диске следит владелец установки. Журнал задачи – backups\backup-task.log. Итог последнего запуска виден в Планировщике и в backups\backup-task.log.

.PARAMETER At
    Время запуска, по умолчанию 03:00.

.PARAMETER Keep
    Сколько самых новых проверенных копий оставлять: значение передаётся backup-db.ps1 (-Keep). По умолчанию 0 – задача ничего не удаляет.

.PARAMETER Remove
    Снять задачу.

.EXAMPLE
    .\scripts\install-backup-task.ps1 -At 22:00
.EXAMPLE
    .\scripts\install-backup-task.ps1 -Keep 14
#>
[CmdletBinding()]
param(
    [string]$At = '03:00',
    [int]$Keep = 0,
    [switch]$Remove
)

$ErrorActionPreference = 'Stop'
if ($Keep -lt 0) { Write-Host "-Keep – число копий, которые нужно оставить; 0 – ничего не удалять: $Keep" -ForegroundColor Red; exit 1 }
$name = 'LocalTriage-BackupDb'
if ($Remove) {
    Unregister-ScheduledTask -TaskName $name -Confirm:$false
    Write-Host "Задача $name снята."
    exit 0
}
$root = Split-Path -Parent $PSScriptRoot
$log = Join-Path $root 'backups\backup-task.log'
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $log) | Out-Null
$script = Join-Path $PSScriptRoot 'backup-db.ps1'
$keepArgument = if ($Keep -gt 0) { " -Keep $Keep" } else { '' }  # без -Keep команда задачи прежняя
$command = "& '$script' -Check$keepArgument *>> '$log'; exit `$LASTEXITCODE"
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -Command `"$command`"" -WorkingDirectory $root
$trigger = New-ScheduledTaskTrigger -Daily -At $At
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName $name -Action $action -Trigger $trigger -Settings $settings -Force | Out-Null
$kept = if ($Keep -gt 0) { " Остаются $Keep самых новых проверенных копий, копии старше удаляются." } else { ' Старые копии задача не удаляет.' }
Write-Host "Задача ${name}: ежедневно в $At и при следующей возможности после пропуска.$kept Журнал: $log"
exit 0
