# Общее для backup-db.ps1, restore-db.ps1 и restore-check.ps1: команды клиентов из образа базы и сводка базы (ADR-0128, раздел 9).
# Клиенты PostgreSQL на компьютере не нужны: pg_dump, pg_restore и psql запускаются внутри контейнера базы.

# Контейнер сервиса db этой установки (проект Compose определяется папкой приложения).
function Get-DbContainer([string]$AppDir) {
    Push-Location -LiteralPath $AppDir
    try {
        $id = & docker compose -f docker-compose.yml ps -q db
    } finally {
        Pop-Location
    }
    if ($LASTEXITCODE -ne 0 -or -not "$id".Trim()) {
        throw 'Контейнер базы не запущен. Запустите его: docker compose up -d db'
    }
    return "$id".Trim()
}

# Команда клиента в контейнере базы. Сообщения клиента в stderr при 'Stop' остановили бы сценарий в Windows PowerShell 5.1 раньше
# проверки кода выхода, поэтому на время вызова действует 'Continue'; вывод ошибок попадает в текст исключения.
function Invoke-InDb([string]$Container, [string[]]$Command) {
    $saved = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $output = & docker exec $Container @Command 2>&1
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $saved
    }
    $text = @($output | ForEach-Object { "$_" })
    if ($code -ne 0) { throw "Команда в контейнере базы завершилась с кодом ${code}: $($Command[0]). $($text -join ' ')" }
    return $text
}

# Сводка базы одной строкой JSON: схема, строки в каждой таблице, состояние последовательностей, граница операций Hub.
$script:DbSummarySql = @'
SELECT json_build_object(
  'schema', (SELECT value FROM meta WHERE key = 'schema_version'),
  'tables', (SELECT json_object_agg(CASE table_schema WHEN 'public' THEN table_name ELSE table_schema || '.' || table_name END, n) FROM (
      SELECT table_schema, table_name, (xpath('/row/c/text()', query_to_xml(format('SELECT COUNT(*) AS c FROM %I.%I', table_schema, table_name), false, true, '')))[1]::text::bigint AS n
        FROM information_schema.tables WHERE table_schema IN ('public', 'feeds', 'app_state') AND table_type = 'BASE TABLE' ORDER BY table_schema, table_name) t),
  'sequences', (SELECT json_object_agg(sequencename, COALESCE(last_value, 0)) FROM pg_sequences WHERE schemaname = 'public'),
  'max_hub_op', (SELECT COALESCE(MAX(id), 0) FROM hub_ops),
  'max_hub_attempt', (SELECT COALESCE(MAX(id), 0) FROM hub_attempts))
'@

function Get-DbSummary([string]$Container, [string]$User, [string]$Database) {
    $line = Invoke-InDb $Container @('psql', '-X', '-A', '-t', '-q', '-v', 'ON_ERROR_STOP=1', '-U', $User, '-d', $Database, '-c', $script:DbSummarySql)
    return (($line -join '') | ConvertFrom-Json)
}

# Имя базы: PostgreSQL усекает имена до 63 байт, и временное имя с приставкой могло бы совпасть с самой базой.
function Test-DbName([string]$Name) {
    return ($Name -cmatch '^[a-z_][a-z0-9_]*$') -and $Name.Length -le 30
}

# Чем закончилась замена имён, когда ответа сервера нет. DROP ждёт замок незавершённой замены и после него заново ищет имя, поэтому исход после
# него окончателен: копию удалил он – замены не было; имя копии уже другое – замена выполнена. Если DROP успел удалить копию до второй смены имён,
# транзакция замены откатится сама. 'unknown' – сервер не ответил; копия при этом могла быть уже удалена, поэтому об исходе судят по прежнему имени.
function Get-DbSwitchOutcome([string]$Container, [string]$User, [string]$Database, [string]$Fresh, [string]$Previous, [bool]$HadBase) {
    for ($attempt = 0; $attempt -lt 3; $attempt++) {
        if ($attempt) { Start-Sleep -Seconds 2 }
        try {
            Invoke-InDb $Container @('psql', '-X', '-q', '-v', 'ON_ERROR_STOP=1', '-U', $User, '-d', 'postgres', '-c', "DROP DATABASE IF EXISTS $Fresh") | Out-Null
            $names = @(Invoke-InDb $Container @('psql', '-X', '-A', '-t', '-q', '-v', 'ON_ERROR_STOP=1', '-U', $User, '-d', 'postgres', '-c',
                "SELECT datname FROM pg_database WHERE datname IN ('$Database', '$Previous')") | ForEach-Object { "$_".Trim() })
        } catch {
            continue
        }
        if ($HadBase) {
            if ($names -contains $Previous) { return 'switched' }
            if ($names -contains $Database) { return 'unchanged' }
        } else {
            return $(if ($names -contains $Database) { 'switched' } else { 'unchanged' })
        }
    }
    return 'unknown'
}

# Свободное место в файловой системе контейнера базы, байт.
function Get-DbFreeBytes([string]$Container, [string]$Path = '/var/lib/postgresql/data') {
    $line = (Invoke-InDb $Container @('df', '-Pk', $Path) | Select-Object -Last 1)
    return [int64](($line -split '\s+')[3]) * 1024
}

# Запас места перед развёртыванием копии: сама база, её индексы и журнал во время загрузки (ADR-0128, раздел 9).
function Assert-DbSpace([string]$Container, [int64]$DatabaseBytes, [string]$Path = '/var/lib/postgresql/data') {
    $need = [int64]($DatabaseBytes * 2)
    $free = Get-DbFreeBytes $Container $Path
    if ($free -lt $need) {
        throw "В хранилище Docker свободно $([math]::Round($free / 1GB, 1)) ГБ, а нужно не меньше $([math]::Round($need / 1GB, 1)) ГБ."
    }
}

# Запас места на диске Windows под файл копии: сжатая копия не больше самой базы.
function Assert-FolderSpace([string]$Folder, [int64]$Bytes) {
    $rootPath = [IO.Path]::GetPathRoot([IO.Path]::GetFullPath($Folder))
    if ($rootPath.StartsWith('\\')) { return }  # сетевая папка: место этим способом не узнать, отказ придёт при записи
    $drive = New-Object IO.DriveInfo ($rootPath)
    if ($drive.AvailableFreeSpace -lt $Bytes) {
        throw "На диске $($drive.Name) свободно $([math]::Round($drive.AvailableFreeSpace / 1GB, 1)) ГБ, а копии нужно до $([math]::Round($Bytes / 1GB, 1)) ГБ."
    }
}

# Подключений к базе, кроме этого запроса.
function Get-DbSessions([string]$Container, [string]$User, [string]$Database) {
    $line = Invoke-InDb $Container @('psql', '-X', '-A', '-t', '-q', '-U', $User, '-d', 'postgres', '-c',
        "SELECT COUNT(*) FROM pg_stat_activity WHERE datname = '$Database' AND pid <> pg_backend_pid()")
    return [int](($line -join '').Trim())
}

# Позиция журнала сервера: не изменилась – ни одна запись не прошла, чтение и pg_dump её не двигают.
function Get-DbWalPosition([string]$Container, [string]$User) {
    return ((Invoke-InDb $Container @('psql', '-X', '-A', '-t', '-q', '-U', $User, '-d', 'postgres', '-c', 'SELECT pg_current_wal_insert_lsn()')) -join '').Trim()
}

# Размер базы копии из её сопроводительного файла: без него место проверить нельзя.
function Get-DumpDatabaseBytes($Meta) {
    if ($null -eq $Meta.database_bytes -or [int64]$Meta.database_bytes -le 0) { throw 'В сопроводительном файле нет размера базы: снимите новую копию.' }
    return [int64]$Meta.database_bytes
}

# Размер базы, байт.
function Get-DbSize([string]$Container, [string]$User, [string]$Database) {
    $line = Invoke-InDb $Container @('psql', '-X', '-A', '-t', '-q', '-U', $User, '-d', 'postgres', '-c', "SELECT pg_database_size('$Database')")
    return [int64](($line -join '').Trim())
}

# SHA-256 файла средствами .NET: Get-FileHash доступен не при любом окружении Windows PowerShell 5.1.
function Get-Sha256([string]$Path) {
    $sha = [Security.Cryptography.SHA256]::Create()
    $stream = [IO.File]::OpenRead((Resolve-Path -LiteralPath $Path).Path)
    try {
        return ([BitConverter]::ToString($sha.ComputeHash($stream)) -replace '-', '').ToLowerInvariant()
    } finally {
        $stream.Dispose()
        $sha.Dispose()
    }
}

# docker cp пишет ход копирования в stderr: при 'Stop' это остановило бы сценарий в Windows PowerShell 5.1.
function Invoke-DockerCopy([string]$From, [string]$To) {
    $saved = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & docker cp $From $To 2>&1 | Out-Null
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $saved
    }
    if ($code -ne 0) { throw "Не удалось скопировать файл: docker cp завершился с кодом $code." }
}

# Запись текста в UTF-8 без BOM: одинаково в PowerShell 5.1 и 7. Сначала временный файл рядом, сброс на диск и только потом замена:
# обрыв посреди записи не оставит усечённый файл на месте прежнего (без сопроводительного файла копию не примет восстановление).
function Write-Utf8File([string]$Path, [string]$Text) {
    $temporary = "$Path.tmp"
    $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes($Text)
    try {
        $stream = [IO.File]::Open($temporary, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try {
            $stream.Write($bytes, 0, $bytes.Length)
            $stream.Flush($true)
        } finally {
            $stream.Dispose()
        }
        if (Test-Path -LiteralPath $Path) {
            # третий аргумент – путь резервной копии: $null PowerShell передал бы строковому параметру .NET пустой строкой, и замена отказала бы
            [IO.File]::Replace($temporary, $Path, [System.Management.Automation.Language.NullString]::Value)
        } else {
            [IO.File]::Move($temporary, $Path)
        }
    } catch {
        if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue }
        throw
    }
}

# Одинаковы ли сводки: схема, строки всех таблиц, последовательности. Возвращает список различий.
function Compare-DbSummary($Expected, $Actual) {
    $found = @()
    if ("$($Expected.schema)" -ne "$($Actual.schema)") { $found += "схема $($Expected.schema) и $($Actual.schema)" }
    foreach ($part in 'tables', 'sequences') {
        $left = @{}; $right = @{}
        foreach ($p in $Expected.$part.PSObject.Properties) { $left[$p.Name] = "$($p.Value)" }
        foreach ($p in $Actual.$part.PSObject.Properties) { $right[$p.Name] = "$($p.Value)" }
        foreach ($name in @($left.Keys) + @($right.Keys) | Sort-Object -Unique) {
            if ($left[$name] -ne $right[$name]) { $found += "$name – $($left[$name]) и $($right[$name])" }
        }
    }
    return ,$found
}

# Отметка о проверенной копии в базе приложения (python -m app.storage.tools backup-note): по ней /healthz показывает возраст последней
# проверенной копии – папку копий приложение в контейнере не видит. Команда выполняется в образе приложения, как шаг после восстановления
# в restore-db.ps1; база задаётся явно. Возвращает пустую строку или причину сбоя: решать, что с ней делать, – вызывающему.
function Send-BackupNote([string]$AppDir, [string]$Database, [string]$Name, [string]$CheckedAt) {
    $saved = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'  # сообщения Compose в stderr при 'Stop' остановили бы сценарий в Windows PowerShell 5.1
    $code = 1
    $output = @()
    Push-Location -LiteralPath $AppDir
    try {
        $output = & docker compose -f docker-compose.yml run --rm --no-deps -T -e "PGDATABASE=$Database" triage python -m app.storage.tools `
            backup-note --name $Name --checked-at $CheckedAt 2>$null
        $code = $LASTEXITCODE
    } catch {
        return "$_"
    } finally {
        Pop-Location
        $ErrorActionPreference = $saved
    }
    if ($code -eq 0) { return '' }
    $detail = ''
    try {
        $answer = (@($output) -join "`n") | ConvertFrom-Json
        if ($answer -and $answer.error) { $detail = ": $($answer.error)" }
    } catch {
        $detail = ''
    }
    return "команда backup-note завершилась с кодом $code$detail"
}

# Пройдена ли у копии проверка восстановления: по её сопроводительному файлу. Файла нет или он не читается – не пройдена.
function Test-BackupChecked([string]$Dump) {
    try {
        $meta = Get-Content -LiteralPath "$Dump.json" -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json
        return [bool]($meta -and $meta.restore_check -eq 'пройдена')
    } catch {
        return $false
    }
}

# Правило хранения копий (backup-db.ps1 -Keep N): остаются N самых новых проверенных копий и всё, что новее самой старой из них;
# копии старше неё удаляются вместе с сопроводительными файлами. Разбираются только файлы с именем ровно triage-ГГГГММДД-ЧЧММСС.dump:
# остальное в папке (журнал задачи, список отменённых баз, before-local-state, файлы другого вида) не трогается. Проверенных копий
# не больше N – ничего не удаляется. Сопроводительный файл удаляется первым: копия без него – непроверенная, а не «проверенная»
# без файла. Что удалено и что удалить не удалось – в вывод.
function Remove-OldBackups([string]$Folder, [int]$Keep) {
    if ($Keep -le 0) { return }
    $dumps = @(Get-ChildItem -LiteralPath $Folder -Filter 'triage-*.dump' -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -cmatch '^triage-[0-9]{8}-[0-9]{6}\.dump$' } | Sort-Object -Property Name -Descending)
    $checked = @($dumps | Where-Object { Test-BackupChecked $_.FullName })
    if ($checked.Count -le $Keep) { return }
    $oldest = $checked[$Keep - 1].Name
    foreach ($dump in $dumps) {
        if ([string]::CompareOrdinal($dump.Name, $oldest) -ge 0) { continue }
        try {
            $sidecar = "$($dump.FullName).json"
            if (Test-Path -LiteralPath $sidecar -PathType Leaf) { Remove-Item -LiteralPath $sidecar -Force -ErrorAction Stop }
            Remove-Item -LiteralPath $dump.FullName -Force -ErrorAction Stop
            Write-Host "Удалена старая копия: $($dump.Name)"
        } catch {
            Write-Host "Старая копия не удалена: $($dump.Name). $_" -ForegroundColor Yellow
        }
    }
}
