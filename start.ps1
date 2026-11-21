<#
.SYNOPSIS
    Запуск «Локального триажа» в Docker и открытие интерфейса http://127.0.0.1:8765.

.DESCRIPTION
    При первом запуске сам создаёт .env: папка для клонов репозиториев (REPOS_ROOT) – папка repos в корне диска,
    на котором лежит папка приложения (например, D:/repos; создаётся, если её нет), подключается в контейнер только
    для чтения; весь диск контейнер не видит. Интерфейс – на порту 8765. Править .env руками не нужно: адрес Ollama,
    модель по умолчанию, статусы Hub и порог срочности SCA меняются в приложении на странице «Настройки», а папка
    с клонами каждого проекта выбирается внутри корня на странице проекта.

    Если в .env корнем остался весь диск (D:/) или демо-репозитории этой папки приложения (так было на этапах 1
    и 2), сценарий предлагает заменить его папкой для клонов и меняет .env только после согласия.

    В папку для клонов по умолчанию кладётся копия демо-репозиториев (local-triage-demo) – для кнопки «Создать
    демо-проект», где бы ни лежала папка приложения.

    Затем проверяет корень, подключает видеокарту NVIDIA (docker-compose.gpu.yml), если на компьютере есть
    nvidia-smi, собирает образ, если его ещё нет, поднимает контейнер и ждёт ответа приложения. После запуска
    спрашивает у приложения, видит ли оно Ollama из контейнера (тем же путём, которым пойдут запросы к модели),
    и подсказывает, что делать, если нет. Если демо-выгрузки examples\demo\demo-hub-report.xlsx нет, строит её
    в образе приложения. В конце печатает, когда снята последняя проверенная копия базы в папке backups, и предупреждает,
    если такой копии нет или она старше 48 часов; запуск из-за этого не отменяется.

.PARAMETER ReposRoot
    Другая папка для клонов репозиториев, например D:/work/repos. Записывается в .env, контейнер пересоздаётся.
    Без параметра корень не меняется (кроме замены корня диска или демо-репозиториев – с согласия).

.PARAMETER Build
    Пересобрать образ (после обновления кода). Без интернета не нужен: образ загружается scripts\import-image.ps1.

.PARAMETER NoBrowser
    Не открывать браузер.

.PARAMETER NoGpu
    Не подключать видеокарту к контейнеру (например, если GPU в Docker Desktop недоступен). Метрики видеокарты
    тогда не видны, видеопамять показывается по данным Ollama.

.PARAMETER LanAddress
    Открыть интерфейс и в локальной сети – например, для ВМ VMware на этом компьютере: адрес IPv4 этого компьютера
    (из ipconfig, например 192.0.2.10). Записывается в .env (TRIAGE_LAN_ADDR); порт публикуется ещё и на этом
    адресе (docker-compose.lan.yml), 127.0.0.1 остаётся. Входа по паролю в приложении нет: интерфейс увидит любой,
    кто достанет до этого адреса.

.PARAMETER Migrate
    Обновить схему основной базы, если новой сборке это нужно: сначала создаётся и проверяется копия (scripts\backup-db.ps1), затем
    выполняются миграции. Без этого параметра запуск на такой базе останавливается с пояснением.

.PARAMETER Maintenance
    Режим обслуживания: основная база неподвижна, формы отклоняются, исполнителю ничего не выдаётся (проверка после восстановления
    копии).

.PARAMETER NewDatabase
    Начать с пустой основной базы, хотя у установки есть копии прежней или база прежней версии (triage.db): без параметра запуск
    останавливается и предлагает восстановить копию (том базы мог быть утрачен).

.PARAMETER LocalOnly
    Снова открыть интерфейс только на этом компьютере (убрать TRIAGE_LAN_ADDR из .env).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\start.ps1
.EXAMPLE
    .\start.ps1 -ReposRoot D:/work/repos
.EXAMPLE
    .\start.ps1 -Build -NoBrowser
.EXAMPLE
    .\start.ps1 -LanAddress 192.0.2.10
#>
[CmdletBinding()]
param(
    [string]$ReposRoot = '',
    [switch]$Build,
    [switch]$NoBrowser,
    [switch]$NoGpu,
    [string]$LanAddress = '',
    [switch]$LocalOnly,
    [switch]$Migrate,
    [switch]$Maintenance,
    [switch]$NewDatabase
)

$ErrorActionPreference = 'Stop'

function Stop-WithMessage([string]$Message) {
    Write-Host $Message -ForegroundColor Red
    exit 1
}

# ---------------------------------------------------------------- .env

# Путь для .env: прямые слэши, без кавычек и «/» в конце; диск целиком – «D:/».
function ConvertTo-EnvPath([string]$Path) {
    $p = $Path.Trim().Trim('"').Trim("'").Replace('\', '/')
    if ($p -match '^[A-Za-z]:/?$') { return $p.Substring(0, 2) + '/' }
    if ($p.Length -gt 1) { $p = $p.TrimEnd('/') }
    return $p
}

# Папка для клонов по умолчанию: repos в корне диска, на котором лежит папка приложения («D:/repos»). Для сетевой
# папки (\\server\share\...) – repos рядом с папкой приложения. Весь диск в контейнер не подключается.
function Get-DefaultReposRoot([string]$AppDir) {
    $root = [IO.Path]::GetPathRoot($AppDir)
    if ($root -match '^[A-Za-z]:\\?$') { return $root.Substring(0, 2) + '/repos' }
    $parent = Split-Path -Parent $AppDir
    if ($parent) { return (ConvertTo-EnvPath $parent) + '/repos' }
    return './examples/demo/repos'
}

# Корень – весь диск («D:/», «D:»): так подключали папку для клонов на этапе 2
function Test-DriveRoot([string]$Value) {
    return [bool]($Value -and ($Value.Trim().Trim('"').Trim("'").Replace('\', '/') -match '^[A-Za-z]:/?$'))
}

# Значение для .env: в кавычках, если в пути есть пробел или «#»
function Format-EnvValue([string]$Value) {
    if ($Value -match '[\s#]') { return '"' + $Value + '"' }
    return $Value
}

# Строки .env, где переменная Name получила значение Value: строка Name=… заменяется (или добавляется в конец),
# остальные строки не меняются.
function Set-EnvLine([string[]]$Lines, [string]$Name, [string]$Value) {
    $found = $false
    $result = New-Object System.Collections.Generic.List[string]
    foreach ($line in $Lines) {
        if ($line -match ('^\s*' + [regex]::Escape($Name) + '\s*=')) {
            if (-not $found) { $result.Add("$Name=$(Format-EnvValue $Value)") }
            $found = $true
        } else {
            $result.Add($line)
        }
    }
    if (-not $found) { $result.Add("$Name=$(Format-EnvValue $Value)") }
    return ,$result.ToArray()
}

function Read-Lines([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return ,@() }
    return ,[IO.File]::ReadAllLines($Path, [Text.Encoding]::UTF8)
}

function Write-Lines([string]$Path, [string[]]$Lines) {
    $text = ($Lines -join "`n") + "`n"
    [IO.File]::WriteAllText($Path, $text, (New-Object Text.UTF8Encoding($false)))
}

# .env в папке приложения: при первом запуске создаётся из .env.example с папкой для клонов (параметр ReposRoot
# или repos в корне диска с папкой приложения) и портом 8765; ReposRoot у существующего .env меняет только
# REPOS_ROOT. Возвращает @{ Created; Changed; Root } – Root пустой, если корень не менялся. Если корнем в .env
# остались весь диск или демо-репозитории, .env не меняется: Suggest – предлагаемая папка для клонов, Current –
# что сейчас (замену с согласия человека делает Set-ReposRoot).
function Initialize-EnvFile([string]$AppDir, [string]$ReposRoot) {
    $envFile = Join-Path $AppDir '.env'
    if (-not (Test-Path -LiteralPath $envFile)) {
        $root = if ($ReposRoot) { ConvertTo-EnvPath $ReposRoot } else { Get-DefaultReposRoot $AppDir }
        $lines = Read-Lines (Join-Path $AppDir '.env.example')
        $lines = Set-EnvLine $lines 'REPOS_ROOT' $root
        $lines = Set-EnvLine $lines 'TRIAGE_PORT' '8765'
        Write-Lines $envFile $lines
        return @{ Created = $true; Changed = $true; Root = $root }
    }
    if ($ReposRoot) {
        $root = ConvertTo-EnvPath $ReposRoot
        Write-Lines $envFile (Set-EnvLine (Read-Lines $envFile) 'REPOS_ROOT' $root)
        return @{ Created = $false; Changed = $true; Root = $root }
    }
    # .env прежних этапов: корень – весь диск или демо-репозитории этой же папки приложения. Сам .env не меняется:
    # замену предлагают человеку (Set-ReposRoot после согласия)
    $current = Get-EnvValue (Read-Lines $envFile) 'REPOS_ROOT'
    if ((Test-DriveRoot $current) -or (Test-DemoReposRoot $AppDir $current)) {
        return @{ Created = $false; Changed = $false; Root = ''; Suggest = (Get-DefaultReposRoot $AppDir);
                  Current = $current }
    }
    return @{ Created = $false; Changed = $false; Root = '' }
}

# Пароль основной базы в .env: при первом запуске – случайный; уже заданный не меняется (том базы хранит его).
function Initialize-DbPassword([string]$AppDir) {
    $envFile = Join-Path $AppDir '.env'
    $lines = Read-Lines $envFile
    # Compose берёт значение из окружения процесса раньше, чем из .env. Источник один – строка .env, а разбирает её только Compose:
    # иначе база создалась бы с одним паролем, а следующий запуск пришёл бы с другим
    if (Test-EnvValueSet $lines 'POSTGRES_PASSWORD') {
        Remove-Item Env:POSTGRES_PASSWORD -ErrorAction SilentlyContinue
        return $false
    }
    $password = $env:POSTGRES_PASSWORD
    if ($password) {
        if ($password -notmatch '^[A-Za-z0-9_.~+/=:@-]+$') {
            Stop-WithMessage 'Пароль базы в переменной POSTGRES_PASSWORD содержит кавычки, пробелы или другие особые знаки: запишите его в .env сами, по правилам Docker Compose.'
        }
    } else {
        # не docker volume inspect: ошибка в stderr останавливает сценарий в Windows PowerShell 5.1 при $ErrorActionPreference = 'Stop'
        $volumes = @(docker volume ls -q --filter name=local-triage_pgdata)
        if ($LASTEXITCODE -ne 0) {  # без ответа Docker нельзя считать, что тома нет: новый пароль к нему не подошёл бы
            Stop-WithMessage 'Docker Desktop не отвечает. Запустите его и повторите.'
        }
        if ($volumes -contains 'local-triage_pgdata') {
            Stop-WithMessage 'В .env нет POSTGRES_PASSWORD, а том базы local-triage_pgdata уже есть: новый пароль к нему не подойдёт. Верните прежнее значение в .env.'
        }
        $bytes = New-Object byte[] 24
        $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
        try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
        $password = -join ($bytes | ForEach-Object { $_.ToString('x2') })
    }
    # пустых строк пароля может быть несколько, в том числе с export: действует последняя, поэтому заменяются все
    $others = @($lines | Where-Object { $_ -notmatch '^\s*(?:export\s+)?POSTGRES_PASSWORD\s*[=:]' })
    Write-Lines $envFile (Set-EnvLine $others 'POSTGRES_PASSWORD' $password)
    Remove-Item Env:POSTGRES_PASSWORD -ErrorAction SilentlyContinue
    return $true
}

# Записывает в .env новую папку для клонов (только REPOS_ROOT, остальные строки не меняются)
function Set-ReposRoot([string]$AppDir, [string]$Root) {
    $envFile = Join-Path $AppDir '.env'
    Write-Lines $envFile (Set-EnvLine (Read-Lines $envFile) 'REPOS_ROOT' (ConvertTo-EnvPath $Root))
}

# Согласие человека на замену: только при запуске в окне PowerShell (ввод не перенаправлен); иначе – нет
function Confirm-Replace([string]$Question) {
    if ([Console]::IsInputRedirected) { return $false }
    $answer = Read-Host "$Question [Д/н]"
    return (-not $answer) -or ($answer.Trim() -match '^(д|да|y|yes)$')
}

# Копия демо-репозиториев examples/demo/repos в папку для клонов (local-triage-demo): так кнопка «Создать
# демо-проект» находит их, где бы ни лежала папка приложения. Уже есть – не трогается. Возвращает путь копии или ''.
function Copy-DemoRepos([string]$AppDir, [string]$Root) {
    $demo = Join-Path $AppDir 'examples\demo\repos'
    if (-not (Test-Path -LiteralPath $demo -PathType Container)) { return '' }
    if (-not (Test-Path -LiteralPath $Root -PathType Container)) { return '' }
    $target = Join-Path $Root 'local-triage-demo'
    if (Test-Path -LiteralPath $target) { return '' }
    Copy-Item -LiteralPath $demo -Destination $target -Recurse
    return $target
}

# Команда обслуживания основной базы в образе приложения; ответ – разобранный JSON. Код 1 у status – штатный ответ «база не подходит».
function Invoke-StorageTool([string[]]$ComposeArgs, [string[]]$Tool) {
    $saved = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'  # сообщения Compose в stderr при 'Stop' остановили бы сценарий в Windows PowerShell 5.1
    try {
        $output = & docker @ComposeArgs run --rm --no-deps -T triage python -m app.storage.tools @Tool 2>$null
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $saved
    }
    try {
        $answer = ($output -join "`n") | ConvertFrom-Json
    } catch {
        $answer = $null
    }
    if ($null -eq $answer -or $code -ge 2) {
        $detail = if ($answer -and $answer.error) { ": $($answer.error)" } else { '' }
        Stop-WithMessage "Команда обслуживания базы ($($Tool -join ' ')) не выполнена$detail"
    }
    return $answer
}

function Get-SchemaState([string[]]$ComposeArgs) {
    return Invoke-StorageTool $ComposeArgs @('status')
}

# Что запрещает запуск приложения на базе в состоянии State (ответ команды status); пустая строка – запускать можно.
# Основная база лежит в томе Docker, а следы прежней жизни установки – в папке данных и в копиях рядом с ней. Том можно утратить
# (docker compose down -v, сброс данных Docker Desktop): приложение не должно молча начать работу на пустой базе вместо прежней.
function Get-StartBlocker([string]$State, [string]$DataDir, [bool]$NewDatabase) {
    if (-not $DataDir) { return '' }
    if ($State -ne 'empty') { return '' }
    if ($NewDatabase) { return '' }
    if (Test-Path -LiteralPath (Join-Path $DataDir 'triage.db')) {
        return ('Основная база пуста, а в папке данных лежит база прежней версии (triage.db). Эта сборка базу прежней версии не ' +
            'переносит: перенос выполняла сборка 0.10.0.dev7. Восстановите копию: .\scripts\restore-db.ps1 -Dump <файл из backups> ' +
            '-Confirm, затем снова .\start.ps1 – или начните с пустой базы: .\start.ps1 -NewDatabase. Приложение не запущено.')
    }
    # копии – рядом с папкой данных: её можно очищать (ADR-0133)
    $backupDir = Join-Path (Split-Path -Parent $DataDir) 'backups'
    $dumps = @(Get-ChildItem -LiteralPath $backupDir, (Join-Path $DataDir 'backups') -Filter 'triage-*.dump' -File -ErrorAction SilentlyContinue)
    if ($dumps.Count -or (Test-Path -LiteralPath (Join-Path $DataDir 'triage.db.sqlite-0.9.26'))) {
        return ('Основная база пуста, а у этой установки она была: в папке данных есть её копии или база прежней версии. Похоже, том базы ' +
            'утрачен (docker compose down -v, сброс данных Docker Desktop). Восстановите последнюю копию: ' +
            '.\scripts\restore-db.ps1 -Dump <файл из backups> -Confirm, затем снова .\start.ps1; README, раздел «Копии, восстановление ' +
            'и возврат». Начать с пустой базы: .\start.ps1 -NewDatabase. Приложение не запущено.')
    }
    return ''
}

# Последняя проверенная копия базы по сопроводительным файлам папки копий: самая новая копия triage-ГГГГММДД-ЧЧММСС.dump, у которой
# пройдена проверка восстановления (restore_check в .dump.json) и сам файл на месте. Возвращает имя и время снятия (UTC, из имени
# файла) или $null. Файл, который не читается, пропускается: строка о копиях запуск не отменяет.
function Get-LastCheckedBackup([string]$BackupDir) {
    $sidecars = @(Get-ChildItem -LiteralPath $BackupDir -Filter 'triage-*.dump.json' -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -cmatch '^triage-[0-9]{8}-[0-9]{6}\.dump\.json$' } | Sort-Object -Property Name -Descending)
    foreach ($sidecar in $sidecars) {
        try {
            $dump = $sidecar.FullName.Substring(0, $sidecar.FullName.Length - '.json'.Length)
            if (-not (Test-Path -LiteralPath $dump -PathType Leaf)) { continue }
            $meta = Get-Content -LiteralPath $sidecar.FullName -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json
            if (-not $meta -or $meta.restore_check -ne 'пройдена') { continue }
            $taken = [datetime]::ParseExact($sidecar.Name.Substring('triage-'.Length, 15), 'yyyyMMdd-HHmmss',
                [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal)
            return [pscustomobject]@{ Name = [IO.Path]::GetFileName($dump); TakenUtc = $taken }
        } catch {
            continue
        }
    }
    return $null
}

# Строка итога о последней проверенной копии базы (бэклог 76): возраст по времени снятия; копии нет или она старше StaleHours –
# предупреждение. Только сообщает: ежедневная задача могла не отработать, а узнать об этом больше негде.
function Show-LastCheckedBackup([string]$BackupDir, [int]$StaleHours = 48) {
    $how = 'Снять и проверить копию: .\scripts\backup-db.ps1 -Check; ежедневная задача – .\scripts\install-backup-task.ps1, ' +
        'её журнал – backups\backup-task.log.'
    $last = Get-LastCheckedBackup $BackupDir
    if (-not $last) {
        Write-Host "Проверенной копии базы в папке backups нет. $how" -ForegroundColor Yellow
        return
    }
    $age = [double]((Get-Date).ToUniversalTime() - $last.TakenUtc).TotalHours
    if ($age -lt 0) { $age = [double]0 }  # часы компьютера могли отстать от копии
    $hours = [int][math]::Floor($age)
    $line = "Последняя проверенная копия базы: $($last.Name) от $($last.TakenUtc.ToLocalTime().ToString('dd.MM.yyyy HH:mm')) ($hours ч назад)."
    if ($age -gt $StaleHours) {
        Write-Host "$line Это больше $StaleHours часов. $how" -ForegroundColor Yellow
    } else {
        Write-Host $line
    }
}

# Задано ли значение в строках .env. Значение не разбирается: что значат кавычки внутри него, знает только Compose
function Test-EnvValueSet([string[]]$Lines, [string]$Name) {
    $set = $false
    foreach ($line in $Lines) {  # как у Compose: действует последняя строка, возможен префикс export
        if ($line -match ('^\s*(?:export\s+)?' + [regex]::Escape($Name) + '\s*[=:]\s*(.*?)\s*$')) {
            $set = $Matches[1] -notin @('', '""', "''")
        }
    }
    return $set
}

# Значение переменной из строк .env (без кавычек); нет такой строки – пустая строка
function Get-EnvValue([string[]]$Lines, [string]$Name) {
    foreach ($line in $Lines) {
        if ($line -match ('^\s*' + [regex]::Escape($Name) + '\s*=\s*(.*?)\s*$')) {
            return $Matches[1].Trim('"').Trim("'")
        }
    }
    return ''
}

# Корень – демо-репозитории examples/demo/repos этой папки приложения (абсолютным или относительным путём)
function Test-DemoReposRoot([string]$AppDir, [string]$Value) {
    if (-not $Value) { return $false }
    $demo = [IO.Path]::GetFullPath((Join-Path $AppDir 'examples\demo\repos')).TrimEnd('\')
    $path = $Value.Replace('/', '\')
    if (-not [IO.Path]::IsPathRooted($path)) { $path = Join-Path $AppDir $path }
    try {
        $full = [IO.Path]::GetFullPath($path).TrimEnd('\')
    } catch {
        return $false
    }
    return $full -ieq $demo
}

# Адрес для доступа к интерфейсу из локальной сети: IPv4 без порта; не 0.0.0.0 (все адаптеры), не 127.x (это и
# так открыто), не 169.254.x (адрес без сети) и не широковещательный.
function Test-LanAddress([string]$Value) {
    $v = "$Value".Trim()
    if ($v -notmatch '^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$') { return $false }
    $parts = @([int]$Matches[1], [int]$Matches[2], [int]$Matches[3], [int]$Matches[4])
    if (@($parts | Where-Object { $_ -gt 255 }).Count) { return $false }
    if ($parts[0] -eq 0 -or $parts[0] -eq 127 -or $parts[0] -ge 224 -or ($parts[0] -eq 169 -and $parts[1] -eq 254)) {
        return $false
    }
    return $true
}

# Адрес есть у сетевого адаптера этого компьютера: иначе Docker не опубликует на нём порт и контейнер не запустится
function Test-LocalAddress([string]$Value) {
    try {
        return [bool](Get-NetIPAddress -IPAddress $Value.Trim() -ErrorAction Stop)
    } catch {
        return $false
    }
}

# Записать адрес для доступа из сети в .env (TRIAGE_LAN_ADDR); пустой – доступ только с этого компьютера
function Set-LanAddress([string]$AppDir, [string]$Address) {
    $envFile = Join-Path $AppDir '.env'
    Write-Lines $envFile (Set-EnvLine (Read-Lines $envFile) 'TRIAGE_LAN_ADDR' $Address.Trim())
}

# TRIAGE_LAN_ADDR из строк .env: значение в кавычках – без кавычек и пробелов по краям, без кавычек – до « #»
# (комментарий). Compose этот адрес из .env не читает: start.ps1 передаёт ему проверенное значение сам.
function Get-LanAddressValue([string[]]$Lines) {
    foreach ($line in $Lines) {
        if ($line -match '^\s*TRIAGE_LAN_ADDR\s*=(.*)$') {
            $v = $Matches[1].Trim()
            if ($v -match '^"([^"]*)"') { return $Matches[1].Trim() }
            if ($v -match "^'([^']*)'") { return $Matches[1].Trim() }
            return ($v -replace '\s+#.*$', '').Trim()
        }
    }
    return ''
}

# Публикации порта из итоговой настройки Compose, которых быть не должно: адрес не из Allowed или не задан (все
# адаптеры). Пусто – всё в порядке.
function Get-WrongPublications($Ports, [string[]]$Allowed) {
    $wrong = @()
    foreach ($p in @($Ports)) {
        $ip = [string]$p.host_ip
        if (-not $ip -or ($Allowed -notcontains $ip)) {
            $wrong += $(if ($ip) { $ip } else { 'все адаптеры' })
        }
    }
    return ,$wrong
}

# ---------------------------------------------------------------- проверки

function Test-Url([string]$Url) {
    $options = @{ Uri = $Url; UseBasicParsing = $true; TimeoutSec = 2 }
    if ($PSVersionTable.PSVersion.Major -ge 7) { $options['NoProxy'] = $true }
    try {
        return (Invoke-WebRequest @options).StatusCode -eq 200
    } catch {
        return $false
    }
}

# Ответ приложения в JSON: @{ Status = код HTTP (0 – нет ответа); Json = объект или $null }. Текст читается как
# UTF-8 сам: Windows PowerShell без charset в ответе прочитал бы русский текст неверно.
function Get-AppJson([string]$Url) {
    $options = @{ Uri = $Url; UseBasicParsing = $true; TimeoutSec = 40 }
    if ($PSVersionTable.PSVersion.Major -ge 7) { $options['NoProxy'] = $true }
    try {
        $response = Invoke-WebRequest @options
        $text = [Text.Encoding]::UTF8.GetString($response.RawContentStream.ToArray())
        return @{ Status = [int]$response.StatusCode; Json = ($text | ConvertFrom-Json) }
    } catch {
        $code = 0
        if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
        return @{ Status = $code; Json = $null }
    }
}

# Отвечает ли Ollama на этом компьютере по адресу из настроек (host.docker.internal из контейнера – это
# 127.0.0.1 здесь). Адрес не этого компьютера – $null: проверять нечего.
function Test-HostOllama([string]$OllamaUrl) {
    $uri = $null
    if (-not [Uri]::TryCreate($OllamaUrl, [UriKind]::Absolute, [ref]$uri)) { return $null }
    $localNames = @('host.docker.internal', 'localhost', '127.0.0.1', '[::1]', '::1')
    if (-not ($localNames -contains $uri.Host)) { return $null }
    $hostName = if ($uri.Host -like '*::1*') { '[::1]' } else { '127.0.0.1' }
    return Test-Url ('{0}://{1}:{2}{3}/api/version' -f $uri.Scheme, $hostName, $uri.Port, $uri.AbsolutePath.TrimEnd('/'))
}

function Show-OllamaHelp([string]$Problem, [string]$OllamaUrl) {
    Write-Host "Приложение в контейнере не достучалось до Ollama: $Problem" -ForegroundColor Yellow
    $onHost = Test-HostOllama $OllamaUrl
    if ($onHost -eq $true) {
        Write-Host ('Ollama на этом компьютере отвечает, но из контейнера недоступна. Проверьте адрес Ollama на странице ' +
            '«Настройки» приложения: для Docker Desktop – http://host.docker.internal:11434 (127.0.0.1 внутри контейнера – сам ' +
            'контейнер). Открывать Ollama на всю сеть (OLLAMA_HOST=0.0.0.0) не нужно: Docker Desktop доводит host.docker.internal ' +
            'до 127.0.0.1 этого компьютера. Подробнее – README, раздел «Ollama и контейнер».') -ForegroundColor Yellow
    } elseif ($onHost -eq $false) {
        Write-Host ('Ollama на этом компьютере не отвечает: запустите её (значок Ollama в области уведомлений или команда ' +
            'ollama serve) и снова запустите .\start.ps1.') -ForegroundColor Yellow
    }
}

# Подключённый сценарий (. .\start.ps1) только объявляет функции: так их проверяют тесты
if ($MyInvocation.InvocationName -eq '.') { return }

# ---------------------------------------------------------------- запуск

Set-Location -LiteralPath $PSScriptRoot

# Доступ из локальной сети: параметры проверяются до любых записей в .env
if ($LanAddress -and $LocalOnly) {
    Stop-WithMessage 'Укажите что-то одно: -LanAddress (открыть в локальной сети) или -LocalOnly (только этот компьютер).'
}
if ($LanAddress) {
    if (-not (Test-LanAddress $LanAddress)) {
        Stop-WithMessage "Адрес для доступа из сети: ожидается IPv4 этого компьютера, например 192.0.2.10 (не 0.0.0.0, не 127.x и не 169.254.x), а не «$LanAddress»."
    }
    if (-not (Test-LocalAddress $LanAddress)) {
        Stop-WithMessage "Адреса $LanAddress нет у сетевых адаптеров этого компьютера. Укажите адрес из ipconfig."
    }
}
# -LocalOnly сужает доступ – записывается сразу (и если Docker не запущен); -LanAddress – только после запуска
if ($LocalOnly -and (Test-Path -LiteralPath (Join-Path $PSScriptRoot '.env'))) {
    Set-LanAddress $PSScriptRoot ''
}

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Stop-WithMessage 'Docker не найден. Установите Docker Desktop и запустите его.'
}
# Вывод в stderr при 'Stop' останавливает сценарий в Windows PowerShell 5.1 раньше понятного сообщения
$ErrorActionPreference = 'Continue'
docker info --format '{{.ServerVersion}}' *> $null
$dockerExit = $LASTEXITCODE
$ErrorActionPreference = 'Stop'
if ($dockerExit -ne 0) {
    Stop-WithMessage 'Docker Desktop не запущен. Запустите его и повторите.'
}

if ($ReposRoot -and -not (Test-Path -LiteralPath $ReposRoot -PathType Container)) {
    Stop-WithMessage "Папка не найдена: $ReposRoot. Укажите в -ReposRoot существующую папку, например D:/work/repos."
}
$defaultRoot = Get-DefaultReposRoot $PSScriptRoot
# Папка для клонов по умолчанию создаётся при первом запуске (или когда человек согласился на неё перейти)
function New-DefaultRoot {
    if (-not (Test-Path -LiteralPath $defaultRoot)) {
        New-Item -ItemType Directory -Path $defaultRoot | Out-Null
        Write-Host "Создана папка для клонов репозиториев: $defaultRoot" -ForegroundColor Cyan
    }
}
$envState = Initialize-EnvFile $PSScriptRoot $ReposRoot
if (Initialize-DbPassword $PSScriptRoot) {
    Write-Host 'Пароль основной базы записан в .env (POSTGRES_PASSWORD).' -ForegroundColor Cyan
}
if ($envState.Created) {
    if (-not $ReposRoot) { New-DefaultRoot }
    Write-Host ("Создан .env: папка для клонов репозиториев – $($envState.Root) (только для чтения), интерфейс – на порту " +
        '8765. Другая папка: .\start.ps1 -ReposRoot D:/work/repos') -ForegroundColor Cyan
} elseif ($envState.Suggest) {
    $what = if (Test-DriveRoot $envState.Current) { "весь диск $($envState.Current)" } else { 'только демо-репозитории' }
    Write-Host ("В .env корнем для клонов указан $what. Контейнеру не нужен весь диск: клоны лучше держать в отдельной " +
        "папке $($envState.Suggest) (она подключается только для чтения).") -ForegroundColor Yellow
    if (Confirm-Replace "Заменить REPOS_ROOT в .env на $($envState.Suggest)?") {
        New-DefaultRoot
        Set-ReposRoot $PSScriptRoot $envState.Suggest
        Write-Host ("REPOS_ROOT в .env: $($envState.Suggest). Перенесите или склонируйте туда репозитории и выберите папки " +
            'проектов заново на их страницах. Контейнер будет пересоздан.') -ForegroundColor Cyan
    } else {
        Write-Host ("Корень не изменён. Заменить позже: .\start.ps1 -ReposRoot $($envState.Suggest) (папку создайте " +
            'заранее).') -ForegroundColor Yellow
    }
} elseif ($envState.Changed) {
    Write-Host "Папка для клонов в .env: $($envState.Root). Папки проектов внутри прежнего корня выберите заново на их страницах." -ForegroundColor Cyan
}

# Доступ из локальной сети (docker-compose.lan.yml): адрес из -LanAddress, иначе из .env (-LocalOnly – без него).
# Проверенный адрес передаётся Compose переменной окружения процесса – она важнее строки .env: проверяется и
# публикуется одно и то же значение.
$lanAddr = if ($LanAddress) { $LanAddress.Trim() } elseif ($LocalOnly) { '' } else {
    Get-LanAddressValue (Read-Lines (Join-Path $PSScriptRoot '.env')) }
$base = @('compose', '-f', 'docker-compose.yml')
$lan = $false
$lanNote = ''
if ($lanAddr) {
    if ((Test-LanAddress $lanAddr) -and (Test-LocalAddress $lanAddr)) {
        $base += @('-f', 'docker-compose.lan.yml')
        $lan = $true
        $env:TRIAGE_LAN_ADDR = $lanAddr
    } else {
        $lanNote = ("В .env задан TRIAGE_LAN_ADDR=$lanAddr, но такого адреса у этого компьютера сейчас нет: интерфейс " +
            'открыт только на 127.0.0.1. Новый адрес: .\start.ps1 -LanAddress <адрес>, только этот компьютер: ' +
            '.\start.ps1 -LocalOnly')
    }
}
if (-not $lan) { Remove-Item Env:TRIAGE_LAN_ADDR -ErrorAction SilentlyContinue }
# Адреса этого компьютера – в контейнер (TRIAGE_HOST_ADDRESSES): изнутри контейнера их не видно, а внешний провайдер
# (класс external, ADR-0104) не должен вести на сам компьютер; без них внешние запросы не отправляются
# (сбой чтения адресов запуск не ломает: без них внешние запросы держит свежий снимок сборщика метрик)
$hostAddrs = @()
try {
    $hostAddrs = @(Get-NetIPAddress -ErrorAction SilentlyContinue | ForEach-Object { ($_.IPAddress -split '%')[0] } |
        Sort-Object -Unique)
} catch { $hostAddrs = @() }
$env:TRIAGE_HOST_ADDRESSES = ($hostAddrs -join ',')
$compose = $base
$gpu = $false
if ($NoGpu) {
    Write-Host 'Видеокарта к контейнеру не подключается (-NoGpu): видеопамять – по данным Ollama.'
} elseif (Get-Command nvidia-smi -ErrorAction SilentlyContinue) {
    $compose = $base + @('-f', 'docker-compose.gpu.yml')
    $gpu = $true
    Write-Host 'Найдена видеокарта NVIDIA: её метрики будут видны на странице прогона.'
}

# Настройки – так, как их видит Docker Compose: .env, переменные окружения и значения по умолчанию
$configJson = & docker @compose config --format json
if ($LASTEXITCODE -ne 0) {
    Stop-WithMessage 'Docker Compose не принял настройки: проверьте .env.'
}
$service = (($configJson -join "`n") | ConvertFrom-Json).services.triage
# Итоговые публикации порта – только 127.0.0.1 и проверенный адрес сети: адрес из окружения или опечатка в .env
# (0.0.0.0, чужой адрес) контейнер не пересоздают
$allowedIps = @('127.0.0.1') + $(if ($lan) { @($lanAddr) } else { @() })
$wrong = Get-WrongPublications $service.ports $allowedIps
if ($wrong.Count) {
    Stop-WithMessage ("Порт интерфейса был бы опубликован на: $($wrong -join ', '). Так нельзя: допустимы только " +
        "127.0.0.1$(if ($lan) { " и $lanAddr" }). Проверьте TRIAGE_PORT и TRIAGE_LAN_ADDR в .env и переменных окружения.")
}
$repos = $service.volumes | Where-Object { $_.target -eq '/repos' } | Select-Object -First 1
if (-not $repos -or -not $repos.source) {
    Stop-WithMessage "В .env не задан REPOS_ROOT – корень папок с репозиториями. Запустите .\start.ps1 -ReposRoot $(Get-DefaultReposRoot $PSScriptRoot)"
}
if (-not (Test-Path -LiteralPath $repos.source -PathType Container)) {
    Stop-WithMessage "Корень папок с репозиториями не найден: $($repos.source). Укажите другой: .\start.ps1 -ReposRoot D:/work"
}
$data = $service.volumes | Where-Object { $_.target -eq '/data' } | Select-Object -First 1
if ($data -and $data.source) {
    New-Item -ItemType Directory -Force -Path $data.source | Out-Null
}
$port = [string](($service.ports | Select-Object -First 1).published)
if (-not $port) { $port = '8765' }
# Путь к корню папок с репозиториями на этом компьютере – для подсказок в интерфейсе («куда клонировать»)
$env:REPOS_ROOT_HOST = ConvertTo-EnvPath ([string]$repos.source)

# Демо: в папку для клонов по умолчанию кладётся копия демо-репозиториев (кнопка «Создать демо-проект» находит её
# при любой глубине папки приложения); подключены только сами демо-репозитории – подсказка про свою папку
$demoRepos = Join-Path $PSScriptRoot 'examples\demo\repos'
$reposFull = [IO.Path]::GetFullPath([string]$repos.source).TrimEnd('\')
$reposIsDemo = (Test-Path -LiteralPath $demoRepos -PathType Container) -and
        ($reposFull -ieq [IO.Path]::GetFullPath($demoRepos).TrimEnd('\'))
# признак для приложения: предупреждение «Демонстрационные репозитории» – только по факту подключения демо-папки (бэклог 94)
$env:REPOS_ROOT_IS_DEMO = if ($reposIsDemo) { '1' } else { '0' }
if ($reposIsDemo) {
    Write-Host ('Подключены только демо-репозитории. Чтобы выбирать в приложении свои папки, подключите папку для клонов: ' +
        ".\start.ps1 -ReposRoot $defaultRoot") -ForegroundColor Yellow
} elseif ($reposFull -ieq [IO.Path]::GetFullPath($defaultRoot.Replace('/', '\')).TrimEnd('\')) {
    $copied = Copy-DemoRepos $PSScriptRoot $reposFull
    if ($copied) { Write-Host "Демо-репозитории скопированы в $copied – для кнопки «Создать демо-проект»." }
}

$imageName = if ($service.image) { [string]$service.image } else { 'local-triage:latest' }  # другой тег – TRIAGE_IMAGE в .env
$image = docker image ls --quiet $imageName
if ($Build -or -not $image) {
    Write-Host "Сборка образа $imageName..."
    # Коммит и время сборки – для плашки внизу страниц: видно, из какого кода собран открытый в браузере образ.
    # Сведения необязательные: без git или без папки .git (перенесённая копия) сборка идёт дальше с «неизвестен»
    $env:BUILD_COMMIT = 'unknown'
    $env:BUILD_DIRTY = 'unknown'
    $env:BUILD_TIME = (Get-Date).ToString('dd.MM.yyyy HH:mm')
    $stopPreference = $ErrorActionPreference
    # при 'Stop' сообщение git в stderr прервало бы сценарий в Windows PowerShell 5.1 раньше проверки кода выхода
    $ErrorActionPreference = 'Continue'
    try {
        if (Get-Command git -ErrorAction SilentlyContinue) {
            $head = & git -C $PSScriptRoot rev-parse --short HEAD 2>$null
            if ($LASTEXITCODE -eq 0 -and "$head".Trim() -match '^[0-9a-f]{7,40}$') {
                $env:BUILD_COMMIT = "$head".Trim()
                # правки вне коммита – в том, что входит в образ, включая новые файлы; сбой проверки – «не проверено»
                $changes = & git -C $PSScriptRoot status --porcelain --untracked-files=all -- app Dockerfile `
                    .dockerignore requirements.lock examples/demo/demo-hub-report.xlsx 2>$null
                if ($LASTEXITCODE -eq 0) { $env:BUILD_DIRTY = if ("$changes".Trim()) { '1' } else { '0' } }
            }
        }
    } catch {
        $env:BUILD_COMMIT = 'unknown'
        $env:BUILD_DIRTY = 'unknown'
    } finally {
        $ErrorActionPreference = $stopPreference
    }
    & docker @compose build
    if ($LASTEXITCODE -ne 0) {
        Stop-WithMessage 'Образ не собрался. Без интернета загрузите готовый образ: scripts\import-image.ps1'
    }
}

# База – первой: готовность сервера и совместимость схемы проверяются отдельно от запуска приложения, сбой базы не повод убирать GPU
# значение окна PowerShell не должно пережить запуск: постоянный режим задаётся строкой TRIAGE_MAINTENANCE в .env
if ($Maintenance) { $env:TRIAGE_MAINTENANCE = '1' } else { Remove-Item Env:TRIAGE_MAINTENANCE -ErrorAction SilentlyContinue }
& docker @base up -d --wait --no-build db
if ($LASTEXITCODE -ne 0) {
    Stop-WithMessage 'Контейнер базы не запустился или не стал готов. Журнал: docker compose logs db'
}
$schema = Get-SchemaState $base
$dataDir = if ($data -and $data.source) { [string]$data.source } else { '' }
# до обновления схемы и запуска приложения: утраченную базу не подменяют пустой
$blocker = Get-StartBlocker ([string]$schema.state) $dataDir ([bool]$NewDatabase)
if ($blocker) { Stop-WithMessage $blocker }
if ($schema.state -eq 'migrate') {
    if (-not $Migrate) {
        Stop-WithMessage ("Схема основной базы $($schema.schema), этой сборке нужна $($schema.expected). Обновление с копией: " +
            '.\start.ps1 -Migrate')
    }
    & docker @base stop triage
    if ($LASTEXITCODE -ne 0) { Stop-WithMessage 'Приложение не остановлено: копия и обновление схемы не выполнялись.' }
    & (Join-Path $PSScriptRoot 'scripts\backup-db.ps1') -Check
    if ($LASTEXITCODE -ne 0) { Stop-WithMessage 'Копия перед обновлением схемы не создана или не проверена: схема не менялась.' }
    Invoke-StorageTool $base @('migrate') | Out-Null
    $schema = Get-SchemaState $base
}
# файлы состояния – в базу до запуска приложения; прерванный перенос продолжается той же командой; сверка не прошла – приложение
# не запускается (ADR-0133)
if ($schema.local_state_pending) {
    if (-not ($Migrate -or $NewDatabase)) {
        Stop-WithMessage ('В папке данных есть файлы состояния, а в базу они не перенесены. Перенос: .\start.ps1 -Migrate')
    }
    & docker @base stop triage
    if ($LASTEXITCODE -ne 0) { Stop-WithMessage 'Приложение не остановлено: перенос файлов состояния не начат.' }
    # для отката на прежнюю сборку файлы нужны и после очистки папки данных; копия – рядом с копиями базы
    try {
        $kept = Join-Path $PSScriptRoot 'backups\before-local-state'
        New-Item -ItemType Directory -Force -Path $kept | Out-Null
        foreach ($item in @('feeds.db', 'feeds.db-wal', 'mask.key', 'hub-worker.key', 'providers')) {
            $from = Join-Path $dataDir $item
            if (Test-Path -LiteralPath $from) { Copy-Item -LiteralPath $from -Destination $kept -Recurse -Force -ErrorAction Stop }
        }
    } catch {
        Stop-WithMessage "Копия файлов состояния в backups\before-local-state не создана: $($_.Exception.Message). Перенос не начат."
    }
    Invoke-StorageTool $base @('local-state-import') | Out-Null
    Invoke-StorageTool $base @('local-state-verify') | Out-Null
    $schema = Get-SchemaState $base
}
if ($schema.state -notin @('ok', 'empty')) {
    Stop-WithMessage ("Основная база не подходит этой сборке: состояние $($schema.state), схема $($schema.schema), " +
        "нужна $($schema.expected). Приложение не запущено, база не менялась.")
}

& docker @compose up -d --no-build
if ($LASTEXITCODE -ne 0 -and $gpu) {
    # Например, «could not select device driver nvidia»: GPU в Docker Desktop недоступен (старый драйвер, движок
    # Hyper-V, политика). Метрики видеокарты необязательны – приложение запускается без неё.
    Write-Host 'Видеокарту не удалось подключить к контейнеру. Запускаю без неё: метрики видеокарты не будут видны, видеопамять – по данным Ollama. Чтобы не пробовать каждый раз, запускайте .\start.ps1 -NoGpu' -ForegroundColor Yellow
    $compose = $base
    & docker @compose up -d --no-build
}
if ($LASTEXITCODE -ne 0) {
    Stop-WithMessage 'Контейнер не запустился. Журнал: docker compose logs triage'
}

$url = "http://127.0.0.1:$port"
Write-Host "Жду ответа приложения на $url ..."
$ready = $false
for ($i = 0; $i -lt 60 -and -not $ready; $i++) {
    $ready = Test-Url "$url/healthz"
    if (-not $ready) { Start-Sleep -Seconds 1 }
}
if (-not $ready) {
    $reason = (Get-AppJson "$url/healthz").Json
    if ($reason -and $reason.status) {
        Stop-WithMessage "Приложение запущено, но не готово: $($reason.status). Журнал: docker compose logs triage"
    }
    Stop-WithMessage 'Приложение не ответило за минуту. Журнал: docker compose logs triage'
}

# Ollama – так, как её видит приложение в контейнере: по адресу из его настроек и тем же путём, которым пойдут
# запросы к модели (host.docker.internal, файл hosts контейнера, проверка адресов). Проверка отсюда, с этого
# компьютера, показала бы только, что Ollama жива здесь.
$ollamaUrl = [string]$service.environment.OLLAMA_URL
if (-not $ollamaUrl) { $ollamaUrl = 'http://host.docker.internal:11434' }
$check = Get-AppJson "$url/api/ollama"
if ($check.Status -eq 200 -and $check.Json) {
    $ollama = $check.Json
    if ($ollama.url) { $ollamaUrl = [string]$ollama.url }
    $lanProfile = $ollama.profile -and [string]$ollama.profile.trust -eq 'lan'
    if ($ollama.profile) {
        Write-Host ("Код по умолчанию разбирает профиль «{0}» ({1}): {2}" -f $ollama.profile.name, $ollama.profile.where, $ollamaUrl)
    }
    if ($ollama.error -and $lanProfile) {
        # сервер в сети организации (ADR-0102): Ollama там должна слушать сеть, межсетевой экран – пропускать порт
        # только с этого компьютера; адреса сервера подтверждаются в приложении
        Write-Host ("Сервер модели в сети не ответил приложению: $($ollama.error) На том компьютере Ollama должна " +
            'слушать сеть (переменная OLLAMA_HOST=0.0.0.0 и перезапуск Ollama), а межсетевой экран – пропускать порт ' +
            '11434 только с адреса этого компьютера. Адреса сервера подтверждаются на странице «Настройки → ' +
            'Провайдеры моделей». Подробнее – docs/lan-model-server.md.') -ForegroundColor Yellow
    } elseif ($ollama.error) {
        Show-OllamaHelp ([string]$ollama.error) $ollamaUrl
    } else {
        $models = @($ollama.models)
        Write-Host ('Ollama {0} отвечает приложению в контейнере ({1}), моделей: {2}.' -f $ollama.version, $ollamaUrl, $models.Count)
        if ($models.Count -eq 0) {
            Write-Host 'В Ollama нет ни одной модели. Загрузите модель, например: ollama pull gpt-oss:20b' -ForegroundColor Yellow
        } elseif ($ollama.default_model -and $ollama.default_model_found -eq $false) {
            Write-Host "Модели по умолчанию $($ollama.default_model) в Ollama нет. Загрузите её: ollama pull $($ollama.default_model) – или выберите другую модель на странице «Настройки»." -ForegroundColor Yellow
        }
    }
} elseif ($check.Status -eq 404) {
    # Образ приложения старше этого сценария: доступ к Ollama из контейнера видно по метрикам приложения
    $metrics = Get-AppJson "$url/api/metrics"
    if ($metrics.Json -and $metrics.Json.error) {
        Show-OllamaHelp ([string]$metrics.Json.error) $ollamaUrl
    } elseif ($metrics.Json) {
        Write-Host 'Ollama отвечает приложению в контейнере.'
    }
} else {
    Write-Host 'Доступ к Ollama из контейнера проверить не удалось. Журнал: docker compose logs triage' -ForegroundColor Yellow
}

# Демо-выгрузки нет (например, папку принесли без неё) – она строится в образе приложения (Python и openpyxl там
# уже есть, на этом компьютере ничего ставить не нужно)
$demoXlsx = Join-Path $PSScriptRoot 'examples\demo\demo-hub-report.xlsx'
if ((Test-Path -LiteralPath $demoRepos -PathType Container) -and -not (Test-Path -LiteralPath $demoXlsx)) {
    Write-Host 'Строю демо-выгрузку examples\demo\demo-hub-report.xlsx ...'
    & docker run --rm --network none -v "${PSScriptRoot}:/work" -w /work local-triage:latest python scripts/make_demo_xlsx.py
    if ($LASTEXITCODE -ne 0) {
        Write-Host 'Демо-выгрузку построить не удалось – см. README, раздел «Демо».' -ForegroundColor Yellow
    }
}

Write-Host "Готово: $url"
if ($lan) {
    if ($LanAddress) { Set-LanAddress $PSScriptRoot $lanAddr }  # адрес в .env – только после успешного запуска
    if (Test-Url "http://${lanAddr}:$port/healthz") {
        Write-Host ("Интерфейс опубликован и в локальной сети: http://${lanAddr}:$port (только http) – с этого компьютера " +
            'адрес ответил; доступ из ВМ проверьте, открыв его там. Входа по паролю нет: каждому, кто достанет до ' +
            'этого адреса, доступно всё – карточки с кодом, настройки, загрузка, разбор, удаление проектов. Только ' +
            'этот компьютер: .\start.ps1 -LocalOnly') -ForegroundColor Yellow
    } else {
        Write-Host ("Адрес в локальной сети http://${lanAddr}:$port с этого компьютера не ответил: интерфейс точно " +
            "доступен на $url. Журнал: docker compose logs triage") -ForegroundColor Yellow
    }
} elseif ($lanNote) {
    Write-Host $lanNote -ForegroundColor Yellow
}
Write-Host 'Адрес Ollama, модель по умолчанию и статусы Hub – в приложении, страница «Настройки»; справочники БДУ, CWE и CAPEC – страница «Справочники».'
# Копии базы лежат на этом компьютере, приложение в контейнере их не видит: возраст последней проверенной – по файлам папки копий
try { Show-LastCheckedBackup (Join-Path $PSScriptRoot 'backups') }
catch { Write-Host "Сведения о копиях базы получить не удалось: $($_.Exception.Message)" -ForegroundColor Yellow }
# Метрики относятся к компьютеру, на котором запускается этот сценарий и работает местная Ollama.
try { & (Join-Path $PSScriptRoot 'scripts\host-metrics.ps1') -Action Start -DataDir (Join-Path $PSScriptRoot 'data') }
catch {
    if ($Maintenance) {
        # в обслуживании приложение не обновляет аренду сборщика: сбой здесь ожидаем, при обычном запуске сборщик поднимается сам
        Write-Host ('Сборщик метрик в режиме обслуживания не запущен: для обслуживания он не нужен, при обычном запуске ' +
            'start.ps1 поднимется сам. Подробность: ' + $_.Exception.Message)
    } else {
        Write-Host ('Метрики RAM/CPU хоста и адреса этого компьютера недоступны: ' + $_.Exception.Message + ' Триаж ' +
            'продолжает работу; внешние провайдеры моделей (LLM_EXTERNAL=1) без свежих адресов компьютера запросов не ' +
            'отправят – перезапустите start.ps1.') -ForegroundColor Yellow
    }
}
if (-not $NoBrowser) {
    Start-Process $url
}
