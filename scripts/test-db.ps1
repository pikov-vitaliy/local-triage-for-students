<#
.SYNOPSIS
    Отдельный контейнер PostgreSQL для тестов: порт 127.0.0.1:5433, данные в памяти (tmpfs), рабочую базу не трогает.

.DESCRIPTION
    pytest без него не запускается (tests/conftest.py, переменная TRIAGE_TEST_DSN): запасного варианта нет. Контейнер
    создаётся один раз и живёт между прогонами; -Reset пересоздаёт его (пустой сервер).

.EXAMPLE
    .\scripts\test-db.ps1
    .venv\Scripts\python -m pytest
#>
[CmdletBinding()]
param([switch]$Reset)
$ErrorActionPreference = 'Stop'
$name = 'triage-test-pg'
# тот же образ, что у сервиса db в docker-compose.yml
$image = 'postgres:17.9-alpine@sha256:6f30057d31f5861b66f3545d4821f987aacf1dd920765f0acadea0c58ff975b1'
$exists = docker ps -a --filter "name=^$name$" --format '{{.Names}}'
if ($Reset -and $exists) { docker rm -f $name | Out-Null; $exists = $null }
if ($exists) {
    docker start $name | Out-Null
} else {
    docker run -d --name $name --restart unless-stopped `
        -e POSTGRES_PASSWORD=triage-test -e POSTGRES_USER=triage -e POSTGRES_DB=postgres `
        -e 'POSTGRES_INITDB_ARGS=--encoding=UTF8 --locale=C --lc-ctype=C.UTF-8' `
        -p 127.0.0.1:5433:5432 --tmpfs /var/lib/postgresql/data:rw,size=4g `
        $image -c fsync=off -c synchronous_commit=off -c full_page_writes=off -c max_connections=400 | Out-Null
}
for ($i = 0; $i -lt 60; $i++) {
    docker exec $name pg_isready -U triage *> $null
    if ($LASTEXITCODE -eq 0) { Write-Host "Тестовая база готова: 127.0.0.1:5433"; exit 0 }
    Start-Sleep -Seconds 1
}
Write-Host 'Тестовая база не ответила за минуту. Журнал: docker logs triage-test-pg' -ForegroundColor Red
exit 1
