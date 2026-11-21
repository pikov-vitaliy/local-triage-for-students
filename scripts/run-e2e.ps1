<#
.SYNOPSIS
    Проверки в браузере (tests/e2e): весь путь работы с приложением на демо-данных.

.DESCRIPTION
    Запускает приложение из окружения разработки (.venv) на порту, выделенном ОС при запуске с временной папкой данных
    и корнем папок с репозиториями examples/demo/repos, поддельную Ollama и системный Chrome через
    Playwright. Браузеры Playwright не скачиваются, контейнер и его данные не затрагиваются.

    Сценарий: демо-проект, список находок, триаж, карточка, согласие, «Проверено», «Скопировать для Hub»,
    «Внесено в Hub», вопрос к модели, задание и пакет SCA для внешних агентов, загрузка их ответов, повторный
    импорт с сохранением решений; настройки, обзор папок, архив и удаление, клавиши и тема, вёрстка до 360 px;
    статусы Hub по-русски, «Риск принят», «Дефект для Hub» (SAST и SCA), страница «Справочники» с выдуманными фидами.

    Итог честный: если браузер не найден, нет свободного порта, а с -RealModel – Ollama или модели, это ошибка,
    а не пропуск; если ни одна проверка в браузере не выполнилась, сценарий завершается с ошибкой.

    Нужно окружение разработки (один раз, из корня репозитория):
        python -m venv .venv
        .venv\Scripts\python -m pip install -r requirements.txt -r requirements-dev.txt

.PARAMETER RealModel
    Ещё и проверка с настоящей моделью в Ollama на 127.0.0.1:11434: разбор двух находок и вопрос к модели.

.PARAMETER Model
    Модель для -RealModel, по умолчанию gpt-oss:20b (модель по умолчанию приложения).

.PARAMETER Browser
    chrome или msedge. По умолчанию – chrome.

.PARAMETER Headed
    Показывать окно браузера.

.PARAMETER Filter
    Только проверки, подходящие под выражение pytest -k, например -Filter settings.
.PARAMETER TimeoutMs
    Общий предел ожидания элементов и переходов в браузере, мс (по умолчанию 15000). Под нагрузкой –
    параллельные прогоны тестов на том же компьютере – ставьте 30000; сами ожидания идут по событиям, а не паузами.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\scripts\run-e2e.ps1
.EXAMPLE
    .\scripts\run-e2e.ps1 -RealModel
.EXAMPLE
    .\scripts\run-e2e.ps1 -RealModel -Model qwen2.5-coder:14b
.EXAMPLE
    .\scripts\run-e2e.ps1 -Browser chrome -Headed
#>
[CmdletBinding()]
param(
    [switch]$RealModel,
    [string]$Model = 'gpt-oss:20b',
    [ValidateSet('', 'msedge', 'chrome')]
    [string]$Browser = '',
    [switch]$Headed,
    [string]$Filter = '',
    [int]$TimeoutMs = 15000
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $root

$python = Join-Path $root '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    Write-Host 'Нет окружения разработки .venv. Создайте его из корня репозитория:' -ForegroundColor Red
    Write-Host '  python -m venv .venv'
    Write-Host '  .venv\Scripts\python -m pip install -r requirements.txt -r requirements-dev.txt'
    exit 1
}
& $python -c 'import playwright, pytest' 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host 'В .venv нет Playwright или pytest. Установите зависимости для разработки:' -ForegroundColor Red
    Write-Host '  .venv\Scripts\python -m pip install -r requirements.txt -r requirements-dev.txt'
    exit 1
}

$arguments = @('-m', 'pytest', 'tests/e2e', '--e2e', '-p', 'no:cacheprovider', '-q', '-rs')
if ($RealModel) {
    $arguments += @("--real-model=$Model")
    Write-Host "Ещё и с настоящей моделью: $Model (Ollama на 127.0.0.1:11434)."
}
if ($Browser) { $arguments += @('--browser-channel', $Browser) }
if ($Headed) { $arguments += @('--headed') }
if ($Filter) { $arguments += @('-k', $Filter) }
$env:E2E_TIMEOUT_MS = "$TimeoutMs"

$env:PYTHONUTF8 = '1'
$env:PYTHONIOENCODING = 'utf-8'
& $python @arguments
$code = $LASTEXITCODE
if ($code -eq 0) {
    Write-Host 'Проверки в браузере прошли.' -ForegroundColor Green
} else {
    Write-Host "Проверки в браузере не прошли (код $code). Журнал приложения – app.log во временной папке pytest." -ForegroundColor Red
}
exit $code
