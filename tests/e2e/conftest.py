"""Проверки в браузере: приложение из .venv на порту, выделенном ОС при запуске, поддельная Ollama (tests/fake_ollama.py)
и системный Chrome через Playwright (Edge – только явно, --browser-channel msedge). Браузеры Playwright не скачиваются. Заготовки – e2e_support.py.

Запуск: scripts/run-e2e.ps1 (или `pytest tests/e2e --e2e`); с настоящей моделью – scripts/run-e2e.ps1 -RealModel.

Явный запуск проверок в браузере не может «пройти», ничего не проверив: нет браузера, свободного порта, Ollama или
модели при --real-model – ошибка, а не пропуск; если ни одна проверка в браузере не выполнилась, итог запуска –
ошибка (pytest_sessionfinish).
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from e2e_support import REAL_OLLAMA, AppServer, AppStartError, make_fake_ollama, ollama_models, open_page, \
    start_app, stop_app


@pytest.fixture(scope="session")
def app_server(tmp_path_factory: pytest.TempPathFactory) -> Iterator[AppServer]:
    """Приложение с поддельной Ollama – одно на все проверки в браузере."""
    fake = make_fake_ollama()
    try:
        server = start_app(tmp_path_factory.mktemp("e2e-app"), fake.url)
    except AppStartError as e:
        fake.close()
        if "свободного порта" in str(e):
            pytest.fail(str(e), pytrace=False)
        raise
    server.fake = fake
    try:
        yield server
    finally:
        stop_app(server.process)
        fake.close()


@pytest.fixture(scope="session")
def real_model(request: pytest.FixtureRequest) -> str:
    """Имя настоящей модели (--real-model); нет Ollama или модели – проверка пропускается."""
    name = str(request.config.getoption("--real-model") or "")
    models = ollama_models()
    if not models:
        pytest.fail(f"Ollama не отвечает на {REAL_OLLAMA}", pytrace=False)
    if name not in models:
        pytest.fail(f"В Ollama нет модели {name}: ollama pull {name}", pytrace=False)
    return name


@pytest.fixture(scope="session")
def real_app_server(tmp_path_factory: pytest.TempPathFactory, real_model: str) -> Iterator[AppServer]:
    """Приложение с настоящей Ollama этого компьютера – только для проверки с меткой real_model."""
    server = start_app(tmp_path_factory.mktemp("e2e-real"), REAL_OLLAMA)
    try:
        yield server
    finally:
        stop_app(server.process)


@pytest.fixture(scope="session")
def browser(request: pytest.FixtureRequest):
    """Системный Chrome (иной канал – --browser-channel), без окна, если не задано --headed."""
    sync_api = pytest.importorskip(
        "playwright.sync_api", reason="нет Playwright: .venv\\Scripts\\python -m pip install -r requirements-dev.txt")
    wanted = str(request.config.getoption("--browser-channel") or "")
    channels = [wanted] if wanted else ["chrome"]
    headless = not request.config.getoption("--headed")
    pw = sync_api.sync_playwright().start()
    found, errors = None, []
    for channel in channels:
        try:
            found = pw.chromium.launch(channel=channel, headless=headless)
            break
        except Exception as e:  # такого браузера на компьютере нет
            errors.append(f"{channel}: {str(e).splitlines()[0]}")
    if found is None:
        pw.stop()
        pytest.fail("Не найден системный браузер: " + "; ".join(errors), pytrace=False)
    try:
        yield found
    finally:
        found.close()
        pw.stop()


@pytest.fixture
def ui(browser, app_server: AppServer):
    """Вкладка с приложением на поддельной Ollama: (page, watch). После проверки – ни ошибок скриптов и консоли,
    ни запросов на другие адреса."""
    context, page, watch = open_page(browser, app_server.url)
    yield page, watch
    problems = watch.problems()
    context.close()
    assert not problems, "\n".join(problems)


# ============================================================================ итог запуска

_RAN = {"passed": 0}


def pytest_runtest_logreport(report: pytest.TestReport) -> None:
    if report.when == "call" and report.passed and "e2e" in report.keywords:
        _RAN["passed"] += 1


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    """С --e2e ни одной выполненной проверки в браузере – ошибка запуска: зелёный итог без проверок обманчив."""
    if session.config.getoption("--e2e") and exitstatus == 0 and _RAN["passed"] == 0:
        session.exitstatus = pytest.ExitCode.TESTS_FAILED
        reporter = session.config.pluginmanager.get_plugin("terminalreporter")
        if reporter is not None:
            reporter.write_line("Ни одна проверка в браузере не выполнилась – запуск считается неудачным.", red=True)
