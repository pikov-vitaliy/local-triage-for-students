"""Общие настройки тестов: корень репозитория в пути импорта, параметры запуска проверок в браузере и несколько
общих заготовок.

Проверки в браузере (tests/e2e) по умолчанию пропускаются: их запускает scripts/run-e2e.ps1 или
`pytest tests/e2e --e2e`. Проверка с настоящей моделью в Ollama этого компьютера – ещё и с `--real-model`.
"""

from __future__ import annotations

import socket
import sys
from pathlib import Path

import pytest

# Ответ службы имён по каждому имени запоминается на весь прогон. Тестовые адреса (example.org и др., RFC 2606)
# разрешает app/llm_net.py перед соединением; через медленный DNS (VPN) одно разрешение шло около 11 с, и прогон
# растягивался до часа. Ответы те же, что дал DNS при первом обращении, – поведение тестов не меняется; отказы
# (несуществующее имя) не запоминаются. Тесты, подменяющие getaddrinfo сами, получают эту обёртку как «настоящую».
_real_getaddrinfo = socket.getaddrinfo
_dns_answers: dict = {}


def _remembered_getaddrinfo(host, port, *args, **kwargs):
    key = (host, port, args, tuple(sorted(kwargs.items())))
    if key not in _dns_answers:
        _dns_answers[key] = list(_real_getaddrinfo(host, port, *args, **kwargs))
    return list(_dns_answers[key])


socket.getaddrinfo = _remembered_getaddrinfo

# create_app в одном процессе вкладывает обработчики запуска маршрутизаторов друг в друга (FastAPI): за прогон стек запуска
# растёт на тесты, в работе приложения глубина мала (около 65 вызовов)
sys.setrecursionlimit(10000)

ROOT = Path(__file__).resolve().parent.parent
TESTS = Path(__file__).resolve().parent
for folder in (ROOT, TESTS):
    if str(folder) not in sys.path:
        sys.path.insert(0, str(folder))

import db_support  # noqa: E402 – после настройки путей


def pytest_addoption(parser: pytest.Parser) -> None:
    group = parser.getgroup("local-triage", "проверки в браузере (tests/e2e)")
    group.addoption("--e2e", action="store_true", default=False,
                    help="запустить проверки в браузере: приложение из .venv, поддельная Ollama, системный Edge или "
                         "Chrome")
    group.addoption("--real-model", action="store", nargs="?", const="gpt-oss:20b", default="",
                    metavar="МОДЕЛЬ",
                    help="ещё и проверка с настоящей моделью в Ollama на 127.0.0.1:11434 (по умолчанию "
                         "gpt-oss:20b)")
    group.addoption("--browser-channel", action="store", default="",
                    help="браузер: chrome (по умолчанию) или msedge – только явно")
    group.addoption("--headed", action="store_true", default=False, help="показывать окно браузера")


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "e2e: проверка в браузере (запуск – scripts/run-e2e.ps1 или --e2e)")
    config.addinivalue_line("markers", "real_model: проверка с настоящей моделью в Ollama (--real-model)")
    config.addinivalue_line("markers", "docker_db: копии и восстановление базы в Docker – на кластере учебного стенда "
                                       "не идут (pytest -m \"not docker_db\", ADR-0155)")


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    run_e2e = config.getoption("--e2e")
    real_model = config.getoption("--real-model")
    skip_e2e = pytest.mark.skip(reason="проверка в браузере: запуск – scripts/run-e2e.ps1 или pytest --e2e")
    skip_real = pytest.mark.skip(reason="проверка с настоящей моделью: запуск – scripts/run-e2e.ps1 -RealModel "
                                        "или pytest --e2e --real-model")
    for item in items:
        if "e2e" in item.keywords and not run_e2e:
            item.add_marker(skip_e2e)
        elif "real_model" in item.keywords and not real_model:
            item.add_marker(skip_real)


def pytest_sessionstart(session) -> None:
    db_support.install()


def pytest_sessionfinish(session, exitstatus) -> None:
    db_support.finish()


# Потоки прогонов, запущенные в тестах (бэклог 125). Тест, который не остановил свой поток, оставлял его работать после
# удаления базы: поток раз за разом писал в общий журнал «очередь прогонов недоступна» и вызывал подменённые другими
# тестами функции – отсюда редкие падения чужих тестов в полном прогоне.
_started_runners: list = []
_leaked_runners: list[str] = []
_stuck_runners: list[str] = []
_GONE = {"PoolClosed", "DatabaseUnavailable"}  # базы нет: пул закрыт или соединение не открывается


def _watch_runners() -> None:
    from app.triage import TriageRunner
    if getattr(TriageRunner.start, "_watched", False):
        return
    real_start = TriageRunner.start

    def start(self, *args, **kwargs):
        if not any(known is self for known in _started_runners):
            _started_runners.append(self)
        return real_start(self, *args, **kwargs)

    start._watched = True  # type: ignore[attr-defined]
    TriageRunner.start = start  # type: ignore[method-assign]


def _stop_runners_without_database(where: str) -> None:
    """Останавливает потоки прогонов, чья база уже закрыта или удалена; живые базы фикстур модуля не трогает."""
    for runner in list(_started_runners):
        thread = getattr(runner, "_thread", None)
        if thread is None or not thread.is_alive():
            _started_runners.remove(runner)
            continue
        if runner._halt.is_set():
            continue  # уже останавливается: доработает текущую находку и выйдет
        try:
            runner.db._scalar("SELECT 1")
            continue
        except Exception as e:  # noqa: BLE001 – разбирается ниже по виду ошибки
            chain, seen = [], e
            while seen is not None and len(chain) < 8:
                chain.append(type(seen).__name__)
                seen = seen.__cause__ or seen.__context__
        if not _GONE.intersection(chain):
            continue  # база жива, но запрос не прошёл (например, пул занят) – не утечка
        _leaked_runners.append(where)
        if runner.shutdown():
            _started_runners.remove(runner)
        else:  # поток не вышел за время ожидания: остаётся под наблюдением, в итоге назван отдельно
            _stuck_runners.append(where)


def pytest_terminal_summary(terminalreporter) -> None:
    if _leaked_runners:
        terminalreporter.write_sep("-", "потоки прогонов остались без базы, запрошена остановка (бэклог 125)")
        for where in sorted(set(_leaked_runners)):
            note = " – поток не завершился за время ожидания" if where in _stuck_runners else ""
            terminalreporter.write_line(f"  {where}{note}")


@pytest.fixture(autouse=True)
def _databases_of_this_test(request):
    """Базы, созданные за время теста, удаляются после него; базы фикстур модуля живут до конца прогона. Поток
    прогонов, оставшийся без базы, останавливается здесь же."""
    _watch_runners()
    before = db_support.known_databases()
    yield
    db_support.drop_created_since(before)
    _stop_runners_without_database(request.node.nodeid)


@pytest.fixture
def mask_key() -> bytes:
    """Постоянный ключ маскирования: номера плейсхолдеров в тестах воспроизводимы."""
    return bytes(range(32))


@pytest.fixture
def hub_xlsx(tmp_path: Path) -> Path:
    """Синтетический отчёт AppSec.Hub (tests/hub_fixtures.py) во временной папке."""
    from hub_fixtures import make_hub_xlsx

    return make_hub_xlsx(tmp_path / "hub-report.xlsx")

@pytest.fixture(autouse=True)
def no_affiliation_words():
    """Маска принадлежности (ADR-0118) – состояние процесса: тест задаёт слова сам, остальные идут без них."""
    from app import affiliation
    affiliation.configure(())
    yield
    affiliation.configure(())


@pytest.fixture(autouse=True)
def no_retry_sleep(monkeypatch):
    """Паузы между повторами после сбоя службы имён (ADR-0113) в тестах не ждутся: сбой имени в тестах – подмена
    getaddrinfo, настоящая пауза лишь замедлила бы прогон. Тесты повторов подменяют _sleep сами и считают паузы."""
    from app import llm_net, sca_research_net
    monkeypatch.setattr(llm_net, "_sleep", lambda seconds: None)
    monkeypatch.setattr(sca_research_net, "_sleep", lambda seconds: None)
