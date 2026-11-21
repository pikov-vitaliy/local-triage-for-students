"""Заготовки проверок в браузере: ответы поддельной модели, запуск приложения из этого окружения Python,
вкладка браузера с наблюдением за ошибками и запросами, частые шаги сценария.

Корень папок с репозиториями – examples/demo/repos, папка данных – временная: в проверки не попадают ни настоящие
выгрузки, ни папки с диска.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from fake_ollama import FakeOllama, ask_answer, is_ask_request, verdict_answer

ROOT = Path(__file__).resolve().parents[2]
DEMO = ROOT / "examples" / "demo"
DEMO_REPOS = DEMO / "repos"
DEMO_REPORT = DEMO / "demo-hub-report.xlsx"
DEMO_REPORT_V2 = DEMO / "demo-hub-report-v2.xlsx"
DEMO_ANSWERS = DEMO / "sca-answers.json"
REAL_OLLAMA = "http://127.0.0.1:11434"

# ============================================================================ ответы поддельной модели

_TARGET = re.compile(r"^Строка срабатывания(?: в файле репозитория)?: (\d+)\s*$", re.M)
_ENCLOSING = re.compile(r"^Объемлющий метод или функция: (.*)$", re.M)
# Безопасные места демо (examples/demo/README.md): поддельная модель называет их ложными срабатываниями
_SAFE = ("findByStatus", "downloadReport", "shuffleBannerOrder", "get_product", "load_import_settings")


def _prompt_text(body: dict[str, Any]) -> str:
    messages = body.get("messages") if isinstance(body.get("messages"), list) else []
    return "\n".join(str(m.get("content") or "") for m in messages if isinstance(m, dict))


def e2e_reply(body: dict[str, Any]) -> dict[str, Any]:
    """Ответ поддельной модели: ссылки «строка N» ведут на строку срабатывания из промпта, так что в карточке они
    кликабельны; вердикт зависит от метода с находкой, на один и тот же запрос ответ всегда один."""
    text = _prompt_text(body)
    lines = [int(n) for n in _TARGET.findall(text)]
    line = lines[-1] if lines else 0
    where = f"строка {line}" if line else "строка срабатывания"
    if is_ask_request(body):
        return ask_answer(f"Значение приходит из параметра запроса и без проверки доходит до вызова ({where}). "
                          "Если бы оно приходило из сессии, вердикт был бы тем же: проверки всё равно нет.")
    enclosing = " ".join(_ENCLOSING.findall(text))
    if "Код: нет" in text or "только строка срабатывания" in text:
        verdict = "uncertain"
    elif any(name in enclosing for name in _SAFE):
        verdict = "false_positive"
    else:
        verdict = "true_positive"
    return verdict_answer(
        verdict, 85,
        what_code_does=f"Метод принимает значение из запроса и передаёт его дальше ({where}).",
        why=[f"Значение берётся из запроса ({where}).", "Проверки или экранирования перед использованием не видно."],
        data_flow=[f"{where}: значение из запроса используется в вызове"],
        evidence_lines=[line] if line else [],
        check_by_eye=[f"Откуда приходит значение ({where}).", "Нет ли проверки выше по коду."],
        terms=[{"term": "срабатывание", "meaning": "место в коде, на которое указал анализатор"}],
    )


def make_fake_ollama() -> FakeOllama:
    return FakeOllama(default_answer=e2e_reply)


def private_ipv4() -> str | None:
    """Частный IPv4 этого компьютера (RFC 1918) для поддельного сервера в сети организации. В Windows – адрес
    адаптера vEthernet (обычно внутренний коммутатор Hyper-V или WSL; проверяется только имя адаптера, что адрес
    не виден из других сетей – нет); иначе – любой частный адрес. Нет – None: e2e сервера в сети пропускается с причиной."""
    import ipaddress
    import socket
    import subprocess
    if sys.platform == "win32":
        try:
            out = subprocess.run(["powershell", "-NoProfile", "-Command",
                                  "Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -like "
                                  "'vEthernet*' } | Select-Object -ExpandProperty IPAddress"],
                                 capture_output=True, text=True, timeout=30).stdout.split()
        except (OSError, subprocess.SubprocessError):
            out = []
        for address in out:
            try:
                if ipaddress.ip_address(address).is_private and not ipaddress.ip_address(address).is_link_local:
                    return address
            except ValueError:
                continue
    found = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            found.add(str(info[4][0]))
    except OSError:
        return None
    order = [ipaddress.ip_network(n) for n in ("172.16.0.0/12", "10.0.0.0/8", "192.168.0.0/16")]
    for network in order:
        for address in sorted(found):
            if ipaddress.ip_address(address) in network:
                return address
    return None


# ============================================================================ приложение

@dataclass
class AppServer:
    url: str
    data_dir: Path
    log: Path
    process: subprocess.Popen
    fake: FakeOllama | None = None


class AppStartError(RuntimeError):
    pass


def start_app(tmp: Path, ollama_url: str, repos_root: Path = DEMO_REPOS, port: int | None = None,
              extra_env: dict[str, str] | None = None, team_name: str = "Платформа") -> AppServer:
    """Приложение из этого окружения Python (uvicorn) с папкой данных в tmp; ждёт ответа /healthz. team_name –
    название команды в настройках до запуска: без него дефект SAST не выдаётся (ADR-0092 п. 11); "" – не задавать."""
    # Порт выбирает ОС при bind самого uvicorn: между проверкой и запуском нет свободного сокета.
    port = port or 0
    data_dir = tmp / "data"
    log = tmp / "app.log"
    if team_name:  # приложение дополняет настройки при первом запуске, сохранённые не меняет
        from app.db import Database
        db = Database(data_dir / "triage.db")
        try:
            db.set_settings({"team_name": team_name})
        finally:
            db.close()
    from db_support import libpq_env
    env = {**os.environ, "DATA_DIR": str(data_dir), "REPOS_ROOT": str(repos_root), "OLLAMA_URL": ollama_url, "OSV_URL": "off",
           "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8", **libpq_env(data_dir / "triage.db")}
    for name in ("REPOS_ROOT_HOST", "REPOS_ROOT_IS_DEMO", "DEFAULT_MODEL", "HUB_STATUS_MAP", "SCA_URGENT_CVSS",
                 "TRUSTED_HOSTS"):
        env.pop(name, None)
    # признак демо-папки задаётся явно, как его ставит start.ps1 (бэклог 94): стартовая схема – демо-репозитории
    env["REPOS_ROOT_IS_DEMO"] = "1" if Path(repos_root).resolve() == Path(DEMO_REPOS).resolve() else "0"
    env.update(extra_env or {})
    with log.open("wb") as out:
        process = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "app.main:create_app", "--factory", "--host", "127.0.0.1", "--port",
             str(port), "--no-access-log", "--timeout-graceful-shutdown", "3"],
            cwd=ROOT, env=env, stdout=out, stderr=subprocess.STDOUT,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0)
    deadline = time.monotonic() + 40
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AppStartError("Приложение не запустилось:\n" + log.read_text(encoding="utf-8", errors="replace"))
        # /healthz на этом порту может отвечать другой процесс, пока наш ещё запускается.
        # Uvicorn пишет эту строку только после успешного связывания своего сокета.
        bound = re.search(r"Uvicorn running on (http://127\.0\.0\.1:\d+)",
                          log.read_text(encoding="utf-8", errors="replace"))
        if bound is None:
            time.sleep(0.1)
            continue
        url = bound.group(1)
        try:
            with urllib.request.urlopen(url + "/healthz", timeout=2) as r:
                if r.status == 200:
                    return AppServer(url=url, data_dir=data_dir, log=log, process=process)
        except (urllib.error.URLError, OSError):
            time.sleep(0.3)
    stop_app(process)
    raise AppStartError("Приложение не ответило за 40 с:\n" + log.read_text(encoding="utf-8", errors="replace"))


def stop_app(process: subprocess.Popen) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(5)


def ollama_models(url: str = REAL_OLLAMA) -> list[str]:
    """Модели настоящей Ollama на этом компьютере или [] – Ollama не отвечает."""
    try:
        with urllib.request.urlopen(url + "/api/tags", timeout=3) as r:
            data = json.loads(r.read().decode("utf-8"))
    except (urllib.error.URLError, OSError, ValueError):
        return []
    return [str(m.get("name") or "") for m in data.get("models") or []]


# ============================================================================ браузер

@dataclass
class Watch:
    """Что происходило на странице: ошибки скриптов и консоли, адреса запросов."""

    base: str
    console_errors: list[str] = field(default_factory=list)
    page_errors: list[str] = field(default_factory=list)
    requests: list[str] = field(default_factory=list)
    allowed_errors: list[str] = field(default_factory=list)

    def problems(self) -> list[str]:
        result = [f"ошибка скрипта: {e}" for e in self.page_errors]
        result += [f"консоль: {e}" for e in self.console_errors
                   if not any(allowed in e for allowed in self.allowed_errors)]
        result += [f"внешний запрос: {u}" for u in self.requests
                   if not (u.startswith(self.base + "/") or u == self.base or u.startswith(("data:", "blob:")))]
        return result


def open_page(browser, base: str, width: int = 1280, height: int = 900, theme: str = "light",
              timezone_id: str | None = None, accept_dialogs: bool = True):
    """Новая вкладка в отдельном профиле: тема, буфер обмена, ответ на диалоги (confirm и уход со страницы с
    несохранённым решением – «да»); timezone_id – часовой пояс браузера (по умолчанию – как у компьютера)."""
    context = browser.new_context(base_url=base, viewport={"width": width, "height": height}, locale="ru-RU",
                                  color_scheme=theme, accept_downloads=True,
                                  **({"timezone_id": timezone_id} if timezone_id else {}))
    context.grant_permissions(["clipboard-read", "clipboard-write"], origin=base)
    page = context.new_page()
    watch = Watch(base=base)
    page.on("console", lambda m: watch.console_errors.append(m.text) if m.type == "error" else None)
    page.on("pageerror", lambda e: watch.page_errors.append(str(e)))
    page.on("request", lambda r: watch.requests.append(r.url))
    if accept_dialogs:
        page.on("dialog", lambda d: d.accept())
    # общий предел ожидания элементов и переходов – одна настройка (бэклог п. 25, аудит Kimi KIMI-11): по умолчанию
    # 15 с, под нагрузкой (параллельные прогоны на одном компьютере) – scripts/run-e2e.ps1 -TimeoutMs 30000;
    # сами ожидания – по событиям (адрес, элемент, состояние), не фиксированные паузы
    page.set_default_timeout(int(os.environ.get("E2E_TIMEOUT_MS") or 15000))
    return context, page, watch


# ============================================================================ шаги сценария

def project_id_from(url: str) -> int:
    return int(re.search(r"/projects/(\d+)", url).group(1))


def finding_id_from(url: str) -> int:
    return int(re.search(r"/findings/(\d+)", url).group(1))


def create_demo(page) -> int:
    """«Создать демо-проект» на странице проектов; возвращает номер проекта."""
    page.goto("/")
    page.locator("#create-demo").first.click()
    page.wait_for_url(re.compile(r"/projects/\d+\?ok=project_demo"))
    return project_id_from(page.url)


def run_triage(page, project_id: int, model: str = "", timeout_ms: int = 60000, scope: str = "all") -> int:
    """Запуск триажа на странице проекта и ожидание конца прогона; возвращает номер прогона."""
    page.goto(f"/projects/{project_id}#step3")
    if model:
        page.select_option("#model-select", model)
    page.check(f'input[name="scope"][value="{scope}"]')
    page.get_by_role("button", name="Запустить триаж", exact=True).click()
    page.wait_for_url(re.compile(r"/runs/\d+$"))
    run_id = int(re.search(r"/runs/(\d+)", page.url).group(1))
    wait_run_done(page, timeout_ms)
    return run_id


def wait_run_done(page, timeout_ms: int = 60000) -> None:
    """Ожидание конца прогона на его странице (состояние приходит потоком событий). Ожидание – через expect:
    page.wait_for_function со строкой выполняет её через eval, а политика CSP приложения это запрещает."""
    from playwright.sync_api import expect

    expect(page.locator("#run-state")).to_have_class(re.compile(r"\bstate-done\b"), timeout=timeout_ms)


def clipboard(page) -> str:
    """Текст из буфера обмена; буфер Windows хранит перевод строки как CRLF – здесь он LF, как на странице."""
    return str(page.evaluate("navigator.clipboard.readText()") or "").replace("\r\n", "\n")


def no_horizontal_scroll(page) -> bool:
    return page.evaluate("document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1")


# ---------------------------------------------------------------------------- SCA: дефект по тексту набора (0.9.8)

DEMO_SCA_EXPLANATION = ("CVE-2099-10002: Парсер по умолчанию подгружает внешние сущности, и через них можно прочитать "
                        "файл сервера.\nCVE-2099-10001: Вложенные сущности раскрываются без предела, и небольшой "
                        "документ занимает всю память.")


def save_sca_decision(page) -> None:
    """«Сохранить» на карточке SCA (обычная форма): решение – и по отмеченным находкам этой версии (Б8)."""
    page.get_by_role("button", name="Сохранить", exact=True).click()
    page.wait_for_url(re.compile(r"ok=sca_(?:saved|all_reviewed|no_other)"))


def sca_set_text_ready(page, explanation: str) -> None:
    """Текст набора дефекта SCA (ADR-0091): у «Обновить» короткого текста нет, дефект собирается по тексту набора –
    Объяснение по строке на уязвимость и отметка «Версию проверил сам» (целевая версия – из ответа агента; без
    исследования компонента она не проверена). После сохранения у набора не остаётся препятствий к выдаче."""
    from playwright.sync_api import expect

    page.fill("#package-explanation", explanation)
    page.check("#package-version-checked")
    page.click("#package-text-save")
    page.wait_for_url(re.compile(r"ok=sca_text_saved"))
    expect(page.locator("#sca-set-problems")).to_have_count(0)


def open_fields(page) -> None:
    """Карточка дефекта: прочие поля Hub свёрнуты – раскрыть перед правкой."""
    box = page.locator("#defect-other-fields")
    if box.count() and not box.evaluate("e => e.open"):
        box.locator("summary").click()


def open_more(page) -> None:
    """Карточка дефекта: служебные блоки свёрнуты в «Подробнее» – раскрыть перед действием."""
    box = page.locator("#defect-more")
    if box.count() and not box.evaluate("e => e.open"):
        box.locator("summary").first.click()


def worker_key(server) -> str:
    """Ключ исполнителя запущенного приложения: в базе (ADR-0133)."""
    from db_support import conninfo_of, database_for_path
    from keys_support import worker_key_of
    return worker_key_of(conninfo_of(database_for_path(server.data_dir / "triage.db")))
