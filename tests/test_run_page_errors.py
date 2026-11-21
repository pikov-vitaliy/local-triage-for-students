"""Страница прогона: ошибки находок списком, «Повторить ошибочные» по сохранённым срезам и без клона, кнопка
разбора находок не рядом с управлением прогоном, отбор «с ошибкой в последнем прогоне», --help журнала обмена."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parent.parent
TESTS = Path(__file__).resolve().parent
for folder in (ROOT, TESTS):
    if str(folder) not in sys.path:
        sys.path.insert(0, str(folder))

from app import metrics  # noqa: E402
from app.config import Settings  # noqa: E402
from app.db import FINAL_RUN_STATES  # noqa: E402
from app.main import create_app  # noqa: E402
from app.run_errors import error_group, error_label, error_reason, group_run_errors  # noqa: E402
from fake_ollama import FakeOllama  # noqa: E402
from hub_fixtures import make_hub_xlsx  # noqa: E402
from test_web import BASE, GPU, ORIGIN, upload, write_repos  # noqa: E402

SCRIPT = ROOT / "scripts" / "model_traffic.py"

pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")


@pytest.fixture
def web(tmp_path: Path, monkeypatch):
    """Приложение с временной папкой данных и клонами; поддельная Ollama одной модели."""
    monkeypatch.setattr(metrics, "gpu_stats", lambda: dict(GPU))
    fake = FakeOllama(loaded=["qwen2.5-coder:14b"])
    write_repos(tmp_path / "repos")
    settings = Settings(data_dir=tmp_path / "data", repos_root=tmp_path / "repos", ollama_url=fake.url,
                        max_upload_mb=1)
    app = create_app(settings)
    with TestClient(app, base_url=BASE) as client:
        yield SimpleNamespace(client=client, app=app, fake=fake, settings=settings, tmp=tmp_path)
    fake.close()


def prepared(web) -> int:
    r = web.client.post("/projects", data={"name": "Demo Library"}, headers=ORIGIN, follow_redirects=False)
    assert r.status_code == 303, r.text
    pid = int(r.headers["location"].split("/")[2].split("?")[0])
    assert upload(web.client, pid, make_hub_xlsx(web.tmp / "hub.xlsx")).status_code == 303
    r = web.client.post(f"/projects/{pid}/repos", data={"repos_dir": "team"}, headers=ORIGIN, follow_redirects=False)
    assert r.status_code == 303, r.text
    return pid


def start_run(web, pid: int, **data) -> int:
    form = {"model": "qwen2.5-coder:14b", "scope": "all", **data}
    r = web.client.post(f"/projects/{pid}/runs", data=form, headers=ORIGIN, follow_redirects=False)
    assert r.status_code == 303, r.text
    return int(r.headers["location"].rsplit("/", 1)[1])


def wait_run(web, run_id: int, timeout: float = 30.0) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        run = web.app.state.db.get_run(run_id)
        if run["state"] in FINAL_RUN_STATES:
            return run
        time.sleep(0.05)
    raise AssertionError("прогон не закончился")


def make_error_run(web) -> tuple[int, int, str]:
    """Прогон, в котором первая находка дважды ответила не по формату; (проект, прогон, ID находки)."""
    pid = prepared(web)
    web.fake.answers = ["это не JSON", "и снова не JSON"]
    run_id = start_run(web, pid)
    run = wait_run(web, run_id)
    assert run["failed"] == 1
    assert web.app.state.db.run_errors(run_id)[0]["hub_id"] != ""
    return pid, run_id, web.app.state.db.run_errors(run_id)[0]["hub_id"]


# ============================================================================ разбор ошибок

def test_error_groups_labels_and_reasons():
    assert error_group("Модель дважды ответила не по формату: нет поля why.") == "format"
    assert error_group("Ответ модели оборван: исчерпан предел длины ответа.") == "format"
    assert error_group("Ollama не отвечает по адресу http://127.0.0.1:11434.") == "unavailable"
    assert error_group("Модели «qwen2.5-coder:14b» нет на сервере Ollama.") == "unavailable"
    assert error_group("Не удалось сохранить вердикт (ошибка 12).") == "other"
    assert error_label("Модель дважды ответила не по формату") == "ошибка формата"
    assert error_label("Ollama не отвечает") == "модель недоступна"
    assert error_label("Не удалось сохранить срез") == "ошибка разбора"
    assert "оборвала" in error_reason("Ответ модели оборван: исчерпан предел длины ответа.")
    reasoning = "Ответ модели оборван: модель рассуждала и не дошла до ответа за 8192 токенов (num_predict = 8192)."
    assert error_group(reasoning) == "format" and "рассуждение" in error_reason(reasoning)
    assert error_reason("Не удалось сохранить вердикт") == "не удалось сохранить ответ модели"
    grouped = group_run_errors([
        {"hub_id": "A", "error": "Модель дважды ответила не по формату", "finding_id": 1, "rule": "rule-a",
         "retryable": True},
        {"hub_id": "B", "error": "Ollama не отвечает", "finding_id": 2, "rule": "rule-b", "retryable": False},
        {"hub_id": "C", "error": "Не удалось сохранить вердикт", "finding_id": None, "rule": "", "retryable": False},
    ], 7)
    assert (grouped["total"], grouped["retryable"], grouped["unknown"]) == (3, 1, 0)
    unknown = group_run_errors([{"hub_id": "D", "error": "Результат неизвестен: обращение ушло", "finding_id": 4,
                                 "rule": "r", "retryable": True}], 7)
    assert (unknown["retryable"], unknown["unknown"]) == (0, 1) and unknown["groups"][-1]["key"] == "unknown"
    counts = {group["key"]: group["count"] for group in grouped["groups"]}
    assert counts == {"format": 1, "unavailable": 1, "other": 1, "unknown": 0}
    first = grouped["groups"][0]["rows"][0]
    assert first["url"] == "/projects/7/findings/1" and first["rule"] == "rule-a"
    assert first["detail"] == "Модель дважды ответила не по формату"


# ============================================================================ страница прогона

def test_run_page_lists_errors_and_moves_review_button(web):
    pid, run_id, failed_id = make_error_run(web)
    page = web.client.get(f"/runs/{run_id}")
    body = page.text
    assert page.status_code == 200
    assert 'id="run-errors"' in body and "Ошибки:" in body
    assert "ответ не по формату" in body and "Модель дважды ответила не по формату" in body
    assert 'id="last-error"' not in body
    assert "Продолжить разбор" not in body
    assert 'id="review-findings"' in body and "Разбирать находки" in body
    # ссылка разбора находок – вне блока управления прогоном
    actions = body[body.index('id="run-actions"'):]
    actions = actions[:actions.index("</section>")]
    assert "Разбирать находки" not in actions and "Повторить ошибочные" not in actions
    # в ленте – короткая метка и полный текст только в подсказке
    feed = body[body.index('<tbody id="feed">'):body.index("</tbody>", body.index('<tbody id="feed">'))]
    assert "ошибка формата" in feed
    assert 'title="Модель дважды ответила не по формату' in feed
    assert '<span class="muted small block">Модель дважды' not in feed

    status = web.client.get(f"/runs/{run_id}/status").json()
    assert status["errors"]["total"] == 1 and status["errors"]["retryable"] == 1
    assert status["errors"]["groups"][0]["rows"][0]["hub_id"] == failed_id
    errored = [item for item in status["feed"] if item["state"] == "error"]
    assert errored and errored[0]["error_label"] == "ошибка формата"
    assert status["run"]["notice"] == ""


def test_findings_filter_last_run_error(web):
    pid, run_id, failed_id = make_error_run(web)
    page = web.client.get(f"/projects/{pid}/findings?run_error=1&kind=SAST")
    assert page.status_code == 200
    assert failed_id in page.text
    assert page.text.count('class="row-check"') == 1
    # после успешного повтора последний прогон ошибок не имеет
    web.fake.answers = []
    r = web.client.post(f"/runs/{run_id}/retry-errors", headers=ORIGIN, follow_redirects=False)
    assert r.status_code == 303
    new_id = int(r.headers["location"].rsplit("/", 1)[1])
    wait_run(web, new_id)
    page = web.client.get(f"/projects/{pid}/findings?run_error=1&kind=SAST")
    assert failed_id not in page.text
    assert page.text.count('class="row-check"') == 0


def test_retry_errors_creates_selected_fresh_run(web):
    pid, run_id, failed_id = make_error_run(web)
    web.fake.answers = []
    r = web.client.post(f"/runs/{run_id}/retry-errors", headers=ORIGIN, follow_redirects=False)
    assert r.status_code == 303, r.text
    new_id = int(r.headers["location"].rsplit("/", 1)[1])
    new = web.app.state.db.get_run(new_id)
    assert new["scope"] == "selected" and new["fresh"] == 1 and new["model"] == "qwen2.5-coder:14b"
    assert new["total"] == 1
    items = web.app.state.db._all("SELECT hub_id FROM run_items WHERE run_id = ?", (new_id,))
    assert [row["hub_id"] for row in items] == [failed_id]
    done = wait_run(web, new_id)
    assert (done["state"], done["failed"], done["done"]) == ("done", 0, 1)


def test_retry_errors_uses_stored_snapshots_without_clone(web):
    pid, run_id, failed_id = make_error_run(web)
    # Клонов больше нет: папка проекта удалена, проект остаётся с сохранёнными срезами.
    shutil.rmtree(web.tmp / "repos" / "team")
    web.fake.answers = []
    r = web.client.post(f"/runs/{run_id}/retry-errors", headers=ORIGIN, follow_redirects=False)
    assert r.status_code == 303, r.text
    new_id = int(r.headers["location"].rsplit("/", 1)[1])
    done = wait_run(web, new_id)
    assert (done["state"], done["failed"], done["done"]) == ("done", 0, 1)
    case = web.app.state.db.get_case(pid, failed_id)
    assert case is not None and case["context"]["status"] == "ok"
    assert case["verdict_id"] is not None


# ============================================================================ журнал обмена: справка и UTC

@pytest.mark.parametrize("args", [("--help",), ("list", "--help"), ("show", "--help"), ("dump", "--help"),
                                  ("verify", "--help"), ("stats", "--help")])
def test_model_traffic_help_exits_zero_in_non_utf8_console(args):
    env = {**os.environ, "PYTHONUTF8": "0", "PYTHONIOENCODING": "cp437"}
    result = subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True, env=env, timeout=60)
    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")
    assert b"usage:" in result.stdout


def test_model_traffic_list_says_utc(tmp_path: Path):
    env = {**os.environ, "PYTHONUTF8": "1"}
    result = subprocess.run([sys.executable, str(SCRIPT), "list", "--dir", str(tmp_path)], capture_output=True,
                            text=True, encoding="utf-8", env=env, timeout=60)
    assert result.returncode == 0, result.stderr
    assert "UTC" in result.stdout
