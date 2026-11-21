"""Веб-интерфейс, этап 2: разделы на APIRouter, настройки из базы поверх окружения, защита решения от перезаписи
из устаревшей вкладки, сверка кода перед сохранением решения, модель прогона на странице прогона, журнал и страница
ошибки без текста кода."""

from __future__ import annotations

import logging
import re
import time
from pathlib import Path

from fastapi.testclient import TestClient

from app import metrics
from app.config import Settings
from app.main import create_app
from app.routes import api, findings, projects, runs
from app.view import TEMPLATES_DIR
from fake_ollama import FakeOllama
from hub_fixtures import INVOICE, SAST_ROWS, make_hub_xlsx
from test_web import (BASE, GPU, ORIGIN, create_project, prepared, start_run, upload, wait_run, web,  # noqa: F401
                      write_repos)

AS_JSON = {**ORIGIN, "Accept": "application/json"}
CODE_MARK = "SECRET_CODE_LINE_4242"


def form_fields(html: str) -> dict:
    """Скрытые поля формы решения: всё, что страница отправляет вместе с решением."""
    return {name: re.search(rf'name="{name}" value="([^"]*)"', html).group(1)
            for name in ("finding_version", "verdict_id", "review_revision", "code_hash", "code_chars")}


def card_of(web, pid: int, hub_id: str) -> tuple[int, str]:
    fid = web.app.state.db.get_finding_by_hub_id(pid, hub_id)["id"]
    return fid, web.client.get(f"/projects/{pid}/findings/{fid}").text


# ============================================================================ сборка приложения

def test_sections_are_routers_and_templates_are_split(web):
    sections = {"projects": projects, "findings": findings, "runs": runs, "api": api}
    paths = {name: {route.path for route in module.router.routes} for name, module in sections.items()}
    assert {"/", "/projects/{project_id}", "/projects/{project_id}/import"} <= paths["projects"]
    assert "/projects/{project_id}/findings/{finding_id}/review" in paths["findings"]
    assert {"/runs/{run_id}/events", "/runs/{run_id}/stop"} <= paths["runs"]
    assert paths["api"] == {"/healthz", "/api/metrics", "/api/metrics/history", "/api/runs/active",
                            "/api/research/active", "/api/model/warmup"}
    assert web.client.get("/healthz").status_code == 200  # разделы подключены к приложению
    for name in ("base.html", "macros.html", "error.html", "projects/list.html", "projects/project.html",
                 "findings/list.html", "findings/card.html", "runs/run.html", "settings/index.html", "sca/index.html"):
        assert (TEMPLATES_DIR / name).is_file(), name


# ============================================================================ решение из двух вкладок

def test_second_tab_does_not_overwrite_newer_decision(web):
    pid = prepared(web)
    assert wait_run(web, start_run(web, pid))["state"] == "done"
    fid, card = card_of(web, pid, "510001")
    tab_a = tab_b = form_fields(card)
    assert tab_a["review_revision"] == "0" and tab_a["code_hash"] and tab_a["code_chars"] == "14000"
    url = f"/projects/{pid}/findings/{fid}/review"
    r = web.client.post(url, headers=ORIGIN, follow_redirects=False,
                        data={**tab_a, "fix": "Параметризовать запрос.", "decision": "disagree", "final_verdict": "true_positive",
                              "comment": "Вкладка A.", "reviewed": "1", "action": "save"})
    assert r.status_code == 303
    r = web.client.post(url, headers=ORIGIN, data={**tab_b, "fix": "Параметризовать запрос.", "decision": "agree", "comment": "Вкладка B.",
                                                   "reviewed": "1", "action": "save"})
    assert r.status_code == 409 and "в другой вкладке или окне" in r.text
    assert "Вкладка B.</textarea>" in r.text  # введённое не потеряно
    db = web.app.state.db
    assert db.get_review(pid, "510001")["final_comment"] == "Вкладка A."
    r = web.client.post(url, headers=AS_JSON, data={**tab_b, "fix": "Параметризовать запрос.", "decision": "agree", "action": "copy"})
    assert r.status_code == 409 and r.json()["reason"] == "revision"
    # копирование из актуальной вкладки: ответ сообщает новую редакцию, и следующая отправка с ней проходит
    fresh = form_fields(web.client.get(f"/projects/{pid}/findings/{fid}").text)
    assert fresh["review_revision"] == "1"
    answer = web.client.post(url, headers=AS_JSON, data={**fresh, "fix": "Параметризовать запрос.", "decision": "agree", "comment": "Итог.",
                                                         "reviewed": "1", "action": "copy"}).json()
    assert answer["ok"] and answer["revision"] == 2 and answer["notice"] == ""
    r = web.client.post(url, headers=ORIGIN, follow_redirects=False,
                        data={**fresh, "review_revision": str(answer["revision"]), "fix": "Параметризовать запрос.", "decision": "agree",
                              "comment": "Итог.", "reviewed": "1", "action": "next"})
    assert r.status_code == 303 and db.get_review(pid, "510001")["revision"] == 3
    assert db.get_review(pid, "510001")["code_hash"] == fresh["code_hash"]


def test_page_without_new_fields_is_still_accepted(web):
    """Карточка, открытая до обновления приложения, присылает только версию находки и вердикт."""
    pid = prepared(web)
    fid, card = card_of(web, pid, "510002")
    fields = form_fields(card)
    r = web.client.post(f"/projects/{pid}/findings/{fid}/review", headers=ORIGIN, follow_redirects=False,
                        data={"finding_version": fields["finding_version"], "verdict_id": fields["verdict_id"],
                              "fix": "Параметризовать запрос.", "decision": "later", "action": "save"})
    assert r.status_code == 303


# ============================================================================ код изменился

def test_code_change_while_card_is_open_refuses_decision(web):
    pid = prepared(web)
    fid, card = card_of(web, pid, "510001")
    fields = form_fields(card)
    invoice = web.tmp / "repos" / "team" / "billing-core" / INVOICE
    invoice.write_text(invoice.read_text(encoding="utf-8").replace("// строка 50", "// правка 50"),
                       encoding="utf-8")
    url = f"/projects/{pid}/findings/{fid}/review"
    r = web.client.post(url, headers=AS_JSON, data={**fields, "fix": "Параметризовать запрос.", "decision": "later", "action": "copy"})
    assert r.status_code == 409 and r.json()["reason"] == "code"
    r = web.client.post(url, headers=ORIGIN, data={**fields, "fix": "Параметризовать запрос.", "decision": "disagree", "final_verdict": "true_positive",
                                                   "comment": "Смотрел код.", "reviewed": "1", "action": "save"})
    assert r.status_code == 409 and "Код находки в клоне изменился" in r.text
    assert web.app.state.db.get_review(pid, "510001") is None
    fresh = form_fields(r.text)  # страница ответа – уже по текущему коду
    assert fresh["code_hash"] != fields["code_hash"]
    r = web.client.post(url, headers=ORIGIN, follow_redirects=False,
                        data={**fresh, "fix": "Параметризовать запрос.", "decision": "disagree", "final_verdict": "true_positive",
                              "comment": "Смотрел код.", "reviewed": "1", "action": "save"})
    assert r.status_code == 303 and web.app.state.db.get_review(pid, "510001")["reviewed"] == 1


def test_code_changed_after_analysis_warns_but_keeps_reviewed_mark(web):
    pid = prepared(web)
    assert wait_run(web, start_run(web, pid))["state"] == "done"
    invoice = web.tmp / "repos" / "team" / "billing-core" / INVOICE
    invoice.write_text(invoice.read_text(encoding="utf-8").replace("// строка 50", "// правка 50"),
                       encoding="utf-8")
    fid, card = card_of(web, pid, "510001")
    assert 'id="code-changed"' in card and "Разобрать заново" in card
    fields = form_fields(card)
    url = f"/projects/{pid}/findings/{fid}/review"
    # «Согласен» с ответом модели о прежнем коде не сохраняется
    r = web.client.post(url, headers=ORIGIN, follow_redirects=False,
                        data={**fields, "fix": "Параметризовать запрос.", "decision": "agree", "comment": "Смотрел код.", "reviewed": "1",
                              "action": "next"})
    assert r.status_code == 409
    assert web.app.state.db.get_review(pid, "510001") is None
    # «Не согласен» со своим вердиктом сохраняется с отметкой «Проверено»: прежний срез модели – предупреждение,
    # а не запрет (ADR-0147); карточка по-прежнему предупреждает
    r = web.client.post(url, headers=ORIGIN, follow_redirects=False,
                        data={**fields, "fix": "Параметризовать запрос.", "decision": "disagree", "final_verdict": "true_positive",
                              "comment": "Смотрел код.", "reviewed": "1", "action": "stay"})
    assert r.status_code == 303 and "ok=code_changed" not in r.headers["location"], r.headers["location"]
    review = web.app.state.db.get_review(pid, "510001")
    assert (review["decision"], review["reviewed"]) == ("disagree", 1)
    page = web.client.get(f"/projects/{pid}/findings/{fid}").text
    assert 'id="code-changed"' in page and "отмечается проверенным как обычно" in page
    # снять и поставить отметку отдельно (клавиша v) – тоже без запрета
    fields = form_fields(page)
    mark = f"/projects/{pid}/findings/{fid}/reviewed"
    for value, expected in (("0", 0), ("1", 1)):
        r = web.client.post(mark, headers=ORIGIN, follow_redirects=False, data={**fields, "reviewed": value})
        assert r.status_code == 303, r.text
        assert web.app.state.db.get_review(pid, "510001")["reviewed"] == expected
        fields = form_fields(web.client.get(f"/projects/{pid}/findings/{fid}").text)


# ============================================================================ настройки из базы

def test_settings_from_database_override_environment(web):
    pid = prepared(web)
    assert wait_run(web, start_run(web, pid))["state"] == "done"
    db = web.app.state.db
    assert db.get_settings()["ollama_url"] == web.fake.url  # первый запуск записал значения из окружения
    db.set_settings({"hub_status_map": {"false_positive": "Not an issue"}, "default_model": "gpt-oss:20b"})
    fid, card = card_of(web, pid, "510001")
    assert "«Ложное срабатывание» – в Hub статус «Not an issue»" in card
    # предпросмотр текста для Hub появляется только после решения (0.9.5, ADR-0088) – это обоснование оператора
    r = web.client.post(f"/projects/{pid}/findings/{fid}/review", headers=ORIGIN, follow_redirects=False,
                        data={**form_fields(card), "fix": "Параметризовать запрос.", "decision": "false_positive",
                              "comment": "Значение приводится к числу.", "action": "stay"})
    assert r.status_code == 303
    assert "Значение приводится к числу." in web.client.get(f"/projects/{pid}/findings/{fid}").text
    page = web.client.get(f"/projects/{pid}").text
    assert '<option value="gpt-oss:20b" data-info=' in page and re.search(r'value="gpt-oss:20b"[^>]* selected', page)
    db.update_project(pid, model="qwen2.5-coder:14b")  # модель проекта важнее модели из настроек
    page = web.client.get(f"/projects/{pid}").text
    assert re.search(r'value="qwen2.5-coder:14b"[^>]* selected', page)


def test_environment_is_only_the_first_default(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(metrics, "gpu_stats", lambda: None)
    fake = FakeOllama()
    write_repos(tmp_path / "repos")
    first = Settings(data_dir=tmp_path / "data", repos_root=tmp_path / "repos", ollama_url=fake.url)
    try:
        with TestClient(create_app(first), base_url=BASE) as client:
            client.app.state.db.set_settings({"default_model": "gpt-oss:20b"})
        later = Settings(data_dir=tmp_path / "data", repos_root=tmp_path / "repos", ollama_url="http://127.0.0.1:9",
                         default_model="qwen2.5-coder:14b")
        with TestClient(create_app(later), base_url=BASE) as client:
            stored = client.app.state.db.get_settings()
            assert stored["ollama_url"] == fake.url and stored["default_model"] == "gpt-oss:20b"
            assert client.get("/api/metrics").json()["models"] == []  # метрики – по адресу из настроек
            assert fake.paths().count("/api/ps") >= 1
    finally:
        fake.close()


# ============================================================================ модель прогона

def test_run_page_shows_entry_of_run_model(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(metrics, "gpu_stats", lambda: dict(GPU))
    fake = FakeOllama(loaded=["gpt-oss:20b", "qwen2.5-coder:14b"])  # нужная модель – вторая в /api/ps
    fake.vram_share = 0.5
    write_repos(tmp_path / "repos")
    settings = Settings(data_dir=tmp_path / "data", repos_root=tmp_path / "repos", ollama_url=fake.url)
    try:
        with TestClient(create_app(settings), base_url=BASE) as client:
            pid = create_project(client)
            assert upload(client, pid, make_hub_xlsx(tmp_path / "hub.xlsx")).status_code == 303
            client.post(f"/projects/{pid}/repos", data={"repos_dir": "team"}, headers=ORIGIN)
            run_id = client.app.state.runner.enqueue(pid, "qwen2.5-coder:14b", "all")
            deadline = time.monotonic() + 30
            while client.app.state.db.get_run(run_id)["state"] != "done" and time.monotonic() < deadline:
                time.sleep(0.05)
            from app.routes.common import compute_metrics
            from app.llm import OllamaClient
            observer = client.app.state.telemetry
            fake.loaded.sort(key=lambda m: m["name"] != "gpt-oss:20b")  # первой в /api/ps стоит чужая модель
            observer.record(compute_metrics(OllamaClient, fake.url))
            status = client.get(f"/runs/{run_id}/status").json()
            assert [m["name"] for m in status["metrics"]["models"]] == ["gpt-oss:20b", "qwen2.5-coder:14b"]
            assert status["run_model"]["name"] == "qwen2.5-coder:14b" and status["run_model"]["vram_pct"] == 50
            page = client.get(f"/runs/{run_id}").text
            assert 'id="m-model">qwen2.5-coder:14b</div>' in page and "50% в видеопамяти" in page
            fake.loaded = [m for m in fake.loaded if m["name"] != "qwen2.5-coder:14b"]  # модель прогона выгружена
            observer.record(compute_metrics(OllamaClient, fake.url))
            page = client.get(f"/runs/{run_id}").text
            assert 'id="m-model">не загружена</div>' in page and "в памяти: gpt-oss:20b" in page
            assert client.get(f"/runs/{run_id}/status").json()["run_model"] is None
    finally:
        fake.close()


# ============================================================================ журнал и страница ошибки

def test_internal_error_page_and_log_without_code(tmp_path: Path, monkeypatch, caplog):
    """Необработанная ошибка не уходит дальше приложения: иначе сервер записал бы её в журнал с текстом
    и трассировкой. TestClient без raise_server_exceptions=False поднял бы такую ошибку в тесте."""
    monkeypatch.setattr(metrics, "gpu_stats", lambda: None)
    caplog.set_level(logging.DEBUG)
    settings = Settings(data_dir=tmp_path / "data", repos_root=tmp_path, ollama_url="http://127.0.0.1:9")
    app = create_app(settings)
    with TestClient(app, base_url=BASE) as client:
        def broken(*args, **kwargs):
            try:
                raise KeyError(CODE_MARK)
            except KeyError as cause:
                raise RuntimeError(f"код находки: {CODE_MARK}") from cause

        monkeypatch.setattr(app.state.db, "list_projects", broken)
        r = client.get("/", headers={"Accept": "text/html"})
        eid = re.search(r"номер ошибки ([0-9a-f]{8})", r.text).group(1)
        assert r.status_code == 500 and CODE_MARK not in r.text and "Внутренняя ошибка приложения" in r.text
        assert r.headers["content-security-policy"] and r.headers["cache-control"] == "no-store"
        r = client.get("/", headers={"Accept": "application/json"})
        assert r.status_code == 500 and re.search(r"номер ошибки [0-9a-f]{8}", r.json()["detail"])
    assert CODE_MARK not in caplog.text and f"[ошибка {eid}]" in caplog.text
    assert "RuntimeError ← KeyError" in caplog.text and "broken" in caplog.text


def test_unreadable_export_is_logged_without_its_content(web, monkeypatch, caplog):
    caplog.set_level(logging.DEBUG)
    pid = create_project(web.client)

    def broken(path, limit):
        raise ValueError(f"ячейка: {CODE_MARK}")

    monkeypatch.setattr(projects, "parse_workbook", broken)
    r = upload(web.client, pid, make_hub_xlsx(web.tmp / "hub.xlsx"))
    eid = re.search(r"ошибка ([0-9a-f]{8})", r.text).group(1)
    assert r.status_code == 400 and CODE_MARK not in r.text
    assert CODE_MARK not in caplog.text and f"[ошибка {eid}]" in caplog.text and "ValueError" in caplog.text


# ============================================================================ находки «нет в новой выгрузке»

def test_missing_finding_card_still_opens_and_is_not_offered(web):
    pid = prepared(web)
    db = web.app.state.db
    fid = db.get_finding_by_hub_id(pid, "510004")["id"]
    path = make_hub_xlsx(web.tmp / "smaller.xlsx", sast=[row for row in SAST_ROWS if row["Issue id"] != "510004"])
    assert upload(web.client, pid, path).status_code == 303
    assert db.get_finding(pid, fid)["missing"] == 1
    assert web.client.get(f"/projects/{pid}/findings/{fid}").status_code == 200
    first = db.neighbor_unreviewed(pid, -1, "next")
    assert first is not None and first != fid
    assert "исчезло 1" in web.client.get(f"/projects/{pid}").text
