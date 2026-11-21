"""Веб-интерфейс: защита запросов, проекты, загрузка выгрузки, папки и кодовые базы, список и карточка находки,
решение и текст для Hub, прогон, поток событий, метрики."""

from __future__ import annotations

import html
import re
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
from app.main import auto_folder, create_app, list_codebase_dirs, list_project_dirs  # noqa: E402
from fake_ollama import FakeOllama  # noqa: E402
from hub_fixtures import INVOICE, PY_LINE, SAST_ROWS, SEARCH, SETTINGS, SQL_LINE, make_hub_xlsx  # noqa: E402

BASE = "http://127.0.0.1:8765"
ORIGIN = {"Origin": BASE}
XSS = '<script>alert("x")</script>'
GPU = {"name": "Demo GPU", "memory_used_mb": 9000, "memory_total_mb": 16000, "memory_pct": 56.2,
       "temperature_c": 61, "utilization_pct": 87, "power_w": 210.5, "count": 1, "gpus": []}


def write_repos(root: Path) -> None:
    """Папка проекта team: клон billing-core и клон каталога под другим именем (Catalog_API)."""
    java = [f"    // строка {n}" for n in range(1, 71)]
    java[56] = f"    // </td></tr>{XSS}"  # строка 57: разметка в коде должна показываться как текст
    java[57] = "        " + SQL_LINE  # строка 58 – срабатывание 510001
    invoice = root / "team" / "billing-core" / INVOICE
    invoice.parent.mkdir(parents=True)
    invoice.write_text("\n".join(java) + "\n", encoding="utf-8")
    (root / "team" / "billing-core" / "pom.xml").write_text("<project/>\n", encoding="utf-8")
    python = [f"# строка {n}" for n in range(1, 20)]
    python[2] = python[4] = ""  # пустые строки 3 и 5: нумерация в карточке не должна съезжать
    python[8] = "    " + PY_LINE  # строка 9 – срабатывание 510004
    search = root / "team" / "Catalog_API" / SEARCH
    search.parent.mkdir(parents=True)
    search.write_text("\n".join(python) + "\n", encoding="utf-8")
    (root / "team" / "Catalog_API" / "requirements.txt").write_text("flask\n", encoding="utf-8")
    (root / ".hidden").mkdir()


@pytest.fixture
def web(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(metrics, "gpu_stats", lambda: dict(GPU))
    fake = FakeOllama(loaded=["qwen2.5-coder:14b"])
    write_repos(tmp_path / "repos")
    # название команды – для первой фразы дефекта SAST: без него дефект не выдаётся (ADR-0092 п. 11)
    # osv_url="" – тестовое приложение в интернет не ходит: запрос OSV (ADR-0112) включают тесты сами через runner_for
    settings = Settings(data_dir=tmp_path / "data", repos_root=tmp_path / "repos", ollama_url=fake.url,
                        max_upload_mb=1, team_name="Тестовая команда", osv_url="")
    app = create_app(settings)
    with TestClient(app, base_url=BASE) as client:
        yield SimpleNamespace(client=client, app=app, fake=fake, settings=settings, tmp=tmp_path)
    fake.close()


def create_project(client: TestClient, name: str = "Demo Library") -> int:
    r = client.post("/projects", data={"name": name}, headers=ORIGIN, follow_redirects=False)
    assert r.status_code == 303, r.text
    return int(r.headers["location"].split("/")[2].split("?")[0])


def upload(client: TestClient, project_id: int, path: Path):
    with open(path, "rb") as fh:
        return client.post(f"/projects/{project_id}/import", headers=ORIGIN, follow_redirects=False,
                           files={"file": (path.name, fh.read(),
                                           "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")})


def prepared(web) -> int:
    """Проект с загруженной выгрузкой и выбранной папкой проекта."""
    pid = create_project(web.client)
    assert upload(web.client, pid, make_hub_xlsx(web.tmp / "hub.xlsx")).status_code == 303
    r = web.client.post(f"/projects/{pid}/repos", data={"repos_dir": "team"}, headers=ORIGIN, follow_redirects=False)
    assert r.status_code == 303, r.text
    return pid


def wait_run(web, run_id: int, timeout: float = 30.0) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        run = web.app.state.db.get_run(run_id)
        if run["state"] in FINAL_RUN_STATES + ("paused",):
            return run
        time.sleep(0.05)
    raise AssertionError("прогон не закончился")


def shown_hash(client, card_url: str) -> str:
    """Отпечаток текста для Hub, который показывает карточка SAST (поле формы отметки «Внесено в Hub»)."""
    found = re.search(r'id="entered-text-hash" value="([0-9a-f]*)"', client.get(card_url).text)
    return found.group(1) if found else ""


def hidden_fields(html: str) -> dict:
    """Скрытые поля формы решения: версия находки и вердикта, которые видит человек."""
    return {name: re.search(rf'name="{name}" value="([^"]*)"', html).group(1)
            for name in ("finding_version", "verdict_id")}


def start_run(web, pid: int, **data) -> int:
    form = {"model": "qwen2.5-coder:14b", "scope": "all", **data}
    r = web.client.post(f"/projects/{pid}/runs", data=form, headers=ORIGIN, follow_redirects=False)
    assert r.status_code == 303, r.text
    return int(r.headers["location"].rsplit("/", 1)[1])


# ============================================================================ защита

def test_health_and_security_headers(web):
    r = web.client.get("/healthz")
    assert r.status_code == 200 and r.json()["status"] == "ok"
    csp = r.headers["content-security-policy"]
    assert "default-src 'self'" in csp and "script-src 'self'" in csp and "frame-ancestors 'none'" in csp
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["cache-control"] == "no-store"
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert web.client.get(path).status_code == 404
    css = web.client.get("/static/app.css")
    assert css.status_code == 200 and css.headers.get("cache-control") != "no-store"


def test_untrusted_host_is_rejected(web):
    assert web.client.get("/healthz", headers={"Host": "evil.example:8765"}).status_code == 400
    assert web.client.get("/healthz", headers={"Host": "localhost:8765"}).status_code == 200
    assert web.client.get("/healthz", headers={"Host": "[::1]:8765"}).status_code == 200


def test_post_requires_same_origin(web):
    data = {"name": "p"}
    assert web.client.post("/projects", data=data, follow_redirects=False).status_code == 403
    for origin in ("http://evil.example", "null", "http://127.0.0.1:9999", "https://127.0.0.1:8765"):
        r = web.client.post("/projects", data=data, headers={"Origin": origin}, follow_redirects=False)
        assert r.status_code == 403, origin
    r = web.client.post("/projects", data=data, headers={"Referer": "http://evil.example/x"}, follow_redirects=False)
    assert r.status_code == 403
    r = web.client.post("/projects", data=data, headers={"Referer": BASE + "/"}, follow_redirects=False)
    assert r.status_code == 303
    assert web.client.post("/projects", data=data, headers=ORIGIN, follow_redirects=False).status_code == 303


def test_body_size_limit(web):
    pid = create_project(web.client)
    big = b"a;b\n" * (400 * 1024)  # больше 1 МБ
    r = web.client.post(f"/projects/{pid}/import", headers=ORIGIN, files={"file": ("big.csv", big, "text/csv")})
    assert r.status_code == 413 and "слишком большой" in r.text

    def chunks():  # тело без Content-Length
        for _ in range(40):
            yield b"x" * 65536

    r = web.client.post(f"/projects/{pid}/import", content=chunks(),
                        headers={**ORIGIN, "Content-Type": "multipart/form-data; boundary=zzz"})
    assert r.status_code == 413


def test_project_name_is_escaped(web):
    pid = create_project(web.client, f"Проверка {XSS}")
    page = web.client.get(f"/projects/{pid}")
    assert page.status_code == 200
    assert "&lt;script&gt;alert(" in page.text and XSS not in page.text
    r = web.client.post("/projects", data={"name": "   "}, headers=ORIGIN)
    assert r.status_code == 400 and "Укажите название" in r.text


# ============================================================================ выгрузка, папки, кодовые базы

def test_upload_errors(web):
    pid = create_project(web.client)
    r = web.client.post(f"/projects/{pid}/import", headers=ORIGIN,
                        files={"file": ("notes.txt", b"hello", "text/plain")})
    assert r.status_code == 400 and "Поддерживаются" in r.text
    r = web.client.post(f"/projects/{pid}/import", headers=ORIGIN,
                        files={"file": ("report.xlsx", b"not a workbook", "application/octet-stream")})
    assert r.status_code == 400 and "flash-err" in r.text
    assert list((web.settings.tmp_dir).iterdir()) == []  # временные файлы удалены


def test_upload_maps_codebases_and_guards_paths(web):
    pid = prepared(web)
    page = web.client.get(f"/projects/{pid}")
    assert page.status_code == 200
    for text in ("Summary Report", "billing-core", "catalog-api", "Catalog_API"):
        assert text in page.text
    assert 'src="http' not in page.text and 'href="http' not in page.text
    db = web.app.state.db
    cmap = db.get_codebase_map(pid)
    assert cmap["billing-core"]["folder"] == "billing-core"
    assert cmap["catalog-api"]["folder"] == "Catalog_API"  # без учёта регистра и разделителей

    for bad in ("../", "..", "team/../..", ".hidden", "C:/Windows", "/etc"):
        r = web.client.post(f"/projects/{pid}/repos", data={"repos_dir": bad}, headers=ORIGIN)
        assert r.status_code == 400, bad
    r = web.client.post(f"/projects/{pid}/codebases", headers=ORIGIN,
                        data={"cb-1": "billing-core", "folder-1": "../../outside"})
    assert r.status_code == 400
    r = web.client.post(f"/projects/{pid}/codebases", headers=ORIGIN, follow_redirects=False,
                        data={"cb-1": "billing-core", "folder-1": ""})
    assert r.status_code == 303
    assert db.get_codebase_map(pid)["billing-core"] == {"folder": "", "manual": True}
    page = web.client.get(f"/projects/{pid}")
    assert "Клонировать только эти" in page.text
    # «Подобрать заново» ручной выбор не трогает, сбросить его можно только отдельной кнопкой
    r = web.client.post(f"/projects/{pid}/codebases", data={"action": "auto"}, headers=ORIGIN,
                        follow_redirects=False)
    assert r.status_code == 303 and "automapped" in r.headers["location"]
    assert db.get_codebase_map(pid)["billing-core"] == {"folder": "", "manual": True}
    assert 'value="reset" data-confirm="Сбросить ручные соответствия (1)' in web.client.get(f"/projects/{pid}").text
    r = web.client.post(f"/projects/{pid}/codebases", data={"action": "reset"}, headers=ORIGIN,
                        follow_redirects=False)
    assert r.status_code == 303
    assert db.get_codebase_map(pid)["billing-core"] == {"folder": "billing-core", "manual": False}


def test_folder_change_reopens_reviewed_findings(web):
    pid = prepared(web)
    db = web.app.state.db
    fid = db.get_finding_by_hub_id(pid, "510001")["id"]
    card = web.client.get(f"/projects/{pid}/findings/{fid}").text
    r = web.client.post(f"/projects/{pid}/findings/{fid}/review", headers=ORIGIN, follow_redirects=False,
                        data={**hidden_fields(card), "fix": "Параметризовать запрос.", "decision": "disagree", "final_verdict": "false_positive",
                              "comment": "Значение приводится к числу.", "reviewed": "1", "action": "save"})
    assert r.status_code == 303 and db.get_review(pid, "510001")["reviewed"] == 1
    page = web.client.get(f"/projects/{pid}").text
    idx = re.search(r'name="cb-(\d+)" value="billing-core"', page).group(1)
    r = web.client.post(f"/projects/{pid}/codebases", headers=ORIGIN, follow_redirects=False,
                        data={f"cb-{idx}": "billing-core", f"folder-{idx}": "Catalog_API"})
    assert r.status_code == 303 and "reopened=1" in r.headers["location"]
    assert db.get_review(pid, "510001")["reviewed"] == 0
    page = web.client.get(r.headers["location"]).text
    assert "У 1 находки снята отметка «Проверено»" in page
    # форма карточки, открытой до смены клона, отметку не вернёт
    r = web.client.post(f"/projects/{pid}/findings/{fid}/review", headers={**ORIGIN, "Accept": "application/json"},
                        data={**hidden_fields(card), "fix": "Параметризовать запрос.", "decision": "later", "reviewed": "1", "action": "save"})
    assert r.status_code == 409 and db.get_review(pid, "510001")["reviewed"] == 0
    # число в адресе – только цифры ASCII
    for bad in ("%C2%B2", "9" * 40, "-1", "x"):
        page = web.client.get(f"/projects/{pid}?ok=repos&reopened={bad}")
        assert page.status_code == 200 and "снята отметка" not in page.text


def set_git_head(repo: Path, commit: str) -> None:
    """Клон git в миниатюре: HEAD указывает на ветку main с данным коммитом."""
    heads = repo / ".git" / "refs" / "heads"
    heads.mkdir(parents=True, exist_ok=True)
    (repo / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="ascii")
    (heads / "main").write_text(commit + "\n", encoding="ascii")


def review_reviewed(client: TestClient, pid: int, fid: int) -> None:
    card = client.get(f"/projects/{pid}/findings/{fid}").text
    r = client.post(f"/projects/{pid}/findings/{fid}/review", headers=ORIGIN, follow_redirects=False,
                    data={**hidden_fields(card), "fix": "Параметризовать запрос.", "decision": "disagree", "final_verdict": "false_positive",
                          "comment": "Значение приводится к числу.", "reviewed": "1", "action": "save"})
    assert r.status_code == 303, r.text


def test_revision_change_before_run_reopens_and_is_explained(web):
    repo = web.tmp / "repos" / "team" / "billing-core"
    set_git_head(repo, "a" * 40)
    pid = prepared(web)  # при сохранении папки ревизия клона запоминается
    db = web.app.state.db
    assert db.revisions(pid)["billing-core"] == "a" * 40
    fid = db.get_finding_by_hub_id(pid, "510001")["id"]
    review_reviewed(web.client, pid, fid)
    set_git_head(repo, "b" * 40)  # git pull в клоне
    assert wait_run(web, start_run(web, pid))["state"] == "done"  # прогон сверяет ревизии перед разбором
    assert db.get_review(pid, "510001")["reviewed"] == 0
    page = web.client.get(f"/projects/{pid}").text
    assert "Сменилась ревизия клона (billing-core)" in page and "у 1 находки снята отметка" in page
    page_idx = re.search(r'name="cb-(\d+)" value="billing-core"', page).group(1)
    r = web.client.post(f"/projects/{pid}/codebases", headers=ORIGIN, follow_redirects=False,
                        data={f"cb-{page_idx}": "billing-core", f"folder-{page_idx}": "billing-core"})
    assert r.status_code == 303 and "Сменилась ревизия клона" not in web.client.get(f"/projects/{pid}").text


def test_revision_change_is_detected_at_startup(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(metrics, "gpu_stats", lambda: None)
    fake = FakeOllama()
    write_repos(tmp_path / "repos")
    repo = tmp_path / "repos" / "team" / "billing-core"
    set_git_head(repo, "a" * 40)
    settings = Settings(data_dir=tmp_path / "data", repos_root=tmp_path / "repos", ollama_url=fake.url)
    try:
        with TestClient(create_app(settings), base_url=BASE) as client:
            pid = create_project(client)
            assert upload(client, pid, make_hub_xlsx(tmp_path / "hub.xlsx")).status_code == 303
            r = client.post(f"/projects/{pid}/repos", data={"repos_dir": "team"}, headers=ORIGIN,
                            follow_redirects=False)
            assert r.status_code == 303
            fid = client.app.state.db.get_finding_by_hub_id(pid, "510001")["id"]
            review_reviewed(client, pid, fid)
        set_git_head(repo, "c" * 40)  # пока приложение остановлено, клон подменили
        with TestClient(create_app(settings), base_url=BASE) as client:
            assert client.app.state.db.get_review(pid, "510001")["reviewed"] == 0
            assert "Сменилась ревизия клона (billing-core)" in client.get(f"/projects/{pid}").text
    finally:
        fake.close()


def test_sheet_check_follows_import_result(web):
    pid = create_project(web.client)
    assert upload(web.client, pid, make_hub_xlsx(web.tmp / "hub.xlsx")).status_code == 303
    page = web.client.get(f"/projects/{pid}").text
    assert 'badge-warn">расходится со сводкой' in page  # в сводке SAST 120, на листе меньше
    path = make_hub_xlsx(web.tmp / "auto.xlsx", practices="auto", severities="auto")
    assert upload(web.client, pid, path).status_code == 303
    page = web.client.get(f"/projects/{pid}").text
    assert 'badge-warn">расходится со сводкой' not in page
    assert 'badge-ok">сходится со сводкой' in page


def test_folder_helpers(tmp_path: Path):
    write_repos(tmp_path)
    assert list_project_dirs(tmp_path) == ["", "team"]
    assert list_codebase_dirs(tmp_path / "team") == ["billing-core", "Catalog_API"]
    assert list_codebase_dirs(tmp_path) == ["team", "team/billing-core", "team/Catalog_API"]
    assert auto_folder("catalog-api", ["billing-core", "Catalog_API"]) == "Catalog_API"
    assert auto_folder("group/Billing.Core", ["billing-core"]) == "billing-core"
    assert auto_folder("billing-core", ["billing_core", "Billing-Core"]) == ""  # неоднозначно
    assert auto_folder("billing-core", ["team/billing-core", "billing-core"]) == "billing-core"
    assert auto_folder("notify-gateway", ["billing-core"]) == ""


# ============================================================================ находки и карточка

def test_findings_list_and_card_escape_code(web):
    pid = prepared(web)
    r = web.client.get(f"/projects/{pid}/findings")
    assert r.status_code == 200 and "510001" in r.text and "example-parser" in r.text
    r = web.client.get(f"/projects/{pid}/findings?kind=SCA")
    assert "example-parser" in r.text and "510001" not in r.text
    r = web.client.get(f"/projects/{pid}/findings?kind=bogus&verdict=bogus&page=abc")
    assert r.status_code == 200
    r = web.client.get(f"/projects/{pid}/findings?kind=SAST&page=99", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].endswith("findings?kind=SAST&page=1")
    fid = web.app.state.db.get_finding_by_hub_id(pid, "510001")["id"]
    card = web.client.get(f"/projects/{pid}/findings/{fid}")
    assert card.status_code == 200
    assert XSS not in card.text and "&lt;script&gt;alert(" in card.text
    assert 'class="is-target"' in card.text and "Скопировать комментарий для Hub" in card.text
    assert "Модель эту находку ещё не разбирала" in card.text
    assert web.client.get(f"/projects/{pid}/findings/999999").status_code == 404


def test_card_hides_credential_in_differing_export_line(web):
    settings_file = web.tmp / "repos" / "team" / "billing-core" / SETTINGS
    settings_file.parent.mkdir(parents=True, exist_ok=True)
    java = [f"    // строка {n}" for n in range(1, 21)]
    java[13] = "    String k = loadFromVault();"  # строка 14 в клоне уже другая
    settings_file.write_text("\n".join(java) + "\n", encoding="utf-8")
    row = {**SAST_ROWS[2], "Source code": 'String k = "hunter2hunter2"; : 14',  # короткий литерал без «ключа»
           "Artifact": 'String k = """\nhunter2hunter2\n""";'}  # копия кода с многострочным литералом
    pid = create_project(web.client)
    web.app.state.db.update_project(pid, mask_secrets=True)  # маску включает оператор (по умолчанию её нет)
    assert upload(web.client, pid, make_hub_xlsx(web.tmp / "secret.xlsx", sast=[row])).status_code == 303
    r = web.client.post(f"/projects/{pid}/repos", data={"repos_dir": "team"}, headers=ORIGIN, follow_redirects=False)
    assert r.status_code == 303
    fid = web.app.state.db.get_finding_by_hub_id(pid, "510003")["id"]
    card = web.client.get(f"/projects/{pid}/findings/{fid}").text
    assert "Фрагмент из выгрузки не найден рядом со строкой находки" in card
    assert "Проверьте, о том ли коде речь" in card and "Прочие колонки выгрузки" in card
    assert "Строка в клоне не совпадает" not in card
    assert "hunter2hunter2" not in card and 'id="trace-export-line"' in card and "&lt;SECRET_" in card


def test_card_version_matches_shown_code_snapshot(web, monkeypatch):
    pid = prepared(web)
    db = web.app.state.db
    fid = db.get_finding_by_hub_id(pid, "510001")["id"]
    real_get_case = db.get_case

    def switch_then_get(project_id, hub_id):  # параллельный запрос сменил клон, пока строилась карточка
        db.set_codebase_folder(project_id, "billing-core", "Catalog_API", manual=True)
        return real_get_case(project_id, hub_id)

    monkeypatch.setattr(db, "get_case", switch_then_get)
    card = web.client.get(f"/projects/{pid}/findings/{fid}").text
    monkeypatch.setattr(db, "get_case", real_get_case)
    assert "код из клона" in card and SQL_LINE in html.unescape(card)  # срез из прежнего клона, как в снимке
    r = web.client.post(f"/projects/{pid}/findings/{fid}/review", headers={**ORIGIN, "Accept": "application/json"},
                        data={**hidden_fields(card), "fix": "Параметризовать запрос.", "decision": "later", "reviewed": "1", "action": "save"})
    assert r.status_code == 409 and db.get_review(pid, "510001") is None


def test_card_after_run_keeps_blank_lines_and_target(web):
    pid = prepared(web)
    assert wait_run(web, start_run(web, pid))["state"] == "done"
    fid = web.app.state.db.get_finding_by_hub_id(pid, "510004")["id"]
    card = web.client.get(f"/projects/{pid}/findings/{fid}").text
    target = re.search(r'<tr id="L(\d+)" class="is-target"><td class="ln">'
                       r'<span class="mark" aria-hidden="true">▶</span>\d+</td><td class="src">(.*?)</td>', card)
    assert target and target.group(1) == "9" and html.unescape(target.group(2)).strip() == PY_LINE
    assert '<td class="ln">3</td><td class="src"></td>' in card  # пустая строка на своём месте


def test_triage_review_and_copy_for_hub(web):
    pid = prepared(web)
    run_id = start_run(web, pid)
    assert wait_run(web, run_id)["state"] == "done"
    db = web.app.state.db
    fid = db.get_finding_by_hub_id(pid, "510001")["id"]
    card = web.client.get(f"/projects/{pid}/findings/{fid}")
    assert "verdict-false_positive" in card.text and "Ложное срабатывание" in card.text

    shown = hidden_fields(card.text)
    assert shown["finding_version"] and shown["verdict_id"].isdigit()

    url = f"/projects/{pid}/findings/{fid}/review"
    as_json = {**ORIGIN, "Accept": "application/json"}
    # «Ложное срабатывание» рядом с тем же вердиктом модели – «Согласен» в базе; в Hub уходит обоснование оператора
    r = web.client.post(url, headers=as_json, data={**shown, "fix": "Параметризовать запрос.", "decision": "false_positive", "final_verdict": "",
                                                    "comment": "Проверено вручную.", "reviewed": "1",
                                                    "action": "copy"})
    assert r.status_code == 200, r.text
    answer = r.json()
    assert answer["final_verdict"] == "false_positive" and answer["reviewed"]
    assert answer["hub_text"] == "Проверено вручную." and db.get_review(pid, "510001")["decision"] == "agree"
    assert db.get_review(pid, "510001")["copied_at"] is None  # отметка – только после копирования в браузере
    copied_url = f"/projects/{pid}/findings/{fid}/copied"
    r = web.client.post(copied_url, headers=as_json, data={"revision": str(answer["revision"])})
    assert r.status_code == 200 and db.get_review(pid, "510001")["copied_at"] == r.json()["copied_at"]
    other = db.get_finding_by_hub_id(pid, "510002")["id"]
    other_url = f"/projects/{pid}/findings/{other}/copied"
    assert web.client.post(other_url, headers=as_json, data={"revision": "1"}).status_code == 409  # решения нет
    assert web.client.post(copied_url, headers=as_json).status_code == 400  # без редакции не засчитывается
    # другая вкладка успела сохранить решение заново – подтверждение старой копии не засчитывается
    r = web.client.post(url, headers=as_json, data={**shown, "fix": "Параметризовать запрос.", "decision": "false_positive", "comment": "Изменено.",
                                                    "action": "copy"})
    assert r.json()["revision"] == answer["revision"] + 1
    r = web.client.post(copied_url, headers=as_json, data={"revision": str(answer["revision"])})
    assert r.status_code == 409 and "скопируйте текст ещё раз" in r.json()["detail"]
    assert web.client.post(copied_url, headers=as_json, data={"revision": "x"}).status_code == 400

    # «Согласен» – это вердикт модели: устаревшее значение поля итогового вердикта не мешает (иначе после нового
    # разбора копирование заходит в тупик), сохраняется вердикт модели
    r = web.client.post(url, headers=as_json, data={**shown, "fix": "Параметризовать запрос.", "decision": "agree", "final_verdict": "true_positive",
                                                    "comment": "Проверено вручную.", "action": "save"})
    assert r.status_code == 200 and r.json()["final_verdict"] == "false_positive"

    r = web.client.post(url, headers=ORIGIN, follow_redirects=False,
                        data={**shown, "fix": "Параметризовать запрос.", "decision": "true_positive", "final_verdict": "",
                              "comment": "Нет проверки.", "reviewed": "1", "action": "next"})
    assert r.status_code == 303
    review = db.get_review(pid, "510001")
    assert (review["decision"], review["final_verdict"], review["reviewed"]) == ("disagree", "true_positive", 1)
    nxt = r.headers["location"]
    assert nxt.startswith(f"/projects/{pid}/findings/") and nxt != f"/projects/{pid}/findings/{fid}"
    assert web.client.post(url, headers=ORIGIN, data={**shown, "fix": "Параметризовать запрос.", "decision": "bogus"}).status_code == 400
    assert web.client.post(url, data={**shown, "fix": "Параметризовать запрос.", "decision": "agree"}).status_code == 403

    # страница устарела: модель спросили заново, у находки другой вердикт
    rerun = web.app.state.runner.enqueue(pid, "qwen2.5-coder:14b", "selected", ["510001"], fresh=True)
    assert wait_run(web, rerun)["state"] == "done"
    r = web.client.post(url, headers=as_json, data={**shown, "fix": "Параметризовать запрос.", "decision": "agree", "action": "save"})
    assert r.status_code == 409 and r.json()["reason"] == "verdict" and "Вердикт модели изменился" in r.json()["detail"]
    # устаревание проверяется раньше, чем согласованность решения
    r = web.client.post(url, headers=as_json, data={**shown, "fix": "Параметризовать запрос.", "decision": "agree", "final_verdict": "true_positive",
                                                    "action": "save"})
    assert r.status_code == 409
    r = web.client.post(url, headers={**ORIGIN, "Accept": "text/html"}, data={**shown, "fix": "Параметризовать запрос.", "decision": "agree"})
    assert r.status_code == 409 and "flash-err" in r.text
    assert db.get_review(pid, "510001")["decision"] == "disagree"

    page = web.client.get(f"/projects/{pid}/findings?reviewed=yes")
    # повторный разбор по тому же коду решение на проверку не возвращает (ADR-0097;
    # до 0.9.10 – COR-1: возвращал)
    assert "510001" in page.text


def test_next_reports_when_only_current_is_left(web):
    pid = prepared(web)
    db = web.app.state.db
    for hub_id in ("510001", "510002", "510003"):
        db.save_review(pid, hub_id, decision="later", final_verdict="", final_comment="", reviewed=True)
    fid = db.get_finding_by_hub_id(pid, "510004")["id"]
    card = web.client.get(f"/projects/{pid}/findings/{fid}")
    assert "Других непроверенных нет" in card.text
    r = web.client.post(f"/projects/{pid}/findings/{fid}/review", headers=ORIGIN, follow_redirects=False,
                        data={**hidden_fields(card.text), "fix": "Параметризовать запрос.", "decision": "later", "action": "next"})
    assert r.status_code == 303 and r.headers["location"].endswith(f"/findings/{fid}?ok=no_other")
    r = web.client.post(f"/projects/{pid}/findings/{fid}/review", headers=ORIGIN, follow_redirects=False,
                        data={**hidden_fields(card.text), "fix": "Параметризовать запрос.", "decision": "false_positive", "final_verdict": "",
                              "comment": "Значение приводится к числу.", "reviewed": "1", "action": "next"})
    assert r.headers["location"].endswith("/findings?ok=all_reviewed")


def test_later_keeps_finding_unreviewed_and_is_not_copied(web):
    """«Отложить» – вернуться позже: находка остаётся непроверенной, а в Hub ничего не переносится (ADR-0089)."""
    pid = prepared(web)
    assert wait_run(web, start_run(web, pid))["state"] == "done"
    db = web.app.state.db
    fid = db.get_finding_by_hub_id(pid, "510001")["id"]
    card = web.client.get(f"/projects/{pid}/findings/{fid}").text
    r = web.client.post(f"/projects/{pid}/findings/{fid}/review", headers={**ORIGIN, "Accept": "application/json"},
                        data={**hidden_fields(card), "fix": "Параметризовать запрос.", "decision": "later", "final_verdict": "",
                              "comment": "Вернуться после ответа команды.", "reviewed": "1", "action": "save"})
    assert r.status_code == 200, r.text
    answer = r.json()
    assert not answer["reviewed"]  # отложенная находка остаётся непроверенной
    review = db.get_review(pid, "510001")
    assert (review["decision"], review["final_verdict"], review["reviewed"]) == ("later", "", 0)
    card = web.client.get(f"/projects/{pid}/findings/{fid}").text
    assert "Вернуться после ответа команды." in html.unescape(card) and 'id="hub-stale" hidden' in card
    # копировать нечего: короткий комментарий – только у ложного срабатывания
    copy = web.client.post(f"/projects/{pid}/findings/{fid}/review", headers={**ORIGIN, "Accept": "application/json"},
                           data={**hidden_fields(card), "review_revision": str(review["revision"]),
                                 "fix": "Параметризовать запрос.", "decision": "later", "final_verdict": "",
                                 "comment": "Вернуться после ответа команды.", "action": "copy"})
    assert copy.status_code == 400 and "hub_text" not in copy.json()
    assert "только при решении «Ложное срабатывание»" in copy.json()["detail"]


def test_run_page_status_events_and_controls(web):
    pid = prepared(web)
    run_id = start_run(web, pid)
    run = wait_run(web, run_id)
    assert run["state"] == "done" and run["total"] == 4
    page = web.client.get(f"/runs/{run_id}")
    assert page.status_code == 200 and f"Прогон №{run_id}" in page.text and "Demo GPU" in page.text
    status = web.client.get(f"/runs/{run_id}/status").json()
    assert status["run"]["state"] == "done" and status["run"]["state_label"] == "завершён"
    assert status["metrics"]["gpu"]["util_pct"] == 87 and status["metrics"]["vram_total_mb"] == 16000
    assert all(item["url"] for item in status["feed"])
    with web.client.stream("GET", f"/runs/{run_id}/events") as stream:
        body = stream.read().decode("utf-8")
    assert "event: status" in body and "event: end" in body
    for action in ("pause", "resume", "stop"):
        assert web.client.post(f"/runs/{run_id}/{action}").status_code == 403
        assert web.client.post(f"/runs/{run_id}/{action}", headers=ORIGIN,
                               follow_redirects=False).status_code == 303
    assert web.client.get("/runs/999999/status").status_code == 404


def test_selected_run_and_single_active_run(web):
    pid = prepared(web)
    web.fake.delay = 0.4
    run_id = start_run(web, pid, scope="selected", hub_id=["510002", "73001"])
    assert web.app.state.db.get_run(run_id)["total"] == 1  # SCA в прогон не попадает
    r = web.client.post(f"/projects/{pid}/runs", data={"model": "qwen2.5-coder:14b", "scope": "all"}, headers=ORIGIN)
    assert r.status_code == 400 and "незавершённый прогон" in r.text
    assert wait_run(web, run_id)["state"] == "done"
    r = web.client.post(f"/projects/{pid}/runs", data={"model": "", "scope": "all"}, headers=ORIGIN)
    assert r.status_code == 400 and "Не выбрана модель" in r.text


def test_api_metrics(web):
    data = web.client.get("/api/metrics").json()
    assert data["gpu"]["name"] == "Demo GPU" and data["gpu"]["temp_c"] == 61
    assert data["vram_used_mb"] == 9000 and data["vram_total_mb"] == 16000
    assert data["models"][0]["name"] == "qwen2.5-coder:14b" and data["models"][0]["vram_pct"] == 100


def test_errors_are_in_russian(web):
    r = web.client.get("/projects/424242", headers={"Accept": "text/html"})
    assert r.status_code == 404 and "Не найдено" in r.text and "Проект не найден" in r.text
    r = web.client.get("/projects/424242", headers={"Accept": "application/json"})
    assert r.status_code == 404 and r.json()["detail"] == "Проект не найден."
    r = web.client.get("/no-such-page", headers={"Accept": "text/html"})
    assert r.status_code == 404 and "Страница не найдена" in r.text and "Not Found" not in r.text
    r = web.client.get("/projects/abc", headers={"Accept": "text/html"})
    assert r.status_code == 422 and "Неверный адрес" in r.text
    r = web.client.post("/healthz", headers={**ORIGIN, "Accept": "application/json"})
    assert r.status_code == 405 and r.json()["detail"] == "Такой запрос здесь не поддерживается."
    pid = create_project(web.client)
    r = web.client.post(f"/projects/{pid}/import", content=b"x",
                        headers={**ORIGIN, "Accept": "application/json", "Content-Type": "multipart/form-data"})
    assert r.status_code == 400 and r.json()["detail"] == "Неверный запрос."


def test_internal_error_page_is_in_russian(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(metrics, "gpu_stats", lambda: None)
    settings = Settings(data_dir=tmp_path / "data", repos_root=tmp_path, ollama_url="http://127.0.0.1:9")
    app = create_app(settings)
    with TestClient(app, base_url=BASE, raise_server_exceptions=False) as client:
        def broken():
            raise RuntimeError("сбой")

        monkeypatch.setattr(app.state.db, "list_projects", broken)
        r = client.get("/", headers={"Accept": "text/html"})
        assert r.status_code == 500 and "Внутренняя ошибка приложения" in r.text
        assert "Traceback" not in r.text and "RuntimeError" not in r.text


def test_ollama_problems_are_shown(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(metrics, "gpu_stats", lambda: None)
    # у каждого адреса своя папка данных: адрес из окружения – только начальное значение настройки в базе
    cases = (("http://192.0.2.10:11434", "не входит в разрешённые", "не отвечает"),
             ("http://127.0.0.1:9", "не отвечает", "не входит в разрешённые"))
    for k, (url, text, other) in enumerate(cases):
        settings = Settings(data_dir=tmp_path / f"data-{k}", repos_root=tmp_path / "missing", ollama_url=url)
        with TestClient(create_app(settings), base_url=BASE) as client:
            pid = create_project(client)
            page = client.get(f"/projects/{pid}")
            assert page.status_code == 200 and text in page.text and other not in page.text
            assert "не подключена" in page.text  # REPOS_ROOT не найден
            data = client.get("/api/metrics").json()
            assert data["gpu"] is None and data["error"]
