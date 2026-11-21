"""Срезы кода в базе вместо клонов после разбора (ADR-0072): удаление клона целиком, частичное удаление, пустая
папка, подбор папок заново, повторная загрузка выгрузки, прогон и сверка без клона, «Сохранить срезы кода»
и шаг 2. Данные выдуманные (tests/hub_fixtures.py), модель – поддельная (tests/fake_ollama.py)."""

from __future__ import annotations

import json
import re
import shutil
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
from app.main import create_app  # noqa: E402
from app.triage import CONTEXT_CHARS, current_code, snapshot_code  # noqa: E402
from fake_ollama import FakeOllama  # noqa: E402
from hub_fixtures import INVOICE, PY_LINE, SQL_LINE, make_hub_xlsx  # noqa: E402
from test_web import (BASE, GPU, ORIGIN, create_project, prepared, set_git_head, start_run, upload,  # noqa: E402
                      wait_run, write_repos)

AS_JSON = {**ORIGIN, "Accept": "application/json"}
MODEL = "qwen2.5-coder:14b"


@pytest.fixture
def web(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(metrics, "gpu_stats", lambda: dict(GPU))
    fake = FakeOllama(loaded=[MODEL])
    write_repos(tmp_path / "repos")
    settings = Settings(data_dir=tmp_path / "data", repos_root=tmp_path / "repos", ollama_url=fake.url,
                        max_upload_mb=1, team_name="Тестовая команда")
    app = create_app(settings)
    with TestClient(app, base_url=BASE) as client:
        yield SimpleNamespace(client=client, app=app, fake=fake, settings=settings, tmp=tmp_path)
    fake.close()


def clone(web, name: str = "billing-core") -> Path:
    return web.tmp / "repos" / "team" / name


def card_url(web, pid: int, hub_id: str) -> str:
    return f"/projects/{pid}/findings/{web.app.state.db.get_finding_by_hub_id(pid, hub_id)['id']}"


def form_of(card: str) -> dict:
    """Скрытые поля формы решения так, как их отправит браузер."""
    names = ("finding_version", "verdict_id", "review_revision", "code_hash", "code_chars")
    return {n: m.group(1) for n in names if (m := re.search(rf'name="{n}" value="([^"]*)"', card))}


def decide(web, pid: int, hub_id: str, decision: str = "disagree", verdict: str = "true_positive",
           comment: str = "Подтверждено: owner приходит из запроса.", action: str = "save") -> dict:
    url = card_url(web, pid, hub_id)
    r = web.client.post(f"{url}/review", headers=AS_JSON, data={
        **form_of(web.client.get(url).text), "fix": "Параметризовать запрос.", "decision": decision, "final_verdict": verdict, "comment": comment,
        "reviewed": "1", "action": action})
    assert r.status_code == 200, r.text
    return r.json()


def analysed(web) -> int:
    """Проект с выгрузкой, клонами и разбором поддельной моделью."""
    pid = prepared(web)
    assert wait_run(web, start_run(web, pid))["state"] == "done"
    return pid


def cases(web, pid: int) -> dict[str, tuple[str, str, int | None]]:
    """{ID находки: (отпечаток, статус среза, вердикт)} – что лежит в базе."""
    rows = web.app.state.db._all("SELECT hub_id, case_hash, context_json, verdict_id FROM cases WHERE project_id = ?",
                                 (pid,))
    return {r["hub_id"]: (r["case_hash"], json.loads(r["context_json"])["status"], r["verdict_id"]) for r in rows}


def reviewed(web, pid: int, hub_id: str) -> int:
    return int((web.app.state.db.get_review(pid, hub_id) or {}).get("reviewed") or 0)


def remove_clone(web, name: str = "billing-core", keep_empty: bool = False) -> None:
    shutil.rmtree(clone(web, name))
    if keep_empty:
        clone(web, name).mkdir()


# ============================================================================ срез из базы – текущий код

def test_snapshot_hash_matches_what_model_saw(web):
    pid = analysed(web)
    db = web.app.state.db
    stored = cases(web, pid)
    remove_clone(web)
    remove_clone(web, "Catalog_API")
    for hub_id in ("510001", "510002", "510003", "510004"):
        case, source = db.get_case(pid, hub_id), db.case_input(pid, hub_id)
        snapshot = snapshot_code(web.settings, source, case)
        assert snapshot is not None and snapshot[1] == stored[hub_id][0], hub_id
        # без клона срез любого размера – тот же срез из базы
        assert current_code(web.settings, source, web.app.state.mask_key, CONTEXT_CHARS, case=case)[2] == \
            stored[hub_id][0]
    assert stored["510001"][1] == "ok" and stored["510002"][1] != "ok"  # файла Renderer.java в клоне нет


def test_card_decision_copy_and_defect_without_clone(web):
    pid = analysed(web)
    db = web.app.state.db
    db.set_settings({"team_name": "Платформа"})
    saved = decide(web, pid, "510001")
    assert saved["reviewed"] and saved["defect_ready"] is True
    before = cases(web, pid)
    remove_clone(web)

    url = card_url(web, pid, "510001")
    card = web.client.get(url).text
    assert 'id="code-from-db"' in card and "тот, который видела модель" in card
    assert "срез из базы приложения" in card and 'id="code-changed"' not in card
    assert html_text(SQL_LINE) in card  # код находки на месте, хотя клона нет
    assert 'id="defect-panel" aria-labelledby="defect-title">' in card
    defect = web.client.post(f"{url}/defect", headers=AS_JSON, data={"number": "", "part": "title"})
    assert defect.status_code == 200 and defect.json()["title"] == "ID1 - Внедрение SQL-кода (SAST)"
    # решение по коду из базы сохраняется, текст дефекта выдаётся, отметка «Проверено» остаётся
    again = decide(web, pid, "510001", comment="Подтверждено повторно без клона.", action="save")
    assert again["reviewed"] and again["defect_ready"] is True
    body = web.client.post(f"{url}/defect", headers=AS_JSON, data={"number": "", "confirm": "1"}).json()["body"]
    assert "Подтверждено повторно без клона." in body
    assert web.client.post(f"{url}/copied", headers=AS_JSON,
                           data={"revision": str(again["revision"])}).status_code == 200
    toggled = web.client.post(f"{url}/reviewed", headers=AS_JSON, data={
        **form_of(web.client.get(url).text), "reviewed": "1"})
    assert toggled.status_code == 200, toggled.text
    assert reviewed(web, pid, "510001") == 1 and cases(web, pid) == before


def prompt_text(chats: list[dict]) -> str:
    """Весь текст сообщений, ушедших модели."""
    return "\n".join(str(m.get("content") or "") for chat in chats for m in chat.get("messages") or [])


def html_text(line: str) -> str:
    return line.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&#34;") \
        .replace("'", "&#39;")


def test_restart_after_clone_removal_keeps_decisions(tmp_path: Path, monkeypatch):
    """Приложение остановлено, клон удалён, приложение запущено заново: решения и срезы на месте."""
    monkeypatch.setattr(metrics, "gpu_stats", lambda: None)
    fake = FakeOllama(loaded=[MODEL])
    write_repos(tmp_path / "repos")
    settings = Settings(data_dir=tmp_path / "data", repos_root=tmp_path / "repos", ollama_url=fake.url)
    try:
        with TestClient(create_app(settings), base_url=BASE) as client:
            first = SimpleNamespace(client=client, app=client.app, fake=fake, settings=settings, tmp=tmp_path)
            pid = analysed(first)
            decide(first, pid, "510001")
            before = cases(first, pid)
        remove_clone(first)
        with TestClient(create_app(settings), base_url=BASE) as client:
            again = SimpleNamespace(client=client, app=client.app, fake=fake, settings=settings, tmp=tmp_path)
            card = client.get(card_url(again, pid, "510001")).text
            assert 'id="code-from-db"' in card and 'id="code-changed"' not in card
            assert reviewed(again, pid, "510001") == 1 and cases(again, pid) == before
            assert "Сменилась ревизия" not in client.get(f"/projects/{pid}").text
    finally:
        fake.close()


def test_partial_removal_file_gone_but_folder_left(web):
    pid = analysed(web)
    decide(web, pid, "510001")
    before = cases(web, pid)
    (clone(web) / INVOICE).unlink()  # остался pom.xml – папка клона на месте, файла находки нет
    card = web.client.get(card_url(web, pid, "510001")).text
    assert 'id="code-from-db"' in card and 'id="code-changed"' not in card
    assert reviewed(web, pid, "510001") == 1 and cases(web, pid) == before


def test_empty_folder_and_removed_git_keep_snapshots(web):
    set_git_head(clone(web), "a" * 40)
    pid = analysed(web)
    decide(web, pid, "510001")
    before = cases(web, pid)
    assert web.app.state.db.revisions(pid).get("billing-core") == "a" * 40
    shutil.rmtree(clone(web) / ".git")  # удалена только .git: ревизии нет, код тот же
    assert web.client.get(f"/projects/{pid}").status_code == 200
    remove_clone(web, keep_empty=True)  # на месте клона пустая папка
    page = web.client.get(f"/projects/{pid}")
    assert page.status_code == 200 and "клон удалён, срезы в базе" in page.text
    assert web.client.post(f"/projects/{pid}/codebases", headers=ORIGIN, data={"action": "auto"},
                           follow_redirects=False).status_code == 303
    assert cases(web, pid) == before and reviewed(web, pid, "510001") == 1
    assert "изменил" not in web.client.get(f"/projects/{pid}").text.split('id="step2"')[1].split('id="step3"')[0]


def test_automap_and_reimport_keep_mapping_of_removed_clone(web):
    pid = analysed(web)
    decide(web, pid, "510001")
    before = cases(web, pid)
    db = web.app.state.db
    mapping = db.get_codebase_map(pid)
    remove_clone(web)
    remove_clone(web, "Catalog_API")
    r = web.client.post(f"/projects/{pid}/codebases", headers=ORIGIN, data={"action": "auto"}, follow_redirects=False)
    assert r.status_code == 303 and "reopened" not in r.headers["location"]
    assert upload(web.client, pid, make_hub_xlsx(web.tmp / "hub-again.xlsx")).status_code == 303
    assert db.get_codebase_map(pid) == mapping and cases(web, pid) == before
    assert reviewed(web, pid, "510001") == 1
    page = web.client.get(f"/projects/{pid}").text
    step2 = page.split('id="step2"')[1].split('id="step3"')[0]
    assert 'id="clone-list"' not in step2 and "Выбранная папка проекта не найдена" not in step2
    assert 'id="snapshots-ready"' in step2


def test_whole_project_folder_removed(web):
    pid = analysed(web)
    shutil.rmtree(web.tmp / "repos" / "team")
    page = web.client.get(f"/projects/{pid}").text
    step2 = page.split('id="step2"')[1].split('id="step3"')[0]
    assert "Выбранная папка проекта не найдена" not in step2 and 'id="snapshots-ready"' in step2
    card = web.client.get(card_url(web, pid, "510004")).text
    assert 'id="code-from-db"' in card and html_text(PY_LINE) in card


def test_clone_present_change_is_still_detected(web):
    pid = analysed(web)
    path = clone(web) / INVOICE
    path.write_text(path.read_text(encoding="utf-8").replace("owner", "owner_id"), encoding="utf-8")
    card = web.client.get(card_url(web, pid, "510001")).text
    assert 'id="code-changed"' in card and 'id="code-from-db"' not in card


def test_stale_analysis_shows_the_current_slice_with_changed_lines(web):
    """Бэклог 112: разбор устарел – под срезом модели карточка показывает текущий срез клона и называет строки,
    которые отличаются; сдвиг номеров отличием не считается. Пока код тот же – блока нет; срез разбора в базе прежний."""
    from app import mask_display
    from app.models import CodeContext
    pid = analysed(web)
    db = web.app.state.db
    assert 'id="code-current"' not in web.client.get(card_url(web, pid, "510001")).text
    before = db.get_case(pid, "510001")
    path = clone(web) / INVOICE
    lines = path.read_text(encoding="utf-8").split("\n")
    target = next(i for i, line in enumerate(lines) if "owner" in line)
    lines[target] = lines[target].replace("owner", "owner_id")
    lines.insert(0, "// новая первая строка файла")
    path.write_text("\n".join(lines), encoding="utf-8")
    card = web.client.get(card_url(web, pid, "510001")).text
    assert 'id="code-changed"' in card and 'id="code-current"' in card
    block = card.split('id="code-current"', 1)[1].split("</table>", 1)[0]
    assert "owner_id" in block and "Модель этот код не разбирала" in block
    changed = [int(n) for n in re.findall(r'<tr class="[^"]*is-changed[^"]*"><td class="ln">(?:<span[^>]*>[^<]*</span>)?(\d+)</td>', block)]
    assert target + 2 in changed, "изменённая строка подсвечена (номер – с учётом вставленной строки)"
    model_lines = len(CodeContext.from_dict(before["context"]).lines)
    assert 0 < len(changed) < model_lines // 2, "сдвинутые, но те же строки не подсвечены"
    assert "Отличаются от среза модели строки" in block.split('id="code-current-diff"', 1)[1]
    assert db.get_case(pid, "510001") == before, "срез разбора и отпечаток в базе не меняются"

    old = CodeContext.from_dict(before["context"])
    same = mask_display.current_slice(old, old)
    assert same["changed"] == "" and same["removed"] == 0 and not any(r["changed"] for r in same["rows"])
    assert mask_display.current_slice(None, old) is None
    assert mask_display._ranges([3, 4, 5, 9, 11, 12]) == "3–5, 9, 11–12"


# ============================================================================ прогон без клона

def test_rerun_without_clone_sends_stored_snapshot(web):
    pid = analysed(web)
    decide(web, pid, "510004", verdict="false_positive", comment="Параметр экранируется.")
    before = cases(web, pid)
    remove_clone(web, "Catalog_API")
    sent = len(web.fake.chats())
    run_id = web.app.state.runner.enqueue(pid, MODEL, "selected", ["510004"], fresh=True)
    assert wait_run(web, run_id)["state"] == "done"
    prompts = web.fake.chats()[sent:]
    assert prompts and PY_LINE in prompt_text(prompts) and "строка 7" in prompt_text(prompts)  # код, а не строка
    after = cases(web, pid)
    assert after["510004"][:2] == before["510004"][:2]  # срез тот же
    items = web.app.state.db._all("SELECT state, error FROM run_items WHERE run_id = ?", (run_id,))
    assert [i["state"] for i in items] == ["done"], items


def test_full_rerun_after_all_clones_removed_uses_stored_snapshots(web):
    """Новая версия промпта после удаления исходников: полный повторный прогон «Все SAST» берёт код из срезов в
    базе – ни одной ошибки «нет клона», срезы те же (так перепроверяются вердикты прогона на реальных данных)."""
    pid = analysed(web)
    before = cases(web, pid)
    for name in ("billing-core", "Catalog_API"):
        remove_clone(web, name)
    sent = len(web.fake.chats())
    run_id = web.app.state.runner.enqueue(pid, MODEL, "all", [], fresh=True)
    assert wait_run(web, run_id)["state"] == "done"
    items = web.app.state.db._all("SELECT state, error FROM run_items WHERE run_id = ?", (run_id,))
    assert items and all(i["state"] == "done" and not i["error"] for i in items), items
    assert len(web.fake.chats()) - sent == len(items)  # каждая находка ушла модели заново
    assert PY_LINE in prompt_text(web.fake.chats()[sent:])  # с кодом из среза, а не одной строкой выгрузки
    after = cases(web, pid)
    assert {h: c[:2] for h, c in after.items()} == {h: c[:2] for h, c in before.items()}  # срезы те же


def test_model_unavailable_keeps_snapshots_and_marks(web):
    pid = analysed(web)
    decide(web, pid, "510001")
    before = cases(web, pid)
    remove_clone(web)
    web.fake.close()  # Ollama не отвечает: срезы находок прогона сверяются с текущим кодом
    run_id = web.app.state.runner.enqueue(pid, MODEL, "all", [], fresh=False)
    wait_run(web, run_id)
    assert cases(web, pid) == before and reviewed(web, pid, "510001") == 1


def test_model_unavailable_does_not_mix_saved_slice_and_returned_file(web, monkeypatch):
    """Ревью Codex ветки долга, круг 5: модель недоступна, клон подключён, а файла находки в нём нет – сверка берёт срез
    из базы, и файл возвращается сразу после этого чтения. Признак подстановки – у того же чтения: «Проверено» по коду B
    не снимается по коду, который никто не прочитал. (Если удалить клон целиком, он отвязывается и срез берётся из
    базы при любой проверке – гонки нет.)"""
    import app.triage as triage
    from app import context

    pid = analysed(web)
    db = web.app.state.db
    decide(web, pid, "510001", verdict="false_positive", comment="Параметр экранируется.")
    case = db.get_case(pid, "510001")
    chars = int(case["context"].get("max_chars") or CONTEXT_CHARS)
    with db._tx() as c:  # человек решал по коду B (тот же размер среза)
        c.execute("UPDATE reviews SET reviewed = 1, code_hash = ?, code_chars = ? WHERE project_id = ?"
                  " AND hub_id = ?", ("b" * 64, chars, pid, "510001"))
    target = clone(web) / case["context"]["file"]
    saved_bytes = target.read_bytes()
    target.unlink()  # файла находки в подключённом клоне нет
    context._INDEX_CACHE.clear()
    real = triage.snapshot_code
    calls = []

    def file_returns(settings, source, stored):
        got = real(settings, source, stored)
        calls.append(got is not None)
        if got is not None and not target.exists():
            target.write_bytes(saved_bytes)  # файл вернулся сразу после чтения
            context._INDEX_CACHE.clear()
        return got

    monkeypatch.setattr(triage, "snapshot_code", file_returns)
    web.fake.close()  # Ollama не отвечает: срезы находок прогона сверяются с текущим кодом
    run_id = web.app.state.runner.enqueue(pid, MODEL, "selected", ["510001"], fresh=True)
    wait_run(web, run_id)
    assert calls and calls[0] and target.exists(), "срез подставлен, файл вернулся"
    assert reviewed(web, pid, "510001") == 1
    assert db.code_change_notice(pid) is None


def test_model_unavailable_keeps_a_decision_saved_after_the_code_was_read(web, monkeypatch):
    """Бэклог 117: модель недоступна, сверка прочитала код находки из клона (он совпал со срезом модели), и сразу
    после этого чтения оператор сохранил решение по другому коду (код в клоне сменился без смены ревизии). Запись
    сверки по старому чтению отметку свежего решения не снимает; пояснения о смене кода нет."""
    import app.triage as triage

    pid = analysed(web)
    db = web.app.state.db
    case = db.get_case(pid, "510001")
    chars = int(case["context"].get("max_chars") or CONTEXT_CHARS)
    real = triage.current_code_origin
    saved = []

    def decision_after_read(settings, source, *args, **kwargs):
        got = real(settings, source, *args, **kwargs)
        if not saved:  # решение сохранено сразу после чтения клона
            db.save_review(pid, "510001", decision="disagree", final_verdict="false_positive",
                           final_comment="Параметр экранируется.", reviewed=True, code_hash="b" * 64,
                           code_chars=chars)
            saved.append(True)
        return got

    monkeypatch.setattr(triage, "current_code_origin", decision_after_read)
    web.fake.close()  # Ollama не отвечает: срезы находок прогона сверяются с текущим кодом
    run_id = web.app.state.runner.enqueue(pid, MODEL, "selected", ["510001"], fresh=False)
    wait_run(web, run_id)
    assert saved, "сверка читала код находки"
    assert reviewed(web, pid, "510001") == 1
    assert db.code_change_notice(pid) is None


def test_decision_with_other_snapshot_size_is_not_proven_without_clone(web):
    """Решение, принятое при другом размере среза, без клона не сравнить с кодом: «сравнить нельзя» – не «всё
    в порядке». Дефект не выдаётся, пока решение не сохранят заново (предбоевая проверка, Б4)."""
    pid = analysed(web)
    saved = decide(web, pid, "510001")
    assert saved["defect_ready"] is True
    db = web.app.state.db
    with db._tx() as c:  # прогон сократил срез под окно модели, а решение записано при полном размере
        row = c.execute("SELECT context_json FROM cases WHERE project_id = ? AND hub_id = '510001'", (pid,)).fetchone()
        context = {**json.loads(row["context_json"]), "max_chars": 9000}
        c.execute("UPDATE cases SET context_json = ? WHERE project_id = ? AND hub_id = '510001'",
                  (json.dumps(context, ensure_ascii=False), pid))
        c.execute("UPDATE reviews SET code_hash = ?, code_chars = ? WHERE project_id = ? AND hub_id = '510001'",
                  ("f" * 64, CONTEXT_CHARS, pid))
    remove_clone(web)
    url = card_url(web, pid, "510001")
    defect = web.client.post(f"{url}/defect", headers=AS_JSON, data={"number": "", "part": "title"})
    assert defect.status_code == 409, defect.text
    decide(web, pid, "510001")  # заново – по срезу из базы
    again = web.client.post(f"{url}/defect", headers=AS_JSON, data={"number": "", "part": "title"})
    assert again.status_code == 200, again.text


# ============================================================================ «Сохранить срезы кода»

def test_save_snapshots_without_model_then_remove_clones(web):
    pid = prepared(web)
    db = web.app.state.db
    page = web.client.get(f"/projects/{pid}").text
    assert 'id="save-snapshots"' in page and 'id="snapshots-count">0 из 4' in page
    r = web.client.post(f"/projects/{pid}/snapshots", headers=ORIGIN, follow_redirects=False)
    assert r.status_code == 303 and "ok=snapshots#step2" in r.headers["location"]
    stored = cases(web, pid)
    assert set(stored) == {"510001", "510002", "510003", "510004"}
    assert all(verdict is None for _, _, verdict in stored.values())
    assert stored["510001"][1] == stored["510004"][1] == "ok"
    assert not web.fake.chats()  # модель не вызывалась
    # повторное нажатие ничего не меняет
    r = web.client.post(f"/projects/{pid}/snapshots", headers=ORIGIN, follow_redirects=False)
    assert "ok=snapshots_none" in r.headers["location"] and cases(web, pid) == stored
    page = web.client.get(f"/projects/{pid}").text
    assert 'id="snapshots-ready"' in page and 'id="save-snapshots"' not in page

    remove_clone(web)
    remove_clone(web, "Catalog_API")
    step2 = web.client.get(f"/projects/{pid}").text.split('id="step2"')[1].split('id="step3"')[0]
    assert step2.count("клон удалён, срезы в базе") == 2 and 'id="clone-list"' not in step2
    card = web.client.get(card_url(web, pid, "510001")).text
    assert 'id="code-from-db"' in card and "тот, который видела модель" not in card
    assert html_text(SQL_LINE) in card
    # решение без разбора моделью – по коду из базы
    saved = decide(web, pid, "510001")
    assert saved["reviewed"] and saved["defect_ready"] is True
    # разбор после удаления клонов – по сохранённым срезам
    assert wait_run(web, start_run(web, pid))["state"] == "done"
    assert SQL_LINE in prompt_text(web.fake.chats()) and "строка 50" in prompt_text(web.fake.chats())
    assert {k: v[:2] for k, v in cases(web, pid).items()} == {k: v[:2] for k, v in stored.items()}
    assert reviewed(web, pid, "510001") == 1 or db.get_review(pid, "510001")["decision"]


def test_save_snapshots_keeps_existing_and_reports_missing_clone(web):
    pid = prepared(web)
    remove_clone(web, "Catalog_API")
    r = web.client.post(f"/projects/{pid}/snapshots", headers=ORIGIN, follow_redirects=False)
    assert "ok=snapshots#step2" in r.headers["location"]
    stored = cases(web, pid)
    assert "510004" not in stored and {"510001", "510002", "510003"} <= set(stored)
    step2 = web.client.get(f"/projects/{pid}").text.split('id="step2"')[1].split('id="step3"')[0]
    assert 'id="snapshots-count">3 из 4' in step2 and 'id="snapshots-ready"' not in step2
    assert 'id="clone-list"' in step2 and "catalog-api" in step2


def test_delete_page_mentions_snapshots(web):
    pid = analysed(web)
    page = web.client.get(f"/projects/{pid}/delete").text
    assert "срезы кода находок SAST, сохранённые в базе приложения, – 2" in page
    assert "из базы они удаляются" in page and "model-traffic" in page  # DOC-03: журнал обмена хранится отдельно


def test_project_without_import_has_no_snapshot_block(web):
    pid = create_project(web.client)
    page = web.client.get(f"/projects/{pid}").text
    assert 'id="snapshots"' not in page


# ============================================================================ замечания ревью готового изменения

def sync(web, pid: int) -> None:
    """Сверка ревизий клонов – как после «Сохранить соответствие» без изменений."""
    r = web.client.post(f"/projects/{pid}/codebases", headers=ORIGIN, data={"action": "save"}, follow_redirects=False)
    assert r.status_code == 303, r.text


def test_revision_sync_right_after_git_removal_keeps_snapshots(web):
    set_git_head(clone(web), "a" * 40)
    pid = analysed(web)
    decide(web, pid, "510001")
    before = cases(web, pid)
    shutil.rmtree(clone(web) / ".git")
    sync(web, pid)
    assert cases(web, pid) == before and reviewed(web, pid, "510001") == 1
    assert web.app.state.db.revision_notice(pid) is None


def test_automap_keeps_mapping_when_other_candidate_appears(web):
    pid = analysed(web)
    decide(web, pid, "510001")
    before = cases(web, pid)
    remove_clone(web)
    (web.tmp / "repos" / "team" / "Billing_Core").mkdir()  # другая папка с подходящим именем
    (web.tmp / "repos" / "team" / "Billing_Core" / "pom.xml").write_text("<project/>\n", encoding="utf-8")
    r = web.client.post(f"/projects/{pid}/codebases", headers=ORIGIN, data={"action": "auto"}, follow_redirects=False)
    assert r.status_code == 303
    assert web.app.state.db.get_codebase_map(pid)["billing-core"]["folder"] == "billing-core"
    assert cases(web, pid) == before and reviewed(web, pid, "510001") == 1


def test_removed_clone_is_detached_and_foreign_clone_is_ignored(web):
    pid = analysed(web)
    decide(web, pid, "510001")
    before = cases(web, pid)
    db = web.app.state.db
    remove_clone(web)
    sync(web, pid)
    assert db.detached_codebases(pid) == {"billing-core"}
    # на то же место положили клон другой выгрузки: другая ревизия и другой код
    write_repos(web.tmp / "other")
    shutil.copytree(web.tmp / "other" / "team" / "billing-core", clone(web))
    path = clone(web) / INVOICE
    path.write_text(path.read_text(encoding="utf-8").replace("owner", "owner_id"), encoding="utf-8")
    set_git_head(clone(web), "b" * 40)
    sync(web, pid)
    assert cases(web, pid) == before and reviewed(web, pid, "510001") == 1
    card = web.client.get(card_url(web, pid, "510001")).text
    assert 'id="code-from-db"' in card and 'id="code-changed"' not in card and "owner_id" not in card
    step2 = web.client.get(f"/projects/{pid}").text.split('id="step2"')[1].split('id="step3"')[0]
    assert "клон не читается, срезы в базе" in step2 and 'id="attach-clones"' in step2
    # «Подключить клоны снова»: в папке теперь другой код – срезы этой кодовой базы сбрасываются, как при смене кода
    r = web.client.post(f"/projects/{pid}/clones/attach", headers=ORIGIN, follow_redirects=False)
    assert r.status_code == 303 and "ok=clones_attached" in r.headers["location"]
    assert db.detached_codebases(pid) == set()
    assert "510001" not in cases(web, pid) and reviewed(web, pid, "510001") == 0
    assert 'id="code-changed"' not in web.client.get(card_url(web, pid, "510001")).text


def test_attach_with_clone_still_removed_detaches_again(web):
    pid = analysed(web)
    before = cases(web, pid)
    remove_clone(web)
    sync(web, pid)
    r = web.client.post(f"/projects/{pid}/clones/attach", headers=ORIGIN, follow_redirects=False)
    assert r.status_code == 303
    assert web.app.state.db.detached_codebases(pid) == {"billing-core"} and cases(web, pid) == before


def test_detach_waits_for_complete_snapshots(web):
    pid = prepared(web)  # разбора не было: срезов нет – отвязывать нельзя
    remove_clone(web)
    sync(web, pid)
    assert web.app.state.db.detached_codebases(pid) == set()


def test_clone_removed_while_slice_is_built(web, monkeypatch):
    import app.triage as triage

    pid = analysed(web)
    decide(web, pid, "510001")
    before = cases(web, pid)
    real = triage.build_context

    def vanish(repo_dir, f, **kw):  # файл был при проверке и пропал при чтении
        if clone(web).exists():
            shutil.rmtree(clone(web))
        return real(repo_dir, f, **kw)

    monkeypatch.setattr(triage, "build_context", vanish)
    run_id = web.app.state.runner.enqueue(pid, MODEL, "selected", ["510001"], fresh=True)
    assert wait_run(web, run_id)["state"] == "done"
    item = web.app.state.db._all("SELECT state, error FROM run_items WHERE run_id = ?", (run_id,))[0]
    assert item["state"] == "skipped" and "файл пропал во время разбора" in item["error"]
    assert cases(web, pid) == before and reviewed(web, pid, "510001") == 1


def test_clone_removed_while_model_answers(web, monkeypatch):
    import app.triage as triage

    pid = analysed(web)
    before = cases(web, pid)
    real = triage.parse_verdict

    def vanish(obj, ctx):  # модель ответила, а клон за это время удалили
        if clone(web).exists():
            shutil.rmtree(clone(web))
        return real(obj, ctx)

    monkeypatch.setattr(triage, "parse_verdict", vanish)
    run_id = web.app.state.runner.enqueue(pid, MODEL, "selected", ["510001"], fresh=True)
    assert wait_run(web, run_id)["state"] == "done"
    item = web.app.state.db._all("SELECT state, verdict_id FROM run_items WHERE run_id = ?", (run_id,))[0]
    assert item["state"] == "done" and item["verdict_id"]  # ответ привязан: код тот же, что в базе
    after = cases(web, pid)
    assert after["510001"][:2] == before["510001"][:2] and after["510001"][2] == item["verdict_id"]


def test_clone_removed_while_model_answers_keeps_reviewed_decided_on_other_code(web, monkeypatch):
    """Ревью Codex ветки долга, круг 4: модель разбирает срез A; пока она отвечает, оператор отмечает решение по коду
    B и удаляет клон. Поздняя сверка подставляет сохранённый срез A – подстановка сменой кода не считается (ADR-0072):
    ответ привязан, «Проверено» остаётся, пояснения о смене кода нет (возврат кода к A не установлен)."""
    import app.triage as triage

    pid = analysed(web)
    db = web.app.state.db
    decide(web, pid, "510001", verdict="false_positive", comment="Параметр экранируется.")
    chars = int(db.get_case(pid, "510001")["context"].get("max_chars") or CONTEXT_CHARS)
    real = triage.parse_verdict

    def vanish(obj, ctx):
        with db._tx() as c:  # пока модель отвечала, человек решил по коду B (тот же размер среза)
            c.execute("UPDATE reviews SET reviewed = 1, code_hash = ?, code_chars = ? WHERE project_id = ?"
                      " AND hub_id = ?", ("b" * 64, chars, pid, "510001"))
        if clone(web).exists():
            shutil.rmtree(clone(web))
        return real(obj, ctx)

    monkeypatch.setattr(triage, "parse_verdict", vanish)
    run_id = web.app.state.runner.enqueue(pid, MODEL, "selected", ["510001"], fresh=True)
    assert wait_run(web, run_id)["state"] == "done"
    item = db._all("SELECT state, verdict_id FROM run_items WHERE run_id = ?", (run_id,))[0]
    assert item["state"] == "done" and item["verdict_id"]
    assert reviewed(web, pid, "510001") == 1
    assert db.code_change_notice(pid) is None


def test_file_presence_distinguishes_missing_and_unknown(tmp_path: Path, monkeypatch):
    from app import context
    from app.models import Finding
    from app.triage import _code_file_present

    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "A.java").write_text("class A {}\n", encoding="utf-8")
    context._INDEX_CACHE.clear()
    assert context.file_presence(repo, "src/A.java") == "found"
    assert context.file_presence(repo, "build/app/src/A.java") == "found"  # по окончанию пути
    assert context.file_presence(repo, "src/B.java") == "missing"
    (repo / "other" / "src").mkdir(parents=True)
    (repo / "other" / "src" / "A.java").write_text("class A {}\n", encoding="utf-8")
    context._INDEX_CACHE.clear()
    assert context.file_presence(repo, "build/app/src/A.java") == "unknown"  # два подходящих файла
    f = Finding(hub_id="1", kind="SAST", codebase="x", file="build/app/src/A.java")
    assert _code_file_present(repo, f) is True  # не определить – читается клон, изменения видны
    assert _code_file_present(repo, f, stored_file="src/A.java") is True
    monkeypatch.setattr(context, "MAX_INDEX_FILES", 0)
    context._INDEX_CACHE.clear()
    assert context.file_presence(repo, "src/Missing.java") == "unknown"  # обход неполный
    monkeypatch.undo()
    context._INDEX_CACHE.clear()
    gone = Finding(hub_id="2", kind="SAST", codebase="x", file="src/Gone.java")
    assert _code_file_present(repo, gone, stored_file="src/Gone.java") is False


def test_save_snapshots_upgrades_line_only_slice_when_file_appears(web):
    pid = prepared(web)
    path = clone(web) / INVOICE
    text = path.read_text(encoding="utf-8")
    path.unlink()
    web.client.post(f"/projects/{pid}/snapshots", headers=ORIGIN, follow_redirects=False)
    assert cases(web, pid)["510001"][1] != "ok"
    assert "файл в клоне не найден" in web.client.get(f"/projects/{pid}").text
    path.write_text(text, encoding="utf-8")  # файл нашёлся (например, обход клона в прошлый раз не успел)
    r = web.client.post(f"/projects/{pid}/snapshots", headers=ORIGIN, follow_redirects=False)
    assert "ok=snapshots#step2" in r.headers["location"]
    assert cases(web, pid)["510001"][1] == "ok"


def test_save_snapshots_never_replaces_slice_with_verdict(web):
    pid = analysed(web)
    before = cases(web, pid)
    r = web.client.post(f"/projects/{pid}/snapshots", headers=ORIGIN, follow_redirects=False)
    assert "ok=snapshots_none" in r.headers["location"] and cases(web, pid) == before


def test_change_in_clone_is_seen_at_any_slice_size(web):
    pid = analysed(web)
    db = web.app.state.db
    path = clone(web) / INVOICE
    path.write_text(path.read_text(encoding="utf-8").replace("owner", "owner_id"), encoding="utf-8")
    case, source = db.get_case(pid, "510001"), db.case_input(pid, "510001")
    _, _, now = current_code(web.settings, source, web.app.state.mask_key, 9000, case=case)
    assert now != case["case_hash"]


def test_snapshot_routes_require_same_origin(web):
    pid = prepared(web)
    assert web.client.post(f"/projects/{pid}/snapshots", follow_redirects=False).status_code == 403
    assert web.client.post(f"/projects/{pid}/clones/attach", follow_redirects=False).status_code == 403
    assert cases(web, pid) == {}


def test_question_to_model_after_clone_removal(web):
    pid = analysed(web)
    remove_clone(web)
    url = card_url(web, pid, "510001")
    sent = len(web.fake.chats())
    r = web.client.post(f"{url}/ask", headers=ORIGIN, follow_redirects=False,
                        data={"question": "Откуда берётся owner?", "model": MODEL})
    assert r.status_code == 303, r.text
    assert SQL_LINE in prompt_text(web.fake.chats()[sent:])


# ============================================================================ второй круг ревью

def test_unreadable_code_never_replaces_full_slice_when_model_is_down(web, monkeypatch):
    import app.triage as triage
    from app.models import CodeContext, Finding

    pid = analysed(web)
    decide(web, pid, "510001")
    before = cases(web, pid)

    def unreadable(repo_dir, f, **kw):  # файл на месте, но прочитать его однозначно нельзя
        return CodeContext.from_dict({"status": "file_missing", "file": f.file, "language": f.language,
                                      "lines": [SQL_LINE]})

    monkeypatch.setattr(triage, "build_context", unreadable)
    assert unreadable(None, Finding.from_dict(web.app.state.db.case_input(pid, "510001")["data"])).lines == [SQL_LINE]
    web.fake.close()  # Ollama не отвечает: срезы прогона сверяются с текущим кодом
    run_id = web.app.state.runner.enqueue(pid, MODEL, "all", [], fresh=False)
    wait_run(web, run_id)
    # срез не тронут; файл на месте, а код из него другой – отметка «Проверено» снята, как при смене кода
    assert cases(web, pid) == before and reviewed(web, pid, "510001") == 0


def test_unreadable_code_never_replaces_full_slice_in_run(web, monkeypatch):
    import app.triage as triage
    from app.models import CodeContext

    pid = analysed(web)
    before = cases(web, pid)
    monkeypatch.setattr(triage, "build_context", lambda repo_dir, f, **kw: CodeContext.from_dict(
        {"status": "file_missing", "file": f.file, "language": f.language, "lines": []}))  # и строки выгрузки нет
    run_id = web.app.state.runner.enqueue(pid, MODEL, "selected", ["510001"], fresh=False)
    assert wait_run(web, run_id)["state"] == "done"
    item = web.app.state.db._all("SELECT state, error FROM run_items WHERE run_id = ?", (run_id,))[0]
    assert item["state"] == "skipped" and "Сохранённый срез не изменён" in item["error"]
    assert cases(web, pid) == before


def test_save_snapshots_refused_while_run_is_running(web):
    pid = prepared(web)
    web.fake.delay = 1.5
    run_id = web.app.state.runner.enqueue(pid, MODEL, "selected", ["510001"], fresh=True)
    deadline = time.monotonic() + 10
    while web.app.state.db.get_run(run_id)["state"] != "running" and time.monotonic() < deadline:
        time.sleep(0.05)
    r = web.client.post(f"/projects/{pid}/snapshots", headers=ORIGIN, follow_redirects=False)
    assert r.status_code == 409 and "идёт прогон" in r.text
    web.fake.delay = 0
    wait_run(web, run_id)


def test_automap_protects_snapshots_of_findings_missing_from_export(web):
    pid = analysed(web)
    db = web.app.state.db
    with db._tx() as c:  # новая выгрузка без находок SAST этой кодовой базы: их срезы остались в базе
        c.execute("UPDATE findings SET missing = 1 WHERE project_id = ? AND codebase = 'billing-core'"
                  " AND kind = 'SAST'", (pid,))
    stored = cases(web, pid)
    remove_clone(web)
    (web.tmp / "repos" / "team" / "Billing_Core").mkdir()
    (web.tmp / "repos" / "team" / "Billing_Core" / "pom.xml").write_text("<project/>\n", encoding="utf-8")
    web.client.post(f"/projects/{pid}/codebases", headers=ORIGIN, data={"action": "auto"}, follow_redirects=False)
    assert db.get_codebase_map(pid)["billing-core"]["folder"] == "billing-core" and cases(web, pid) == stored


def test_detach_skipped_when_repos_root_is_not_connected(web):
    pid = analysed(web)
    root = web.tmp / "repos"
    root.rename(web.tmp / "repos-off")  # диск с клонами не подключён
    try:
        sync(web, pid)
        assert web.app.state.db.detached_codebases(pid) == set()
    finally:
        (web.tmp / "repos-off").rename(root)


def test_detached_codebase_with_new_findings_is_flagged(web):
    pid = analysed(web)
    remove_clone(web)
    sync(web, pid)
    db = web.app.state.db
    with db._tx() as c:  # новая находка отвязанной кодовой базы: среза у неё нет
        c.execute("DELETE FROM cases WHERE project_id = ? AND hub_id = '510002'", (pid,))
    step2 = web.client.get(f"/projects/{pid}").text.split('id="step2"')[1].split('id="step3"')[0]
    assert "клон отвязан, без среза: 1" in step2 and 'id="snapshots-detached-none"' in step2
    assert 'id="snapshots-ready"' not in step2 and 'data-confirm="Подключить клоны снова?' in step2


def test_upgrade_button_appears_when_file_is_back(web):
    pid = prepared(web)
    path = clone(web) / INVOICE
    text = path.read_text(encoding="utf-8")
    path.unlink()
    web.client.post(f"/projects/{pid}/snapshots", headers=ORIGIN, follow_redirects=False)
    assert 'id="save-snapshots"' not in web.client.get(f"/projects/{pid}").text  # файла нет – заменять нечем
    path.write_text(text, encoding="utf-8")
    page = web.client.get(f"/projects/{pid}").text
    assert 'id="save-snapshots"' in page and "файл теперь есть в клоне" in page
    web.client.post(f"/projects/{pid}/snapshots", headers=ORIGIN, follow_redirects=False)
    assert cases(web, pid)["510001"][1] == "ok"
    assert 'id="save-snapshots"' not in web.client.get(f"/projects/{pid}").text


def test_codebase_analysed_without_clone_is_not_detached(web):
    """Кодовую базу разбирали без клона (срезы – только строки выгрузки): отвязывать нечего, клоны больше не нужны –
    неправда; подключённый потом клон читается."""
    pid = prepared(web)
    remove_clone(web)
    remove_clone(web, "Catalog_API")
    assert wait_run(web, start_run(web, pid))["state"] == "done"
    stored = cases(web, pid)
    assert stored and all(status != "ok" for _, status, _ in stored.values())
    sync(web, pid)
    assert web.app.state.db.detached_codebases(pid) == set()
    step2 = web.client.get(f"/projects/{pid}").text.split('id="step2"')[1].split('id="step3"')[0]
    assert 'id="snapshots-ready"' not in step2 and 'id="snapshots-no-code"' in step2
    write_repos(web.tmp / "back")
    shutil.copytree(web.tmp / "back" / "team" / "billing-core", clone(web))
    card = web.client.get(card_url(web, pid, "510001")).text
    # клон читается: модель видела строку выгрузки, а в клоне теперь полный код – карточка просит разобрать заново
    assert 'id="code-from-db"' not in card and 'id="code-changed"' in card


# ============================================================================ третий круг ревью

def test_truncated_file_keeps_slice_but_reopens_review(web):
    """Файл находки в клоне укоротили ниже строки срабатывания: срез в базе остаётся, а отметка «Проверено»
    снимается – код под решением уже другой."""
    pid = analysed(web)
    decide(web, pid, "510001")
    before = cases(web, pid)
    path = clone(web) / INVOICE
    path.write_text("\n".join(path.read_text(encoding="utf-8").splitlines()[:10]) + "\n", encoding="utf-8")
    run_id = web.app.state.runner.enqueue(pid, MODEL, "selected", ["510001"], fresh=False)
    assert wait_run(web, run_id)["state"] == "done"
    assert cases(web, pid)["510001"] == before["510001"] and reviewed(web, pid, "510001") == 0
    assert web.app.state.db.code_change_notice(pid)


def test_save_case_refuses_downgrade_inside_transaction(web):
    pid = analysed(web)
    db = web.app.state.db
    case, source = db.get_case(pid, "510001"), db.case_input(pid, "510001")
    worse = {**case["context"], "status": "file_missing", "lines": [SQL_LINE]}
    assert db.save_case(pid, "510001", "0" * 64, worse, None, source, no_downgrade=True) is False
    assert db.get_case(pid, "510001")["case_hash"] == case["case_hash"]
    better = {**case["context"], "lines": case["context"]["lines"] + ["// ещё строка"]}
    assert db.save_case(pid, "510001", "1" * 64, better, None, source, no_downgrade=True) is True


def test_rerun_without_clone_keeps_reviewed_decided_on_other_code(web):
    """Ревью Codex круга 3 (ветка долга 10.11): решение принято по коду B, модель разбирала A, клон удалён – повторный
    разбор берёт сохранённый срез A; подставленный срез сменой кода не считается (ADR-0072), «Проверено» остаётся и
    до ответа модели, и после."""
    pid = analysed(web)
    db = web.app.state.db
    decide(web, pid, "510004", verdict="false_positive", comment="Параметр экранируется.")
    chars = int(db.get_case(pid, "510004")["context"].get("max_chars") or CONTEXT_CHARS)
    with db._tx() as c:  # человек решал по другому коду B (тот же размер среза)
        c.execute("UPDATE reviews SET reviewed = 1, code_hash = ?, code_chars = ? WHERE project_id = ? AND hub_id = ?",
                  ("b" * 64, chars, pid, "510004"))
    remove_clone(web, "Catalog_API")
    run_id = web.app.state.runner.enqueue(pid, MODEL, "selected", ["510004"], fresh=True)
    assert wait_run(web, run_id)["state"] == "done"
    assert reviewed(web, pid, "510004") == 1
    assert db.code_change_notice(pid) is None
