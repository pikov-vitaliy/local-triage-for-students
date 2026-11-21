"""Раздел «Где исправлять» в тексте дефекта и предупреждение о строках по срезам всех находок (план dev7, раздел 11; ADR-0134).
Данные выдуманы, сети нет."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from app import defect, defect_check, defect_local_text, defect_where, hub_defects
from app.db import text_hash
from app.models import Finding
from app.routes import findings as card
from test_hub_block_builder import sast_model
from test_hub_block_dev30 import BLOCK as DEV30_BLOCK
from test_hub_blank_update_dev31 import TEXT, blank_job, no_block_row, start
from test_hub_defect_update import assemble, deliver, hub_body, note, phase, put_click, read_job, sent_body, tab, take
from test_hub_defects import create, hello, hub_job, sast_ready, to_preview
from test_hub_block_version import BLANK, LINKS, SERVICE, UPD, blank, hub_settings, post_package, prepared, sca_text_ready
from test_web import web  # noqa: F401

COMMIT, OTHER = "a" * 40, "b" * 40
REPO = "https://git.example.test/group/api"
LINK = {"id": 510001, "type": "SAST", "commitLink": f"{REPO}/-/commit/{COMMIT}", "lastScanTs": 1793923200000,
        "scanObject": {"id": 1, "name": "api-scan", "type": "git"}}
STATE = {"detail": {"currentBranch": "develop", "fileName": "src/a.py", "codebase": {"name": "api"}}}
WHERE = defect_where.section([defect_where.place_of(LINK, STATE, None)])


def with_links(**extra) -> dict:
    return {**hub_body(description=hub_defects.command_html(TEXT), **extra), "linkedIssues": [LINK]}


def accepted_state(web, pid: int, issue_id: str = "510001", state: dict | None = None) -> None:
    """Подробное чтение находки, как его принимает синхронизация."""
    db = web.app.state.db
    with db._tx() as c:
        row = c.execute("SELECT hub_url, app_id FROM hub_defects WHERE project_id = ? LIMIT 1", (pid,)).fetchone()
        c.execute("INSERT INTO hub_issue_states(project_id, hub_url, app_id, issue_type, issue_id, confirmed_json, confirmed_presence)"
                  " VALUES (?, ?, ?, 'SAST', ?, ?, 'present')",
                  (pid, hub_defects.hub_ops.hub_base(row[0]), row[1], issue_id, hub_defects.dumps(state or STATE)))


# ============================================================================ чистые правила


def test_section_lists_everything_the_developers_need():
    assert WHERE == ("Где исправлять:\nКодовая база: api\n" f"Репозиторий: {REPO}\nВетка: develop\nКоммит: {COMMIT}\n"
                     "Объект сканирования: api-scan\nДата сканирования: 06.11.2026 00:00 UTC\nФайлы: src/a.py")


def test_several_commits_and_branches_are_all_listed_by_codebase():
    places = [defect_where.place_of({**LINK, "commitLink": f"{REPO}/-/commit/{commit}"},
                                    {"detail": {**STATE["detail"], "currentBranch": branch, "fileName": name}}, None)
              for commit, branch, name in ((COMMIT, "develop", "b.py"), (COMMIT, "develop", "a.py"), (OTHER, "develop", "c.py"), (OTHER, "release", "d.py"))]
    text = defect_where.section(places)
    assert text.count("Кодовая база: api") == 3 and text.count(COMMIT) == 1 and text.count(OTHER) == 2
    assert "Файлы: a.py, b.py" in text and "Ветка: release" in text


@pytest.mark.parametrize("name, shown", [(" : demo-lib : 1.2.3", "demo-lib : 1.2.3"), (": demo-lib : 1.2.3", "demo-lib : 1.2.3"),
                                         ("package-lock.json : demo-lib : 1.2.3", "package-lock.json : demo-lib : 1.2.3"),
                                         ("src/a.py", "src/a.py"), (" : ", "")])
def test_sca_file_name_with_empty_path_does_not_start_with_colon(name, shown):
    """У находки SCA без пути манифеста строка не начинается с двоеточия: не «Файлы: : компонент : версия»."""
    place = defect_where.place_of(LINK, {"detail": {**STATE["detail"], "fileName": name}}, None)
    assert place["file"] == shown
    text = defect_where.section([place])
    assert ("Файлы: " + shown in text) if shown else ("Файлы:" not in text)
    assert "Файлы: :" not in text


def test_nothing_from_hub_means_no_section():
    assert defect_where.section([defect_where.place_of({"id": 1, "type": "SAST"}, None, {"codebase": "api", "file": "a.py"})]) == ""
    assert defect_where.section([]) == ""


def test_missing_values_are_named_not_guessed():
    text = defect_where.section([defect_where.place_of({"id": 1, "commitLink": f"{REPO}/commit/{COMMIT}"}, None, None)])
    assert "Кодовая база: не указана" in text and "Ветка: не указана" in text and f"Коммит: {COMMIT}" in text
    odd = defect_where.place_of({"id": 1, "commitLink": "ревизия 15"}, None, None)
    assert odd["commit"] == "ревизия 15" and odd["repository"] == ""


@pytest.mark.parametrize("head", ["Где исправлять:", "Где исправлять", "  где исправлять : "])
def test_split_finds_section_written_by_hand(head):
    body, section = defect_where.split(f"Текст.\n\n{head}\nВетка: develop\n")
    assert body == "Текст." and section.endswith("Ветка: develop") and section.splitlines()[0].strip().lower().startswith("где исправлять")


def test_subheading_inside_reason_is_not_a_section():
    """Подзаголовок с тем же названием в обосновании: текст проверяется целиком, и настоящая рекомендация не теряется."""
    phrase = defect.sast_phrase("Команда")
    good = (f"{phrase}\n\nОбоснование:\nДанные из запроса.\nГде исправлять:\nв модуле api.\n\nРекомендация:\n1) Параметризовать запрос.")
    assert defect_where.split(good) == (good, "")
    assert defect_check.sast_problems(good, team_phrase=phrase) == []
    assert defect_where.split(defect_where.join(good, WHERE))[1] == WHERE, "последний заголовок – настоящий раздел"


@pytest.mark.parametrize("tail", ["Рекомендация:\n1) Добавить тест", "Добавить тест", "1) Добавить тест: в конвейер", "Рекомендация: добавить тест"])
def test_template_lines_cannot_hide_behind_section_head(tail):
    phrase = defect.sast_phrase("Команда")
    text = f"{phrase}\n\nОбоснование:\nДанные.\n\nРекомендация:\n1) Параметризовать.\nГде исправлять:\n{tail}"
    assert defect_where.split(text) == (text, "")
    assert defect_check.sast_problems(text, team_phrase=phrase) != [] or "Рекомендация" not in tail


def test_body_of_keeps_text_without_section_as_is():
    assert defect_where.split("Текст.\r\n") == ("Текст.\r\n", "")
    assert defect_where.body_of("Текст.\n") == "Текст."
    assert defect_where.body_of(defect_where.join("Текст.", WHERE)) == "Текст."


def test_split_without_section_and_mention_inside_a_sentence():
    assert defect_where.split("Где исправлять: в модуле api.") == ("Где исправлять: в модуле api.", "")
    assert defect_where.join("Текст.", "") == "Текст." and defect_where.join("", WHERE) == WHERE


def test_section_has_no_hub_boundary_and_survives_round_trip():
    text = defect_where.join(TEXT, WHERE)
    html = hub_defects.command_html(text)
    assert hub_defects.IMPORT_BOUNDARY not in hub_defects.description_lines(html)
    assert hub_defects.split_description(html)[0] == text


def test_team_format_check_looks_at_text_before_section():
    phrase = defect.sast_phrase("Команда")
    good = f"{phrase}\n\nОбоснование:\nДанные из запроса.\n\nРекомендация:\n1) Параметризовать запрос."
    assert defect_check.sast_problems(good, team_phrase=phrase) == []
    assert defect_check.sast_problems(defect_where.join(good, WHERE), team_phrase=phrase) == []
    assert defect_check.sast_problems(defect_where.join("Обоснование:", WHERE), team_phrase=phrase) != []


# ============================================================================ Push


def test_push_without_block_adds_section_and_it_stays_in_the_draft(web):
    pid, row = no_block_row(web, TEXT + " Правка.")
    db = web.app.state.db
    accepted_state(web, pid)
    start(web, pid, row, with_links())
    blank_job(web, status=500, body={}, error="Hub ответил кодом 500")
    page = tab(web, pid)
    state = hub_defects.update_state(db.hub_defect(row["id"]))
    assert state["phase"] == "preview", note(db, row["id"])
    assert state["where_added"] is True and state["new"]["command_text"] == defect_where.join(TEXT + " Правка.", WHERE)
    assert f'id="hub-update-where-{row["id"]}"' in page and f"Коммит: {COMMIT}" in page and "develop" in page
    assert put_click(web, pid, row).status_code == 200, "тот же текст в «Push в Hub» – подпись подготовки сходится"
    read_job(web, with_links())
    put = take(web)
    assert put is not None and put["method"] == "PUT", (put, note(db, row["id"]))
    assert put["body"]["description"] == hub_defects.command_html(defect_where.join(TEXT + " Правка.", WHERE))
    deliver(web, put, 204, text="")
    read_job(web, {**sent_body(db, row["id"]), "linkedIssues": [LINK]})
    assert phase(db, row["id"]) == "done", note(db, row["id"])
    assert db.hub_defect(row["id"])["draft_command_text"] == defect_where.join(TEXT + " Правка.", WHERE)


def test_second_push_does_not_duplicate_section(web):
    pid, row = no_block_row(web, defect_where.join(TEXT, WHERE))
    db = web.app.state.db
    accepted_state(web, pid)
    written = hub_defects.command_html(defect_where.join(TEXT, WHERE))
    body = {**hub_body(description=written), "linkedIssues": [LINK]}
    start(web, pid, row, body)
    # заготовку Hub не выдаст, блок собирается из данных находки (ADR-0139); чтение не удалось – правок по-прежнему нет
    job = take(web)
    assert job["path"].startswith("/templates/defects/model?"), job["path"]
    deliver(web, job, 500, {}, error="Hub 500")
    assert take(web) is None
    tab(web, pid)
    state = hub_defects.update_state(db.hub_defect(row["id"]))
    assert state["phase"] == "cancelled" and state["note"].startswith("Изменений для отправки нет"), state
    assert not state.get("blank_tried") and defect_where.has_head(db.hub_defect(row["id"])["draft_command_text"])


def test_free_form_section_is_not_doubled(web):
    mine = "Где исправлять:\nв ветке release, модуль api"
    pid, row = no_block_row(web, defect_where.join(TEXT, mine))
    db = web.app.state.db
    accepted_state(web, pid)
    start(web, pid, row, with_links())
    deliver(web, take(web), 200, sast_model())
    tab(web, pid)
    state = hub_defects.update_state(db.hub_defect(row["id"]))
    # свободную форму приложение не разбирает: остаётся как есть, рядом добавляется блок
    assert state["new"]["command_text"] == defect_where.join(TEXT, mine) and state["block_mode"] == "added"
    assert hub_defects.WHERE_WITH_BLOCK in state["warnings"]


def test_own_section_is_kept_and_difference_is_a_warning(web):
    mine = "Где исправлять:\nВетка: release, правка оператора"
    pid, row = no_block_row(web, defect_where.join(TEXT, mine))
    db = web.app.state.db
    accepted_state(web, pid)
    start(web, pid, row, with_links())
    deliver(web, take(web), 500, {}, error="Hub 500")  # блока нет – раздел оператора остаётся
    tab(web, pid)
    state = hub_defects.update_state(db.hub_defect(row["id"]))
    assert state["phase"] == "preview" and not state.get("where_added")
    assert state["new"]["command_text"] == defect_where.join(TEXT, mine)
    assert hub_defects.WHERE_DIFFERS in state["warnings"]


def test_block_from_blank_means_no_section(web):
    pid, row = no_block_row(web)
    db = web.app.state.db
    accepted_state(web, pid)
    start(web, pid, row, with_links())
    blank_job(web)
    tab(web, pid)
    state = hub_defects.update_state(db.hub_defect(row["id"]))
    assert state["phase"] == "preview" and state["block_mode"] == "added", state
    assert "Где исправлять" not in state["new"]["command_text"] and not state.get("where_added")


def test_hub_without_commit_and_branch_changes_nothing(web):
    pid, row = no_block_row(web, TEXT + " Правка.")
    db = web.app.state.db
    start(web, pid, row)
    blank_job(web, status=500, body={}, error="Hub ответил кодом 500")
    tab(web, pid)
    state = hub_defects.update_state(db.hub_defect(row["id"]))
    assert state["new"]["command_text"] == TEXT + " Правка.", "старые ответы без commitLink и ветки"


def test_text_from_decisions_keeps_section(web):
    pid, row = no_block_row(web, defect_where.join(TEXT, WHERE))
    db = web.app.state.db
    response = assemble(web, pid, db.hub_defect(row["id"]))
    assert response.status_code < 400, response.text
    draft = db.hub_defect(row["id"])["draft_command_text"]
    body, section = defect_where.split(draft)
    assert section == WHERE, draft
    assert TEXT not in body and body.startswith("После тщательного анализа"), draft


def test_text_from_decisions_keeps_free_form_section_and_drops_subheading(web):
    free = "Где исправлять:\nв ветке release, модуль api"
    pid, row = no_block_row(web, defect_where.join(TEXT, free))
    db = web.app.state.db
    assert assemble(web, pid, db.hub_defect(row["id"])).status_code < 400
    draft = db.hub_defect(row["id"])["draft_command_text"]
    assert draft.endswith(free) and draft.startswith("После тщательного анализа"), draft
    assert defect_where.own_tail("Обоснование:\nГде исправлять:\nв api\nРекомендация:\n1) Правка.") == ""


@pytest.mark.parametrize("old", ["Объяснение:\nГде исправлять:\nдовод\nРекомендации:\n1) Прежнее.\nИсточники:\nx",
                                 "Объяснение\nГде исправлять:\nдовод\nРекомендации\n1) Прежнее.\nИсточники\nx"])
def test_old_explanation_is_not_carried_over(old):
    assert defect_where.own_tail(old) == ""


def test_section_in_rebuilt_text_is_not_doubled(monkeypatch):
    """Заголовок пришёл в собранный текст из комментария к решению: второй экземпляр не дописывается и при повторной сборке."""
    built = "Находка 1:\nГде исправлять:\nв модуле api"
    monkeypatch.setattr(defect_local_text, "_from_decisions", lambda request, row: {"command_text": built, "refusals": []})
    once = defect_local_text.generate(None, {"draft_command_text": ""})["command_text"]
    twice = defect_local_text.generate(None, {"draft_command_text": once})["command_text"]
    assert once == built and twice == built


def test_shown_lines_are_collected_once_per_preparation(web, monkeypatch):
    pid, row = no_block_row(web)
    db = web.app.state.db
    calls = []
    real = card.defect_shown_lines
    monkeypatch.setattr(card, "defect_shown_lines", lambda *a, **k: calls.append(a) or real(*a, **k))
    with db._tx() as c:
        targets = hub_defects.loads(row["targets_json"], [])
        c.execute("UPDATE hub_defects SET targets_json = ? WHERE id = ?", (hub_defects.dumps(targets * 5), row["id"]))
    assert assemble(web, pid, db.hub_defect(row["id"])).status_code < 500
    assert len(calls) <= 2, calls  # подготовка за действие – не больше двух, по одному обходу, а не по разу на цель


# ============================================================================ создание


def test_create_with_empty_blank_sends_section(web):
    pid, url = sast_ready(web)
    db = web.app.state.db
    hello(web)
    row = to_preview(web, pid, url, blank_body={"summary": "заготовка", "description": "", "priority": {"name": "Major", "rank": 2},
                                                "severity": {"name": "Medium", "rank": 2}, "linkedIssues": [LINK]})
    assert defect_where.split(row["command_text"])[1], row["command_text"]
    page = web.client.get(f"/projects/{pid}/defects/{row.get('draft_owner_id') or row['id']}").text
    assert 'id="hub-defect-where"' in page and f"Коммит: {COMMIT}" in page
    assert create(web, pid, row["id"], priority="Critical").status_code == 200
    job = hub_job(web, body={"id": 555})
    assert COMMIT in job["body"]["description"], job["body"]["description"]
    hub_job(web, body={"id": 555, "summary": row["summary"], "linkedIssues": [LINK], "description": job["body"]["description"]})
    fresh = db.hub_defect(row["id"])
    assert fresh["state"] == "done", fresh["error"]
    assert fresh["draft_command_text"] == row["command_text"]


def test_create_sca_with_empty_blank_is_not_refused(web):
    """Текст набора сравнивается с генератором без раздела: неизменившийся набор не «изменился»."""
    pid = prepared(web)
    db = web.app.state.db
    hub_settings(web, pid)
    assert post_package(web, pid, "73001", ["73001", "73002"], **UPD).status_code == 200
    url = f"/projects/{pid}/sca/findings/{db.get_finding_by_hub_id(pid, '73001')['id']}"
    sca_text_ready(web, url)
    assert blank(web, url).status_code == 200
    links = [{**LINK, "id": int(i), "type": t["type"]} for i, t in (("73001", LINKS[0]), ("73002", LINKS[1]))]
    hub_job(web, body={**BLANK, "description": "", "linkedIssues": links})
    hub_job(web, body=SERVICE)
    row = db.hub_defects(pid)[0]
    assert row["state"] == "preview" and defect_where.split(row["command_text"])[1], row["command_text"]
    answer = create(web, pid, row["id"])
    assert answer.status_code == 200, answer.text[:600]
    job = hub_job(web, body={"id": 900})
    assert COMMIT in job["body"]["description"]


def test_neighbor_links_to_defect_whose_text_has_section(web):
    """Дефект с разделом и соседняя находка с тем же решением: второй дефект не создаётся, а привязка возможна – сравнивается
    текст решения. Проверка транзакции привязки сравнивает так же."""
    db = web.app.state.db
    assert text_hash(defect_where.body_of(defect_where.join(TEXT, WHERE))) == text_hash(TEXT)
    pid, row = no_block_row(web)
    with db._tx() as c:
        c.execute("UPDATE hub_defects SET command_text = ?, state = 'done', hub_defect_id = '777', origin = 'app' WHERE id = ?",
                  (defect_where.join(TEXT, WHERE), row["id"]))
    with pytest.raises(ValueError, match="изменился"):
        db.hub_defect_link_start(pid, row["id"], "777", item={}, body_hash="другой текст")
    try:
        db.hub_defect_link_start(pid, row["id"], "777", item={}, body_hash=text_hash(TEXT))
    except Exception as exc:  # дальше проверки операции; сверка текста решения пройдена
        assert "изменился" not in str(exc), exc


def test_create_with_block_in_blank_has_no_section(web):
    pid, url = sast_ready(web)
    hello(web)
    row = to_preview(web, pid, url, blank_body={"summary": "заготовка", "description": DEV30_BLOCK, "priority": {"name": "Major", "rank": 2},
                                                "severity": {"name": "Medium", "rank": 2}, "linkedIssues": [LINK]})
    assert "Где исправлять" not in row["command_text"]


# ============================================================================ предупреждение о строках


def fake_request(targets: list[str], monkeypatch) -> SimpleNamespace:
    lines = {"1": {10, 11}, "2": {50, 51}, "3": {90}}
    monkeypatch.setattr(card, "shown_lines", lambda request, pid, f, case: lines[f.hub_id])
    # семья из двух физических строк: последовательная привязка
    family = [{"targets_json": hub_defects.dumps([{"hub_id": t} for t in targets[:1]])}, {"targets_json": hub_defects.dumps([{"hub_id": t} for t in targets[1:]])}]
    monkeypatch.setattr(card.defect_drafts, "family_in", lambda c, row: family)
    db = SimpleNamespace(
        hub_defect_bound=lambda pid, hub_id: family[0] if targets else None, on_connection=lambda work: work(None),
        get_finding_by_hub_id=lambda pid, hub_id: {"kind": "SAST", "data": Finding(hub_id=hub_id, kind="SAST").to_dict()},
        get_case=lambda pid, hub_id: None)
    return SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(db=db)))


def test_lines_are_checked_against_all_findings_of_the_defect(monkeypatch):
    f = Finding(hub_id="1", kind="SAST")
    together = card.defect_shown_lines(fake_request(["1", "2", "3"], monkeypatch), 1, f, None)
    assert together == {10, 11, 50, 51, 90}
    assert card.line_warnings("Значение из строки 50.", "", together) == []
    assert card.line_warnings("Значение из строки 999.", "", together), "строки нет ни в одном срезе – предупреждение остаётся"


def test_finding_without_defect_is_checked_against_its_own_lines(monkeypatch):
    f = Finding(hub_id="1", kind="SAST")
    alone = card.defect_shown_lines(fake_request([], monkeypatch), 1, f, None)
    assert alone == {10, 11}
    assert card.line_warnings("Значение из строки 50.", "", alone)
    assert card.defect_shown_lines(fake_request([], monkeypatch), 1, f, None, own=set()) is None, "кода нет – как раньше"
