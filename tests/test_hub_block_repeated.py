"""Повторённый служебный блок в описании дефекта (ADR-0137). Данные выдуманы, сети нет."""

from __future__ import annotations

import json

import pytest

from app import defect_drafts, hub_block_version, hub_defects
from test_defect import save_sast
from test_defect_add import OTHER_REASON, add_now, link_row
from test_hub_defect_import import apply_sync, deliver, sync, take
from test_hub_defect_update import hub_body, phase, put_click, read_job, ready, sent_body, to_preview as update_preview
from test_hub_defects import FIX, hello, hub_job
from test_web import web  # noqa: F401

BOUNDARY = "<p>Информация об объекте сканирования:</p>"
FIRST = BOUNDARY + "<p>Первый блок: ветка main</p>"
SECOND = BOUNDARY + "<p>Второй блок: ветка develop</p>"
TEXT = "<p>Текст дефекта.</p>"


def test_text_is_above_the_first_boundary():
    text, lines, note = hub_defects.split_description(TEXT + FIRST + SECOND)
    assert text == "Текст дефекта." and note == "" and "Второй блок: ветка develop" in lines
    assert hub_defects.split_description(TEXT + FIRST + SECOND, repeated=False)[2], "своя запись – строго"
    assert hub_defects.split_at_hub_block(TEXT + FIRST + SECOND)[2], "по умолчанию строго"


def test_block_is_everything_below_the_first_boundary_byte_for_byte():
    assert hub_defects.hub_block(TEXT + FIRST + SECOND) == (FIRST + SECOND, "")
    assert hub_defects.hub_block(TEXT + FIRST) == (FIRST, "")
    assert hub_defects.block_repeated(TEXT + FIRST + SECOND) and not hub_defects.block_repeated(TEXT + FIRST)


def test_first_boundary_split_across_elements_does_not_fall_to_the_second():
    first = "<span>Информация об </span><span>объекте сканирования:</span><p>Первый блок</p>"
    assert hub_defects.block_repeated(TEXT + first + SECOND)
    block, problem = hub_defects.hub_block(TEXT + first + SECOND)
    assert block == "" and "не выделяется" in problem, "первый блок не теряется молча"


def test_same_blocks_stay_visible_when_reading_foreign_description():
    lines = hub_defects.split_description(TEXT + FIRST + FIRST)[1]
    assert lines.count("Информация об объекте сканирования:") == 1 and lines.count("Первый блок: ветка main") == 2
    assert hub_defects.split_at_hub_block(TEXT + FIRST + FIRST)[2] == "", "своя запись: Hub дописал то же"


def test_second_block_number_is_only_a_hint():
    numbers = hub_defects._read_of(hub_body(description=TEXT + FIRST + BOUNDARY + "<p>ID: 510077</p>"))["hub_numbers"]
    assert "510077" in numbers


def test_glued_first_block_is_still_refused():
    assert "склеен" in hub_defects.hub_block("<p>Текст<br>Информация об объекте сканирования:<br>а</p>" + SECOND)[1]


def test_sca_version_is_replaced_in_both_blocks():
    block = BOUNDARY + "<p>Версия исправления: 1.0</p>" + BOUNDARY + "<p>Версия исправления: 2.0</p>"
    got = hub_block_version.retarget(block, "3.0")
    assert got.places == 2 and got.block.count("Версия исправления: 3.0") == 2


def two_blocks(links=((510001, "SAST"),)) -> dict:
    return hub_body(links=links, description=TEXT + FIRST + SECOND)


def test_pull_apply_and_push_keep_both_blocks(web):
    pid, row = ready(web, build=False)
    db = web.app.state.db
    hello(web)
    assert sync(web, pid, row["id"]).status_code == 200
    read_job(web, two_blocks())
    page = web.client.get(f"/projects/{pid}/defects/{row['id']}").text
    assert "встречается больше одного раза" in page
    assert apply_sync(web, pid, row["id"]).status_code == 200, "«Применить» проходит"
    owner = db.hub_defect(row["id"])
    assert owner["command_text"] == "Текст дефекта." and owner["draft_command_text"] == "Текст дефекта."
    assert sync(web, pid, row["id"]).status_code == 200
    read_job(web, two_blocks())
    assert json.loads(db.hub_defect(row["id"])["sync_json"]).get("matches") is True, "повторный Pull совпадает"
    # Push: текст новый, оба блока байт в байт, подтверждение проходит
    owner = defect_drafts.save(db, db.hub_defect(row["id"]), str(db.hub_defect(row["id"])["draft_revision"]), summary=owner["draft_summary"], command="Новый текст дефекта.")
    update_preview(web, pid, owner, two_blocks())
    preview = db.hub_defect(row["id"])
    assert phase(db, row["id"]) == "preview", hub_defects.update_state(preview)
    assert hub_defects.BLOCK_REPEATED in hub_defects.update_state(preview)["warnings"]
    assert put_click(web, pid, preview).status_code == 200
    read_job(web, two_blocks())
    put = take(web)
    assert put["method"] == "PUT" and put["body"]["description"].endswith(FIRST + SECOND)
    assert "Новый текст дефекта." in put["body"]["description"]
    deliver(web, put, 204, text="")
    read_job(web, sent_body(db, row["id"]))
    assert phase(db, row["id"]) == "done", hub_defects.update_state(db.hub_defect(row["id"]))


def test_repeated_block_with_other_text_conflicts_with_unsent_edit(web):
    pid, row = ready(web, build=False)
    db = web.app.state.db
    edited = defect_drafts.save(db, row, str(row["draft_revision"]), summary=row["summary"], command=row["draft_command_text"] + "\nПравка оператора.")
    assert sync(web, pid, row["id"]).status_code == 200
    read_job(web, two_blocks())
    before = db.hub_defect(row["id"])
    assert apply_sync(web, pid, row["id"]).status_code == 409, "текст изменён с двух сторон"
    fresh = db.hub_defect(row["id"])
    assert fresh == before and fresh["draft_command_text"] == edited["draft_command_text"]


def test_push_of_one_block_answered_with_two_is_not_confirmed(web):
    """Строгость сверки своей записи: Hub вернул второй другой блок, которого приложение не отправляло."""
    pid, row = ready(web, build=True)
    db = web.app.state.db
    update_preview(web, pid, row)
    assert put_click(web, pid, db.hub_defect(row["id"])).status_code == 200
    read_job(web)
    put = take(web)
    assert not hub_defects.block_repeated(put["body"]["description"])
    deliver(web, put, 204, text="")
    answer = sent_body(db, row["id"])
    answer["description"] += SECOND
    read_job(web, answer)
    assert phase(db, row["id"]) == "unconfirmed", hub_defects.update_state(db.hub_defect(row["id"]))
    assert not db.get_review(pid, "510001")["entered_hub"]


def test_link_to_a_defect_with_repeated_block_is_confirmed(web):
    pid, row = ready(web, build=False)
    db = web.app.state.db
    hello(web)
    assert sync(web, pid, row["id"]).status_code == 200
    read_job(web, two_blocks())
    assert apply_sync(web, pid, row["id"]).status_code == 200
    save_sast(web, pid, "510002", "true_positive", "", OTHER_REASON, FIX)
    add_now(web, pid, db.hub_defect(row["id"]))
    assert hub_job(web, body={})["path"] == "/defects/777/link"
    read_job(web, two_blocks(links=((510001, "SAST"), (510002, "SAST"))))
    bound = link_row(db, pid)
    assert bound["state"] == "done", bound["error"]
    assert db.get_review(pid, "510002")["entered_hub"] == 1


@pytest.mark.parametrize("description", [FIRST + SECOND])
def test_creation_answered_with_two_different_blocks_is_not_confirmed(web, description):
    from test_hub_defects import create, sast_ready, to_preview
    pid, url = sast_ready(web)
    db = web.app.state.db
    row = to_preview(web, pid, url)
    create(web, pid, row["id"])
    hub_job(web, body={"id": 555})
    hub_job(web, body={"id": 555, "appId": 7, "summary": row["summary"], "description": TEXT + description, "linkedIssues": [{"id": 510001, "type": "SAST"}]})
    current = db.hub_defect(row["id"])
    assert current["state"] == "unknown" and "текст команды не выделен" in current["error"]
    assert not current["confirm_op_id"] and not db.get_review(pid, "510001")["entered_hub"]
