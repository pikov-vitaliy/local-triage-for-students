"""Единая версия в служебном блоке Hub у дефектов SCA и описание, синхронизируемое целиком (ADR-0132, 0.10.0.dev7)."""

from __future__ import annotations

import json

import pytest

from app import hub_block_version as hbv
from app import hub_defects
from test_hub_defect_import import apply_sync, deliver, sync, tab
from test_hub_defect_update import act, form_fields, hub_body, note, phase, put_click, read_job, sca_ready, sent_body, to_preview
from test_hub_defects import AS_JSON, BLANK, SERVICE, blank, create, hub_job, hub_settings, no_job
from test_sca import sca_text_ready
from test_sca_package_decision import UPD, post_package
from test_web import prepared, web  # noqa: F401

TABLE = ("<table><tbody><tr><th>ID</th><th>Компонент</th><th>Версия исправления</th></tr>"
         "<tr><td><a href=\"https://hub.example/1.0\">73001</a></td><td>pkg:demo</td><td>1.0</td></tr>"
         "<tr><td>73002</td><td>pkg:demo</td><td>1.0</td></tr></tbody></table>")
ONE = "<p>Компонент: pkg:demo</p><p>Версия исправления: 1.0</p>"
DETAIL = ("<p><strong>Рекомендации</strong></p><p>Обновление demo до версии 1.0</p>"
          "<p><strong>Источники</strong></p><p><a href=\"https://repo.example/demo-1.0.pom\">demo-1.0.pom</a></p>")
BLOCK = "<h3>Информация об объекте сканирования:</h3>" + TABLE + DETAIL


def test_all_forms_are_replaced_and_links_stay():
    got = hbv.retarget(BLOCK, "2.5")
    assert got.places == 3 and got.previous == ("1.0",) and got.target == "2.5"
    assert got.block.count("<td>2.5</td>") == 2 and "Обновление demo до версии 2.5" in got.block
    assert 'href="https://hub.example/1.0"' in got.block, "ссылка в другой колонке не меняется"
    assert "demo-1.0.pom" in got.block, "номер версии в имени файла – не значение версии"
    alone = hbv.retarget(ONE, "2.5")
    assert alone.places == 1 and "<p>Версия исправления: 2.5</p>" in alone.block
    assert "<p>Компонент: pkg:demo</p>" in alone.block


def test_second_call_changes_nothing():
    first = hbv.retarget(BLOCK, "2.5")
    second = hbv.retarget(first.block, "2.5")
    assert second.places == 0 and second.block == first.block and second.view() == {}


def test_link_inside_replaced_cell_keeps_its_address():
    block = '<table><tr><th>Версия исправления</th></tr><tr><td> <a href="https://example.org/1.0">1.0</a> </td></tr></table>'
    got = hbv.retarget(block, "22.333")
    assert got.places == 1
    assert got.block == '<table><tr><th>Версия исправления</th></tr><tr><td> <a href="https://example.org/1.0">22.333</a> </td></tr></table>'


def test_nested_paragraph_in_a_cell_is_replaced_once_and_html_stays_whole():
    block = "<table><tr><th>Версия исправления</th></tr><tr><td><p>Версия исправления: 1.0</p></td></tr></table>"
    got = hbv.retarget(block, "22.333")
    assert got.places == 1
    assert got.block == "<table><tr><th>Версия исправления</th></tr><tr><td><p>Версия исправления: 22.333</p></td></tr></table>"
    assert hbv.retarget(got.block, "22.333").places == 0


def test_field_value_table_form():
    block = "<table><tr><th>Компонент</th><td>demo</td></tr><tr><th>Версия исправления</th><td>1.0</td></tr><tr><th>Ветка</th><td>master</td></tr></table>"
    got = hbv.retarget(block, "2.0")
    assert got.places == 1 and "<th>Версия исправления</th><td>2.0</td>" in got.block
    assert "<th>Ветка</th><td>master</td>" in got.block


def test_empty_value_is_filled():
    block = "<table><tr><th>Версия исправления</th></tr><tr><td></td></tr></table>"
    got = hbv.retarget(block, "2.0")
    assert got.places == 1 and "<td>2.0</td>" in got.block and got.previous == ()


@pytest.mark.parametrize("paragraph, expected", [
    ("<p>Обновление demo до версии </p>", "<p>Обновление demo до версии 2.0</p>"),
    ("<p>Обновление demo до версии</p>", "<p>Обновление demo до версии 2.0</p>"),
    ("<p>Версия исправления: </p>", "<p>Версия исправления: 2.0</p>"),
])
def test_empty_recommendation_paragraph_is_filled(paragraph, expected):
    """Hub не знает версии исправления – в рекомендации находки «до версии » без номера. Целевая версия вписывается и туда,
    иначе в блоке остаётся рекомендация без версии рядом со сводкой, где версия уже стоит."""
    block = ("<table><tr><th>Версия исправления</th></tr><tr><td></td></tr></table>"
             f"<p><strong>Рекомендации</strong></p>\n{paragraph}\n<p><strong>Источники</strong></p>")
    got = hbv.retarget(block, "2.0")
    assert expected in got.block and "<td>2.0</td>" in got.block and got.places == 2 and got.notes == ()
    assert hbv.retarget(got.block, "2.0").places == 0
    assert hbv.masked(got.block) == hbv.masked(block), "заполненный и исходный пустой блок различаются только версией"


@pytest.mark.parametrize("paragraph, shown", [
    ("<p>Обновление demo до версии<br>1.0</p>", "1.0"),
    ("<p>Обновление demo до версии<br><b>1.0</b></p>", "1.0"),
    ("<p>Обновление demo до версии<br>V1.0</p>", "V1.0"),
    ("<p>Обновление demo до версии<br>release-1.0 (LTS)</p>", "release-1.0"),
    ("<p>Обновление demo до версии <br><span>RELEASE_1_0</span></p>", "RELEASE_1_0"),
])
def test_text_after_break_is_not_taken_for_empty(paragraph, shown):
    """За пустым значением в том же абзаце есть текст: это может быть само значение, вставка оставила бы в рекомендации две
    версии – абзац не трогается, оператор видит пометку."""
    got = hbv.retarget(paragraph, "2.0")
    assert got.block == paragraph and got.places == 0 and got.notes and shown in got.notes[0]


def test_heading_and_empty_recommendation_in_one_paragraph_is_filled():
    """Hub соединил «Рекомендации» и пустую рекомендацию в один абзац: за переносом не версия – значение пустое, вписывается."""
    got = hbv.retarget("<p>Рекомендации<br>Обновление demo до версии </p>", "2.0")
    assert got.block == "<p>Рекомендации<br>Обновление demo до версии 2.0</p>" and got.places == 1


def test_glue_is_decided_by_visible_text():
    """Последняя буква записана сущностью: пробел перед номером нужен, хотя в разметке перед местом вставки «;»."""
    block = "<p>Обновление demo до верси&#1080;</p>"
    got = hbv.retarget(block, "2.0")
    assert got.block == "<p>Обновление demo до верси&#1080; 2.0</p>" and got.places == 1
    assert hbv.retarget(got.block, "2.0").places == 0 and hbv.masked(got.block) == hbv.masked(block)
    spaced = "<p>Обновление demo до версии&nbsp;</p>"
    assert hbv.retarget(spaced, "2.0").block == "<p>Обновление demo до версии&nbsp;2.0</p>"


@pytest.mark.parametrize("filled, empty", [
    ("<p>Версия исправления:2.0</p>", "<p>Версия исправления:</p>"),
    ("<p>Версия исправления: 2.0</p>", "<p>Версия исправления: </p>"),
    ("<p>Обновление demo до версии 2.0</p>", "<p>Обновление demo до версии</p>"),
    ("<p>Обновление demo до версии 2.0</p>", "<p>Обновление demo до версии </p>"),
])
def test_previously_filled_form_masks_like_empty_one(filled, empty):
    """Ранее записанная форма и пустая заготовка, которую Hub может дописать второй раз, совпадают без значения версии."""
    assert hbv.masked(filled) == hbv.masked(empty)
    assert hbv.retarget("<p>Версия исправления:</p>", "2.0").block == "<p>Версия исправления:2.0</p>"


def test_fix_version_field_with_text_after_break_behaves_as_before():
    """Форма «Версия исправления:» с текстом за переносом заполняется, как до 0.10.0.dev12: маска ранее записанного блока
    совпадает с пустой заготовкой, которую Hub может дописать второй раз."""
    empty = "<p>Версия исправления:<br>Компонент: demo</p>"
    filled = "<p>Версия исправления:2.0<br>Компонент: demo</p>"
    assert hbv.retarget(empty, "2.0").block == filled
    assert hbv.masked(filled) == hbv.masked(empty)
    boundary = "<p>Информация об объекте сканирования:</p>"
    text, _, note = hub_defects.split_at_hub_block("<p>Текст</p>" + boundary + filled + boundary + empty)
    assert note == "" and "Текст" in text, note


def test_complex_value_stays_and_operator_is_told():
    block = '<table><tr><th>Версия исправления</th></tr><tr><td><b>1.0</b> или <b>1.1</b></td></tr></table>'
    got = hbv.retarget(block, "2.0")
    assert got.places == 0 and got.block == block
    assert got.notes and "1.0 или 1.1" in got.notes[0]


def test_special_characters_in_target_are_escaped():
    got = hbv.retarget(ONE, "2.0<b>&")
    assert "Версия исправления: 2.0&lt;b&gt;&amp;</p>" in got.block
    assert hbv.retarget(got.block, "2.0<b>&").places == 0


@pytest.mark.parametrize("text, target", [
    ("Рекомендации\nОбновление demo до версии 2.0", "2.0"),
    ("Рекомендации\nПереход на Java 17\nОбновление demo до версии 2.0.\n\nИсточники", "2.0"),
    ("Рекомендации\nОбновление demo до версии 2.0\nОбновление demo до версии 2.0", "2.0"),
    ("Рекомендации\nОбновление demo до версии 2.0\nОбновление other до версии 3.0", ""),
    ("Рекомендации\nИсправленной версии нет", ""),
    ("", ""),
])
def test_target_of_text(text, target):
    assert hbv.target_of(text) == target


def test_for_defect_only_sca_and_note_without_target():
    text = "Рекомендации\nОбновление demo до версии 2.0"
    assert hbv.for_defect("SAST", text, BLOCK).block == BLOCK
    assert hbv.for_defect("SCA", text, BLOCK).places == 3
    none = hbv.for_defect("SCA", "Рекомендации\nПерейти на другую библиотеку", BLOCK)
    assert none.block == BLOCK and none.notes == (hbv.NO_TARGET_NOTE,)
    assert hbv.for_defect("SCA", "Текст", "<p>нет форм</p>").notes == ()


def test_two_blocks_differing_only_in_version_are_one_block():
    head = "<p>После анализа</p><p>Рекомендации</p><p>Обновление demo до версии 2.5</p>"
    sent = hbv.retarget(BLOCK, "2.5").block
    text, block, note = hub_defects.split_at_hub_block(head + sent + BLOCK)
    assert note == "", "исходная заготовка, дописанная Hub к блоку с целевой версией, не считается другим блоком"
    assert "Обновление demo до версии 2.5" in text
    assert "Обновление demo до версии 2.5" in "\n".join(block), "остаётся первый блок, с целевой версией"
    assert "Обновление demo до версии 1.0" not in "\n".join(block)


@pytest.mark.parametrize("old, new", [("pkg:demo", "pkg:other"), ("73002", "73003"), ("demo-1.0.pom", "demo-1.1.pom")])
def test_block_that_differs_elsewhere_stays_a_second_block(old, new):
    """Различается не значение версии, а другое: номер находки, компонент, источник – это два блока, текст не выделяется."""
    head = "<p>Текст</p>"
    assert hub_defects.split_at_hub_block(head + hbv.retarget(BLOCK, "2.5").block + BLOCK.replace(old, new))[2]


SCA_BLOCK = ("<h3>Информация об объекте сканирования:</h3><table><tbody><tr><th>ID</th><th>Версия исправления</th></tr>"
             "<tr><td>73001</td><td>1.1.1</td></tr><tr><td>73002</td><td>1.1.1</td></tr></tbody></table>"
             "<p><strong>Рекомендации</strong></p><p>Обновление demo до версии 1.1.1</p>")


LINKS = [{"id": 73001, "type": "SCA_S"}, {"id": 73002, "type": "SCA_S"}]


def sca_preview(web):
    """Решение «Обновить» по набору, заготовка Hub с версией сканера 1.1.1, предпросмотр создания."""
    pid = prepared(web)
    db = web.app.state.db
    hub_settings(web, pid)
    assert post_package(web, pid, "73001", ["73001", "73002"], **UPD).status_code == 200
    url = f"/projects/{pid}/sca/findings/{db.get_finding_by_hub_id(pid, '73001')['id']}"
    sca_text_ready(web, url)
    assert blank(web, url).status_code == 200
    hub_job(web, body={**BLANK, "description": SCA_BLOCK, "linkedIssues": LINKS})
    hub_job(web, body=SERVICE)
    row = db.hub_defects(pid)[0]
    assert row["state"] == "preview"
    target = hbv.target_of(row["command_text"])
    assert target and target != "1.1.1"
    return pid, row, target


def created_sca(web):
    pid, row, target = sca_preview(web)
    assert create(web, pid, row["id"]).status_code == 200
    hub_job(web, body={"id": 900})
    hub_job(web, body={"id": 900, "linkedIssues": LINKS})
    fresh = web.app.state.db.hub_defect(row["id"])
    assert fresh["state"] == "done", fresh["error"]
    return pid, fresh, target


def obj(row, **changes):
    return {**json.loads(row["confirmed_object_json"]), **changes}


def test_preview_shows_replacement_and_row_keeps_original_blank(web):
    pid, row, target = sca_preview(web)
    assert json.loads(row["blank_json"])["description"] == SCA_BLOCK, "исходная заготовка хранится как есть"
    card = web.client.get(f"/projects/{pid}/defects/{row['id']}").text
    assert 'id="hub-defect-block-version"' in card and f"на {target}, мест: 3" in card
    assert f"Обновление demo до версии {target}" in card and "Обновление demo до версии 1.1.1" not in card


def test_create_sends_target_version_and_is_confirmed(web):
    pid, row, target = sca_preview(web)
    assert create(web, pid, row["id"]).status_code == 200
    job = hub_job(web, body={"id": 900})
    sent = job["body"]["description"]
    assert f"<td>{target}</td>" in sent and f"Обновление demo до версии {target}" in sent and "1.1.1" not in sent
    hub_job(web, body={"id": 900, "linkedIssues": LINKS})
    fresh = web.app.state.db.hub_defect(row["id"])
    assert fresh["state"] == "done", fresh["error"]
    assert json.loads(fresh["blank_json"])["description"] == SCA_BLOCK


@pytest.mark.parametrize("glue", ["", "\n"])
def test_original_blank_appended_by_hub_is_still_confirmed(web, glue):
    """Hub дописал исходную заготовку к описанию, которое уже несёт блок с целевой версией."""
    pid, row, target = sca_preview(web)
    assert create(web, pid, row["id"]).status_code == 200
    hub_job(web, body={"id": 900})
    db = web.app.state.db
    sent = db.hub_defect(row["id"])["body_html"]
    hub_job(web, body={"id": 900, "summary": row["summary"], "linkedIssues": LINKS, "description": sent + glue + SCA_BLOCK})
    fresh = db.hub_defect(row["id"])
    assert fresh["state"] == "done", fresh["error"]
    seen = json.loads(fresh["import_json"])
    assert seen["text_note"] == "" and "Обновление" in seen["command_text"]


def reformatted(description):
    """Как Hub переписывает разметку: пробелы между тегами и внутри тегов, текст тот же."""
    return description.replace("<td>", "\n    <td>").replace("<p>", "<p >")


def test_both_blocks_reformatted_by_hub_are_still_confirmed(web):
    pid, row, target = sca_preview(web)
    assert create(web, pid, row["id"]).status_code == 200
    job = hub_job(web, body={"id": 900})
    described = reformatted(job["body"]["description"]) + reformatted(SCA_BLOCK)
    hub_job(web, body={"id": 900, "summary": row["summary"], "linkedIssues": LINKS, "description": described})
    fresh = web.app.state.db.hub_defect(row["id"])
    assert fresh["state"] == "done", fresh["error"]


def test_blank_with_other_finding_is_not_confirmed(web):
    """Второй блок отличается не только версией: создание не считается подтверждённым молча."""
    pid, row, target = sca_preview(web)
    assert create(web, pid, row["id"]).status_code == 200
    job = hub_job(web, body={"id": 900})
    described = job["body"]["description"] + SCA_BLOCK.replace("73002", "73009")
    hub_job(web, body={"id": 900, "summary": row["summary"], "linkedIssues": LINKS, "description": described})
    assert web.app.state.db.hub_defect(row["id"])["state"] != "done"


@pytest.mark.parametrize("change", [
    reformatted,
    lambda text: text.replace("</p><p>Обновление", "<br>Обновление"),
])
def test_pull_treats_reformatting_as_no_change(web, change):
    pid, row, target = created_sca(web)
    db = web.app.state.db
    assert change(obj(row)["description"]) != obj(row)["description"]
    assert sync(web, pid, row["id"]).status_code == 200
    hub_job(web, body=obj(row, description=change(obj(row)["description"])))
    state = json.loads(db.hub_defect(row["id"])["sync_json"])
    assert state.get("matches") is True, state


def test_pull_shows_block_edit_apply_and_repeat_matches(web):
    pid, row, target = created_sca(web)
    db = web.app.state.db
    assert sync(web, pid, row["id"]).status_code == 200
    hub_job(web, body=obj(row))
    assert json.loads(db.hub_defect(row["id"])["sync_json"]).get("matches") is True, "сразу после создания различий нет"
    edited = obj(row)["description"].replace(f"Обновление demo до версии {target}", "Обновление demo до версии 7.7.7")
    assert edited != obj(row)["description"]
    assert sync(web, pid, row["id"]).status_code == 200
    hub_job(web, body=obj(row, description=edited))
    state = json.loads(db.hub_defect(row["id"])["sync_json"])
    assert "+ Обновление demo до версии 7.7.7" in state["block_diff"] and state["read"]["block_changed"] is True
    assert f'id="hub-sync-block-{row["id"]}"' in tab(web, pid)
    assert apply_sync(web, pid, row["id"]).status_code == 200
    fresh = db.hub_defect(row["id"])
    assert json.loads(fresh["confirmed_object_json"])["description"] == edited
    assert sync(web, pid, row["id"]).status_code == 200
    hub_job(web, body=json.loads(fresh["confirmed_object_json"]))
    assert json.loads(db.hub_defect(row["id"])["sync_json"]).get("matches") is True, "после «Применить» повторный Pull совпадает"
    no_job(web)


def test_block_edited_in_hub_and_text_in_draft_is_a_conflict(web):
    pid, row, target = created_sca(web)
    db = web.app.state.db
    db.hub_defect_update(row["id"], draft_command_text=row["command_text"] + "\nЛокальная правка")
    edited = obj(row)["description"].replace(f"Обновление demo до версии {target}", "Обновление demo до версии 7.7.7")
    assert sync(web, pid, row["id"]).status_code == 200
    hub_job(web, body=obj(row, description=edited))
    r = apply_sync(web, pid, row["id"])
    assert r.status_code >= 400 and "Конфликт сверки" in r.json()["detail"], r.text
    assert json.loads(db.hub_defect(row["id"])["confirmed_object_json"])["description"] != edited


def test_push_brings_block_to_target_and_is_confirmed(web):
    """Дефект, созданный раньше, с версией сканера в блоке: Push приводит блок к целевой версии, показывая замену."""
    pid, row, url = sca_ready(web)
    db = web.app.state.db
    links = ((73001, "SCA_S"), (73002, "SCA_S"))
    fresh = db.hub_defect(row["id"])
    target = hbv.target_of(fresh["draft_command_text"] or fresh["command_text"])
    assert target
    first = hub_body(links=links, summary=fresh["summary"],
                     description="<p>Прежний текст</p>" + SCA_BLOCK)
    to_preview(web, pid, row, first)
    assert phase(db, row["id"]) == "preview", note(db, row["id"])
    page = tab(web, pid)
    assert f'id="hub-update-block-version-{row["id"]}"' in page and f"на {target}, мест: 3" in page
    assert put_click(web, pid, row).status_code == 200
    read_job(web, first)
    from test_hub_defect_import import take
    put = take(web)
    assert put is not None and put["method"] == "PUT", note(db, row["id"])
    sent = put["body"]["description"]
    assert f"<td>{target}</td>" in sent and f"Обновление demo до версии {target}" in sent and "1.1.1" not in sent
    deliver(web, put, 204, text="")
    read_job(web, sent_body(db, row["id"], linkedIssues=LINKS))
    assert phase(db, row["id"]) == "done", note(db, row["id"])
    # блок уже с целевой версией: второй Push правок не находит
    again = sent_body(db, row["id"], linkedIssues=LINKS)
    assert act(web, pid, row["id"], "update").status_code == 200
    read_job(web, again)
    tab(web, pid)
    assert "Изменений для отправки нет" in note(db, row["id"]), note(db, row["id"])


def test_cells_are_separated_only_for_reading():
    """Показ оператору разделяет ячейки, сравнения описаний – прежние строки: иначе у всех дефектов появилось бы ложное различие."""
    assert "73001 | 1.0" in "\n".join(hub_defects.description_for_reading(hbv.retarget(SCA_BLOCK, "1.0").block))
    assert "730011.0" in "\n".join(hub_defects.description_lines(hbv.retarget(SCA_BLOCK, "1.0").block))


@pytest.mark.parametrize("paragraph, expected", [
    ('<p>Версия исправления: <a href="https://r.example/1.0">1.0</a></p>', '<a href="https://r.example/1.0">2.5</a>'),
    ("<p>Обновление <strong>demo</strong> до версии 1.0</p>", "<p>Обновление <strong>demo</strong> до версии 2.5</p>"),
    ("<p>Обновление demo до версии <b>1.0</b></p>", "<b>2.5</b>"),
])
def test_nested_markup_in_paragraph_is_replaced_and_kept(paragraph, expected):
    got = hbv.retarget(paragraph, "2.5")
    assert expected in got.block and got.places == 1 and got.notes == ()
    assert hbv.retarget(got.block, "2.5").places == 0


def test_value_split_between_tags_stays_with_a_note():
    paragraph = "<p>Версия исправления: <b>1.</b>0</p>"
    got = hbv.retarget(paragraph, "2.5")
    assert got.block == paragraph and got.places == 0 and "не заменена" in got.notes[0]


@pytest.mark.parametrize("change", [
    lambda text: text.replace("Обновление demo", "Обновление <strong>demo</strong>"),
    lambda text: text.replace("<td>73001</td>", "<td><span>73001</span></td>"),
])
def test_pull_treats_inline_markup_as_no_change(web, change):
    pid, row, target = created_sca(web)
    described = change(obj(row)["description"])
    assert described != obj(row)["description"]
    assert sync(web, pid, row["id"]).status_code == 200
    hub_job(web, body=obj(row, description=described))
    state = json.loads(web.app.state.db.hub_defect(row["id"])["sync_json"])
    assert state.get("matches") is True, state


def test_long_block_difference_is_shown_whole(web):
    pid, row, target = created_sca(web)
    rows = "".join(f"<tr><td>{n}</td><td>{target}</td></tr>" for n in range(80000, 80080))
    described = obj(row)["description"].replace("</tbody>", rows + "</tbody>")
    assert sync(web, pid, row["id"]).status_code == 200
    hub_job(web, body=obj(row, description=described))
    state = json.loads(web.app.state.db.hub_defect(row["id"])["sync_json"])
    assert len(state["block_diff"]) == 80 and state["block_diff"][-1] == f"+ 80079 | {target}"


def test_link_address_change_is_a_change():
    first, second = "<h3>Информация об объекте сканирования:</h3><p><a href=\"https://a.example\">x</a></p>", ""
    second = first.replace("a.example", "b.example")
    assert hub_defects._block_lines(first) != hub_defects._block_lines(second)


def test_column_header_in_td_is_not_a_pair():
    table = ("<table><tr><td>Компонент</td><td>Версия исправления</td><td>Источник</td></tr>"
             "<tr><td>demo</td><td>1.0</td><td>x</td></tr></table>")
    got = hbv.retarget(table, "2.5")
    assert "<td>Источник</td>" in got.block and "<td>demo</td><td>2.5</td><td>x</td>" in got.block and got.places == 1


def test_two_td_header_cells_stay_with_a_note():
    table = "<table><tr><td>Версия исправления</td><td>Источник</td></tr><tr><td>1.0</td><td>x</td></tr></table>"
    got = hbv.retarget(table, "2.5")
    assert got.block == table and got.places == 0 and "Источник" in got.notes[0]


def test_field_value_row_in_td_is_replaced():
    table = "<table><tr><td>Компонент</td><td>demo</td></tr><tr><td>Версия исправления</td><td>1.0</td></tr></table>"
    assert hbv.retarget(table, "2.5").block == table.replace("<td>1.0</td>", "<td>2.5</td>")


def test_two_blocks_formatted_differently_are_one_block():
    head, sent = "<p>Текст</p>", hbv.retarget(BLOCK, "2.5").block
    spaced = sent.replace("<td>", "\n   <td>")
    assert hub_defects.split_at_hub_block(head + spaced + BLOCK)[2] == ""
    assert hub_defects.split_at_hub_block(head + sent + BLOCK.replace("<td>", "\n   <td>"))[2] == ""


def test_pull_sees_edit_in_description_with_two_accepted_blocks():
    head, sent = "<p>Текст</p>", hbv.retarget(BLOCK, "2.5").block
    accepted, edited = head + sent + BLOCK, head + sent.replace("версии 2.5", "версии 7.7") + BLOCK
    assert hub_defects.split_at_hub_block(edited)[2] == "", "текст по-прежнему выделяется"
    row = {"confirmed_object_json": json.dumps({"description": accepted})}
    assert "+ Обновление demo до версии 7.7" in hub_defects._block_diff(row, {"description": edited})
    assert hub_defects._block_diff(row, {"description": accepted}) == []


def test_push_without_changes_keeps_the_version_warning(web):
    """Цели нет: заменить нечего, правок нет, но итог называет расхождение."""
    pid, row, url = sca_ready(web)
    db = web.app.state.db
    links = ((73001, "SCA_S"), (73002, "SCA_S"))
    text = "Рекомендации\nПерейти на другой компонент"
    db.hub_defect_update(row["id"], draft_command_text=text, command_text=text)
    fresh = db.hub_defect(row["id"])
    described = hub_defects.description_html(text, SCA_BLOCK)
    assert act(web, pid, row["id"], "update").status_code == 200
    read_job(web, hub_body(links=links, summary=fresh["summary"], description=described))
    summary = hub_defects.update_state(db.hub_defect(row["id"]))["candidate"]["summary"]  # заголовок по текущему формату
    assert act(web, pid, row["id"], "update-cancel", form_fields(web, pid, f"hub-update-cancel-form-{row['id']}")).status_code == 200
    assert act(web, pid, row["id"], "update").status_code == 200
    read_job(web, hub_body(links=links, summary=summary, description=described))
    tab(web, pid)
    assert "Изменений для отправки нет" in note(db, row["id"]) and hbv.NO_TARGET_NOTE in note(db, row["id"]), note(db, row["id"])


def test_paragraph_inside_cell_is_not_a_change_and_keeps_two_blocks_as_one():
    wrapped = "<table><tr><td><p>A</p></td><td><p>B</p></td></tr></table>"
    plain = "<table><tr><td>A</td><td>B</td></tr></table>"
    boundary = "<p>Информация об объекте сканирования:</p>"
    row = {"confirmed_object_json": json.dumps({"description": boundary + wrapped})}
    assert hub_defects._block_diff(row, {"description": boundary + plain}) == []
    assert hub_defects.split_at_hub_block("<p>Текст</p>" + boundary + wrapped + boundary + plain)[2] == ""
    assert "|" not in hub_defects.description_for_reading(wrapped)


def test_block_appearing_after_empty_accepted_description_is_shown():
    block = "<p>Информация об объекте сканирования:</p><p>Строка</p>"
    assert hub_defects._block_diff({"confirmed_object_json": json.dumps({"description": ""})}, {"description": block}) == ["+ Строка"]
    assert hub_defects._block_diff({"confirmed_object_json": json.dumps({})}, {"description": block}) == []
    assert hub_defects._block_diff({"confirmed_object_json": ""}, {"description": block}) == []


def test_stale_create_form_is_refused_when_sent_block_differs(web):
    """Форма открыта на прежней сборке: подпись без блока с целевой версией не проходит, «Создать» просит обновить карточку."""
    pid, row, target = sca_preview(web)
    assert hub_defects.creation_signature(row) != hub_defects.creation_signature(
        {**row, "command_text": row["command_text"].replace(f"до версии {target}", "до версии 8.8.8")})
    r = web.client.post(f"/projects/{pid}/hub/defects/{row['id']}/create", data={"create_snapshot": "прежняя подпись"}, headers=AS_JSON)
    assert r.status_code >= 400 and "Предпросмотр создания изменился" in r.text, r.text
    no_job(web)


@pytest.mark.parametrize("newline", ["\r\n", "\r"])
def test_target_is_found_with_browser_newlines(newline):
    assert hbv.target_of(f"Рекомендации{newline}Обновление demo до версии 2.0{newline}{newline}Источники") == "2.0"


def test_value_moved_between_cells_is_a_change():
    boundary = "<p>Информация об объекте сканирования:</p>"
    first = boundary + "<table><tr><td>1</td><td>23</td></tr></table>"
    second = boundary + "<table><tr><td>12</td><td>3</td></tr></table>"
    row = {"confirmed_object_json": json.dumps({"description": first})}
    assert hub_defects._block_diff(row, {"description": second}) == ["− 1 | 23", "+ 12 | 3"]
    assert hub_defects.split_at_hub_block("<p>Текст</p>" + first + second)[2], "два разных блока не считаются одним"


def test_literal_bars_in_text_stay_and_are_compared():
    boundary = "<p>Информация об объекте сканирования:</p>"
    row = {"confirmed_object_json": json.dumps({"description": boundary + "<p>|demo|</p>"})}
    assert hub_defects._block_diff(row, {"description": boundary + "<p>demo</p>"}) == ["− |demo|", "+ demo"]
    mixed = "<table><tr><td>A</td><td><p>B</p></td><td>C</td></tr></table>"
    assert hub_defects.description_for_reading(mixed)[0] == "A"
    assert "|" not in "".join(hub_defects.description_for_reading("<table><tr><td><p>A</p></td><td><p>B</p></td></tr></table>"))


def test_value_moved_to_empty_cell_is_a_change():
    boundary = "<p>Информация об объекте сканирования:</p>"
    first = boundary + "<table><tr><td>1.0</td><td></td></tr></table>"
    second = boundary + "<table><tr><td></td><td>1.0</td></tr></table>"
    row = {"confirmed_object_json": json.dumps({"description": first})}
    assert hub_defects._block_diff(row, {"description": second}) == ["− 1.0 | (пусто)", "+ (пусто) | 1.0"]
    assert hub_defects._block_diff(row, {"description": first.replace("<td></td>", "<td> \n</td>")}) == []
    assert "(пусто)" not in hub_defects.description_lines(first), "текст дефекта и прежние сравнения не меняются"


def test_line_moved_to_next_cell_is_a_change():
    boundary = "<p>Информация об объекте сканирования:</p>"
    first = boundary + "<table><tr><td>A<br>B</td><td>C</td></tr></table>"
    second = boundary + "<table><tr><td>A</td><td>B<br>C</td></tr></table>"
    row = {"confirmed_object_json": json.dumps({"description": first})}
    assert hub_defects._block_diff(row, {"description": second})
    assert hub_defects.split_at_hub_block("<p>Текст</p>" + first + second)[2]
    assert hub_defects._block_diff(row, {"description": first.replace("<td>", "\n <td>")}) == []


@pytest.mark.parametrize("gap", ["<br>", "<br/>", "<br />"])
def test_form_after_line_break_in_paragraph_is_replaced(gap):
    paragraph = f"<p><strong>Рекомендации</strong>{gap}Обновление demo до версии 1.1.1{gap}Ещё строка 1.1.1</p>"
    got = hbv.retarget(paragraph, "2.5")
    assert got.block == paragraph.replace("до версии 1.1.1", "до версии 2.5") and got.places == 1
    assert hbv.retarget(got.block, "2.5").places == 0


def test_push_without_block_changes_nothing_new(web):
    """Занесённый дефект без блока: версия менять негде, предпросмотр о замене не говорит."""
    pid, row, url = sca_ready(web)
    links = ((73001, "SCA_S"), (73002, "SCA_S"))
    db = web.app.state.db
    fresh = db.hub_defect(row["id"])
    to_preview(web, pid, row, hub_body(links=links, summary=fresh["summary"], description="<p>Прежний текст</p>"))
    assert f'id="hub-update-block-version-{row["id"]}"' not in tab(web, pid)


def test_block_diff_after_apply_and_repeat(web):
    row = {"confirmed_object_json": json.dumps({"description": "<p>Текст</p>" + SCA_BLOCK})}
    same = {"description": "<p>Другой текст</p>\n" + SCA_BLOCK.replace("<tbody>", "\n<tbody>\n")}
    assert hub_defects._block_diff(row, same) == [], "переформатирование и текст выше блока – не изменение блока"
    edited = {"description": "<p>Текст</p>" + SCA_BLOCK.replace("Обновление demo до версии 1.1.1", "Обновление demo до версии 1.2.3")}
    diff = hub_defects._block_diff(row, edited)
    assert "− Обновление demo до версии 1.1.1" in diff and "+ Обновление demo до версии 1.2.3" in diff
    accepted = {"confirmed_object_json": json.dumps(edited)}
    assert hub_defects._block_diff(accepted, edited) == [], "после «Применить» база новая: повторный Pull совпадает"
    assert hub_defects._block_diff({"confirmed_object_json": ""}, edited) == []
    removed = {"description": "<p>Текст</p>"}
    assert hub_defects._block_diff(row, removed)[0].startswith("− "), "блок убран в Hub – это изменение"
    added = hub_defects._block_diff({"confirmed_object_json": json.dumps(removed)}, edited)
    assert added and all(line.startswith("+ ") for line in added), "блок появился в Hub – это изменение"
