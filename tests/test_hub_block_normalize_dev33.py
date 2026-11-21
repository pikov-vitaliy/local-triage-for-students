"""Служебный блок Hub в подтверждении записи сверяется с допуском переформатирования Hub (0.9.26.dev33: после «Push в Hub» с добавленным блоком Hub вернул тот же блок без переносов и отступов между тегами и с tbody,
а приложение сравнивало побайтно и писало «чтение не подтвердило»). Кнопки «Проверить в Hub» в интерфейсе нет – у
дефекта «Push в Hub» и «Pull из Hub». Данные выдуманы, сети нет."""

from __future__ import annotations


import pytest

from app import hub_defects
from test_hub_blank_update_dev31 import BLOCK as PLAIN_BLOCK, TEXT, blank_job, no_block_row, start  # noqa: F401
from test_hub_defect_update import deliver, hub_body, note, phase, put_click, read_job, sent_body, tab, take, web  # noqa: F401

SENT_BLOCK = ("<h3>Информация об объекте сканирования:</h3>\n<table>\n        <tr>\n            <th>Ветка</th>\n"
              "            <td>master</td>\n        </tr>\n</table>\n\n    <h3>Трасса</h3>\n    <div>{code} src/a.js:1</div>\n")
HUB_BLOCK = ("<h3>Информация об объекте сканирования:</h3><table><tbody><tr><th>Ветка</th><td>master</td></tr></tbody>"
             "</table><h3>Трасса</h3><div>{code} src/a.js:1</div>")


def test_canonical_form_ignores_only_hub_reformatting():
    assert hub_defects.canonical_html(SENT_BLOCK) == hub_defects.canonical_html(HUB_BLOCK)
    assert hub_defects.canonical_html(HUB_BLOCK.replace("master", "dev")) != hub_defects.canonical_html(SENT_BLOCK)
    assert hub_defects.canonical_html(HUB_BLOCK.replace("<td>master</td>", "")) != hub_defects.canonical_html(SENT_BLOCK)
    assert hub_defects.canonical_html('<a href="x" class="y">t</a>') == hub_defects.canonical_html('<a class="y"  href="x">t</a>')
    assert hub_defects.canonical_html("<p>a<br/>b</p>") == hub_defects.canonical_html("<p>a<br>b</p>")
    assert hub_defects.canonical_html("<p>a  b</p>") == hub_defects.canonical_html("<p>a b</p>")
    assert hub_defects.canonical_html("<p>ab</p>") != hub_defects.canonical_html("<p>a b</p>")
    # ревью dev33, круг 1: значимые пробелы и атрибуты не прячутся
    assert hub_defects.canonical_html("<pre>a\nb</pre>") != hub_defects.canonical_html("<pre>a b</pre>")
    assert hub_defects.canonical_html("<td>file <b>name</b></td>") != hub_defects.canonical_html("<td>file<b>name</b></td>")
    assert hub_defects.canonical_html("<b>a</b> <i>b</i>") != hub_defects.canonical_html("<b>a</b><i>b</i>")
    assert hub_defects.canonical_html("<table><tbody hidden><tr><td>x</td></tr></tbody></table>") != \
        hub_defects.canonical_html("<table><tr><td>x</td></tr></table>")
    assert hub_defects.canonical_html("<table><thead><tr><th>x</th></tr></thead></table>") != \
        hub_defects.canonical_html("<table><tr><th>x</th></tr></table>")


@pytest.mark.parametrize("tail,ok", [("", True), ("<p>Чужой комментарий</p>", False)])
def test_confirmation_accepts_the_reformatted_block_only(tail, ok):
    text = hub_defects.command_html("Обоснование:\nтекст\n\nРекомендация:\n1) Мера.")
    sent = {"summary": "ID5 - T (SAST)", "description": text + "\n" + SENT_BLOCK}
    seen = {"summary": "ID5 - T (SAST)", "description": text + HUB_BLOCK + tail}
    assert hub_defects.update_content_new(seen, sent) is ok
    other = {"summary": "ID5 - T (SAST)", "description": hub_defects.command_html("Другой текст.") + HUB_BLOCK}
    assert hub_defects.update_content_new(other, sent) is False
    assert hub_defects.block_start(seen["description"], SENT_BLOCK) == (len(text) if ok else -1)


def test_push_with_a_blank_block_is_confirmed_after_hub_reformatting(web):
    """Дефект без блока: шаг «blank», Push с блоком заготовки; Hub отвечает блоком в своей форме – «Обновлено в Hub»."""
    pid, row = no_block_row(web, TEXT + " Правка.")
    db = web.app.state.db
    start(web, pid, row)
    blank_job(web, body={"description": SENT_BLOCK})
    tab(web, pid)
    assert phase(db, row["id"]) == "preview", note(db, row["id"])
    assert put_click(web, pid, row).status_code == 200
    read_job(web, hub_body(description=hub_defects.command_html(TEXT)))
    put = take(web)
    assert put["method"] == "PUT" and put["body"]["description"].endswith(SENT_BLOCK)
    deliver(web, put, 204, text="")
    sent = hub_defects.update_state(db.hub_defect(row["id"]))["sent"]
    reformatted = sent["description"][:-len(SENT_BLOCK)].rstrip("\n") + HUB_BLOCK
    read_job(web, sent_body(db, row["id"], description=reformatted))
    assert phase(db, row["id"]) == "done", note(db, row["id"])


def test_no_check_in_hub_button(web):
    """«Проверить в Hub» нет ни во вкладке «Дефекты», ни в карточке находки (у дефекта только Push и Pull)."""
    pid, row = no_block_row(web)
    page = web.client.get(f"/projects/{pid}/defects").text
    assert "Проверить в Hub" not in page and "hub-defect-recheck" not in page


def test_block_start_is_linear_and_exact():
    """Поиск блока – за один разбор: длинное описание перед блоком не мешает; граница – начало куска верхнего уровня."""
    head = "<p>x</p>" * 5000
    description = head + HUB_BLOCK
    assert hub_defects.block_start(description, SENT_BLOCK) == len(head)
    assert hub_defects.block_start(description.replace("master", "dev"), SENT_BLOCK) == -1
    assert hub_defects.block_start("<div><p>t</p>" + HUB_BLOCK + "</div>", SENT_BLOCK) == -1


def test_nested_tables_and_text_start_after_a_separator():
    """Ревью dev33, круг 2: вложенная таблица, в которую Hub вставил tbody, рядом с внешним tbody с атрибутами; блок,
    начинающийся текстом после переноса строки."""
    sent = '<table><tbody class="outer"><tr><td>\n<table><tr><td>x</td></tr></table>\n</td></tr></tbody></table>'
    hub = ('<table><tbody class="outer"><tr><td><table><tbody><tr><td>x</td></tr></tbody></table></td></tr></tbody>'
           "</table>")
    assert hub_defects.canonical_html(sent) == hub_defects.canonical_html(hub)
    block = "Информация об объекте сканирования:<br><table>\n<tr><td>x</td></tr>\n</table>"
    description = "<p>Текст.</p>\r\n" + block.replace("\n", "")
    assert hub_defects.block_start(description, block) == description.index("Информация")
    many = "<table><tbody><tr><td>x</td></tr></tbody></table>" * 3000
    assert hub_defects.canonical_html(many).count("<table>") == 3000


@pytest.mark.parametrize("separator", ["&#10;", "&#32;", "\r\n&#10; "])
def test_block_after_whitespace_entities(separator):
    """Ревью dev33, круг 3: пробелы перед блоком пришли сущностями – граница находится по исходному HTML."""
    block = "Информация об объекте сканирования:<br><table>\n<tr><td>x</td></tr>\n</table>"
    description = "<p>Текст.</p>" + separator + block.replace("\n", "")
    start = hub_defects.block_start(description, block)
    assert start != -1 and description[start:].lstrip(" \r\n").replace("&#10;", "").replace("&#32;", "").lstrip(" ") \
        .startswith("Информация")
    assert hub_defects.block_start(description.replace("<td>x</td>", "<td>y</td>"), block) == -1


def test_whitespace_entity_inside_the_expected_block():
    """Ревью dev33, круг 4: блок сам начинается пробельной сущностью; Hub убрал только перенос между тегами."""
    block = "&#10;Информация об объекте сканирования:<br><table>\n<tr><td>x</td></tr></table>"
    text = hub_defects.command_html("Текст.")
    sent = {"summary": "T", "description": text + "\n" + block}
    seen = {"summary": "T", "description": sent["description"].replace("<table>\n", "<table>")}
    assert hub_defects.block_start(seen["description"], block) != -1
    changed = {"summary": "T", "description": seen["description"].replace("<td>x</td>", "<td>y</td>")}
    assert hub_defects.block_start(changed["description"], block) == -1
    # граница не переносится через непробельный текст
    glued = text + "Хвост " + block.replace("<table>\n", "<table>")
    assert hub_defects.block_start(glued, block) == -1
