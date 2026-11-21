"""Служебный блок Hub – часть текста дефекта (0.9.26.dev30):
создание отправляет текст и блок заготовки, карточка дефекта показывает блок под текстом (очищенный HTML), «Push в
Hub» сохраняет блок Hub байт в байт, а дефекту без блока добавляет блок заготовки. Данные выдуманы, сети нет."""

from __future__ import annotations

import json

import pytest

from app import hub_defects
from test_hub_defects import (  # noqa: F401
    BLANK,
    HUB_DESCRIPTION,
    REASON,
    TITLE,
    create,
    hello,
    hub_job,
    sast_ready,
    to_preview,
    web,
)

BLOCK = ("<h3>Информация об объекте сканирования:</h3><table><tr><th>Ветка</th><td>master</td></tr></table>"
         "<h3>Трасса</h3><div>{code}</div><div>src/a.js:1</div>")


# ============================================================================ чистые правила


def test_sanitizer_keeps_safe_markup_and_drops_the_rest():
    raw = ('<h3 class="x" onclick="alert(1)">Информация</h3><script>alert(1)</script><style>p{}</style>'
           '<table><tr><th>Ветка</th><td>master &amp; dev</td></tr></table>'
           '<a href="https://example.org/x" onclick="x">ссылка</a> <a href="javascript:alert(1)">плохая</a>'
           '<img src="x" onerror="alert(1)"><p>текст<br>строка</p><unknown>тег</unknown>')
    out = hub_defects.sanitize_hub_html(raw)
    assert out.startswith("<h3>Информация</h3><table><tr><th>Ветка</th><td>master &amp; dev</td></tr></table>")
    assert '<a href="https://example.org/x" rel="noopener noreferrer" target="_blank">ссылка</a>' in out
    assert "<a>плохая</a>" in out and "javascript" not in out
    assert "script" not in out and "alert" not in out and "onclick" not in out and "<img" not in out
    assert "<p>текст<br>строка</p>" in out and "тег" in out and "<unknown>" not in out
    assert hub_defects.sanitize_hub_html("") == "" and hub_defects.sanitize_hub_html(None) == ""
    # незакрытые теги закрываются
    assert hub_defects.sanitize_hub_html("<div><p>a").endswith("</p></div>")


def test_block_for_write_prefers_hub_then_blank():
    row = {"blank_json": json.dumps({"description": BLOCK})}
    with_hub = {"description": "<p>Текст.</p>" + BLOCK}
    assert hub_defects.block_for_write(row, with_hub) == (BLOCK, "")
    assert hub_defects.block_for_write(row, {"description": "<p>Только текст</p>"}) == (BLOCK, "")
    assert hub_defects.block_for_write(row, None) == (BLOCK, "")
    assert hub_defects.block_for_write({"blank_json": "{}"}, {"description": "<p>Только текст</p>"}) == ("", "")
    glued = {"description": "<div><p>Текст.</p>" + BLOCK + "</div>"}
    block, warning = hub_defects.block_for_write(row, glued)
    assert block == BLOCK and "склеен" in warning and "блок заготовки" in warning and "вручную" not in warning
    block, warning = hub_defects.block_for_write({"blank_json": "{}"}, glued)
    assert block == "" and "только текст" in warning
    assert hub_defects.hub_has_block(with_hub) and not hub_defects.hub_has_block({"description": "<p>x</p>"})
    assert hub_defects.block_for_display(row, with_hub)[0].startswith("<h3>Информация об объекте сканирования:</h3>")
    assert hub_defects.block_for_display(row, with_hub)[1] == "hub"
    assert hub_defects.block_for_display(row, {"description": "<p>x</p>"})[1] == "blank"
    assert hub_defects.block_for_display({"blank_json": "{}"}, glued) == ("", "")
    assert hub_defects.block_for_display(row, glued) == ("", ""), "склеенный блок карточка не подменяет заготовкой"


def test_update_description_carries_the_block_and_keep_markup_compares_text_parts():
    text = "Обоснование:\nтекст\n\nРекомендация:\n1) Мера."
    assembled, problem = hub_defects.update_description(text, BLOCK)
    assert problem == "" and assembled == hub_defects.command_html(text) + "\n" + BLOCK
    only, problem = hub_defects.update_description(text)
    assert problem == "" and only == hub_defects.command_html(text)
    hub = {"description": "<p>Обоснование:<br>текст</p><p>Рекомендация:<br>1) Мера.</p>\n" + BLOCK}
    assert hub_defects.keep_hub_markup(hub, assembled) == hub["description"], "текст тот же – описание Hub как есть"
    changed, _ = hub_defects.update_description(text + " Ещё.", BLOCK)
    assert hub_defects.keep_hub_markup(hub, changed) == changed
    assert hub_defects.update_content_new({"summary": "T", "description": assembled}, {"summary": "T", "description": assembled})


# ============================================================================ создание и карточка


def test_create_sends_text_and_blank_block_and_card_shows_it(web):
    pid, url = sast_ready(web)
    db = web.app.state.db
    hello(web)
    row = to_preview(web, pid, url)
    owner = row.get("draft_owner_id") or row["id"]
    page = web.client.get(f"/projects/{pid}/defects/{owner}").text
    assert 'id="hub-defect-block"' in page and "Информация об объекте сканирования:" in page
    assert page.index('id="hub-defect-body"') < page.index('id="hub-defect-block"')
    card = web.client.get(url).text
    assert "следом в описание уйдёт служебный блок Hub из заготовки" in card
    assert create(web, pid, row["id"], priority="Critical").status_code == 200
    job = hub_job(web, body={"id": 555})
    description = job["body"]["description"]
    assert description.endswith("\n" + HUB_DESCRIPTION) and description.startswith("<p>")
    assert hub_defects.split_description(description)[0].startswith("После тщательного анализа")
    hub_job(web, body={"id": 555, "summary": TITLE, "linkedIssues": [{"id": 510001, "type": "SAST"}],
                       "description": description})
    current = db.hub_defect(row["id"])
    assert current["state"] == "done", current
    assert db.get_review(pid, "510001")["entered_hub"] == 1
    page = web.client.get(f"/projects/{pid}/defects/{owner}").text
    assert 'id="defect-hub-block"' in page and "<p>demo</p>" in page
    assert 'id="hub-defect-block"' not in page
    # «Описание в Hub» – только текстовая часть, без строк блока
    hub_text = page.split('id="defect-hub-description"')[1].split("</div>")[0] if 'id="defect-hub-description"' in page else ""
    assert "demo" not in hub_text


@pytest.mark.parametrize("tail,state", [("", "done"), ("<p>Чужой комментарий</p>", "unconfirmed")])
def test_create_confirmation_checks_the_whole_description(web, tail, state):
    pid, url = sast_ready(web)
    db = web.app.state.db
    hello(web)
    row = to_preview(web, pid, url)
    assert create(web, pid, row["id"], priority="Critical").status_code == 200
    job = hub_job(web, body={"id": 555})
    hub_job(web, body={"id": 555, "summary": TITLE, "linkedIssues": [{"id": 510001, "type": "SAST"}],
                       "description": job["body"]["description"] + tail})
    assert db.hub_defect(row["id"])["state"] == state


# ============================================================================ «Push в Hub»

from test_hub_defect_update import (  # noqa: E402,F401
    BLOCK as HUB_BLOCK,
    DESCRIPTION as HUB_DESC,
    deliver,
    hub_body,
    ready,
    read_job,
    sent_body,
    take,
    to_preview as update_preview,
    to_put,
    note,
    phase,
)


def test_push_keeps_the_hub_block_byte_for_byte(web):
    """Дефект из Hub с блоком: правка текста – описание = новый текст + исходный блок Hub."""
    pid, row = ready(web)
    put = to_put(web, pid, row)
    description = put["body"]["description"]
    assert description.endswith("\n" + HUB_BLOCK) and hub_defects.split_description(description)[0]
    assert "Информация об объекте сканирования:" in description
    deliver(web, put, 204, text="")
    read_job(web, sent_body(web.app.state.db, row["id"]))
    assert phase(web.app.state.db, row["id"]) == "done"
    page = web.client.get(f"/projects/{pid}/defects/{row['id']}").text
    assert 'id="defect-hub-block"' in page and "InvoiceDao.java" in page


def test_push_adds_the_blank_block_to_a_defect_without_one(web):
    """Дефект в Hub без блока (создан только текстом), заготовка с блоком сохранена: Push добавляет блок заготовки;
    без правки текста это тоже изменение (его видно в предпросмотре)."""
    pid, row = ready(web, build=False)
    db = web.app.state.db
    text_only = hub_body(description=hub_defects.command_html("Текст без блока."))
    with db._tx() as c:
        c.execute("UPDATE hub_defects SET blank_json = ?, draft_command_text = ? WHERE id = ?",
                  (json.dumps({"description": HUB_BLOCK}), "Текст без блока.", row["id"]))
    row = db.hub_defect(row["id"])
    update_preview(web, pid, row, text_only)
    state = hub_defects.update_state(db.hub_defect(row["id"]))
    assert state["phase"] == "preview", note(db, row["id"])
    assert state["new"]["description"] == hub_defects.command_html("Текст без блока.") + "\n" + HUB_BLOCK
    assert state["kept_description"] is False


def test_push_without_text_change_keeps_the_hub_description(web):
    pid, row = ready(web, build=False)
    db = web.app.state.db
    text = hub_defects.split_description(HUB_DESC)[0]
    with db._tx() as c:
        c.execute("UPDATE hub_defects SET draft_command_text = ? WHERE id = ?", (text, row["id"]))
    row = db.hub_defect(row["id"])
    update_preview(web, pid, row)
    assert phase(db, row["id"]) == "cancelled" and "Изменений для отправки нет" in note(db, row["id"])


# ============================================================================ круг 2 ревью


def test_hub_appending_the_blank_block_twice_is_confirmed(web):
    pid, url = sast_ready(web)
    db = web.app.state.db
    hello(web)
    row = to_preview(web, pid, url)
    assert create(web, pid, row["id"], priority="Critical").status_code == 200
    job = hub_job(web, body={"id": 555})
    hub_job(web, body={"id": 555, "summary": TITLE, "linkedIssues": [{"id": 510001, "type": "SAST"}],
                       "description": job["body"]["description"] + "\n" + HUB_DESCRIPTION})
    assert db.hub_defect(row["id"])["state"] == "done"
    assert db.get_review(pid, "510001")["entered_hub"] == 1


def test_card_hub_text_keeps_angle_brackets(web):
    pid, url = sast_ready(web)
    hello(web)
    row = to_preview(web, pid, url)
    assert create(web, pid, row["id"], priority="Critical").status_code == 200
    hub_job(web, body={"id": 555})
    hub_job(web, body={"id": 555, "summary": TITLE, "linkedIssues": [{"id": 510001, "type": "SAST"}],
                       "description": "<p>std::vector&lt;int&gt; и &lt;b&gt;</p>\n" + HUB_DESCRIPTION})
    owner = row.get("draft_owner_id") or row["id"]
    page = web.client.get(f"/projects/{pid}/defects/{owner}").text
    assert "std::vector&lt;int&gt; и &lt;b&gt;" in page


def test_put_confirmation_requires_the_original_block_substring():
    text = "Обоснование:\nтекст"
    sent = {"summary": "T", "description": hub_defects.description_html(text, BLOCK)}
    assert hub_defects.update_content_new({"summary": "T", "description": sent["description"]}, sent)
    tidy = sent["description"].replace("<p>Обоснование", "<p >Обоснование")
    assert hub_defects.update_content_new({"summary": "T", "description": tidy}, sent), "нормализация текста"
    # dev33: переформатирование Hub (пробелы, переносы, tbody) успеху не мешает; другое содержимое блока – мешает
    spaced = sent["description"].replace("<td>master</td>", "\n    <td>master</td>\n")
    assert hub_defects.update_content_new({"summary": "T", "description": spaced}, sent), "отступы – переформатирование"
    changed_block = sent["description"].replace("<td>master</td>", "<td>dev</td>")
    assert not hub_defects.update_content_new({"summary": "T", "description": changed_block}, sent), "блок другой"
    assert not hub_defects.update_content_new({"summary": "T", "description": hub_defects.command_html(text)}, sent)


def test_block_mode_and_warnings():
    hub = {"description": "<p>Текст.</p>" + BLOCK}
    assert hub_defects.block_mode_of(hub, BLOCK, "", hub["description"]) == "kept"
    assert hub_defects.block_mode_of(hub, BLOCK, "", "<p>Другой.</p>" + BLOCK) == "same"
    assert hub_defects.block_mode_of({"description": "<p>Текст.</p>"}, BLOCK, "", "<p>Другой.</p>" + BLOCK) == "added"
    assert hub_defects.block_mode_of(hub, BLOCK, "склеен", "<p>Другой.</p>" + BLOCK) == "replaced"
    assert hub_defects.block_mode_of(hub, "", "склеен", "<p>Другой.</p>") == "dropped"
    assert hub_defects.block_mode_of({"description": "<p>Текст.</p>"}, "", "", "<p>Другой.</p>") == "none"


def test_glued_block_warning_does_not_drop_hub_warnings(web):
    pid, row = ready(web, build=False)
    db = web.app.state.db
    glued = hub_body(description="<div><p>Старый текст.</p>" + HUB_BLOCK + "<p>Комментарий рецензента.</p></div>",
                     links=((510001, "SAST"), (599999, "SAST")))
    with db._tx() as c:
        c.execute("UPDATE hub_defects SET draft_command_text = ? WHERE id = ?", ("Новый текст.", row["id"]))
    row = db.hub_defect(row["id"])
    update_preview(web, pid, row, glued)
    state = hub_defects.update_state(db.hub_defect(row["id"]))
    assert state["phase"] == "preview", note(db, row["id"])
    warnings = state["warnings"]
    assert sum("не выделяется" in w for w in warnings) == 1 and any("599999" in w for w in warnings), warnings
    assert state["block_mode"] == "dropped" and state["new"]["description"] == hub_defects.command_html("Новый текст.")


# ============================================================================ круг 3 ревью


def test_empty_blank_block_appended_twice_is_confirmed(web):
    pid, url = sast_ready(web)
    db = web.app.state.db
    hello(web)
    row = to_preview(web, pid, url, blank_body={**BLANK, "description": "<p>Информация об объекте сканирования:</p>"})
    assert create(web, pid, row["id"], priority="Critical").status_code == 200
    job = hub_job(web, body={"id": 555})
    hub_job(web, body={"id": 555, "summary": TITLE, "linkedIssues": [{"id": 510001, "type": "SAST"}],
                       "description": job["body"]["description"] + "\n<p>Информация об объекте сканирования:</p>"})
    assert db.hub_defect(row["id"])["state"] == "done"


def test_appended_block_must_repeat_both_substrings(web):
    pid, url = sast_ready(web)
    db = web.app.state.db
    hello(web)
    row = to_preview(web, pid, url)
    assert create(web, pid, row["id"], priority="Critical").status_code == 200
    job = hub_job(web, body={"id": 555})
    sent = job["body"]["description"]
    altered = sent.replace("<p>demo</p>", "<p>demo-2</p>") + "\n" + HUB_DESCRIPTION  # первый блок изменён по содержанию (dev33)
    hub_job(web, body={"id": 555, "summary": TITLE, "linkedIssues": [{"id": 510001, "type": "SAST"}],
                       "description": altered})
    assert db.hub_defect(row["id"])["state"] != "done"


def test_void_tags_of_the_original_parser_are_intact():
    description = '<img src="x">Текст.<h3>Информация об объекте сканирования:</h3><p>Ветка: main</p>'
    block, problem = hub_defects.hub_block(description)
    assert problem == "" and block == "<h3>Информация об объекте сканирования:</h3><p>Ветка: main</p>"
    assert "img" in hub_defects._VOID_TAGS and "img" not in hub_defects._SANITIZER_VOID


def test_card_shows_glued_hub_description_whole_and_blank_as_proposed(web):
    pid, row = ready(web, build=False)
    db = web.app.state.db
    glued = hub_body(description="<div><p>Старый текст.</p>" + HUB_BLOCK + "<p>Комментарий рецензента.</p></div>")
    with db._tx() as c:
        c.execute("UPDATE hub_defects SET confirmed_object_json = ?, blank_json = ? WHERE id = ?",
                  (json.dumps(glued), json.dumps({"description": BLOCK}), row["id"]))
    page = web.client.get(f"/projects/{pid}/defects/{row['id']}").text
    assert 'id="defect-hub-block"' not in page and "Комментарий рецензента." in page and "InvoiceDao.java" in page
    plain = hub_body(description="<p>Только текст.</p>")
    with db._tx() as c:
        c.execute("UPDATE hub_defects SET confirmed_object_json = ? WHERE id = ?", (json.dumps(plain), row["id"]))
    page = web.client.get(f"/projects/{pid}/defects/{row['id']}").text
    assert 'id="defect-hub-block"' in page and "Служебный блок Hub (из заготовки)" in page and "уйдёт следом за текстом" in page


# ============================================================================ круг 4 ревью


def test_blank_with_trailing_newline_appended_twice_is_confirmed(web):
    pid, url = sast_ready(web)
    db = web.app.state.db
    hello(web)
    blank = HUB_DESCRIPTION + "\n"
    row = to_preview(web, pid, url, blank_body={**BLANK, "description": blank})
    assert create(web, pid, row["id"], priority="Critical").status_code == 200
    job = hub_job(web, body={"id": 555})
    assert job["body"]["description"].endswith("\n" + blank)
    hub_job(web, body={"id": 555, "summary": TITLE, "linkedIssues": [{"id": 510001, "type": "SAST"}],
                       "description": job["body"]["description"] + "\n" + blank})
    assert db.hub_defect(row["id"])["state"] == "done"


def test_glued_block_with_same_text_keeps_the_hub_description(web):
    pid, row = ready(web, build=False)
    db = web.app.state.db
    glued = hub_body(description="<div><p>Тот же текст.</p>" + HUB_BLOCK + "<p>Комментарий рецензента.</p></div>")
    with db._tx() as c:
        c.execute("UPDATE hub_defects SET draft_command_text = ?, blank_json = ? WHERE id = ?",
                  ("Тот же текст.", json.dumps({"description": HUB_BLOCK}), row["id"]))
    row = db.hub_defect(row["id"])
    update_preview(web, pid, row, glued)
    assert phase(db, row["id"]) == "cancelled" and "Изменений для отправки нет" in note(db, row["id"])


# ============================================================================ круг 5 ревью


def test_text_quoted_inside_the_hub_block_is_not_a_repeat():
    text = "Параметризовать запрос."
    block = "<h3>Информация об объекте сканирования:</h3><p>Комментарий: Параметризовать запрос.</p>"
    assembled, problem = hub_defects.update_description(text, block)
    assert problem == "" and assembled == hub_defects.description_html(text, block)
    _, problem = hub_defects.update_description("Текст.\n\nТекст.", block)
    assert problem == "" , "повтор внутри текста – один абзац текста целиком"


def test_kept_description_has_no_block_warning(web):
    pid, row = ready(web, build=False)
    db = web.app.state.db
    glued = hub_body(description="<div><p>Тот же текст.</p>" + HUB_BLOCK + "<p>Комментарий рецензента.</p></div>",
                     summary="ID5 - Прежний (SAST)")
    with db._tx() as c:
        c.execute("UPDATE hub_defects SET draft_command_text = ?, draft_summary = ?, blank_json = ? WHERE id = ?",
                  ("Тот же текст.", "ID5 - Новый заголовок (SAST)", json.dumps({"description": HUB_BLOCK}), row["id"]))
    row = db.hub_defect(row["id"])
    update_preview(web, pid, row, glued)
    state = hub_defects.update_state(db.hub_defect(row["id"]))
    assert state["phase"] == "preview", note(db, row["id"])
    assert state["block_mode"] == "kept" and state["kept_description"] is True
    assert not any("не выделяется" in w for w in state["warnings"]), state["warnings"]


# ============================================================================ круг 6 ревью


def test_list_inside_the_hub_block_does_not_disable_the_numbering_check():
    text = "Рекомендация:\n1) А\n2) Б"
    block = "<h3>Информация об объекте сканирования:</h3><ul><li>Категория</li></ul>"
    sent = {"summary": "T", "description": hub_defects.description_html(text, block)}
    assert hub_defects.update_content_new({"summary": "T", "description": sent["description"]}, sent)
    numbered = "<p>Рекомендация:</p><ol><li>А</li><li>Б</li></ol>\n" + block
    assert not hub_defects.update_content_new({"summary": "T", "description": numbered}, sent), "разбор подставил список"


def test_blank_with_trailing_newline_appended_without_separator(web):
    pid, url = sast_ready(web)
    db = web.app.state.db
    hello(web)
    blank = HUB_DESCRIPTION + "\n"
    row = to_preview(web, pid, url, blank_body={**BLANK, "description": blank})
    assert create(web, pid, row["id"], priority="Critical").status_code == 200
    job = hub_job(web, body={"id": 555})
    hub_job(web, body={"id": 555, "summary": TITLE, "linkedIssues": [{"id": 510001, "type": "SAST"}],
                       "description": job["body"]["description"] + blank})
    assert db.hub_defect(row["id"])["state"] == "done"
