"""О9 (предложения дизайнера): у SAST и SCA своя панель дефекта поверх общего каркаса – у каждой своё пояснение,
чужого нет; предпросмотр короткого комментария ложного срабатывания раскрыт сразу. Данные выдуманы."""

from __future__ import annotations

import re

from test_defect import save_sast
from test_sca import sca_card
from test_web import prepared, start_run, wait_run, web  # noqa: F401

SAST_HINT = "Дефект создаётся из отмеченных галочкой находок"
SCA_HINT = "Короткий текст для Hub (кнопка внизу) – в комментарий к смене статуса находки."


def test_sast_and_sca_panels_have_their_own_hint(web):  # noqa: F811
    pid = prepared(web)
    assert wait_run(web, start_run(web, pid))["state"] == "done"
    web.app.state.db.set_settings({"team_name": "Платформа"})
    url, _ = save_sast(web, pid, "510001", "disagree", "true_positive",
                       "Подтверждено: owner из запроса попадает в SQL без параметров.")
    sast = web.client.get(url).text
    assert 'id="defect-panel"' in sast and SAST_HINT in sast and SCA_HINT not in sast
    _, sca = sca_card(web, pid, "73002")
    assert 'id="defect-panel"' in sca and SCA_HINT in sca and SAST_HINT not in sca


def test_false_positive_preview_is_open(web):  # noqa: F811
    pid = prepared(web)
    assert wait_run(web, start_run(web, pid))["state"] == "done"
    url, _ = save_sast(web, pid, "510001", "disagree", "false_positive",
                       "Значение берётся из константы, подстановки нет.")
    page = web.client.get(url).text
    assert re.search(r'<details class="hub-preview" id="hub-preview" open>', page), "предпросмотр раскрыт"
