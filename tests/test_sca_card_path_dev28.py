"""0.9.26.dev28: путь оператора SCA без лишней прокрутки: страница не прыгает вверх-вниз,
в карточке сразу видно, что советуют модели и какой результат разбора. Данные выдуманы."""

import re
from urllib.parse import quote

from test_defect_links import defect, seed
from test_hub_defects import hub_settings
from test_sca import ORIGIN, form_fields, sca_card, sca_text_ready
from test_sca_package_decision import FP, UPD, package_fields
from test_web import prepared, web  # noqa: F401


def db_fid(web, pid: int, hub_id: str) -> int:
    return int(web.app.state.db.get_finding_by_hub_id(pid, hub_id)["id"])


def save(web, pid: int, hub_id: str, apply_to: list[str] | None = None, **decision):
    """Решение формой карточки без JSON: ответ – редирект, по нему видно, куда откроется страница."""
    fid, card = sca_card(web, pid, hub_id)
    data = {**form_fields(card), **package_fields(card), "apply_to": apply_to or [hub_id], "reviewed": "1",
            "action": "save", **decision}
    r = web.client.post(f"/projects/{pid}/sca/findings/{fid}/review", data=data, headers=ORIGIN, follow_redirects=False)
    assert r.status_code in (302, 303), r.text
    return fid, r.headers["location"]


def test_card_opens_on_the_next_step_after_saving(web):
    pid = prepared(web)
    hub_settings(web, pid)
    both = ["73001", "73002"]  # решение на весь набор: иначе плашка «Перед выдачей дефекта» держит текст не готовым
    fid, location = save(web, pid, "73001", apply_to=both, **UPD)  # «Обновить» – к дефекту по шаблону команды
    assert location.endswith(f"/sca/findings/{fid}?ok=sca_saved#sca-set"), location  # текста ещё нет – к набору
    url = f"/projects/{pid}/sca/findings/{fid}"
    sca_text_ready(web, url)
    _, location = save(web, pid, "73001", apply_to=both, **UPD)  # текст утверждён – к блоку «Создать дефект в Hub»
    assert location.endswith("?ok=sca_saved#hub-defect-section"), location  # блок создания теперь в своей панели (dev9)
    assert 'id="hub-defect-button"' in web.client.get(url).text
    back = f"/projects/{pid}/sca?group_by=family&family=x&page=1"
    card = web.client.get(f"{url}?back={quote(back, safe='')}").text
    # адрес возврата (без якоря: его добавляет видимая ссылка) уходит в заготовку, а из неё – в карточку дефекта
    assert f'/hub-defect?back={quote(back, safe="/")}' in card, "заготовка дефекта передаёт адрес возврата"
    _, location = save(web, pid, "73002", **FP)  # ложное срабатывание – к «Отправить в Hub»
    assert location.endswith("?ok=sca_saved#hub-send"), location


def test_approving_the_text_leads_to_the_create_block(web):
    pid = prepared(web)
    hub_settings(web, pid)
    fid, _ = save(web, pid, "73001", **UPD)
    url = f"/projects/{pid}/sca/findings/{fid}"
    card = web.client.get(url).text
    revision = re.search(r'name="text_revision" value="(\d+)"', card).group(1)
    r = web.client.post(f"{url}/package-text", data={"text_revision": revision, "target_version": "9.9.9"},
                        headers=ORIGIN, follow_redirects=False)
    # текст ещё не готов – к перечню условий (dev9); готовый текст ведёт к созданию: tests/e2e/test_dev9_operator_flow.py
    assert r.status_code in (302, 303) and r.headers["location"].endswith("?ok=sca_text_saved#sca-set-problems"), r.headers


def test_summary_line_under_the_title(web):
    pid = prepared(web)
    hub_settings(web, pid)
    fid, card = sca_card(web, pid, "73001")
    summary = re.search(r'<p class="finding-summary[^"]*" id="finding-summary">.*?</p>', card, re.S).group(0)
    assert "Исследование: <strong>не проводилось" in summary and "finding-summary-decision\">не принято" in summary
    assert "Дефект: <strong>нет" in summary
    save(web, pid, "73001", **UPD)
    summary = re.search(r'id="finding-summary">.*?</p>', web.client.get(f"/projects/{pid}/sca/findings/{fid}").text, re.S).group(0)
    assert 'Решение: <strong id="finding-summary-decision">обновить, проверено' in summary
    # сохранение копированием (AJAX) – ответ несёт строку для сводки
    from test_sca import AS_JSON
    _, card = sca_card(web, pid, "73002")
    answer = web.client.post(f"/projects/{pid}/sca/findings/{int(db_fid(web, pid, '73002'))}/review", headers=AS_JSON,
                             data={**form_fields(card), **package_fields(card), "apply_to": ["73002"], "action": "copy",
                                   **FP}).json()
    assert answer["summary_decision"] == "не применимо"


def test_back_to_the_list_goes_to_the_table_and_defect_card_keeps_it(web):
    pid = seed(web)
    hub_settings(web, pid)
    db = web.app.state.db
    back = f"/projects/{pid}/sca?group_by=family&family=x&page=1"
    fid = int(db.get_finding_by_hub_id(pid, "910124")["id"])
    card = web.client.get(f"/projects/{pid}/sca/findings/{fid}?back={quote(back, safe='')}").text
    assert f'href="{back}#components"'.replace("&", "&amp;") in card, "возврат – к таблице библиотек"
    # карточка дефекта: «К списку SCA» с тем же отбором; без back – к списку своего вида
    row = defect(web, pid, "SCA", ["910124"], 9)
    page = web.client.get(f"/projects/{pid}/defects/{row['id']}?back={quote(back, safe='')}").text
    assert f'id="defect-back" href="{back}#components">← К списку SCA'.replace("&", "&amp;") in page
    assert f'name="back_to" value="{back}"'.replace("&", "&amp;") in page, "действия карточки (Push и другие) несут адрес возврата"
    plain = web.client.get(f"/projects/{pid}/defects/{row['id']}").text
    assert f'id="defect-back" href="/projects/{pid}/sca#components">← К списку SCA' in plain
    # из общего списка находок – обратно в него, с теми же отборами; действия форм карточки несут адрес возврата
    findings_back = f"/projects/{pid}/findings?kind=SCA&q=demo&page=2"
    page = web.client.get(f"/projects/{pid}/defects/{row['id']}?back={quote(findings_back, safe='')}").text
    assert f'id="defect-back" href="{findings_back}">← К списку находок'.replace("&", "&amp;") in page
    assert f'/defects/{row["id"]}/fields?back={quote(findings_back, safe="")}' in page.replace("&amp;", "&")
    other = f"/projects/{pid + 1}/sca"  # чужой проект – адрес не принимается
    page = web.client.get(f"/projects/{pid}/defects/{row['id']}?back={quote(other, safe='')}").text
    assert f'id="defect-back" href="/projects/{pid}/sca#components">← К списку SCA' in page
    # обзор групп: ссылка на группу – сразу у таблицы
    groups = web.client.get(f"/projects/{pid}/sca?group_by=family").text
    assert re.search(r'href="[^"]*family=[^"#]*#components"', groups), "ссылка группы без якоря таблицы"


def test_defects_tab_does_not_repeat_the_verification_note(web):
    from app.hub_defects import VERIFY_NOTE_DONE
    pid = seed(web)
    db = web.app.state.db
    row = defect(web, pid, "SCA", ["910124"], 9)
    db.hub_defect_update(row["id"], error=VERIFY_NOTE_DONE)
    page = web.client.get(f"/projects/{pid}/defects").text
    assert page.count(VERIFY_NOTE_DONE) == 1, "пометка строки повторяла текст состояния"


def test_defect_card_url_keeps_the_return_address():
    """Адрес возврата переживает заготовку (back из запроса), «Создать» и «Отменить» (back_to из формы карточки);
    служебное back=defect-card адресом возврата не считается."""
    from app.routes.hub_defect_routes import _card_url
    back = "/projects/1/sca?group_by=family&family=x&page=1#components"
    assert _card_url(1, 5, {"back": back}) == "/projects/1/defects/5?back=" + quote(back, safe="")
    assert _card_url(1, 5, {"back": "defect-card", "back_to": back}) == "/projects/1/defects/5?back=" + quote(back, safe="")
    assert _card_url(1, 5, {"back": "defect-card"}) == "/projects/1/defects/5"
    assert _card_url(1, 5, {}) == "/projects/1/defects/5"
    assert _card_url(1, 5, {"back_to": back}, ok="x") == "/projects/1/defects/5?ok=x&back=" + quote(back, safe="")
    assert _card_url(1, 5, {}, ok="x") == "/projects/1/defects/5?ok=x"
