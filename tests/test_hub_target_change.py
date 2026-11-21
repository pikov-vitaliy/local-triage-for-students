"""Цель записи в Hub сверяется в транзакции постановки (KIMI-12, бэклог 44): номер приложения Hub проекта или адрес
Hub, сменённые в другой вкладке между предпросмотром (сборкой запроса) и транзакцией постановки, – отказ без строки
операции и без запроса к Hub у «Подготовить дефект», «Создать», «Привязать к дефекту», статуса из карточки и «Отправить
выбранные в Hub»; со скриптом и без него. Подмена – как в воспроизведении аудита: настройка меняется прямо перед
транзакцией. Статус из карточки и «Отправить выбранные» сверяют назначение, которое показала форма (поля hub_base и
hub_app_id): смена между показом формы и отправкой – тоже отказ, формы без этих полей – отказ. Та же цель после
возврата прежнего значения (или сохранённая заново) запись не останавливает. Данные, адреса и номера выдуманы."""

from __future__ import annotations

import dataclasses
from datetime import date
from types import SimpleNamespace

import pytest

from app.db import Database
from app.routes import hub_bulk, hub_status_routes
from app.routes.hub_status_routes import StaleTarget, hub_target_check
from test_defect import save_sast
from test_hub_bulk import AS_PAGE, preview, target_fields_of, targets_of
from test_hub_bulk import send as send_selected
from test_hub_defect_guard import card_of, created, link_fields
from test_hub_defects import FIX, REASON, blank, cancel, create, hub_job, no_job, pair_project, sast_ready, shown
from test_hub_defects import to_preview
from test_hub_status_routes import AS_JSON, HUB, decide, fid, project, sast, send, send_fields_of, shown_send_fields
from test_web import ORIGIN, web  # noqa: F401

OTHER_HUB = "https://hub2.example.org"
CHANGED_PREVIEW = "изменились после предпросмотра"
CHANGED_REQUEST = "изменились, пока собирался запрос"
CHANGED_CARD = "изменились, пока карточка была открыта"  # статус из карточки: назначение формы
CHANGED_BULK = "изменились, пока открыт предпросмотр"  # «Отправить выбранные»: назначение формы


@pytest.fixture(autouse=True)
def fixed_today(monkeypatch):
    """Срок 2027-01-26 – от «сегодня» 28.10.2026 (у hub_bulk своя ссылка today)."""
    monkeypatch.setattr(hub_status_routes, "today", lambda: date(2026, 10, 28))
    monkeypatch.setattr(hub_bulk, "today", lambda: date(2026, 10, 28))


# ============================================================================ помощники


def change_before(monkeypatch, db: Database, method: str, change) -> None:
    """db.<method> (транзакция постановки) сначала выполняет change(): другая вкладка сменила номер приложения или
    адрес Hub после того, как маршрут прочитал проект и настройки (чередование воспроизведения аудита)."""
    original = getattr(db, method)

    def wrapped(*args, **kwargs):
        change()
        return original(*args, **kwargs)

    monkeypatch.setattr(db, method, wrapped)


def flips(db: Database, pid: int, what: str):
    """(сменить, вернуть): номер приложения Hub проекта 7 → 8 или адрес Hub на другой и обратно."""
    if what == "app":
        return (lambda: db.update_project(pid, hub_app_id=8)), (lambda: db.update_project(pid, hub_app_id=7))
    return (lambda: db.set_settings({"hub_url": OTHER_HUB})), (lambda: db.set_settings({"hub_url": HUB}))


def ops(db: Database, purpose: str) -> list[dict]:
    return [o for o in db.hub_ops_list() if o["purpose"] == purpose]


# ============================================================================ дефект: «Создать»


@pytest.mark.parametrize("what", ["app", "hub"])
def test_create_refuses_when_the_target_changed_before_the_transaction(web, monkeypatch, what):
    """Воспроизведение аудита: предпросмотр с appId=7, перед транзакцией «Создать» приложение стало 8 (или сменился
    адрес Hub) – отказ 400, строка остаётся в предпросмотре, POST /defects не поставлен. Прежнее значение вернули –
    «Создать» проходит с appId=7."""
    pid, url = sast_ready(web)
    db = web.app.state.db
    row = to_preview(web, pid, url)
    assert row["app_id"] == 7 and row["hub_url"] == HUB
    change, restore = flips(db, pid, what)
    with monkeypatch.context() as m:
        change_before(m, db, "hub_defect_advance", change)
        r = create(web, pid, row["id"])
    assert r.status_code == 400 and CHANGED_PREVIEW in r.json()["detail"], r.text
    assert "Отменить предпросмотр" in r.json()["detail"]
    assert db.hub_defect(row["id"])["state"] == "preview"
    assert ops(db, "defect_create") == []
    no_job(web)
    restore()
    r = create(web, pid, row["id"])
    assert r.status_code == 200, r.text
    job = hub_job(web, body={"id": 555})
    assert job["purpose"] == "defect_create" and job["path"] == "/defects" and job["body"]["appId"] == 7
    assert db.hub_defect(row["id"])["state"] == "created"


def test_create_after_the_app_changed_is_refused_without_script_and_a_new_preview_takes_the_new_app(web):
    """Приложение сменили до нажатия «Создать»: отказ и без скрипта (страница ошибки, 400), POST не поставлен;
    «Отменить предпросмотр» и новая заготовка – уже по приложению 8."""
    pid, url = sast_ready(web)
    db = web.app.state.db
    row = to_preview(web, pid, url)
    db.update_project(pid, hub_app_id=8)
    r = web.client.post(f"/projects/{pid}/hub/defects/{row['id']}/create", data={}, headers=ORIGIN,
                        follow_redirects=False)
    assert r.status_code == 400 and CHANGED_PREVIEW in r.text, r.text[:500]
    assert db.hub_defect(row["id"])["state"] == "preview" and ops(db, "defect_create") == []
    no_job(web)
    assert cancel(web, pid, row["id"]).status_code == 200
    assert blank(web, url).status_code == 200
    job = hub_job(web)
    assert job["purpose"] == "defect_blank" and job["path"].startswith("/defects/blank?appId=8&")


def test_the_same_target_saved_again_after_the_preview_does_not_refuse(web):
    """Номер приложения и адрес Hub сохранили заново теми же (адрес – с косой чертой в конце: основа та же) – «Создать»
    проходит: сравнивается цель, а не факт сохранения."""
    pid, url = sast_ready(web)
    db = web.app.state.db
    row = to_preview(web, pid, url)
    db.update_project(pid, hub_app_id=7)
    db.set_settings({"hub_url": HUB + "/"})
    r = create(web, pid, row["id"])
    assert r.status_code == 200, r.text
    assert hub_job(web, body={"id": 556})["body"]["appId"] == 7


# ============================================================================ дефект: заготовка и привязка


@pytest.mark.parametrize("what", ["app", "hub"])
def test_blank_refuses_when_the_target_changed_before_the_transaction(web, monkeypatch, what):
    """«Подготовить дефект» (заготовка): приложение или адрес Hub сменились между сборкой запроса и транзакцией –
    отказ 400, ни строки дефекта, ни операций; прежнее значение вернули – заготовка ставится по appId=7."""
    pid, url = sast_ready(web)
    db = web.app.state.db
    fields = shown(web, url)
    change, restore = flips(db, pid, what)
    with monkeypatch.context() as m:
        change_before(m, db, "hub_defect_start", change)
        r = blank(web, url, fields)
    assert r.status_code == 400 and CHANGED_REQUEST in r.json()["detail"], r.text
    assert db.hub_defects(pid) == [] and db.hub_ops_list() == []
    no_job(web)
    restore()
    assert blank(web, url, fields).status_code == 200
    job = hub_job(web)
    assert job["purpose"] == "defect_blank" and job["path"].startswith("/defects/blank?appId=7&")


@pytest.mark.parametrize("what", ["app", "hub"])
def test_link_refuses_when_the_target_changed_before_the_transaction(web, monkeypatch, what):
    """«Привязать к дефекту»: готовый дефект выбран по приложению 7 и адресу Hub, перед транзакцией приложение стало 8
    (или сменился адрес Hub) – отказ 400, строки привязки и POST /defects/{id}/link нет, находка свободна; прежнее
    значение вернули – привязка ставится к тому же Hub и приложению 7."""
    pid = pair_project(web)
    db = web.app.state.db
    url, _ = save_sast(web, pid, "510001", "true_positive", "", REASON, FIX)
    created(web, pid, url)
    save_sast(web, pid, "510005", "true_positive", "", REASON, FIX)
    sibling = card_of(web, pid, "510005")
    fields = link_fields(web.client.get(sibling).text)
    rows = len(db.hub_defects(pid))
    change, restore = flips(db, pid, what)
    with monkeypatch.context() as m:
        change_before(m, db, "hub_defect_link_start", change)
        r = web.client.post(f"{sibling}/hub-defect-link", headers=AS_JSON, data=fields)
    assert r.status_code == 400 and CHANGED_REQUEST in r.json()["detail"], r.text
    assert len(db.hub_defects(pid)) == rows and ops(db, "defect_link") == []
    assert db.hub_defect_bound(pid, "510005") is None
    no_job(web)
    restore()
    r = web.client.post(f"{sibling}/hub-defect-link", headers=AS_JSON, data=fields)
    assert r.status_code == 200, r.text
    link = hub_job(web, body={})
    assert link["purpose"] == "defect_link" and link["path"] == "/defects/555/link"
    assert ops(db, "defect_link")[0]["app_id"] == 7 and ops(db, "defect_link")[0]["hub_url"] == HUB


# ============================================================================ статус: карточка и «Отправить выбранные»


@pytest.mark.parametrize("what", ["app", "hub"])
def test_status_from_the_card_refuses_when_the_target_changed(web, monkeypatch, what):
    """Воспроизведение аудита для статуса: перед транзакцией постановки приложение стало 8 (или сменился адрес Hub) –
    отказ 400 со скриптом и без, операции нет; прежнее значение вернули – статус ставится с app_id=7."""
    pid = project(web, [sast("101")])
    decide(web, pid, "101")
    db = web.app.state.db
    change, restore = flips(db, pid, what)
    with monkeypatch.context() as m:
        change_before(m, db, "hub_enqueue", change)
        r = send(web, pid, "101")
    assert r.status_code == 400 and CHANGED_CARD in r.json()["detail"], r.text
    assert db.hub_ops_list() == []
    restore()
    page_data = {"expires": "2027-01-26", "review_revision": str(db.get_review(pid, "101")["revision"]),
                 "finding_sig": db.finding_sig(pid, "101"), **shown_send_fields(web, pid, "101")}
    with monkeypatch.context() as m:
        change_before(m, db, "hub_enqueue", change)
        r = web.client.post(f"/projects/{pid}/findings/{db.get_finding_by_hub_id(pid, '101')['id']}/hub-status",
                            data=page_data, headers=ORIGIN, follow_redirects=False)
    assert r.status_code == 400 and CHANGED_CARD in r.text, r.text[:500]
    assert db.hub_ops_list() == []
    restore()
    r = send(web, pid, "101")
    assert r.status_code == 200, r.text
    op = db.hub_ops_list()[0]
    assert op["purpose"] == "status" and op["app_id"] == 7 and op["hub_url"] == HUB


@pytest.mark.parametrize("what", ["app", "hub"])
def test_send_selected_refuses_when_the_target_changed(web, monkeypatch, what):
    """«Отправить выбранные в Hub»: состав собран по приложению 7, перед транзакцией приложение стало 8 (или сменился
    адрес Hub) – страница предпросмотра с отказом 400 (без скрипта) и JSON 400, операции нет; прежнее значение
    вернули – одна операция status с app_id=7."""
    pid = project(web, [sast("101", 2), sast("105", 11)])
    decide(web, pid, "101")
    decide(web, pid, "105", comment="Другое обоснование.")
    db = web.app.state.db
    shown_targets = targets_of(preview(web, pid, "101", "105"))
    change, restore = flips(db, pid, what)
    with monkeypatch.context() as m:
        change_before(m, db, "hub_enqueue", change)
        r = send_selected(web, pid, shown_targets)
    assert r.status_code == 400 and CHANGED_BULK in r.text, r.text[:500]
    assert "обновите предпросмотр" in r.text and db.hub_ops_list() == []
    restore()
    with monkeypatch.context() as m:
        change_before(m, db, "hub_enqueue", change)
        r = send_selected(web, pid, shown_targets, headers=AS_JSON)
    assert r.status_code == 400 and CHANGED_BULK in r.json()["detail"], r.text
    assert db.hub_ops_list() == []
    restore()
    r = send_selected(web, pid, shown_targets)
    assert r.status_code == 303, r.text[:300]
    [op] = db.hub_ops_list()
    assert op["purpose"] == "status" and op["app_id"] == 7 and op["hub_url"] == HUB


# ============================================================================ статус: назначение, показанное формой


@pytest.mark.parametrize("what", ["app", "hub"])
def test_status_form_carries_the_shown_target_and_a_change_after_showing_refuses(web, what):
    """Форма «Отправить в Hub» карточки несёт назначение, которое показала карточка (адрес Hub и приложение 7). Его
    сменили в другой вкладке после показа карточки, а отправка ушла со старой формой: отказ 400 со скриптом и без него,
    операции и задания исполнителю нет – запрос не собирается для приложения 8 или другого Hub, которых оператор не
    видел. Обновлённая карточка показывает новое назначение – отправка проходит туда."""
    pid = project(web, [sast("101")])
    decide(web, pid, "101")
    db = web.app.state.db
    card = web.client.get(f"/projects/{pid}/findings/{fid(web, pid, '101')}").text
    form = send_fields_of(card)
    assert form["hub_base"] == HUB and form["hub_app_id"] == "7"
    data = {"expires": "2027-01-26", "review_revision": str(db.get_review(pid, "101")["revision"]),
            "finding_sig": db.finding_sig(pid, "101"), **form}
    change, _ = flips(db, pid, what)
    change()
    url = f"/projects/{pid}/findings/{fid(web, pid, '101')}/hub-status"
    r = web.client.post(url, data=data, headers=AS_JSON)
    assert r.status_code == 400 and CHANGED_CARD in r.json()["detail"], r.text
    r = web.client.post(url, data=data, headers=AS_PAGE, follow_redirects=False)
    assert r.status_code == 400 and CHANGED_CARD in r.text and "text/html" in r.headers["content-type"], r.text[:500]
    assert db.hub_ops_list() == []
    no_job(web)
    fresh = shown_send_fields(web, pid, "101")
    assert (fresh["hub_base"], fresh["hub_app_id"]) == ((HUB, "8") if what == "app" else (OTHER_HUB, "7"))
    r = web.client.post(url, data={**data, **fresh}, headers=AS_JSON)
    assert r.status_code == 200, r.text
    [op] = db.hub_ops_list()
    assert (op["hub_url"], op["app_id"]) == ((HUB, 8) if what == "app" else (OTHER_HUB, 7))


def test_status_form_without_the_target_fields_is_refused(web):
    """Форма без назначения (страница, открытая до обновления приложения) или с испорченным номером приложения – отказ:
    куда смотрел оператор, неизвестно."""
    pid = project(web, [sast("101")])
    decide(web, pid, "101")
    db = web.app.state.db
    for override in ({"hub_base": "", "hub_app_id": ""}, {"hub_app_id": "семь"}, {"hub_base": "hub.example.org"}):
        r = send(web, pid, "101", extra=override)
        assert r.status_code == 400 and r.json()["detail"] == hub_status_routes.CARD_FORM_OUTDATED, (override, r.text)
    assert db.hub_ops_list() == []
    assert send(web, pid, "101").status_code == 200


@pytest.mark.parametrize("what", ["app", "hub"])
def test_send_selected_form_carries_the_shown_target_and_a_change_after_showing_refuses(web, what):
    """Форма предпросмотра «Отправить выбранные» несёт назначение, по которому собран показанный состав (адрес Hub и
    приложение 7); его сменили после показа – отказ 400 без скрипта (страница предпросмотра с отказом и новым
    назначением в форме) и со скриптом, операции нет; отправка формы обновлённого предпросмотра проходит."""
    pid = project(web, [sast("101", 2), sast("105", 11)])
    decide(web, pid, "101")
    decide(web, pid, "105", comment="Другое обоснование.")
    db = web.app.state.db
    html = preview(web, pid, "101", "105")
    form = target_fields_of(html)
    assert form == {"hub_base": HUB, "hub_app_id": "7"}
    change, _ = flips(db, pid, what)
    change()
    r = send_selected(web, pid, targets_of(html), shown=form)
    assert r.status_code == 400 and CHANGED_BULK in r.text, r.text[:500]
    new = (HUB, "8") if what == "app" else (OTHER_HUB, "7")
    assert tuple(target_fields_of(r.text).values()) == new, "страница отказа – уже с новым назначением"
    r = send_selected(web, pid, targets_of(html), shown=form, headers=AS_JSON)
    assert r.status_code == 400 and CHANGED_BULK in r.json()["detail"], r.text
    r = send_selected(web, pid, targets_of(html), shown={})
    assert r.status_code == 400 and hub_bulk.FORM_OUTDATED in r.text, "форма без назначения – страница до обновления"
    assert db.hub_ops_list() == []
    no_job(web)
    fresh = preview(web, pid, "101", "105")
    r = send_selected(web, pid, targets_of(fresh), shown=target_fields_of(fresh))
    assert r.status_code == 303, r.text[:300]
    [op] = db.hub_ops_list()
    assert (op["hub_url"], str(op["app_id"])) == new


# ============================================================================ сама проверка


def test_target_check_reads_the_hub_address_as_the_settings_page_does(web, monkeypatch):
    """hub_target_check читает в транзакции то же, что settings_of: адрес из базы поверх значения из окружения
    (нет записи или она испорчена – значение окружения); номер приложения не задан или пустая показанная цель – отказ."""
    db = web.app.state.db
    pid = project(web, [sast("101")])
    request = SimpleNamespace(app=web.app)
    state = web.app.state.web
    monkeypatch.setattr(state, "base", dataclasses.replace(state.base, hub_url=HUB))

    def passes(hub_url: str = HUB, app_id=7) -> bool:
        try:
            db.hub_enqueue_many([], check=hub_target_check(request, pid, hub_url, app_id))
        except StaleTarget:
            return False
        return True

    assert passes() and passes(HUB + "/") and not passes(OTHER_HUB) and not passes(app_id=8)
    assert not passes(hub_url="") and not passes(app_id=None)
    db.set_settings({"hub_url": OTHER_HUB})
    assert not passes() and passes(OTHER_HUB)
    with db._tx() as c:  # записи нет – действует адрес из окружения
        c.execute("DELETE FROM settings WHERE key = 'hub_url'")
    assert passes()
    with db._tx() as c:  # испорченная запись пропускается, как у get_settings
        c.execute("INSERT INTO settings(key, value_json, updated_at) VALUES ('hub_url', '{', '2026-10-28')")
    assert passes()
    db.update_project(pid, hub_app_id=None)
    assert not passes()
