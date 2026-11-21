"""LTA-002 (итоговая проверка): ответ и дефект SCA из одного снимка, номер ответа агента в форме, занятая база.

Замечания: клиент получал новый answer_id, не увидев нового ответа; db.snapshot() не включал находку и состав группы;
отпечаток дефекта допускал цикл A -> B -> A; под замком шли форматирование и обращения к справочникам; SQLITE_BUSY и
ожидание замка не превращались в понятный отказ.
"""

from __future__ import annotations

import threading
import time
from unittest.mock import patch

import pytest

from app import db as db_module
from app import defect, sca
from app.db import Database, DatabaseBusy, StaleReview
from app.models import Finding
from app.routes.sca import answer_signature
from test_audit_lta001b import reimport
from test_audit_lta002 import AS_JSON, FP_REASON, Case, answer  # noqa: F401
from test_audit_lta003 import sca_finding  # noqa: F401
from test_sca import form_fields
from test_web import ORIGIN, prepared, web  # noqa: F401


@pytest.fixture
def case(web):  # noqa: F811
    return Case(web)


def save_json(case, fields: dict, *, decision: str = "agree", comment: str = FP_REASON, verdict: str = "", reviewed: str = "1",
              action: str = "save"):
    data = {**fields, "decision": decision, "reviewed": reviewed, "action": action, "comment": comment}
    if verdict:
        data["final_verdict"] = verdict
    return case.web.client.post(f"{case.url}/review", headers=AS_JSON, data=data)


def after_commit(case, action):
    """Подмена db.save_review: после настоящей записи (COMMIT) один раз выполняется action, затем ответ собирается."""
    original = case.db.save_review
    fired = []

    def wrapper(*args, **kwargs):
        result = original(*args, **kwargs)
        if not fired:
            fired.append(True)
            action()
        return result

    return patch.object(case.db, "save_review", side_effect=wrapper)


# ============================================================================ (2) номер ответа агента в форме

def test_two_submissions_after_a_moved_answer_never_check_an_unseen_answer(case):
    """Согласие с A (рекомендация 1.1); сразу после записи приходит B с тем же выводом update, но другой рекомендацией.
    Ответ сохранения не передаёт форме номер B; вторая отправка с тем же токеном отклоняется; проверенное согласие с
    ответом, которого человек не видел, не возникает."""
    case.put("агент 1", "update", "Ответ A", "1.1.0")
    fields = case.fields()
    answer_a = case.db.sca_answers(case.pid, case.f.component, case.f.version, "maven")[0]
    with after_commit(case, lambda: case.put("агент 1", "update", "Ответ B", "2.0.0")):
        first = save_json(case, fields, comment="Обновить до 1.1.0.")
    assert first.status_code == 200, first.text
    body = first.json()
    latest = case.db.sca_answers(case.pid, case.f.component, case.f.version, "maven")[0]
    assert latest["id"] != answer_a["id"] and latest["recommended_version"] == "2.0.0"
    assert body["answer_moved"] is True and body["reviewed"] is False
    assert body["answer_id"] == str(answer_a["id"]), "форма остаётся с ответом, который видел человек"
    assert body["current_answer_id"] == str(latest["id"]) and "новый ответ" in body["notice"]

    # вторая отправка: токен ответа и редакция – из ответа сервера, согласие и «Проверено» поставлены вновь
    second = save_json(case, {**fields, "answer_id": body["answer_id"], "review_revision": str(body["revision"])})
    assert second.status_code == 409 and second.json()["reason"] == "answer", second.text
    stored = case.review()
    assert stored["reviewed"] == 0 and stored["answer_sig"] == answer_signature(answer_a), \
        "ни «Проверено», ни подпись ответа B не записаны"
    assert case.reviewed_count() == 0

    # после обновления карточки (виден ответ B, токен B) сохранение проходит и подпись – ответа B
    fresh = case.fields()
    assert fresh["answer_id"] == str(latest["id"])
    third = save_json(case, fresh)
    assert third.status_code == 200 and third.json()["reviewed"] is True
    assert case.review()["answer_sig"] == answer_signature(latest)


def test_card_shows_the_new_answer_before_the_token_is_replaced(case):
    """Страница после обновления показывает полный новый ответ и рекомендацию вместе с новым токеном."""
    case.put("агент 1", "update", "Ответ A", "1.1.0")
    case.put("агент 1", "update", "Ответ B-для-страницы", "2.0.0")
    page = case.web.client.get(case.url).text
    latest = case.db.sca_answers(case.pid, case.f.component, case.f.version, "maven")[0]
    assert "Ответ B-для-страницы" in page and "2.0.0" in page
    assert f'name="answer_id" value="{latest["id"]}"' in page


# ============================================================================ (3) ответ из одного снимка

def set_fixed_version(case, value: str) -> None:
    def change(f: Finding) -> None:
        if f.hub_id == case.f.hub_id:
            f.fixed_version = value

    reimport(case.web, case.pid, change)


def test_changed_fixed_version_after_commit_is_reflected_in_the_text(case):
    """Версия исправления не входит в подпись решения, поэтому решение остаётся действующим; ответ собирается по
    новым данным находки и предупреждает о них. Короткий текст 0.9.8 – только обоснование оператора."""
    set_fixed_version(case, "1.1.0")
    case.db.save_sca_answers(case.pid, "агент 1", [])  # без изменений
    fields = case.fields()
    with after_commit(case, lambda: set_fixed_version(case, "2.0.0")):
        r = save_json(case, fields, decision="disagree", verdict="false_positive", action="copy")
    assert r.status_code == 200, r.text
    body = r.json()
    # у находки только AST: компонент и обоснование (ADR-0101); версии исправления из Hub в тексте нет
    assert body["hub_text"] == "example-parser 1.4.2: " + FP_REASON and "1.1.0" not in body["hub_text"]
    assert body["copy_allowed"] is True and body["reviewed"] is True
    assert "данные находки изменились" in body["notice"]


def test_finding_vanishing_after_commit_forbids_copying(case):
    fields = case.fields()
    with after_commit(case, lambda: reimport(case.web, case.pid, drop={case.f.hub_id})):
        r = save_json(case, fields, decision="disagree", verdict="false_positive", comment="Не применимо.",
                      action="copy")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["copy_allowed"] is False and body["defect_ready"] is False
    assert "пропала из выгрузки" in body["notice"]
    assert case.review()["final_comment"] == "Не применимо.", "решение записано (оно было в транзакции до пропажи)"


def test_project_deleted_after_commit_is_a_controlled_conflict(case):
    fields = case.fields()
    with after_commit(case, lambda: case.db.delete_project(case.pid)):
        r = save_json(case, fields, action="copy")
    assert r.status_code == 409 and r.json()["reason"] == "deleted", r.text


def test_deleted_decision_is_not_replaced_by_the_stale_record(case):
    """Запись решения исчезла между COMMIT и снимком: прежняя запись из памяти не подставляется."""
    fields = case.fields()

    def drop_review():
        with case.db._tx() as c:
            c.execute("DELETE FROM reviews WHERE project_id = ?", (case.pid,))

    with after_commit(case, drop_review):
        r = save_json(case, fields, action="copy")
    assert r.status_code == 409 and r.json()["reason"] == "deleted", r.text


# ============================================================================ (4) отпечаток и снимок: A -> B -> A

def issue(case, url: str):
    from test_sca import sca_text_ready
    sca_text_ready(case.web, url)  # текст набора дефекта (ADR-0091)
    return case.web.client.post(f"{url}/defect", headers=AS_JSON, data={"number": "", "confirm": "1"})


def decide_both(case) -> str:
    for hub_id in ("73001", "73002"):
        row = case.db.get_finding_by_hub_id(case.pid, hub_id)
        url = f"/projects/{case.pid}/sca/findings/{row['id']}"
        r = case.web.client.post(f"{url}/review", headers=AS_JSON, data={
            **form_fields(case.web.client.get(url).text), "decision": "disagree", "final_verdict": "true_positive",
            "comment": f"Обновить {hub_id}.", "reviewed": "1", "action": "save"})
        assert r.status_code == 200, r.text
    return case.url


def test_reads_of_the_group_cannot_interleave_with_imports_a_b_a(case):
    """Чтение участников группы остановлено посреди снимка; в это время импорт B и затем импорт A ждут замок. Снимок целиком
    описывает A, а после импортов отпечаток равен отпечатку снимка (значения те же), и текст соответствует состоянию."""
    set_fixed_version(case, "1.1.0")
    decide_both(case)
    real = Database._sca_answer_row
    reading, release = threading.Event(), threading.Event()

    def paused(row):
        reading.set()  # группа уже прочитана, ответы читаются
        assert release.wait(10)
        return real(row)

    snapshots, finished = [], []

    def take():
        snapshots.append(case.db.sca_snapshot(case.pid, "73001"))

    def flip():
        set_fixed_version(case, "2.0.0")  # B
        set_fixed_version(case, "1.1.0")  # A
        finished.append(time.monotonic())

    with patch.object(Database, "_sca_answer_row", staticmethod(paused)):
        reader = threading.Thread(target=take)
        reader.start()
        assert reading.wait(10)
        writer = threading.Thread(target=flip)
        writer.start()
        writer.join(30)
        assert finished, "импорты не ждут снимок, но в него не попадают: он видит состояние на своё начало"
        release.set()
    reader.join(10)
    writer.join(10)
    [snap] = snapshots
    assert {m["hub_id"]: m["data"].get("fixed_version") for m in snap._members}["73001"] == "1.1.0", "снимок целиком – A"
    assert finished and case.db.sca_defect_fingerprint(case.pid, "73001") == snap.fingerprint, \
        "значения вернулись к A: отпечаток тот же, и текст из снимка A соответствует нынешнему состоянию"


def test_number_is_not_written_for_a_changed_state_and_is_for_an_equal_one(case):
    set_fixed_version(case, "1.1.0")
    decide_both(case)
    snap = case.db.sca_snapshot(case.pid, "73001")
    set_fixed_version(case, "2.0.0")
    with pytest.raises(StaleReview):
        case.db.set_sca_defect_number_checked(case.pid, "k1", 5, "73001", snap.fingerprint)
    set_fixed_version(case, "1.1.0")  # снова A
    assert case.db.set_sca_defect_number_checked(case.pid, "k1", 5, "73001", snap.fingerprint) == []
    assert case.db.defect_number(case.pid, "k1") == 5


def test_defect_text_comes_from_the_snapshot_not_from_later_reads(case):
    """Импорт B между снимком и построением текста не попадает в текст: он собирается только из данных снимка, а запись
    номера отклоняется, потому что состояние изменилось."""
    set_fixed_version(case, "1.1.0")
    url = decide_both(case)
    original = case.db.sca_snapshot

    def snapshot_then_import(*args, **kwargs):
        snap = original(*args, **kwargs)
        set_fixed_version(case, "2.0.0")  # B после снимка
        return snap

    from test_sca import sca_text_ready
    sca_text_ready(case.web, url)  # текст набора – до подмены снимка: её ловит только выдача
    with patch.object(case.db, "sca_snapshot", side_effect=snapshot_then_import):
        r = case.web.client.post(f"{url}/defect", headers=AS_JSON, data={"number": "", "confirm": "1"})
    assert r.status_code == 409, r.text
    assert case.db.defect_number(case.pid, defect.defect_key_sca(case.f.component, case.f.version, "maven")) is None


# ============================================================================ (9) замок: что держится под ним

def test_formatting_and_feeds_run_outside_the_lock(case):
    """Форматирование текста, готовность дефекта и обращения к справочникам БДУ идут вне замка базы."""
    set_fixed_version(case, "1.1.0")
    # 73002 ниже уходит в «ложное срабатывание»: в наборе остаётся только AST, а набор только с AST дефекта не даёт
    # (ADR-0101) – публичное соответствие для него
    case.db.save_ast_map([("AST-2026-000101", "CVE-2099-10002")])
    url = decide_both(case)
    held = []
    from app.feeds import FeedStore

    real_hub_text, real_bdu = sca.hub_text, FeedStore.bdu_by_cve

    def hub_text(*args, **kwargs):
        held.append(("hub_text", case.db._lock.owned()))
        return real_hub_text(*args, **kwargs)

    def bdu(self, *args, **kwargs):
        held.append(("bdu", case.db._lock.owned()))
        return real_bdu(self, *args, **kwargs)

    other = case.db.get_finding_by_hub_id(case.pid, "73002")["id"]
    other_url = f"/projects/{case.pid}/sca/findings/{other}"
    with patch("app.routes.sca.sca.hub_text", hub_text), patch.object(FeedStore, "bdu_by_cve", bdu):
        saved = case.web.client.post(f"{other_url}/review", headers=AS_JSON, data={
            **form_fields(case.web.client.get(other_url).text), "decision": "disagree",
            "final_verdict": "false_positive", "comment": FP_REASON, "reviewed": "1", "action": "copy"})
        issued = issue(case, url)
    assert saved.status_code == 200 and issued.status_code == 200, issued.text
    assert {name for name, _ in held} >= {"hub_text", "bdu"}
    assert not [x for x in held if x[1]], f"под замком базы: {held}"


# ============================================================================ (9) занятость базы и ожидание замка

def test_lock_wait_is_bounded(tmp_path, monkeypatch):
    database = Database(tmp_path / "triage.db")
    try:
        monkeypatch.setattr(db_module, "LOCK_TIMEOUT", 0.3)
        held, release = threading.Event(), threading.Event()

        def hold():
            with database._tx():
                held.set()
                release.wait(10)

        holder = threading.Thread(target=hold)
        holder.start()
        assert held.wait(5)
        started = time.monotonic()
        with pytest.raises(DatabaseBusy):
            database.create_project("ждёт замок писателя")
        assert time.monotonic() - started < 3, "ожидание ограничено"
        assert database.list_projects() == [], "чтение не ждёт запись"
        release.set()
        holder.join(10)
        assert database.create_project("после освобождения") > 0, "после освобождения база работает"
    finally:
        database.close()


def test_writer_lock_timeout_is_a_bounded_refusal_not_a_version_conflict(case, monkeypatch):
    fields = case.fields()
    monkeypatch.setattr(db_module, "LOCK_TIMEOUT", 0.2)
    held, release = threading.Event(), threading.Event()

    def hold():
        with case.db._tx():
            held.set()
            release.wait(30)

    holder = threading.Thread(target=hold)
    holder.start()
    assert held.wait(5)
    try:
        with pytest.raises(DatabaseBusy):
            case.db.save_review(case.pid, case.f.hub_id, decision="disagree", final_verdict="true_positive",
                                final_comment="x", reviewed=True)
        response = save_json(case, fields, decision="disagree", verdict="true_positive", comment="x")
    finally:
        release.set()
        holder.join(10)
    assert response.status_code == 503 and response.headers.get("retry-after") == "5", response.text
    assert "База данных занята" in response.json()["detail"] and "reason" not in response.json()
    assert case.review() is None, "ничего не записано, откат выполнен"
    assert save_json(case, fields, decision="disagree", verdict="true_positive", comment="x").status_code == 200


def test_lost_commit_is_not_a_busy_refusal_and_is_not_retried(case, monkeypatch):
    """Обрыв на COMMIT: страница называет результат неизвестным, без предложения повторить через несколько секунд."""
    import psycopg
    from app.storage import postgresql
    fields = case.fields()
    real = postgresql.Connection.execute
    failed = []

    def failing(self, query, params=None, **kw):
        if query == "COMMIT" and not failed:
            failed.append(query)
            raise psycopg.OperationalError("обрыв")
        return real(self, query, params, **kw)
    monkeypatch.setattr(postgresql.Connection, "execute", failing)
    response = save_json(case, fields, decision="disagree", verdict="true_positive", comment="x")
    monkeypatch.undo()
    assert response.status_code == 503 and "retry-after" not in response.headers, response.text
    assert "результат неизвестен" in response.text


def test_busy_database_gives_a_readable_page(case, monkeypatch):
    def busy(*args, **kwargs):
        raise DatabaseBusy(db_module.BUSY_TEXT)

    monkeypatch.setattr(case.db, "get_project", busy)
    page = case.web.client.get(f"/projects/{case.pid}", headers={"Accept": "text/html"})
    monkeypatch.undo()
    assert page.status_code == 503 and "База данных занята" in page.text
