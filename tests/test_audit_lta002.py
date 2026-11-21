"""LTA-002: проверка ответа агента и сохранение решения SCA – одна транзакция.

Замечание аудита 15.10.2026 (реестр – docs/state/audit-2026-10-15.md): маршрут проверял номер ответа до записи, и
ответ, загруженный между проверкой и записью, не мешал сохранить «Проверено» с отпечатком прежнего ответа.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from app import sca
from app.models import Finding, ScaAnswer
from test_sca import form_fields
from test_web import ORIGIN, prepared, web  # noqa: F401

AS_JSON = {**ORIGIN, "Accept": "application/json"}
HUB_ID = "73001"


FP_REASON = "Уязвимая функция разбора в продукте не вызывается."  # ложное срабатывание – только с обоснованием


def answer(conclusion: str = "not_applicable", text: str = "Ответ A", recommended: str = "", f: Finding | None = None):
    return ScaAnswer(component=f.component, version=f.version, conclusion=conclusion, explanation=text,
                     recommended_version=recommended, vulnerabilities=sca.finding_ids(f))


class Case:
    """Проект с находкой SCA 73001 и ответом агента A."""

    def __init__(self, web) -> None:  # noqa: F811
        self.web = web
        self.pid = prepared(web)
        self.db = web.app.state.db
        row = self.db.get_finding_by_hub_id(self.pid, HUB_ID)
        self.fid = row["id"]
        self.f = Finding.from_dict(row["data"])
        self.url = f"/projects/{self.pid}/sca/findings/{self.fid}"
        self.a = answer(f=self.f)
        self.db.save_sca_answers(self.pid, "агент 1", [self.a])

    def put(self, source: str, conclusion: str, text: str, recommended: str = ""):
        return self.db.save_sca_answers(self.pid, source, [answer(conclusion, text, recommended, self.f)])

    def fields(self) -> dict:
        return form_fields(self.web.client.get(self.url).text)

    def agree(self, fields: dict | None = None):
        return self.web.client.post(f"{self.url}/review", headers=AS_JSON, data={
            **(fields or self.fields()), "decision": "agree", "reviewed": "1", "action": "save",
            "comment": FP_REASON})

    def review(self) -> dict | None:
        return self.db.get_review(self.pid, HUB_ID)

    def reviewed_count(self) -> int:
        return int(self.db.review_stats(self.pid).get("sca_reviewed") or 0)


@pytest.fixture
def case(web):  # noqa: F811
    return Case(web)


def interleave(case: Case, action):
    """Второй завершённый запрос ровно между проверкой страницы и транзакцией решения (как в воспроизведении аудита)."""
    original = case.db.save_review

    def injected(*args, **kwargs):
        action()
        return original(*args, **kwargs)

    return patch.object(case.db, "save_review", side_effect=injected)


# ============================================================================ критерий 1: оба порядка

def test_answer_loaded_between_check_and_write_gives_conflict(case):
    """Воспроизведение аудита: ответ B появился между проверкой и записью – решение не сохранено, 409."""
    fields = case.fields()
    with interleave(case, lambda: case.put("агент 1", "update", "Ответ B", "99.0.0")):
        r = case.agree(fields)
    assert r.status_code == 409 and r.json()["reason"] == "answer", r.text
    assert case.review() is None, "решение не записано"
    assert case.reviewed_count() == 0


def test_answer_loaded_after_the_decision_reopens_it(case):
    """Другой порядок: решение записано первым, ответ B – вторым: «Проверено» снято, редакция выросла."""
    r = case.agree()
    assert r.status_code == 200 and case.review()["reviewed"] == 1 and case.reviewed_count() == 1
    revision = case.review()["revision"]
    stats = case.put("агент 1", "update", "Ответ B", "99.0.0")
    assert stats["reopened"] == 1
    review = case.review()
    assert review["reviewed"] == 0 and review["decision"] == "agree", "решение и история остаются"
    assert review["revision"] == revision + 1, "затронутое решение получает новую редакцию"
    assert case.reviewed_count() == 0


def test_stale_page_cannot_overwrite_after_the_answer_update(case):
    fields = case.fields()
    assert case.agree(fields).status_code == 200
    case.put("агент 1", "update", "Ответ B", "99.0.0")
    r = case.agree(fields)
    assert r.status_code == 409 and r.json()["reason"] in ("answer", "revision")
    assert case.review()["reviewed"] == 0


# ============================================================================ критерий 2: старое согласие

def test_old_agreement_never_becomes_reviewed_after_the_update(case):
    assert case.agree().status_code == 200
    case.put("агент 1", "update", "Ответ B", "99.0.0")
    assert case.review()["reviewed"] == 0
    # отметка «Проверено» отдельным запросом (клавиша v) для согласия по прежнему ответу – отказ
    fields = case.fields()
    r = case.web.client.post(f"{case.url}/reviewed", headers=AS_JSON, data={
        "reviewed": "1", "finding_version": fields["finding_version"], "review_revision": fields["review_revision"]})
    assert r.status_code == 409 and r.json()["reason"] == "answer", r.text
    assert case.review()["reviewed"] == 0 and case.reviewed_count() == 0
    # без полей страницы (скрипт без редакции) – тоже
    r = case.web.client.post(f"{case.url}/reviewed", headers=AS_JSON, data={"reviewed": "1"})
    assert r.status_code == 409 and case.review()["reviewed"] == 0


def test_new_decision_by_the_current_answer_is_accepted(case):
    case.put("агент 1", "update", "Ответ B", "99.0.0")
    r = case.agree()
    assert r.status_code == 200 and case.review()["reviewed"] == 1
    fields = case.fields()
    r = case.web.client.post(f"{case.url}/reviewed", headers=AS_JSON, data={
        "reviewed": "1", "finding_version": fields["finding_version"], "review_revision": fields["review_revision"]})
    assert r.status_code == 200, "по текущему ответу отметка ставится"


# ============================================================================ критерий 3: источники, A→B→A, нет решения

def test_same_source_replacement_between_check_and_write(case):
    fields = case.fields()
    with interleave(case, lambda: case.put("агент 1", "not_applicable", "Ответ A, другой текст")):
        r = case.agree(fields)
    assert r.status_code == 409 and r.json()["reason"] == "answer", "замена тем же источником – другой номер ответа"


def test_new_source_between_check_and_write(case):
    fields = case.fields()
    with interleave(case, lambda: case.put("агент 2", "update", "Ответ второго агента", "2.0.0")):
        r = case.agree(fields)
    assert r.status_code == 409 and r.json()["reason"] == "answer"
    assert case.review() is None


def test_cycle_a_b_a_between_check_and_write(case):
    """A → B → A: к записи содержимое снова как у A, но это новые записи – страница с прежним номером не проходит."""
    fields = case.fields()

    def cycle():
        case.put("агент 1", "update", "Ответ B", "99.0.0")
        case.put("агент 1", "not_applicable", "Ответ A")

    with interleave(case, cycle):
        r = case.agree(fields)
    assert r.status_code == 409 and r.json()["reason"] == "answer"
    assert case.review() is None
    # со свежей страницы сохранение проходит и ставит отпечаток текущего ответа
    r = case.agree()
    assert r.status_code == 200 and case.review()["reviewed"] == 1


def test_no_previous_decision_and_answer_arrives(case):
    assert case.review() is None
    fields = case.fields()
    assert fields["review_revision"] == "0"
    with interleave(case, lambda: case.put("агент 1", "update", "Ответ B", "99.0.0")):
        r = case.agree(fields)
    assert r.status_code == 409
    assert case.review() is None, "пустое решение не создаётся"


def test_page_without_answer_field_is_checked_against_the_answer_read_before_the_write(case):
    """Старая страница без номера ответа: ожидаемым считается ответ, прочитанный маршрутом перед записью."""
    fields = case.fields()
    fields.pop("answer_id")
    with interleave(case, lambda: case.put("агент 1", "update", "Ответ B", "99.0.0")):
        r = case.agree(fields)
    assert r.status_code == 409 and r.json()["reason"] == "answer"
    assert case.agree(case.fields()).status_code == 200


def test_decision_without_any_answer_is_not_blocked(web):  # noqa: F811
    """Ответа агента нет вовсе: «Не согласен» сохраняется, как раньше (ожидаемый номер – пустой)."""
    pid = prepared(web)
    row = web.app.state.db.get_finding_by_hub_id(pid, HUB_ID)
    url = f"/projects/{pid}/sca/findings/{row['id']}"
    fields = form_fields(web.client.get(url).text)
    r = web.client.post(f"{url}/review", headers=AS_JSON, data={
        **fields, "decision": "disagree", "final_verdict": "true_positive", "comment": "Обновить.", "reviewed": "1",
        "action": "save"})
    assert r.status_code == 200, r.text


# ============================================================================ критерий 4: JSON, счётчики, текст для Hub

def test_conflict_changes_neither_counters_nor_defect_text(case):
    fields = case.fields()
    before = (case.reviewed_count(), case.db.review_stats(case.pid))
    with interleave(case, lambda: case.put("агент 1", "update", "Ответ B", "99.0.0")):
        r = case.agree(fields)
    assert r.status_code == 409
    body = r.json()
    assert body["ok"] is False and "hub_text" not in body and "defect_ready" not in body
    assert (case.reviewed_count(), case.db.review_stats(case.pid)) == before
    d = case.web.client.post(f"{case.url}/defect", headers=AS_JSON, data={"number": "", "confirm": "1"})
    assert d.status_code == 409 and "Ложное срабатывание" not in d.text and "Ответ A" not in d.text


def test_html_form_conflict_keeps_the_draft_and_writes_nothing(case):
    fields = case.fields()
    with interleave(case, lambda: case.put("агент 1", "update", "Ответ B", "99.0.0")):
        r = case.web.client.post(f"{case.url}/review", headers=ORIGIN, data={
            **fields, "decision": "agree", "reviewed": "1", "action": "save",
            "comment": FP_REASON})
    assert r.status_code == 409 and "Решение не сохранено" in r.text
    assert case.review() is None


def ordered_race(case, point: str):
    """Решение и загрузка нового ответа идут в настоящих потоках, порядок задан событиями (не случаем): загрузка проходит
    до записи решения (before_write), между записью и снимком ответа (after_write) или после снимка (after_snapshot)."""
    import threading

    uploaded, reached = threading.Event(), threading.Event()
    fields = case.fields()
    original_save, original_snapshot = case.db.save_review, case.db.sca_snapshot

    def save(*args, **kwargs):
        if point == "before_write":
            reached.set()
            assert uploaded.wait(10)
        result = original_save(*args, **kwargs)
        if point == "after_write":
            reached.set()
            assert uploaded.wait(10)
        return result

    def snapshot(*args, **kwargs):
        result = original_snapshot(*args, **kwargs)
        if point == "after_snapshot":
            reached.set()
            assert uploaded.wait(10)
        return result

    def upload():
        assert reached.wait(10)
        case.put("агент 1", "update", "Ответ B", "99.0.0")
        uploaded.set()

    worker = threading.Thread(target=upload)
    worker.start()
    with patch.object(case.db, "save_review", side_effect=save), patch.object(case.db, "sca_snapshot",
                                                                              side_effect=snapshot):
        response = case.agree(fields)
    worker.join(10)
    assert uploaded.is_set(), "загрузка ответа прошла в нужной точке"
    return response, fields


def test_threads_upload_before_the_write_gives_a_conflict(case):
    from app.routes.sca import answer_signature

    response, _ = ordered_race(case, "before_write")
    assert response.status_code == 409 and response.json()["reason"] == "answer"
    assert case.review() is None and case.reviewed_count() == 0, "конфликт ничего не записал"
    assert answer_signature(case.db.sca_answers(case.pid, case.f.component, case.f.version, "maven")[0])


def test_threads_upload_between_write_and_snapshot_gives_a_warned_unchecked_decision(case):
    response, fields = ordered_race(case, "after_write")
    assert response.status_code == 200, response.text
    body = response.json()
    latest = case.db.sca_answers(case.pid, case.f.component, case.f.version, "maven")[0]
    assert body["reviewed"] is False and body["progress"]["reviewed"] == 0 and body["notice"]
    assert body["answer_moved"] is True and body["answer_id"] == fields["answer_id"]
    assert body["current_answer_id"] == str(latest["id"]) and body["revision"] == case.review()["revision"]
    assert case.review()["reviewed"] == 0 and case.reviewed_count() == 0


def test_threads_upload_after_the_snapshot_reflects_the_state_the_client_saw(case):
    from app.routes.sca import answer_signature

    response, fields = ordered_race(case, "after_snapshot")
    assert response.status_code == 200, response.text
    body = response.json()
    latest = case.db.sca_answers(case.pid, case.f.component, case.f.version, "maven")[0]
    # ответ клиенту описывает состояние до загрузки: проверено, без предупреждения; в базе загрузка уже сняла отметку
    assert body["reviewed"] is True and body["notice"] == "" and body["answer_moved"] is False
    assert body["progress"]["reviewed"] == 1 and body["answer_id"] == fields["answer_id"]
    stored = case.review()
    assert body["revision"] < stored["revision"] and stored["reviewed"] == 0
    assert stored["answer_sig"] != answer_signature(latest), "подпись прежнего ответа: новый ответ с «Проверено» не связан"
    assert case.reviewed_count() == 0


def test_random_threads_keep_the_invariant(case):
    """Случайная гонка (порядок не гарантируется – его проверяют три теста выше): код ответа допустим, а «Проверено» с
    подписью устаревшего ответа в итоге не остаётся."""
    import threading

    from app.routes.sca import answer_signature

    for lap in range(20):
        fields = case.fields()
        barrier = threading.Barrier(2)
        codes = []

        def decide():
            barrier.wait()
            codes.append(case.agree(fields))

        def upload_answer():
            barrier.wait()
            case.put("агент 1", "update", f"Ответ {lap}", "99.0.0")

        threads = [threading.Thread(target=decide), threading.Thread(target=upload_answer)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        [response] = codes
        assert response.status_code in (200, 409), (lap, response.status_code, response.text)
        review = case.review()
        latest = case.db.sca_answers(case.pid, case.f.component, case.f.version, "maven")[0]
        if response.status_code == 409:
            assert review is None
        else:
            assert review["reviewed"] == 0 and review["answer_sig"] != answer_signature(latest)
        assert case.reviewed_count() == 0
        case.db.save_sca_answers(case.pid, "агент 1", [case.a])
        with case.db._tx() as c:
            c.execute("DELETE FROM reviews WHERE project_id = ?", (case.pid,))
