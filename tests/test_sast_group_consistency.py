"""SAST: единство группы «та же строка и категория» по итоговому тексту и в транзакции записи, номер группы,
отметки «скопировано» и «Внесено в Hub» у дефекта (ADR-0089, 0.9.6, второй круг проверки)."""

from __future__ import annotations

import re

import pytest

from app import defect
from app.db import text_hash
from app.routes.findings import group_conflict_rows, group_number_plan, sibling_take_fix
from hub_fixtures import SAST_ROWS, SCA_ROWS, make_hub_xlsx
from test_sast_two_outcomes import TWIN, AS_JSON, card_url, fields, group, issue_defect, review  # noqa: F401
from test_web import ORIGIN, create_project, upload  # noqa: F401
from test_web import web  # noqa: F401


# ============================================================================ итоговый текст и номер – чистые функции

def row(hub_id: str, decision: str, verdict: str, comment: str, fix: str = "", model_fix: str = "",
        review_vid: int | None = None, case_vid: int | None = None, number: int | None = None,
        missing: int = 0) -> dict:
    return {"hub_id": hub_id, "missing": missing, "decision": decision, "final_verdict": verdict,
            "final_comment": comment, "final_fix": fix, "model_fix": model_fix, "review_verdict_id": review_vid,
            "case_verdict_id": case_vid, "defect_number": number}


def test_group_compares_the_final_text_not_the_raw_fields():
    mine = defect.sast_effective("true_positive", "Значение попадает в SQL – без параметров.",
                                 "1) Параметризовать запрос.", "disagree", "")
    # рекомендация модели в текст не входит (ADR-0092): у соседа без своей рекомендации текст другой
    same_by_model = row("2", "agree", "true_positive", "Подтверждено: Значение попадает в SQL " + chr(0x2014)
                        + " без параметров.", model_fix="Параметризовать запрос.", review_vid=3, case_vid=3)
    assert "другой текст" in group_conflict_rows([same_by_model], mine)
    # с 0.10.0.dev21 (ADR-0149) вводное слово и длинное тире – часть текста: такой сосед пишет в Hub другой текст
    assert "другой текст" in group_conflict_rows([{**same_by_model, "final_fix": "Параметризовать запрос."}], mine)
    same_words = {**same_by_model, "final_comment": "Значение попадает в SQL – без параметров.",
                  "final_fix": "Параметризовать запрос."}
    assert group_conflict_rows([same_words], mine) == ""
    # своя рекомендация с другой нумерацией – тот же пункт
    assert group_conflict_rows([row("3", "disagree", "true_positive", "Значение попадает в SQL – без параметров.",
                                    fix="Параметризовать запрос.")], mine) == ""
    other_model = {**same_by_model, "final_fix": "Переписать метод."}
    assert "другой текст" in group_conflict_rows([other_model], mine)
    # пропавшая находка и решение «Отложить» в сравнение не входят
    assert group_conflict_rows([{**other_model, "missing": 1}, row("4", "later", "", "позже")], mine) == ""


def test_group_number_plan():
    assert group_number_plan([], None) == (None, "", "")
    assert group_number_plan([], 5) == (5, "", "")
    assert group_number_plan([], None, own=4) == (4, "", ""), "пока у группы нет номеров – свой номер свободен"
    one = [row("2", "", "", "", number=2)]
    assert group_number_plan(one, None)[0] == 2
    number, error, _ = group_number_plan(one, 1)
    assert number is None and "ID2" in error
    # свой прежний номер участвует в подсчёте, но исключением не служит: при равенстве – меньший номер
    number, error, note = group_number_plan(one, None, own=1)
    assert (number, error) == (1, "") and "разные номера" in note
    assert group_number_plan(one, 2, own=1)[1], "номер, который не стал номером группы, не принимается"
    # A – ID1, B и C – ID2: номер группы ID2 для всех, другой не принимается
    many = [row("B", "", "", "", number=2), row("C", "", "", "", number=2, missing=1)]
    assert group_number_plan(many, None, own=1)[0] == 2
    assert group_number_plan(many, 1, own=1)[1] and group_number_plan(many, 2, own=1)[:2] == (2, "")
    assert "ID1 – эта находка" in group_number_plan(many, None, own=1)[2]


def test_take_fix_is_the_text_that_went_into_the_defect():
    own = row("2", "disagree", "true_positive", "x", fix="Свой пункт.")
    assert sibling_take_fix(own) == "Свой пункт."
    model = row("3", "agree", "true_positive", "x", model_fix="Пункт модели.", review_vid=1, case_vid=1)
    assert sibling_take_fix(model) == "", "рекомендация модели не переносится (ADR-0092)"
    assert sibling_take_fix(row("4", "disagree", "true_positive", "x")) == "", "общего пункта больше нет"
    assert sibling_take_fix(row("5", "disagree", "false_positive", "x")) == ""


# ============================================================================ маршруты: транзакция, номер, отметки

def test_group_is_rechecked_inside_the_write_transaction(web, group, monkeypatch):  # noqa: F811
    """Предварительная проверка группы не видит соседа (как при гонке двух вкладок), а запись – видит: отказ, решение
    не записано, текст не выдан."""
    db = web.app.state.db
    first, twin = card_url(web, group, "510001"), card_url(web, group, "510011")
    assert review(web, first, "false_positive", "Имя таблицы берётся из заранее заданной строки.").status_code == 200
    before = db.get_review(group, "510011")
    monkeypatch.setattr(db, "group_rows", lambda *a, **k: [])
    copied = review(web, twin, "false_positive", "Проверено, всё хорошо.", action="copy")
    assert copied.status_code == 400 and "другой текст" in copied.json()["detail"], copied.text
    assert db.get_review(group, "510011") == before, "в транзакции записи отказ – ничего не записано"


def test_defect_number_is_rechecked_inside_the_write_transaction(web, group, monkeypatch):  # noqa: F811
    db = web.app.state.db
    first, twin = card_url(web, group, "510001"), card_url(web, group, "510011")
    for url in (first, twin):
        assert review(web, url, "true_positive", "Значение из запроса попадает в SQL.",
                      fix="Параметризовать запрос.").status_code == 200
    assert issue_defect(web, first).json()["number"] == 1
    monkeypatch.setattr(db, "group_rows", lambda *a, **k: [])
    wrong = issue_defect(web, twin, number="ID5")
    assert wrong.status_code == 400 and "ID1" in wrong.json()["detail"], wrong.text
    assert db.defect_number(group, defect.defect_key_sast("510011")) is None


def test_own_stored_number_does_not_override_the_group(web, group):  # noqa: F811
    db = web.app.state.db
    first, twin = card_url(web, group, "510001"), card_url(web, group, "510011")
    for url in (first, twin):
        assert review(web, url, "true_positive", "Значение из запроса попадает в SQL.",
                      fix="Параметризовать запрос.").status_code == 200
    db.set_defect_number(group, defect.defect_key_sast("510001"), 3)
    db.set_defect_number(group, defect.defect_key_sast("510011"), 2)
    # у группы ID2 и ID3: номер группы – меньший, ID2; свой ID3 у 510001 исключением не служит
    refused = issue_defect(web, first, number="ID3")
    assert refused.status_code == 400 and "ID2" in refused.json()["detail"], refused.text
    proposed = issue_defect(web, first)
    assert proposed.status_code == 200 and proposed.json()["number"] == 2, "предлагается номер группы, а не свой"
    assert db.defect_number(group, defect.defect_key_sast("510001")) == 2


def test_defect_issue_reports_revision_and_text_fingerprint(web, group):  # noqa: F811
    db = web.app.state.db
    first = card_url(web, group, "510001")
    assert review(web, first, "true_positive", "Значение из запроса попадает в SQL.",
                  fix="Параметризовать запрос.").status_code == 200
    issued = issue_defect(web, first).json()
    revision = db.get_review(group, "510001")["revision"]
    assert issued["revision"] == revision and issued["entered"] is False
    assert issued["entered_hash"] == text_hash(issued["body"]), "отпечаток – именно выданного тела"
    # «скопировано» – к выданной редакции (скрипт подтверждает её после копирования тела)
    copied = web.client.post(f"{first}/copied", headers=AS_JSON, data={"revision": str(issued["revision"])})
    assert copied.status_code == 200 and db.get_review(group, "510001")["copied_at"]


def test_entered_mark_checks_the_text_the_operator_saw(web, group):  # noqa: F811
    db = web.app.state.db
    first = card_url(web, group, "510001")
    assert review(web, first, "true_positive", "Значение из запроса попадает в SQL.",
                  fix="Параметризовать запрос.").status_code == 200
    issued = issue_defect(web, first).json()
    db.set_settings({"team_name": "Другая команда"})  # в другой вкладке сменили название команды
    revision = str(db.get_review(group, "510001")["revision"])
    moved = web.client.post(f"{first}/entered", headers=AS_JSON, data={
        "entered": "1", "review_revision": revision, "text_hash": issued["entered_hash"]})
    assert moved.status_code == 400 and "скопируйте текст заново" in moved.json()["detail"], moved.text
    assert not db.get_review(group, "510001")["entered_hub"]
    card = web.client.get(first).text
    current = re.search(r'name="text_hash" id="entered-text-hash" value="([0-9a-f]+)"', card).group(1)
    ok = web.client.post(f"{first}/entered", headers=AS_JSON, data={
        "entered": "1", "review_revision": revision, "text_hash": current})
    assert ok.status_code == 200 and db.get_review(group, "510001")["entered_hub"]


def test_postponed_finding_cannot_be_marked_entered(web, group):  # noqa: F811
    db = web.app.state.db
    first = card_url(web, group, "510001")
    assert review(web, first, "later", "Вернуться после уточнения у разработчика.").status_code == 200
    card = web.client.get(first).text
    assert re.search(r'id="mark-entered"[^>]* hidden', card), "кнопка отметки скрыта у отложенной находки"
    revision = str(db.get_review(group, "510001")["revision"])
    refused = web.client.post(f"{first}/entered", headers=AS_JSON, data={"entered": "1", "review_revision": revision})
    assert refused.status_code == 400 and "отложенная находка" in refused.json()["detail"], refused.text
    assert not db.get_review(group, "510001")["entered_hub"]


def test_entered_mark_of_sast_needs_the_fingerprint(web, group):  # noqa: F811
    """Страница, открытая до 0.9.6, не несёт отпечатка показанного текста: отметку она не ставит, снять может."""
    db = web.app.state.db
    first = card_url(web, group, "510001")
    assert review(web, first, "false_positive", "Имя таблицы берётся из заранее заданной строки.").status_code == 200
    revision = str(db.get_review(group, "510001")["revision"])
    old_page = web.client.post(f"{first}/entered", headers=AS_JSON, data={"entered": "1", "review_revision": revision})
    assert old_page.status_code == 400 and "Обновите карточку" in old_page.json()["detail"], old_page.text
    assert not db.get_review(group, "510001")["entered_hub"]
    assert web.client.post(f"{first}/entered", headers=AS_JSON, data={"entered": "0"}).status_code == 200


def test_defect_is_not_issued_to_a_stale_tab(web, group):  # noqa: F811
    db = web.app.state.db
    first = card_url(web, group, "510001")
    assert review(web, first, "true_positive", "Значение из запроса попадает в SQL.",
                  fix="Параметризовать запрос.").status_code == 200
    old = str(db.get_review(group, "510001")["revision"])
    assert review(web, first, "true_positive", "Значение из запроса попадает в SQL без проверки.",
                  fix="Параметризовать запрос.").status_code == 200  # другая вкладка сохранила новую редакцию
    stale = web.client.post(f"{first}/defect", headers=AS_JSON, data={"number": "", "confirm": "1",
                                                                      "review_revision": old})
    assert stale.status_code == 409 and "другой вкладке" in stale.json()["detail"], stale.text
    fresh = web.client.post(f"{first}/defect", headers=AS_JSON, data={
        "number": "", "confirm": "1", "review_revision": str(db.get_review(group, "510001")["revision"])})
    assert fresh.status_code == 200


@pytest.fixture
def group3(web):  # noqa: F811
    """Группа из трёх находок одной строки и категории: 510001, 510011 и 510012."""
    twin2 = dict(TWIN, **{"Issue id": "510012"})
    pid = create_project(web.client)
    path = make_hub_xlsx(web.tmp / "group3.xlsx", sast=[*SAST_ROWS, TWIN, twin2], sca=SCA_ROWS, practices="auto")
    assert upload(web.client, pid, path).status_code == 303
    r = web.client.post(f"/projects/{pid}/repos", data={"repos_dir": "team"}, headers=ORIGIN, follow_redirects=False)
    assert r.status_code == 303, r.text
    web.app.state.db.set_settings({"team_name": "Платформа"})
    return pid


def test_three_findings_converge_to_the_majority_number(web, group3):  # noqa: F811
    """Маршрут: у A – ID1, у B и C – ID2. Номер группы – ID2: A не выдаёт дефект с ID1, ей предлагается ID2."""
    db = web.app.state.db
    for hub_id in ("510001", "510011", "510012"):
        assert review(web, card_url(web, group3, hub_id), "true_positive", "Значение из запроса попадает в SQL.",
                      fix="Параметризовать запрос.").status_code == 200
    db.set_defect_number(group3, defect.defect_key_sast("510001"), 1)
    db.set_defect_number(group3, defect.defect_key_sast("510011"), 2)
    db.set_defect_number(group3, defect.defect_key_sast("510012"), 2)
    a_url = card_url(web, group3, "510001")
    assert 'id="defect-number" value="2"' in web.client.get(a_url).text
    refused = issue_defect(web, a_url, number="ID1")
    assert refused.status_code == 400 and "ID2" in refused.json()["detail"], refused.text
    fixed = issue_defect(web, a_url)
    assert fixed.status_code == 200 and fixed.json()["number"] == 2
    assert {db.defect_number(group3, defect.defect_key_sast(h)) for h in ("510001", "510011", "510012")} == {2}
    # B с номером группы – без отказа
    assert issue_defect(web, card_url(web, group3, "510011"), number="ID2").status_code == 200


def test_old_true_positive_without_reason_gives_no_defect(web, group):  # noqa: F811
    """Решение «истинная» без обоснования, сохранённое до 0.9.6: дефект с «Нет информации» не выдаётся, номер не
    записывается, карточка просит дописать обоснование."""
    db = web.app.state.db
    first = card_url(web, group, "510001")
    assert review(web, first, "true_positive", "Значение из запроса попадает в SQL.",
                  fix="Параметризовать запрос.").status_code == 200
    with db._tx() as c:  # как решение прежней версии: обоснование пустое
        c.execute("UPDATE reviews SET final_comment = 'Подтверждено:' WHERE project_id = ? AND hub_id = ?",
                  (group, "510001"))
    refused = issue_defect(web, first)
    assert refused.status_code == 409 and "нет обоснования" in refused.json()["detail"], refused.text
    assert "body" not in refused.json()
    assert db.defect_number(group, defect.defect_key_sast("510001")) is None
    card = web.client.get(first).text
    assert 'id="defect-panel" aria-labelledby="defect-title" hidden' in card
    blocked = card.split('id="defect-blocked"')[1].split("</div>")[0]
    assert "нет обоснования" in blocked, "подсказка видна вне скрытой панели"
    # отметку «Внесено в Hub» по такому решению тоже не поставить
    revision = str(db.get_review(group, "510001")["revision"])
    hashed = re.search(r'id="entered-text-hash" value="([0-9a-f]*)"', card).group(1)
    refused = web.client.post(f"{first}/entered", headers=AS_JSON, data={
        "entered": "1", "review_revision": revision, "text_hash": hashed})
    assert refused.status_code == 400 and "нет обоснования" in refused.json()["detail"], refused.text
    assert not db.get_review(group, "510001")["entered_hub"]


def test_old_decision_without_own_fix_asks_for_a_recommendation(web):  # noqa: F811
    """Прежнее решение «истинная» без своей рекомендации (до 0.9.8): дефект не выдаётся – ни общего пункта, ни
    рекомендации модели (ADR-0092); пересохранение без рекомендации отклоняется; со своей рекомендацией текст – её
    пункты."""
    from test_r092_hub_text import HUB_ID, bind_verdict
    from test_web import prepared
    pid = prepared(web)
    db = web.app.state.db
    db.set_settings({"team_name": "Платформа"})
    bind_verdict(web, pid, "true_positive", "Подтверждено: значение попадает в SQL.", "Рекомендация модели.")
    url = card_url(web, pid, HUB_ID)
    # прежнее решение (до 0.9.8): сохранено формой, своя рекомендация пуста
    assert review(web, url, "true_positive", "Значение из запроса попадает в SQL.", fix="Пункт.").status_code == 200
    db._conn.execute("UPDATE reviews SET final_fix = '' WHERE project_id = ? AND hub_id = ?", (pid, HUB_ID))
    refused = issue_defect(web, url)
    assert refused.status_code == 409 and "нет рекомендации" in refused.json()["detail"], refused.text
    again = review(web, url, "true_positive", "Значение из запроса попадает в SQL.", fix="")
    assert again.status_code == 400 and "рекомендацию" in again.json()["detail"], again.text
    code_only = review(web, url, "true_positive", "Значение из запроса попадает в SQL.", fix="```sql\nSELECT ?\n```")
    assert code_only.status_code == 400, "один пример кода рекомендацией не считается"
    saved = review(web, url, "true_positive", "Значение из запроса попадает в SQL.", fix="Параметризовать запрос.")
    assert saved.status_code == 200, saved.text
    body = issue_defect(web, url).json()["body"]
    assert body.endswith("Рекомендация:\n1) Параметризовать запрос.")
    assert "Рекомендация модели" not in body and defect.DEFAULT_RECOMMENDATION not in body


def test_new_model_answer_does_not_change_a_defect_with_own_fix(web):  # noqa: F811
    """Своя рекомендация от смены ответа модели не зависит: новый разбор с другой рекомендацией текст дефекта не
    меняет (ADR-0092)."""
    from test_r092_hub_text import HUB_ID, bind_verdict
    from test_web import prepared
    pid = prepared(web)
    db = web.app.state.db
    db.set_settings({"team_name": "Платформа"})
    bind_verdict(web, pid, "true_positive", "Подтверждено: значение попадает в SQL.", "Рекомендация А.")
    url = card_url(web, pid, HUB_ID)
    assert review(web, url, "true_positive", "Значение из запроса попадает в SQL.",
                  fix="Свой пункт.").status_code == 200
    first = issue_defect(web, url).json()
    assert first["body"].endswith("1) Свой пункт.")
    bind_verdict(web, pid, "true_positive", "Подтверждено: значение попадает в SQL.", "Рекомендация Б.")
    again = review(web, url, "true_positive", "Значение из запроса попадает в SQL.", fix="Свой пункт.")
    assert again.status_code == 200, again.text
    assert issue_defect(web, url).json()["body"] == first["body"]


def test_delayed_issue_does_not_restore_an_old_number(web, group, monkeypatch):  # noqa: F811
    """Чередование запросов: запрос выдачи A прочитал её прежний номер ID1, а пока он шёл, A перевыдали с ID2 и B
    получила ID2. В транзакции записи собственный номер читается заново: отложенный запрос с ID1 отклоняется, у
    группы остаётся ID2."""
    db = web.app.state.db
    a_url, b_url = card_url(web, group, "510001"), card_url(web, group, "510011")
    for url in (a_url, b_url):
        assert review(web, url, "true_positive", "Значение из запроса попадает в SQL.",
                      fix="Параметризовать запрос.").status_code == 200
    db.set_defect_number(group, defect.defect_key_sast("510001"), 2)
    db.set_defect_number(group, defect.defect_key_sast("510011"), 2)
    real = db.defect_number
    # до транзакции запрос видит прежний собственный номер A – ID1 (как отложенный запрос)
    monkeypatch.setattr(db, "defect_number", lambda pid, key: 1 if key == defect.defect_key_sast("510001")
                        else real(pid, key))
    monkeypatch.setattr(db, "group_rows", lambda *a, **k: [])  # и не видит соседей до записи
    delayed = issue_defect(web, a_url, number="ID1")
    assert delayed.status_code == 400 and "ID2" in delayed.json()["detail"], delayed.text
    monkeypatch.undo()
    assert {db.defect_number(group, defect.defect_key_sast(h)) for h in ("510001", "510011")} == {2}


def test_take_all_needs_the_whole_group_and_the_same_text_as_the_defect_compares():
    """«Взять решение и текст у всех» (ADR-0090): вся группа показана, у всех действующее решение с обоснованием,
    итоговые тексты совпадают так же, как их сравнивает выдача дефекта, – с учётом регистра."""
    from app.routes.findings import group_take_all

    def row(hub_id, comment, fix):
        return {"hub_id": hub_id, "decision": "disagree", "final_verdict": "true_positive", "final_comment": comment,
                "final_fix": fix, "model_fix": "", "review_verdict_id": None, "case_verdict_id": None}

    same = [row("1", "Значение из запроса попадает в SQL.", "Проверять UserID."),
            row("2", "Значение из запроса попадает в SQL.", "Проверять UserID.")]
    taken = group_take_all(same, 2)
    assert taken == {"outcome": "true_positive", "comment": "Значение из запроса попадает в SQL.",
                     "fix": "Проверять UserID."}
    assert group_take_all(same, 3) is None, "показана не вся группа"
    assert group_take_all(same[:1], 1) is None, "одной соседке хватает её собственной кнопки"
    assert group_take_all([same[0], row("2", "Значение из запроса попадает в SQL.", "Проверять userid.")], 2) is None
    assert group_take_all([same[0], {**same[1], "decision": "later"}], 2) is None
    assert group_take_all([same[0], {**same[1], "final_comment": ""}], 2) is None


def test_stale_card_gets_the_real_reason_and_reload(web):  # noqa: F811
    """Карточку открыли, затем модель разобрала находку заново: решение по тому же коду остаётся в силе, редакция не
    меняется – дефект из открытой карточки выдаётся (ADR-0097; до 0.9.10 – отказ «разобрали заново»). Решение,
    изменённое в другой вкладке, – своё сообщение и обновление карточки (ADR-0090)."""
    from test_r092_hub_text import HUB_ID, bind_verdict
    from test_web import prepared
    pid = prepared(web)
    db = web.app.state.db
    db.set_settings({"team_name": "Платформа"})
    bind_verdict(web, pid, "true_positive", "Подтверждено: значение попадает в SQL.", "Рекомендация А.")
    url = card_url(web, pid, HUB_ID)
    assert review(web, url, "true_positive", "Значение из запроса попадает в SQL.", fix="Пункт.").status_code == 200
    shown = str(db.get_review(pid, HUB_ID)["revision"])
    bind_verdict(web, pid, "true_positive", "Подтверждено: значение попадает в SQL.", "Рекомендация Б.")
    kept = web.client.post(f"{url}/defect", headers=AS_JSON, data={"confirm": "1", "review_revision": shown})
    assert kept.status_code == 200, kept.text
    assert str(db.get_review(pid, HUB_ID)["revision"]) == shown
    # другая вкладка сменила решение на «Отложить»: редакция другая – обновить карточку
    assert review(web, url, "true_positive", "Значение из запроса попадает в SQL.", fix="Пункт.").status_code == 200
    shown = str(db.get_review(pid, HUB_ID)["revision"])
    assert web.client.post(f"{url}/review", headers=AS_JSON, data={
        **fields(web, url), "decision": "later", "comment": "", "action": "save"}).status_code == 200
    other = web.client.post(f"{url}/defect", headers=AS_JSON, data={"confirm": "1", "review_revision": shown})
    assert other.status_code == 409 and other.json().get("reload") is True, other.text
    assert "другой вкладке" in other.json()["detail"]


@pytest.mark.parametrize("origin", ["manual", "defect"])
def test_defect_answer_says_whether_entered_mark_fits_this_text(web, group, origin):  # noqa: F811
    """Ответ выдачи дефекта сообщает entered_current: отметка «Внесено в Hub» поставлена по этому тексту. После смены
    названия команды текст другой – отметку нужно подтвердить заново."""
    db = web.app.state.db
    url = card_url(web, group, "510001")
    assert review(web, url, "true_positive", "Значение из запроса попадает в SQL.",
                  fix="Параметризовать запрос.").status_code == 200
    first = issue_defect(web, url).json()
    assert first["entered"] is False and first["entered_current"] is False
    if origin == "manual":
        marked = web.client.post(f"{url}/entered", headers=AS_JSON, data={
            "entered": "1", "review_revision": str(first["revision"]), "text_hash": first["entered_hash"]})
        assert marked.status_code == 200, marked.text
    else:
        from test_hub_defect_guard import created
        from test_hub_defects import hub_settings
        hub_settings(web, group)
        created(web, group, url)
        mark = db.get_review(group, "510001")
        assert mark["entered_origin"] == "defect" and mark["entered_text_hash"] != mark["entered_decision_hash"]
    again = issue_defect(web, url).json()
    assert again["entered"] is True and again["entered_current"] is True
    db.set_settings({"team_name": "Команда платёжного сервиса"})
    changed = issue_defect(web, url).json()
    assert changed["entered"] is True and changed["entered_current"] is False
