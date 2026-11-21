"""Решение компонента – находкам его версии (0.10.0.dev27, ADR-0153: решение принимается в
карточке компонента и само подставляется в находки и дефект). Кнопка карточки компонента записывает вывод
«обновить», обоснование и «Проверено» всем находкам версии; «Сохранить и применить» делает это одним нажатием.
Форма несёт то, что карточка показала: редакцию решения компонента и отпечаток находок. Данные выдуманы."""

from __future__ import annotations

import re

from app.models import Finding
from app.sca_contract import input_ref
from app.triage import order_findings
from test_component_defects import seed
from test_sca_research_routes import AS_JSON, decide
from test_web import ORIGIN, web  # noqa: F401

PARSER = input_ref("pypi", "example-parser", "1.4.2")
WHY = "Версия затронута публичной уязвимостью разбора входных данных; исправление есть в 1.4.9."


def card(web, pid: int, ref: str = PARSER, query: str = "") -> str:  # noqa: F811
    r = web.client.get(f"/projects/{pid}/components/{ref}{query}")
    assert r.status_code == 200, r.status_code
    return r.text


def shown(page: str) -> dict:
    """Поля формы применения из карточки: то, что оператор видел."""
    form = page.split('id="component-apply-form"', 1)[1].split("</form>", 1)[0]
    return {name: re.search(rf'name="{name}" value="([^"]*)"', form).group(1) for name in ("decision_revision", "token")}


def apply_decision(web, pid: int, fields: dict | None = None, ref: str = PARSER):  # noqa: F811
    data = fields if fields is not None else shown(card(web, pid, ref))
    return web.client.post(f"/projects/{pid}/components/{ref}/apply-findings", headers=ORIGIN, data=data,
                           follow_redirects=False)


def reviews(web, pid: int, *hub_ids: str) -> dict:  # noqa: F811
    db = web.app.state.db
    return {h: db.get_review(pid, h) for h in hub_ids}


def decided(web, pid: int, **fields) -> None:  # noqa: F811
    revision = int((web.app.state.db.decision(pid, PARSER) or {}).get("revision") or 0)
    r = decide(web, pid, PARSER, **{"action": "update", "rationale": WHY, "target_version": "1.4.9",
                                    "revision": revision, **fields})
    assert r.status_code == 303, r.text


def test_update_decision_goes_to_every_finding_of_the_version(web):  # noqa: F811
    pid = seed(web)
    page = card(web, pid)
    assert 'id="component-apply-button"' not in page
    assert "Сначала сохраните решение" in page.split('id="component-apply-why">', 1)[1].split("</p>", 1)[0]
    decided(web, pid)
    page = card(web, pid)
    assert "Применить решение к находкам этой версии (2)" in page and 'id="component-apply-why"' not in page
    r = apply_decision(web, pid)
    assert r.status_code == 303 and "ok=applied" in r.headers["location"] and "n=2" in r.headers["location"]
    got = reviews(web, pid, "73001", "73002", "73003")
    for hub_id in ("73001", "73002"):
        review = got[hub_id]
        assert (review["decision"], review["final_verdict"]) == ("disagree", "true_positive"), hub_id
        assert review["final_comment"] == WHY and review["reviewed"], hub_id
        assert review["kapo_state"] == "actual", "новое решение «обновить» – уточнение «актуальна» (ADR-0145)"
    assert got["73003"] is None, "находка другого компонента не тронута"
    done = card(web, pid, query="?ok=applied&n=2")
    assert "Решение записано находкам этой версии: 2" in done and 'id="component-apply-defect"' in done
    result = done.split('id="component-apply-result">', 1)[1].split("</p>", 1)[0]
    assert "Решение записано находкам этой версии: 2" in result, "итог виден в блоке, к которому ведёт переход"
    assert 'id="component-apply-result"' not in card(web, pid), "без итога в адресе блок итог не показывает"


def test_defect_target_follows_the_component_decision(web):  # noqa: F811
    from test_sca import sca_card
    pid = seed(web)
    decided(web, pid)
    assert "ok=applied" in apply_decision(web, pid).headers["location"]
    _, finding_card = sca_card(web, pid, "73001")
    assert "1.4.9" in finding_card.split('id="sca-set"', 1)[1], "целевая версия дефекта – из решения компонента"
    assert "решение отложено" not in finding_card


def test_save_and_apply_is_one_request_and_keeps_the_json_contract(web):  # noqa: F811
    """Ревью dev27: «Сохранить и применить» отвечает обработчику формы JSON с редакцией и адресом перехода; запись
    находкам идёт тем же запросом."""
    pid = seed(web)
    token = re.search(r'name="apply_token" value="([^"]*)"', card(web, pid)).group(1)
    r = decide(web, pid, PARSER, headers=AS_JSON, action="update", rationale=WHY, target_version="1.4.9",
               after="apply", apply_token=token)
    assert r.status_code == 200, r.text
    answer = r.json()
    assert answer["ok"] and answer["revision"] == 1 and answer["applied"] == 2 and answer["apply_error"] == ""
    assert "ok=applied" in answer["redirect"] and "n=2" in answer["redirect"]
    assert all(v and v["final_verdict"] == "true_positive" for v in reviews(web, pid, "73001", "73002").values())
    # без JSON – обычное перенаправление на карточку с итогом
    token = re.search(r'name="apply_token" value="([^"]*)"', card(web, pid)).group(1)
    plain = decide(web, pid, PARSER, action="update", rationale=WHY + " Уточнено.", target_version="1.4.9",
                   revision=1, after="apply", apply_token=token)
    assert plain.status_code == 303 and "ok=applied" in plain.headers["location"]
    assert web.app.state.db.get_review(pid, "73001")["final_comment"] == WHY + " Уточнено."


def test_save_and_apply_reports_a_refused_apply_separately(web):  # noqa: F811
    """Решение компонента сохранено, а находкам не записано (действие не «обновить»): ответ говорит и то, и другое."""
    pid = seed(web)
    token = re.search(r'name="apply_token" value="([^"]*)"', card(web, pid)).group(1)
    r = decide(web, pid, PARSER, headers=AS_JSON, action="keep", rationale="Уязвимый разбор в продукте не используется.",
               after="apply", apply_token=token)
    answer = r.json()
    assert answer["ok"] and answer["applied"] == 0 and answer["apply_error"] == "apply_action"
    assert "ok=decision" in answer["redirect"] and "err=apply_action" in answer["redirect"]
    assert web.app.state.db.decision(pid, PARSER)["action"] == "keep"
    assert reviews(web, pid, "73001", "73002") == {"73001": None, "73002": None}
    page = card(web, pid, query="?ok=decision&err=apply_action")
    assert "Решение сохранено" in page and "только решение «обновить»" in page


def test_existing_decisions_are_replaced_each_with_its_own_kapo(web):  # noqa: F811
    """Ревью dev27: прежнее решение первой находки («Ложное срабатывание» со своим уточнением) не срывает запись и
    не переносит своё уточнение остальным: у каждой находки уточнение своё – прежнее, если оно допустимо для
    «обновить», иначе значение по умолчанию."""
    db = web.app.state.db
    pid = seed(web)
    db.save_review(pid, "73001", decision="disagree", final_verdict="false_positive",
                   final_comment="Компонент определён ошибочно.", reviewed=True, kapo_state="false_positive")
    db.save_review(pid, "73002", decision="disagree", final_verdict="true_positive", final_comment="Обновить.",
                   reviewed=True, kapo_state="actual")
    decided(web, pid)
    assert "У 2 из 2 уже есть своё решение – оно заменится." in card(web, pid)
    assert "ok=applied" in apply_decision(web, pid).headers["location"]
    first, second = db.get_review(pid, "73001"), db.get_review(pid, "73002")
    assert (first["final_verdict"], first["final_comment"]) == ("true_positive", WHY)
    assert first["kapo_state"] == "actual", "несовместимое прежнее уточнение заменено значением нового решения"
    assert second["kapo_state"] == "actual", "допустимое уточнение находки сохраняется"


def test_stale_card_does_not_overwrite_what_the_operator_has_not_seen(web):  # noqa: F811
    """Ревью dev27: карточку открыли, затем решение находки изменили в другой вкладке – старая кнопка ничего не
    записывает; то же при изменившемся решении компонента."""
    db = web.app.state.db
    pid = seed(web)
    decided(web, pid)
    fields = shown(card(web, pid))
    db.save_review(pid, "73002", decision="disagree", final_verdict="uncertain", final_comment="Пока неясно.",
                   reviewed=True)
    r = apply_decision(web, pid, fields)
    assert "err=apply_changed" in r.headers["location"]
    assert db.get_review(pid, "73001") is None and db.get_review(pid, "73002")["final_verdict"] == "uncertain"
    # решение компонента сменилось после открытия карточки
    fields = shown(card(web, pid))
    decided(web, pid, rationale=WHY + " Новая редакция.")
    r = apply_decision(web, pid, fields)
    assert "err=apply_changed" in r.headers["location"] and db.get_review(pid, "73001") is None
    # свежая карточка – запись проходит, записана новая редакция
    assert "ok=applied" in apply_decision(web, pid).headers["location"]
    assert db.get_review(pid, "73001")["final_comment"] == WHY + " Новая редакция."
    # повторное нажатие той же кнопки (редакции находок уже другие) ничего не меняет
    again = apply_decision(web, pid, fields)
    assert "err=apply_changed" in again.headers["location"]


def test_missing_token_or_wrong_request_writes_nothing(web):  # noqa: F811
    db = web.app.state.db
    pid = seed(web)
    decided(web, pid)
    for fields in ({}, {"decision_revision": "1"}, {"decision_revision": "1", "token": "0" * 64}):
        r = apply_decision(web, pid, fields)
        assert r.status_code == 303 and "err=apply_changed" in r.headers["location"], fields
    assert db.get_review(pid, "73001") is None


def test_finding_gone_from_the_export_blocks_the_whole_apply(web):  # noqa: F811
    """Ревью dev27: находка версии ушла из выгрузки после открытия карточки – не записывается никому."""
    db = web.app.state.db
    pid = seed(web)
    decided(web, pid)
    fields = shown(card(web, pid))
    kept = [Finding.from_dict(db.get_finding_by_hub_id(pid, h)["data"]) for h in ("73002", "73003")]
    db.save_import(pid, "next.csv", "csv", [], {}, [], order_findings(kept))
    r = apply_decision(web, pid, fields)
    assert "err=apply_changed" in r.headers["location"]
    assert reviews(web, pid, "73001", "73002") == {"73001": None, "73002": None}


def test_findings_with_the_same_cleaned_name_are_all_written_or_none(web):  # noqa: F811
    """Ревью dev27: карточка объединяет находки по очищенному имени (невидимый знак в имени одной из них), а пакет
    снимка сравнивает имена буквально. Решение получают все показанные находки."""
    db = web.app.state.db
    pid = seed(web)
    findings = [Finding.from_dict(db.get_finding_by_hub_id(pid, h)["data"]) for h in ("73001", "73002", "73003")]
    odd = Finding(hub_id="73004", kind="SCA", component="example-" + chr(0x200B) + "parser", version="1.4.2", build_type="pypi",
                  cve=["CVE-2099-0004"], cvss=5.0)
    db.save_import(pid, "next.csv", "csv", [], {}, [], order_findings(findings + [odd]))
    decided(web, pid)
    page = card(web, pid)
    assert "Применить решение к находкам этой версии (3)" in page
    assert "n=3" in apply_decision(web, pid).headers["location"]
    assert all(v and v["final_verdict"] == "true_positive" for v in reviews(web, pid, "73001", "73002", "73004").values())


def test_other_actions_and_missing_decision_are_not_applied(web):  # noqa: F811
    pid = seed(web)
    r = apply_decision(web, pid, {"decision_revision": "0", "token": "x"})
    assert r.status_code == 303 and "err=apply_no_decision" in r.headers["location"]
    refused = card(web, pid, query="?err=apply_no_decision")
    assert "по компоненту нет действующего решения" in refused.split('id="component-apply-result">', 1)[1][:400]
    decided(web, pid, action="keep", rationale="Уязвимый разбор в продукте не используется.", target_version="")
    page = card(web, pid)
    assert 'id="component-apply-button"' not in page and "только решение «обновить»" in page
    assert 'id="save-component-apply"' in page, "форма решения предлагает «Сохранить и применить»"
    r = apply_decision(web, pid, {"decision_revision": "1", "token": "x"})
    assert "err=apply_action" in r.headers["location"]
    assert reviews(web, pid, "73001", "73002") == {"73001": None, "73002": None}


# ---------------------------------------------------------------- ревью dev27, круг 2

def test_hidden_revision_is_the_revision_of_the_shown_decision(web, monkeypatch):  # noqa: F811
    """Карточка показывает одно решение и кладёт в форму его редакцию: отдельного чтения решения для кнопки нет, даже
    если в базе к этому мигу уже другая редакция."""
    db = web.app.state.db
    pid = seed(web)
    decided(web, pid)
    real, real_history = db.decision, db.decision_history
    other = {"revision": 99, "rationale": "Чужая редакция."}
    monkeypatch.setattr(db, "decision", lambda project_id, ref: {**real(project_id, ref), **other})
    monkeypatch.setattr(db, "decision_history", lambda project_id, ref: [
        {**item, **other} if index == 0 else item for index, item in enumerate(real_history(project_id, ref))])
    page = card(web, pid)
    assert shown(page)["decision_revision"] == "1", "в форме – редакция решения из блока «Решение оператора»"


def test_new_agent_answer_after_the_page_was_opened_refuses_the_apply(web, monkeypatch):  # noqa: F811
    """Ответ агента или исследование сменились после открытия карточки: решения находок те же, но отпечаток
    показанного другой – старая кнопка ничего не записывает."""
    from app.routes import sca as sca_routes
    db = web.app.state.db
    pid = seed(web)
    decided(web, pid)
    answer = {"n": 1}
    monkeypatch.setattr(sca_routes, "_latest_answer", lambda _db, _pid, _f: {
        "id": answer["n"], "origin": "research", "research_sig": f"sig{answer['n']}"})
    fields = shown(card(web, pid))
    answer["n"] = 2
    r = apply_decision(web, pid, fields)
    assert "err=apply_changed" in r.headers["location"]
    assert db.get_review(pid, "73001") is None and db.get_review(pid, "73002") is None
    assert shown(card(web, pid))["token"] != fields["token"], "свежая карточка несёт новый отпечаток"
    monkeypatch.undo()  # дальше – настоящие ответы базы: свежая карточка применяется
    assert "ok=applied" in apply_decision(web, pid).headers["location"]


def test_state_is_rechecked_inside_the_write_transaction(web, monkeypatch):  # noqa: F811
    """Состояние находок изменилось между чтением запроса и записью: пересчёт внутри транзакции видит другой
    отпечаток – не записывается ничего."""
    from app.routes import sca as sca_routes
    db = web.app.state.db
    pid = seed(web)
    decided(web, pid)
    fields = shown(card(web, pid))
    real = sca_routes._apply_state
    calls = []

    def racing(*args):
        recipients, token = real(*args)
        calls.append(token)
        return (recipients, token) if len(calls) == 1 else (recipients, "изменилось")

    monkeypatch.setattr(sca_routes, "_apply_state", racing)
    r = apply_decision(web, pid, fields)
    assert len(calls) == 2 and "err=apply_changed" in r.headers["location"]
    assert db.get_review(pid, "73001") is None and db.get_review(pid, "73002") is None


def test_finding_added_after_the_page_was_opened_refuses_the_apply(web):  # noqa: F811
    """В версию добавилась находка (новая выгрузка) после открытия карточки: части состава решение не записывается."""
    db = web.app.state.db
    pid = seed(web)
    decided(web, pid)
    fields = shown(card(web, pid))
    findings = [Finding.from_dict(db.get_finding_by_hub_id(pid, h)["data"]) for h in ("73001", "73002", "73003")]
    extra = Finding(hub_id="73005", kind="SCA", component="example-parser", version="1.4.2", build_type="pypi",
                    cve=["CVE-2099-0005"], cvss=4.0)
    db.save_import(pid, "next.csv", "csv", [], {}, [], order_findings(findings + [extra]))
    r = apply_decision(web, pid, fields)
    assert "err=apply_changed" in r.headers["location"]
    assert reviews(web, pid, "73001", "73002", "73005") == {"73001": None, "73002": None, "73005": None}
    assert "n=3" in apply_decision(web, pid).headers["location"]


def test_refused_save_does_not_apply(web):  # noqa: F811
    """«Сохранить и применить» при отказе самого сохранения (ошибка формы 422, конфликт редакции 409): находкам не
    записывается ничего."""
    pid = seed(web)
    token = re.search(r'name="apply_token" value="([^"]*)"', card(web, pid)).group(1)
    empty = decide(web, pid, PARSER, headers=AS_JSON, action="update", rationale="", target_version="1.4.9",
                   after="apply", apply_token=token)
    assert empty.status_code == 422
    decided(web, pid)
    late = decide(web, pid, PARSER, headers=AS_JSON, action="update", rationale=WHY, target_version="1.4.9",
                  revision=0, after="apply", apply_token=token)
    assert late.status_code == 409
    assert reviews(web, pid, "73001", "73002") == {"73001": None, "73002": None}


def test_form_button_warns_about_replaced_decisions(web):  # noqa: F811
    """Предупреждение о замене решений стоит и у кнопки формы – даже когда решения компонента ещё нет."""
    db = web.app.state.db
    pid = seed(web)
    db.save_review(pid, "73001", decision="disagree", final_verdict="uncertain", final_comment="Пока неясно.",
                   reviewed=True)
    page = card(web, pid)
    assert 'id="component-apply-button"' not in page
    hint = page.split('id="save-component-apply-hint">', 1)[1].split("</p>", 1)[0]
    assert "У 1 из 2 уже есть своё решение – оно заменится." in hint and "запишется находкам этой версии (2)" in hint


# ---------------------------------------------------------------- ревью dev27, круг 3

def test_form_is_built_from_the_findings_and_research_the_card_shows(web, monkeypatch):  # noqa: F811
    """Карточка строит отпечаток из тех находок и того исследования, которые сама показывает: повторного чтения
    состава и исследования для формы нет. Добавленная между чтениями находка в отпечаток не попадает, и запись по
    такой странице отклоняется – в базе находок больше, чем показано."""
    from app.routes import sca as sca_routes
    db = web.app.state.db
    pid = seed(web)
    decided(web, pid)
    real = db.sca_usages
    seen = []

    def usages_once(project_id, ref):
        seen.append(ref)
        return real(project_id, ref)

    monkeypatch.setattr(db, "sca_usages", usages_once)
    page = card(web, pid)
    assert len(seen) == 1, "состав версии читается один раз – тот, что показан в «Где используется»"
    fields = shown(page)
    monkeypatch.undo()
    assert fields["token"] == sca_routes._apply_state(db, pid, PARSER)[1], "отпечаток страницы равен отпечатку базы"
    assert "ok=applied" in apply_decision(web, pid, fields).headers["location"]


def test_manual_target_of_the_defect_text_stays(web):  # noqa: F811
    """Запись решения находкам текст дефекта не меняет: версия, указанная оператором в тексте дефекта, остаётся; из
    решения компонента цель берётся, только когда своей в наборе нет."""
    from test_sca import AS_JSON as SCA_JSON, sca_card
    db = web.app.state.db
    pid = seed(web)
    db.save_review(pid, "73001", decision="disagree", final_verdict="true_positive", final_comment="Обновить.",
                   reviewed=True)
    fid, page = sca_card(web, pid, "73001")
    saved = web.client.post(f"/projects/{pid}/sca/findings/{fid}/package-text", headers=SCA_JSON, data={
        "text_revision": re.search(r'name="text_revision" value="(\d+)"', page).group(1), "target_version": "1.4.8",
        "explanation": "CVE-2099-0001: разбор входных данных без ограничения глубины ведёт к отказу в обслуживании."})
    assert saved.status_code == 200, saved.text
    decided(web, pid)
    assert "ok=applied" in apply_decision(web, pid).headers["location"]
    _, after = sca_card(web, pid, "73001")
    assert 'name="target_version"' in after and 'value="1.4.8"' in after.split('name="target_version"', 1)[1][:200]


def test_failed_second_write_names_the_saved_decision(web, monkeypatch):  # noqa: F811
    """«Сохранить и применить»: решение компонента сохранено, а запись находкам сорвалась (база занята) – ответ формы
    несёт сохранённую редакцию и код сбоя, а не общую ошибку."""
    from app.routes import sca as sca_routes
    pid = seed(web)
    token = re.search(r'name="apply_token" value="([^"]*)"', card(web, pid)).group(1)

    from app.storage.postgresql import DatabaseBusy

    def busy(*_a, **_k):
        raise DatabaseBusy("база занята")

    monkeypatch.setattr(sca_routes, "apply_component_decision", busy)
    r = decide(web, pid, PARSER, headers=AS_JSON, action="update", rationale=WHY, target_version="1.4.9",
               after="apply", apply_token=token)
    assert r.status_code == 200, r.text
    answer = r.json()
    assert answer["ok"] and answer["revision"] == 1 and answer["applied"] == 0 and answer["apply_error"] == "apply_failed"
    assert "ok=decision" in answer["redirect"] and "err=apply_failed" in answer["redirect"]
    assert "Решение компонента сохранено" in answer["apply_message"]
    assert "Обновите страницу" in answer["apply_message"], "кнопки блока на этой странице может не быть"
    page = card(web, pid, query="?ok=decision&err=apply_failed")
    assert "Решение сохранено" in page and "Решение компонента сохранено" in page and "Обновите страницу" in page


# ---------------------------------------------------------------- ревью dev27, круг 4

import pytest  # noqa: E402


@pytest.mark.parametrize("error,code,words", [
    ("unknown", "apply_unknown", "Исход записи решения находкам неизвестен"),
    ("unavailable", "apply_failed", "база была занята или недоступна"),
    ("program", "apply_internal", "внутренняя ошибка приложения"),
])
def test_second_write_failures_are_told_apart(web, monkeypatch, caplog, error, code, words):  # noqa: F811
    """Обрыв на COMMIT – «исход неизвестен», а не «не записано»; недоступная база – сбой хранилища; ошибка программы –
    свой код, а не «база занята». Решение компонента во всех случаях сохранено и названо."""
    from app.routes import sca as sca_routes
    from app.storage.postgresql import CommitUnknown, DatabaseUnavailable
    pid = seed(web)
    token = re.search(r'name="apply_token" value="([^"]*)"', card(web, pid)).group(1)
    failure = {"unknown": CommitUnknown("обрыв"), "unavailable": DatabaseUnavailable("нет связи"),
               "program": TypeError("комментарий находки: секретный текст")}[error]

    def fail(*_a, **_k):
        raise failure

    monkeypatch.setattr(sca_routes, "apply_component_decision", fail)
    answer = decide(web, pid, PARSER, headers=AS_JSON, action="update", rationale=WHY, target_version="1.4.9",
                    after="apply", apply_token=token).json()
    assert answer["ok"] and answer["revision"] == 1 and answer["apply_error"] == code
    assert words in answer["apply_message"], "итог записи находкам назван в самом ответе"
    assert "секретный текст" not in caplog.text, "текст исключения в журнал приложения не попадает"
    if error == "program":
        assert "TypeError" in caplog.text and "запись находкам упала" in caplog.text
    # обычная форма без скрипта: страница с обоими итогами, без перенаправления на карточку (ей нужна база)
    token = re.search(r'name="apply_token" value="([^"]*)"', card(web, pid)).group(1)
    plain = decide(web, pid, PARSER, action="update", rationale=WHY + " Ещё раз.", target_version="1.4.9",
                   revision=1, after="apply", apply_token=token)
    assert plain.status_code == 200 and "Решение компонента сохранено" in plain.text and words in plain.text
    assert "Редакция решения: 2." in plain.text and f"/components/" in plain.text


def test_form_script_names_the_unknown_outcome_when_a_draft_stays():
    """Обработчик формы решения: при оставшемся черновике неизвестный исход записи находкам не выдаётся за «не
    записано» – текст сценария различает коды."""
    from pathlib import Path
    script = (Path(__file__).resolve().parents[1] / "app" / "static" / "navigation.js").read_text(encoding="utf-8")
    block = script.split("var applyNote = ", 1)[1].split("say(", 1)[0]
    assert block.index("answer.apply_message") < block.index("Находкам решение не записано"), "сначала текст сервера"
    stay = script.split("dirty = false; remove(key);", 1)[1].split("} else {", 1)[0]
    assert "if (answer.apply_message)" in stay and stay.index("apply_message") < stay.index("location.assign")
    assert "save-component-apply" in script.split("var buttons = ", 1)[1].split(";", 1)[0]


# ---------------------------------------------------------------- ревью dev27, круг 5

def test_failures_inside_the_write_are_told_apart_and_do_not_leak_into_the_log(web, monkeypatch, caplog):  # noqa: F811
    """Сбой внутри самой записи решений (db.save_reviews): отказ проверки решения – «отклонило запись»; ошибка
    программы, в том числе ValueError, – внутренняя ошибка, а не отказ. Текст исключения в журнал не попадает."""
    from app.routes import sca as sca_routes
    db = web.app.state.db
    pid = seed(web)
    secret = "комментарий находки: секретный текст"
    token = re.search(r'name="apply_token" value="([^"]*)"', card(web, pid)).group(1)
    monkeypatch.setattr(db, "save_reviews", lambda *_a, **_k: (_ for _ in ()).throw(ValueError(secret)))
    answer = decide(web, pid, PARSER, headers=AS_JSON, action="update", rationale=WHY, target_version="1.4.9",
                    after="apply", apply_token=token).json()
    assert answer["ok"] and answer["apply_error"] == "apply_internal", answer
    monkeypatch.setattr(db, "save_reviews",
                        lambda *_a, **_k: (_ for _ in ()).throw(sca_routes.ReviewRejected(secret)))
    fields = shown(card(web, pid))
    r = apply_decision(web, pid, fields)
    assert "err=apply_rejected" in r.headers["location"]
    assert "секретный текст" not in caplog.text
    assert reviews(web, pid, "73001", "73002") == {"73001": None, "73002": None}


# ---------------------------------------------------------------- ревью dev27, круг 6

def test_apply_button_keeps_the_way_back_to_the_filtered_list(web):  # noqa: F811
    """Кнопка «Применить решение к находкам этой версии» не теряет возврат к отфильтрованному списку: и после
    записи, и после отказа «К списку» ведёт туда, откуда оператор пришёл. Чужой адрес возвратом не становится."""
    from urllib.parse import parse_qs, quote, urlsplit
    pid = seed(web)
    decided(web, pid)
    listing = f"/projects/{pid}/components?q=parser&page=2"
    page = card(web, pid, query="?back=" + quote(listing, safe=""))
    action = page.split('id="component-apply-form"', 1)[0].rsplit('action="', 1)[1].split('"', 1)[0]
    assert parse_qs(urlsplit(action.replace("&amp;", "&")).query)["back"] == [listing]
    url = f"/projects/{pid}/components/{PARSER}/apply-findings?back=" + quote(listing, safe="")
    stale = web.client.post(url, headers=ORIGIN, data={**shown(page), "token": "x"}, follow_redirects=False)
    where = urlsplit(stale.headers["location"])
    assert parse_qs(where.query) == {"err": ["apply_changed"], "back": [listing]} and where.fragment == "component-apply"
    done = web.client.post(url, headers=ORIGIN, data=shown(page), follow_redirects=False)
    where = urlsplit(done.headers["location"])
    assert parse_qs(where.query) == {"ok": ["applied"], "n": ["2"], "back": [listing]}
    after = web.client.get(done.headers["location"]).text
    assert f'href="{listing.replace("&", "&amp;")}"' in after, "«К списку» ведёт в отфильтрованный список"
    foreign = web.client.post(f"/projects/{pid}/components/{PARSER}/apply-findings?back=" + quote("//evil.example/x", safe=""),
                              headers=ORIGIN, data=shown(card(web, pid)), follow_redirects=False)
    assert "evil.example" not in foreign.headers["location"]
    assert "back" not in parse_qs(urlsplit(apply_decision(web, pid).headers["location"]).query), "без back – как раньше"
