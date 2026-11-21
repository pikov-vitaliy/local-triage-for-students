"""«Проверено» и пояснение о смене кода (бэклог 114, 115; план 09.11, этап 3): отметка относится к коду, который
видел человек, – если код вернулся к срезу модели, а человек решал по другому коду, отметка снимается; пояснение
называет причину (срез пересобран новой версией приложения или код в клоне изменился), уходит, когда отметки у всех
его находок вернулись, и по «Понятно». Данные выдуманы."""

from __future__ import annotations

from app.db import code_notice_version
from app.view import code_change_note
from test_hub_status_routes import project, sast
from test_web import ORIGIN, web  # noqa: F401

CTX = {"status": "ok", "file": "src/A.java", "start_line": 10, "lines": ["String p = \"x\";"], "max_chars": 12000}


def _reviewed(db, pid, hub_id):
    return db.get_review(pid, hub_id)["reviewed"]


def _decide(db, pid, hub_id, code_hash):
    db.save_review(pid, hub_id, decision="disagree", final_verdict="false_positive", final_comment="Ложное.",
                   reviewed=True, code_hash=code_hash, code_chars=12000)


def test_code_back_to_model_slice_reopens_when_operator_saw_other_code(web):  # noqa: F811
    db = web.app.state.db
    pid = project(web, [sast("1")])
    db.save_case(pid, "1", "slice-a", CTX, None)  # срез модели – код A
    _decide(db, pid, "1", "slice-b")  # человек решал по коду B
    db.save_case(pid, "1", "slice-a", CTX, None)  # код в клоне вернулся к A без смены ревизии
    assert not _reviewed(db, pid, "1"), "код A человек не видел – отметка снимается"
    # причину по отпечатку решения не отличить: не «пересобран новой версией» (ревью Codex)
    notice = db.code_change_notice(pid)
    assert notice["unclear"] == 1 and notice["rebuilt"] == 0
    text = code_change_note(notice, 0)
    assert "изменился код в клоне или срез пересобран" in text and "код в клоне тот же" not in text


def test_cached_verdict_path_still_checks_the_decision_code(web):  # noqa: F811
    """Прогон с готовым вердиктом по тому же срезу save_case не вызывает (ревью Codex): проверка кода решения – там
    же, reopen_for_decision_code."""
    db = web.app.state.db
    pid = project(web, [sast("6")])
    db.save_case(pid, "6", "slice-a", CTX, None)
    _decide(db, pid, "6", "slice-b")
    source = db.case_input(pid, "6")  # снимок – после решения: код читается, когда решение уже есть
    assert db.reopen_for_decision_code(pid, "6", "slice-a", 12000, source) == 1
    assert not _reviewed(db, pid, "6")
    _decide(db, pid, "6", "slice-a")
    source = db.case_input(pid, "6")
    assert db.reopen_for_decision_code(pid, "6", "slice-a", 12000, source) == 0 and _reviewed(db, pid, "6")
    assert db.reopen_for_decision_code(pid, "6", "slice-z", 4000, source) == 0, "другой размер среза – не сравнимо"
    # источник среза устарел (сменились находка или клон) – результат старого чтения пропускается (ревью Codex)
    _decide(db, pid, "6", "slice-b")
    stale = {**db.case_input(pid, "6"), "revision": "другая-ревизия"}
    assert db.reopen_for_decision_code(pid, "6", "slice-a", 12000, stale) == 0 and _reviewed(db, pid, "6")


def test_decision_saved_after_the_code_was_read_keeps_reviewed(web):  # noqa: F811
    """Бэклог 117: сверка прочитала код A, затем код сменили на B без смены ревизии и оператор сохранил решение по B.
    Запись сверки по чтению A отметку свежего решения не снимает – ни в пути готового вердикта, ни при записи среза;
    чтение считается устаревшим, срез не записывается. Следующее чтение – уже с этим решением – работает как раньше."""
    db = web.app.state.db
    pid = project(web, [sast("13")])
    db.save_case(pid, "13", "slice-a", CTX, None)
    source = db.case_input(pid, "13")  # чтение клона (код A) – до решения
    _decide(db, pid, "13", "slice-b")
    assert db.reopen_for_decision_code(pid, "13", "slice-a", 12000, source) == 0
    assert db.save_case(pid, "13", "slice-a", CTX, None, source) is False, "чтение устарело – ничего не записано"
    assert _reviewed(db, pid, "13") and db.code_change_notice(pid) is None
    fresh = db.case_input(pid, "13")  # следующая сверка: решение уже есть, код в клоне вернулся к A
    assert fresh["review_revision"] == source["review_revision"] + 1
    assert db.reopen_for_decision_code(pid, "13", "slice-a", 12000, fresh) == 1
    assert not _reviewed(db, pid, "13")


def test_worse_slice_branch_keeps_a_decision_saved_after_the_read(web):  # noqa: F811
    """Бэклог 117, ветка «новый срез хуже сохранённого» (ревью 10.11): сверка прочитала укороченный файл, затем файл
    вернули и оператор сохранил решение – запоздавшее снятие отметки по старому чтению пропускается; по чтению,
    сделанному уже после решения, отметка снимается как раньше; чтение другой ревизии клона тоже пропускается."""
    db = web.app.state.db
    pid = project(web, [sast("16")])
    db.save_case(pid, "16", "slice-a", CTX, None)
    source = db.case_input(pid, "16")  # чтение клона – до решения
    _decide(db, pid, "16", "slice-a")
    assert db.reopen_for_code_change(pid, "16", source) == 0 and _reviewed(db, pid, "16")
    assert db.code_change_notice(pid) is None
    fresh = db.case_input(pid, "16")
    assert db.reopen_for_code_change(pid, "16", {**fresh, "revision": "другая-ревизия"}) == 0
    assert db.reopen_for_code_change(pid, "16", fresh) == 1 and not _reviewed(db, pid, "16")


def test_decision_on_the_same_code_during_a_run_keeps_the_result(web):  # noqa: F811
    """Бэклог 117, обратная сторона: решение сохранено во время разбора по тому же коду – отметку снимать не за что,
    срез и вердикт записываются как раньше."""
    db = web.app.state.db
    pid = project(web, [sast("14")])
    db.save_case(pid, "14", "slice-a", CTX, None)
    source = db.case_input(pid, "14")
    _decide(db, pid, "14", "slice-a")
    assert db.save_case(pid, "14", "slice-a", CTX, None, source) is True
    assert _reviewed(db, pid, "14")


def test_mark_without_code_hash_after_the_read_is_rechecked_by_the_next_read(web):  # noqa: F811
    """Бэклог 117: отметка без отпечатка кода, поставленная после чтения, – запись по старому чтению пропускается
    (срез не меняется), а следующая сверка сравнивает срезы и снимает отметку, если код другой."""
    db = web.app.state.db
    pid = project(web, [sast("15")])
    db.save_case(pid, "15", "slice-a", CTX, None)
    source = db.case_input(pid, "15")
    db.save_review(pid, "15", decision="disagree", final_verdict="false_positive", final_comment="Ложное.", reviewed=True)
    changed = {**CTX, "lines": ["String p = getParameter(\"p\");"]}
    assert db.save_case(pid, "15", "slice-d", changed, None, source) is False
    assert _reviewed(db, pid, "15") and db.get_case(pid, "15")["case_hash"] == "slice-a"
    assert db.save_case(pid, "15", "slice-d", changed, None, db.case_input(pid, "15")) is True
    assert not _reviewed(db, pid, "15")


def test_same_code_as_operator_saw_still_keeps_reviewed(web):  # noqa: F811
    db = web.app.state.db
    pid = project(web, [sast("2")])
    db.save_case(pid, "2", "slice-a", CTX, None)
    _decide(db, pid, "2", "slice-b")
    db.save_case(pid, "2", "slice-b", CTX, None)  # пересобранный срез – тот код, что видел человек (ADR-0147 п. 6)
    assert _reviewed(db, pid, "2")


def test_notice_names_rebuilt_slice_only_when_lines_are_the_same(web):  # noqa: F811
    db = web.app.state.db
    pid = project(web, [sast("3")])
    db.save_case(pid, "3", "slice-a", CTX, None)
    db.save_review(pid, "3", decision="disagree", final_verdict="false_positive", final_comment="Ложное.",
                   reviewed=True)  # без отпечатка кода – сравнение с прежним срезом
    db.save_case(pid, "3", "slice-c", CTX, None)  # строки те же, другой отпечаток (сверка строки из выгрузки)
    notice = db.code_change_notice(pid)
    assert notice["reopened"] == 1 and notice["rebuilt"] == 1 and notice["hub_ids"] == ["3"]
    text = code_change_note(notice, db.reviewed_among(pid, notice["hub_ids"]))
    assert "срез пересобран новой версией приложения" in text and "код в клоне изменился" not in text


def test_mask_labels_alone_do_not_prove_the_same_code(web):  # noqa: F811
    """Номер метки зависит от значения (HMAC): разные метки – возможно, другое значение в коде (ревью Codex круга 2)."""
    db = web.app.state.db
    pid = project(web, [sast("7")])
    db.save_case(pid, "7", "slice-a", {**CTX, "lines": ["String p = <SECRET_ab12>;"]}, None)
    db.save_review(pid, "7", decision="disagree", final_verdict="false_positive", final_comment="Ложное.", reviewed=True)
    db.save_case(pid, "7", "slice-c", {**CTX, "lines": ["String p = <SECRET_cd34>;"]}, None)
    notice = db.code_change_notice(pid)
    assert notice["rebuilt"] == 0 and notice["unclear"] == 1
    assert "изменился код в клоне или срез пересобран" in code_change_note(notice, 0)


def test_notice_names_code_change_and_goes_away_when_all_reviewed_again(web):  # noqa: F811
    db = web.app.state.db
    pid = project(web, [sast("4")])
    db.save_case(pid, "4", "slice-a", CTX, None)
    db.save_review(pid, "4", decision="disagree", final_verdict="false_positive", final_comment="Ложное.", reviewed=True)
    db.save_case(pid, "4", "slice-d", {**CTX, "lines": ["String p = getParameter(\"p\");"]}, None)
    notice = db.code_change_notice(pid)
    assert notice["rebuilt"] == 0
    text = code_change_note(notice, db.reviewed_among(pid, notice["hub_ids"]))
    assert "код в клоне изменился без смены ревизии у 1 находки" in text
    page = web.client.get(f"/projects/{pid}").text
    assert 'id="code-change-notice"' in page
    db.set_reviewed(pid, "4", True)
    assert code_change_note(notice, db.reviewed_among(pid, notice["hub_ids"])) == ""
    assert 'id="code-change-notice"' not in web.client.get(f"/projects/{pid}").text


def test_manual_unreview_after_all_reviewed_does_not_bring_the_notice_back(web):  # noqa: F811
    """Ревью Codex ветки долга, круг 5: отметки всех находок пояснения вернулись – пояснение снято в той же транзакции,
    что и последняя отметка; ручное снятие отметки потом его не возвращает, следующее пояснение продолжает номер
    редакции. Текст пояснения не говорит, что модель разобрала находки заново."""
    db = web.app.state.db
    pid = project(web, [sast("11"), sast("12")])
    for hub_id in ("11", "12"):
        db.save_case(pid, hub_id, "slice-a", CTX, None)
        _decide(db, pid, hub_id, None)
        db.save_case(pid, hub_id, "slice-b", {**CTX, "lines": ["y"]}, None)
    notice = db.code_change_notice(pid)
    assert "Модель разобрала" not in code_change_note(notice, 0)
    rev = code_notice_version(notice)
    db.set_reviewed(pid, "11", True)
    assert db.code_change_notice(pid), "одна находка ещё не проверена"
    _decide(db, pid, "12", None)  # сохранение решения с отметкой – тоже возвращает отметку
    assert db.code_change_notice(pid) is None
    db.set_reviewed(pid, "11", False)
    assert db.code_change_notice(pid) is None, "ручное снятие отметки – не смена кода"
    assert 'id="code-change-notice"' not in web.client.get(f"/projects/{pid}").text
    db.save_case(pid, "12", "slice-c", {**CTX, "lines": ["z"]}, None)
    assert code_notice_version(db.code_change_notice(pid)) != rev


def test_understood_clears_the_notice(web):  # noqa: F811
    db = web.app.state.db
    pid = project(web, [sast("5")])
    db.save_case(pid, "5", "slice-a", CTX, None)
    db.save_review(pid, "5", decision="disagree", final_verdict="false_positive", final_comment="Ложное.", reviewed=True)
    db.save_case(pid, "5", "slice-e", {**CTX, "lines": ["y"]}, None)
    notice = db.code_change_notice(pid)
    assert notice
    # устаревшая вкладка: показано прежнее пояснение – новое не стирается (ревью Codex)
    shown = code_notice_version(notice)
    assert shown == "rev:1" and f'value="{shown}"' in web.client.get(f"/projects/{pid}").text
    # дополнение в ту же секунду меняет редакцию: устаревшая вкладка нового не стирает (ревью Codex круга 2)
    db.save_case(pid, "5", "slice-f", {**CTX, "lines": ["z"]}, None)
    db.save_review(pid, "5", decision="disagree", final_verdict="false_positive", final_comment="Ложное.", reviewed=True)
    db.save_case(pid, "5", "slice-g", {**CTX, "lines": ["w"]}, None)
    r = web.client.post(f"/projects/{pid}/code-change/clear", headers=ORIGIN, data={"shown_at": shown},
                        follow_redirects=False)
    assert r.status_code in (302, 303) and db.code_change_notice(pid)
    notice = db.code_change_notice(pid)
    r = web.client.post(f"/projects/{pid}/code-change/clear", headers=ORIGIN,
                        data={"shown_at": code_notice_version(notice)}, follow_redirects=False)
    assert r.status_code in (302, 303)
    assert db.code_change_notice(pid) is None
    assert not _reviewed(db, pid, "5"), "«Понятно» отметку не возвращает"


def test_new_notice_after_understood_is_not_cleared_by_a_stale_tab(web):  # noqa: F811
    """Редакция сквозная (ревью Codex круга 3): «Понятно» не удаляет запись, а снимает её; следующее пояснение
    получает следующий номер, и вторая вкладка с прежним пояснением его не снимет."""
    db = web.app.state.db
    pid = project(web, [sast("8")])
    db.save_case(pid, "8", "slice-a", CTX, None)
    db.save_review(pid, "8", decision="disagree", final_verdict="false_positive", final_comment="Ложное.", reviewed=True)
    db.save_case(pid, "8", "slice-b", {**CTX, "lines": ["y"]}, None)
    shown_a = code_notice_version(db.code_change_notice(pid))
    assert db.clear_code_change_notice(pid, shown_a) and db.code_change_notice(pid) is None
    db.save_review(pid, "8", decision="disagree", final_verdict="false_positive", final_comment="Ложное.", reviewed=True)
    db.save_case(pid, "8", "slice-c", {**CTX, "lines": ["z"]}, None)
    notice_b = db.code_change_notice(pid)
    assert notice_b and code_notice_version(notice_b) != shown_a
    assert not db.clear_code_change_notice(pid, shown_a), "вкладка с пояснением A не снимает B"
    assert db.code_change_notice(pid) == notice_b


def test_saving_folders_keeps_the_notice_revision(web):  # noqa: F811
    """Ревью Codex ветки долга, круг 4: сохранение папок (и выгрузки, и «Подключить клоны снова») снимает пояснение,
    но номер редакции сохраняется – пояснение B после него не получает номер A, и вкладка с A его не снимет."""
    db = web.app.state.db
    pid = project(web, [sast("9")])
    db.save_case(pid, "9", "slice-a", CTX, None)
    _decide(db, pid, "9", None)
    db.save_case(pid, "9", "slice-b", {**CTX, "lines": ["y"]}, None)
    shown_a = code_notice_version(db.code_change_notice(pid))
    r = web.client.post(f"/projects/{pid}/clones/attach", headers=ORIGIN, follow_redirects=False)
    assert r.status_code in (302, 303) and db.code_change_notice(pid) is None
    _decide(db, pid, "9", None)
    db.save_case(pid, "9", "slice-c", {**CTX, "lines": ["z"]}, None)
    notice_b = db.code_change_notice(pid)
    assert notice_b and code_notice_version(notice_b) != shown_a
    assert not db.clear_code_change_notice(pid, shown_a), "вкладка с пояснением A не снимает B"
    assert db.code_change_notice(pid) == notice_b
    db.clear_revision_notice(pid)
    assert db.code_change_notice(pid) is None


def test_clearing_without_a_notice_writes_nothing(web):  # noqa: F811
    db = web.app.state.db
    pid = project(web, [sast("10")])
    db.clear_revision_notice(pid)
    assert db._scalar("SELECT COUNT(*) FROM meta WHERE key = ?", (f"codechange:{pid}",)) == 0


def test_truncated_notice_stays_until_understood():
    """Номеров больше предела – состав неполный: пояснение не уходит само (ревью Codex)."""
    notice = {"codebases": ["main"], "reopened": 3, "hub_ids": ["2", "3"], "truncated": True, "at": "x"}
    assert code_change_note(notice, 2)


def test_legacy_notice_without_ids_stays_until_understood():
    legacy = {"codebases": ["main"], "reopened": 2, "at": "2026-11-09T10:00:00Z"}
    assert "код в клоне изменился без смены ревизии у 2 находок" in code_change_note(legacy, 0)
    mixed = {**legacy, "hub_ids": ["7"], "legacy": True}
    assert code_change_note(mixed, 1), "номера прежних находок неизвестны – пояснение остаётся до «Понятно»"
