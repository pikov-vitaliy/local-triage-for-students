"""Уточнение по ГОСТ Р КАПО у нового решения SCA: при выводе «обновить» по умолчанию выбрано «актуальна». Сохранённые решения показываются как сохранены: «по выводу» прежних решений –
анализ не завершён, ничего не подставляется. Подстановку при смене итога в браузере делает app.js по data-kapo-default."""
import re

from test_sca import AS_JSON, answers_text, form_fields, post_answers, prepared, sca_card, web  # noqa: F401


def _selected(card: str) -> str:
    options = re.search(r'<select name="kapo_state"[^>]*>(.*?)</select>', card, re.S).group(1)
    chosen = re.search(r'<option value="([^"]*)"[^>]*? selected>', options)
    return chosen.group(1) if chosen else "<none>"


def test_fresh_update_card_preselects_actual(web):
    pid = prepared(web)
    assert post_answers(web, pid, answers_text()).status_code == 303
    fid, card = sca_card(web, pid, "73001")
    assert 'data-model-verdict="true_positive"' in card
    assert 'id="kapo-state" aria-describedby="kapo-hint" data-kapo-default="actual"' in card
    assert _selected(card) == "actual"
    assert "по выводу (сейчас: анализ не завершён)" in card  # пустой вариант по-прежнему называет, что за ним стоит


def test_saved_decision_keeps_its_refinement(web):
    pid = prepared(web)
    assert post_answers(web, pid, answers_text()).status_code == 303
    fid, card = sca_card(web, pid, "73001")
    url = f"/projects/{pid}/sca/findings/{fid}"
    saved = web.client.post(f"{url}/review", headers=AS_JSON, data={
        **form_fields(card), "decision": "agree", "final_verdict": "true_positive", "comment": "Обновить до 1.4.9.",
        "reviewed": "1", "kapo_state": "", "action": "save"}).json()
    assert saved["ok"] and saved["kapo_state"] == "not_finished"  # «по выводу» сохраняется как «анализ не завершён»
    card = web.client.get(url).text
    assert "data-kapo-default" not in card and _selected(card) == "not_finished"
    # прежнее решение без уточнения (до 0.9.0): показывается «по выводу», по умолчанию ничего не подставляется
    db = web.app.state.db
    with db._tx() as c:
        c.execute("UPDATE reviews SET kapo_state = '' WHERE project_id = ? AND hub_id = ?", (pid, "73001"))
    card = web.client.get(url).text
    assert "data-kapo-default" not in card and _selected(card) == ""


def test_card_without_update_verdict_only_carries_the_default(web):
    pid = prepared(web)
    assert post_answers(web, pid, answers_text()).status_code == 303
    db = web.app.state.db
    with db._tx() as c:
        hub_id = c.execute("SELECT hub_id FROM findings WHERE project_id = ? AND data_json LIKE '%demo-xml%' ORDER BY id",
                           (pid,)).fetchone()[0]
    _, card = sca_card(web, pid, hub_id)  # совет агента по demo-xml – «неясно»: вывод не предвыбран, поле ждёт итога
    assert 'data-kapo-default="actual"' in card and _selected(card) == ""
