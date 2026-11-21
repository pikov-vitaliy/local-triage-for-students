"""Бэклог 100: карточка SAST находки, исправленной в Hub (Fixed), – честные подписи шага 5. Над выбором решения – «статус в Hub
не меняется»; у «Ложного срабатывания» – «комментарий останется в приложении»; «Подтверждаю дефект» – без изменений (дефект по
исправленной находке возможен, ADR-0089). Данные выдуманы, сети нет."""

from test_finding_status_now import accept_state, card
from test_hub_status_routes import decide, project, sast
from test_web import web  # noqa: F401


def test_fixed_card_labels_both_outcomes(web):
    pid = project(web, [sast("101")])
    page = card(web, pid, "101")
    assert 'id="hub-fixed-note"' not in page and "комментарий и смена статуса в Hub" in page
    accept_state(web, pid, "101", "Fixed")
    page = card(web, pid, "101")  # до решения
    assert 'id="hub-fixed-note"' in page and "статус в Hub не меняется" in page
    assert "комментарий останется в приложении: статус Fixed в Hub не трогается" in page
    assert "комментарий и смена статуса в Hub" not in page
    assert "обоснование, рекомендация, дефект в Hub" in page, "«Подтверждаю дефект» – без изменений"
    decide(web, pid, "101")  # после решения – те же подписи
    page = card(web, pid, "101")
    assert 'id="hub-fixed-note"' in page and "статус Fixed в Hub не трогается" in page
