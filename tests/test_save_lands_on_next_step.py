"""После сохранения решения карточка открывается на следующем шаге маршрута, а не с начала (У1); подсказка у поля
рекомендации – по тому, что есть в карточке (У2). Данные выдуманные, модель поддельная."""

from __future__ import annotations

from app.routes.findings import SAST_NEED_FIX, need_fix_text
from test_code_snapshots import analysed, card_url, form_of, web  # noqa: F401
from test_web import ORIGIN


def save_plain(web, url: str, decision: str, **fields) -> str:  # noqa: F811
    r = web.client.post(url + "/review", headers=ORIGIN, follow_redirects=False, data={
        **form_of(web.client.get(url).text), "decision": decision, "final_verdict": "",
        "comment": "Подтверждено: значение из запроса.", "fix": "Параметризовать запрос.", **fields})
    assert r.status_code in (302, 303), r.text
    return r.headers["location"]


def test_saved_decision_opens_transfer_step(web):  # noqa: F811
    pid = analysed(web)
    url = card_url(web, pid, "510001")
    assert save_plain(web, url, "true_positive").endswith("ok=saved#step-6")
    assert save_plain(web, url, "later").endswith("ok=saved#step-7")


def test_need_fix_text_follows_the_card():
    assert "кнопкой «Взять пункты из рекомендации модели»" in need_fix_text("1) Параметризовать.", ["Параметризовать."])
    code_only = need_fix_text("```\nquery(x)\n```", [])
    assert "только пример кода" in code_only and "кнопк" not in code_only
    assert "Пунктов рекомендации модели нет" in need_fix_text("", [])
    assert "кнопк" not in SAST_NEED_FIX, "отказ сервера не знает, есть ли кнопка в карточке"
