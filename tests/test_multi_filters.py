"""Бэклог 99, 102, 103: отбор «Статус Hub» по нескольким значениям, «Живые в Hub», «Hub и модель разошлись», «без кода в
клоне» – по общему пути отбора: SQL, чипы, скрытые поля форм, адрес карточки и «назад», подписи. Данные выдуманы."""

from __future__ import annotations

import html
import re

from app.routes.findings import multi_values, read_selection
from test_db import verdict
from test_finding_status_now import accept_state
from test_hub_status_routes import fid, project, sast
from test_web import web  # noqa: F401

STATES = {"101": "Fixed", "102": "False Positive", "103": "Accepted risk", "104": "Open", "105": "Confirmed"}


def seeded(web) -> int:
    pid = project(web, [sast(h, line=n + 2) for n, h in enumerate(("101", "102", "103", "104", "105", "106"))])
    for hub_id, status in STATES.items():
        accept_state(web, pid, hub_id, status)
    db = web.app.state.db
    # вердикты модели и срезы: 102 FP/истинная и 105 Confirmed/ложная – расхождение; 103 Accepted risk/истинная и 104
    # Open/ложная – нет; у 104 кода в клоне нет, у 105 код есть, у 106 среза нет
    for hub_id, value, status in (("102", "true_positive", "ok"), ("103", "true_positive", "ok"),
                                  ("104", "false_positive", "missing"), ("105", "false_positive", "ok")):
        vid = db.save_verdict(f"code-{hub_id}", "demo", "sast-v6", verdict(value), {})
        db.save_case(pid, hub_id, f"code-{hub_id}", {"status": status, "reason": "missing" if status != "ok" else ""}, vid)
    return pid


def shown(web, pid: int, page: str) -> set[str]:
    ids = {fid(web, pid, h): h for h in (*STATES, "106")}
    return {ids[int(n)] for n in re.findall(rf"/projects/{pid}/findings/(\d+)\?", page) if int(n) in ids}


def test_multi_values_are_ordered_unique_and_bounded():
    from starlette.datastructures import QueryParams
    q = QueryParams("hub_status=Open&hub_status=&hub_status=Confirmed&hub_status=Open&hub_live=1")
    assert multi_values(q, "hub_status") == ("Open", "Confirmed")
    assert multi_values(QueryParams("&".join(f"hub_status={n}" for n in range(40))), "hub_status") == tuple(str(n) for n in range(20))
    selection = read_selection(q)
    assert selection["hub_status"] == ("Open", "Confirmed") and selection["hub_live"] == "1"


def test_filters_select_the_right_findings(web):  # noqa: F811
    pid = seeded(web)
    base = f"/projects/{pid}/findings?kind=SAST"
    assert shown(web, pid, web.client.get(base + "&hub_status=Open&hub_status=Confirmed").text) == {"104", "105"}
    assert shown(web, pid, web.client.get(base + "&hub_live=1").text) == {"104", "105", "106"}
    assert shown(web, pid, web.client.get(base + "&hub_model_diff=1").text) == {"102", "105"}
    assert shown(web, pid, web.client.get(base + "&no_code=1").text) == {"104"}
    assert shown(web, pid, web.client.get(base + "&no_code=1&verdict=false_positive").text) == {"104"}


def test_address_keeps_every_value_on_each_step(web):  # noqa: F811
    pid = seeded(web)
    page = web.client.get(f"/projects/{pid}/findings?kind=SAST&hub_status=Open&hub_status=Confirmed&page_size=25").text
    text = html.unescape(page)
    # скрытые поля форм размера страницы, перехода по номеру и кодовой базы – по одному полю на значение
    assert text.count('name="hub_status" value="Open"') >= 3 and text.count('name="hub_status" value="Confirmed"') >= 3
    # чипы: выбранное значение снимается, остальные сохраняются; «любой» снимает все
    assert re.search(r'href="[^"]*hub_status=Confirmed[^"]*"[^>]*>\s*Open', text) or "hub_status=Confirmed" in text
    # адрес карточки и «назад» несут оба значения
    card = re.search(rf'href="(/projects/{pid}/findings/\d+\?[^"]+)"', text).group(1)
    assert card.count("hub_status=") == 2 or ("hub_status=Open" in card and "hub_status=Confirmed" in card)
    card_page = html.unescape(web.client.get(card).text)
    assert "статус Hub: Open, Confirmed" in card_page
    # «Живые в Hub» и «Hub и модель разошлись» – готовые отборы
    assert "hub_live=1" in text and "hub_model_diff=1" in text and "no_code=1" in text
