"""Карточка SCA, открытая из списка находок с отбором (многозначный статус Hub, «Живые в Hub»), обходит соседей внутри
него – «Дальше» и «Сохранить и дальше» не открывают находку вне отбора (ревью Codex dev18, находка 3). Данные выдуманы."""

from __future__ import annotations

import re
from urllib.parse import quote

from test_finding_status_now import accept_state
from test_hub_status_routes import fid, project, sca
from test_web import ORIGIN, web  # noqa: F401


def test_sca_neighbors_stay_in_list_selection(web):  # noqa: F811
    pid = project(web, [sca(h) for h in ("801", "802", "803")])
    for hub_id, status in (("801", "Open"), ("802", "Fixed"), ("803", "Confirmed")):
        accept_state(web, pid, hub_id, status)
    db = web.app.state.db
    with db._tx() as c:  # статусы SCA – в принятом состоянии с типом SCA_S
        c.execute("UPDATE hub_issue_states SET issue_type = 'SCA_S' WHERE project_id = ?", (pid,))
    for back, expected in ((f"/projects/{pid}/findings?hub_status=Open&hub_status=Confirmed", "803"),
                           (f"/projects/{pid}/findings?hub_live=1", "803")):
        card = web.client.get(f"/projects/{pid}/sca/findings/{fid(web, pid, '801')}?back={quote(back, safe='')}").text
        nxt = re.search(r'id="nav-next"[^>]*href="[^"]*/sca/findings/(\d+)', card) or re.search(r'href="[^"]*/sca/findings/(\d+)[^"]*"[^>]*id="nav-next"', card)
        assert nxt, "нет ссылки «Дальше»"
        assert int(nxt.group(1)) == fid(web, pid, expected), back
    # без отбора – обычный обход по порядку
    card = web.client.get(f"/projects/{pid}/sca/findings/{fid(web, pid, '801')}").text
    assert f"/sca/findings/{fid(web, pid, '802')}" in card


def _card(web, pid, hub_id, back):  # noqa: F811
    return web.client.get(f"/projects/{pid}/sca/findings/{fid(web, pid, hub_id)}?back={quote(back, safe='')}").text


def test_sca_save_next_and_reviewed_walk_stay_in_selection(web):  # noqa: F811
    """«Сохранить и дальше» – следующая внутри отбора, даже если общей следующей нет; отбор «проверено: да» обходит
    проверенные, непроверенная между ними в обход не попадает (ревью Codex dev18, круг 3)."""
    import html as html_mod
    pid = project(web, [sca(h) for h in ("811", "812", "813", "814")])
    for hub_id, status in (("811", "Open"), ("812", "Fixed"), ("813", "Confirmed"), ("814", "Open")):
        accept_state(web, pid, hub_id, status)
    db = web.app.state.db
    with db._tx() as c:
        c.execute("UPDATE hub_issue_states SET issue_type = 'SCA_S' WHERE project_id = ?", (pid,))
    back = f"/projects/{pid}/findings?hub_status=Open&hub_status=Confirmed"
    card = html_mod.unescape(_card(web, pid, "811", back))
    action = re.search(r'action="([^"]*/review[^"]*)" id="review-form"', card).group(1)
    fields = {name: re.search(rf'name="{name}" value="([^"]*)"', card).group(1)
              for name in ("finding_version", "answer_id", "review_revision")}
    r = web.client.post(action, headers=ORIGIN, follow_redirects=False,
                        data={**fields, "decision": "later", "final_verdict": "", "comment": "", "action": "next"})
    assert r.status_code == 303, r.text
    assert f"/sca/findings/{fid(web, pid, '813')}" in r.headers["location"], r.headers["location"]
    # «проверено: да»: 811 и 813 проверены, 814 – нет; из 811 следующая – 813, а не 814 и не 812
    for hub_id in ("811", "813"):
        db.save_review(pid, hub_id, decision="agree", final_verdict="false_positive", final_comment="Проверено.", reviewed=True)
    card = _card(web, pid, "811", back + "&reviewed=yes")
    nxt = re.search(r'id="nav-next"[^>]*href="[^"]*/sca/findings/(\d+)', card)
    assert nxt and int(nxt.group(1)) == fid(web, pid, "813")
    # общей следующей непроверенной нет (все проверены): «Сохранить и дальше» в отборе «проверено: да» всё равно
    # ведёт к следующей внутри отбора (прежнее условие next_id is not None – ревью Codex dev18, группа 3)
    for hub_id in ("812", "814"):
        db.save_review(pid, hub_id, decision="agree", final_verdict="false_positive", final_comment="Проверено.", reviewed=True)
    card = html_mod.unescape(_card(web, pid, "811", back + "&reviewed=yes"))
    action = re.search(r'action="([^"]*/review[^"]*)" id="review-form"', card).group(1)
    fields = {name: re.search(rf'name="{name}" value="([^"]*)"', card).group(1)
              for name in ("finding_version", "answer_id", "review_revision")}
    r = web.client.post(action, headers=ORIGIN, follow_redirects=False,
                        data={**fields, "decision": "later", "final_verdict": "", "comment": "", "action": "next"})
    assert r.status_code == 303, r.text
    assert f"/sca/findings/{fid(web, pid, '813')}" in r.headers["location"], r.headers["location"]
