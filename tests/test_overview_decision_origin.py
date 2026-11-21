"""Бэклог 98: обзор проекта – «Внесено в Hub M из K проверенных моих решений» только по решениям оператора (происхождение
operator и прежнее пустое), решения из Hub (hub_sync, hub_defect) – отдельной плашкой «Решений из Hub»; снятое «Проверено»
при оставшейся отметке «Внесено» в счёт не идёт; «Отложить» решением оператора не считается. Данные выдуманы."""

from __future__ import annotations

import re

from test_hub_status_routes import project, sast
from test_web import web  # noqa: F401


def test_overview_counts_by_decision_origin(web):  # noqa: F811
    pid = project(web, [sast(str(900 + n), line=n + 2) for n in range(7)])
    db = web.app.state.db
    for hub_id in ("900", "901", "902", "903", "904", "905"):
        db.save_review(pid, hub_id, decision="disagree", final_verdict="false_positive", final_comment="Проверено.", reviewed=True)
    db.save_review(pid, "906", decision="later", final_verdict="", final_comment="", reviewed=True)
    with db._tx() as c:
        for hub_id, origin in (("900", "operator"), ("901", ""), ("902", "hub_sync"), ("903", "hub_defect"),
                               ("904", "operator"), ("905", "operator")):
            c.execute("UPDATE reviews SET decision_origin = ?, entered_hub = 1 WHERE project_id = ? AND hub_id = ?",
                      (origin, pid, hub_id))
        c.execute("UPDATE reviews SET reviewed = 0 WHERE project_id = ? AND hub_id = '905'", (pid,))  # «Проверено» снято
        c.execute("UPDATE reviews SET entered_hub = 0 WHERE project_id = ? AND hub_id = '904'", (pid,))
    stats = db.review_stats(pid)
    assert (stats["reviewed_operator"], stats["entered_operator"], stats["hub_decisions"]) == (3, 2, 2)
    page = re.sub(r"\s+", " ", web.client.get(f"/projects/{pid}").text)
    assert '<span class="stat-label">Внесено в Hub</span><span class="stat-value">2</span>' in page
    assert "из 3 проверенных моих решений" in page
    assert 'id="hub-decisions-stat"' in page and '<span class="stat-label">Решений из Hub</span><span class="stat-value">2</span>' in page
