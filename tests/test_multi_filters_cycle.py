"""Полный цикл адреса многозначного отбора (план dev18, «многозначный отбор»; ревью Codex dev18, круги 2–3): два статуса Hub
и каждый новый флаг – страница 2 → смена кодовой базы → размер страницы → переход по номеру → карточка → переходы j/k →
«Сохранить и дальше» → «назад»; отбор (статусы и флаг) сохраняется на каждом шаге, состав выборки – только подходящие
находки. Чипы статуса включают и выключают значение, «любой» снимает все. Данные выдуманы."""

from __future__ import annotations

import html
import re
from urllib.parse import parse_qs, urlsplit

import pytest

from app.models import Finding
from test_db import verdict
from test_finding_status_now import accept_state
from test_hub_status_routes import project
from test_web import ORIGIN, hidden_fields, web  # noqa: F401

N = 90  # больше страницы в 25 строк и с запасом для каждого флага
STATUS = {0: "Open", 1: "Confirmed", 2: "Fixed"}
WANTED = ["Open", "Confirmed"]


def seeded(web) -> tuple[int, dict[str, str], dict[str, set[str]]]:
    findings = [Finding(hub_id=str(500 + n), kind="SAST", rule="Внедрение SQL", cwe=["CWE-89"],
                        codebase="demo" if n % 2 else "other", file="demo.py", line=n + 2, snippet="q = 'S' + v",
                        severity="high") for n in range(N)]
    pid = project(web, findings)
    db = web.app.state.db
    statuses, flagged = {}, {"hub_live=1": set(), "hub_model_diff=1": set(), "no_code=1": set()}
    for n in range(N):
        hub_id = str(500 + n)
        statuses[hub_id] = STATUS[n % 3]
        accept_state(web, pid, hub_id, STATUS[n % 3])
        if STATUS[n % 3] in WANTED:
            flagged["hub_live=1"].add(hub_id)
        # Confirmed и «ложная» у модели – расхождение; у части – срез без кода в клоне
        value = "false_positive" if STATUS[n % 3] == "Confirmed" else "true_positive"
        no_code = n % 4 in (0, 1)  # в обеих кодовых базах
        vid = db.save_verdict(f"cycle-{hub_id}", "demo", "sast-v6", verdict(value), {})
        db.save_case(pid, hub_id, f"cycle-{hub_id}", {"status": "export_line_only" if no_code else "ok",
                                                      "reason": "missing" if no_code else "", "lines": ["x"]}, vid)
        if STATUS[n % 3] == "Confirmed":
            flagged["hub_model_diff=1"].add(hub_id)
        if no_code and STATUS[n % 3] in WANTED:
            flagged["no_code=1"].add(hub_id)
    return pid, statuses, flagged


def hub_ids_on(web, pid: int, page: str) -> set[str]:
    ids = {int(r["id"]): r["hub_id"] for r in web.app.state.db._all("SELECT id, hub_id FROM findings WHERE project_id = ?", (pid,))}
    return {ids[int(n)] for n in re.findall(rf"/projects/{pid}/findings/(\d+)\?", page) if int(n) in ids}


def hub_id_of(web, finding_id: int) -> str:
    return web.app.state.db._one("SELECT hub_id FROM findings WHERE id = ?", (finding_id,))["hub_id"]


def params(url: str) -> dict[str, list[str]]:
    return parse_qs(urlsplit(html.unescape(url)).query)


def form_url(page: str, marker: str) -> str:
    """GET-форма страницы со скрытыми полями: адрес, который отправит браузер (marker – уникальное поле формы)."""
    for form in re.findall(r'<form method="get" action="([^"]+)"[^>]*>(.*?)</form>', page, re.S):
        if marker in form[1]:
            fields = re.findall(r'<input type="hidden" name="([^"]+)" value="([^"]*)"', form[1])
            return form[0] + "?" + "&".join(f"{k}={v}" for k, v in fields)
    raise AssertionError(f"нет формы с {marker}")


def keeps(url: str, flag: str) -> None:
    got = params(url)
    assert got.get("hub_status") == WANTED, url
    if flag:
        key, value = flag.split("=")
        assert got.get(key) == [value], url


@pytest.mark.parametrize("flag", ["", "hub_live=1", "hub_model_diff=1", "no_code=1"])
def test_full_cycle_keeps_two_statuses_and_flag(web, flag):  # noqa: F811
    pid, statuses, flagged = seeded(web)
    allowed = flagged.get(flag) or {h for h, s in statuses.items() if s in WANTED}
    allowed = {h for h in allowed if statuses[h] in WANTED}

    def check(page: str) -> set[str]:
        rows = hub_ids_on(web, pid, page)
        assert rows <= allowed, rows - allowed
        return rows

    base = f"/projects/{pid}/findings?kind=SAST&hub_status=Open&hub_status=Confirmed&page_size=25" + (f"&{flag}" if flag else "")
    page1 = web.client.get(base).text
    shown = check(page1)
    assert shown
    nxt = re.search(r'rel="next" href="([^"]+)"', page1)
    if len(allowed) > 25:
        keeps(nxt.group(1), flag)
        page2 = web.client.get(html.unescape(nxt.group(1))).text
        assert check(page2) - shown
    else:
        page2 = page1
    cb_url = form_url(page2, 'name="kind"') + "&cb=demo"
    keeps(cb_url, flag)
    page_cb = web.client.get(cb_url).text
    check(page_cb)
    size_url = form_url(page_cb, 'name="page" value="1"') + "&page_size=50"
    keeps(size_url, flag)
    assert params(size_url)["cb"] == ["demo"]
    page_size = web.client.get(size_url).text
    jump_url = form_url(page_size, 'name="page_size" value="50"') + "&page=1"
    keeps(jump_url, flag)
    page_jump = web.client.get(jump_url).text
    assert check(page_jump)
    # карточка и переходы j/k – по ссылкам, с открытием соседней карточки
    card_url = html.unescape(re.search(rf'href="(/projects/{pid}/findings/\d+\?[^"]+)"', page_jump).group(1))
    keeps(card_url, flag)
    card = html.unescape(web.client.get(card_url).text)
    assert "статус Hub: Open, Confirmed" in card
    for nav in ("nav-next", "nav-prev"):
        link = re.search(rf'id="{nav}" href="([^"]+)"', card)
        if link:
            keeps(link.group(1), flag)
            assert hub_id_of(web, int(re.search(r"/findings/(\d+)", link.group(1)).group(1))) in allowed
            assert "статус Hub: Open, Confirmed" in html.unescape(web.client.get(link.group(1)).text)
    # «Сохранить и дальше»
    action = re.search(r'action="([^"]*/review[^"]*)" id="review-form"', card).group(1)
    r = web.client.post(action, headers=ORIGIN, follow_redirects=False,
                        data={**hidden_fields(card), "fix": "Параметризовать запрос.", "decision": "false_positive",
                              "final_verdict": "", "comment": "Значение приводится к числу.", "reviewed": "1", "action": "next"})
    assert r.status_code == 303
    location = r.headers["location"]
    keeps(location, flag)
    target = re.search(rf"/projects/{pid}/findings/(\d+)", urlsplit(location).path)
    if target:
        assert hub_id_of(web, int(target.group(1))) in allowed
    # «назад» – тот же отбор и та же выборка
    back = params(card_url)["back"][0]
    keeps(back, flag)
    check(web.client.get(back).text)


def test_chips_toggle_values_and_any_resets(web):  # noqa: F811
    pid, _, _ = seeded(web)
    page = html.unescape(web.client.get(f"/projects/{pid}/findings?kind=SAST&hub_status=Open&hub_status=Confirmed").text)
    group = page[page.index("Статус Hub"):]
    chips = dict((label.strip(), href) for href, label in re.findall(r'<a[^>]+href="([^"]+)"[^>]*>([^<]+)</a>', group)[:6])
    assert params(chips["Open"]).get("hub_status") == ["Confirmed"], "выбранное значение выключается"
    assert params(chips["Fixed"])["hub_status"] == ["Open", "Confirmed", "Fixed"], "новое добавляется"
    anys = [href for href, label in re.findall(r'<a[^>]+href="([^"]+)"[^>]*>([^<]+)</a>', page) if label.strip() == "любой"]
    assert any("hub_status" not in params(h) and params(h).get("kind") == ["SAST"] for h in anys), "«любой» снимает все"
