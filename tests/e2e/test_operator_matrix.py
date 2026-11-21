"""Матрица сценариев оператора (перечень – docs/e2e-operator-matrix.md):
проверки сценариев, которых не было в других файлах. Прогон модели: пауза, продолжение и перезапуск приложения посреди
работы; решение «Риск принят» у SCA с отправкой в Hub; дефект SCA: создание, «Pull из Hub» и «Push в Hub»; перенос
находки между наборами; перезапуск посреди цепочки замены комментария. Модель и исполнитель поддельные, Hub, номера и
учётные данные выдуманы, сеть – только приложение на 127.0.0.1."""

from __future__ import annotations

import json
import re
from urllib.parse import urlsplit

import pytest

pytest.importorskip("playwright.sync_api")

from playwright.sync_api import expect  # noqa: E402

from db_support import connect_db  # noqa: E402
from e2e_support import (  # noqa: E402
    DEMO_REPOS,
    DEMO_SCA_EXPLANATION,
    create_demo,
    make_fake_ollama,
    open_page,
    run_triage,
    save_sca_decision,
    sca_set_text_ready,
    start_app,
    stop_app,
    wait_run_done,
)
from fake_ollama import FakeOllama, verdict_answer  # noqa: E402
from test_hub_defect_import_flow import import_number  # noqa: E402
from test_hub_defect_update_flow import BLOCK, OLD_SUMMARY, defect, run_worker  # noqa: E402
from test_hub_status_card import (  # noqa: E402
    FALSE_REASON,
    NEW_REASON,
    answer_200,
    hub_server,  # noqa: F401
    open_first_sast,
    save_false_positive,
    send_and_answer,
    set_hub,
    start_worker,
)
from test_operator_readiness import seeded_app  # noqa: E402
from test_scroll_and_decision_ergonomics import open_first_sca  # noqa: E402
from test_stored_code_snapshots import restart  # noqa: E402

pytestmark = pytest.mark.e2e

RUN_ITEMS = 12
RISK_REASON = "Уязвимая функция разбора XML не вызывается, риск принят: пересмотреть при обновлении компонента."
# Находки одной версии компонента в демо-проекте (examples/demo): первая карточка SCA и её соседка
SCA_IDS = ["200201", "200202"]


def run_status(page, run_url: str) -> dict:
    return page.request.get(run_url + "/status").json()["run"]


def progress_above(done: int, total: int) -> re.Pattern:
    """Строка хода прогона, где обработано больше done: приходит потоком событий, без опроса и пауз."""
    numbers = "|".join(str(n) for n in range(done + 1, total + 1))
    return re.compile(rf"Обработано (?:{numbers}) из {total}\b")


def start_run(page, pid: int) -> str:
    page.goto(f"/projects/{pid}#step3")
    page.get_by_role("button", name="Запустить триаж", exact=True).click()
    page.wait_for_url(re.compile(r"/runs/\d+$"))
    return page.url


def choose_agree(page) -> None:
    """«Согласен с агентом»: у первой находки демо это «Обновить» (вывод агента из загруженного ответа)."""
    page.locator("label").filter(has=page.locator("input[name=decision][value=agree]")).click()
    expect(page.locator("#final-verdict")).to_have_value("true_positive")


def save_risk_accepted(page, card: str) -> None:
    page.goto(card)
    page.locator("label").filter(has=page.locator("input[name=decision][value=risk_accepted]")).click()
    page.select_option("#kapo-state", "not_actual")
    page.fill("#comment", RISK_REASON)
    save_sca_decision(page)
    page.goto(card)
    expect(page.locator("input[name=decision][value=risk_accepted]")).to_be_checked()
    expect(page.locator("#kapo-state")).to_have_value("not_actual")


def sca_create_hub(seen: dict):
    """Поддельный Hub для дефекта SCA: заготовка по запрошенным находкам с типом SCA_S, справочник, создание, чтение."""
    def answer(job: dict) -> tuple[int, str]:
        path, method = job["path"], job["method"]
        if path.startswith("/defects/blank?"):
            seen["blank_path"] = path
            ids = re.search(r"issueIds=([0-9,]+)", path).group(1).split(",")
            seen["links"] = [{"id": int(i), "type": "SCA_S"} for i in ids]
            return 200, json.dumps({"summary": "заготовка", "description": "<p>Информация об объекте сканирования:</p>",
                                    "priority": {"name": "Major", "rank": 2}, "severity": {"name": "Medium", "rank": 2},
                                    "source": "Tool", "stage": "DEV", "type": "Software", "status": "Registered",
                                    "linkedIssues": seen["links"]}, ensure_ascii=False)
        if path == "/defects/serviceInfo":
            return 200, json.dumps({"statuses": [{"name": "Registered", "rank": 0}],
                                    "priorities": [{"name": "Major", "rank": 2}]})
        if method == "POST" and path == "/defects":
            seen["created"] = job["body"]
            return 200, json.dumps({"id": 555})
        if path == "/defects/555":
            return 200, json.dumps({"id": 555, "appId": seen["created"]["appId"], "summary": seen["created"]["summary"],
                                    "linkedIssues": seen["links"], "description": seen["created"]["description"]},
                                   ensure_ascii=False)
        return 404, "{}"
    return answer


def sca_defect_777(ids: list[str], **extra) -> dict:
    return defect([], summary=OLD_SUMMARY.replace("(SAST)", "(SCA)"),
                  linkedIssues=[{"id": int(i), "type": "SCA_S"} for i in ids], **extra)


def sca_update_hub(ids: list[str], seen: dict):
    """Поддельный Hub для дефекта №777 с находками SCA: чтение – прежний дефект или, после записи, отправленное;
    `PUT` – 204 без тела, тело записи – в seen["put"]."""
    def answer(job: dict) -> tuple[int, str]:
        assert job["path"] == "/defects/777", job
        if job["method"] == "PUT":
            seen.setdefault("put", []).append(job["body"])
            return 204, ""
        assert job["method"] == "GET", job
        if seen.get("put"):
            return 200, json.dumps({**seen["put"][-1], "updateTs": "2026-10-29T12:00:00Z"}, ensure_ascii=False)
        return 200, json.dumps(sca_defect_777(ids), ensure_ascii=False)
    return answer


def test_run_pause_resume_and_finish_the_same_run(browser, tmp_path):
    """Сценарий 2: «Пауза» останавливает прогон, «Продолжить» продвигает тот же прогон до конца, каждая находка
    спрошена у модели один раз."""
    pid, repos, _ = seeded_app(tmp_path, count=RUN_ITEMS)
    with FakeOllama(delay=0.25, default_answer=verdict_answer(evidence_lines=[4])) as fake:
        server = start_app(tmp_path, fake.url, repos_root=repos)
        context, page, watch = open_page(browser, server.url)
        try:
            run_url = start_run(page, pid)
            page.get_by_role("button", name="Пауза", exact=True).click()
            expect(page.locator("#run-state")).to_have_class(re.compile(r"\bstate-paused\b"), timeout=15000)
            paused = run_status(page, run_url)
            assert paused["state"] == "paused" and paused["done"] < paused["total"] == RUN_ITEMS
            page.get_by_role("button", name="Продолжить", exact=True).click()
            expect(page.locator("#run-state")).to_have_class(re.compile(r"\bstate-(?:running|done)\b"), timeout=15000)
            expect(page.locator("#progress-text")).to_have_text(progress_above(paused["done"], RUN_ITEMS), timeout=30000)
            wait_run_done(page)
            assert page.url.split("?")[0] == run_url, "продолжается тот же прогон"
            finished = run_status(page, run_url)
            assert finished["done"] == RUN_ITEMS and finished["failed"] == 0
            assert len(fake.chats()) == RUN_ITEMS, "после паузы находки повторно не спрашиваются"
            assert not watch.problems(), watch.problems()
        finally:
            context.close()
            stop_app(server.process)


def test_sca_risk_accepted_goes_to_hub(browser, hub_server):  # noqa: F811
    """Сценарии 4 и 11: у находки SCA решение «Риск принят» с уточнением по ГОСТ Р КАПО и комментарием; «Отправить в
    Hub» – поддельный исполнитель получает статус «Accepted risk» типа SCA_S; карточка показывает отметку."""
    context, page, watch = open_page(browser, hub_server.url)
    try:
        pid = create_demo(page)
        set_hub(page, pid)
        open_first_sca(page, pid)
        card = page.url.split("?")[0].split("#")[0]
        save_risk_accepted(page, card)
        expect(page.locator("#hub-send")).to_be_visible()
        job = send_and_answer(page, hub_server)
        assert job["path"] == "/issue/status/update" and job["method"] == "POST"
        assert job["body"]["status"] == "Accepted risk" and job["body"]["issueType"] == "SCA_S"
        assert RISK_REASON in job["body"]["reason"]
        expect(page.locator("#entered-badge")).to_be_visible()
        assert not watch.problems(), watch.problems()
    finally:
        context.close()


def create_sca_defect(page, server, seen: dict) -> tuple[int, str, list[dict]]:
    """От решения по версии до созданного дефекта SCA: возвращает проект, адрес карточки находки и задания исполнителя."""
    pid = create_demo(page)
    set_hub(page, pid)
    open_first_sca(page, pid)
    card = page.url.split("?")[0].split("#")[0]
    choose_agree(page)
    save_sca_decision(page)
    members = page.locator("#sca-set-members").inner_text().split(", ")
    assert members == SCA_IDS
    sca_set_text_ready(page, DEMO_SCA_EXPLANATION)
    expect(page.locator("#hub-defect-button")).to_be_visible()
    stop, jobs, thread = start_worker(server, [sca_create_hub(seen)] * 4)
    try:
        page.click("#hub-defect-button")
        page.wait_for_url(re.compile(r"/defects/\d+(\?.*)?$"))
        expect(page.locator("#hub-defect-preview")).to_be_visible(timeout=30000)
        expect(page.locator("#hub-defect-summary")).to_contain_text("(SCA)")
        expect(page.locator("#hub-defect-targets")).to_contain_text("(2)")
        page.click("#hub-defect-create")
        expect(page.locator("#hub-defect-done")).to_be_visible(timeout=30000)
        expect(page.locator("#hub-defect-done")).to_contain_text("№555")
        expect(page.locator("#hub-defect-done")).to_contain_text("ID1")
    finally:
        stop.set()
        thread.join(timeout=30)
    return pid, card, jobs


def test_sca_defect_created_through_hub(browser, hub_server):  # noqa: F811
    """Сценарий 12: решение по версии и текст набора, «Создать дефект», заготовка SCA_S, «Создать» – номер дефекта в
    Hub, ID<n> в заголовке, отметка в карточке находки и строка во вкладке «Дефекты»."""
    context, page, watch = open_page(browser, hub_server.url)
    seen: dict = {}
    try:
        pid, card, jobs = create_sca_defect(page, hub_server, seen)
        assert [j["path"].split("?")[0] for j in jobs] == ["/defects/blank", "/defects/serviceInfo", "/defects",
                                                           "/defects/555"]
        assert "type=SCA_S" in seen["blank_path"] and f"issueIds={','.join(SCA_IDS)}" in seen["blank_path"]
        created = seen["created"]
        assert re.fullmatch(r"ID1 - .+ \(SCA\)", created["summary"]), created["summary"]
        assert "до версии 2.3.9" in created["description"] and "CVE-2099-10002" in created["description"]
        assert created["description"].endswith("<p>Информация об объекте сканирования:</p>")
        page.goto(card)
        expect(page.locator("#entered-badge")).to_be_visible()
        page.goto(f"/projects/{pid}/defects")
        expect(page.locator("#hub-defects tbody tr")).to_have_count(1)
        expect(page.locator("#hub-defects tbody tr").first).to_have_attribute("data-state", "done")
        expect(page.locator('#hub-defects a[href*="/defects/555"]')).to_be_visible()
        assert not watch.problems(), watch.problems()
    finally:
        context.close()


def test_sca_defect_badge_names_the_defect(browser, hub_server):  # noqa: F811
    """Сценарий 12, отметка в карточке находки: создан дефект, статус и комментарий в Hub не отправлялись. Отметка
    говорит о дефекте, как в карточке SAST и как кнопка «Отметить: дефект создан в Hub» в этой же карточке."""
    context, page, _ = open_page(browser, hub_server.url)
    seen: dict = {}
    try:
        _, card, jobs = create_sca_defect(page, hub_server, seen)
        assert "/issue/status/update" not in [j["path"] for j in jobs]
        page.goto(card)
        expect(page.locator("#entered-badge")).to_contain_text("дефект создан в Hub")
    finally:
        context.close()


def test_sca_defect_pull_and_push(browser, tmp_path):
    """Сценарии 13 и 14 для дефекта SCA: дефект занесён из Hub; «Pull из Hub» во вкладке и в карточке – «совпадает»;
    решение и текст набора; «Push в Hub» уходит прочитанным объектом с новыми заголовком и текстом, блок Hub сохранён;
    «Pull из Hub» после записи снова «совпадает»."""
    seen: dict = {}
    with make_fake_ollama() as fake:
        server = start_app(tmp_path, fake.url)
        context, page, watch = open_page(browser, server.url)
        try:
            pid = create_demo(page)
            set_hub(page, pid)
            open_first_sca(page, pid)
            card = page.url.split("?")[0].split("#")[0]
            hub = sca_update_hub(SCA_IDS, seen)
            page.goto(f"/projects/{pid}/defects")
            import_number(page, "777")
            run_worker(server, [hub], lambda: expect(
                page.locator("form[id^='hub-import-accept-form-'] button")).to_be_visible(timeout=30000))
            page.locator("form[id^='hub-import-accept-form-'] button").click()
            page.wait_for_url(re.compile(r"ok=hub_import_done"))
            row = page.locator('#hub-defects tr[data-origin="import"]')
            expect(row).to_have_attribute("data-state", "done")
            # «Pull из Hub» во вкладке: в Hub то же, что принято
            row.locator("form[id^='hub-sync-form-'] button").click()
            expect(page.locator("[id^=hub-sync-matches-]")).to_have_count(0)
            jobs = run_worker(server, [hub], lambda: expect(page.locator("[id^=hub-sync-matches-]")).to_be_visible(
                timeout=30000))
            assert [(j["method"], j["path"]) for j in jobs] == [("GET", "/defects/777")]
            expect(page.locator("[id^=hub-sync-matches-]")).to_contain_text("совпадает")
            expect(page.locator("section.hub-sync-preview")).to_have_count(0)
            # «Pull из Hub» в карточке дефекта
            row.locator('td[data-label="Заголовок"] a').click()
            page.wait_for_url(re.compile(r"/defects/\d+(\?.*)?$"))
            defect_card = page.url.split("?")[0]
            pull = page.locator(".page-actions").get_by_role("button", name="Pull из Hub", exact=True)
            pull.click()
            expect(page.locator("[id^=hub-sync-matches-]")).to_have_count(0)
            jobs = run_worker(server, [hub], lambda: expect(page.locator("[id^=hub-sync-matches-]")).to_be_visible(
                timeout=30000))
            assert [(j["method"], j["path"]) for j in jobs] == [("GET", "/defects/777")]
            expect(page.locator("[id^=hub-sync-matches-]")).to_contain_text("совпадают с принятой версией")
            assert page.url.split("?")[0] == defect_card
            # решение и текст набора в карточке находки
            page.goto(card)
            choose_agree(page)
            save_sca_decision(page)
            sca_set_text_ready(page, DEMO_SCA_EXPLANATION)
            page.goto(defect_card)
            expect(page.locator("#defect-generate-blocked")).to_have_count(0)
            page.get_by_role("button", name="Собрать текст из решений").click()
            expect(page.locator("#draft-command-text")).to_have_value(re.compile("до версии 2.3.9"))
            # «Push в Hub» во вкладке: подготовка, предпросмотр, запись
            page.goto(f"/projects/{pid}/defects")
            row = page.locator('#hub-defects tr[data-origin="import"]')
            row.locator("form[id^='hub-update-form-'] button").click()
            page.wait_for_url(re.compile(r"ok=hub_update_queued"))
            run_worker(server, [hub], lambda: expect(page.locator("section.hub-update-preview")).to_be_visible(
                timeout=30000))
            preview = page.locator("section.hub-update-preview")
            expect(preview.locator("[id^='hub-update-old-summary-']")).to_contain_text("(SCA)")
            new_summary = preview.locator("[id^='hub-update-summary-']").inner_text().strip()
            assert new_summary.startswith("ID5 - ") and new_summary.endswith("(SCA)"), new_summary
            preview.locator("form[id^='hub-update-put-form-'] button").click()
            page.wait_for_url(re.compile(r"ok=hub_update_put_queued"))
            row = page.locator('#hub-defects tr[data-origin="import"]')
            jobs = run_worker(server, [hub] * 3, lambda: expect(row).to_contain_text("Обновлено в Hub", timeout=30000))
            assert [(j["method"], j["path"]) for j in jobs] == [("GET", "/defects/777"), ("PUT", "/defects/777"),
                                                                ("GET", "/defects/777")]
            put = seen["put"][0]
            before = sca_defect_777(SCA_IDS)
            assert {k: v for k, v in put.items() if k not in ("summary", "description")} == {
                k: v for k, v in before.items() if k not in ("summary", "description")}
            assert put["summary"] == new_summary
            assert "до версии 2.3.9" in put["description"] and put["description"].endswith(BLOCK)
            assert "Старый текст команды" not in put["description"]
            assert [(i["id"], i["type"]) for i in put["linkedIssues"]] == [(int(i), "SCA_S") for i in SCA_IDS]
            page.goto(card)
            expect(page.locator("#entered-badge")).to_be_visible()
            # «Pull из Hub» после записи: расхождений нет
            page.goto(defect_card)
            page.locator(".page-actions").get_by_role("button", name="Pull из Hub", exact=True).click()
            expect(page.locator("[id^=hub-sync-matches-]")).to_have_count(0)
            run_worker(server, [hub], lambda: expect(page.locator("[id^=hub-sync-matches-]")).to_be_visible(
                timeout=30000))
            expect(page.locator("[id^=hub-sync-matches-]")).to_contain_text("совпадают с принятой версией")
            expect(page.locator("section.hub-sync-preview")).to_have_count(0)
            assert not watch.problems(), watch.problems()
        finally:
            context.close()
            stop_app(server.process)


def test_restart_in_the_middle_of_a_run(browser, tmp_path):
    """Сценарий 19: приложение остановлено, когда часть находок разобрана. После запуска на той же базе прогон на паузе
    с пояснением, ничего не потеряно; «Продолжить» доводит тот же прогон до конца без ошибок."""
    pid, repos, _ = seeded_app(tmp_path, count=RUN_ITEMS)
    with FakeOllama(delay=0.5, default_answer=verdict_answer(evidence_lines=[4])) as fake:
        server = start_app(tmp_path, fake.url, repos_root=repos)
        context, page, watch = open_page(browser, server.url)
        try:
            run_url = start_run(page, pid)
            run_path = run_url[len(server.url):]
            expect(page.locator("#progress-text")).to_have_text(progress_above(0, RUN_ITEMS), timeout=30000)
            before = run_status(page, run_url)
            assert 0 < before["done"] < RUN_ITEMS
            assert not watch.problems(), watch.problems()
        finally:
            context.close()  # поток событий страницы закрывается раньше приложения: это не ошибка страницы
            stop_app(server.process)
        server = restart(tmp_path, fake.url, repos)
        context, page, watch = open_page(browser, server.url)
        try:
            page.goto(run_path)
            expect(page.locator("#run-state")).to_have_class(re.compile(r"\bstate-paused\b"))
            expect(page.locator("#run-notice")).to_contain_text("Приложение перезапускалось")
            expect(page.locator("#run-notice")).to_contain_text("Нажмите «Продолжить»")
            paused = run_status(page, server.url + run_path)
            assert paused["state"] == "paused" and before["done"] <= paused["done"] < RUN_ITEMS
            fake.delay = 0
            page.get_by_role("button", name="Продолжить", exact=True).click()
            wait_run_done(page)
            assert page.url.split("?")[0] == server.url + run_path, "продолжается тот же прогон"
            finished = run_status(page, server.url + run_path)
            assert finished["done"] == RUN_ITEMS and finished["failed"] == 0
            expect(page.locator("#run-notice")).to_be_hidden()
            assert not watch.problems(), watch.problems()
        finally:
            context.close()
            stop_app(server.process)


@pytest.mark.parametrize("crash", [False, True], ids=["second_step_queued", "crash_before_second_step"])
def test_restart_after_first_step_of_comment_replace(browser, tmp_path, crash):
    """Сценарий 19, цепочка замены комментария: первый шаг («Confirmed») выполнен, приложение остановлено. После запуска
    исполнитель получает только второй шаг («False Positive» с новым комментарием), первый не повторяется.

    crash_before_second_step – сбой между записью результата первого шага и постановкой второго: такой миг снаружи не
    поймать, поэтому пока приложение остановлено, состояние в базе приводится к нему (второго шага нет, отметки о его
    постановке нет). Второй шаг тогда ставит восстановление при запуске (hub_effects.recover_chains)."""
    with make_fake_ollama() as fake:
        server = start_app(tmp_path, fake.url)
        context, page, watch = open_page(browser, server.url)
        try:
            pid = create_demo(page)
            set_hub(page, pid)
            run_triage(page, pid)
            open_first_sast(page, pid)
            card = page.url.split("?")[0].split("#")[0]
            save_false_positive(page, card)
            send_and_answer(page, server)
            page.wait_for_url(re.compile(re.escape(card)))
            expect(page.locator("#entered-badge")).to_be_visible()
            page.fill("#comment", NEW_REASON)
            page.click("#copy-hub")
            expect(page.locator("#copy-status")).to_contain_text("скопирован")
            expect(page.locator("#hub-send-button")).to_have_text("Обновить комментарий в Hub")
            page.locator("#hub-send-replace-box").check()
            page.locator("#hub-send-button").click()
            expect(page.locator("#hub-send-status")).to_contain_text("сначала «Подтверждено»")
            stop, first_jobs, thread = start_worker(server, [answer_200])
            thread.join(timeout=30)
            stop.set()
            assert not thread.is_alive() and [j["body"]["status"] for j in first_jobs] == ["Confirmed"], first_jobs
            assert not watch.problems(), watch.problems()
        finally:
            context.close()
            stop_app(server.process)
        with connect_db(server.data_dir / "triage.db") as db:
            ops = db.execute("SELECT id, state, request_json FROM hub_ops WHERE purpose = 'status' ORDER BY id").fetchall()
            first, second = ops[-2], ops[-1]
            assert first["state"] == "done" and second["state"] == "queued", [dict(o) for o in ops]
            if crash:
                request = json.loads(first["request_json"])
                assert request["then"].pop("chained") == second["id"]
                db.execute("DELETE FROM hub_ops WHERE id = ?", (second["id"],))
                db.execute("UPDATE hub_ops SET request_json = ? WHERE id = ?",
                           (json.dumps(request, ensure_ascii=False), first["id"]))
            db.commit()
        server = restart(tmp_path, fake.url, DEMO_REPOS)
        card = server.url + urlsplit(card).path  # после перезапуска порт другой
        context, page, watch = open_page(browser, server.url)
        try:
            page.goto(card)
            stop, jobs, thread = start_worker(server, [answer_200])
            thread.join(timeout=30)
            stop.set()
            assert not thread.is_alive(), "второй шаг замены не пришёл исполнителю после перезапуска"
            assert [(j["path"], j["body"]["status"]) for j in jobs] == [("/issue/status/update", "False Positive")]
            assert NEW_REASON in jobs[0]["body"]["reason"] and FALSE_REASON not in jobs[0]["body"]["reason"]
            page.goto(card)
            expect(page.locator("#entered-badge")).to_be_visible()
            expect(page.locator("#hub-send-button")).to_have_text("Отправить в Hub")
            assert not watch.problems(), watch.problems()
        finally:
            context.close()
            stop_app(server.process)


def test_sca_finding_moves_between_sets(browser, hub_server):  # noqa: F811
    """Сценарий 10: находка переносится в новый набор: у неё «набор N» и только она в составе, у соседки – вся версия
    без неё; возврат в общий дефект версии восстанавливает состав."""
    context, page, watch = open_page(browser, hub_server.url)
    try:
        pid = create_demo(page)
        open_first_sca(page, pid)
        card = page.url.split("?")[0].split("#")[0]
        choose_agree(page)
        save_sca_decision(page)
        expect(page.locator("#sca-set-title")).to_contain_text("вся версия компонента")
        expect(page.locator("#sca-set-members")).to_have_text(", ".join(SCA_IDS))
        page.goto(card)
        moved, other = SCA_IDS
        expect(page.locator(".finding-id")).to_have_text(moved)
        page.locator("#sca-set-move > summary").click()
        page.select_option("#sca-set-target", "new")
        page.locator("#sca-set-form button[type=submit]").click()
        page.wait_for_url(re.compile(r"ok=sca_set_saved"))
        expect(page.locator("#sca-set-title")).to_contain_text("набор 1")
        expect(page.locator("#sca-set-members")).to_have_text(moved)
        page.locator("#siblings a", has_text=other).click()
        expect(page.locator(".finding-id")).to_have_text(other)
        expect(page.locator("#sca-set-title")).to_contain_text("вся версия компонента")
        expect(page.locator("#sca-set-members")).to_have_text(other)
        # обратно в общий дефект версии
        page.goto(card)
        page.locator("#sca-set-move > summary").click()
        page.select_option("#sca-set-target", "0")
        page.locator("#sca-set-form button[type=submit]").click()
        page.wait_for_url(re.compile(r"ok=sca_set_saved"))
        expect(page.locator("#sca-set-title")).to_contain_text("вся версия компонента")
        expect(page.locator("#sca-set-members")).to_have_text(", ".join(SCA_IDS))
        assert not watch.problems(), watch.problems()
    finally:
        context.close()
