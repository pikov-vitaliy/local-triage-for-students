"""Статус находки в Hub из карточки (этап 2, ADR-0115) в браузере: адрес Hub и номер приложения заданы, в карточке
SAST выбрано «Ложное срабатывание», срок – кнопкой «+90 дней», «Отправить в Hub»; поддельный исполнитель в потоке теста
забирает операцию и отвечает 200 – карточка сама перезагружается, показывает «Записано в Hub» со сроком и отметку
«статус и комментарий в Hub»; отбор «Не внесены в Hub» её больше не показывает; клавиши карточки не срабатывают в
поле срока. То же для карточки SCA; вёрстка 360 px. Hub, номера и учётные данные выдуманы, сеть – только приложение
на 127.0.0.1."""

from __future__ import annotations

import json
import re
import threading
import urllib.parse
import urllib.request
from datetime import date, timedelta

import pytest

pytest.importorskip("playwright.sync_api")

from playwright.sync_api import expect  # noqa: E402

from e2e_support import worker_key  # noqa: E402
from e2e_support import (  # noqa: E402
    create_demo,
    make_fake_ollama,
    no_horizontal_scroll,
    open_page,
    run_triage,
    start_app,
    stop_app,
)

pytestmark = pytest.mark.e2e

HUB = "https://hub.example.org"
APP_ID = "4242"
FALSE_REASON = "Имя таблицы берётся из заранее заданной строки, поэтому SQL-инъекция исключена."
SCA_REASON = "Уязвимая функция разбора XML в приложении не вызывается: компонент нужен только сборке."


def worker_call(base: str, key: str, method: str, path: str, payload: dict | None = None) -> dict:
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(base + path, data=data, method=method,
                                 headers={"Accept": "application/json", "Content-Type": "application/json",
                                          "Origin": base, "X-Hub-Worker-Key": key})
    with urllib.request.urlopen(req, timeout=40) as resp:
        return json.loads(resp.read().decode("utf-8"))


def answer_200(job: dict) -> tuple[int, str]:
    return 200, "{}"


def fake_worker(base: str, key: str, stop: threading.Event, jobs: list, answers: list) -> None:
    """Поддельный исполнитель: приветствие, долгий опрос; на очередную операцию отвечает следующим из answers
    (функция задание -> (код, тело)), после последнего выходит."""
    worker_call(base, key, "POST", "/api/hub/worker/hello",
                {"worker_id": "e2e-status", "hub_url": HUB, "hub_user": "Иван Тестов", "hub_login": "user1",
                 "roles": ["DEVELOPER"], "version": "e2e"})
    query = urllib.parse.urlencode({"worker_id": "e2e-status", "hub_url": HUB, "wait": 2})
    while not stop.is_set() and len(jobs) < len(answers):
        job = worker_call(base, key, "GET", f"/api/hub/jobs?{query}").get("job")
        if not job:
            continue
        status, body = answers[len(jobs)](job)
        jobs.append(job)
        worker_call(base, key, "POST", f"/api/hub/jobs/{job['attempt_id']}/result",
                    {"lease_token": job["lease_token"], "worker_id": "e2e-status", "status": status,
                     "headers": {"content-type": "application/json"}, "body_text": body, "took_ms": 15})


def start_worker(server, answers: list | None = None) -> tuple[threading.Event, list, threading.Thread]:
    key = worker_key(server)
    stop, jobs = threading.Event(), []
    thread = threading.Thread(target=fake_worker, args=(server.url, key, stop, jobs, answers or [answer_200]),
                              daemon=True)
    thread.start()
    return stop, jobs, thread


def set_hub(page, pid: int) -> None:
    """Адрес Hub в настройках и номер приложения в параметрах проекта – как это делает оператор."""
    page.goto("/settings#hub")
    page.fill("#hub-url", HUB)
    page.locator("#hub-url-save").click()
    page.wait_for_url(re.compile(r"/settings\?ok=settings_saved"))
    page.goto(f"/projects/{pid}#params")
    page.locator("#params > summary").click()
    page.fill("#project-hub-app-id", APP_ID)
    page.locator("#params button[type=submit]", has_text="Сохранить параметры").click()
    page.wait_for_url(re.compile(rf"/projects/{pid}\?ok=project_saved"))


def plus_90() -> str:
    return (date.today() + timedelta(days=90)).isoformat()


def plus_91() -> str:
    return (date.today() + timedelta(days=91)).isoformat()


def ru(day: str) -> str:
    return f"{day[8:10]}.{day[5:7]}.{day[0:4]}"


def send_and_answer(page, server) -> dict:
    """«+90 дней» → «Отправить в Hub»; поддельный исполнитель отвечает – карточка перезагружается сама."""
    page.locator("#hub-send [data-date-value]", has_text="+90 дней").click()
    expect(page.locator("#hub-send-expires")).to_have_value(plus_90())
    expect(page.locator("#hub-send-until-preview")).to_contain_text(" по вашему времени")
    page.locator("#hub-send-button").click()
    expect(page.locator("#hub-send-status")).to_contain_text("В очереди: ждём исполнителя")
    stop, jobs, thread = start_worker(server)
    try:
        expect(page.locator("#hub-send-status")).to_contain_text("Записано в Hub", timeout=30000)
    finally:
        stop.set()
        thread.join(timeout=30)
    assert len(jobs) == 1
    return jobs[0]


def open_first_sast(page, pid: int) -> None:
    page.goto(f"/projects/{pid}/findings?kind=SAST")
    page.locator('table tbody a[href*="/findings/"]').first.click()
    page.wait_for_url(re.compile(rf"/projects/{pid}/findings/\d+(?:\?.*)?$"))


@pytest.fixture
def hub_server(tmp_path):
    with make_fake_ollama() as fake:
        server = start_app(tmp_path, fake.url)
        try:
            yield server
        finally:
            stop_app(server.process)


def test_sast_false_positive_goes_to_hub(browser, hub_server):
    # браузер в поясе UTC+3: срок карточка показывает так, как интерфейс Hub, – конец выбранного дня по UTC
    context, page, watch = open_page(browser, hub_server.url, timezone_id="Etc/GMT-3")
    try:
        pid = create_demo(page)
        set_hub(page, pid)
        run_triage(page, pid)
        open_first_sast(page, pid)
        card = page.url
        # без решения блок не виден: он – часть «Ложного срабатывания»
        expect(page.locator("#hub-send")).to_be_hidden()
        page.locator("label").filter(has=page.locator('input[name="decision"][value="false_positive"]')).click()
        page.fill("#comment", FALSE_REASON)
        expect(page.locator("#hub-send")).to_be_visible()
        expect(page.locator("#hub-send-expires")).to_have_value("")  # срок без умолчания
        # форма несёт назначение, которое показала карточка (KIMI-12): адрес Hub и номер приложения
        expect(page.locator("#hub-send-form input[name=hub_base]")).to_have_value(HUB)
        expect(page.locator("#hub-send-form input[name=hub_app_id]")).to_have_value(APP_ID)
        before = page.locator("#hub-send-text-hash").get_attribute("value")
        page.click("#copy-hub")  # сохраняет решение (и копирует текст)
        expect(page.locator("#copy-status")).to_contain_text("скопирован")
        # отпечаток показанного текста для «Отправить в Hub» пришёл с ответом сохранения (до него решения не было)
        expect(page.locator("#hub-send-text-hash")).not_to_have_value(before or "")
        # клавиши карточки в поле срока не срабатывают: «y» не меняет решение
        page.locator("#hub-send-expires").focus()
        page.keyboard.press("y")
        expect(page.locator('input[name="decision"][value="false_positive"]')).to_be_checked()
        job = send_and_answer(page, hub_server)
        assert job["method"] == "POST" and job["path"] == "/issue/status/update"
        body = job["body"]
        assert body["status"] == "False Positive" and body["issueType"] == "SAST"
        assert body["expiredAt"] == plus_90() + "T00:00:00Z" and FALSE_REASON in body["reason"]
        page.wait_for_url(card)
        expect(page.locator("#hub-send-status")).to_contain_text(f"срок до {ru(plus_91())}, 02:59")
        expect(page.locator("#hub-send-status time")).to_have_attribute("datetime", plus_90() + "T23:59:59Z")
        expect(page.locator("#entered-badge")).to_be_visible()
        expect(page.locator("#entered-badge")).to_contain_text("статус и комментарий в Hub")
        # отметка поставлена – находки нет в отборе «Не внесены в Hub»
        hub_id = page.locator("[data-copy-text]").first.get_attribute("data-copy-text")
        page.goto(f"/projects/{pid}/findings?kind=SAST&reviewed=yes&entered=no")
        expect(page.locator("main")).not_to_contain_text(hub_id)
        assert not watch.problems(), watch.problems()
    finally:
        context.close()


def save_false_positive(page, card: str) -> None:
    """Сохранённое «Ложное срабатывание» с «Проверено» – условие массовой отправки (ADR-0119): отметка ставится явно,
    по умолчанию она стоит не у каждой находки."""
    page.goto(card)
    page.locator("label").filter(has=page.locator('input[name="decision"][value="false_positive"]')).click()
    page.fill("#comment", FALSE_REASON)
    page.locator("#reviewed-box").check()
    page.click("#save-btn")
    page.wait_for_url(re.compile(r"ok=saved"))


def test_send_selected_from_list(browser, hub_server):
    """«Отправить выбранные в Hub» (ADR-0119): две находки SAST с сохранённым «Ложным срабатыванием» отмечены в
    списке → предпросмотр показывает обе → общий комментарий и «+90 дней» → одна операция на поддельном исполнителе →
    «Записано в Hub», у обеих карточек отметка."""
    context, page, watch = open_page(browser, hub_server.url)
    try:
        pid = create_demo(page)
        set_hub(page, pid)
        run_triage(page, pid)
        page.goto(f"/projects/{pid}/findings?kind=SAST")
        # две разные карточки: в строке списка на карточку ведёт не одна ссылка – берём по пути без параметров
        links = page.locator('table tbody a[href*="/findings/"]')
        seen: dict[str, str] = {}
        for i in range(links.count()):
            href = links.nth(i).get_attribute("href") or ""
            seen.setdefault(href.split("?")[0], href)
            if len(seen) == 2:
                break
        cards = list(seen.values())
        assert len(cards) == 2, cards
        for card in cards:
            save_false_positive(page, card)
        page.goto(f"/projects/{pid}/findings?kind=SAST")
        expect(page.locator("#send-selected")).to_be_disabled()
        page.locator("table thead .check-all").check()
        expect(page.locator("#send-selected")).to_be_enabled()
        page.click("#send-selected")
        page.wait_for_url(re.compile(r"/hub/send-selected\?"))
        ready_rows = page.locator("#bulk-ready tbody tr")
        assert ready_rows.count() == 2, (cards, page.locator("#bulk-excluded").inner_text()
                                         if page.locator("#bulk-excluded").count() else "исключённых нет")
        # форма предпросмотра несёт назначение, по которому собран состав (KIMI-12)
        expect(page.locator("#bulk-form input[name=hub_base]")).to_have_value(HUB)
        expect(page.locator("#bulk-form input[name=hub_app_id]")).to_have_value(APP_ID)
        page.fill("#bulk-comment", FALSE_REASON + " Проверено по списку.")
        page.locator("[data-date-value]", has_text="+90 дней").click()
        expect(page.locator("#hub-send-until-preview")).to_contain_text(" по вашему времени")
        page.click("#bulk-send")
        page.wait_for_url(re.compile(r"op=\d+"))
        expect(page.locator("#hub-send-status")).to_contain_text("В очереди")
        stop, jobs, thread = start_worker(hub_server)
        try:
            expect(page.locator("#hub-send-status")).to_contain_text("Записано в Hub", timeout=30000)
        finally:
            stop.set()
            thread.join(timeout=30)
        assert len(jobs) == 1 and jobs[0]["path"] == "/issue/status/change"
        assert len(jobs[0]["body"]["issues"]) == 2 and "Проверено по списку" in jobs[0]["body"]["reason"]
        expect(page.locator("#hub-send-status")).to_contain_text("находок: 2")
        for card in cards:
            page.goto(card)
            expect(page.locator("#entered-badge")).to_be_visible()
            expect(page.locator("#entered-bulk")).to_be_visible()
        assert not watch.problems(), watch.problems()
    finally:
        context.close()


def test_sca_false_positive_goes_to_hub(browser, hub_server):
    context, page, watch = open_page(browser, hub_server.url)
    try:
        pid = create_demo(page)
        set_hub(page, pid)
        page.goto(f"/projects/{pid}/sca")
        page.click("#sca-continue")
        page.wait_for_url(re.compile(r"/sca/findings/\d+"))
        card = page.url
        page.locator("label").filter(has=page.locator("input[name=decision][value=disagree]")).click()
        page.select_option("#final-verdict", "false_positive")
        page.fill("#comment", SCA_REASON)
        page.locator("#review-form button[name=action][value=save]").click()
        page.wait_for_url(re.compile(r"ok=sca_(?:saved|all_reviewed|no_other)"))
        page.goto(card)
        expect(page.locator("#hub-send")).to_be_visible()
        job = send_and_answer(page, hub_server)
        assert job["path"] == "/issue/status/update" and job["body"]["issueType"] == "SCA_S"
        assert job["body"]["status"] == "False Positive" and SCA_REASON in job["body"]["reason"]
        expect(page.locator("#entered-badge")).to_be_visible()
        assert not watch.problems(), watch.problems()
    finally:
        context.close()


@pytest.mark.parametrize("theme", ["light", "dark"])
def test_hub_send_panel_fits_360(browser, hub_server, theme):
    context, page, _ = open_page(browser, hub_server.url)
    try:
        pid = create_demo(page)
        set_hub(page, pid)
        run_triage(page, pid)
        open_first_sast(page, pid)
        card = page.url
    finally:
        context.close()
    context, page, watch = open_page(browser, hub_server.url, width=360, height=800, theme=theme)
    try:
        page.goto(card)
        page.locator("label").filter(has=page.locator('input[name="decision"][value="false_positive"]')).click()
        expect(page.locator("#hub-send")).to_be_visible()
        assert no_horizontal_scroll(page)
        assert not watch.problems(), watch.problems()
    finally:
        context.close()


def test_unknown_result_offers_verify_without_reload(browser, hub_server):
    """Hub не ответил (503): карточка без перезагрузки показывает «результат неизвестен» и кнопку «Сверить»;
    сверка читает статус, он совпал – карточка перезагружается с «Записано в Hub» и отметкой."""
    context, page, watch = open_page(browser, hub_server.url)
    sent = {}

    def unavailable(job):
        sent.update(job["body"])
        return 503, '{"message": "Service Unavailable"}'

    def read_back(job):
        assert job["method"] == "GET" and job["path"].startswith("/issue/status?issueId=")
        # Hub отвечает на адресное чтение записью той же находки – с её номером и типом (бэклог 118)
        return 200, json.dumps({"issueId": sent["issueId"], "issueType": sent["issueType"], "status": sent["status"],
                                "reason": sent["reason"], "expiredAt": sent["expiredAt"]}, ensure_ascii=False)

    try:
        pid = create_demo(page)
        set_hub(page, pid)
        run_triage(page, pid)
        open_first_sast(page, pid)
        card = page.url
        page.locator("label").filter(has=page.locator('input[name="decision"][value="false_positive"]')).click()
        page.fill("#comment", FALSE_REASON)
        page.click("#copy-hub")
        expect(page.locator("#copy-status")).to_contain_text("скопирован")
        expect(page.locator("#hub-verify-form")).to_be_hidden()
        page.locator("#hub-send [data-date-value]", has_text="+30 дней").click()
        page.locator("#hub-send-button").click()
        expect(page.locator("#hub-send-status")).to_contain_text("В очереди")
        stop, jobs, thread = start_worker(hub_server, [unavailable, read_back])
        try:
            expect(page.locator("#hub-send-status")).to_contain_text("Результат неизвестен", timeout=30000)
            expect(page.locator("#hub-verify-button")).to_be_visible()
            assert page.url == card  # без перезагрузки
            page.locator("#hub-verify-button").click()
            expect(page.locator("#hub-send-status")).to_contain_text("Записано в Hub", timeout=30000)
        finally:
            stop.set()
            thread.join(timeout=30)
        assert [job["method"] for job in jobs] == ["POST", "GET"]
        expect(page.locator("#entered-badge")).to_be_visible()
        expect(page.locator("#hub-verify-form")).to_be_hidden()
        assert not watch.problems(), watch.problems()
    finally:
        context.close()


def test_unsaved_edit_is_not_sent(browser, hub_server):
    """Решение изменено, но не сохранено: «Отправить в Hub» не уходит, карточка просит сначала сохранить."""
    context, page, watch = open_page(browser, hub_server.url)
    try:
        pid = create_demo(page)
        set_hub(page, pid)
        run_triage(page, pid)
        open_first_sast(page, pid)
        page.locator("label").filter(has=page.locator('input[name="decision"][value="false_positive"]')).click()
        page.fill("#comment", FALSE_REASON)
        page.click("#copy-hub")
        expect(page.locator("#copy-status")).to_contain_text("скопирован")
        page.fill("#comment", FALSE_REASON + " Уточнение не сохранено.")
        page.locator("#hub-send [data-date-value]", has_text="+30 дней").click()
        page.locator("#hub-send-button").click()
        expect(page.locator("#copy-status")).to_contain_text("сохраните его и затем отправьте в Hub")
        expect(page.locator("#hub-send-status")).to_be_hidden()
        assert not watch.problems(), watch.problems()
    finally:
        context.close()


def test_send_waits_while_decision_is_being_saved(browser, hub_server):
    """«Сохранить» отправлено, ответа ещё нет: «Отправить в Hub» не уходит со старой редакцией. Состояние «ответа ещё
    нет» воспроизводится событием submit формы решения из страницы: обработчики карточки срабатывают, а сам запрос не
    уходит (событие не настоящее) – как будто сервер ещё не ответил."""
    context, page, watch = open_page(browser, hub_server.url)
    try:
        pid = create_demo(page)
        set_hub(page, pid)
        run_triage(page, pid)
        open_first_sast(page, pid)
        page.locator("label").filter(has=page.locator('input[name="decision"][value="false_positive"]')).click()
        page.fill("#comment", FALSE_REASON)
        texts = page.evaluate("""() => {
            const form = document.getElementById('review-form');
            form.dispatchEvent(new Event('submit', {cancelable: true}));
            document.querySelector('#hub-send [data-date-value]').click();
            document.getElementById('hub-send-button').click();
            return [document.getElementById('copy-status').textContent,
                    document.getElementById('hub-send-status').hidden];
        }""")
        assert "Решение ещё сохраняется" in texts[0] and texts[1] is True, texts
        assert not watch.problems(), watch.problems()
    finally:
        context.close()


NEW_REASON = "Класс лежит в тестовых исходниках и в артефакт сборки не входит: отладочного кода в продукте нет."


def test_replace_comment_of_status_already_in_hub(browser, hub_server):
    """Замена комментария у статуса, который уже стоит в Hub (dev29): после записанного «Ложного срабатывания» оператор
    правит обоснование и сохраняет – панель переходит в режим «Обновить комментарий в Hub» с прежним сроком; по
    подтверждению уходят две операции (поддельный исполнитель отвечает 200 на обе): «Confirmed», затем «Ложное
    срабатывание» с новым комментарием; карточка показывает «Записано в Hub» и отметку."""
    context, page, watch = open_page(browser, hub_server.url)
    try:
        pid = create_demo(page)
        set_hub(page, pid)
        run_triage(page, pid)
        open_first_sast(page, pid)
        card = page.url.split("?")[0]
        save_false_positive(page, card)
        send_and_answer(page, hub_server)
        page.wait_for_url(re.compile(re.escape(card)))
        expect(page.locator("#entered-badge")).to_be_visible()
        expect(page.locator("#hub-send-button")).to_have_text("Отправить в Hub")
        expect(page.locator("#hub-send-replace-note")).to_be_hidden()
        # правка обоснования и сохранение копированием (AJAX, без перехода): ответ сохранения переключает панель
        # в режим замены
        page.fill("#comment", NEW_REASON)
        page.click("#copy-hub")
        expect(page.locator("#copy-status")).to_contain_text("скопирован")
        expect(page.locator("#hub-send-button")).to_have_text("Обновить комментарий в Hub")
        expect(page.locator("#hub-send-replace-note")).to_contain_text("уже стоит «Ложное срабатывание»")
        expect(page.locator("#hub-send-replace-confirm")).to_be_visible()
        expect(page.locator("#entered-badge")).to_be_hidden()
        assert page.url.split("?")[0] == card, "панель переключилась без перехода"
        # прежний срок (+90 дней первой отправки) подставлен ответом сохранения; флажок обязателен; отправка – без
        # перезагрузки карточки
        expect(page.locator("#hub-send-expires")).to_have_value(plus_90())
        expect(page.locator("#hub-send-replace-box")).to_have_attribute("required", "")
        page.locator("#hub-send-replace-box").check()
        page.locator("#hub-send-button").click()
        expect(page.locator("#hub-send-status")).to_contain_text("сначала «Подтверждено»")
        stop, jobs, thread = start_worker(hub_server, [answer_200, answer_200])
        try:
            expect(page.locator("#hub-send-status")).to_contain_text("Записано в Hub", timeout=45000)
        finally:
            stop.set()
            thread.join(timeout=30)
        assert len(jobs) == 2, jobs
        assert jobs[0]["path"] == "/issue/status/update" and jobs[0]["body"]["status"] == "Confirmed"
        assert jobs[0]["body"]["expiredAt"] == plus_90() + "T00:00:00Z"
        assert jobs[1]["path"] == "/issue/status/update" and jobs[1]["body"]["status"] == "False Positive"
        assert NEW_REASON in jobs[1]["body"]["reason"] and jobs[1]["body"]["expiredAt"] == plus_90() + "T00:00:00Z"
        page.wait_for_url(re.compile(re.escape(card)))
        expect(page.locator("#entered-badge")).to_be_visible()
        expect(page.locator("#hub-send-button")).to_have_text("Отправить в Hub")
        expect(page.locator("#hub-send-replace-note")).to_be_hidden()
        assert not watch.problems(), watch.problems()
    finally:
        context.close()


ALREADY_SCA = ('{"errorMessage": "Unable to change status for SCA_S issue #%s: issue already has the requested status '
               'FALSE_POSITIVE", "requestValidationError": null}')


def test_refusal_line_follows_a_changed_decision(browser, hub_server):
    """Отказ Hub «already has…» у «Ложного срабатывания» SCA; оператор меняет решение на «Риск принят» и сохраняет
    копированием (без перехода): кнопка – «Отправить в Hub», строка отказа – о прежнем решении, без предложения
    замены (ревью dev29, круг 8)."""
    context, page, watch = open_page(browser, hub_server.url)

    def refuse(job):
        return 400, ALREADY_SCA % job["body"]["issueId"]

    try:
        pid = create_demo(page)
        set_hub(page, pid)
        page.goto(f"/projects/{pid}/sca")
        page.click("#sca-continue")
        page.wait_for_url(re.compile(r"/sca/findings/\d+"))
        card = page.url
        page.locator("label").filter(has=page.locator("input[name=decision][value=disagree]")).click()
        page.select_option("#final-verdict", "false_positive")
        page.fill("#comment", SCA_REASON)
        page.locator("#review-form button[name=action][value=save]").click()
        page.wait_for_url(re.compile(r"ok=sca_(?:saved|all_reviewed|no_other)"))
        page.goto(card)
        page.locator("#hub-send [data-date-value]", has_text="+90 дней").click()
        page.locator("#hub-send-button").click()
        expect(page.locator("#hub-send-status")).to_contain_text("В очереди")
        stop, jobs, thread = start_worker(hub_server, [refuse])
        try:
            expect(page.locator("#hub-send-status")).to_contain_text("уже стоит", timeout=30000)
        finally:
            stop.set()
            thread.join(timeout=30)
        page.wait_for_url(re.compile(re.escape(card.split("?")[0])))  # отказ перезагружает карточку: режим – с сервера
        expect(page.locator("#hub-send-button")).to_have_text("Обновить комментарий в Hub")
        expect(page.locator("#hub-send-status")).to_contain_text("Заменить комментарий можно")
        # другое решение, сохранённое копированием без перехода
        page.locator("label").filter(has=page.locator("input[name=decision][value=risk_accepted]")).click()
        page.select_option("#kapo-state", "not_actual")
        page.fill("#comment", SCA_REASON + " Риск принят на срок до пересмотра.")
        page.click("#copy-hub")
        expect(page.locator("#copy-status")).to_contain_text("скопирован")
        assert page.url.split("?")[0] == card.split("?")[0]
        expect(page.locator("#hub-send-button")).to_have_text("Отправить в Hub")
        expect(page.locator("#hub-send-status")).to_contain_text("Текущее решение другое – отправьте его")
        expect(page.locator("#hub-send-status")).not_to_contain_text("Заменить комментарий можно")
        assert not watch.problems(), watch.problems()
    finally:
        context.close()
