"""Дефект в Hub из карточки (ADR-0120) в браузере: адрес Hub и номер приложения заданы, в карточке SAST сохранено
«Подтверждаю дефект» с обоснованием и рекомендацией, «Создать дефект в Hub»; поддельный исполнитель в потоке теста
отдаёт заготовку и справочник – карточка сама перезагружается и показывает предпросмотр (заголовок, текст, находки,
приоритет из справочника); «Создать» – исполнитель отвечает на создание и чтение – карточка показывает «Дефект создан
в Hub» со ссылкой и отметку «дефект создан в Hub»; смена решения после этого – только с подтверждением (ADR-0121):
отказ открывает флажок, после подтверждения карточка помечает, что дефект в Hub прежний; во вкладке «Дефекты» – строка
со ссылками на карточку и на дефект. У находки с дефектом «Проверить в Hub» – опрос до итога (404 – пояснение),
«Снять отметку» и «Отправить в Hub» – отказ 409 открывает флажок, с ним действие проходит; новая находка той же группы –
«Привязать к дефекту», отказ Hub – «не принят», вторая попытка – опрос до «Находки привязаны к дефекту в Hub».
Hub, номера и учётные данные выдуманы, сеть – только приложение на 127.0.0.1."""

from __future__ import annotations

import json
import re

import pytest

pytest.importorskip("playwright.sync_api")

from playwright.sync_api import expect  # noqa: E402

from e2e_support import create_demo, open_page, run_triage, start_app, stop_app  # noqa: E402
from fake_ollama import FakeOllama, verdict_answer  # noqa: E402
from test_hub_status_card import hub_server, open_first_sast, set_hub, start_worker  # noqa: E402,F401
from test_operator_sast_route import card_urls, seeded  # noqa: E402

pytestmark = pytest.mark.e2e

REASON = "Строка подставляет параметр owner из запроса в SQL-запрос конкатенацией: через него можно изменить запрос."
FIX = "1) Использовать параметризованные запросы PreparedStatement.\n2) Имена таблиц – только из белого списка."
FALSE_REASON = "Ложное срабатывание: owner сверяется с белым списком имён до сборки запроса."
SERVICE = {"statuses": [{"name": "Registered", "rank": 0}],
           "priorities": [{"name": "Blocker", "rank": 0}, {"name": "Critical", "rank": 1}, {"name": "Major", "rank": 2}]}


def make_hub(seen: dict):
    """Ответы поддельного Hub по пути задания; номера находок – из заготовки, которую запросило приложение."""
    def answer(job: dict) -> tuple[int, str]:
        path, method = job["path"], job["method"]
        if path.startswith("/defects/blank?"):
            ids = re.search(r"issueIds=([0-9,]+)", path).group(1).split(",")
            seen["links"] = [{"id": int(i), "type": "SAST"} for i in ids]
            return 200, json.dumps({"summary": "заготовка", "description": "<p>Информация об объекте сканирования:</p>",
                                    "priority": {"name": "Major", "rank": 2}, "severity": {"name": "Medium", "rank": 2},
                                    "source": "Tool", "stage": "DEV", "type": "Software", "status": "Registered",
                                    "linkedIssues": seen["links"]}, ensure_ascii=False)
        if path == "/defects/serviceInfo":
            return 200, json.dumps(SERVICE)
        if method == "POST" and path == "/defects":
            seen["created"] = job["body"]
            return 200, json.dumps({"id": 555})
        if method == "POST" and path == "/defects/555/link":
            if not seen.get("link_ok"):  # отказ Hub в привязке: строка «не принят», находка свободна
                return 404, json.dumps({"errorMessage": "Not Found"})
            seen["links"] = seen["links"] + [{"id": int(i), "type": "SAST"} for i in job["body"]["issueIds"]]
            return 200, "{}"
        if path == "/defects/555":
            return 200, json.dumps({"id": 555, "appId": seen["created"]["appId"], "summary": seen["created"]["summary"], "linkedIssues": seen["links"],
                                    "description": seen["created"]["description"]}, ensure_ascii=False)
        return 404, "{}"
    return answer


def test_defect_from_sast_card(browser, hub_server):
    context, page, watch = open_page(browser, hub_server.url)
    seen: dict = {}
    try:
        pid = create_demo(page)
        set_hub(page, pid)
        run_triage(page, pid)
        open_first_sast(page, pid)
        card = page.url
        expect(page.locator("#hub-defect")).to_be_hidden()  # шаг «Перенос в Hub» – после выбора «Подтверждаю дефект»
        page.locator("label").filter(has=page.locator('input[name="decision"][value="true_positive"]')).click()
        # решение выбрано, но не сохранено: блок виден, вместо кнопки – причина (dev26)
        expect(page.locator("#hub-defect-not-ready")).to_be_visible()
        expect(page.locator("#hub-defect-button")).to_have_count(0)
        page.fill("#comment", REASON)
        page.fill("#fix", FIX)
        page.click("#save-btn")
        page.wait_for_url(re.compile(r"ok=saved"))
        expect(page.locator("#defect-panel")).to_be_visible()
        expect(page.locator("#hub-defect")).to_be_visible()
        expect(page.locator("#hub-defect-not-ready")).to_have_count(0)
        expect(page.locator("#hub-defect-button")).to_be_visible()
        expect(page.locator("#hub-defect-preview")).to_have_count(0)
        stop, jobs, thread = start_worker(hub_server, [make_hub(seen)] * 4)
        try:
            page.click("#hub-defect-button")
            # логика оператора: «Создать дефект» открывает карточку дефекта, она сама дожидается заготовки
            page.wait_for_url(re.compile(r"/defects/\d+(\?.*)?$"))
            defect_card = page.url
            expect(page.locator("#hub-defect-preview")).to_be_visible(timeout=30000)
            expect(page.locator("#hub-defect-summary")).to_contain_text("(SAST)")
            expect(page.locator("#hub-defect-body")).to_contain_text("Рекомендация:")
            expect(page.locator("#hub-defect-targets")).to_contain_text("(1)")
            # предпросмотр с «Отменить предпросмотр» виден и в карточке находки при другом выбранном решении (круг 4 Codex)
            page.goto(card)
            page.locator("label").filter(has=page.locator('input[name="decision"][value="later"]')).click()
            expect(page.locator("#hub-defect-cancel")).to_be_visible()
            page.goto(defect_card)
            page.click("#hub-defect-create")
            expect(page.locator("#hub-defect-done")).to_be_visible(timeout=30000)
            expect(page.locator("#hub-defect-done")).to_contain_text("№555")
        finally:
            stop.set()
            thread.join(timeout=30)
        assert [j["path"].split("?")[0] for j in jobs] == ["/defects/blank", "/defects/serviceInfo", "/defects",
                                                           "/defects/555"]
        created = jobs[2]["body"]
        assert created["summary"].endswith("(SAST)")  # приоритет – из заготовки Hub: поля скрыты
        assert created["description"].startswith("<p>После тщательного анализа уязвимости команда Платформа")
        assert "<br>1) " in created["description"] and "<script" not in created["description"]
        # dev30: следом за текстом – блок заготовки Hub как есть
        assert created["description"].endswith("\n<p>Информация об объекте сканирования:</p>")
        page.goto(card)  # после «Создать» оператор в карточке дефекта; отметка видна в карточке находки
        expect(page.locator("#entered-badge")).to_be_visible()
        expect(page.locator("#entered-badge")).to_contain_text("дефект создан в Hub")
        # ADR-0121: решение находки с созданным дефектом меняется только с подтверждением – отказ 409 открывает
        # флажок, после подтверждения карточка помечает, что дефект в Hub прежний
        expect(page.locator("#hub-defect-recheck")).to_have_count(0)  # «Проверить в Hub» убрана (dev33)
        watch.allowed_errors.append("status of 409")  # отказ «нужно подтверждение» – ответ 409, так и задумано
        page.fill("#comment", REASON + " Уточнено после создания дефекта.")
        page.click("#save-btn")
        expect(page.locator("#defect-bound-row")).to_be_visible()
        expect(page.locator("#defect-bound-text")).to_contain_text("№555")
        expect(page.locator("#hub-defect-decision-changed")).to_have_count(0)
        page.check("#defect-bound-confirm")
        page.click("#save-btn")
        page.wait_for_url(re.compile(r"ok=saved"))
        expect(page.locator("#defect-bound-row")).to_be_hidden()
        expect(page.locator("#hub-defect-decision-changed")).to_be_visible()
        expect(page.locator("#hub-defect-decision-changed")).to_contain_text("№555")
        # правка 3 ревью: подтверждение – к одной правке. «Ложное срабатывание» и копирование: отказ, флажок,
        # подтверждённое копирование сохраняет и снимает флажок; новая правка – следующее копирование спрашивает снова
        page.locator("label").filter(has=page.locator('input[name="decision"][value="false_positive"]')).click()
        page.fill("#comment", FALSE_REASON)
        page.click("#copy-hub")
        expect(page.locator("#defect-bound-row")).to_be_visible()
        page.check("#defect-bound-confirm")
        page.click("#copy-hub")
        expect(page.locator("#copy-status")).to_contain_text("скопирован")
        expect(page.locator("#defect-bound-row")).to_be_hidden()
        expect(page.locator("#defect-bound-confirm")).not_to_be_checked()
        page.fill("#comment", FALSE_REASON + " Уточнено.")
        page.click("#copy-hub")
        expect(page.locator("#defect-bound-row")).to_be_visible()
        expect(page.locator("#defect-bound-confirm")).not_to_be_checked()
        page.goto(f"/projects/{pid}/defects")
        expect(page.locator("#hub-defects tbody tr")).to_have_count(1)
        expect(page.locator("#hub-defects tbody tr").first).to_have_attribute("data-state", "done")
        expect(page.locator('#hub-defects a[href*="/findings/"]').first).to_be_visible()
        expect(page.locator('#hub-defects a[href*="/defects/555"]')).to_be_visible()
        expect(page.locator('nav.tabs a[aria-current="page"]')).to_contain_text("Дефекты")
        assert not watch.problems(), watch.problems()
    finally:
        context.close()


def test_form_problems_warning_appears_on_violation(browser, hub_server):
    """Панель «Дефект для Hub» (ADR-0123 п. 5): в рекомендации – требование к конвейеру («Добавить тест…»); после
    сохранения карточка показывает предупреждение «Текст не по требованиям команды» с номером требования, копирование
    не запрещено; рекомендация по требованиям – предупреждения нет."""
    context, page, watch = open_page(browser, hub_server.url)
    try:
        pid = create_demo(page)
        set_hub(page, pid)
        run_triage(page, pid)
        open_first_sast(page, pid)
        expect(page.locator("#defect-form-problems")).to_have_count(0)
        page.locator("label").filter(has=page.locator('input[name="decision"][value="true_positive"]')).click()
        page.fill("#comment", REASON)
        page.fill("#fix", FIX + "\n3) Добавить тест, подтверждающий исправление.")
        page.click("#save-btn")
        page.wait_for_url(re.compile(r"ok=saved"))
        expect(page.locator("#defect-panel")).to_be_visible()
        expect(page.locator("#defect-form-problems")).to_be_visible()
        expect(page.locator("#defect-form-problems")).to_contain_text("Текст не по требованиям команды")
        expect(page.locator("#defect-form-problems")).to_contain_text("S6")
        expect(page.locator("#copy-defect-body")).to_be_enabled()
        page.fill("#fix", FIX)
        page.click("#save-btn")
        expect(page.locator("#defect-form-problems")).to_have_count(0)  # карточка перезагрузилась после сохранения
        expect(page.locator("#defect-panel")).to_be_visible()
        assert not watch.problems(), watch.problems()
    finally:
        context.close()


def save_true_positive(page) -> None:
    """«Подтверждаю дефект» с обоснованием, рекомендацией и «Проверено» – формой открытой карточки."""
    page.locator("label").filter(has=page.locator('input[name="decision"][value="true_positive"]')).click()
    page.fill("#comment", REASON)
    page.fill("#fix", FIX)
    page.locator("#reviewed-box").check()
    page.click("#save-btn")
    page.wait_for_url(re.compile(r"ok=saved"))


def created_in_card(page, server, seen: dict) -> None:
    """«Создать дефект в Hub» → предпросмотр → «Создать»: поддельный исполнитель отвечает на заготовку, справочник,
    создание и чтение – карточка показывает «Дефект создан в Hub»."""
    stop, jobs, thread = start_worker(server, [make_hub(seen)] * 4)
    finding = page.url.split("?")[0]
    try:
        page.click("#hub-defect-button")
        page.wait_for_url(re.compile(r"/defects/\d+(\?.*)?$"))  # карточка дефекта (логика оператора)
        expect(page.locator("#hub-defect-preview")).to_be_visible(timeout=30000)
        page.click("#hub-defect-create")
        expect(page.locator("#hub-defect-done")).to_contain_text("Дефект создан в Hub", timeout=30000)
        page.goto(finding)
        expect(page.locator("#hub-defect-done")).to_contain_text("Дефект создан в Hub", timeout=30000)
    finally:
        stop.set()
        thread.join(timeout=30)
    assert [j["path"].split("?")[0] for j in jobs] == ["/defects/blank", "/defects/serviceInfo", "/defects",
                                                       "/defects/555"]


def answer_404(job: dict) -> tuple[int, str]:
    return 404, json.dumps({"errorMessage": "Not Found"})


def test_recheck_unmark_and_status_of_a_finding_with_a_defect(browser, hub_server):
    """ADR-0121 в браузере у находки с созданным дефектом: «Проверить в Hub» – опрос до итога (ответ 404 – пояснение,
    потом «проверено»); «Снять отметку» – отказ 409 открывает флажок с текстом, с ним отметка снимается; статус
    у находки в дефекте – через дефект (dev32): вместо панели отправки пояснение и ссылка на дефект."""
    context, page, watch = open_page(browser, hub_server.url)
    seen: dict = {}
    try:
        pid = create_demo(page)
        set_hub(page, pid)
        run_triage(page, pid)
        open_first_sast(page, pid)
        card = page.url.split("?")[0]
        save_true_positive(page)
        created_in_card(page, hub_server, seen)
        # «Проверить в Hub» с dev33 нет: у дефекта – «Push в Hub» и «Pull из Hub»
        expect(page.locator("#hub-defect-recheck")).to_have_count(0)
        expect(page.locator("#hub-defect-done")).to_contain_text("№555")
        # «Снять отметку «Внесено в Hub»»: отказ 409 открывает флажок с текстом отказа, с ним отметка снимается
        watch.allowed_errors.append("status of 409")  # отказ «нужно подтверждение» – ответ 409, так и задумано
        page.goto(card)
        expect(page.locator("#entered-note")).to_be_visible()
        expect(page.locator("#unenter-defect-row")).to_be_hidden()
        page.click("#unmark-entered")
        expect(page.locator("#unenter-defect-row")).to_be_visible()
        expect(page.locator("#unenter-defect-text")).to_contain_text("№555")
        expect(page.locator("#unenter-defect-text")).to_contain_text("Снять отметку «Внесено в Hub»?")
        expect(page.locator("#entered-note")).to_be_visible()
        page.check("#unenter-defect-confirm")
        page.click("#unmark-entered")
        expect(page.locator("#entered-note")).to_be_hidden()
        expect(page.locator("#unenter-defect-row")).to_be_hidden()
        expect(page.locator("#mark-entered")).to_be_visible()
        # статус находки в дефекте – через дефект (dev32): «Ложное срабатывание» сохраняется с подтверждением, а вместо
        # панели «Отправить в Hub» – пояснение и ссылка на дефект; формы отправки нет
        page.goto(card)
        page.locator("label").filter(has=page.locator('input[name="decision"][value="false_positive"]')).click()
        page.fill("#comment", FALSE_REASON)
        page.click("#save-btn")
        expect(page.locator("#defect-bound-row")).to_be_visible()
        page.check("#defect-bound-confirm")
        page.click("#save-btn")
        page.wait_for_url(re.compile(r"ok=saved"))
        expect(page.locator("#hub-send")).to_be_visible()
        expect(page.locator("#hub-send-in-defect-text")).to_contain_text("входит в дефект №555 (ID1)")
        expect(page.locator("#hub-send-in-defect-text")).to_contain_text("идут через дефект")
        expect(page.locator("#hub-send-form")).to_have_count(0)
        expect(page.locator("#hub-send-button")).to_have_count(0)
        with page.expect_navigation():
            page.click("#hub-send-in-defect-link")
        expect(page).to_have_url(re.compile(r"/defects/\d+"))
        expect(page.locator("#defect-title, h1").first).to_contain_text("ID1")
        assert not watch.problems(), watch.problems()
    finally:
        context.close()


def test_new_group_member_is_linked_with_polling(browser, tmp_path):
    """ADR-0121 п. 5 в браузере: две находки одной строки, категории и кода; дефект создан из первой – вторая с тем же
    текстом получает «Привязать к дефекту №555 (ID1)»; отказ Hub в привязке – «не принят», кнопка снова видна; вторая
    попытка – опрос до итога, «Находки привязаны к дефекту в Hub» и отметка."""
    pid, repos = seeded(tmp_path, 2)
    seen: dict = {}
    with FakeOllama(default_answer=verdict_answer(evidence_lines=[2])) as fake:
        server = start_app(tmp_path, fake.url, repos_root=repos)
        context, page, watch = open_page(browser, server.url)
        try:
            set_hub(page, pid)
            run_triage(page, pid)
            first, second = card_urls(page, pid)
            page.goto(first)
            save_true_positive(page)
            created_in_card(page, server, seen)
            anchor = seen["links"][0]["id"]
            page.goto(second)
            save_true_positive(page)
            expect(page.locator("#hub-defect-button")).to_have_count(0)
            expect(page.locator("#hub-defect-link-button")).to_contain_text("Привязать к дефекту №555 (ID1)")
            expect(page.locator("#hub-defect-link-targets")).to_contain_text("(1)")
            # отказ Hub в привязке: опрос до итога, «не принят», находка свободна – кнопка снова в карточке
            page.click("#hub-defect-link-button")
            expect(page.locator("#hub-defect-status")).to_contain_text("Привязываю находки к дефекту №555")
            stop, jobs, thread = start_worker(server, [make_hub(seen)])
            try:
                expect(page.locator("#hub-defect-status")).to_contain_text("Hub не принял", timeout=30000)
            finally:
                stop.set()
                thread.join(timeout=30)
            assert [j["path"] for j in jobs] == ["/defects/555/link"]
            page.goto(second)
            expect(page.locator("#hub-defect-status")).to_contain_text("привязка находок отклонена")
            expect(page.locator("#hub-defect-link-button")).to_be_visible()
            # вторая попытка: привязка и чтение – опрос до «Находки привязаны к дефекту в Hub»
            seen["link_ok"] = True
            page.click("#hub-defect-link-button")
            expect(page.locator("#hub-defect-status")).to_contain_text("Привязываю находки к дефекту №555")
            stop, jobs, thread = start_worker(server, [make_hub(seen)] * 2)
            try:
                expect(page.locator("#hub-defect-done")).to_contain_text("Находки привязаны к дефекту в Hub",
                                                                         timeout=30000)
            finally:
                stop.set()
                thread.join(timeout=30)
            assert [j["path"] for j in jobs] == ["/defects/555/link", "/defects/555"]
            assert jobs[0]["body"]["issueIds"] == [({993000, 993001} - {anchor}).pop()]
            expect(page.locator("#hub-defect-done")).to_contain_text("№555")
            expect(page.locator("#hub-defect-link-button")).to_have_count(0)
            expect(page.locator("#entered-badge")).to_contain_text("дефект создан в Hub")
            assert not watch.problems(), watch.problems()
        finally:
            context.close()
            stop_app(server.process)
