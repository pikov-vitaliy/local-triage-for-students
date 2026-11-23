"""Язык интерфейса (ADR-0158): английский по умолчанию, русский вторым; переключатель в «Настройках», каталог
переводов, подписи, формы чисел, запрос к модели, тексты дефектов, примеры, страницы стенда на английском."""
from __future__ import annotations

import html
import json
import re
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import defect, defect_check, i18n, prompts
from app.config import DEFAULT_STATUS_MAP, Settings
from app.main import create_app
from app.models import Finding
from app.view import SEVERITY_LABELS, VERDICT_LABELS
from fake_ollama import FakeOllama
from test_web import BASE, ORIGIN, web, write_repos  # noqa: F401

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import i18n_check  # noqa: E402

CYR = re.compile(r"[А-Яа-яЁё]")
HUB_STATUSES = (*DEFAULT_STATUS_MAP.values(), "Не подтверждено", "Открыто", "Исправлено")
AS_HTML = {**ORIGIN, "Accept": "text/html"}


# ============================================================================ каталог и механизм

def test_catalog_is_complete_without_conflicts():
    """Каждая строка из _(), N_(), plural(), Labels(), register_messages, ltT(), ltPlural() переведена, без кириллицы,
    с теми же подстановками; ни один ключ не переведён в разных частях каталога по-разному."""
    assert i18n_check.problems() == []


def test_translate_follows_current_language():
    with i18n.use("ru"):
        assert i18n._("Настройки сохранены.") == "Настройки сохранены."
    with i18n.use("en"):
        assert i18n._("Настройки сохранены.") == "Settings saved."
        assert i18n._("неизвестная строка без перевода") == "неизвестная строка без перевода"


def test_default_language_is_english_without_setting(monkeypatch):
    monkeypatch.delenv("TRIAGE_LANG", raising=False)
    i18n.set_saved(None)
    assert i18n.current() == "en"
    monkeypatch.setenv("TRIAGE_LANG", "ru")
    assert i18n.current() == "ru"
    i18n.set_saved("en")
    assert i18n.current() == "en"  # сохранённая настройка – выше окружения


def test_labels_translate_on_read_and_keep_keys():
    with i18n.use("en"):
        assert VERDICT_LABELS["false_positive"] == "false positive"
        assert dict(VERDICT_LABELS.items())["true_positive"] == "true positive"
        assert SEVERITY_LABELS.get("unknown-key", "нет") == "no"
    with i18n.use("ru"):
        assert VERDICT_LABELS["false_positive"] == "ложная"
    assert {**VERDICT_LABELS}["false_positive"] == "ложная"  # распаковка копирует msgid, а не перевод


@pytest.mark.parametrize("n, ru, en", [(1, "находка", "finding"), (2, "находки", "findings"), (5, "находок", "findings"),
                                       (11, "находок", "findings"), (21, "находка", "findings")])
def test_plural_forms_in_both_languages(n, ru, en):
    with i18n.use("ru"):
        assert i18n.plural(n, "находка", "находки", "находок") == ru
    with i18n.use("en"):
        assert i18n.plural(n, "находка", "находки", "находок") == en


def test_js_catalog_only_in_english():
    with i18n.use("ru"):
        assert i18n.js_catalog() == {}
    with i18n.use("en"):
        part = i18n.js_catalog()
        assert part and not any(CYR.search(v) for v in part.values())


# ============================================================================ модель: строка языка ответа

def _finding() -> Finding:
    return Finding(hub_id="101", kind="SAST", rule="python.sqli", file="app/db.py", line=3, cwe="CWE-89",
                   severity="high")


def _context():
    from app.models import CodeContext
    return CodeContext(status="ok", file="app/db.py", language="python", start_line=1, end_line=3, target_line=3,
                       lines=["import db", "q = 'x'", "db.run(q)"])


def test_model_request_russian_unchanged_english_adds_one_line():
    f, ctx = _finding(), _context()
    with i18n.use("ru"):
        ru = prompts.build_sast_messages(f, ctx)
    with i18n.use("en"):
        en = prompts.build_sast_messages(f, ctx)
    assert ru[0] == en[0]  # системное сообщение (промпт) – одно и то же
    assert prompts.ANSWER_LANGUAGE_EN not in ru[1]["content"]
    assert en[1]["content"] == ru[1]["content"] + "\n" + prompts.ANSWER_LANGUAGE_EN
    assert prompts.request_key("m", ru) != prompts.request_key("m", en)  # кэш вердиктов различает языки


# ============================================================================ тексты дефектов

def _body(lang: str) -> str:
    with i18n.use(lang):
        return defect.sast_body(_finding(), "true_positive", "Строка 3 склеивает SQL из данных запроса.",
                                "Передавайте значения параметрами запроса.", "Альфа")


def test_defect_text_in_english_and_same_key_in_both_languages():
    ru, en = _body("ru"), _body("en")
    assert ru.startswith("После тщательного анализа уязвимости команда Альфа")
    assert en.startswith("After a thorough analysis of the vulnerability, team Альфа")
    assert "Rationale:" in en and "Recommendation:" in en
    assert defect.body_key(ru) == defect.body_key(en)
    other = defect.sast_body(_finding(), "true_positive", "Другое обоснование.", "Другая рекомендация.", "Альфа")
    assert defect.body_key(other) != defect.body_key(ru)


@pytest.mark.parametrize("ui", ["ru", "en"])
@pytest.mark.parametrize("text_lang", ["ru", "en"])
def test_defect_check_accepts_both_languages(ui, text_lang):
    body = _body(text_lang)
    with i18n.use(ui):
        problems = defect_check.sast_problems(body, team_phrase=defect.sast_phrases("Альфа"))
    assert not [p for p in problems if p.split(":", 1)[0] in ("S1", "S2")], problems


def test_false_positive_prefix_in_both_languages():
    assert defect.reason_text("Ложное срабатывание:") == ""
    assert defect.reason_text("False positive:") == ""


def test_own_where_section_kept_with_field_named_like_a_heading():
    """Ручной раздел «Где исправлять» с полем «Description: …» сохраняется при пересборке (ревью dev38, круг 2)."""
    from app import defect_where
    for head, repo in (("Где исправлять:", "Репозиторий: demo"), ("Where to fix:", "Repository: example")):
        text = f"Тело решения.\n\n{head}\n{repo}\nDescription: change the parser"
        assert defect_where.own_tail(text) == f"{head}\n{repo}\nDescription: change the parser"


def test_own_where_section_kept_with_free_text_after_field():
    from app import defect_where
    text = "Тело.\n\nГде исправлять:\nDescription: обрабатывать до проверки\nТолько для ветки release."
    assert defect_where.own_tail(text) == "Где исправлять:\nDescription: обрабатывать до проверки\nТолько для ветки release."
    sub = "Обоснование.\n\nГде исправлять:\nОписание\nтекст"  # подзаголовок шаблона ниже – как до dev38
    assert defect_where.own_tail(sub) == ""


def test_body_key_keeps_operator_text_literal():
    one = "X\n\nRationale:\nDescription is parsed as JSON."
    two = "X\n\nRationale:\nОписание is parsed as JSON."
    assert defect.body_key(one) != defect.body_key(two)
    assert defect.body_key("X\n\nRationale:\nA.") == defect.body_key("X\n\nОбоснование:\nA.")
    assert defect.body_key("X\n\nRationale:\nBranch: release") != defect.body_key("X\n\nRationale:\nВетка: release")


def test_run_language_is_kept_and_db_errors_are_not_swallowed():
    from app.triage import TriageRunner

    class Db:
        def __init__(self, fail=False):
            self.data, self.fail = {}, fail

        def get_settings(self):
            if self.fail:
                raise RuntimeError("база недоступна")
            return dict(self.data)

        def set_settings(self, values):
            self.data.update(values)

    runner = TriageRunner.__new__(TriageRunner)
    runner._run_lang, runner.db = {}, Db()
    runner.db.data["run_lang:7"] = "ru"
    with i18n.use("en"):
        assert runner._lang_of(7) == "ru"  # сохранённый язык прогона, а не текущий
        assert runner._lang_of(8) == "en" and runner.db.data["run_lang:8"] == "en"
    runner._run_lang, runner.db = {}, Db()
    runner.db.get_run = lambda run_id: {"done": 3}  # прогон начат до dev38: ключа нет, находки уже разбирались
    with i18n.use("en"):
        assert runner._lang_of(10) == "ru"
    runner._run_lang, runner.db = {}, Db(fail=True)
    with pytest.raises(RuntimeError):
        runner._lang_of(9)  # сбой базы – не подмена языка, а ошибка (прогон встанет на паузу)


# ============================================================================ учебные примеры

def test_examples_catalog_and_rule_texts_are_translated():
    import openpyxl

    table = i18n.catalog_part("examples_data")
    catalog = json.loads((ROOT / "examples/catalog/catalog.json").read_text(encoding="utf-8"))
    for e in catalog["examples"]:
        assert e["description"] in table, e["id"]
        assert e["level"] in table, e["id"]
    files = sorted((ROOT / "examples/catalog").glob("*/export.xlsx")) + sorted((ROOT / "examples/demo").glob("*.xlsx"))
    missing = set()
    for path in files:
        wb = openpyxl.load_workbook(path, read_only=True)
        for ws in wb.worksheets:
            rows = list(ws.iter_rows(values_only=True))
            if not rows or "Category" not in rows[0]:
                continue
            col = list(rows[0]).index("Category")
            for row in rows[1:]:
                value = row[col] if col < len(row) else None
                if isinstance(value, str) and CYR.search(value) and value not in table:
                    missing.add(value)
    assert not missing, sorted(missing)[:5]


def test_example_rule_texts_translated_on_display_only():
    """Категория хранится как в выгрузке (входит в отпечаток случая): перевод – только при показе."""
    from app.examples import rule_text

    with i18n.use("ru"):
        assert rule_text("Межсайтовый скриптинг") == "Межсайтовый скриптинг"
    with i18n.use("en"):
        assert rule_text("Межсайтовый скриптинг") == "Cross-site scripting"
        assert rule_text("чужое правило") == "чужое правило"


# ============================================================================ переключатель и страницы

def _visible(page: str) -> str:
    """Видимый текст страницы: текст узлов и подсказки (title, aria-label, placeholder), без скриптов и стилей."""
    page = re.sub(r"<(script|style)\b.*?</\1>", " ", page, flags=re.S | re.I)
    attrs = " ".join(m.group(2) for m in re.finditer(r'\b(title|aria-label|placeholder|data-section|data-confirm)="([^"]*)"',
                                                     page))
    text = re.sub(r"<[^>]+>", " ", page)
    return html.unescape(text + " " + attrs)


def _cyrillic_runs(text: str, allowed=()) -> list[str]:
    """Отрезки текста с кириллицей (с соседними словами – чтобы было видно, откуда строка)."""
    runs = re.findall(r"(?:\S+\s+){0,4}\S*[А-Яа-яЁё]+\S*(?:\s+\S+){0,4}", text)
    return [" ".join(r.split()) for r in runs if not any(a in r for a in allowed)]


@pytest.fixture
def web_en(tmp_path: Path, monkeypatch):
    """Приложение без TRIAGE_LANG и без сохранённого языка – английский по умолчанию."""
    from app import metrics
    from test_web import GPU

    monkeypatch.setattr(metrics, "gpu_stats", lambda: dict(GPU))
    monkeypatch.delenv("TRIAGE_LANG", raising=False)
    fake = FakeOllama(loaded=["qwen2.5-coder:14b"])
    write_repos(tmp_path / "repos")
    settings = Settings(data_dir=tmp_path / "data", repos_root=tmp_path / "repos", ollama_url=fake.url,
                        max_upload_mb=5, team_name="Team", osv_url="")
    app = create_app(settings)
    with TestClient(app, base_url=BASE) as client:
        yield type("W", (), {"client": client, "settings": settings, "tmp": tmp_path})
    fake.close()


def test_switch_language_and_keep_it_after_restart(tmp_path):
    fake = FakeOllama(loaded=["qwen2.5-coder:14b"])
    write_repos(tmp_path / "repos")
    settings = Settings(data_dir=tmp_path / "data", repos_root=tmp_path / "repos", ollama_url=fake.url, osv_url="")
    try:
        with TestClient(create_app(settings), base_url=BASE) as client:
            page = client.get("/settings")
            assert '<html lang="ru"' in page.text and 'id="language-form"' in page.text  # TRIAGE_LANG=ru набора
            r = client.post("/settings/language", data={"lang": "en"}, headers=AS_HTML, follow_redirects=False)
            assert r.status_code == 303 and r.headers["location"].startswith("/settings?ok=language_saved")
            page = client.get(r.headers["location"])
            assert '<html lang="en"' in page.text and "Interface language saved." in page.text
            assert "data-i18n=" in page.text  # строки сценариев – атрибутом, без встроенного скрипта (CSP)
            r = client.post("/settings/language", data={"lang": "xx"}, headers=AS_HTML, follow_redirects=False)
            assert r.status_code == 400
        i18n.set_saved(None)
        # та же папка данных после перезапуска – язык из базы, а не из TRIAGE_LANG=ru
        with TestClient(create_app(settings), base_url=BASE) as client:
            assert '<html lang="en"' in client.get("/settings").text
            client.post("/settings/language", data={"lang": "ru"}, headers=AS_HTML, follow_redirects=False)
            assert '<html lang="ru"' in client.get("/settings").text
    finally:
        fake.close()


def test_stand_pages_in_english_have_no_russian_text(web_en):
    client = web_en.client
    r = client.post("/projects/demo", headers=ORIGIN, follow_redirects=False)
    assert r.status_code == 303, r.text
    pid = int(r.headers["location"].split("/")[2].split("?")[0])
    findings = client.get(f"/projects/{pid}/findings").text
    first = re.search(rf'href="/projects/{pid}/findings/(\d+)', findings)
    pages = ["/", "/examples", "/settings", "/settings/providers", "/journal", "/feeds", "/cwe", "/capec", "/help",
             f"/projects/{pid}", f"/projects/{pid}/findings", f"/projects/{pid}/sca", f"/projects/{pid}/components"]
    if first:
        pages.append(f"/projects/{pid}/findings/{first.group(1)}")
    problems = {}
    for url in pages:
        page = client.get(url)
        assert page.status_code == 200, url
        assert '<html lang="en"' in page.text, url
        # данные: код демо-примера, имена кодовых баз и выдуманной библиотеки, название языка «Русский»
        # статусы AppSec.Hub – значения самого Hub (DEFAULT_STATUS_MAP), «орг» – значение маски принадлежности
        runs = _cyrillic_runs(_visible(page.text), allowed=("Русский", "Язык", "орг", *HUB_STATUSES))
        if runs:
            problems[url] = runs[:8]
    if problems and __import__("os").environ.get("I18N_DUMP"):  # полный список – в файл (разбор при доработке)
        Path(__import__("os").environ["I18N_DUMP"]).write_text(json.dumps(problems, ensure_ascii=False, indent=1),
                                                               encoding="utf-8")
    assert not problems, problems
