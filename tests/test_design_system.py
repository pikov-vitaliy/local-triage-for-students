"""Оформление: токены обеих тем и их контраст, макросы, base.html и правила для статических файлов."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from app.view import TEMPLATES_DIR, make_templates

ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "app" / "static"
CSS = (STATIC / "app.css").read_text(encoding="utf-8")
JS = (STATIC / "app.js").read_text(encoding="utf-8")
THEME_JS = (STATIC / "theme.js").read_text(encoding="utf-8")
DESIGN = (ROOT / "docs" / "DESIGN.md").read_text(encoding="utf-8")
BASE = (TEMPLATES_DIR / "base.html").read_text(encoding="utf-8")
MACROS = (TEMPLATES_DIR / "macros.html").read_text(encoding="utf-8")

ENV = make_templates().env

def test_documented_size_tokens_match_css():
    for name in ('r-sm','r','r-lg','control-h','control-h-sm','fs-xs','fs-sm','fs-base','fs-md','fs-lg','fs-xl','fs-2xl'):
        value=re.search(r'--'+name+r':\s*(\d+)px;',CSS).group(1)
        assert re.search(r'`--'+name+r'`\s+'+value+r'\b',DESIGN),name

def test_size_tokens_are_used_without_changing_values():
    for n in range(1,9):assert f'var(--s-{n})' in CSS
    assert not re.search(r'border-radius:\s*\d+px',CSS)


def render(source: str, **context) -> str:
    return ENV.from_string(source).render(**context)


# ============================================================================ токены

def _block(pattern: str) -> dict[str, str]:
    m = re.search(pattern, CSS, re.S | re.M)
    assert m, pattern
    return dict(re.findall(r"(--[a-z0-9-]+):\s*([^;]+);", m.group(1)))


LIGHT = _block(r"^:root \{(.*?)\n\}")
DARK_MEDIA = _block(r':root:not\(\[data-theme="light"\]\) \{(.*?)\n  \}')
DARK = _block(r':root\[data-theme="dark"\] \{(.*?)\n\}')


def _is_color(value: str) -> bool:
    return value.startswith("#") or "rgb" in value


def test_dark_blocks_are_identical_and_cover_every_color_token():
    assert DARK_MEDIA == DARK  # тёмная тема по системе и по кнопке – одна и та же палитра
    colors = {name for name, value in LIGHT.items() if _is_color(value)}
    assert colors == set(DARK), sorted(colors ^ set(DARK))
    assert all(_is_color(value) for value in DARK.values())


def _luminance(color: str) -> float:
    h = color.strip().lstrip("#")
    assert len(h) == 6, color
    channels = []
    for i in (0, 2, 4):
        c = int(h[i:i + 2], 16) / 255
        channels.append(c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4)
    r, g, b = channels
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast(a: str, b: str) -> float:
    la, lb = _luminance(a), _luminance(b)
    return (max(la, lb) + 0.05) / (min(la, lb) + 0.05)


# Текст на фоне – от 4,5:1 (WCAG AA)
TEXT_PAIRS = [
    ("text", "bg"), ("text", "surface"), ("text", "surface-2"), ("text", "surface-3"),
    ("text-2", "bg"), ("text-2", "surface"), ("text-2", "surface-2"),
    ("muted", "bg"), ("muted", "surface"), ("muted", "surface-2"),
    ("accent", "bg"), ("accent", "surface"), ("accent-ink", "accent"), ("accent-ink", "accent-hover"),
    ("accent-soft-ink", "accent-soft"),
    ("ok-ink", "ok-bg"), ("warn-ink", "warn-bg"), ("err-ink", "err-bg"), ("info-ink", "info-bg"),
    ("ok-ink", "surface"), ("warn-ink", "surface"), ("err-ink", "surface"),
    ("muted-ink", "muted-bg"), ("muted-ink", "surface-3"),
    ("tp-ink", "tp-bg"), ("fp-ink", "fp-bg"), ("unc-ink", "unc-bg"), ("none-ink", "none-bg"),
    ("urgent-ink", "urgent-bg"), ("sev-crit-ink", "sev-crit-bg"),
    ("sev-high", "surface"), ("sev-medium", "surface"), ("sev-low", "surface"),
    ("code-ink", "code-bg"), ("code-ink", "hl-target"), ("code-ink", "hl-evidence"), ("code-ink", "hl-steer"),
    ("code-ink", "hl-flash"), ("code-ln", "code-gutter"), ("code-ln", "code-bg"),
    ("toast-ink", "toast-bg"),
    # карточка SAST, маршрут 1–7 (0.9.7): номер шага, пройденный шаг, подписи сверки, группа, шаг 4
    ("surface", "text"), ("ok-ink", "bg"), ("muted", "warn-bg"), ("muted", "info-bg"),
    ("warn-ink", "info-bg"), ("accent", "surface-2"),
]
# Границы полей, фокус, заливки полос, значки – от 3:1
UI_PAIRS = [
    ("control-border", "surface"), ("control-border", "bg"), ("focus", "surface"), ("focus", "bg"),
    ("accent", "surface-3"), ("ok-solid", "surface-3"), ("hl-target-bar", "hl-target"),
    ("hl-evidence-bar", "hl-evidence"), ("hl-steer-bar", "hl-steer"),
    ("toast-ok", "toast-bg"), ("toast-warn", "toast-bg"), ("toast-err", "toast-bg"), ("toast-info", "toast-bg"),
    ("toast-muted", "toast-bg"),
    # карточка SAST (0.9.7): рамка выбранного варианта решения и фокус на его заливке
    ("accent", "accent-soft"), ("focus", "accent-soft"),
]


@pytest.mark.parametrize("theme", ["light", "dark"])
def test_token_pairs_have_enough_contrast(theme):
    palette = LIGHT if theme == "light" else DARK
    weak = [(ink, bg, round(contrast(palette[f"--{ink}"], palette[f"--{bg}"]), 2))
            for pairs, minimum in ((TEXT_PAIRS, 4.5), (UI_PAIRS, 3.0)) for ink, bg in pairs
            if contrast(palette[f"--{ink}"], palette[f"--{bg}"]) < minimum]
    assert weak == []


def test_text_on_colored_chips_uses_paired_tokens():
    # литеральный белый или чёрный текст поверх цвета из токена в тёмной теме пропадает
    rules = re.findall(r"([^{}]+)\{([^{}]*)\}", CSS)
    offenders = [sel.strip() for sel, body in rules
                 if re.search(r"(?<!-)color:\s*#(?:fff|ffffff|000|000000)\b", body, re.I)]
    assert offenders == []


def test_width_classes_cover_every_percent():
    for n in range(101):
        assert f".p-{n} {{ width: {n}%; }}" in CSS or (n == 0 and ".p-0 { width: 0; }" in CSS), n


# ============================================================================ статические файлы

@pytest.mark.parametrize("name", ["app.css", "app.js", "theme.js", "favicon.svg"])
def test_static_files_make_no_external_requests(name):
    text = (STATIC / name).read_text(encoding="utf-8")
    assert not re.search(r"https?://(?!www\.w3\.org/2000/svg)", text)
    assert "@import" not in text and "url(http" not in text


def test_texts_use_short_dash():
    for path in (STATIC / "app.css", STATIC / "app.js", STATIC / "theme.js", TEMPLATES_DIR / "base.html",
                 TEMPLATES_DIR / "macros.html", ROOT / "docs" / "DESIGN.md", Path(__file__)):
        assert chr(0x2014) not in path.read_text(encoding="utf-8"), path.name


def test_script_writes_page_data_as_text_only():
    # данные находок и ответы модели – только через textContent и createElement
    for forbidden in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"):
        assert forbidden not in JS, forbidden
    assert "textContent" in JS


def test_csp_friendly_templates():
    for text in (BASE, MACROS):
        assert "style=" not in text
        assert "<style" not in text
        assert re.findall(r"<script(?![^>]*\bsrc=)", text) == []  # только внешние скрипты приложения


def test_theme_script_marks_js_and_keeps_choice_in_storage():
    assert 'root.classList.add("js")' in THEME_JS
    assert "localStorage" in THEME_JS and "try {" in THEME_JS


# ============================================================================ base.html

def test_base_renders_with_error_page_context():
    page = ENV.get_template("error.html").render(status=404, message="Нет такой страницы.", settings=None,
                                                 ok_message="", error="")
    assert page.startswith("<!doctype html>")
    for marker in ('id="theme-toggle"', 'id="keys-dialog"', 'id="toasts"', 'id="sr-status"', 'id="sr-alert"',
                   'id="hotkeys-enabled"', 'href="/settings"', 'class="skip-link"', 'data-page="error"'):
        assert marker in page, marker
    assert 'aria-current="page"' not in page.split("<main", 1)[0]  # «Настройки» подсвечены только на своей странице
    assert 'id="keys-toggle"' not in page  # переключатель карточки этапа 1 – свой, без повтора id
    assert 'src="http' not in page and 'href="http' not in page


def test_settings_link_is_current_on_settings_page():
    page = render('{% extends "base.html" %}{% block page %}settings{% endblock %}', settings=None,
                  ok_message="", error="")
    head = page.split("<main", 1)[0]
    assert re.search(r'href="/settings" aria-current="page"', head)


def test_flash_messages_keep_their_classes():
    page = render('{% extends "base.html" %}', ok_message="Готово.", error="Не вышло.", settings=None)
    assert '<p class="flash flash-ok" role="status">Готово.</p>' in page
    assert '<p class="flash flash-err" role="alert">Не вышло.</p>' in page


# ============================================================================ макросы

def macro(call: str, **context) -> str:
    names = re.findall(r"\b([a-z_]+)\(", call)
    return render('{% from "macros.html" import ' + ", ".join(sorted(set(names))) + " %}" + call, **context)


def test_stage1_macros_keep_their_markup():
    assert macro('{{ verdict_badge("true_positive", 90) }}') == \
        '<span class="badge verdict verdict-true_positive">истинная · 90%</span>'
    assert macro("{{ verdict_badge(None) }}") == '<span class="badge verdict verdict-none">нет</span>'
    assert macro('{{ severity("critical") }}') == '<span class="sev-badge">критическая</span>'
    assert macro('{{ severity("high") }}') == '<span class="sev sev-high">высокая</span>'
    assert macro('{{ run_state("done") }}') == '<span class="state state-done">завершён</span>'


def test_code_view_rows_match_the_card_markup():
    rows = [{"n": 3, "text": "", "target": False, "evidence": False, "steering": False},
            {"n": 4, "text": "run(<x>)", "target": True, "evidence": False, "steering": False},
            {"n": 5, "text": "# ignore", "target": False, "evidence": True, "steering": True},
            {"n": None, "text": "…", "target": False, "evidence": False, "steering": False}]
    html = macro("{{ code_view(rows) }}", rows=rows)
    assert '<div class="code code-wrap" id="code" tabindex="0" role="region" aria-label="Код вокруг находки">' in html
    assert '<tr id="L3"><td class="ln">3</td><td class="src"></td></tr>' in html
    assert ('<tr id="L4" class="is-target"><td class="ln"><span class="mark" aria-hidden="true">▶</span>4</td>'
            '<td class="src">run(&lt;x&gt;)</td></tr>') in html
    assert '<tr id="L5" class="is-evidence is-steering"><td class="ln"><span class="mark mark-steer"' in html
    assert '<tr><td class="ln"></td><td class="src">…</td></tr>' in html


def test_icon_is_hidden_unless_labelled_and_unknown_names_render_nothing():
    plain = macro('{{ icon("check") }}')
    assert plain.startswith('<svg class="icon icon-check"') and 'aria-hidden="true"' in plain
    labelled = macro('{{ icon("x", label="Закрыть") }}')
    assert 'role="img" aria-label="Закрыть"' in labelled and "aria-hidden" not in labelled
    assert macro('{{ icon("nope") }}') == ""
    for name in re.findall(r'^  "([a-z-]+)": ', MACROS, re.M):
        assert f"`{name}`" in DESIGN, name  # каждый значок описан


def test_progress_is_a_class_width_never_a_style():
    html = macro("{{ progress(7, 15, 3) }}")
    assert "pbar-done p-46" in html and "pbar-entered p-20" in html and "style" not in html
    assert "Проверено <strong>7</strong> из 15" in html and "Внесено в Hub <strong>3</strong>" in html
    assert 'class="pbar" aria-hidden="true"' in html
    tiny = macro("{{ progress(1, 300, caption=False) }}")
    assert "p-1" in tiny and 'role="img" aria-label="Проверено 1 из 300"' in tiny
    assert "p-0" in macro("{{ progress(0, 0) }}")
    assert "p-100" in macro("{{ progress(20, 15) }}")


@pytest.mark.parametrize("value, words, width", [(95, "высокая, 95%", "p-95"), (80, "высокая, 80%", "p-80"),
                                                  (55, "средняя, 55%", "p-55"), (10, "низкая, 10%", "p-10"),
                                                  ("120", "высокая, 100%", "p-100")])
def test_confidence_in_words_and_percent(value, words, width):
    html = macro("{{ confidence(v) }}", v=value)
    assert f"уверенность {words}" in html and width in html


def test_confidence_without_value_renders_nothing():
    assert macro("{{ confidence(None) }}") == ""


@pytest.mark.parametrize("score, level", [(9.8, "critical"), (9, "critical"), ("7,5", "high"), (4, "medium"),
                                          (0.1, "low"), (0, "none")])
def test_cvss_scale(score, level):
    assert f'class="cvss cvss-{level}"' in macro("{{ cvss(s) }}", s=score)


def test_marks_sca_conclusion_and_badges():
    assert macro("{{ marks() }}") == ""
    html = macro('{{ marks(True, True, "2026-10-15T10:00:00+00:00", "2026-10-15T11:00:00+00:00", True) }}')
    assert "проверено</span>" in html and "в Hub</span>" in html and "нет в выгрузке" in html
    assert 'title="Проверено 2026-10-15 10:00 UTC"' in html
    assert macro('{{ sca_conclusion("update") }}') == '<span class="badge conclusion conclusion-update">обновить</span>'
    assert "нет ответа" in macro('{{ sca_conclusion("") }}')
    assert macro('{{ kind_badge("SCA-license") }}') == '<span class="badge badge-kind">SCA, лицензии</span>'


def test_navigation_macros():
    tabs = macro('{{ tabs([("a", "Обзор", "/p/1"), ("b", "Находки", "/p/1/f", 21)], "b") }}')
    assert '<a class="tab" href="/p/1">Обзор</a>' in tabs
    assert '<a class="tab" href="/p/1/f" aria-current="page">Находки <span class="tab-count">21</span></a>' in tabs
    chip = macro('{{ chip("/x?a=1&b=2", "Срочные", True, 4) }}')
    assert chip == ('<a class="chip is-active" href="/x?a=1&amp;b=2" aria-current="true">Срочные '
                    '<span class="chip-count">4</span></a>')


def test_empty_state_with_and_without_actions():
    simple = macro('{{ empty_state("Пусто", "Загрузите выгрузку.", "/p/1", "К проекту") }}')
    assert '<a class="btn btn-primary" href="/p/1">К проекту</a>' in simple and "Загрузите выгрузку." in simple
    bare = macro('{{ empty_state("Только заголовок") }}')
    assert "empty-actions" not in bare and "empty-text" not in bare
    custom = render('{% from "macros.html" import empty_state %}'
                    '{% call empty_state("Пусто") %}<a class="btn" href="/z">Своё</a>{% endcall %}')
    assert '<div class="empty-actions"><a class="btn" href="/z">Своё</a></div>' in custom


def test_copy_button_escapes_text():
    html = macro('{{ copy_button("ID", text=t, done="Скопирован") }}', t='1"<x>')
    assert 'data-copy-text="1&#34;&lt;x&gt;"' in html and 'data-copy-done="Скопирован"' in html
    assert 'data-copy-target="sca-task"' in macro('{{ copy_button(target="sca-task") }}')


def test_every_macro_is_documented_and_styled():
    for name in re.findall(r"\{% macro ([a-z_]+)\(", MACROS):
        assert f"`{name}(" in DESIGN, name
    samples = (macro("{{ progress(3, 9, 1) }}") + macro("{{ confidence(70) }}") + macro("{{ cvss(9.9) }}")
               + macro("{{ marks(True, True, missing=True) }}") + macro('{{ sca_conclusion("unclear") }}')
               + macro('{{ stat(1, "Проверено", "ok", "из 2") }}') + macro('{{ chip("/", "Все", True, 1) }}')
               + macro('{{ tabs([("a", "A", "/", 1)], "a") }}') + macro('{{ empty_state("x", "y", "/", "z") }}')
               + macro("{{ code_legend(True) }}") + macro('{{ kind_badge("SAST") }}'))
    classes = {c for attr in re.findall(r'class="([^"]+)"', samples) for c in attr.split()}
    # icon-<имя> – метка значка для поиска в разметке, оформлять её не нужно
    missing = sorted(c for c in classes
                     if not c.startswith("icon-") and not re.search(r"\." + re.escape(c) + r"\b", CSS))
    assert missing == []
