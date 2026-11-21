"""Сравнение полей дефекта читается оператором (описание не идёт JSON-строкой с кодами символов)."""

from app.view import make_templates


def render(changes):
    return make_templates().env.get_template("projects/defect_fields_diff.html").render(changes=changes)


def test_description_is_shown_as_text_lines_and_other_values_without_escaped_cyrillic():
    html = render([
        {"path": "/description", "before_present": True, "after_present": True,
         "before": "<p>Прежний текст</p><p>строка 12</p>", "after": "<p>Новый текст<br>вторая строка</p>"},
        {"path": "/priority", "before_present": True, "after_present": True,
         "before": {"name": "Высокий"}, "after": {"name": "Средний"}},
        {"path": "/stage", "before_present": False, "after_present": True, "after": "Разработка"},
    ])
    assert "\\u04" not in html and "\\u003c" not in html
    assert "<th scope=\"row\">Описание</th>" in html
    assert "Прежний текст\n\nстрока 12" in html and "Новый текст\nвторая строка" in html
    readable = [part.split("</div>", 1)[0] for part in html.split('<div class="defect-text defect-hub-text">')[1:]]
    assert readable and all("&lt;p&gt;" not in part for part in readable), "в строках описания тегов нет"
    assert "<summary>Точный HTML</summary>" in html and "&lt;p&gt;Прежний текст&lt;/p&gt;" in html
    assert "Высокий" in html and "Средний" in html
    assert "свойство отсутствует" in html and "Разработка" in html


def test_whitespace_only_description_change_is_flagged_and_exact_html_kept():
    """Ревью 30.10: строки описания схлопывают пробелы – отличие только в них не должно пропасть из виду."""
    before, after = '<pre>strcmp(s, "a  b")</pre>', '<pre>strcmp(s, "a b")</pre>'
    html = render([{"path": "/description", "before_present": True, "after_present": True,
                    "before": before, "after": after}])
    assert "defect-raw-only" in html and "Видимый текст совпадает" in html
    assert "strcmp(s, &#34;a  b&#34;)" in html and "strcmp(s, &#34;a b&#34;)" in html
    assert html.count("<summary>Точный HTML</summary>") == 2
    same = render([{"path": "/description", "before_present": True, "after_present": True,
                    "before": "<p>Было</p>", "after": "<p>Стало</p>"}])
    assert "defect-raw-only" not in same


def test_changed_lines_of_description_are_listed_under_the_columns():
    """Колонки – окна с прокруткой, правка в конце длинного текста без прокрутки не видна."""
    before = "<p>Обоснование</p><p>строка 1</p><p>Версия: 1.0</p>"
    after = "<p>Обоснование</p><p>строка 1</p><p>Версия: 1.1</p><p>Где исправлять:</p><p>Ветка: &lt;main&gt;</p>"
    html = render([{"path": "/description", "before_present": True, "after_present": True, "before": before, "after": after},
                   {"path": "/summary", "before_present": True, "after_present": True, "before": "A", "after": "B"}])
    assert html.count('<th scope="row">Изменённые строки</th>') == 1, "только у описания"
    changed = html.split('<pre class="hub-text fields-diff-changed">', 1)[1].split("</pre>", 1)[0]
    assert changed.split("\n") == ["− Версия: 1.0", "+ Версия: 1.1", "+ Где исправлять:", "+ Ветка: &lt;main&gt;"]
    same = render([{"path": "/description", "before_present": True, "after_present": True,
                    "before": "<p>a  b</p>", "after": "<p>a b</p>"}])
    assert "Изменённые строки" not in same, "видимый текст тот же – строк нет, остаётся пометка о разметке"
    absent = render([{"path": "/description", "before_present": False, "after_present": True, "after": "<p>Текст</p>"}])
    assert "Изменённые строки" not in absent


def test_changed_lines_have_a_limit_and_compare_whole_lines():
    """Ревью dev8: страница строится при каждом открытии, посимвольного разбора нет, объём ограничен."""
    from app import view
    big = "".join(f"<p>строка {i}</p>" for i in range(view.TEXT_CHANGES_MAX_LINES))
    assert view.text_changes(big, big + "<p>ещё</p>") == [view.TEXT_CHANGES_TOO_LONG]
    assert view.text_changes(None, "<p>a</p>") == []
    assert view.text_changes("<p>версия 1</p><p>б</p>", "<p>версия 2</p><p>б</p>") == ["− версия 1", "+ версия 2"]
    many_old = "".join(f"<p>компонент {i} версия 1</p>" for i in range(400))
    many_new = many_old.replace("версия 1", "версия 2")
    assert len(view.text_changes(many_old, many_new)) == 800


def test_markup_in_values_stays_escaped():
    html = render([{"path": "/summary", "before_present": True, "after_present": True,
                    "before": "<script>x</script>", "after": {"a": "<b>"}}])
    assert "<script>x</script>" not in html and "&lt;script&gt;" in html
    assert "<b>" not in html


def test_json_text_keeps_cyrillic_and_markup_readable_and_escaped():
    env = make_templates().env
    html = env.from_string('<pre>{{ v | json_text }}</pre>').render(v={"appName": "Демо", "description": "<p>Текст</p>"})
    assert '"appName": "Демо"' in html and "\\u04" not in html
    assert "&lt;p&gt;Текст&lt;/p&gt;" in html and "<p>Текст" not in html
