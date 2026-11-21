"""Подтверждение своей записи, когда Hub переписал служебный блок сильнее канонической формы (ADR-0146): например, Hub
вычищает декларацию DOCTYPE и «теги» из текста, заново экранировал
сущности, табуляцию и неразрывный пробел заменил пробелом, таблицы свернул в одну строку. Содержание блока не изменилось –
блок сверяется единицами текста; текст команды выше блока – по-прежнему строками; изменённое содержание не подтверждается."""
from app import hub_defects as hd

HEAD = ("<p>Описание<br>CVE-2099-0001 (https://nvd.example.org/CVE-2099-0001)</p>"
        "<p>Объяснение<br>CVE-2099-0001: разбор сущностей DOCTYPE без ограничений. Условия: диапазоны по GitHub Advisory: "
        "&gt;= 2.1.0, &lt; 2.8.1.</p><p>Рекомендации<br>Обновление lib до версии 2.8.1</p>")

SENT_BLOCK = """<h3>Информация об объекте сканирования:</h3>
    <table>
        <tbody>
        </tbody>
    </table>
<h3>Сводка по уязвимостям:</h3>
    <table>
        <tr>
            <th>ID</th>
            <th>Компонент</th>
            <th>Версия исправления</th>
        </tr>
        <tr>
            <td>        <a href="https://hub.example.org/issues/SCA_S/1">1</a>
</td>
            <td>pkg:npm/lib</td>
            <td>2.8.1</td>
        </tr>
    </table>
<h3>Детальная информация по уязвимостям:</h3>
<p>----------</p>
<h4>ID: <a href="https://hub.example.org/issues/SCA_S/1">1</a></h4>
<p><strong>Описание</strong></p>
<p>### Proof of Concept
const original = `
<!DOCTYPE lolz>
<!ENTITY lol "lol">
<!ENTITY lol1 "&lol;&lol;&lol;">
&lol9;
`;
If run on untrusted input, an SVG < 1 KB stalls the application.
#### >= 2.1.0, <= 3.3.2
values such as `java&#9;script:` could remain executable.</p>
"""

HUB_BLOCK = ("<h3>Информация об объекте сканирования:</h3>\n    <table><tbody></tbody></table>\n"
             "<h3>Сводка по уязвимостям:</h3>\n    <table><tbody><tr><th>ID</th><th>Компонент</th><th>Версия исправления</th></tr>"
             "<tr><td>        <a href=\"https://hub.example.org/issues/SCA_S/1\">1</a>\n</td><td>pkg:npm/lib</td><td>2.8.1</td></tr>"
             "</tbody></table>\n<h3>Детальная информация по уязвимостям:</h3>\n<p>----------</p>\n"
             "<h4>ID: <a href=\"https://hub.example.org/issues/SCA_S/1\">1</a></h4>\n<p><strong>Описание</strong></p>\n"
             "<p>### Proof of Concept\nconst original = `\n\n&amp;lol9;\n`;\n"
             "If run on untrusted input, an SVG &lt; 1&nbsp;KB stalls the application.\n"
             "#### &gt;= 2.1.0, &lt;= 3.3.2\nvalues such as `java script:` could remain executable.</p>\n")

SUMMARY = "ID1 - lib | Component version: 2.0.0 (SCA)"


def _sent(block: str = SENT_BLOCK) -> dict:
    return {"summary": SUMMARY, "description": HEAD + block}


def _hub(head: str = HEAD, block: str = HUB_BLOCK) -> dict:
    return {"summary": SUMMARY, "description": head + block}


def test_block_rewritten_by_hub_is_confirmed_by_text_units():
    block, problem = hd.hub_block(_sent()["description"])
    assert block and not problem
    assert hd.block_start(_hub()["description"], block) < 0, "каноническая форма такую переработку Hub не покрывает"
    assert hd.block_units(block) == hd.block_units(HUB_BLOCK)
    assert hd.update_content_new(_hub(), _sent()) is True


def test_changed_block_content_is_not_confirmed():
    assert hd.update_content_new(_hub(block=HUB_BLOCK.replace("<td>2.8.1</td>", "<td>2.8.2</td>")), _sent()) is False
    assert hd.update_content_new(_hub(block=HUB_BLOCK.replace("could remain executable", "remain")), _sent()) is False


def test_changed_text_above_block_is_not_confirmed():
    assert hd.update_content_new(_hub(head=HEAD.replace("до версии 2.8.1", "до версии 2.8.2")), _sent()) is False


def test_block_missing_in_hub_is_not_confirmed():
    assert hd.update_content_new({"summary": SUMMARY, "description": HEAD}, _sent()) is False
    assert hd.block_text_start(HEAD) == -1 and hd.block_text_start(HEAD + HUB_BLOCK) == len(HEAD)
