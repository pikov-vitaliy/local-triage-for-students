"""«Целевая версия … затронута» – предупреждение, а не запрет (ADR-0145: оператор выбрал своё решение – значит,
по нему можно создать дефект): текст набора утверждается с версией оператора, предупреждение
идёт отдельным списком `cautions` – на карточке и в JSON-ответе сохранения текста – и переживает другие блокирующие проблемы."""
from test_sca_applicability import AS_JSON, disputed, text_form, web  # noqa: F401


def test_affected_target_is_a_caution_not_a_block(disputed, web):  # noqa: F811
    pid, url, db, ref = disputed
    card = web.client.get(url).text
    assert 'id="sca-set-cautions"' in card and "утверждению не мешает" in card
    assert "затронута: CVE-2099-30001" in card and "Дефект можно утвердить и с ней" in card
    form = text_form(card)  # объяснение – по строке на уязвимость «Описания», иначе блокирует само объяснение
    form["explanation"] = (form["explanation"] + "\nCVE-2099-10002: подмена данных при разборе документа из внешнего "
                           "источника без проверки значения.").strip()
    saved = web.client.post(f"{url}/package-text", headers=AS_JSON, data=form)
    answer = saved.json()
    assert saved.status_code == 200 and answer["ready"] is True, answer["hint"]
    assert answer["problems"] == [] and any("затронута: CVE-2099-30001" in c for c in answer["cautions"])
    assert "9.9.9" in answer["body"], "версия в тексте – та, что указал оператор"
    # предупреждение не исчезает рядом с настоящей блокировкой
    card = web.client.get(url).text
    refused = web.client.post(f"{url}/package-text", headers=AS_JSON, data={**text_form(card), "explanation": ""}).json()
    assert refused["ready"] is False and refused["problems"]
    assert any("затронута: CVE-2099-30001" in c for c in refused["cautions"])
