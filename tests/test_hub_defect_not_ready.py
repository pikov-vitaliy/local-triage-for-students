"""0.9.26.dev26: блок «Создать дефект в Hub» виден всегда; пока текст дефекта не готов, вместо кнопки – причина
(в карточке без кнопки «Создать дефект» оператору должно быть понятно, почему её нет). Данные выдуманы."""

from test_hub_defects import hub_settings, sast_ready
from test_web import prepared, start_run, wait_run, web  # noqa: F401


def test_sast_card_shows_reason_until_decision_is_saved(web):
    pid = prepared(web)
    assert wait_run(web, start_run(web, pid))["state"] == "done"
    hub_settings(web, pid)
    db = web.app.state.db
    url = f"/projects/{pid}/findings/{db.get_finding_by_hub_id(pid, '510001')['id']}"
    html = web.client.get(url).text
    # в карточке SAST блок лежит внутри шага «Перенос в Hub» (.hub-when-tp), который показывается после выбора
    # «Подтверждаю дефект»; причина вместо кнопки – в разметке с самого начала
    assert 'id="hub-defect"' in html and 'id="hub-defect" hidden' not in html
    assert 'id="hub-defect-not-ready"' in html and "Создать дефект пока нельзя" in html
    assert 'id="hub-defect-button"' not in html
    _, ready_url = sast_ready(web)  # решение «Подтверждаю дефект» сохранено – кнопка есть, причины нет
    ready = web.client.get(ready_url).text
    assert 'id="hub-defect-button"' in ready and 'id="hub-defect-not-ready"' not in ready


def test_sca_card_shows_reason_until_text_is_approved(web):
    from test_sca import sca_text_ready
    from test_sca_package_decision import UPD, post_package
    pid = prepared(web)
    hub_settings(web, pid)
    db = web.app.state.db
    assert post_package(web, pid, "73001", ["73001", "73002"], **UPD).status_code == 200
    url = f"/projects/{pid}/sca/findings/{db.get_finding_by_hub_id(pid, '73001')['id']}"
    html = web.client.get(url).text
    assert 'id="hub-defect-not-ready"' in html and "плашки «Перед выдачей дефекта»" in html
    assert "утвердите текст дефекта" in html  # сама причина – в плашке
    assert 'id="hub-defect-button"' not in html
    assert "Утвердить текст дефекта" in html and "Сохранить текст дефекта" not in html
    sca_text_ready(web, url)
    ready = web.client.get(url).text
    assert 'id="hub-defect-button"' in ready and 'id="hub-defect-not-ready"' not in ready
