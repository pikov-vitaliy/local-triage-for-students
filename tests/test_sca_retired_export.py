"""Старые адреса экспорта не должны выдавать задание с внутренними номерами."""
import pytest

from test_web import prepared, web  # noqa: F401


@pytest.mark.parametrize('name', ['components.csv', 'components.json', 'package.zip'])
def test_legacy_outbound_package_is_retired(web, name):
    pid = prepared(web)
    response = web.client.get(f'/projects/{pid}/sca/{name}', follow_redirects=False)
    assert response.status_code == 410
    assert f'/projects/{pid}/components' in response.text
    assert 'AST-' not in response.text


def test_legacy_export_still_checks_project_presence(web):
    assert web.client.get('/projects/99999/sca/package.zip').status_code == 404
