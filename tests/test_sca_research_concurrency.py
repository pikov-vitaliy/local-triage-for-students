"""Сохранение решения относится к увиденному исследованию, а не к новому ответу из другой вкладки."""
import json

from test_sca_research_routes import (AS_JSON, build_task, kit_answer, project_with_sca, upload_answer)
from test_web import web  # noqa: F401


def ready(web):
    pid = project_with_sca(web)
    manifest = build_task(web, pid)
    payload = kit_answer(manifest)
    assert upload_answer(web, pid, payload).status_code == 303
    ref = manifest['rows'][0]['input_ref']
    old = web.app.state.db.research_row(pid, ref)
    return pid, manifest, payload, ref, old


def form(old, **changes):
    return {'action': 'accept_risk', 'rationale': 'Оператор проверил условия применения',
            'revision': '0', 'expected_input_sig': old['input_sig'],
            'expected_research_sig': old['answer_sig'],
            'expected_research_revision': str(old['revision']), **changes}


def test_new_research_without_new_decision_makes_old_form_stale(web):
    pid, _, payload, ref, old = ready(web)
    changed = json.loads(payload)
    changed['rows'][0]['public_findings'][0]['conditions'] = 'Изменились существенные условия применения'
    assert upload_answer(web, pid, json.dumps(changed)).status_code == 303
    response = web.client.post(f'/projects/{pid}/components/{ref}/decision',
                               headers=AS_JSON, data=form(old), follow_redirects=False)
    assert response.status_code == 409
    assert web.app.state.db.decision(pid, ref) is None


def test_decision_without_seen_research_token_is_not_silently_bound_to_current(web):
    pid, _, _, ref, _ = ready(web)
    response = web.client.post(f'/projects/{pid}/components/{ref}/decision', headers=AS_JSON,
                               data={'action': 'keep', 'rationale': 'Проверено', 'revision': '0'},
                               follow_redirects=False)
    assert response.status_code in (409, 422)
    assert web.app.state.db.decision(pid, ref) is None


def test_replacement_can_be_decided_before_choosing_its_exact_version(web):
    pid, _, _, ref, old = ready(web)
    response = web.client.post(f'/projects/{pid}/components/{ref}/decision', headers=AS_JSON,
                               data=form(old, action='replace', replacement_name='Example Alternative',
                                         replacement_version=''), follow_redirects=False)
    assert response.status_code in (200, 303)
    assert web.app.state.db.decision(pid, ref)['replacement_name'] == 'Example Alternative'


def save_current_risk(web, pid, ref, old):
    response = web.client.post(f'/projects/{pid}/components/{ref}/decision', headers=AS_JSON,
                               data=form(old), follow_redirects=False)
    assert response.status_code in (200, 303)


def test_refreshing_only_source_check_dates_preserves_existing_decision(web):
    pid, _, payload, ref, old = ready(web)
    save_current_risk(web, pid, ref, old)
    changed = json.loads(payload)
    for item in changed['rows']:
        for source in item['research_coverage'] + item['evidence']:
            source['checked_at'] = '2026-10-17'
    assert upload_answer(web, pid, json.dumps(changed)).status_code == 303
    refreshed = web.app.state.db.research_row(pid, ref)
    # Повторное наблюдение сохраняет свежие даты без новой ревизии фактов (SCA-10).
    assert refreshed['revision'] == old['revision']
    assert refreshed['payload']['evidence'][0]['checked_at'] == '2026-10-17'
    result = web.client.get(f'/projects/{pid}/components/{ref}/report?format=json').json()['components'][0]
    assert not result['decision_stale']
    assert result['decision']['action'] == 'accept_risk'
    assert result['public_findings']


def test_changing_conditions_of_public_finding_requires_review_of_risk(web):
    pid, _, payload, ref, old = ready(web)
    save_current_risk(web, pid, ref, old)
    changed = json.loads(payload)
    changed['rows'][0]['public_findings'][0]['conditions'] = 'Изменилось условие, на котором принят риск'
    assert upload_answer(web, pid, json.dumps(changed)).status_code == 303
    result = web.client.get(f'/projects/{pid}/components/{ref}/report?format=json').json()['components'][0]
    assert result['decision_stale']
    assert result['decision']['action'] == 'accept_risk'


def test_research_changed_between_form_check_and_database_write_is_rejected(web, monkeypatch):
    pid, _, payload, ref, old = ready(web)
    db = web.app.state.db
    original = db.save_decision
    def race(*args, **kwargs):
        changed = json.loads(payload)
        changed['rows'][0]['public_findings'][0]['conditions'] = 'Новые факты прямо перед записью решения'
        assert upload_answer(web, pid, json.dumps(changed)).status_code == 303
        return original(*args, **kwargs)
    monkeypatch.setattr(db, 'save_decision', race)
    response = web.client.post(f'/projects/{pid}/components/{ref}/decision', headers=AS_JSON,
                               data=form(old), follow_redirects=False)
    assert response.status_code == 409
    assert db.decision(pid, ref) is None


def test_composition_changed_after_validation_does_not_accept_old_research(web, monkeypatch):
    from app.hub_import import parse_workbook
    from app.triage import order_findings
    from hub_fixtures import SCA_ROWS, make_hub_xlsx
    pid = project_with_sca(web)
    manifest = build_task(web, pid)
    db = web.app.state.db
    original = db.save_research
    def race(*args, **kwargs):
        newer = [dict(row, **{'Component version': '99.0.0'}) for row in SCA_ROWS]
        path = make_hub_xlsx(web.tmp / 'changed-during-answer.xlsx', sast=(), sca=newer)
        parsed = parse_workbook(path)
        db.save_import(pid, path.name, parsed.format, parsed.sheets, parsed.summary, parsed.warnings,
                       order_findings(parsed.findings))
        return original(*args, **kwargs)
    monkeypatch.setattr(db, 'save_research', race)
    response = upload_answer(web, pid, kit_answer(manifest))
    assert response.status_code == 409
    assert db.research(pid) == {}
    assert db.current_task(pid)['imported_at'] is None
