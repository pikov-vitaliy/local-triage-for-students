"""Независимые регрессии смысловых противоречий нового ответа SCA."""
from copy import deepcopy

from app import sca_contract as contract
from test_sca_research_contract import answer, check, row
from test_sca_research_contract import TASK


def report(first):
    return check(answer(first, row(1)))


def test_resolved_identity_cannot_substitute_another_maven_artifact():
    first = deepcopy(row())
    first['identity_resolution']['coordinates'] = 'org.other:other-artifact'
    assert not report(first).ok


def test_unknown_applicability_does_not_become_no_known_vulnerabilities():
    first = deepcopy(row())
    first['public_findings'][0]['applies'] = 'unknown'
    for source in first['research_coverage']:
        source.update(status='ok', complete=True, note='')
    first['package_status'] = 'no_known_vulnerabilities'
    assert contract.row_status(first) == 'incomplete'
    assert not report(first).ok


def test_release_registry_check_is_not_vulnerability_research():
    first = deepcopy(row())
    first['public_findings'] = []
    first['research_coverage'] = [
        {'source': 'Registry publication metadata', 'checked_at': '2026-10-16',
         'status': 'ok', 'complete': True, 'note': 'Only package publication was checked'}
    ]
    first['package_status'] = 'no_known_vulnerabilities'
    assert not report(first).ok


def test_same_version_is_not_an_available_update():
    first = deepcopy(row())
    first['latest_stable_release']['version'] = first['current_version']
    first['update_status'] = 'update_available'
    assert not report(first).ok


def test_unresolved_identity_cannot_attribute_applicable_cve_to_package():
    first = deepcopy(row())
    first['identity_resolution'].update(state='unresolved', coordinates='', source_refs=[])
    first['package_status'] = 'identity_unresolved'
    assert not report(first).ok


def test_untouched_template_is_not_a_completed_research_result():
    payload = answer(*(contract.empty_row(source) for source in TASK['rows']))
    assert not check(payload).ok


def clean_row():
    first = deepcopy(row())
    first['public_findings'] = []
    first['package_status'] = 'no_known_vulnerabilities'
    first['package_advice'].update(action='no_action', target_version=None)
    first['research_coverage'] = [{
        'source': 'Example Project official published advisories',
        'purpose': 'vulnerabilities',
        'query': {'ecosystem': first['ecosystem'],
                  'coordinates': first['identity_resolution']['coordinates'],
                  'version': first['current_version']},
        'source_refs': ['ev-1'], 'checked_at': '2026-10-16',
        'status': 'ok', 'complete': True, 'note': ''
    }]
    return first


def test_arbitrary_official_advisory_source_is_allowed_with_explicit_query_and_purpose():
    assert report(clean_row()).ok


def test_osv_name_alone_does_not_prove_query_target_or_vulnerability_coverage():
    first = clean_row()
    for source in first['research_coverage']:
        source.pop('purpose')
        source.pop('query')
        source.pop('source_refs')
        source['source'] = 'OSV'
    assert not report(first).ok


def test_missing_latest_release_does_not_erase_successful_vulnerability_research():
    first = clean_row()
    first['latest_stable_release'].update(version=None, released_at='', source_refs=[],
                                          note='Latest release could not be established')
    first['update_status'] = 'unknown'
    first['gaps'] = [{'code': 'RELEASE_UNKNOWN', 'text': 'Latest release could not be established'}]
    assert contract.row_status(first) == 'no_known_vulnerabilities'
    assert report(first).ok


def test_update_recommendation_cannot_target_the_current_or_older_version():
    for target in (row()['current_version'], '1.0.0'):
        first = deepcopy(row())
        first['package_advice']['target_version'] = target
        assert not report(first).ok


def test_successful_vulnerability_query_must_match_the_resolved_package_and_current_version():
    first = clean_row()
    first['research_coverage'][0]['query']['coordinates'] = 'org.other:unrelated'
    assert not report(first).ok
    first = clean_row()
    first['research_coverage'][0]['query']['version'] = '0.0.0'
    assert not report(first).ok


def test_short_maven_name_may_add_namespace_but_not_replace_artifact():
    first = deepcopy(row())
    task = deepcopy(TASK)
    raw = first['component'].rsplit(':', 1)[-1]
    task['rows'][0].update(component=raw, identity_kind='short_name')
    first['component'] = raw
    first['identity_resolution']['coordinates'] = 'org.other:unrelated'
    assert not contract.validate_answer(contract.canonical(answer(first, row(1))), task).ok


def test_failed_release_lookup_does_not_erase_complete_vulnerability_search():
    first = clean_row()
    first['latest_stable_release'].update(version=None, released_at='', source_refs=[])
    first['update_status'] = 'unknown'
    first['research_coverage'].append({
        'source': 'Example Registry', 'purpose': 'releases',
        'query': dict(first['research_coverage'][0]['query']), 'source_refs': [],
        'checked_at': '2026-10-16', 'status': 'error', 'complete': False, 'note': 'HTTP 503'
    })
    first['gaps'] = [{'code': 'RELEASE_UNKNOWN', 'text': 'Источник релизов недоступен'}]
    assert contract.row_status(first) == 'no_known_vulnerabilities'
    assert report(first).ok
