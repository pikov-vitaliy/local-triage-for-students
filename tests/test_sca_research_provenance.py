"""Версии и происхождение совета: реестр, точный пакет и текущая версия не заменяются догадкой."""
from copy import deepcopy

import pytest

from app import sca_contract as sc
from test_sca_research_contract import TASK, answer, check, row


@pytest.mark.parametrize('ecosystem,left,right,expected', [
    ('maven', '1.0', '1.0.0', 0),
    ('maven', '1.10', '1.9', 1),
    ('maven', '5.4.32.Final', '5.4.32', 0),
    ('maven', '9.0.0.M1', '9.0.0', -1),
    ('maven', '1.0-rc2', '1.0-rc10', -1),
    ('maven', '1.0-sp1', '1.0', 1),
    ('maven', '1.0-redhat-1', '1.0', None),
    ('npm', '1.0.0-beta.2', '1.0.0-beta.10', -1),
    ('npm', '1.0.0-beta', '1.0.0', -1),
    ('npm', '1.0.0+build.7', '1.0.0+build.8', 0),
    ('npm', '1.0.0-01', '1.0.0', None),
])
def test_explicit_supported_version_order(ecosystem, left, right, expected):
    assert sc.compare_versions(ecosystem, left, right) == expected


def test_update_advice_requires_a_source_for_publication_of_the_target():
    first = deepcopy(row())
    first['package_advice'].pop('source_refs', None)
    assert not check(answer(first, row(1))).ok


def test_unresolved_identity_cannot_attribute_latest_release_or_support_to_a_candidate():
    first = deepcopy(row())
    first['identity_resolution'].update(state='unresolved', coordinates=None, source_refs=[])
    first['public_findings'] = []
    first['package_advice'].update(action='needs_identity', target_version=None)
    first['package_status'] = 'identity_unresolved'
    assert not check(answer(first, row(1))).ok


def test_lost_npm_scope_can_be_resolved_with_an_explicit_basis_and_registry_evidence():
    first = deepcopy(row(1))
    task = deepcopy(TASK)
    name = first['component'].split('/')[-1]
    first['component'] = name
    task['rows'][1]['component'] = name
    first['identity_resolution']['basis'] = 'Подтверждены namespace и точная версия по публикации реестра'
    first['identity_resolution']['source_refs'] = ['ev-identity']
    first['evidence'].append({
        'evidence_ref': 'ev-identity', 'url': 'https://registry.example.invalid/package',
        'checked_at': '2026-10-16', 'source_type': 'registry',
        'justification': 'Публикация текущей версии в реестре',
        'quote': first['identity_resolution']['coordinates'] + '@' + first['current_version'], 'level': 'primary'
    })
    first['research_coverage'].append({
        'source': 'Example Registry', 'purpose': 'identity', 'status': 'ok', 'complete': True,
        'checked_at': '2026-10-16', 'note': '', 'source_refs': ['ev-identity'],
        'query': {'ecosystem': 'npm', 'coordinates': first['identity_resolution']['coordinates'],
                  'version': first['current_version']}
    })
    assert sc.validate_answer(sc.canonical(answer(row(), first)), task).ok
