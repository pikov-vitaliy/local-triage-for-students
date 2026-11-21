"""Выдуманные опубликованные сведения для поведенческих проверок нового контракта, без сетевых запросов."""


def complete_research_row(item):
    """Связать заведомо выдуманный пакет с выдуманными публикациями и протоколом запросов.

    Вызывается при сборке положительной заготовки до подмен, проверяющих отказ. Не применяется к входу приложения.
    """
    eco, raw = item['ecosystem'], item['component']
    coordinates = ('org.example:' + raw) if eco == 'maven' and ':' not in raw else raw
    item['identity_resolution'].update(coordinates=coordinates,
                                       basis='Выдуманный namespace подтверждён публикацией точной версии',
                                       source_refs=['ev-registry'])
    item['evidence'].append({
        'evidence_ref': 'ev-registry', 'url': 'https://registry.example.invalid/package/versions',
        'checked_at': '2026-10-16', 'source_type': 'registry',
        'justification': 'Публикации выдуманного пакета и версий',
        'quote': coordinates + ': ' + ', '.join(filter(None, [item['current_version'],
                    item['latest_stable_release']['version'], item['package_advice']['target_version']])),
        'level': 'primary'
    })
    item['latest_stable_release']['source_refs'] = ['ev-registry']
    item['package_advice']['source_refs'] = ['ev-registry'] if item['package_advice']['target_version'] else []
    query = {'ecosystem': eco, 'coordinates': coordinates, 'version': item['current_version']}
    for entry in item['research_coverage']:
        entry.setdefault('purpose', 'vulnerabilities')
        entry['query'] = dict(query)
        entry.setdefault('source_refs', ['ev-1'] if entry['status'] == 'ok' else [])
    item['research_coverage'].append({
        'source': 'Example Registry identity', 'purpose': 'identity', 'query': query,
        'source_refs': ['ev-registry'], 'checked_at': '2026-10-16', 'status': 'ok', 'complete': True, 'note': ''
    })
    return item
