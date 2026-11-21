"""Снимки прогона и честная статистика неизменяемых ответов."""

from app.db import Database
from app.models import Finding
from app.triage import order_findings


def test_snapshot_survives_reimport_and_counts_queue_separately(tmp_path):
    from app.journal import detail
    db = Database(tmp_path / 'triage.db')
    pid = db.create_project('Журнал')
    findings = [Finding(hub_id='1', kind='SAST', language='C++', rule='x'),
                Finding(hub_id='2', kind='SCA', component='lib', version='1')]
    db.save_import(pid, 'test', 'csv', [], {}, [], order_findings(findings))
    rid = db.create_run(pid, 'model', 'all', 'p1', ['1'])
    snapshot = detail(db, rid)
    assert snapshot['snapshot']['input']['kinds'] == {'SAST': 1, 'SCA': 1}
    assert snapshot['snapshot']['queue']['languages'] == {'C++': 1}
    from app.journal import collect
    assert [r['run']['id'] for r in collect(db, {'language':'C++'})] == [rid]
    assert collect(db, {'language':'Python'}) == []
    original = snapshot['snapshot']['workload_sha256']
    db.save_import(pid, 'new', 'csv', [], {}, [], order_findings([Finding(hub_id='3', kind='SAST')]))
    db.close()
    db = Database(tmp_path / 'triage.db')
    assert detail(db, rid)['snapshot']['workload_sha256'] == original
    assert detail(db, rid)['snapshot']['queue']['total'] == 1
    db.close()


def test_journal_page_and_exports_use_same_filtered_set(web):
    db = web.app.state.db
    pid = db.create_project('Статистика')
    a = db.create_run(pid, 'fast', 'all', 'p1', [])
    db.create_run(pid, 'slow', 'all', 'p1', [])
    response = web.client.get('/journal?model=fast')
    assert response.status_code == 200
    assert 'Журнал' in response.text
    data = web.client.get('/journal/export.json?model=fast').json()
    assert [r['run']['id'] for r in data['runs']] == [a]
    assert data['contract'] == 'local-triage/run-journal/2'
    assert len(data['installation_id']) == 32
    assert web.client.get('/journal/export.json').json()['installation_id'] == data['installation_id']
    csv = web.client.get('/journal/export.csv?model=fast')
    assert csv.status_code == 200 and 'attachment' in csv.headers['content-disposition']
    assert 'fast' in csv.text and 'slow' not in csv.text
    assert web.client.get(f'/journal/{a}').status_code == 200
    assert web.client.get('/journal/999999').status_code == 404
    assert web.client.get('/journal?from=bad').status_code == 400


from test_web import web  # noqa: E402,F401


def test_active_time_excludes_pause_and_interrupted_is_lower_bound(tmp_path, monkeypatch):
    import app.db as module
    import app.journal as journal
    tick=[0]
    monkeypatch.setattr(journal,'monotonic',lambda:tick[0])
    from app.journal import detail
    db = Database(tmp_path / 'clock.db')
    pid = db.create_project('Время')
    rid = db.create_run(pid, 'm', 'all', 'p', [])
    monkeypatch.setattr(module, 'now_iso', lambda: '2026-10-18T10:00:00+00:00')
    db.set_run_state(rid, 'running')
    tick[0]=60
    monkeypatch.setattr(module, 'now_iso', lambda: '2026-10-18T10:01:00+00:00')
    db.set_run_state(rid, 'paused')
    monkeypatch.setattr(module, 'now_iso', lambda: '2026-10-18T11:00:00+00:00')
    db.set_run_state(rid, 'running')
    tick[0]=180
    monkeypatch.setattr(module, 'now_iso', lambda: '2026-10-18T11:02:00+00:00')
    db.set_run_state(rid, 'done')
    result = detail(db, rid)
    assert result['active_seconds'] == 180 and result['elapsed_seconds'] == 3720
    other = db.create_run(pid, 'm', 'all', 'p', [])
    db.set_run_state(other, 'running')
    db.recover_interrupted()
    assert detail(db, other)['time_incomplete']
    db.close()


def test_active_time_uses_monotonic_clock_when_wall_clock_moves_back(tmp_path,monkeypatch):
    import app.db as module
    import app.journal as journal
    tick=[100]
    monkeypatch.setattr(journal,'monotonic',lambda:tick[0])
    db=Database(tmp_path/'ntp.db')
    rid=db.create_run(db.create_project('Часы'),'m','all','p',[])
    monkeypatch.setattr(module,'now_iso',lambda:'2026-10-18T10:00:00+00:00')
    db.set_run_state(rid,'running')
    tick[0]=160
    monkeypatch.setattr(module,'now_iso',lambda:'2026-10-18T09:00:00+00:00')
    db.set_run_state(rid,'paused')
    assert journal.detail(db,rid)['active_seconds']==60
    db.close()


def test_verdicts_are_historical_and_only_same_answer_reviews_count(tmp_path):
    from app.journal import detail
    from test_db import load, sast, verdict
    db = Database(tmp_path / 'verdict.db')
    pid = db.create_project('Вердикты')
    load(db, pid, [sast('1')])
    rid = db.create_run(pid, 'm', 'all', 'p', ['1'])
    old = db.save_verdict('hash', 'm', 'p', verdict('false_positive'), {})
    db.save_case(pid, '1', 'hash', {}, old)
    item = db.next_pending_item(rid)
    db.finish_item(rid, item['id'], 'done', verdict_id=old)
    db.save_review(pid, '1', decision='agree', final_verdict='false_positive', final_comment='Да', reviewed=True, verdict_id=old)
    assert detail(db, rid)['agreement_pct'] == 100
    cached_run=db.create_run(pid,'m','all','p',['1'])
    cached_item=db.next_pending_item(cached_run)
    db.finish_item(cached_run,cached_item['id'],'cached',verdict_id=old)
    assert detail(db,cached_run)['verdicts']=={}
    assert detail(db,cached_run)['cached_verdicts']=={'false_positive':1}
    assert detail(db,cached_run)['review_denominator']==0
    new = db.save_verdict('hash2', 'm', 'p', verdict('true_positive'), {})
    db.save_case(pid, '1', 'hash2', {}, new)
    assert detail(db, rid)['verdicts'] == {'false_positive': 1}
    assert detail(db, rid)['review_denominator'] == 1  # Оценка прежнего ответа сохраняется в истории.
    db.close()


def test_resources_are_aggregate_only_and_eta_needs_three_full_answers(tmp_path):
    from app.journal import resources, detail, eta_average, call_sample
    db = Database(tmp_path / 'resources.db')
    pid = db.create_project('Замеры')
    rid = db.create_run(pid, 'm', 'all', 'p', [])
    db.set_run_state(rid, 'running')
    resources(db, {'gpu': {'util_pct': 40}, 'vram_used_mb': 100}, {'status': 'unavailable'})
    resources(db, {'gpu': {'util_pct': 80}, 'vram_used_mb': 120}, {'status': 'unavailable'})
    stats = detail(db, rid)['snapshot']['resources']
    assert stats['gpu_pct'] == {'count': 2, 'sum': 120, 'max': 80}
    assert 'ram_gib' not in stats
    with db._tx() as c:
        call_sample(c, rid, 10); call_sample(c, rid, 20)
    assert eta_average(db, rid) is None
    with db._tx() as c:
        call_sample(c, rid, 30)
    assert eta_average(db, rid) == 20
    with db._tx() as c:
        for n in range(30):call_sample(c, rid, 1)
    assert eta_average(db, rid) == 1
    db.close()
