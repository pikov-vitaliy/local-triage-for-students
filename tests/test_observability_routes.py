"""Новые поля наблюдения и ограниченные адреса истории."""
from test_web import web,prepared,start_run,wait_run  # noqa: F401


def test_resource_history_and_active_run(web):
    r=web.client.get('/api/metrics/history?window=24h')
    assert r.status_code==200 and len(r.json()['points'])<=1440
    assert web.client.get('/api/metrics/history?window=unknown').status_code==400
    pid=prepared(web)
    run=start_run(web,pid)
    data=web.client.get(f'/runs/{run}/status').json()
    assert data['observed_at'] and 'last_result_at' in data
    assert data['metrics']['observed_at']
    assert web.client.get('/api/runs/active').status_code==200
    page=web.client.get(f'/runs/{run}')
    assert 'RAM компьютера с Ollama' in page.text
    assert 'obs-health' in page.text
    wait_run(web,run)


def test_global_indicator_prefers_running_over_an_older_paused_job(web):
    web.app.state.runner.shutdown()
    db=web.app.state.db
    first=db.create_project('Пауза')
    second=db.create_project('Работа')
    paused=db.create_run(first,'m','all','p',[])
    db.set_run_state(paused,'paused')
    running=db.create_run(second,'m','all','p',[])
    db.set_run_state(running,'running')
    assert web.client.get('/api/runs/active').json()['run']['id']==running
