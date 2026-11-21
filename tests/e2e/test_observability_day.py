"""Сутки логического времени: ограниченность DOM и запросов наблюдателя."""
import copy
import time
import pytest
from playwright.sync_api import expect
from e2e_support import create_demo, run_triage

pytestmark = pytest.mark.e2e


def test_observer_logical_day_has_bounded_dom_and_inflight_requests(ui):
    page, _ = ui
    page.add_init_script("""(() => {const Native=window.EventSource;window.observationSources={created:0,open:0};
      window.EventSource=class extends Native {constructor(...args){super(...args);this.counted=true;window.observationSources.created++;window.observationSources.open++;}
      close(){if(this.counted){this.counted=false;window.observationSources.open--;}return super.close();}};})();""")
    pid = create_demo(page)
    rid = run_triage(page, pid)
    state = page.request.get(page.url + '/status').json()
    state = copy.deepcopy(state)
    origin = time.time()
    step = [0]
    state['run']['state'] = 'running'
    state['run']['state_label'] = 'Идёт'
    state['metrics']['resource_status'] = 'fresh'
    state['metrics']['host'] = {'status': 'fresh', 'cpu_pct': 20, 'memory': {'used_bytes': 20 * 1024**3, 'total_bytes': 64 * 1024**3}}

    def status(route):
        stamp = origin + step[0] * 60
        state['observed_at'] = stamp
        state['metrics']['observed_at'] = stamp
        state['metrics']['host']['sampled_at'] = stamp
        state['current'] = {'phase': 'generating', 'last_model_event_at': stamp}
        route.fulfill(json=state)

    def history(route):
        count = 1440 if '24h' in route.request.url else 180
        stamp = origin + step[0] * 60
        points = [{'at': stamp - (count-i)*5, 'source_epoch': 'synthetic', 'gpu': i%100,
                   'vram': 12000+i%300, 'ram': 20+i%5} for i in range(count)]
        route.fulfill(json={'points': points})

    page.route(f'**/runs/{rid}/status', status)
    page.route('**/api/metrics/history?*', history)
    page.evaluate("""() => {const original=window.fetch;window.observationTest={active:0,max:0};window.fetch=async(...args)=>{
      const t=window.observationTest;t.active++;t.max=Math.max(t.max,t.active);
      try{return await original(...args);}finally{t.active--;}};}""")
    page.clock.install(time=origin*1000)
    session = page.context.new_cdp_session(page)
    session.send('Performance.enable')
    baseline = page.locator('*').count()
    for minute in range(1, 1441):
        step[0] = minute
        page.clock.fast_forward(60_000)
    page.locator('#obs-window').select_option('24h')
    # Дать завершиться двум запросам, не продвигая модель и не подменяя результаты на сервере.
    expect(page.locator('#obs-gpu-chart path')).to_have_count(1)
    assert page.locator('*').count() - baseline < 100
    assert page.evaluate('window.observationTest.max') <= 2
    assert page.evaluate('window.observationSources.created') == 1
    assert page.evaluate('window.observationSources.open') <= 1
    assert page.locator('.resource-charts svg').count() == 3
    session.send('HeapProfiler.collectGarbage')
    metrics = {x['name']: x['value'] for x in session.send('Performance.getMetrics')['metrics']}
    assert metrics['JSHeapUsedSize'] < 12 * 1024**2
    session.detach()
