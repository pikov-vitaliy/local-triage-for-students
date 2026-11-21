"""Панель ресурсов и независимая свежесть состояния в браузере."""
import pytest
from playwright.sync_api import expect
from e2e_support import create_demo,run_triage,no_horizontal_scroll

pytestmark=pytest.mark.e2e


def test_run_resources_and_stale_connection(ui):
    page,watch=ui
    pid=create_demo(page)
    run_triage(page,pid)
    expect(page.locator('#run-observer')).to_be_visible()
    expect(page.locator('#obs-health')).to_contain_text('завершён',timeout=30000)
    expect(page.locator('#obs-ram')).not_to_have_text('Ожидаем измерение')
    page.locator('#obs-window').select_option('24h')
    expect(page.locator('.resource-charts svg')).to_have_count(3)
    for width in (390,1440):
        page.set_viewport_size({'width':width,'height':1000})
        assert no_horizontal_scroll(page)
    # Подменяется только сетевое состояние наблюдения, никакой команды повторного запуска.
    watch.allowed_errors.append('net::ERR_FAILED')  # Ожидаемый результат двух route.abort ниже.
    page.route('**/runs/*/status',lambda route:route.abort())
    page.route('**/runs/*/events',lambda route:route.abort())
    expect(page.locator('#obs-health')).to_contain_text('Нет свежих данных',timeout=22000)


def test_run_keeps_focused_result_and_displays_each_gpu(ui):
    page, _ = ui
    pid = create_demo(page)
    rid = run_triage(page, pid)
    state = page.request.get(f'/runs/{rid}/status').json()
    page.add_init_script("""(() => {const Native=window.EventSource;
      window.EventSource=class extends Native {constructor(...args){super(...args);window.runEvents=this;}};})();""")
    page.route(f'**/runs/{rid}/status', lambda route: route.fulfill(json=state))
    page.reload()
    expect(page.locator('#feed a').first).to_be_visible()
    page.locator('#feed a').first.focus()
    page.evaluate('window.retainedResult=document.activeElement')
    state['feed'].insert(0, {**state['feed'][0], 'hub_id': 999999, 'url': f'/projects/{pid}/findings/999999'})
    state['metrics']['gpu'] = {'name':'GPU A / GPU B', 'util_pct':90, 'temp_c':60, 'power_w':180,
        'gpus':[{'name':'GPU A','utilization_pct':90,'temperature_c':60,'power_w':100,
                 'memory_used_mb':6000,'memory_total_mb':8000},
                {'name':'GPU B','utilization_pct':0,'temperature_c':40,'power_w':80,
                 'memory_used_mb':2000,'memory_total_mb':8000}]}
    page.evaluate("s=>window.runEvents.dispatchEvent(new MessageEvent('status',{data:JSON.stringify(s)}))",state)
    assert page.evaluate('window.retainedResult===document.activeElement && window.retainedResult.isConnected')
    page.locator('#obs-gpus summary').click()
    expect(page.locator('#obs-gpu-list')).to_contain_text('GPU A')
    expect(page.locator('#obs-gpu-list')).to_contain_text('GPU B')
    expect(page.locator('#obs-gpu-list')).to_contain_text('0%')
    expect(page.locator('#obs-gpus')).to_contain_text('максимум')
