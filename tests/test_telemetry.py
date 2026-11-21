"""Наблюдение не блокирует триаж, история ограничена, неизвестное не становится нулём."""
import json
import threading
import time


def test_host_memory_scope_and_freshness(tmp_path):
    from app.telemetry import host_snapshot
    p=tmp_path/'host.json'
    p.write_text(json.dumps({'schema':1,'sequence':5,'sampled_at':100,'host_scope':'ollama_host','memory':{'total_bytes':1000,'available_bytes':300,'used_bytes':700},'cpu_pct':25}))
    assert host_snapshot(p,now=105)['memory']['used_bytes']==700
    assert host_snapshot(p,now=150)['status']=='stale'
    p.write_text('{incomplete')
    assert host_snapshot(p,now=105)['status']=='unavailable'


def test_sampler_snapshot_does_not_wait_for_gpu(tmp_path):
    from app.telemetry import Telemetry
    blocked=threading.Event()
    t=Telemetry(tmp_path,lambda:blocked.wait(1))
    t.start()
    before=time.monotonic()
    assert t.snapshot()['resource_status']=='unavailable'
    assert time.monotonic()-before<.1
    blocked.set();t.close()


def test_bounded_history_and_gaps(tmp_path):
    from app.telemetry import Telemetry
    t=Telemetry(tmp_path,lambda:{})
    origin=time.time()-86400
    for i in range(24*60+1):
        t.record({'gpu':{'util_pct':i%100},'models':[]},origin+i*60)
    assert len(t.history('15m'))<=180
    assert len(t.history('24h'))<=1440
    t.record({'gpu':None,'models':[]},origin+86401)
    assert t.history('15m')[-1]['gpu'] is None
    t.close()
    t=Telemetry(tmp_path,lambda:{})
    assert t.history('24h')
    t.close()


def test_bad_metrics_do_not_keep_fresh_success(tmp_path):
    from app.telemetry import Telemetry
    t=Telemetry(tmp_path,lambda:{})
    t.record({'gpu':{'util_pct':0},'models':[],'error':None},100)
    t.record({'gpu':None,'models':[],'error':'Недоступно'},105)
    assert t.snapshot(now=106)['resource_status']=='unavailable'
    t.close()
