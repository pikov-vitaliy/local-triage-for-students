"""Поток модели: события до финала и та же итоговая проверка ответа."""
import json
import pytest
from app.llm import LlmError, OllamaClient
from test_llm import FIELDS,REQUIRED,ENUMS,MESSAGES,QWEN,answer
from fake_ollama import FakeOllama


def test_streamed_chat_reports_progress_before_final():
    with FakeOllama(default_answer=answer()) as fake:
        events=[]
        result,stats=OllamaClient(fake.url).chat_json(QWEN,MESSAGES,FIELDS,REQUIRED,ENUMS,progress=events.append)
        assert result['verdict']=='false_positive'
        assert any(e['event']=='fragment' for e in events)
        assert events[-1]['event']=='response_done'
        assert fake.chats()[0]['stream'] is True


def test_fragment_reassembly_and_missing_done():
    from app.llm import read_chat_stream
    raw=[json.dumps({'message':{'content':x},'done':False},ensure_ascii=False).encode()+b'\n' for x in ['{"summary":','"Привет"}']]
    raw.append(b'{"done":true,"eval_count":9}\n')
    events=[]
    pieces=[b''.join(raw)[i:i+3] for i in range(0,len(b''.join(raw)),3)]
    result=read_chat_stream(pieces,events.append)
    assert result['message']['content']=='{"summary":"Привет"}'
    assert result['eval_count']==9
    assert events
    with pytest.raises(LlmError,match='заверш'):
        read_chat_stream(raw[:-1],events.append)


def test_real_http_stream_emits_before_completion():
    import threading
    with FakeOllama(default_answer=answer()) as fake:
        fake.stream_delay=.04
        done=threading.Event();fragment=threading.Event();errors=[]
        def run():
            try:OllamaClient(fake.url).chat_json(QWEN,MESSAGES,FIELDS,REQUIRED,ENUMS,progress=lambda e:fragment.set() if e['event']=='fragment' else None)
            except Exception as e:errors.append(e)
            finally:done.set()
        thread=threading.Thread(target=run);thread.start()
        assert fragment.wait(2)
        assert not done.wait(.1)
        thread.join(3)
        assert not errors and done.is_set()


def test_failed_progress_observer_does_not_change_the_model_answer():
    def broken(event):raise RuntimeError('synthetic observer failure')
    with FakeOllama(default_answer=answer()) as fake:
        result,_=OllamaClient(fake.url).chat_json(QWEN,MESSAGES,FIELDS,REQUIRED,ENUMS,progress=broken)
        assert result['verdict']=='false_positive'
