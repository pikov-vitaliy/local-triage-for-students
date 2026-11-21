"""Решения оператора и неполный разбор повторной выгрузки."""
import html
import re

import pytest

from hub_fixtures import SAST_ROWS, make_hub_xlsx
from test_db import db, load, sast, verdict  # noqa: F401
from test_sca import answers_text, form_fields, post_answers, sca_card
from test_web import ORIGIN, prepared, upload, web  # noqa: F401


def changed_model(db):
    pid=db.create_project('Demo Library');load(db,pid,[sast('A')])
    vid=db.save_verdict('same-code','demo','v1',verdict('false_positive'),{})
    db.save_case(pid,'A','same-code',{},vid)
    db.save_review(pid,'A',decision='agree',final_verdict='false_positive',final_comment='Проверено',
                   reviewed=True,verdict_id=vid)
    newer=db.save_verdict('same-code','demo','v1',verdict('true_positive'),{})
    db.save_case(pid,'A','same-code',{},newer)
    return pid


def test_opposite_verdict_on_the_same_code_keeps_the_review(db):
    """Новый ответ модели по тому же коду (тот же отпечаток среза) решение человека не ослабляет – «Проверено»
    остаётся (ADR-0097; до 0.9.10 противоположный вердикт снимал отметку)."""
    pid=changed_model(db)
    review=db.get_review(pid,'A')
    assert review['reviewed']==1 and review['reviewed_at']
    assert db.review_stats(pid)['reviewed']==1


def test_review_after_new_model_answer_can_be_marked_again(db):
    """Отметку «Проверено» по решению прежнего разбора того же кода можно снять и поставить снова (ADR-0097)."""
    pid=changed_model(db)
    db.set_reviewed(pid,'A',False)
    assert db.set_reviewed(pid,'A',True)['reviewed']==1


def test_new_code_still_reopens_the_review(db):
    """Другой код (другой отпечаток среза) по-прежнему снимает «Проверено»."""
    pid=changed_model(db)
    newer=db.save_verdict('other-code','demo','v1',verdict('true_positive'),{})
    db.save_case(pid,'A','other-code',{},newer)
    assert db.get_review(pid,'A')['reviewed']==0


@pytest.mark.parametrize('decision,action',[('disagree','copy'),('risk_accepted','copy'),('risk_accepted','save')])
def test_legacy_sca_model_comment_for_other_verdict_needs_confirmation(web,decision,action):
    pid=prepared(web);assert post_answers(web,pid,answers_text()).status_code==303
    fid,card=sca_card(web,pid,'73001')
    comment=html.unescape(re.search(r'<textarea[^>]*id="comment"[^>]*>(.*?)</textarea>',card,re.S).group(1))
    fields={**form_fields(card),'decision':decision,'final_verdict':'false_positive','comment':comment,
            'action':action,'reviewed':'1'}
    response=web.client.post(f'/projects/{pid}/sca/findings/{fid}/review',headers={**ORIGIN,'Accept':'application/json'},data=fields)
    assert response.status_code==409,response.text
    assert 'комментар' in response.json()['detail'].lower() or 'текст' in response.json()['detail'].lower()
    assert not web.app.state.db.get_review(pid,'73001')


def test_legacy_sca_card_has_comment_confirmation_controls(web):
    pid=prepared(web);post_answers(web,pid,answers_text());_,card=sca_card(web,pid,'73001')
    for element in ['comment-stale','comment-confirm-label','comment-confirm']:
        assert f'id="{element}"' in card
    assert 'data-comment-for=' in card


def test_partial_reimport_requires_explicit_confirmation(web):
    pid=prepared(web)
    old=web.app.state.db.get_finding_by_hub_id(pid,'510002')
    path=make_hub_xlsx(web.tmp/'partial.xlsx',sast=[SAST_ROWS[0],dict(SAST_ROWS[1],**{'Issue id':''})],sca=())
    response=upload(web.client,pid,path)
    assert response.status_code==409,response.text
    assert 'пропущ' in response.text or 'без ID' in response.text
    assert not web.app.state.db.get_finding_by_hub_id(pid,'510002')['missing']
    assert web.app.state.db.get_finding_by_hub_id(pid,'510002')['id']==old['id']


def test_correct_empty_reimport_is_not_confused_with_parse_loss(web):
    # Пустая выгрузка в непустой проект применяется только с подтверждением «Загрузить всё равно»:
    # без него все находки молча получили бы пометку «нет в выгрузке»
    pid=prepared(web)
    path=make_hub_xlsx(web.tmp/'empty.xlsx',sast=(),sca=())
    response=upload(web.client,pid,path)
    assert response.status_code==409 and 'нет ни одной находки' in response.text,response.text
    assert not web.app.state.db.get_finding_by_hub_id(pid,'510002')['missing']
    with open(path,'rb') as fh:
        response=web.client.post(f'/projects/{pid}/import',headers=ORIGIN,follow_redirects=False,data={'confirm_other':'1'},
                                 files={'file':(path.name,fh.read(),'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')})
    assert response.status_code==303,response.text
    assert web.app.state.db.get_finding_by_hub_id(pid,'510002')['missing']
