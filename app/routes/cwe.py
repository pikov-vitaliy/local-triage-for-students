"""Справочник классов CWE внутри приложения: список /cwe с поиском, фильтром и постраничностью, карточка
/cwe/{id} в духе страницы MITRE и страница записи БДУ по CVE /bdu/{cve}, на которую ссылаются наблюдаемые
примеры каталога CWE.

Источник – та же выгрузка каталога, что пользователь загружает на странице «Справочники» (app/feeds.py): полная
запись класса и связи между классами считаются при загрузке, поэтому здесь только чтение. Содержимое каталога –
данные: показывается как есть, на английском, автоэкранированием шаблона, без обращений в интернет. Русское
название рядом с английским берётся из выгрузки БДУ по тому же номеру и только при прямом совпадении.
Каталог не загружен – /cwe показывает пустое состояние, /cwe/{id} и /bdu/{cve} – 404 с подсказкой.
"""

from __future__ import annotations

import re
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse

from app import i18n, worklists
from app.feeds import FeedStore, cwe_id
from app.routes.common import query, render
from app.routes.references import missing_reference

router = APIRouter()

PAGE_SIZE = 200  # записей каталога на страницу списка
KIND_FILTERS = {"weakness": "Weakness", "category": "Category"}
CWE_NOT_LOADED = i18n.N_("Каталог CWE не загружен. Загрузите архив cwec_latest.xml.zip на странице «Справочники».")
CWE_NO_SUCH = i18n.N_("Такого класса в каталоге нет.")
BDU_NOT_LOADED = i18n.N_("Выгрузка БДУ ФСТЭК России не загружена. Загрузите архив vulxml.zip на странице «Справочники».")
TERMS_URL = "https://cwe.mitre.org/about/termsofuse.html"

_CVE = re.compile(r"CVE-\d{4}-\d{4,}")


def store_of(request: Request) -> FeedStore:
    return request.app.state.feeds


def _filters(request: Request) -> dict[str, str]:
    """Значения фильтров из адреса: неизвестный вид записи отбрасывается, а не отбирает молча."""
    kind = request.query_params.get("kind", "")
    return {"q": request.query_params.get("q", "")[:120].strip(),
            "kind": kind if kind in KIND_FILTERS else "",
            "page": request.query_params.get("page", "")[:6],
            "abstraction": request.query_params.get("abstraction", "")[:40],
            "status": request.query_params.get("status", "")[:40],
            **worklists.options(request.query_params, {f"{k}_{d}" for k in ("id","name","kind","abstraction","status") for d in ("asc","desc")})}


def _list_url(base: dict[str, str], **changes: Any) -> str:
    """Адрес списка с одним заменённым параметром: чипы-фильтры и постраничные ссылки."""
    search = query(base, **changes)
    return f"/cwe?{search}" if search else "/cwe"


def _matches(item: dict, text: str) -> bool:
    """Поиск по номеру, английскому и русскому названию: запрос целиком из номера («CWE-89», «89») сверяется как
    число, остальное – слова без учёта регистра («ISO 27001», «SHA1» ищутся в названиях)."""
    key = cwe_id(text)
    if key:
        return item["id"] == key
    needle = text.casefold()
    return needle in item["name"].casefold() or needle in (item["name_ru"] or "").casefold()


def list_context(request: Request) -> dict[str, Any]:
    """Список каталога: поиск по номеру и названиям, фильтр вида записи, постраничность, сведения о загрузке."""
    filters = _filters(request)
    with store_of(request).snapshot() as store:
        meta = store.status().get("cwe", {})
        items = store.cwe_list()
    counts = {"weakness": sum(i["kind"] == "weakness" for i in items),
              "category": sum(i["kind"] == "category" for i in items)}
    choices = {key: sorted({i.get(key, "") for i in items if i.get(key)}) for key in ("abstraction", "status")}
    for key in ("kind", "abstraction", "status"):
        if filters.get(key):
            items = [i for i in items if i.get(key) == filters[key]]
    if filters["q"]:
        items = [i for i in items if _matches(i, filters["q"])]
    sort = filters["sort"] or "id_asc"
    key, direction = sort.rsplit("_", 1)
    items = sorted(items, key=lambda i: int(i["id"].split("-")[-1]) if key == "id" else i.get(key, "").casefold(),
                   reverse=direction == "desc")
    filters["sort"] = sort
    w = worklists.table(items, filters, path="/cwe", default_size=PAGE_SIZE)
    return {"meta": meta, "loaded": bool(meta), "filters": filters, "kind_filters": KIND_FILTERS,
            "choices": choices, "counts": counts, "catalog_size": sum(counts.values()), "worklist": w,
            "prev_url": w["prev"], "next_url": w["next"], "page": w["page"], "pages": w["pages"],
            "total": w["total"], "rows": w["rows"], "terms_url": TERMS_URL}


def detail_context(request: Request, number: str) -> dict[str, Any]:
    """Карточка класса: полная запись, связи, источники из справочника ссылок, сведения о версии каталога –
    одним снимком справочника, чтобы загрузка нового каталога не смешала версии на одной странице."""
    with store_of(request).snapshot() as store:
        return _detail(store, number)


def _detail(store: FeedStore, number: str) -> dict[str, Any]:
    if not store.status().get("cwe"):
        raise HTTPException(status_code=404, detail=i18n._(CWE_NOT_LOADED))
    page = store.cwe_page(number)
    if page is None:
        raise HTTPException(status_code=404, detail=i18n._(CWE_NO_SUCH))
    record = dict(page["record"])
    record['attack_patterns'] = sorted(store.capec_for_cwes([record['id']]), key=lambda x:int(x.split('-')[1]))
    # запись прежней версии приложения хранит расширенное описание строкой, полная – списком абзацев;
    # карточка показывает в обоих случаях список
    extended = record.get("extended")
    if isinstance(extended, str):
        record["extended"] = [extended] if extended.strip() else []
    refs = store.cwe_refs([r["ref_id"] for r in record.get("references", [])])
    # ссылки из блоков примеров – из того же справочника ссылок, без повторов
    example_ids = [r["ref_id"] for ex in record.get("examples", []) for r in ex.get("refs", [])]
    refs.update(store.cwe_refs([i for i in example_ids if i not in refs]))
    record["references"] = [{**r, "source": refs.get(r["ref_id"], {})} for r in record.get("references", [])]
    for ex in record.get("examples", []):
        for ref in ex.get("refs", []):
            ref["source"] = refs.get(ref["ref_id"], {})
    # наблюдаемые примеры: страница БДУ по CVE есть только там, где выгрузка БДУ содержит такую запись
    observed = record.get("observed", [])
    return {"record": record, "links": page["links"], "name_ru": page["name_ru"],
            "bdu": store.bdu_by_cve([o.get("reference", "") for o in observed]),
            "meta": store.status().get("cwe", {}), "terms_url": TERMS_URL,
            # запись прежней версии приложения: новых полей в ней нет, страница показывает то, что есть
            "old": not record.get("full")}


def bdu_context(request: Request, cve: str) -> dict[str, Any]:
    """Записи БДУ по CVE: то, что выгрузка содержит по этому идентификатору."""
    key = str(cve or "").strip().upper()[:40]
    if not _CVE.fullmatch(key):
        raise HTTPException(status_code=404, detail=i18n._("Это не номер уязвимости CVE."))
    with store_of(request).snapshot() as store:
        meta = store.status().get("bdu")
        found = store.bdu_by_cve([key]).get(key, []) if meta else []
    if not meta:
        raise HTTPException(status_code=404, detail=i18n._(BDU_NOT_LOADED))
    if not found:
        raise HTTPException(status_code=404, detail=i18n._("В выгрузке БДУ нет записей по {cve}.", cve=key))
    return {"cve": key, "records": found, "meta": meta}


@router.get("/cwe", response_class=HTMLResponse)
def cwe_page(request: Request):
    return render(request, "cwe/index.html", list_context(request))


@router.get("/cwe/{cwe_id}", response_class=HTMLResponse)
def cwe_detail(request: Request, cwe_id: str):
    """Карточка класса: номер принимается как «CWE-89» и как «89»."""
    try:
        context = detail_context(request, cwe_id)
    except HTTPException as exc:
        if exc.status_code != 404:
            raise
        from app.feeds import cwe_id as normalize
        return missing_reference(request, "cwe", cwe_id, normalize(cwe_id), exc.detail,
                                 store_of(request).status().get("cwe"))
    return render(request, "cwe/detail.html", context)


@router.get("/bdu/{cve}", response_class=HTMLResponse)
def bdu_page(request: Request, cve: str):
    """Запись БДУ по CVE: на неё ссылаются наблюдаемые примеры каталога CWE."""
    return render(request, "cwe/bdu.html", bdu_context(request, cve))
