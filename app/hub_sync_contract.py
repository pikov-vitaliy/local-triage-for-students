"""Контракт чтений синхронизации; автономная копия поставляется с исполнителем."""

import re
import urllib.parse

# BEGIN SYNC CONTRACT
SYNC_PROTOCOL = 2
SYNC_PATHS = (
    ("GET", "/issue/v2", frozenset({"appIds", "pageIndex", "pageSize", "sort", "ignoreBranchFilter"})),
    ("GET", "/issue/sast/{id}", frozenset({"branch"})),
    ("GET", "/issue/sca/security/{id}", frozenset({"branch"})),
    ("GET", "/issue/sca/compliance/{id}", frozenset({"branch"})),
    ("GET", "/issue/dast/{id}", frozenset()),
    ("GET", "/issue/status", frozenset({"issueId", "issueType"})),
    ("GET", "/issue/{type}/{id}/riskAcceptance", frozenset()),
    ("GET", "/issue/{type}/{id}/comment", frozenset()),
    ("GET", "/defects", frozenset({"appId", "pageIndex", "pageSize", "sort"})),
    ("GET", "/defects/{id}", frozenset()),
)


def sync_query_value(key, value):
    if key == "branch":
        return 0 < len(value) <= 1000 and all(ord(ch) >= 32 and ord(ch) != 127 for ch in value)
    if key == "ignoreBranchFilter":
        return value == "true"
    if key == "issueType":
        return value in ("SAST", "SCA_S", "SCA_L", "DAST")
    return bool(re.fullmatch(r"[0-9]{1,12}", value))


def validate_sync(request, app_id):
    if request.get("method") != "GET" or request.get("body") is not None:
        raise ValueError("sync_read: разрешён только GET без тела.")
    if request.get("sync_protocol") != SYNC_PROTOCOL:
        raise ValueError("sync_read: несовместимый протокол исполнителя.")
    if type(app_id) is not int or app_id <= 0:
        raise ValueError("sync_read: отсутствует приложение операции.")
    base, _, query = request.get("path", "").partition("?")
    pairs = urllib.parse.parse_qsl(query, keep_blank_values=True, strict_parsing=bool(query))
    values = dict(pairs)
    if len(pairs) != len(values) or any(not sync_query_value(k, v) for k, v in pairs):
        raise ValueError("sync_read: неверные параметры.")
    for _, template, params in SYNC_PATHS:
        pattern = re.escape(template).replace(r"\{id\}", r"[0-9]{1,12}").replace(
            r"\{type\}", r"(?:SAST|SCA_S|SCA_L|DAST)")
        if not re.fullmatch(pattern, base):
            continue
        if set(values) - params:
            break
        if base in ("/issue/v2", "/defects"):
            optional = {"ignoreBranchFilter"} if base == "/issue/v2" else {"sort"}
            if not params - optional <= set(values):
                break
            if int(values["appIds" if base == "/issue/v2" else "appId"]) != app_id:
                break
            if not 1 <= int(values["pageSize"]) <= 100 or (base == "/defects" and values.get("sort", "0") != "0"):
                break
        if base == "/issue/status" and set(values) != params:
            break
        return
    raise ValueError("sync_read: путь или область чтения не соответствует запуску.")


def validate_sync_purpose(purpose, request, app_id):
    if purpose == "sync_read":
        validate_sync(request, app_id)
        return
    base, _, query = request.get("path", "").partition("?")
    params = dict(urllib.parse.parse_qsl(query))
    if (base == "/issue/v2" or re.fullmatch(r"/issue/(dast|sca/compliance)/[0-9]+", base)
            or base.endswith("/riskAcceptance") or "branch" in params
            or (base == "/defects" and "sort" in params)):
        raise ValueError("Новый путь чтения разрешён только для sync_read.")
# END SYNC CONTRACT
