"""Исполнитель записи в AppSec.Hub для «Локального триажа» (ADR-0114).

Запускается там, где виден Hub: в виртуальной машине с VPN или на компьютере, где стоят Docker Desktop и VPN. При
запуске спрашивает пароль учётной записи Hub (ввод скрыт, пароль нигде не сохраняется), входит в Hub, затем
забирает у приложения задания (только исходящие соединения: долгий опрос) и выполняет каждое – один запрос к REST
Hub из белого списка, – возвращая приложению ответ Hub как есть. Сам ничего не решает: что и когда отправить,
решает приложение и оператор.

Настройки – файл hub_worker.conf рядом со скриптом (app_url, hub_url, login, key). Запуск: hub_worker.cmd или
`python hub_worker.py`. Остановка – Ctrl+C: исполнитель выходит из Hub.

Что исполнитель не делает: не повторяет запрос к Hub (повторяется только доставка ответа приложению), не выполняет
перенаправления (ключ и cookie не уйдут на чужой адрес), не пишет в журнал тела ответов, ключ, cookie и пароль.
Нужен Python 3.11 или новее; сторонние пакеты не нужны.
"""

from __future__ import annotations

import getpass
import http.client
import http.cookiejar
import json
import math
import os
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import warnings
from datetime import datetime

VERSION = "0.10.0.dev10"
REST = "/hub/rest"
HERE = os.path.dirname(os.path.abspath(__file__))
CONF = os.path.join(HERE, "hub_worker.conf")
KEY_HEADER = "X-Hub-Worker-Key"
HUB_TIMEOUT = 30  # запрос к Hub
POLL_WAIT = 25  # долгий опрос приложения (приложение держит не дольше 25 с)
APP_TIMEOUT = 40  # чтение ответа приложения: больше POLL_WAIT
RESULT_MAX = 1024 * 1024  # байт тела ответа Hub в результате (как в приложении)
PAYLOAD_MAX = RESULT_MAX + 32 * 1024  # байт JSON результата: приложение принимает до RESULT_MAX + 64 КБ
DELIVERY_GIVE_UP_S = 15 * 60  # сколько пытаться доставить результат приложению
PLACEHOLDER_KEY = "ВСТАВЬТЕ_КЛЮЧ_ИЗ_НАСТРОЕК"
HUB_SCHEMES = ("https",)  # Hub – только по https

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

# Белый список запросов к Hub – тот же, что в приложении (app/hub_ops.py, ALLOWED): (метод, образец пути, параметры).
# Задание вне списка не выполняется: приложению уходит ответ «не отправлено». PUT – только `PUT /defects/{id}`
# (согласованные поля существующего дефекта, ADR-0126 dev1b); DELETE и прочие PUT не выполняются.
_INT = r"[0-9]{1,12}"
_TYPE = r"(?:SAST|SCA_S|SCA_L|DAST)"
ALLOWED = (
    ("GET", "/auth/user", frozenset()),
    ("GET", "/defects/blank", frozenset({"appId", "issueIds", "type"})),
    ("GET", "/templates/defects/model", frozenset({"issueType", "issueId", "appId"})),
    ("POST", "/defects", frozenset()),
    ("GET", "/defects", frozenset({"appId", "pageIndex", "pageSize", "sort"})),
    ("GET", "/defects/{id}", frozenset()),
    ("POST", "/defects/{id}/link", frozenset()),
    ("POST", "/issue/status/update", frozenset()),
    ("POST", "/issue/status/change", frozenset()),
    ("GET", "/issue/status", frozenset({"issueId", "issueType"})),
    ("GET", "/issue/sast/{id}", frozenset({"branch"})),
    ("GET", "/issue/sca/security/{id}", frozenset({"branch"})),
    ("GET", "/issue/{type}/{id}/comment", frozenset()),
    ("GET", "/defects/serviceInfo", frozenset()),
    ("GET", "/application/{id}/structureUnits", frozenset()),
    ("GET", "/releaseObject/filters", frozenset({"appId"})),
    ("PUT", "/defects/{id}", frozenset()),
)
ALLOWED += tuple(entry for entry in SYNC_PATHS if entry not in ALLOWED)
METHODS = ("GET", "POST", "PUT")
_PATTERNS = tuple((m, re.compile("^" + re.escape(p).replace(r"\{id\}", _INT).replace(r"\{type\}", _TYPE) + "$"), q)
                  for m, p, q in ALLOWED)


class Refused(Exception):
    """Задание не выполняется (белый список, чужой адрес Hub); текст – по-русски."""


class Stop(Exception):
    """Работа прекращается (ключ неверен, настройки неверны); текст – по-русски."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Перенаправления не выполняются: ответ 3xx возвращается как есть."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def log(text: str) -> None:
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {text}", flush=True)


# ============================================================================ настройки


def read_conf(path: str = CONF) -> dict:
    """hub_worker.conf: строки «ключ = значение», пустые и начинающиеся с # пропускаются."""
    values: dict[str, str] = {}
    if not os.path.exists(path):
        raise Stop(f"Нет файла настроек {path}: скопируйте образец hub_worker.conf и заполните его.")
    with open(path, encoding="utf-8-sig") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            name, value = line.split("=", 1)
            values[name.strip().lower()] = value.strip().strip('"').strip("'")
    return values


def base_url(raw: str, schemes: tuple[str, ...], what: str) -> str:
    """Адрес «схема://узел[:порт]» без пути, параметров, # и имени пользователя."""
    text = str(raw or "").strip().rstrip("/")
    parts = urllib.parse.urlsplit(text)
    if (parts.scheme not in schemes or not parts.hostname or parts.path not in ("", "/") or parts.query
            or parts.fragment or "@" in text or "#" in text or any(ch.isspace() for ch in text)):
        raise Stop(f"{what}: нужен адрес вида {schemes[0]}://узел (без пути, параметров и #), получено «{text}».")
    return f"{parts.scheme}://{parts.netloc}"


def check_conf(values: dict) -> dict:
    key = values.get("key", "")
    if not key or key == PLACEHOLDER_KEY:
        raise Stop("В hub_worker.conf нет ключа: скопируйте его в «Настройках» приложения, раздел «AppSec.Hub».")
    if not re.fullmatch(r"[0-9a-f]{64}", key):
        raise Stop("Ключ в hub_worker.conf неверного вида: 64 шестнадцатеричных знака из «Настроек» приложения.")
    login = values.get("login", "")
    if not login or any(ch.isspace() for ch in login):
        raise Stop("В hub_worker.conf нет логина Hub (строка login).")
    worker_id = values.get("worker_id", "") or re.sub(r"[^A-Za-z0-9_.:-]", "-", socket.gethostname())[:60] or "worker"
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,80}", worker_id):
        raise Stop("worker_id в hub_worker.conf: латиница, цифры и - _ . :, до 80 знаков.")
    return {"app_url": base_url(values.get("app_url", ""), ("http", "https"), "app_url"),
            "hub_url": base_url(values.get("hub_url", ""), HUB_SCHEMES, "hub_url"),
            "login": login, "key": key, "worker_id": worker_id}


def hidden_input(prompt: str) -> str:
    """Скрытый ввод пароля; если скрыть нельзя – отказ (пароль не должен появиться на экране). getpass в таком окне
    только предупреждает и читает с эхом – предупреждение превращается в ошибку до чтения."""
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            return getpass.getpass(prompt)
    except getpass.GetPassWarning:
        raise Stop("Ввод нельзя скрыть в этом окне: запустите исполнителя из обычной командной строки (cmd).") from None


# ============================================================================ белый список

# Предел значения issueIds (`GET /defects/blank`) – тот же, что у приложения (app/hub_ops.py: ISSUE_IDS_MAX, _ISSUE_IDS):
# десятки находок одной библиотеки в одном дефекте; остальные параметры – до 200 знаков. Менять вместе с приложением.
ISSUE_IDS_MAX = 2000
_ISSUE_IDS = re.compile(r"[0-9]{1,12}(?:,[0-9]{1,12})*")
_PARAM_VALUE = re.compile(r"[A-Za-z0-9_,.-]{1,200}")


def _param_ok(name: str, value: str) -> bool:
    if name == "branch":
        return bool(sync_query_value(name, value))
    if name == "issueIds":
        return len(value) <= ISSUE_IDS_MAX and _ISSUE_IDS.fullmatch(value) is not None
    return _PARAM_VALUE.fullmatch(value) is not None


def check_job(job: dict, hub_url: str) -> None:
    """Задание должно быть для этого Hub и из белого списка; иначе Refused (запрос к Hub не делается)."""
    if base_url(job.get("hub_url", ""), HUB_SCHEMES, "hub_url задания") != hub_url:
        raise Refused("задание для другого адреса Hub")
    method = str(job.get("method") or "").upper()
    path = str(job.get("path") or "")
    if method not in METHODS:
        raise Refused(f"метод {method or '«»'} не разрешён")
    if not path.startswith("/") or "#" in path or "//" in path or ".." in path or any(ch.isspace() for ch in path):
        raise Refused("неверный путь")
    base, _, query = path.partition("?")
    try:
        pairs = urllib.parse.parse_qsl(query, keep_blank_values=True, strict_parsing=bool(query))
    except ValueError:
        raise Refused("неверные параметры") from None
    names = [k for k, _ in pairs]
    for allowed_method, pattern, params in _PATTERNS:
        if allowed_method == method and pattern.match(base):
            if set(names) - params or len(names) != len(set(names)):
                raise Refused(f"параметры {method} {base} не из белого списка")
            if not all(_param_ok(k, v) for k, v in pairs):
                raise Refused(f"значение параметра {method} {base}")
            if method == "GET" and job.get("body") is not None:
                raise Refused("тело у GET")
            try:
                validate_sync_purpose(job.get("purpose"), job, job.get("app_id"))
                validate_operation(job.get("purpose"), job, job.get("app_id"))
            except ValueError as exc:
                raise Refused(str(exc)) from exc
            return
    raise Refused(f"{method} {base} не входит в белый список")


# BEGIN DEFECT DTO
DEFECT_CONTRACT = "defect-fields-v1"
NAME_RANK = {"name": "string", "rank": "integer"}
ID_NAME = {"id": "string", "name": "string"}
BUG = {"product": "string", "displayName": "string", "link": "string"}
SETTINGS = {"isInheritedFPStatusFromDefect": "boolean", "isInheritedARStatusFromDefect": "boolean"}
ISSUE = {
    **dict.fromkeys(("id", "appId", "defectId", "lastScanTaskId", "lineNumber", "issueChangeStatusInfoId", "ruleId"), "integer"),
    **dict.fromkeys(("appName", "type", "source", "category", "severity", "cveId", "cveLink", "commitLink",
                    "taggedArtifactName", "aiProviderVersion", "tool", "state", "threatGroup", "approver", "branch",
                    "currentBranch"), "string"),
    "updateTs": "date-time", "lastScanTs": "date-time", "aiProviderStatus": ("0", "1"),
    "aiProviderAccuracy": "number", "cvss": "number", "isDeleted": "boolean",
    "application": {"id": "integer", "name": "string"},
    "cwes": [{"id": "string", "link": "string"}],
    "scanObject": {"id": "integer", "name": "string", "url": "string", "type": "string"},
    "statusChangeRequest": {"id": "integer", "requestedStatus": "string"},
}
DEFECT_SCHEMA = {
    **dict.fromkeys(("id", "appId", "priorityId", "severityId", "structureUnitId"), "integer"),
    **dict.fromkeys(("summary", "description", "appName", "status", "source", "tool", "stage", "type",
                    "syncStatus", "syncFailedCause"), "string"),
    **dict.fromkeys(("createTs", "updateTs", "lastSync", "dueDate"), "date-time"),
    **dict.fromkeys(("isActive", "withIssues", "linkedIssuesStatusAlert"), "boolean"),
    "priority": NAME_RANK, "severity": NAME_RANK, "appStructureUnit": ID_NAME, "releaseObject": ID_NAME,
    "externalBugs": [BUG], "settings": SETTINGS, "linkedIssues": [ISSUE],
    "author": {"id": "integer", "login": "string", "firstName": "string", "lastName": "string"},
}
REQUIRED_DEFECT = frozenset({"appId", "priority", "severity", "summary"})

# GET установленного Hub: времена в миллисекундах, severity связи числом.
# Эти свойства не редактируются: полный PUT сохраняет их исходное представление.
READ_ISSUE = {**ISSUE, "severity": "severity-code", "updateTs": "timestamp", "lastScanTs": "timestamp",
              "scanObject": {**ISSUE["scanObject"], "url": "nullable-string"}}
DEFECT_READ_SCHEMA = {**DEFECT_SCHEMA, "createTs": "timestamp", "updateTs": "timestamp",
                      "lastSync": "timestamp", "linkedIssues": [READ_ISSUE]}
DEFECT_WRITE_SCHEMA = {**DEFECT_READ_SCHEMA, "dueDate": "date-time"}


def is_int64(value):
    return type(value) is int and -(2 ** 63) <= value < 2 ** 63


def dto_type(value):
    return {dict: "object", list: "array", str: "string", bool: "boolean", int: "number", float: "number",
            type(None): "null"}.get(type(value), type(value).__name__)


def validate_value(value, schema, path=""):
    """Неизвестные расширения сохраняются; проверяются только объявленные свойства."""
    expected = "object" if isinstance(schema, dict) else "array" if isinstance(schema, list) else schema
    if schema == "nullable-string" and (value is None or type(value) is str):
        return
    if schema == "severity-code" and (is_int64(value) or type(value) is str):
        return
    if schema == "timestamp":
        if is_int64(value):
            return
        schema = "date-time"
    if isinstance(schema, dict) and type(value) is dict:
        for key, child in schema.items():
            if key in value:
                validate_value(value[key], child, path + "/" + key)
        return
    if isinstance(schema, list) and type(value) is list:
        for index, child in enumerate(value):
            validate_value(child, schema[0], f"{path}/{index}")
        return
    if isinstance(schema, tuple) and type(value) is str and value in schema:
        return
    if schema == "string" and type(value) is str:
        return
    if schema == "boolean" and type(value) is bool:
        return
    if schema == "integer" and is_int64(value):
        return
    if schema == "number" and type(value) in (int, float):
        try:
            if math.isfinite(value):
                return
        except OverflowError:
            pass
    if schema == "date-time" and type(value) is str:
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})", value):
            try:
                datetime.fromisoformat(value.upper().replace("Z", "+00:00"))
                return
            except ValueError:
                pass
    if schema == "date-time":
        expected = "string/date-time с часовым поясом"
    raise ValueError(f"{path or '/'}: требуется {expected}, получено {dto_type(value)}.")


def validate_read_defect(body, defect_id, app_id):
    validate_value(body, DEFECT_READ_SCHEMA)
    for key in sorted(REQUIRED_DEFECT | {"id"}):
        if key not in body:
            raise ValueError(f"/{key}: обязательное свойство отсутствует.")
    if not is_int64(app_id):
        raise ValueError("app_id: требуется независимый integer/int64 контекст операции.")
    if body["id"] != int(defect_id):
        raise ValueError("/id: не совпадает с идентификатором пути.")
    if body["appId"] != app_id:
        raise ValueError("/appId: не совпадает с приложением операции.")


def validate_defect(body, defect_id, app_id):
    """Полный PUT: редактируемые поля по контракту записи, прочие по наблюдаемому GET."""
    validate_read_defect(body, defect_id, app_id)
    validate_value(body, DEFECT_WRITE_SCHEMA)


def validate_operation(purpose, request, app_id):
    """Контекстная часть после проверки белого списка; старые текстовые PUT сохраняют контракт."""
    method, path = request.get("method"), request.get("path", "")
    base, _, query = path.partition("?")
    structure = re.fullmatch(r"/application/([0-9]+)/structureUnits", base)
    reference_path = base == "/releaseObject/filters" or structure is not None
    if reference_path and purpose != "defect_reference":
        raise ValueError("Справочный путь разрешён только для defect_reference.")
    if purpose == "defect_reference":
        if method != "GET" or request.get("body") is not None:
            raise ValueError("defect_reference: разрешён только GET без тела.")
        if not is_int64(app_id):
            raise ValueError("defect_reference: app_id должен иметь тип integer/int64.")
        if base == "/defects/serviceInfo" and not query:
            return
        if structure and not query and int(structure[1]) == app_id:
            return
        match = re.fullmatch(r"appId=([0-9]+)", query)
        if base == "/releaseObject/filters" and match and int(match[1]) == app_id:
            return
        raise ValueError("defect_reference: путь, параметры или приложение не совпадают с загрузкой.")
    if "contract_version" in request:
        if request["contract_version"] != DEFECT_CONTRACT or purpose != "defect_update" or method != "PUT":
            raise ValueError("Неизвестный контракт обновления дефекта.")
        match = re.fullmatch(r"/defects/([0-9]+)", path)
        if not match:
            raise ValueError("Неверный путь PUT дефекта.")
        validate_defect(request.get("body"), match[1], app_id)
# END DEFECT DTO


# ============================================================================ Hub


class Hub:
    """Сессия Hub: вход по логину и паролю (cookie JSESSIONID в памяти), запросы REST, выход."""

    def __init__(self, hub_url: str, context: ssl.SSLContext | None = None):
        self.base = hub_url + REST
        self.jar = http.cookiejar.CookieJar()
        handlers: list = [NoRedirect(), urllib.request.HTTPCookieProcessor(self.jar)]
        handlers.append(urllib.request.HTTPSHandler(context=context or ssl.create_default_context()))
        self.opener = urllib.request.build_opener(*handlers)

    def login(self, login: str, password: str) -> int:
        """POST /auth/login, логин и пароль в теле (в адрес не попадают). Возвращает код ответа."""
        data = urllib.parse.urlencode({"username": login, "password": password}).encode("utf-8")
        status, _, _, _, error, _ = self.request("POST", "/auth/login", raw=data,
                                                 content_type="application/x-www-form-urlencoded")
        if status == 0:
            raise Stop(f"Hub недоступен: {error}")
        return status

    def logout(self) -> int:
        if not len(self.jar):
            return 0
        status = self.request("POST", "/auth/logout", raw=b"")[0]
        self.jar.clear()
        return status

    def request(self, method: str, path: str, body=None, raw: bytes | None = None,
                content_type: str = "application/json") -> tuple[int, dict, bytes, bool, str, bool]:
        """Один запрос к Hub -> (код, заголовки, тело до RESULT_MAX, усечено ли, ошибка, отправлен ли).
        Код 0 – ответа нет. «Не отправлен» – только когда соединение не установилось (not_sent_reason): тогда в Hub
        ничего не ушло; любой другой сбой – запрос мог дойти, исход неизвестен."""
        data = raw if raw is not None else (json.dumps(body, ensure_ascii=False).encode("utf-8")
                                            if body is not None else None)
        headers = {"Accept": "application/json", "User-Agent": f"local-triage-hub-worker/{VERSION}"}
        if data is not None:
            headers["Content-Type"] = content_type
        req = urllib.request.Request(self.base + path, data=data, method=method, headers=headers)
        try:
            with self.opener.open(req, timeout=HUB_TIMEOUT) as resp:
                return (*self._read(resp.status, resp), True)
        except urllib.error.HTTPError as e:
            return (*self._read(e.code, e), True)
        except urllib.error.URLError as e:
            return 0, {}, b"", False, f"{type(e).__name__}: {e.reason}", not not_sent_reason(e.reason)
        except (http.client.HTTPException, OSError, ValueError) as e:
            return 0, {}, b"", False, f"{type(e).__name__}: {e}", True

    @staticmethod
    def _read(status: int, resp) -> tuple[int, dict, bytes, bool, str]:
        """Тело ответа до RESULT_MAX + 1 байт. Тело короче заявленного Content-Length или оборванное чтение –
        ошибка: такой ответ не считается полным (у записи это «результат неизвестен»)."""
        headers = {k.lower(): v for k, v in resp.headers.items() if k.lower() in ("location", "content-type")}
        try:
            data = resp.read(RESULT_MAX + 1)
        except (OSError, http.client.HTTPException, ValueError) as e:
            return status, headers, b"", False, f"ответ Hub прочитан не полностью: {type(e).__name__}"
        declared = str(resp.headers.get("Content-Length") or "").strip()
        if declared.isdigit() and len(data) < min(int(declared), RESULT_MAX + 1):
            return status, headers, data[:RESULT_MAX], False, (f"ответ Hub прочитан не полностью: {len(data)} из "
                                                               f"{declared} байт")
        return status, headers, data[:RESULT_MAX], len(data) > RESULT_MAX, ""


def not_sent_reason(reason) -> bool:
    """Соединение с Hub не установилось – запрос точно не ушёл: имя не разрешилось, соединение отклонено, сертификат
    Hub не прошёл проверку (до отправки данных). Решается по типу причины, а не по тексту ошибки."""
    return isinstance(reason, (socket.gaierror, ConnectionRefusedError, ssl.SSLCertVerificationError))


# ============================================================================ приложение


class App:
    """Связь с приложением: ключ в заголовке, Origin – адрес приложения (защита POST приложения его требует)."""

    def __init__(self, app_url: str, key: str, worker_id: str):
        self.base = app_url
        self.key = key
        self.worker_id = worker_id
        self.opener = urllib.request.build_opener(NoRedirect())

    def call(self, method: str, path: str, payload: dict | None = None, timeout: float = APP_TIMEOUT) -> tuple[int, dict]:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8") if payload is not None else None
        headers = {"Accept": "application/json", KEY_HEADER: self.key, "Origin": self.base,
                   "User-Agent": f"local-triage-hub-worker/{VERSION}"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(self.base + path, data=data, method=method, headers=headers)
        try:
            with self.opener.open(req, timeout=timeout) as resp:
                return resp.status, json.loads(resp.read(1024 * 1024).decode("utf-8") or "{}")
        except urllib.error.HTTPError as e:
            try:  # тело ошибки бывает оборвано (IncompleteRead) – код ответа важнее
                answer = json.loads(e.read(64 * 1024).decode("utf-8") or "{}")
            except (ValueError, OSError, http.client.HTTPException):
                answer = {}
            return e.code, answer if isinstance(answer, dict) else {}
        except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError) as e:
            return 0, {"detail": f"{type(e).__name__}: {getattr(e, 'reason', e)}"}

    def hello(self, hub_url: str, user: dict) -> tuple[int, dict]:
        return self.call("POST", "/api/hub/worker/hello", {
            "worker_id": self.worker_id, "hub_url": hub_url, "version": VERSION,
            "hub_user": " ".join(str(user.get(k) or "") for k in ("firstName", "lastName")).strip(),
            "hub_login": str(user.get("name") or ""), "roles": list(user.get("roles") or [])})

    def next_job(self, hub_url: str, wait: int = POLL_WAIT) -> tuple[int, dict]:
        query = urllib.parse.urlencode({"worker_id": self.worker_id, "hub_url": hub_url, "wait": wait, "sync_protocol": SYNC_PROTOCOL})
        return self.call("GET", f"/api/hub/jobs?{query}")

    def deliver(self, attempt_id: int, payload: dict, sleep=time.sleep, monotonic=time.monotonic) -> str:
        """Доставка результата: повторяется при недоступности приложения (запрос к Hub при этом не повторяется).
        Возвращает итог приложения (accepted, duplicate, late, rejected) или given_up."""
        deadline = monotonic() + DELIVERY_GIVE_UP_S
        pause = 2.0
        while True:
            status, answer = self.call("POST", f"/api/hub/jobs/{int(attempt_id)}/result",
                                       {**payload, "worker_id": self.worker_id})
            if status == 200:
                return str(answer.get("outcome") or "accepted")
            if status == 409:
                return "rejected"
            if status == 403:
                raise Stop("Приложение не принимает ключ: его выпустили заново? Впишите новый ключ в hub_worker.conf.")
            if monotonic() >= deadline:
                return "given_up"
            log(f"результат не доставлен ({status or answer.get('detail', 'нет связи')}), повтор через {pause:.0f} с")
            sleep(pause)
            pause = min(pause * 2, 60.0)


# ============================================================================ работа


def result_payload(job: dict, status: int, headers: dict, body: bytes, truncated: bool, error: str,
                   took_ms: int, not_sent: bool = False) -> dict:
    """Результат для приложения; тело – текст UTF-8, весь JSON не длиннее PAYLOAD_MAX (иначе тело усекается)."""
    text = body.decode("utf-8", "replace")
    payload = {"lease_token": job["lease_token"], "status": status, "headers": headers, "body_text": text,
               "truncated": truncated, "error": error, "took_ms": took_ms, "not_sent": not_sent}
    while len(json.dumps(payload, ensure_ascii=False).encode("utf-8")) > PAYLOAD_MAX and payload["body_text"]:
        cut = len(payload["body_text"]) * 3 // 4
        payload["body_text"] = payload["body_text"][:cut]
        payload["truncated"] = True
    return payload


def run_job(hub: Hub, app: App, job: dict, hub_url: str, sleep=time.sleep) -> tuple[str, int]:
    """Одно задание: проверка, запрос к Hub (один раз), доставка ответа. Возвращает (итог доставки, код Hub)."""
    started = time.monotonic()
    try:
        check_job(job, hub_url)
    except (Refused, Stop) as e:
        log(f"задание {job.get('op_id')}: отклонено исполнителем – {e}")
        payload = result_payload(job, 0, {}, b"", False, f"задание отклонено исполнителем: {e}", 0, not_sent=True)
        return app.deliver(job["attempt_id"], payload, sleep=sleep), 0
    method, path = job["method"].upper(), job["path"]
    status, headers, body, truncated, error, sent = hub.request(method, path, job.get("body"))
    took = int((time.monotonic() - started) * 1000)
    log(f"задание {job.get('op_id')}: {method} {path.partition('?')[0]} -> {status or 'нет ответа'} ({took} мс)"
        + (" – не отправлено" if not sent else ""))
    payload = result_payload(job, status, headers, body, truncated, error, took, not_sent=not sent)
    return app.deliver(job["attempt_id"], payload, sleep=sleep), status


def sign_in(hub: Hub, login: str, ask_password) -> dict:
    """Вход в Hub (пароль спрашивается и сразу забывается) и проверка: GET /auth/user."""
    for attempt in range(3):
        password = ask_password(f"Пароль Hub для {login} (ввод скрыт): ")
        status = hub.login(login, password)
        del password
        if status == 200:
            code, _, body, _, error, _ = hub.request("GET", "/auth/user")
            user = json.loads(body.decode("utf-8") or "{}") if code == 200 else {}
            if code == 200 and isinstance(user, dict) and user.get("name"):
                return user
            raise Stop(f"Вход принят, но Hub не вернул пользователя (код {code or error}).")
        log(f"вход не принят (код {status}); попытка {attempt + 1} из 3")
    raise Stop("Вход в Hub не удался: проверьте логин в hub_worker.conf и пароль.")


def work(conf: dict, ask_password=hidden_input, sleep=time.sleep, max_jobs: int | None = None,
         hub: Hub | None = None) -> int:
    """Основной цикл: вход, приветствие, задания до Ctrl+C (или до max_jobs – для проверок)."""
    hub = hub or Hub(conf["hub_url"])
    app = App(conf["app_url"], conf["key"], conf["worker_id"])
    done = 0
    try:
        user = sign_in(hub, conf["login"], ask_password)
        log(f"вошли в Hub как {user.get('firstName', '')} {user.get('lastName', '')} ({user.get('name')})")
        status, answer = app.hello(conf["hub_url"], user)
        if status == 403:
            raise Stop("Приложение не принимает ключ: скопируйте его заново в «Настройках», раздел «AppSec.Hub».")
        if status != 200:
            raise Stop(f"Приложение недоступно по адресу {conf['app_url']}: {answer.get('detail') or status}.")
        log(f"на связи с приложением {conf['app_url']}; жду заданий (Ctrl+C – остановить)")
        while max_jobs is None or done < max_jobs:
            status, answer = app.next_job(conf["hub_url"])
            if status == 403:
                raise Stop("Приложение перестало принимать ключ: его выпустили заново? Впишите новый в hub_worker.conf.")
            if status != 200:
                log(f"приложение не ответило ({status or answer.get('detail', 'нет связи')}), повтор через 5 с")
                sleep(5)
                continue
            job = answer.get("job")
            if not job:
                continue
            outcome, hub_status = run_job(hub, app, job, conf["hub_url"], sleep=sleep)
            done += 1
            if outcome not in ("accepted", "duplicate"):
                log(f"задание {job.get('op_id')}: приложение ответило «{outcome}»")
            if hub_status == 401:
                raise Stop("Сессия Hub истекла. Для нового входа запустите исполнителя явно.")
        return 0
    finally:
        code = hub.logout()
        if code:
            log("выход из Hub выполнен" if 200 <= code < 300 else f"выход из Hub: код {code}")


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")  # type: ignore[attr-defined]
    try:
        conf = check_conf(read_conf())
        return work(conf)
    except Stop as e:
        log(str(e))
        return 2
    except KeyboardInterrupt:
        log("остановлено")
        return 0


if __name__ == "__main__":
    sys.exit(main())
