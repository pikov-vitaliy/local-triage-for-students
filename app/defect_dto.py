"""Типы полного DefectDto по контракту dev1b ADR-0126. Только стандартная библиотека."""

import math
import re
from datetime import datetime

# Этот блок поставляется также внутри автономного исполнителя; равенство проверяет тест.
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
