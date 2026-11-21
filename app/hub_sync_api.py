"""Адаптер замеров Hub; полнота списков проверяется в каждом обходе."""

from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from urllib.parse import urlencode

from app.hub_sync_contract import SYNC_PROTOCOL

DETAIL_PATHS = {"SAST": "sast", "SCA_S": "sca/security", "SCA_L": "sca/compliance", "DAST": "dast"}


@dataclass(frozen=True)
class Adapter:
    version: str = "hub-sync/1"
    issue_sort: int | None = None
    first_page: int | None = None
    serialization: str | None = None
    all_branches: bool = False
    manual_absent: tuple[int, str] | None = None
    risk_absent: tuple[int, str] | None = None
    manual_scope: bool = False
    evidence: str = ""
    issue_size: int = 100
    defect_size: int = 50
    manual_empty: bool = False

    def passport(self):
        return asdict(self)

    def absent_response(self, part, result):
        """Только измеренные формы отсутствия, отдельно для каждого вида ответа."""
        text = result.get("body_text")
        if not isinstance(text, str):
            return False
        if part == "manual" and self.manual_empty and result.get("status") == 200 and not text.strip():
            return True
        absent = self.manual_absent if part == "manual" else self.risk_absent if part == "risk" else None
        return bool(absent and result.get("status") == absent[0]
                    and (text == absent[1] or (absent[1] == "null" and text.strip() == "null")))

    def require(self):
        if (type(self.issue_sort) is not int or type(self.first_page) is not int
                or self.serialization != "flat" or not self.evidence
                or self.manual_absent is None):
            raise ValueError("Контракт полного чтения Hub ещё не подтверждён (ADR-0127 §12.1). "
                             "Параметры сортировки, веток и отсутствия решений требуют проверки.")


ADAPTER = Adapter(version="hub-sync/3-observed-2026-10-30", issue_sort=0, first_page=0,
                  serialization="flat", manual_absent=(200, "null"), defect_size=100,
                  manual_empty=True, manual_scope=True,
                  evidence="Пустой ручной статус; запись без условия относится ко всей находке")


def request(path, **params):
    return {"method": "GET", "path": path + ("?" + urlencode(params) if params else ""),
            "body": None, "sync_protocol": SYNC_PROTOCOL}


def page(adapter, kind, app_id, index, size=None):
    adapter.require()
    if kind == "issue":
        return request("/issue/v2", appIds=app_id, pageIndex=index, pageSize=size or adapter.issue_size,
                       sort=adapter.issue_sort, **({"ignoreBranchFilter": "true"} if adapter.all_branches else {}))
    return request("/defects", appId=app_id, pageIndex=index, pageSize=size or adapter.defect_size)


def application_id(obj, kind):
    actual = obj.get("appId")
    if kind == "defect":
        if actual is None and isinstance(obj.get("app"), dict):
            actual = obj["app"].get("id")
        elif isinstance(actual, dict):
            actual = actual.get("id")
        if isinstance(obj.get("app"), dict) and obj["app"].get("id") != actual:
            raise ValueError("app и appId объекта противоречат друг другу.")
    return actual


def detail(kind, key, branch=None):
    if kind == "defect":
        return request(f"/defects/{key}")
    issue_type, issue_id = key.split(":", 1)
    return request(f"/issue/{DETAIL_PATHS[issue_type]}/{issue_id}",
                   **({"branch": branch} if branch is not None and issue_type != "DAST" else {}))


def identifier(obj, app_id, kind):
    if not isinstance(obj, dict) or type(obj.get("id")) is not int or not 0 < obj["id"] < 10**12:
        raise ValueError("Объект без допустимого ID.")
    actual = application_id(obj, kind)
    if type(actual) is not int or actual != app_id:
        raise ValueError("Объект другого приложения или без appId.")
    if kind == "issue":
        if not isinstance(obj.get("type"), str) or not obj["type"]:
            raise ValueError("У находки не указан тип.")
        return f"{obj['type']}:{obj['id']}"
    return str(obj["id"])


class ShortPage(ValueError):
    def __init__(self, size):
        super().__init__(f"Hub урезал промежуточную страницу до {size}; нужен обход с новым шагом.")
        self.size = size


def read_page(body, app_id, kind, previous_total, seen, size):
    if not isinstance(body, dict) or not isinstance(body.get("filteredEntities"), list):
        raise ValueError("В странице нет массива filteredEntities.")
    total, objects = body.get("totalEntitiesCount"), body["filteredEntities"]
    if type(total) is not int or total < 0 or (previous_total is not None and total != previous_total):
        raise ValueError("Число объектов Hub изменилось или некорректно. Полнота обхода не установлена.")
    keys = [identifier(obj, app_id, kind) for obj in objects]
    if len(set(keys)) != len(keys):
        raise ValueError("Повтор ключа внутри страницы.")
    if len(seen) + len(objects) > total or len(objects) > size:
        raise ValueError("Размер страницы не соответствует заявленному числу объектов.")
    if len(seen) + len(objects) < total and len(objects) != size:
        if objects:
            raise ShortPage(len(objects))
        raise ValueError("Неполная промежуточная страница: продолжение по индексу не подтверждено.")
    if set(keys) & seen:
        raise ValueError("Повтор ключа между страницами.")
    return total, list(zip(keys, objects, strict=True))


def expired(value):
    if value is None or value == "":
        return False
    try:
        instant = (datetime.fromtimestamp(value / 1000, UTC) if type(value) is int
                   else datetime.fromisoformat(value.replace("Z", "+00:00")))
        return instant.tzinfo is None or instant <= datetime.now(UTC)
    except (TypeError, ValueError, AttributeError, OverflowError, OSError):
        return True


def composition_problems(detail):
    """Ни одна связь не теряется при преобразовании полного состава в множество."""
    if not isinstance(detail, dict) or not isinstance(detail.get("linkedIssues"), list):
        return ["В подробном дефекте отсутствует состав linkedIssues."]
    seen = set()
    for link in detail["linkedIssues"]:
        if (not isinstance(link, dict) or type(link.get("id")) is not int
                or not 0 < link["id"] < 10**12 or not isinstance(link.get("type"), str)
                or link["type"] not in DETAIL_PATHS):
            return ["Состав linkedIssues содержит связь без допустимого ID или типа."]
        pair = (link["id"], link["type"])
        if pair in seen:
            return ["Состав linkedIssues содержит повтор одной связи."]
        seen.add(pair)
    return []


# Пометки Hub (dev15, план п. 1.2): сведения прочитаны полностью, но расходятся между собой. Находка принимается по
# проекции решения Hub (`hub_sync_compare.issue_values`: статус – подробный, основание – только из своей согласованной
# записи), пометка показывается у находки и не является отличием. Остальные проблемы – неполное чтение: объект не
# принимается до нового чтения (после принятия расхождений быть не должно).
HUB_NOTES = (
    "Подробный статус и ручная запись противоречат друг другу.",
    "Ручная запись относится к другой находке.",
    "Применимость ручного решения к ветке или условию не установлена.",
    "Срок ручного решения истёк или некорректен.",
    "Основание ложного срабатывания отсутствует.",
    "Сведения о принятом риске отсутствуют.",
    "Риск не подтверждён как действующий для этой находки.",
)


# имена типа находки в записях Hub: в ручной записи (GET /issue/status) для SCA Hub пишет человеческое имя листа
# выгрузки, а не код типа из пути и списка: у ручных записей SCA
# «SCA Security» при ключе находки SCA_S, у SAST – «SAST». К записи риска (GET /issue/{type}/{id}/riskAcceptance)
# применяется та же точная таблица; её фактическая форма не наблюдалась.
# Сопоставление – только по этой таблице, без угадывания
ISSUE_TYPE_NAMES = {"SCA Security": "SCA_S", "SCA Compliance": "SCA_L"}


def same_issue_type(value, issue_type) -> bool:
    """Тип в записи Hub – тот же, что у находки: код типа (SAST, SCA_S, SCA_L, DAST) или его имя в записях Hub."""
    text = str(value or "")
    return text == issue_type or ISSUE_TYPE_NAMES.get(text) == issue_type


def risk_valid(risk, key, app_id) -> bool:
    """Запись риска действует для этой находки этого приложения: ID и тип, приложение, активна, не удалена, без
    условия, срок не истёк. Одна проверка для диагностики и для проекции решения Hub (ревью dev15, Codex круг 3)."""
    if not isinstance(risk, dict) or not key or app_id is None:
        return False
    issue_type, issue_id = key.split(":", 1)
    return (str(risk.get("issueId")) == str(issue_id) and same_issue_type(risk.get("issueType"), issue_type)
            and risk.get("appId") == app_id and risk.get("isActive") is True and not risk.get("deleteTs")
            and risk.get("isConditional") is False and not expired(risk.get("expiredAt")))


def blocking(problems):
    """Проблемы неполного чтения – всё, кроме пометок Hub."""
    return [p for p in problems if p not in HUB_NOTES]


def evidence_problems(hub, key, app_id, adapter):
    """Отдельные свидетельства не превращаются в составное решение без проверки."""
    problems = []
    issue_type, issue_id = key.split(":", 1)
    brief, details = hub.get("brief", {}), hub.get("detail") or {}
    manual, risk = hub.get("manual"), hub.get("risk")
    if not isinstance(details, dict) or not isinstance(details.get("status"), str):
        return ["Текущий подробный статус не получен."]
    if brief.get("currentBranch") is not None and brief["currentBranch"] != details.get("currentBranch"):
        problems.append("Ветка основного подробного ответа не совпала с currentBranch списка.")
    if manual is not None:
        if not isinstance(manual, dict):
            return ["Ручная запись имеет неверный формат."]
        if manual.get("issueId") != int(issue_id) or not same_issue_type(manual.get("issueType"), issue_type):
            problems.append("Ручная запись относится к другой находке.")
        if manual.get("status") != details["status"]:
            problems.append("Подробный статус и ручная запись противоречат друг другу.")
        if brief.get("issueChangeStatusInfoId") is not None and brief["issueChangeStatusInfoId"] != manual.get("id"):
            problems.append("ID ручной записи изменился после чтения списка.")
        if not adapter.manual_scope or any(manual.get(k) is not None for k in ("conditionalCategory", "branch", "isConditional")):
            problems.append("Применимость ручного решения к ветке или условию не установлена.")
        if expired(manual.get("expiredAt")):
            problems.append("Срок ручного решения истёк или некорректен.")
    elif details["status"] == "False Positive":
        # ручная запись читается после подробностей всегда (hub_sync.consume_object): нет ключа – её чтение не
        # завершилось (неполное чтение), null – Hub подтвердил, что записи нет (пометка Hub, ревью плана dev15)
        problems.append("Основание ложного срабатывания отсутствует." if "manual" in hub
                        else "Ручная запись находки не прочитана.")
    if any(isinstance(obj, dict) and obj.get("status") == "Accepted risk"
           for name, obj in hub.items() if name in ("detail", "manual") or name.startswith("branch:")):
        # как у ручной записи: ключа нет – не прочитано, null – Hub подтвердил отсутствие (пометка), иное – неверный
        # формат (ревью dev15: мусорный ответ не должен проходить пометкой)
        if "risk" not in hub:
            problems.append("Сведения о принятом риске не прочитаны.")
        elif risk is None:
            problems.append("Сведения о принятом риске отсутствуют.")
        elif not isinstance(risk, dict):
            problems.append("Запись риска имеет неверный формат.")
        elif not risk_valid(risk, key, app_id):
            problems.append("Риск не подтверждён как действующий для этой находки.")
    # Дополнительные ветки сохраняются отдельно; их статус не подменяет выбранную ветку.
    return problems
