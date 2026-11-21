"""Дефект в Hub из карточки находки (этап 3, ADR-0120).

Чистые правила: запросы цепочки (заготовка → создание → чтение → привязка → чтение), тело дефекта из заготовки Hub и
текста команды (HTML без стилей и скриптов), разбор ответов (номер дефекта, привязанные находки), сверка «результата
неизвестен» по списку дефектов приложения – и последствия ответов исполнителя: переходы строки `hub_defects`, отметка
«Внесено в Hub» (часть «тело дефекта») находкам дефекта с совпавшей редакцией, номер ID<n> за находками. Постановку в
очередь и страницы делают маршруты (app/routes/hub_defect_routes.py); хранение – app/db.py (hub_defects, схема 26).

Успешный POST ничего не завершает: дефект считается созданным только после чтения `GET /defects/{id}`, в котором
привязаны все находки-цели. POST к Hub никогда не повторяется сам; «результат неизвестен» закрывается только сверкой
чтением. Формы DTO – docs/hub-format.md и docs/hub-write-plan.md (раздел 1); поля, которых в спецификации нет,
помечены «уточнить».

С 0.9.23 (ADR-0121): находка, привязанная к дефекту (Database.hub_defect_bound – POST мог дойти до Hub), меняет
решение, статус и отметку «Внесено в Hub» только с подтверждением (DefectBound, bound_text, refuse_bound, save_check);
новая находка группы привязывается к готовому дефекту (строка «привязываю», маршрут – hub_defect_routes); «Проверить
в Hub» (start_recheck, _on_recheck) – только сверка: ответ 404 и состав linkedIssues (находки со статусом Open) дают
пояснение в строке; снятие привязки находок удалённого в Hub дефекта – следующая сборка (бэклог 39).

С 0.9.23.dev3 (ADR-0124): «Занести из Hub» и «Pull из Hub» – существующий дефект Hub в базе приложения, только
чтением `GET /defects/{id}` (import_item, _on_import, _on_import_sync): ни POST, ни отметок «Внесено в Hub», ни номеров
ключам находок ни в одном пути; номер ID<n> из заголовка – только резерв hub_defects.number.

С 0.9.23.dev4 (ADR-0125): «Push в Hub» – заголовок и описание занесённого дефекта по текущим решениям, запросом
`PUT /defects/{id}` (тело – объект второго чтения с новыми summary и description, блок Hub – исходная подстрока):
чтение → предпросмотр → второе чтение → PUT → подтверждающее чтение, «Сверить» при неизвестном исходе (start_update,
_on_update); отметки и номера ключам – только по подтверждённому обновлению.

С 0.9.24.dev1 (ADR-0126): одиночные app/import обновляются из сохранённого черновика владельца. Подтверждение
сохраняет полный объект и отдельные отпечатки содержимого и решения до отметок и номеров. Неполный разбор текста
не подтверждает создание, привязку или обновление; повторяется только чтение.
"""

from __future__ import annotations

import html
import json
import re
from difflib import ndiff, unified_diff
from datetime import UTC, datetime
from html.parser import HTMLParser
from typing import Any, Callable, Iterable

from app import defect_drafts, defect_where, hub_block_builder, hub_block_version, hub_ops, hub_status, hub_template_model
from app.db import Database, dumps, hub_verdict, loads, text_hash


class DefectRefused(hub_status.StatusRefused):
    """Подготовка или создание дефекта отклонены до постановки запроса."""


STATES = ("blank", "preview", "creating", "created", "linking", "done", "mismatch", "unknown", "failed", "cancelled",
          "import_reading", "import_preview", "unconfirmed")
# ждём исполнителя: карточка и вкладка опрашивают состояние (чтение дефекта для занесения из Hub – тоже, ADR-0124)
OPEN_STATES = ("blank", "creating", "created", "linking", "import_reading")
RESTORED_NOTE = "База восстановлена из копии, дефект снят: что успело уйти в Hub, занесёт «Синхронизировать» и «Принять состояние Hub»."
RESTORED_PUT_NOTE = "база восстановлена из копии, подготовка снята: что успело уйти в Hub, занесут «Синхронизировать» и «Принять состояние Hub»"
UPDATE_SETTLED = (None, "", "done", "done_diff", "cancelled", "refused", "read_failed")  # такие попытки синхронизации не мешают (hub_sync_compare)
# находка занята этим дефектом; чтение и предпросмотр занесения из Hub целей не держат (ADR-0124 п. 2)
BUSY_STATES = ("blank", "creating", "created", "linking", "preview", "unknown", "unconfirmed", "mismatch", "done")
BOUND_STATES = Database.HUB_DEFECT_BOUND  # находка привязана к дефекту: POST мог дойти до Hub (ADR-0121 п. 1)
STATE_LABELS = {"blank": "заготовка запрошена", "preview": "предпросмотр", "creating": "создаётся",
                "created": "проверка привязки", "linking": "привязка находок", "done": "создан",
                "mismatch": "создан, привязка неполная", "unknown": "результат неизвестен", "failed": "не принят",
                "cancelled": "отменён", "import_reading": "чтение из Hub", "import_preview": "предпросмотр занесения",
                "unconfirmed": "содержимое не подтверждено"}
SERVICE_INFO_PATH = "/defects/serviceInfo"
PAGE_SIZE = 50  # страница списка дефектов при сверке
PAGES_MAX = 20  # дальше сверка не листает: исход остаётся неизвестным, решает оператор
ISSUE_IDS_MAX = hub_ops.ISSUE_IDS_MAX  # предел значения параметра issueIds – один с белым списком запросов (hub_ops)
VERIFY_NOTE_DONE = "сверено чтением: дефект найден в Hub, находки привязаны"
VERIFY_NOTE_NONE = "сверка: в Hub нет дефекта с таким заголовком и находками – исход неизвестен, решает оператор"
VERIFY_NOTE_FAILED = "сверка не удалась: чтение из Hub не выполнено – сверьте ещё раз"
# «Проверить в Hub» у созданного дефекта (ADR-0121 п. 6)
RECHECK_OK = "проверено в Hub: дефект на месте, находки привязаны"
RECHECK_FAILED = "проверка в Hub не удалась ({reason}) – нажмите «Проверить в Hub» ещё раз"
RECHECK_MISSING = "в составе дефекта в Hub нет находок {ids}: они отвязаны или их статус уже не Open – проверьте в Hub"
RECHECK_NO_LIST = "проверка не выполнена: ответ Hub без состава дефекта"
RECHECK_404 = ("дефект в Hub не найден (404) – возможно, удалён; находки остаются привязанными, снятие привязки – в "
               "следующей сборке")
# строка привязки новой находки к готовому дефекту: чтение после привязки (или «Сверить») не нашло находку
LINK_NOT_DONE = "привязка не состоялась: в составе дефекта №{defect} в Hub нет находок {ids}"
# вопросы подтверждения для находки, привязанной к дефекту (ADR-0121 п. 2–4)
SAVE_QUESTION = "Сохранить решение?"
IN_DEFECT_STATUS = ("статус и комментарий в Hub у неё идут через дефект, отдельно не отправляются. Чтобы отметить ложное "
                    "срабатывание или принятый риск, сначала отвяжите её от дефекта в Hub, затем {how}.")
IN_DEFECT_HOW_IMPORT = "примените «Pull из Hub» у дефекта"
IN_DEFECT_HOW_APP = "на вкладке «Дефекты» нажмите «Синхронизировать», затем «Принять состояние Hub»"
UNENTER_QUESTION = "Снять отметку «Внесено в Hub»?"
# адрес дефекта в интерфейсе Hub (страница приложения – «…/#/appprofile/<номер>/…»); точный путь страницы дефекта
# уточнить проверкой в Hub
HUB_DEFECT_PATH = "/#/appprofile/{app_id}/defects/{defect_id}"
_ITEM = re.compile(r"^\s*([0-9]{1,2})\)\s*(.+)$")
_TAG = re.compile(r"<[^>]+>")
_DIGITS = re.compile(r"[0-9]{1,12}")


# ============================================================================ запросы цепочки


def blank_request(app_id: int, targets: list[dict], issue_type: str) -> dict:
    """`GET /defects/blank?appId&issueIds&type` по всем находкам-целям (issueIds через запятую)."""
    ids = ",".join(str(int(t["issue_id"])) for t in targets)
    if not ids:
        raise ValueError("Нет находок для заготовки дефекта.")
    if len(ids) > ISSUE_IDS_MAX:
        raise ValueError(f"Слишком много находок для одной заготовки (параметр issueIds длиннее {ISSUE_IDS_MAX} "
                         "знаков): создайте дефект из меньшего числа находок.")
    request = {"method": "GET", "path": f"/defects/blank?appId={int(app_id)}&issueIds={ids}&type={issue_type}",
               "body": None}
    hub_ops.check_request(request["method"], request["path"])
    return request


def service_info_request() -> dict:
    request = {"method": "GET", "path": SERVICE_INFO_PATH, "body": None}
    hub_ops.check_request(request["method"], request["path"])
    return request


def create_request(body: dict) -> dict:
    request = {"method": "POST", "path": "/defects", "body": body}
    hub_ops.check_request(request["method"], request["path"])
    return request


def read_request(defect_id: str) -> dict:
    request = {"method": "GET", "path": f"/defects/{int(defect_id)}", "body": None}
    hub_ops.check_request(request["method"], request["path"])
    return request


def link_request(defect_id: str, targets: list[dict], group_id: Any = None) -> dict:
    """`POST /defects/{id}/link`, тело DefectIssuesRequestDto {defectId, issueIds[], issueType, groupId}; у всех
    целей один тип находки. groupId – из заготовки, если Hub его отдал (назначение поля уточнить)."""
    types = {str(t["issue_type"]) for t in targets}
    if len(types) != 1:
        raise ValueError("Привязка к дефекту – находки одного типа.")
    body = {"defectId": int(defect_id), "issueIds": [int(t["issue_id"]) for t in targets], "issueType": types.pop(),
            "groupId": group_id}
    request = {"method": "POST", "path": f"/defects/{int(defect_id)}/link", "body": body}
    hub_ops.check_request(request["method"], request["path"])
    return request


def list_request(app_id: int, page: int, size: int = PAGE_SIZE) -> dict:
    request = {"method": "GET", "path": f"/defects?appId={int(app_id)}&pageIndex={int(page)}&pageSize={int(size)}",
               "body": None}
    hub_ops.check_request(request["method"], request["path"])
    return request


# ============================================================================ тело дефекта


def command_html(text: str) -> str:
    """Текст команды (тело дефекта из карточки) → HTML без стилей и скриптов: абзацы – `<p>`, строки внутри абзаца –
    `<br>`. Пункты «1) …», «2) …» уходят текстом, как в шаблоне команды (нумерация «1)» символ в символ – требование
    S1); `<ol>` редактор Hub показывал без номеров. Весь текст экранируется.

    С 0.10.0.dev21 содержимое текста оператора не теряется (ADR-0149): каждая пустая строка сверх одной между абзацами –
    пустой абзац `<p><br></p>`, отступ в начале строки – неразрывные пробелы (Hub хранит их обычными пробелами,
    ADR-0146). Не уходят только пробелы в конце строк и пустые строки по краям текста. Сверки прочитанного описания
    сравнивают строки без пустых и с нормализованными пробелами – им это не мешает."""
    out: list[str] = []
    block: list[str] = []
    blanks = 0
    for raw in str(text or "").replace("\r\n", "\n").split("\n"):
        line = raw.rstrip()
        if not line.strip():
            blanks += 1
            continue
        if block and blanks:
            out.append(_paragraph(block))
            out += ["<p><br></p>"] * (blanks - 1)
            block = []
        blanks = 0
        block.append(line)
    if block:
        out.append(_paragraph(block))
    return "".join(out)


def _paragraph(lines: list[str]) -> str:
    """Абзац command_html: строки через `<br>`, отступ в начале строки – неразрывными пробелами (табуляция – четыре)."""
    def one(line: str) -> str:
        body = line.lstrip(" \t")
        lead = line[:len(line) - len(body)].replace("\t", "    ")
        return "&nbsp;" * len(lead) + html.escape(body)
    return "<p>" + "<br>".join(one(line) for line in lines) + "</p>"


def blank_for_send(row: dict) -> hub_block_version.Retarget:
    """Блок заготовки, который уходит в Hub (ADR-0132): исходная заготовка с целевой версией из текста дефекта.
    Сама заготовка в `blank_json` остаётся исходной: Hub может дописать её второй раз, и её нужно узнать (`_blank_appended_twice`)."""
    blank = str((loads(row.get("blank_json"), {}) or {}).get("description") or "")
    return hub_block_version.for_defect(str(row.get("kind") or ""), str(row.get("command_text") or ""), blank)


def description_html(command_text: str, blank_description: Any) -> str:
    """Описание дефекта: текст команды в HTML, затем `description` заготовки Hub как есть (блок «Информация об объекте
    сканирования» по шаблону Hub)."""
    extra = str(blank_description or "")
    return command_html(command_text) + ("\n" + extra if extra else "")


def plain_text(value: Any) -> str:
    """Текст HTML без тегов и сущностей, пробелы схлопнуты – для сверки начала description с текстом команды."""
    return hub_ops.normalize_text(html.unescape(_TAG.sub(" ", str(value or ""))))


def command_plain(command_text: str) -> str:
    """Текст команды так, как он читается из нашего же HTML."""
    return plain_text(command_html(command_text))


def description_matches(description: Any, command_text: str) -> bool:
    """Описание Hub начинается с текста команды – по строкам разметки (description_lines): дефект, созданный до
    0.9.26.dev14 со списком `<ol>`, читается как «1) …» и узнаётся сверкой (ревью dev14)."""
    expected = hub_ops.normalize_text("\n".join(description_lines(command_html(command_text))))
    return bool(expected) and hub_ops.normalize_text("\n".join(description_lines(description))).startswith(expected)


def level_names(items: Any) -> list[str]:
    """Имена уровней из справочника serviceInfo: элементы – {name, rank} или строки."""
    names: list[str] = []
    for item in items if isinstance(items, list) else []:
        name = item.get("name") if isinstance(item, dict) else item
        if isinstance(name, str) and name.strip() and name not in names:
            names.append(name.strip())
    return names


def level_name(value: Any) -> str:
    if isinstance(value, dict):
        return str(value.get("name") or "")
    return str(value or "")


def pick_level(items: Any, name: str, fallback: Any) -> Any:
    """Уровень по имени из справочника ({name, rank} как в serviceInfo); имя не из списка – ValueError; пустое имя или
    нет списка – значение заготовки как есть."""
    name = str(name or "").strip()
    names = level_names(items)
    if not name or not names or name == level_name(fallback):
        return fallback  # прежний выбор – уровень заготовки целиком, с rank (ревью dev11 A1)
    for item in items:
        if level_name(item) == name:
            return item if isinstance(item, dict) else {"name": name}
    raise ValueError(f"Значение «{name}» не из списка Hub ({', '.join(names)}).")


LEVEL_IDS = (("priority", "priorityId"), ("severity", "severityId"))


def level_codes(objects: Iterable[Any]) -> dict:
    """Соответствие уровня коду – только из дефектов, прочитанных из Hub, где Hub сам дал {name, rank} и ID рядом
    (ADR-0126: ID не выводится из rank): (поле, имя, rank) → ID; противоречивое соответствие не берётся."""
    seen: dict = {}
    for obj in objects:
        if not isinstance(obj, dict):
            continue
        for field, id_field in LEVEL_IDS:
            level, code = obj.get(field), obj.get(id_field)
            if (isinstance(level, dict) and type(code) is int and type(level.get("rank")) is int
                    and level_name(level)):
                seen.setdefault((field, level_name(level), level["rank"]), set()).add(code)
    return {key: next(iter(codes)) for key, codes in seen.items() if len(codes) == 1}


def fill_level_codes(body: dict, codes: dict, blank: dict) -> dict:
    """Hub при создании требует код уровня (ответ 400 «invalid priority code null»), а заготовка
    GET /defects/blank его не даёт: код подставляется только из соответствия, данного Hub (level_codes). Неизменённая
    комбинация заготовки с кодом остаётся как есть; другой уровень получает код только из соответствия, а при коде в
    заготовке без соответствия – отказ (ADR-0126 п. 2–3, ревью dev11 A2/B2); соответствия нет и кода в заготовке нет –
    тело уходит без кода, отказ Hub показывается как есть. Возвращает использованные соответствия {ключ: код} – их
    транзакция постановки проверяет повторно."""
    used: dict = {}
    for field, id_field in LEVEL_IDS:
        level = body.get(field)
        if not isinstance(level, dict):
            continue
        if level == blank.get(field) and blank.get(id_field) is not None:
            continue
        key = (field, level_name(level), level.get("rank"))
        code = codes.get(key)
        if code is not None:
            body[id_field] = used[key] = code
        elif blank.get(id_field) is not None:
            raise DefectRefused(f"Нет подтверждённого Hub соответствия значения «{level_name(level)}» коду {id_field}: "
                                "оставьте значение заготовки.")
    return used


def level_codes_changed(used: dict, codes: dict) -> bool:
    """Соответствие, по которому собрано тело, изменилось или стало противоречивым (ревью dev11 A4/B1)."""
    return any(codes.get(key) != code for key, code in used.items())


def level_diffs(sent: dict, defect: dict) -> list[str]:
    """Отправленные уровни и коды, которых нет в прочитанном дефекте (ревью dev11 A3/B3): уровень – по имени и rank.
    Сверяются поля, которые чтение вернуло (в DefectDto Hub priority и severity обязательны); поля нет в ответе –
    расхождения не доказано."""
    diffs = []
    for field, id_field in LEVEL_IDS:
        if field in sent and field in defect:
            level, seen = sent[field], defect.get(field)
            # rank в NameRankDto необязателен: его отсутствие в ответе – не расхождение
            if isinstance(level, dict):
                same = (isinstance(seen, dict) and level_name(level) == level_name(seen)
                        and ("rank" not in seen or level.get("rank") == seen["rank"]))
            else:
                same = level == seen
            if not same:
                diffs.append(f"{field}: отправлено {json.dumps(level, ensure_ascii=False)}, "
                             f"прочитано {json.dumps(seen, ensure_ascii=False)}")
        if id_field in sent and id_field in defect and defect[id_field] != sent[id_field]:
            diffs.append(f"{id_field}: отправлено {sent[id_field]}, прочитано {defect.get(id_field)}")
    return diffs


def create_body(blank: dict, app_id: int, summary: str, description: str, priority: Any, severity: Any) -> dict:
    """Тело `POST /defects`: заготовка Hub (DefectDto без id) с правками – appId, заголовок, описание, приоритет и
    серьёзность; status, source, stage, type и linkedIssues – из заготовки."""
    body = {k: v for k, v in blank.items() if k != "id" and not str(k).startswith("_")}  # «_targets» – отметка приложения
    body.update(appId=int(app_id), summary=str(summary), description=str(description))
    if priority is not None:
        body["priority"] = priority
    if severity is not None:
        body["severity"] = severity
    return body


def create_composition_check(body: dict, targets: list[dict]) -> None:
    """7а: фактический POST обязан содержать весь показанный состав, без исправления заготовки."""
    from app.hub_sync_api import composition_problems
    expected = {(int(t["issue_id"]), str(t["issue_type"])) for t in targets}
    problems = composition_problems(body)
    actual = linked_pairs(body) if not problems else set()
    if problems or actual != expected or not expected:
        detail = "; ".join(problems) if problems else "связи не совпадают с подтверждённым составом"
        raise DefectRefused("Состав linkedIssues заготовки не соответствует предпросмотру: " + detail
                            + ". Создание не поставлено; отмените предпросмотр и подготовьте заново.")


def creation_signature(row: dict) -> str:
    """Показанные заготовка, блок с целевой версией, состав и редакция черновика; проверяются и внутри перехода. Блок входит в подпись
    потому, что отправляется именно он: вкладка, открытая на прежней сборке, показывала другое и должна обновиться (ADR-0132)."""
    from app.hub_entity_versions import digest
    return digest({**{k: row.get(k) for k in ("id", "project_id", "hub_url", "app_id", "number", "summary",
                   "command_text", "targets_json", "left_out_json", "warnings_json", "blank_json",
                   "draft_revision", "draft_summary", "draft_command_text", "members_snapshot",
                   "source_fingerprint", "number_keys_json")}, "sent_block": blank_for_send(row).block})


# ============================================================================ разбор ответов Hub


def parse_defect_id(result: dict) -> str:
    """Номер созданного дефекта: из тела ответа (`id`, `defectId`) или из заголовка Location – как подсказка
    (hub-write-plan, раздел 1); подтверждается чтением."""
    body = hub_ops.parse_json(str(result.get("body_text") or ""))
    if isinstance(body, dict):
        for key in ("id", "defectId"):
            value = body.get(key)
            if isinstance(value, int) and not isinstance(value, bool) and value > 0:
                return str(value)
            if isinstance(value, str) and _DIGITS.fullmatch(value.strip()):
                return value.strip()
    headers = result.get("headers") if isinstance(result.get("headers"), dict) else {}
    location = str(headers.get("location") or "").rstrip("/")
    tail = location.rsplit("/", 1)[-1]
    return tail if _DIGITS.fullmatch(tail) else ""


def linked_pairs(defect: Any) -> set[tuple[int, str]]:
    """Привязанные находки дефекта (`linkedIssues[{id, type, …}]`) → {(номер, тип)}."""
    pairs: set[tuple[int, str]] = set()
    for item in (defect.get("linkedIssues") if isinstance(defect, dict) else None) or []:
        if not isinstance(item, dict):
            continue
        raw_id = item.get("id", item.get("issueId"))
        raw_type = item.get("type", item.get("issueType"))
        if isinstance(raw_id, bool) or not isinstance(raw_id, (int, str)) or not _DIGITS.fullmatch(str(raw_id)):
            continue
        pairs.add((int(raw_id), str(raw_type or "")))
    return pairs


def missing_targets(defect: Any, targets: list[dict]) -> list[dict]:
    """Цели, которых нет среди привязанных находок дефекта."""
    linked = linked_pairs(defect)
    return [t for t in targets if (int(t["issue_id"]), str(t["issue_type"])) not in linked]


def expected_pairs(row: dict) -> set[tuple[int, str]] | None:
    """Создание: предпросмотр; привязка: подтверждённый прежний состав и новые цели."""
    pairs = {(int(t["issue_id"]), str(t["issue_type"])) for t in loads(row.get("targets_json"), [])}
    if not row.get("create_op_id") and not row.get("blank_op_id"):
        previous = loads(row.get("blank_json"), {}).get("expected_previous_links")
        if previous is None:
            return None
        pairs.update((int(i), t) for i, t in previous)
    return pairs


def composition_diff(row: dict, defect: dict) -> dict:
    from app.hub_sync_api import composition_problems
    expected, actual = expected_pairs(row), linked_pairs(defect)
    problems = composition_problems(defect)
    if expected is None:
        problems.append("Подтверждённый прежний состав привязки не сохранён.")
    return {"missing": sorted((expected or set()) - actual),
            "extra": sorted(actual - (expected or set())), "problems": problems}


def _unconfirmed_composition(db, row, op, expect_op, defect, **fields):
    diff = composition_diff(row, defect)
    if not any(diff.values()):
        return False
    parts = ["Недостающие связи: " + ", ".join(f"{t}:{i}" for i, t in diff["missing"]),
             "Лишние связи: " + ", ".join(f"{t}:{i}" for i, t in diff["extra"]), *diff["problems"]]
    verification = loads(fields.pop("verify_json", row.get("verify_json")), {})
    verification["composition"] = diff
    db.hub_defect_update(int(row["id"]), expect_state=row["state"], expect_op=expect_op,
                         state="unconfirmed", verify_op_id=None, import_json=dumps(_read_of(defect)),
                         verify_json=dumps(verification), error="Состав не подтверждён. " + "; ".join(parts), **fields)
    return True


def defect_link(hub_url: str, app_id: int | None, defect_id: str) -> str:
    base = hub_ops.hub_base(hub_url)
    if not base or not defect_id:
        return ""
    return base + HUB_DEFECT_PATH.format(app_id=int(app_id or 0), defect_id=defect_id)


def brief_matches(brief: Any, summary: str, login: str = "") -> bool:
    """Кандидат из списка дефектов (DefectBriefDto): тот же заголовок; если в кратком виде есть автор и известен
    login исполнителя – тот же автор. Имя поля автора в спецификации не названо – уточнить; проверяются обычные
    варианты."""
    if not isinstance(brief, dict):
        return False
    if hub_ops.normalize_text(brief.get("summary")) != hub_ops.normalize_text(summary):
        return False
    if login:
        for key in ("author", "createdBy", "creator", "owner", "reporter"):
            value = brief.get(key)
            if not value:
                continue
            name = value if isinstance(value, str) else (value.get("login") or value.get("name")
                                                        or value.get("username") if isinstance(value, dict) else "")
            if name and str(name).strip().casefold() != login.strip().casefold():
                return False
    return True


def candidate_matches(defect: Any, row: dict) -> bool:
    """Прочитанный дефект – наш: тот же заголовок, привязаны все цели, в начале описания – текст команды."""
    if not isinstance(defect, dict):
        return False
    if hub_ops.normalize_text(defect.get("summary")) != hub_ops.normalize_text(row.get("summary")):
        return False
    if any(composition_diff(row, defect).values()):
        return False
    return description_matches(defect.get("description"), str(row.get("command_text") or ""))


# ============================================================================ находка, привязанная к дефекту (ADR-0121)


class DefectBound(Exception):
    """Действие с находкой, привязанной к дефекту в Hub (смена решения, статус, снятие отметки), – только с
    подтверждением defect_confirm=1 (ADR-0121); текст – по-русски, row – строка дефекта."""

    def __init__(self, text: str, row: dict | None = None) -> None:
        super().__init__(text)
        self.row = row


def bound_label(row: dict) -> str:
    """«№555 (ID1)» – номер дефекта в Hub и номер ID<n>; номер в Hub ещё не известен (дефект создаётся) – «ID1»."""
    number = str(row.get("hub_defect_id") or "")
    raw = row.get("number")
    label = f"ID{raw}" if isinstance(raw, int) and not isinstance(raw, bool) and raw > 0 else ""
    if number:
        return f"№{number}" + (f" ({label})" if label else "")
    return label


def bound_name(row: dict) -> str:
    """«дефект №555 (ID1)»; номер в Hub ещё не известен – «дефект ID1 (создаётся в Hub)»."""
    label = bound_label(row)
    if row.get("hub_defect_id"):
        return f"дефект {label}"
    return (f"дефект {label}" if label else "дефект") + " (создаётся в Hub)"


def bound_text(row: dict, question: str, hub_id: str = "") -> str:
    """Текст отказа «нужно подтверждение»: в какой дефект входит находка (hub_id – не своя находка, а соседка группы),
    что дефект в Hub не изменится, и вопрос. Номер в Hub ещё не известен – «который создаётся в Hub»."""
    who = f"Находка {hub_id}" if hub_id else "Находка"
    if row.get("hub_defect_id"):
        head = f"{who} входит в {bound_name(row)}, созданный в Hub."
    else:
        label = bound_label(row)
        head = f"{who} входит в дефект{' ' + label if label else ''}, который создаётся в Hub (номер в Hub ещё не известен)."
    return f"{head} Дефект в Hub не изменится – поправьте его в Hub сами. {question}"


def in_defect_text(row: dict, hub_id: str = "") -> str:
    """Пояснение dev32: находка (hub_id – соседка группы, своя – без номера) входит в дефект – статус в Hub через
    дефект. Как освободить находку – по происхождению дефекта: у занесённого из Hub – «Pull из Hub» (ADR-0124), у
    созданного приложением – синхронизация с принятием состояния Hub (ADR-0127); ревью dev32, круг 1."""
    who = f"Находка {hub_id}" if hub_id else "Находка"
    how = IN_DEFECT_HOW_IMPORT if str(row.get("origin") or "") == "import" else IN_DEFECT_HOW_APP
    return f"{who} входит в {bound_name(row)}: {IN_DEFECT_STATUS.format(how=how)}"


def refuse_in_defect(c, project_id: int, hub_ids, own: str = "") -> None:
    """В транзакции постановки статуса (dev32): одна из находок hub_ids входит в дефект – DefectBound с пояснением
    (без вопроса о подтверждении: отправка статуса у находки в дефекте не предусмотрена)."""
    for hub_id in hub_ids:
        row = Database.hub_defect_bound_in(c, project_id, str(hub_id))
        if row is not None:
            raise DefectBound(in_defect_text(row, "" if str(hub_id) == str(own) else str(hub_id)), row)


def refuse_bound(c, project_id: int, hub_ids, question: str, own: str = "") -> None:
    """В транзакции записи: одна из находок hub_ids привязана к дефекту – DefectBound с текстом (own – своя находка
    карточки, её номер в тексте не называется)."""
    for hub_id in hub_ids:
        row = Database.hub_defect_bound_in(c, project_id, str(hub_id))
        if row is not None:
            raise DefectBound(bound_text(row, question, "" if str(hub_id) == str(own) else str(hub_id)), row)


def unenter_check(project_id: int, hub_id: str) -> Callable:
    """Проверка в транзакции снятия отметки «Внесено в Hub» (mark_entered(check=…)): находка в дефекте – DefectBound."""
    def check(c) -> None:
        refuse_bound(c, project_id, [hub_id], UNENTER_QUESTION, own=hub_id)
    return check


def decision_changes(old: dict | None, decision: str, final_verdict: str, comment: str, final_fix: str | None) -> bool:
    """Сохранение меняет решение (ADR-0121 п. 2): другой итог, другой вид решения (кроме «Согласен» ↔ «Не согласен» –
    новый ответ модели), другое обоснование или рекомендация (final_fix None – прежняя) – как правило «тот же текст»
    записи решения (Database._save_review_in). Повторное сохранение того же и отметка «Проверено» – не смена."""
    if not old or not old.get("decision"):
        return True
    fix = str(old.get("final_fix") or "") if final_fix is None else str(final_fix)
    same = (hub_verdict(old["decision"], old.get("final_verdict") or "") == hub_verdict(decision, final_verdict)
            and str(old.get("final_comment") or "") == str(comment or "")
            and str(old.get("final_fix") or "") == fix
            and (old["decision"] == decision or {old["decision"], decision} <= {"agree", "disagree"}))
    return not same


def save_check(db: Database, project_id: int, hub_id: str, decision: str, final_verdict: str, comment: str,
               final_fix: str | None, confirmed: bool, inner: Callable | None = None) -> Callable:
    """Проверка группы для save_review(group_check=…): сначала прежняя (inner), затем – находка привязана к дефекту и
    решение действительно меняется, а подтверждения нет – DefectBound. Привязка и прежнее решение читаются в
    транзакции записи: проверка вызывается внутри неё, замок общего соединения реентерабелен."""
    def check(rows: list[dict]) -> None:
        if inner is not None:
            inner(rows)
        if confirmed:
            return
        row = db.hub_defect_bound(project_id, hub_id)
        if row is not None and decision_changes(db.get_review(project_id, hub_id), decision, final_verdict, comment,
                                                final_fix):
            raise DefectBound(bound_text(row, SAVE_QUESTION), row)
    return check


# ============================================================================ вид для карточки и вкладки


def link_rereadable(row: dict) -> bool:
    """Строка привязки «привязка неполная» с целями: итог определит новое чтение (ADR-0136). Записи нет, строка создания
    сюда не попадает; схлопнутая строка – история, читать нечего."""
    return (row.get("state") == "mismatch" and row.get("origin") != "import" and bool(row.get("hub_defect_id"))
            and not row.get("create_op_id") and not row.get("blank_op_id")
            and int(row.get("draft_owner_id") or row.get("id") or 0) != int(row.get("id") or 0)
            and bool(loads(row.get("targets_json"), [])))


def view(row: dict | None) -> dict:
    """Состояние дефекта для карточки: {state, final, text, tone, verify}."""
    if row is None:
        return {"state": "", "final": True, "text": "", "tone": "", "verify": False}
    state, error, number = row["state"], str(row.get("error") or ""), str(row.get("hub_defect_id") or "")
    # итог «Проверить в Hub» (ADR-0121 п. 6) с dev33 не выводится: кнопки нет, у дефекта – «Push в Hub» и «Pull из Hub»
    note = ""
    texts = {
        "blank": ("Ждём исполнителя: он запросит у Hub заготовку дефекта…", "", False, False),
        "preview": ("Заготовка получена: проверьте предпросмотр и нажмите «Создать».", "", True, False),
        "creating": ("Исполнитель создаёт дефект в Hub…", "", False, False),
        "created": (f"Дефект №{number} создан, проверяю привязку находок чтением…", "", False, False),
        "linking": (f"Привязываю находки к дефекту №{number}…", "", False, False),
        "done": (" ".join(p for p in (error, note) if p),
                 "warn" if "не записан" in error or (note and note != RECHECK_OK) else "ok", True, False),
        "mismatch": (f"Дефект №{number} создан, но {error or 'привязаны не все находки'}. Проверьте дефект в Hub.",
                     "warn", True, link_rereadable(row)),
        "unknown": (f"Результат неизвестен ({error or 'ответа нет'}). Нажмите «Pull из Hub»: приложение прочитает дефект "
                    "в Hub; повторно само не создаст.", "warn", True, True),
        "unconfirmed": ("Содержимое дефекта в Hub не совпало с отправленным снимком. "
                        "Сравните версии и нажмите «Pull из Hub». Повторной записи нет.", "warn", True, True),
        # итог чтения (_conclude ставит confirm_op_id): Hub не отказывал – находки нет в составе (круг 5 ревью)
        "failed": ((f"{error or 'ошибка'}. Можно попробовать ещё раз." if row.get("confirm_op_id") else
                    f"Hub не принял: {error or 'ошибка'}. Можно попробовать ещё раз."), "err", True, False),
        "cancelled": (error, "warn" if error else "", True, False),
    }
    if row.get("origin") == "import":  # занесение из Hub (ADR-0124): только чтение, «Сверить» результата нет
        return import_view(row)
    text, tone, final, verify = texts.get(state, ("", "", True, False))
    if state == "done" and update_state(row).get("phase"):
        update_text, update_tone, update_final = update_view(row)
        text = " ".join(p for p in (text, update_text) if p)
        tone = "warn" if "warn" in (tone, update_tone) else update_tone or tone
        final = final and update_final
    if state == "done" and row.get("sync_op_id"):  # «Pull из Hub» у дефекта из приложения идёт (dev34)
        text, tone, final, verify = (f"Сверяю с Hub: читаю дефект №{number}…", "", False, False)
    elif state == "done":
        sync_state = loads(row.get("sync_json"), {}) or {}
        if isinstance(sync_state, dict) and sync_state.get("error"):  # сверка не удалась: пояснение, состояние прежнее
            text = " ".join(p for p in (text, "сверка с Hub: " + str(sync_state["error"])) if p)
            tone = "err" if tone == "err" else "warn"
    if state == "unknown" and row.get("verify_op_id"):
        # сверка идёт: исполнитель читает список и кандидатов – карточка продолжает опрос, кнопка скрыта
        text, tone, final, verify = (f"Сверяю с Hub: {error or 'жду исполнителя'}", "", False, False)
    if state == "done" and row.get("verify_op_id"):  # «Проверить в Hub» идёт: карточка опрашивает, кнопка скрыта
        text, tone, final, verify = (f"Проверяю в Hub: читаю дефект №{number}…", "", False, False)
    if state == "unconfirmed" and loads(row.get("verify_json"), {}).get("composition"):
        text += " " + error
    confirmation = loads(row.get("verify_json"), {}).get("confirmation", {})
    return {"state": state, "final": final, "text": text, "tone": tone, "verify": verify,
            "diff": confirmation.get("diff", "")}


def preview(db: Database, row: dict, card_url: Callable[[str], str]) -> dict | None:
    """Предпросмотр для карточки: заголовок, текст команды, что добавит Hub, приоритет и серьёзность из заготовки и
    списки из serviceInfo (если справочник прочитан), окончательный состав находок и кто не вошёл."""
    if row is None or row["state"] != "preview":
        return None
    blank = loads(row.get("blank_json"), {}) or {}
    service = service_info(db, str(row.get("hub_url") or ""))
    targets = loads(row.get("targets_json"), [])
    block = blank_for_send(row)
    return {"snapshot": creation_signature(row),
            "summary": str(row.get("summary") or ""), "command_text": str(row.get("command_text") or ""),
            "hub_adds": bool(str(blank.get("description") or "").strip()),
            "where_added": bool(defect_where.split(row.get("command_text"))[1]),  # раздел «Где исправлять» в тексте (dev7)
            "hub_block": sanitize_hub_html(block.block),  # уйдёт в описание следом за текстом (dev30), версия – целевая (dev7)
            "block_version": block.view(), "block_notes": list(block.notes),
            "priority": level_name(blank.get("priority")), "severity": level_name(blank.get("severity")),
            "priorities": level_names(service.get("priorities")), "severities": level_names(service.get("severities")),
            "targets": [{"hub_id": str(t.get("hub_id") or ""), "url": card_url(str(t.get("hub_id") or ""))}
                        for t in targets],
            "left_out": loads(row.get("left_out_json"), []), "warnings": loads(row.get("warnings_json"), [])}


def service_info(db: Database, hub_url: str) -> dict:
    """Справочник `GET /defects/serviceInfo` из последней выполненной операции чтения; нет – {}."""
    op = db.hub_last_read(hub_url, SERVICE_INFO_PATH)
    if op is None:
        return {}
    body = hub_ops.parse_json((loads(op.get("result_json"), {}) or {}).get("body_text", ""))
    return body if isinstance(body, dict) else {}


# ============================================================================ последствия ответов исполнителя


def _first_target(op: dict) -> dict:
    targets = loads(op.get("targets_json"), [])
    return targets[0] if targets and isinstance(targets[0], dict) else {}


def _result(op: dict) -> dict:
    return loads(op.get("result_json"), {}) or {}


def _body(op: dict) -> Any:
    return hub_ops.parse_json(str(_result(op).get("body_text") or ""))


def is_defect_read(op: dict) -> bool:
    """Чтение (purpose read) принадлежит сверке дефекта: в первой цели – verify_defect."""
    return isinstance(_first_target(op).get("verify_defect"), int)


def after_op(db: Database, op: dict | None, worker_login: str = "",
             prepare: Callable[[dict], dict] | None = None) -> None:
    """Последствия закрытой операции цепочки дефекта или сверки. Каждый шаг применяется, только если строка всё ещё
    ждёт именно этой операции (expect_op в транзакции): повторная доставка, опрос карточки и устаревший обработчик
    ничего не меняют, а уже подтверждённая строка доводит недостающие последствия. prepare(строка) – подготовка
    обновления по текущим решениям (маршрут с запросом, ADR-0125): нужна ответам чтения «Push в Hub»; без неё
    такой ответ ждёт показа вкладки (sync)."""
    if not op or op["state"] not in ("done", "failed", "unknown", "cancelled"):
        return
    # «Push в Hub» (ADR-0125) – до общего преобразования cancelled → failed: отмена до выдачи исполнителю и
    # закрытие без ответа ведут к разным итогам
    if isinstance(_first_target(op).get("defect_update"), int):
        _on_update(db, op, _first_target(op), prepare)
        return
    if op["state"] == "cancelled":
        op = {**op, "state": "failed", "error": op.get("error") or "операция отменена"}
    purpose, first = op["purpose"], _first_target(op)
    if purpose == "read":
        if isinstance(first.get("verify_defect"), int):
            _on_list(db, op, first)
        return
    # занесение из Hub и «Pull из Hub» (ADR-0124 п. 3, 6) – до общего _on_read: строка – по цели операции
    if purpose == "defect_read" and isinstance(first.get("import_defect"), int):
        _on_import(db, op, first)
        return
    if purpose == "defect_read" and isinstance(first.get("import_sync"), int):
        _on_import_sync(db, op, first)
        return
    if purpose == "defect_read" and isinstance(first.get("verify_defect"), int):
        _on_candidate(db, op, first)
        return
    if purpose == "defect_read" and isinstance(first.get("recheck_defect"), int):  # «Проверить в Hub» (ADR-0121)
        _on_recheck(db, op, first)
        return
    row = db.hub_defect_by_op(int(op["id"]))
    if row is None:
        return
    if purpose == "defect_blank":
        _on_blank(db, row, op)
    elif purpose == "defect_create":
        _on_create(db, row, op, worker_login)
    elif purpose == "defect_read":
        _on_read(db, row, op)
    elif purpose == "defect_link":
        _on_link(db, row, op)


CLOSED = ("done", "failed", "unknown", "cancelled")


def sync(db: Database, row: dict, prepare: Callable[[dict], dict] | None = None) -> dict:
    """При показе: операция, которой ждёт строка, уже закрыта без доставки результата (истёкшая аренда, отмена) –
    последствия применяются здесь; у подтверждённого дефекта с недоведёнными последствиями (сбой после записи итога) –
    доводятся. prepare – подготовка обновления (ADR-0125, как у after_op). Возвращает актуальную строку."""
    if db.read_only:  # режим обслуживания: показывается сохранённое состояние, очередь и последовательности не меняются
        return row
    if row["state"] in ("done", "mismatch", "failed"):  # failed – итог строки привязки чтением (ADR-0121 п. 5)
        if not int(row.get("effects_done") if row.get("effects_done") is not None else 1):
            _apply_effects(db, row)
            return db.hub_defect(int(row["id"])) or row
        # «Проверить в Hub», «Pull из Hub» (ADR-0124 п. 6) и шаг «Push в Hub» (ADR-0125): операция закрылась
        # без доставки ответа (аренда истекла, отмена) или ответ записан, а последствия – нет
        for field in ("verify_op_id", "sync_op_id", "update_op_id"):
            if row["state"] == "done" and row.get(field):
                op = db.hub_op(int(row[field]))
                if op is not None and op["state"] in CLOSED:
                    after_op(db, op, prepare=prepare)
                    return db.hub_defect(int(row["id"])) or row
        return row
    if row["state"] in ("unknown", "unconfirmed"):
        op_id = row.get("verify_op_id")  # идёт сверка: её текущая операция могла закрыться без доставки
    elif row["state"] in OPEN_STATES:
        op_id = {"blank": row.get("blank_op_id"), "creating": row.get("create_op_id"), "created": row.get("read_op_id"),
                 "linking": row.get("link_op_id"), "import_reading": row.get("read_op_id")}[row["state"]]
    else:
        return row
    op = db.hub_op(int(op_id)) if op_id else None
    if op is not None and op["state"] in CLOSED:
        after_op(db, op)
        return db.hub_defect(int(row["id"])) or row
    return row


def _on_blank(db: Database, row: dict, op: dict) -> None:
    if row["state"] != "blank" or row.get("blank_op_id") != op["id"]:
        return
    mine = ("blank_op_id", int(op["id"]))
    if op["state"] != "done":
        db.hub_defect_update(int(row["id"]), expect_state="blank", expect_op=mine, state="failed",
                             error=f"заготовка не получена: {op.get('error') or 'ответа нет'}")
        return
    blank = _body(op)
    if not isinstance(blank, dict):
        db.hub_defect_update(int(row["id"]), expect_state="blank", expect_op=mine, state="failed",
                             error="заготовка Hub не разобрана: ответ не объект JSON")
        return
    # заготовка без описания: служебного блока не будет – сведения для разработчиков уходят разделом текста (план dev7, раздел 11)
    fields = {}
    if not str(blank.get("description") or "").strip():
        added = with_where(db, {**row, "blank_json": dumps(blank)}, blank, {"command_text": str(row.get("command_text") or "")})
        if added.get("where_added"):
            fields["command_text"] = added["command_text"]
    db.hub_defect_update(int(row["id"]), expect_state="blank", expect_op=mine, state="preview",
                         blank_json=dumps({**blank, "_targets": blank_target_ids(row)}),
                         draft_fields_json=dumps(defect_drafts.fields_of(blank)), error="", **fields)


def read_item(row: dict, defect_id: str) -> dict:
    """Операция чтения `GET /defects/{id}` по целям дефекта."""
    return dict(purpose="defect_read", request=read_request(str(defect_id)), hub_url=row["hub_url"],
                app_id=row.get("app_id"), project_id=int(row["project_id"]), targets=loads(row.get("targets_json"), []))


def _read_step(db: Database, row: dict, expect_state: str, defect_id: str, expect_op: tuple[str, int] | None,
               **fields: Any) -> dict | None:
    """Переход в created с постановкой чтения – одной транзакцией: строка ушла из expect_state или ждёт уже другой
    операции – ничего; очередь отказала – «результат неизвестен» с причиной, оператор сверит кнопкой."""
    try:
        fresh, _ = db.hub_defect_advance(int(row["id"]), expect_state=expect_state, expect_op=expect_op,
                                         item=read_item(row, defect_id), op_field="read_op_id", state="created",
                                         hub_defect_id=str(defect_id), error="", **fields)
    except ValueError as e:
        return db.hub_defect_update(int(row["id"]), expect_state=expect_state, expect_op=expect_op, state="unknown",
                                    hub_defect_id=str(defect_id), error=f"чтение дефекта не поставлено: {e}", **fields)
    return fresh


def _on_create(db: Database, row: dict, op: dict, worker_login: str = "") -> None:
    if row["state"] != "creating" or row.get("create_op_id") != op["id"]:
        return
    mine = ("create_op_id", int(op["id"]))
    if op["state"] == "failed":
        db.hub_defect_update(int(row["id"]), expect_state="creating", expect_op=mine, state="failed",
                             error=str(op.get("error") or "Hub не принял дефект"))
        return
    if op["state"] == "unknown":
        db.hub_defect_update(int(row["id"]), expect_state="creating", expect_op=mine, state="unknown",
                             error=str(op.get("error") or "ответа от Hub нет"))
        return
    defect_id = parse_defect_id(_result(op))
    if not defect_id:
        # Hub на POST /defects отвечает 201 без тела и без Location: номер ищется
        # сразу тем же чтением, что и «Сверить» (список и кандидаты, без записи) – переход и постановка первой
        # страницы одной транзакцией (ревью dev12); отказ очереди – «неизвестен» с кнопкой «Сверить»
        status = _result(op).get("status")
        if isinstance(status, int) and 200 <= status < 300:
            state = {"page": 0, "total": 0, "login": str(worker_login or ""), "pending": [], "checked": []}
            try:
                fresh, _ = db.hub_defect_advance(int(row["id"]), expect_state="creating", expect_op=mine,
                                                 item=list_item(row, 0), op_field="verify_op_id", state="unknown",
                                                 verify_json=dumps(state), error="сверяю по списку дефектов Hub…")
            except ValueError:
                fresh = None
            if fresh is not None:
                return
        db.hub_defect_update(int(row["id"]), expect_state="creating", expect_op=mine, state="unknown",
                             error="Hub ответил без номера дефекта")
        return
    _read_step(db, row, "creating", defect_id, mine, hub_link=defect_link(row["hub_url"], row.get("app_id"), defect_id),
               created_by=str(worker_login or "")[:200])


def _has_expected_id(defect: Any, expected: Any) -> bool:
    """Полный ответ относится к запрошенному дефекту; нечисловой ID разбором не считается."""
    return (isinstance(defect, dict) and bool(_DIGITS.fullmatch(str(defect.get("id"))))
            and str(int(str(defect["id"]))) == str(expected))


def _has_expected_app(defect: Any, expected: Any) -> bool:
    """Приложение ответа совпадает с сохранённым назначением операции."""
    raw = defect.get("appId") if isinstance(defect, dict) else None
    return (not isinstance(raw, bool) and bool(_DIGITS.fullmatch(str(raw)))
            and int(str(raw)) == expected)


def _targets_within(row: dict, defect: Any) -> bool:
    """Все цели строки (номер и тип связи) есть в составе прочитанного дефекта."""
    linked = linked_pairs(defect)
    targets = loads(row.get("targets_json"), []) or []
    return all(_DIGITS.fullmatch(str(t.get("hub_id") or "")) is not None
               and (int(str(t["hub_id"])), str(t.get("issue_type") or "")) in linked for t in targets)


def _repeat_expected(db: Database, row: dict) -> bool:
    """Подтверждение своей записи строгое: две границы в ответе – текст не выделен. Исключение – в ожидаемом описании блок уже
    повторялся (ADR-0137): строка привязки к такому дефекту ждёт его описание, а не текст приложения."""
    create = db.hub_op(row["create_op_id"]) if row.get("create_op_id") else None
    sent = loads((create or {}).get("request_json"), {}).get("body")
    return block_repeated(sent.get("description") if isinstance(sent, dict) else row.get("body_html"))


def _on_read(db: Database, row: dict, op: dict) -> None:
    if row.get("read_op_id") != op["id"] or row.get("origin") == "import":  # чтение занесения – _on_import (ADR-0124)
        return
    if row["state"] in ("done", "mismatch", "failed"):  # повторная доставка подтверждения: довести последствия
        # доведённые последствия повторяются (идемпотентно), только если нынешний состав строки входит в состав,
        # прочитанный этой операцией: после «Применить» Pull в нём могут быть находки, которых в подтверждённой
        # операции не было, – им отметка от неё не ставится (ревью dev34, круг 6)
        if row.get("confirm_op_id") == op["id"] and (
                not int(row.get("effects_done") if row.get("effects_done") is not None else 1)
                or _targets_within(row, _body(op))):
            _apply_effects(db, row, str(op.get("closed_at") or ""))
        return
    if row["state"] != "created":  # привязка ещё идёт или строка уже в другом состоянии: прежнее чтение не применяется
        return
    mine = ("read_op_id", int(op["id"]))
    if op["state"] != "done":
        db.hub_defect_update(int(row["id"]), expect_state="created", expect_op=mine, state="unknown",
                             error=f"чтение дефекта №{row['hub_defect_id']} не выполнено – нажмите «Pull из Hub»")
        return
    defect = _body(op)
    only_link = not row.get("create_op_id") and not row.get("blank_op_id")  # строка привязки (ADR-0121 п. 5)
    # у строки привязки ответ без состава – не «находок нет», а неразобранный ответ; у строки создания – как в 0.9.22
    # (бэклог 40)
    if (not _has_expected_id(defect, row["hub_defect_id"])
            or (only_link and not isinstance(defect.get("linkedIssues"), list))):
        db.hub_defect_update(int(row["id"]), expect_state="created", expect_op=mine, state="unknown",
                             error="ответ на чтение дефекта не разобран – нажмите «Pull из Hub»")
        return
    if not _has_expected_app(defect, row.get("app_id")):
        db.hub_defect_update(int(row["id"]), expect_state="created", expect_op=mine, state="unknown",
                             error="appId ответа не совпал с приложением операции – нажмите «Pull из Hub»")
        return
    seen = _read_of(defect, _repeat_expected(db, row))
    if seen["text_note"] and not _blank_appended_twice(db, row, defect):
        db.hub_defect_update(int(row["id"]), expect_state="created", expect_op=mine, state="unknown",
                             import_json=dumps(seen), error=seen["text_note"])
        return
    if _unconfirmed_content(db, row, op, mine, defect):
        return
    targets = loads(row.get("targets_json"), [])
    missing = missing_targets(defect, targets)
    composition = composition_diff(row, defect)
    if composition["extra"] or composition["problems"]:
        _unconfirmed_composition(db, row, op, mine, defect)
        return
    if not missing:
        _conclude(db, row, op, mine, "done", VERIFY_NOTE_DONE if row.get("link_op_id") else "")
        return
    ids = ", ".join(str(t.get("hub_id") or t.get("issue_id")) for t in missing)
    if row.get("link_op_id") is None:
        blank = loads(row.get("blank_json"), {}) or {}
        item = dict(purpose="defect_link", request=link_request(str(row["hub_defect_id"]), missing, blank.get("groupId")),
                    hub_url=row["hub_url"], app_id=row.get("app_id"), project_id=int(row["project_id"]),
                    targets=targets, text=str(row.get("summary") or ""), key_extra=f"defect-row:{int(row['id'])}")
        try:
            db.hub_defect_advance(int(row["id"]), expect_state="created", expect_op=mine, item=item,
                                  op_field="link_op_id", state="linking", error="")
        except ValueError as e:
            db.hub_defect_update(int(row["id"]), expect_state="created", expect_op=mine, state="mismatch",
                                 error=f"не привязаны находки {ids}; привязка не поставлена: {e}")
        return
    if only_link and len(missing) == len(targets):
        # строка привязки ведёт себя как строка создания (ADR-0121 п. 5): привязка выполнена, а находки в составе нет –
        # «привязка неполная» ниже (в linkedIssues только Open: отсутствие отвязку не доказывает); привязка с
        # неизвестным исходом и ни одной новой находки в составе – привязка не состоялась: «не принят» одной записью
        # итога, неизвестная операция закрывается в последствиях (_apply_effects; сбой доводят sync и повторная доставка)
        link = db.hub_op(int(row["link_op_id"]))
        if link is not None and link["state"] == "unknown":
            _conclude(db, row, op, mine, "failed", LINK_NOT_DONE.format(defect=row["hub_defect_id"], ids=ids))
            return
    # у строки создания и у строки привязки (в том числе частично подтверждённой) – «привязка неполная» для строки
    # целиком: цели не освобождаются
    _conclude(db, row, op, mine, "mismatch", f"после привязки не привязаны находки {ids}")


def _on_link(db: Database, row: dict, op: dict) -> None:
    if row["state"] != "linking" or row.get("link_op_id") != op["id"]:
        return
    mine = ("link_op_id", int(op["id"]))
    if op["state"] == "done":  # привязка выполнена – переход в created и второе чтение одной транзакцией
        _read_step(db, row, "linking", str(row["hub_defect_id"]), mine)
        return
    if op["state"] == "failed":
        # привязка новой находки к готовому дефекту (ADR-0121 п. 5, строка без заготовки и создания): Hub определённо
        # отказал – в Hub ничего не изменилось, строка «не принят», находки свободны; у созданного дефекта – как раньше
        only_link = not row.get("blank_op_id") and not row.get("create_op_id")
        # отдельная строка привязки: готовый дефект мог быть удалён в Hub – назван ручной путь (бэклог 39)
        manual = (" – если дефект удалён в Hub (проверьте его в Hub или «Синхронизировать» во вкладке «Дефекты»), создайте дефект вручную по панели "
                  "«Дефект для Hub» и нажмите «Отметить: дефект создан в Hub»" if only_link else "")
        db.hub_defect_update(int(row["id"]), expect_state="linking", expect_op=mine,
                             state="failed" if only_link else "mismatch",
                             error=f"привязка находок отклонена: {op.get('error') or 'ошибка'}{manual}")
        return
    db.hub_defect_update(int(row["id"]), expect_state="linking", expect_op=mine, state="unknown",
                         error=f"привязка находок: {op.get('error') or 'ответа нет'} – нажмите «Pull из Hub»")


def _blank_appended_twice(db: Database, row: dict, defect: dict) -> bool:
    """Hub дописал к отправленному описанию (текст и блок заготовки, dev30) ещё раз ровно блок заготовки: две границы
    мешают выделить текст, но описание равно отправленному плюс блок – создание подтверждается (ревью dev30, круг 2);
    иное описание с двумя границами успехом не считается."""
    create = db.hub_op(row["create_op_id"]) if row.get("create_op_id") else None
    sent = loads((create or {}).get("request_json"), {}).get("body")
    blank = str((loads(row.get("blank_json"), {}) or {}).get("description") or "")
    if not isinstance(sent, dict) or not blank.strip():
        return False
    description = str((defect or {}).get("description") or "")
    start = block_start(description, blank)  # дописанный блок – блок заготовки с допуском переформатирования Hub (dev33)
    if start < 0:
        return False
    head = description[:start]  # до дописанного блока – отправленное: текст (с допуском нормализации) и
    if update_content_new({**defect, "description": head}, sent):  # первый блок байт в байт; повтор без разделителя
        return True
    # повтор через один перевод строки (ревью dev30, круг 5): сначала проверяется остаток как есть
    return head.endswith("\n") and update_content_new({**defect, "description": head[:-1]}, sent)


def _unconfirmed_content(db: Database, row: dict, op: dict, expect_op: tuple[str, int], defect: dict,
                         **fields: Any) -> bool:
    """Создание и привязка подтверждают сохранённый снимок, как PUT; несовпадение не назначает последствий."""
    create = db.hub_op(row["create_op_id"]) if row.get("create_op_id") else None
    sent = loads((create or {}).get("request_json"), {}).get("body")
    if not isinstance(sent, dict):  # привязка: неизменяемая копия содержимого родителя на момент постановки
        sent = {"summary": row["summary"], "description": row.get("body_html") or description_html(
            row["command_text"], blank_for_send(row).block)}
    # сверяется всё отправленное описание целиком (ревью A4 31.10); текст – для показа различий
    command, _, _ = split_description(str(sent.get("description") or ""))
    expected = {**sent, "command_text": command}
    levels = level_diffs(sent, defect) if create is not None else []
    if levels:  # уровни и коды создания не подтверждены – не «done» и без отметок (ревью dev11 A3/B3)
        verification = loads(fields.pop("verify_json", row.get("verify_json")), {})
        verification["confirmation"] = {"op_id": op["id"], "sent": sent, "diff": "\n".join(levels)}
        db.hub_defect_update(int(row["id"]), expect_state=row["state"], expect_op=expect_op,
                             state="unconfirmed", verify_op_id=None, import_json=dumps(_read_of(defect)),
                             verify_json=dumps(verification),
                             error="Приоритет или серьёзность не подтверждены чтением.", **fields)
        return True
    if update_content_new(defect, expected):
        return False
    # создание с 0.9.26.dev30 отправляет текст и блок заготовки (dev6–dev29 – только текст); если Hub сам допишет
    # к отправленному ровно блок заготовки, – дефект создан: иначе строка застряла бы в «не подтверждено» без пути
    # исправления (ревью 31.10). Лишние строки покажет сверка. Иное – не подтверждено.
    if create is not None and _blank_appended_twice(db, row, defect):
        return False
    seen = _read_of(defect)
    before = (str(sent.get("summary") or "") + "\n" + command).splitlines()
    after = (seen["summary"] + "\n" + seen["command_text"]).splitlines()
    diff = "\n".join(unified_diff(before, after, fromfile="Отправлено", tofile="Прочитано в Hub", lineterm=""))
    if not diff:  # текст совпал, но исходная подстрока блока Hub изменилась
        diff = "\n".join(unified_diff(str(sent.get("description") or "").splitlines(),
                                     str(defect.get("description") or "").splitlines(),
                                     fromfile="Отправленное описание", tofile="Описание Hub", lineterm=""))
    verification = loads(fields.pop("verify_json", row.get("verify_json")), {})
    verification["confirmation"] = {"op_id": op["id"], "sent": sent, "diff": diff}
    db.hub_defect_update(int(row["id"]), expect_state=row["state"], expect_op=expect_op,
                         state="unconfirmed", verify_op_id=None, import_json=dumps(seen),
                         verify_json=dumps(verification), error="Заголовок или описание не подтверждены чтением.",
                         **fields)
    return True


def _conclude(db: Database, row: dict, op: dict, expect_op: tuple[str, int], state: str, note: str,
              **fields: Any) -> dict | None:
    """Итог чтением (done, mismatch; у строки привязки – и failed): одной записью – состояние, подтверждающая операция и
    «последствия не доведены»;
    затем последствия (_apply_effects) и отметка «доведены». Сбой посередине доводит показ карточки (sync) или
    повторная доставка той же операции."""
    defect = _body(op)
    if not _has_expected_id(defect, fields.get("hub_defect_id", row.get("hub_defect_id"))):
        return db.hub_defect_update(int(row["id"]), expect_state=row["state"], expect_op=expect_op,
                                    state="unknown", verify_op_id=None,
                                    error="ID ответа не совпал с номером дефекта – нажмите «Pull из Hub»", **fields)
    if not _has_expected_app(defect, row.get("app_id")):
        return db.hub_defect_update(int(row["id"]), expect_state=row["state"], expect_op=expect_op,
                                    state="unknown", verify_op_id=None,
                                    error="appId ответа не совпал с приложением операции – нажмите «Pull из Hub»", **fields)
    seen = _read_of(defect, _repeat_expected(db, row))
    if seen["text_note"] and not _blank_appended_twice(db, row, defect):
        return db.hub_defect_update(int(row["id"]), expect_state=row["state"], expect_op=expect_op,
                                    state="unknown", verify_op_id=None,
                                    import_json=dumps(seen), error=seen["text_note"], **fields)
    if _unconfirmed_content(db, row, op, expect_op, defect, **fields):
        return None
    if state == "done" and row.get("origin") != "import" and _unconfirmed_composition(db, row, op, expect_op, defect, **fields):
        return None
    verification = loads(fields.pop("verify_json", row.get("verify_json")), {})
    verification.pop("confirmation", None)
    verification.pop("composition", None)
    fields["verify_json"] = dumps(verification)
    create = db.hub_op(row["create_op_id"]) if row.get("create_op_id") else None
    sent_object = loads((create or {}).get("request_json"), {}).get("body")
    if sent_object:
        fields["update_json"] = dumps({**update_state(row), "sent_object": sent_object})
    fields["import_json"] = dumps(seen)
    if state == "done":
        fields["on_write"] = lambda c, fresh: defect_drafts.confirm(c, fresh, seen, int(op["id"]),
                                                                   loads(row.get("targets_json"), []))
    from app.hub_entity_versions import StaleObservation
    try:
        fresh = db.hub_defect_update(int(row["id"]), expect_state=row["state"], expect_op=expect_op, state=state,
                                     confirm_op_id=int(op["id"]), effects_done=0, verify_op_id=None, error=note, **fields)
    except StaleObservation as exc:
        return db.hub_defect_update(int(row["id"]), expect_state=row["state"], expect_op=expect_op,
                                    state="unconfirmed", verify_op_id=None, error=str(exc))
    if fresh is None:
        return None
    _apply_effects(db, fresh, str(op.get("closed_at") or ""))
    return db.hub_defect(int(fresh["id"])) or fresh


def _apply_effects(db: Database, row: dict, closed_at: str | None = None) -> None:
    """Последствия итога чтением (идемпотентно): «неизвестные» операции создания и привязки закрыты тем, что показало
    чтение (дефект есть – создание выполнено; у done привязка выполнена, у mismatch и failed – нет); у done – отметки
    «Внесено в
    Hub» (не поверх более поздней отметки человека: closed_at подтверждающей операции) и номера ID<n>."""
    if closed_at is None:
        confirm = db.hub_op(int(row["confirm_op_id"])) if row.get("confirm_op_id") else None
        closed_at = str((confirm or {}).get("closed_at") or "")
    done = row["state"] == "done"
    _close_ops(db, row, "done" if done else "failed", VERIFY_NOTE_DONE if done else str(row.get("error") or ""))
    # занесённому из Hub при занесении отметки и номера ключам не ставятся (ADR-0124 п. 5); после подтверждённого
    # обновления текста – ставятся по обычным правилам, только для подтверждённого поколения (ADR-0125 п. 4)
    if done and (row.get("origin") != "import" or update_confirmed(row)):
        apply_marks(db, row, closed_at)
    if row.get("confirm_op_id"):
        db.hub_defect_update(int(row["id"]), expect_op=("confirm_op_id", int(row["confirm_op_id"])), effects_done=1)


def _close_ops(db: Database, row: dict, link_state: str = "done", note: str = VERIFY_NOTE_DONE) -> None:
    """Операции, оставшиеся «результат неизвестен», закрываются тем, что показало чтение: создание – выполнено (дефект
    прочитан), привязка – link_state. Иначе блокировка целей в очереди держалась бы и после итога. У подтверждённого
    обновления занесённого дефекта (ADR-0125) – операции попытки этого поколения (update_op_id и put_op_id): чтение
    показало отправленный текст, запись состоялась."""
    for field, state in (("create_op_id", "done"), ("link_op_id", link_state)):
        op_id = row.get(field)
        if not op_id:
            continue
        op = db.hub_op(int(op_id))
        if op is not None and op["state"] == "unknown":
            db.hub_resolve(int(op_id), state, note if state == link_state else VERIFY_NOTE_DONE)
    if update_confirmed(row):
        state = update_state(row)
        if int((state.get("confirmed") or {}).get("generation") or 0) == int(state.get("generation") or 0):
            for op_id in (row.get("update_op_id"), state.get("put_op_id")):
                op = db.hub_op(int(op_id)) if op_id else None
                if op is not None and op["state"] == "unknown":
                    db.hub_resolve(int(op_id), "done", UPDATE_NOTE_DONE)


def _effect_check(c, row: dict, key: str) -> None:
    targets = loads(row.get("targets_json"), [])
    # у целей без происхождения (схема 28, принятый синхронизацией состав) поколение не сверяется, но принадлежность
    # ключа строке – всегда: прочитанная до принятия отсутствия строка не вернёт снятый номер (ревью 31.10)
    if any(t.get("entered_origin") == "defect" for t in targets) and not defect_drafts.current_effect(c, row):
        raise ValueError("Подтверждённое поколение дефекта изменилось.")
    current = c.execute("SELECT number_keys_json FROM hub_defects WHERE id = ?", (row["id"],)).fetchone()
    if current is None or key not in loads(current["number_keys_json"], []):
        raise ValueError("Ключ больше не принадлежит физической строке дефекта.")


def by_composition(db: Database, row: dict, expect_op: tuple[str, int] | None = None) -> dict:
    """Отметка «Внесено в Hub» – по подтверждённому составу: цели подтверждённой строки,
    у которых отметки ещё нет, а редакция решения с тех пор выросла (оператор сохранил решение заново) или нет
    отпечатка внесённого текста (Push текста как есть при неготовой заготовке набора, 0.9.26.dev15), получают текущую
    редакцию и отпечаток подтверждённого текста строки (и поля отметки дефекта, если их нет: прежний формат целей,
    состав после Pull синхронизации) – отметка ставится им, а не пропускается. Уже отмеченные цели и находки, решение
    по которым уже не «Подтверждаю дефект», не трогаются. Возвращает строку с обновлёнными целями (цели записаны,
    если строка не изменилась). expect_op – (поле, номер операции), которую строка должна всё ещё ждать (после
    «Проверить в Hub» – verify_op_id: устаревший обработчик ничего не переписывает)."""
    targets = loads(row.get("targets_json"), [])
    if row.get("state") != "done" or not row.get("confirm_op_id"):
        return row
    if row.get("origin") == "import" and not update_confirmed(row):
        return row  # занесённому без подтверждённого обновления отметки не ставятся (ADR-0124 п. 5)
    content = text_hash(dumps({"summary": str(row.get("summary") or ""), "command_text": str(row.get("command_text") or "")}))
    owner_id = int(row.get("draft_owner_id") or row["id"])
    out, changed = [], False
    with db._tx() as c:
        for t in targets:
            # цель подтверждённого состава: с полями отметки дефекта (confirm) или без них (прежний формат; состав,
            # переписанный Pull синхронизации, – ревью dev23, круг 1); отметка статуса или ручная – не трогается
            if t.get("entered_origin", "defect") != "defect":
                out.append(t)
                continue
            r = c.execute("SELECT revision, entered_hub, decision, final_verdict FROM reviews WHERE project_id = ? AND hub_id = ?",
                          (int(row["project_id"]), str(t.get("hub_id") or ""))).fetchone()
            # отмеченная цель и находка, решение по которой уже не «дефект» (оператор сменил его на ложное
            # срабатывание, риск или отложил), не трогаются: в Hub ушёл дефект, а не это решение
            if r is None or r["entered_hub"] or hub_verdict(r["decision"] or "", r["final_verdict"] or "") != "true_positive":
                out.append(t)
                continue
            # цель прежнего формата без поля decision_hash держала отпечаток решения в entered_hash: он переносится в
            # decision_hash (как в confirm), отпечаток содержимого – в entered_hash (ревью dev23, круг 2)
            decision = str(t.get("decision_hash", t.get("entered_hash", "")) or "")
            entered = (str(t.get("entered_hash") or "") if "decision_hash" in t else "") or content
            new = {**t, "revision": int(r["revision"] or 0), "decision_hash": decision, "entered_hash": entered,
                   "entered_origin": "defect", "entered_defect_id": int(t.get("entered_defect_id") or owner_id),
                   "entered_op_id": int(t.get("entered_op_id") or row["confirm_op_id"]),
                   "entered_defect_revision": int(t.get("entered_defect_revision") or row.get("draft_revision") or 0)}
            changed = changed or new != t
            out.append(new)
        if not changed:
            return row
        live = c.execute("SELECT * FROM hub_defects WHERE id = ?", (int(row["id"]),)).fetchone()
        if (live is None or live["state"] != "done" or live["confirm_op_id"] != row.get("confirm_op_id")
                or str(live["targets_json"] or "") != str(row.get("targets_json") or "")
                or (expect_op is not None and live[expect_op[0]] != expect_op[1])):
            return row  # строка уже другая: цели не переписываются, отметки – по прежним правилам
        c.execute("UPDATE hub_defects SET targets_json = ? WHERE id = ?", (dumps(out), int(row["id"])))
    return {**row, "targets_json": dumps(out)}


def apply_marks(db: Database, row: dict, closed_at: str = "", only_unmarked: bool = False,
                expect_op: tuple[str, int] | None = None) -> int:
    """Отметки целям (hub_effects.mark_targets: та же редакция, тот же текст – идемпотентно; отметка той же редакции,
    поставленная человеком не раньше closed_at подтверждающего чтения, не перетирается; цели без отметки – по
    подтверждённому составу, by_composition) и номера дефекта: только ключам без номера или с тем же номером, конфликт –
    пометкой в строке (её видно в карточке и во вкладке). only_unmarked – только целям без отметки (после «Проверить в
    Hub»: ручная отметка, поставленная раньше проверки, не перетирается – проверка ничего не записывала); expect_op –
    операция, которую строка должна всё ещё ждать в транзакции каждой отметки (устаревший обработчик проверки после её
    закрытия и снятия отметки оператором ничего не ставит – ревью dev23, круг 2)."""
    from app import hub_effects
    row = by_composition(db, row, expect_op)
    marked = hub_effects.mark_targets(db, {"defect_row": row, "project_id": row["project_id"], "targets_json": row.get("targets_json"),
                                           "closed_at": closed_at, "only_unmarked": only_unmarked, "expect_op": expect_op})
    number = row.get("number")
    if isinstance(number, int) and not isinstance(number, bool) and number > 0:
        clashes = []
        for key in loads(row.get("number_keys_json"), []):
            try:
                other = db.set_defect_number_if_free(int(row["project_id"]), str(key), int(number),
                                                     check=lambda c, key=key: _effect_check(c, row, key))
            except ValueError:
                continue
            if other is not None:
                clashes.append(f"{key} – уже ID{other}")
        if clashes:
            current = db.hub_defect(int(row["id"])) or row
            note = "номер ID" + str(number) + " не записан: " + "; ".join(clashes)
            if note not in str(current.get("error") or ""):
                db.hub_defect_update(int(row["id"]),
                                     error="; ".join(p for p in (str(current.get("error") or ""), note) if p))
    return marked


# ============================================================================ сверка «результата неизвестен»


def list_item(row: dict, page: int) -> dict:
    return dict(purpose="read", request=list_request(int(row["app_id"] or 0), page), hub_url=row["hub_url"],
                app_id=row.get("app_id"), project_id=int(row["project_id"]),
                targets=[{"verify_defect": int(row["id"]), "page": page, "issue_type": "DEFECTS", "issue_id": int(row["id"])}])


def start_verify(db: Database, row: dict, login: str = "") -> dict:
    """«Сверить» у дефекта без подтверждённого номера: первая страница `GET /defects?appId&pageIndex&pageSize`;
    кандидаты с тем же заголовком (и автором) читаются по одному. Постановка и номер текущей операции сверки
    (verify_op_id) – одной транзакцией; идущая сверка – ValueError."""
    state = {"page": 0, "total": 0, "login": str(login or ""), "pending": [], "checked": []}

    def idle(c) -> None:
        if c.execute("SELECT verify_op_id FROM hub_defects WHERE id = ?", (int(row["id"]),)).fetchone()[0]:
            raise ValueError("Сверка уже идёт: дождитесь ответа исполнителя.")

    fresh, op = db.hub_defect_advance(int(row["id"]), expect_state="unknown", check=idle, item=list_item(row, 0),
                                      op_field="verify_op_id", verify_json=dumps(state),
                                      error="сверяю по списку дефектов Hub…")
    if fresh is None:
        raise ValueError("Состояние дефекта изменилось: обновите карточку.")
    return op


def restart_read(db: Database, row: dict) -> dict | None:
    """«Сверить» у дефекта с известным номером: снова чтение `GET /defects/{id}` (переход и постановка – одной
    транзакцией). Отказ очереди – ValueError с её причиной; строка уже не «неизвестен» – None. Так же сверяется неполная
    привязка строки привязки (link_rereadable)."""
    if row["state"] not in ("unknown", "unconfirmed") and not link_rereadable(row):
        return None

    def same(c) -> None:  # другая вкладка могла схлопнуть строку: чтение пустой истории снова заняло бы семью
        current = dict(c.execute("SELECT * FROM hub_defects WHERE id = ?", (int(row["id"]),)).fetchone())
        if row["state"] == "mismatch" and (not link_rereadable(current) or current["targets_json"] != row["targets_json"]):
            raise ValueError("Состояние дефекта изменилось: обновите карточку.")

    fresh, _ = db.hub_defect_advance(int(row["id"]), expect_state=row["state"], check=same, item=read_item(row, row["hub_defect_id"]),
                                     op_field="read_op_id", state="created", error="")
    return fresh


def settle_restored_in(c, ts: str) -> int:
    """После восстановления копии (ADR-0128, п. 9) ничто, бывшее в работе, не ведёт к записи: создание, привязка и `PUT` могли уйти в Hub после
    копии, а база этого не знает. Строка без итога снимается вместе со своими незавершёнными операциями, незавершённая попытка «Push в Hub» – тоже; что
    успело уйти в Hub, занесут синхронизация и принятие её результата (hub_sync.require_resync_in). Возвращает число снятых строк и попыток."""
    unfinished = ("blank", "preview", "creating", "created", "linking", "unknown", "unconfirmed")
    marks = ",".join("?" * len(unfinished))
    rows = c.execute(f"SELECT id, blank_op_id, create_op_id, read_op_id, link_op_id, verify_op_id FROM hub_defects WHERE origin <> 'import' AND state IN ({marks})",
                     unfinished).fetchall()
    for row in rows:
        c.execute("UPDATE hub_defects SET state = 'cancelled', error = ?, updated_at = ?, closed_at = ? WHERE id = ?", (RESTORED_NOTE, ts, ts, row["id"]))
        for field in ("blank_op_id", "create_op_id", "read_op_id", "link_op_id", "verify_op_id"):
            if row[field]:
                c.execute("UPDATE hub_ops SET state = 'cancelled', error = ?, updated_at = ?, closed_at = ? WHERE id = ? AND state IN ('queued', 'taken', 'unknown')",
                          (RESTORED_NOTE, ts, ts, row[field]))
    count = len(rows)
    for row in c.execute("SELECT id, update_json FROM hub_defects WHERE update_json <> ''").fetchall():
        state = loads(row["update_json"], {}) or {}
        if state.get("phase") not in UPDATE_SETTLED:
            count += c.execute("UPDATE hub_defects SET update_op_id = NULL, update_json = ?, updated_at = ? WHERE id = ?",
                               (dumps({**state, "phase": "cancelled", "step": "", "note": RESTORED_PUT_NOTE}), ts, row["id"])).rowcount
    return count


def _verify_state(row: dict) -> dict:
    state = loads(row.get("verify_json"), {}) or {}
    state.setdefault("page", 0)
    state.setdefault("total", 0)
    state.setdefault("login", "")
    state.setdefault("pending", [])
    state.setdefault("checked", [])
    return state


def _stop_verify(db: Database, row: dict, op: dict, state: dict, note: str) -> None:
    """Сверка закончилась без подтверждения: итог словами, verify_op_id снят – опрос карточки останавливается, кнопка
    «Сверить» снова видна. Только если строка ещё ждёт именно эту операцию сверки."""
    db.hub_defect_update(int(row["id"]), expect_state="unknown", expect_op=("verify_op_id", int(op["id"])),
                         verify_op_id=None, verify_json=dumps(state), error=note)


def _on_list(db: Database, op: dict, first: dict) -> None:
    row = db.hub_defect(int(first["verify_defect"]))
    if row is None or row["state"] != "unknown" or row.get("verify_op_id") != op["id"]:
        return  # повторная доставка уже обработанной страницы или сверка закончилась – ничего
    state = _verify_state(row)
    if op["state"] != "done":
        _stop_verify(db, row, op, state, VERIFY_NOTE_FAILED)
        return
    body = _body(op)
    total = body.get("totalEntitiesCount") if isinstance(body, dict) else None
    if (not isinstance(body, dict) or not isinstance(body.get("filteredEntities"), list)
            or isinstance(total, bool) or not isinstance(total, int) or total < 0):
        _stop_verify(db, row, op, state, VERIFY_NOTE_FAILED)  # не разобранный ответ – не «дефекта нет»
        return
    state["page"] = int(first.get("page") or 0)
    state["total"] = total
    pending = []
    for brief in body.get("filteredEntities") or []:
        if not brief_matches(brief, str(row.get("summary") or ""), state["login"]):
            continue
        raw = brief.get("id")
        if isinstance(raw, bool) or not _DIGITS.fullmatch(str(raw)) or str(raw) in state["checked"]:
            continue
        pending.append(str(raw))
    state["pending"] = pending
    _advance(db, row, op, state)


def _advance(db: Database, row: dict, op: dict, state: dict) -> None:
    """Следующий шаг сверки после операции op: очередной кандидат, следующая страница или итог «не найден». Постановка и
    смена текущей операции сверки – одной транзакцией и только если строка ещё ждёт op."""
    mine = ("verify_op_id", int(op["id"]))
    if state["pending"]:
        candidate = state["pending"].pop(0)
        state["checked"].append(candidate)
        item = dict(purpose="defect_read", request=read_request(candidate), hub_url=row["hub_url"],
                    app_id=row.get("app_id"), project_id=int(row["project_id"]),
                    # цель – строка дефекта, не кандидат (как у recheck_item): ключ и блокировка – по строке
                    targets=[{"verify_defect": int(row["id"]), "candidate": candidate, "issue_type": "DEFECT",
                              "issue_id": int(row["id"])}])
        try:
            db.hub_defect_advance(int(row["id"]), expect_state="unknown", expect_op=mine, item=item,
                                  op_field="verify_op_id", verify_json=dumps(state),
                                  error=f"сверяю: читаю дефект №{candidate} из Hub…")
        except ValueError as e:
            _stop_verify(db, row, op, state, f"сверка: чтение кандидата не поставлено: {e}")
        return
    next_page = int(state["page"]) + 1
    if next_page * PAGE_SIZE < int(state["total"]) and next_page < PAGES_MAX:
        state["page"] = next_page
        try:
            db.hub_defect_advance(int(row["id"]), expect_state="unknown", expect_op=mine, item=list_item(row, next_page),
                                  op_field="verify_op_id", verify_json=dumps(state),
                                  error=f"сверяю по списку дефектов Hub: страница {next_page + 1}…")
        except ValueError as e:
            _stop_verify(db, row, op, state, f"сверка: следующая страница не поставлена: {e}")
        return
    _stop_verify(db, row, op, state, VERIFY_NOTE_NONE)


def _on_candidate(db: Database, op: dict, first: dict) -> None:
    row = db.hub_defect(int(first["verify_defect"]))
    if row is None:
        return
    candidate = str(first.get("candidate") or "")
    if row["state"] == "done":  # повторная доставка совпавшего кандидата: довести последствия
        # как в _on_read: доведённые последствия не повторяются для целей вне прочитанного состава
        if row.get("confirm_op_id") == op["id"] and (
                not int(row.get("effects_done") if row.get("effects_done") is not None else 1)
                or _targets_within(row, _body(op))):
            _apply_effects(db, row, str(op.get("closed_at") or ""))
        return
    if row["state"] != "unknown" or row.get("verify_op_id") != op["id"]:
        return
    state = _verify_state(row)
    if op["state"] != "done":
        _stop_verify(db, row, op, state, VERIFY_NOTE_FAILED)
        return
    defect = _body(op)
    if ((isinstance(defect, dict) and not missing_targets(defect, loads(row.get("targets_json"), [])))
            or (isinstance(defect, dict) and hub_ops.normalize_text(defect.get("summary")) == hub_ops.normalize_text(row["summary"])
                and description_matches(defect.get("description"), row["command_text"]))):
        # ID проверяет _conclude: неверный ответ сохраняет номер кандидата для повторного GET.
        _conclude(db, row, op, ("verify_op_id", int(op["id"])), "done", VERIFY_NOTE_DONE, hub_defect_id=candidate,
                  hub_link=defect_link(row["hub_url"], row.get("app_id"), candidate), verify_json=dumps(state))
        return
    if not _has_expected_id(defect, candidate):
        _stop_verify(db, row, op, state, VERIFY_NOTE_FAILED)  # не разобранный ответ – не «кандидат не подошёл»
        return
    _advance(db, row, op, state)


# ============================================================================ «Проверить в Hub» (ADR-0121 п. 6)


def recheck_note(row: dict | None) -> str:
    """Итог последней «Проверить в Hub» строки (хранится в verify_json под ключом recheck); нет – «»."""
    state = loads((row or {}).get("verify_json"), {}) or {}
    return str(state.get("recheck") or "") if isinstance(state, dict) else ""


def recheck_item(row: dict) -> dict:
    """Чтение `GET /defects/{id}` для «Проверить в Hub»: пометка recheck_defect в цели ведёт ответ в _on_recheck, а не в
    цепочку создания. Цель – строка дефекта, а не номер в Hub (как у списка сверки, list_item): ключ операции и
    блокировка – по строке, поэтому проверки одного дефекта из двух строк и чтение того же номера кандидатом сверки
    другой строки друг другу не мешают; номер дефекта – в пути запроса. Исполнитель цели не получает – только метод,
    путь и тело (app/routes/hub.py)."""
    defect_id = str(row["hub_defect_id"])
    return dict(purpose="defect_read", request=read_request(defect_id), hub_url=row["hub_url"], app_id=row.get("app_id"),
                project_id=int(row["project_id"]),
                targets=[{"recheck_defect": int(row["id"]), "issue_type": "DEFECT", "issue_id": int(row["id"])}])


def start_recheck(db: Database, row: dict) -> dict:
    """«Проверить в Hub» у созданного дефекта: чтение ставится, номер операции – в verify_op_id строки, одной
    транзакцией; строка остаётся «создан». Занесён из Hub (ADR-0124 п. 9 – у него «Pull из Hub»), не «создан», без
    номера в Hub или проверка уже идёт – ValueError."""
    if row.get("origin") == "import":
        raise ValueError("«Проверить в Hub» к дефекту, занесённому из Hub, не применяется: у занесённого дефекта – "
                         "«Pull из Hub» во вкладке «Дефекты».")
    if row["state"] != "done" or not row.get("hub_defect_id"):
        raise ValueError("Проверить в Hub можно только созданный дефект с номером в Hub.")

    def idle(c) -> None:
        if c.execute("SELECT verify_op_id FROM hub_defects WHERE id = ?", (int(row["id"]),)).fetchone()[0]:
            raise ValueError("Проверка уже идёт: дождитесь ответа исполнителя.")

    fresh, _ = db.hub_defect_advance(int(row["id"]), expect_state="done", check=idle, item=recheck_item(row),
                                     op_field="verify_op_id")
    if fresh is None:
        raise ValueError("Состояние дефекта изменилось: обновите карточку.")
    return fresh


def _recheck_done(db: Database, row: dict, mine: tuple[str, int], note: str, **fields: Any) -> dict | None:
    state = loads(row.get("verify_json"), {}) or {}
    state = state if isinstance(state, dict) else {}
    state["recheck"] = note
    return db.hub_defect_update(int(row["id"]), expect_state="done", expect_op=mine, verify_op_id=None,
                                verify_json=dumps(state), **fields)


def _on_recheck(db: Database, op: dict, first: dict) -> None:
    """Итог «Проверить в Hub» – сверка (ADR-0121 п. 6; с 0.9.26.dev23 при «проверено» – ещё отметки целям без
    отметки по подтверждённому составу): ответ 404 –
    пояснение «дефект в Hub не найден» (снятие привязки – следующая сборка, бэклог 39); ответ 200 – состав linkedIssues
    (находки со статусом Open, docs/hub-write-plan.md): находки, которых в нём нет, – в пояснении; ответ без
    разбираемого состава – «проверка не выполнена»; все на месте – «проверено». Тайм-аут, отказ, 5xx, неразобранный
    ответ – «проверка не удалась». Каждый шаг – если строка всё ещё ждёт именно этой операции (expect_op): повторная
    доставка и устаревший обработчик ничего не меняют."""
    row = db.hub_defect(int(first["recheck_defect"]))
    if row is None or row["state"] != "done" or row.get("verify_op_id") != op["id"]:
        return
    mine = ("verify_op_id", int(op["id"]))
    result = _result(op)
    if op["state"] != "done":
        try:
            status = int(result.get("status") or 0)
        except (TypeError, ValueError):
            status = 0
        if status == 404 and not result.get("not_sent"):
            _recheck_done(db, row, mine, RECHECK_404)
            return
        _recheck_done(db, row, mine, RECHECK_FAILED.format(reason=op.get("error") or "ответа нет"))
        return
    defect = _body(op)
    if not isinstance(defect, dict):
        _recheck_done(db, row, mine, RECHECK_FAILED.format(reason="ответ не разобран"))
        return
    if not isinstance(defect.get("linkedIssues"), list):  # состава нет – сверять не с чем
        _recheck_done(db, row, mine, RECHECK_NO_LIST)
        return
    missing = missing_targets(defect, loads(row.get("targets_json"), []))
    if not missing:
        # дефект на месте, находки привязаны – целям без отметки ставится отметка «Внесено в Hub» по подтверждённому
        # составу: до закрытия проверки, чтобы сбой довела повторная доставка (строка
        # всё ещё ждёт эту операцию); уже отмеченные цели не трогаются – проверка ничего в Hub не записывала;
        # занесённому без подтверждённого обновления – нет (ADR-0124 п. 5)
        if row.get("origin") != "import" or update_confirmed(row):
            apply_marks(db, row, str(op.get("closed_at") or ""), only_unmarked=True, expect_op=mine)
        _recheck_done(db, row, mine, RECHECK_OK)
        return
    ids = ", ".join(str(t.get("hub_id") or t.get("issue_id")) for t in missing)
    _recheck_done(db, row, mine, RECHECK_MISSING.format(ids=ids))


# ============================================================================ «Занести из Hub» и «Pull из Hub» (ADR-0124)
#
# Только чтение `GET /defects/{id}` через исполнителя: строка import_reading → предпросмотр import_preview → «Занести»
# одной транзакцией (done, origin 'import'); у занесённого – «Pull из Hub» (sync_op_id → предпросмотр в sync_json →
# «Применить» – только добавление). Ни POST, ни отметок «Внесено в Hub», ни номеров ключам находок (defects) ни в одном
# пути: номер ID<n> из заголовка – резерв hub_defects.number. Цель операции – строка дефекта (ключ и блокировка – по
# строке, как у recheck_item), исполнитель получает только метод и путь.

IMPORT_MAX = 20  # номеров дефектов Hub за одно «Занести из Hub»
IMPORT_TYPE = "DEFECT_IMPORT"  # тип цели операции чтения занесения и сверки
IMPORT_BOUNDARY = "Информация об объекте сканирования:"  # граница блока Hub в описании: единственная такая строка
KIND_OF_TYPE = {"SAST": "SAST", "SCA_S": "SCA"}  # тип находки Hub -> вид дефекта; SCA_L и смешанный – не поддерживаются
TYPE_OF_KIND = {kind: issue for issue, kind in KIND_OF_TYPE.items()}
IMPORT_READ_FAILED = "чтение не удалось – повторите"
IMPORT_SHOWN_CHANGED = "Предпросмотр изменился (другая вкладка или новое чтение): обновите страницу."
IMPORT_CHANGED = ("Состав изменился – обновите предпросмотр ({why}): нажмите «Отменить», затем «Синхронизировать» на "
                  "вкладке «Дефекты» и «Принять состояние Hub» – приложение прочитает дефект снова.")
SYNC_CHANGED = "Состав изменился после сверки ({why}): нажмите «Pull из Hub» ещё раз."
SYNC_UNOBSERVED = "в Hub больше не связана с дефектом (или её статус не Open) – уберётся из состава"
SYNC_INCOMPATIBLE = "несовместима с видом дефекта"
NOT_IN_EXPORT = "нет в текущей выгрузке"
_DEFECT_REF = re.compile(r"/defects/([0-9]{1,12})(?![0-9])")
# пометка рецензента в начале заголовка – в скобках; скобка, всё содержимое которой – ID<число> («[ID3] …»,
# «(ID3) …»), – номер, а не пометка: не снимается
_REVIEWER_MARK = re.compile(r"^\s*(?:\[(?!\s*ID[0-9]+\s*\])[^\]]*\]|\((?!\s*ID[0-9]+\s*\))[^)]*\))\s*")
_TITLE_ID = re.compile(r"(?<![0-9A-Za-z])ID([0-9]{1,6})(?![0-9])")
_NUMBER = re.compile(r"(?<![0-9])[0-9]{1,12}(?![0-9])")
# поля DefectDto по ответу Hub (ADR-0124 п. 9): автор – объект author (берётся login), время изменения – updateTs,
# создания – createTs (целые, миллисекунды эпохи); прочие имена – запасные, берётся первое найденное. createTs запасным
# для «изменён» не служит: это время создания, оно хранится отдельно
_AUTHOR_KEYS = ("author", "createdBy", "creator", "owner", "reporter")
_MODIFIED_KEYS = ("updateTs", "updatedAt", "updated", "modifiedAt", "modified", "lastModified", "changedAt",
                  "updateDate")
_CREATED_KEYS = ("createTs",)
_BLOCKS = frozenset({"p", "div", "h1", "h2", "h3", "h4", "h5", "h6", "blockquote", "pre", "table", "tr", "section",
                     "article", "header", "footer"})


def import_numbers(text: str) -> list[str]:
    """Номера дефектов Hub из поля «Занести из Hub»: числа или ссылки на дефект (число после `/defects/`) через
    пробел, запятую, точку с запятой или с новой строки; повторы (число и ссылка на тот же дефект) – один раз; не больше
    IMPORT_MAX. Иначе ValueError с понятным текстом."""
    out: list[str] = []
    for token in (t for t in re.split(r"[\s,;]+", str(text or "")) if t):
        if _DIGITS.fullmatch(token):
            number = str(int(token))
        else:
            found = _DEFECT_REF.search(token)
            if found is None:
                shown = token if len(token) <= 80 else token[:79] + "…"
                raise ValueError(f"«{shown}» – не номер дефекта Hub и не ссылка на дефект (…/defects/<номер>).")
            number = str(int(found.group(1)))
        if number == "0":
            raise ValueError("Номер дефекта Hub – целое число больше нуля.")
        if number not in out:
            out.append(number)
    if not out:
        raise ValueError("Укажите номера дефектов Hub или ссылки на них.")
    if len(out) > IMPORT_MAX:
        raise ValueError(f"За один раз – не больше {IMPORT_MAX} дефектов Hub (указано {len(out)}).")
    return out


def import_item(row: dict, defect_id: str, sync: bool = False) -> dict:
    """Операция чтения `GET /defects/{id}` для занесения (цель import_defect) или «Pull из Hub» (import_sync); цель –
    строка дефекта (тип DEFECT_IMPORT): свой ключ и блокировка на строку."""
    key = "import_sync" if sync else "import_defect"
    return dict(purpose="defect_read", request=read_request(str(defect_id)), hub_url=row["hub_url"],
                app_id=row.get("app_id"), project_id=int(row["project_id"]),
                targets=[{key: int(row["id"]), "issue_type": IMPORT_TYPE, "issue_id": int(row["id"])}])


# ---------------------------------------------------------------------------- разбор описания и заголовка


EMPTY_CELL = "(пусто)"
CELL_MARK = "\x1f"  # начало ячейки в единицах сравнения: перенос строки из ячейки в ячейку – правка


class _DescriptionLines(HTMLParser):
    """Строки описания дефекта Hub по его разметке: абзацы и блоки – через пустую строку, `<br>` – новая строка (два
    подряд – пустая), пункты `<ol>` – «N) …», `<ul>` – «- …», ссылка – «текст (адрес)» (адрес один раз, если текст и
    есть адрес; ссылка через `<br>` – текст по строкам, адрес после её конца), сущности раскрыты, содержимое script и
    style не берётся. Блок внутри открытого списка (`<li><p>…</p></li>`, `<li><div>`) – мягкий перенос: строка, где
    только что поставлен маркер пункта, не обрывается, конец блока завершает строку без пустой; `<br>` сразу после
    маркера (`<li><br>…`) строку тоже не обрывает. Маркер – только тот, что поставил `<li>`: текст «-» или «1)» из
    данных – обычная строка. Вложенный список внутри открытого – без пустых строк (пустая – только у списка верхнего
    уровня)."""

    def __init__(self, cells: bool = False, units: bool = False) -> None:
        super().__init__(convert_charrefs=True)
        self.lines: list[str] = []
        self._cur: list[str] = []
        self._lists: list[list] = []
        self._cells = cells  # только показ оператору: ячейки строки таблицы через « | », сравнения идут без этого
        self._units = units  # только сравнение служебного блока: каждая ячейка – своя строка
        self._row_cells = 0
        self._cell_gap = False
        self._cell_data = False
        self._links: list[tuple[str, int]] = []
        self._skip = 0
        self._fresh = False  # в текущей строке только что поставлен маркер пункта, текста после него ещё нет
        # строка начиналась с отступа (пробел, табуляция, неразрывный пробел) до нормализации – для LAYOUT_KEPT
        self.indented = False
        self._marker = ""  # маркер пункта, поставленный <li> в текущей строке

    def _only_marker(self) -> bool:
        """В текущей строке – ничего или только что поставленный маркер пункта: блочный тег не отрывает от него текст
        пункта."""
        return self._fresh or not "".join(self._cur).strip()

    def _block(self) -> None:
        """Начало или конец блока: вне списка – граница абзаца; внутри открытого списка – мягкий перенос."""
        if not self._lists:
            self._flush(gap=True)
        elif not self._only_marker():
            self._flush()

    def _flush(self, gap: bool = False) -> None:
        raw = "".join(self._cur)
        text = " ".join(raw.split())
        if self._marker and raw.startswith(self._marker):  # отступ – после маркера пункта (ревью Kimi круга 6)
            raw = raw[len(self._marker):]
        self._marker = ""
        # перевод строки и пробелы разметки отступом не считаются, неразрывный пробел после перевода строки разметки –
        # считается (`<p>\n<strong>&nbsp;…`, ревью Codex круга 7)
        if text and (raw[:1] in (" ", "\t", "\xa0") or raw.lstrip("\r\n")[:1] == "\xa0"):
            self.indented = True
        self._cur = []
        self._fresh = False
        # открытая ссылка продолжается в новой строке: её текст – с начала строки (иначе начало указывало бы в старую)
        self._links = [(href, 0) for href, _ in self._links]
        if text:
            self.lines.append(text)
        if gap and self.lines and self.lines[-1] != "":
            self.lines.append("")

    def handle_starttag(self, tag: str, attrs: list) -> None:
        if tag in ("td", "th"):
            self._cell_data = False
        if tag == "tr":
            self._row_cells = 0
        elif tag in ("td", "th") and self._units:
            self._flush()
            self.lines.append(CELL_MARK)
        elif tag in ("td", "th") and self._cells:
            self._cell_gap = self._row_cells > 0  # разделитель – перед текстом следующей ячейки, если он в той же строке
            self._row_cells += 1
        if tag in ("script", "style"):
            self._skip += 1
        elif tag == "br":
            current = "".join(self._cur).strip()
            if self._lists and current and self._fresh:
                pass  # `<li><br>…` – маркер пункта не отрывается от текста пункта (ADR-0124 п. 9)
            elif current:
                self._flush()
            elif self.lines and self.lines[-1] != "":
                self.lines.append("")
        elif tag in _BLOCKS:
            self._block()
        elif tag in ("ol", "ul"):
            if self._lists:  # вложенный список внутри открытого – без пустой строки
                self._flush()
            else:
                self._flush(gap=True)
                # «Рекомендация:» абзацем перед списком – одна группа с пунктами (так её пишет command_html)
                if len(self.lines) >= 2 and self.lines[-1] == "" and self.lines[-2].endswith(":"):
                    self.lines.pop()
            self._lists.append([tag, 0])
        elif tag == "li":
            self._flush()
            kind, n = "ul", 0
            if self._lists:
                self._lists[-1][1] += 1
                kind, n = self._lists[-1]
            self._marker = f"{n}) " if kind == "ol" else "- "
            self._cur.append(self._marker)
            self._fresh = True
        elif tag == "a":
            self._links.append((str(dict(attrs).get("href") or "").strip(), len("".join(self._cur))))

    def handle_endtag(self, tag: str) -> None:
        if tag in ("td", "th") and (self._units or self._cells) and not self._cell_data:
            self.handle_data(EMPTY_CELL)  # пустая ячейка – тоже место в строке: значение могли перенести в неё
        if tag in ("td", "th") and self._units:
            self._flush()
        if tag in ("script", "style"):
            self._skip = max(0, self._skip - 1)
        elif tag == "a" and self._links:
            href, start = self._links.pop()
            label = " ".join("".join(self._cur)[start:].split())
            if href and not label:
                self._cur.append(href)
                self._fresh = False
            elif href and label != href:
                self._cur.append(f" ({href})")
        elif tag in ("ol", "ul"):
            self._flush(gap=len(self._lists) <= 1)  # пустая строка – только после списка верхнего уровня
            if self._lists:
                self._lists.pop()
        elif tag == "li":
            self._flush()
        elif tag in _BLOCKS:
            self._block()

    def handle_data(self, data: str) -> None:
        if not self._skip:
            if data.strip():
                self._cell_data = True
            if self._cell_gap and data.strip():
                self._cell_gap = False
                if "".join(self._cur).strip():
                    self._cur.append(" | ")
            self._cur.append(data)
            if data.strip():
                self._fresh = False

    def result(self) -> list[str]:
        self.close()
        self._flush()
        out: list[str] = []
        for line in self.lines:
            if line == "" and (not out or out[-1] == ""):
                continue
            out.append(line)
        while out and out[-1] == "":
            out.pop()
        return out


def description_for_reading(value: Any) -> list[str]:
    """Описание дефекта Hub строками для чтения оператором: как description_lines, но ячейки таблицы разделены."""
    text = str(value or "")
    if "<" not in text:
        return description_lines(text)
    parser = _DescriptionLines(cells=True)
    parser.feed(text)
    return parser.result()


def description_lines(value: Any) -> list[str]:
    """Описание дефекта Hub (HTML) -> строки текста по разметке (_DescriptionLines); пустая строка – граница абзаца.
    Описание без разметки – по строкам как есть."""
    text = str(value or "")
    if "<" not in text:
        lines = [" ".join(html.unescape(line).split()) for line in text.replace("\r\n", "\n").split("\n")]
        out: list[str] = []
        for line in lines:
            if line or (out and out[-1]):
                out.append(line)
        while out and not out[-1]:
            out.pop()
        return out
    parser = _DescriptionLines()
    parser.feed(text)
    return parser.result()


def split_description(value: Any, repeated: bool = True) -> tuple[str, list[str], str]:
    """(текст дефекта, строки ниже «Информация об объекте сканирования:», пояснение). Описание
    в Hub – только текст из приложения: «Push в Hub» записывает его без блока Hub. Поэтому описание без этой
    строки – целиком текст дефекта (до 0.9.26.dev4 – «текст не выделен»). Одна такая строка – текст выше неё, строки
    ниже показываются отдельно и сверка их называет; несколько – текст не выделен (ADR-0124 п. 4)."""
    lines = description_lines(value)
    if IMPORT_BOUNDARY not in lines:
        return "\n".join(lines).strip("\n"), [], ""
    return split_at_hub_block(value, repeated)


def _same_lines(a: list[str], b: list[str]) -> bool:
    """Два списка строк разметки совпадают без пустых строк по краям и с нормализацией пробелов."""
    def trim(lines: list[str]) -> list[str]:
        out = [hub_ops.normalize_text(line) for line in lines]
        while out and not out[0]:
            out.pop(0)
        while out and not out[-1]:
            out.pop()
        return out
    return trim(a) == trim(b)


def description_units(value: Any) -> list[str]:
    """Описание единицами текста для сравнения служебного блока: абзац, строка после `<br>`, ячейка таблицы; пустых нет. Hub перекладывает
    разметку (отступы между ячейками, абзац внутри ячейки, `<br>` вместо абзаца, выделение в строке), сравнение от этого не меняется.
    Текст, адреса ссылок и то, в какой ячейке стоит значение, сравниваются полностью."""
    text = str(value or "")
    if "<" not in text:
        return [line for line in description_lines(text) if line]
    parser = _DescriptionLines(units=True)
    parser.feed(text)
    return [line for line in parser.result() if line]


def _same_apart_from_version(value: Any) -> bool:
    """Два блока одинаковы, если не считать значений версии в формах Hub (ADR-0132): заготовка дописана к блоку с целевой версией."""
    units = description_units(hub_block_version.masked(str(value or "")))
    found = [i for i, line in enumerate(units) if line == IMPORT_BOUNDARY]
    return len(found) == 2 and units[found[0] + 1:found[1]] == units[found[1] + 1:]


def split_at_hub_block(value: Any, repeated: bool = False) -> tuple[str, list[str], str]:
    """Деление по единственной строке «Информация об объекте сканирования:» – (текст до неё, строки после,
    пояснение); её нет или несколько – текст не выделен. Нужно и допуску подтверждения своей записи: Hub может сам
    дописать свой блок ниже текста. repeated – чтение чужого описания (ADR-0137): строк несколько – текст до первой, всё
    ниже неё блок; подтверждение своей записи идёт строго, кроме записи, где блок повторялся уже в отправленном."""
    lines = description_lines(value)
    at = [i for i, line in enumerate(lines) if line == IMPORT_BOUNDARY]
    if not repeated and len(at) == 2 and _same_apart_from_version(value):
        # Hub дописал блок заготовки второй раз к описанию, которое уже несло его (dev30, ревью круг 2): текст – до
        # первой границы, блок – один
        lines = lines[:at[1]]
        at = at[:1]
    if repeated:
        at = at[:1]
    if len(at) != 1:
        why = (f"в описании нет строки «{IMPORT_BOUNDARY}»" if not at
               else f"строка «{IMPORT_BOUNDARY}» в описании встречается {len(at)} раза")
        return "", [], why + " – текст команды не выделен"
    block = lines[at[0] + 1:]
    while block and not block[0]:
        block.pop(0)
    return "\n".join(lines[:at[0]]).strip("\n"), block, ""


NO_NUMBER = "в заголовке нет номера ID<n>"
NUMBER_RETURNED = "В заголовке нет номера ID: приложение возвращает его (ID{number})."


def title_number(summary: Any) -> tuple[int | None, str]:
    """Номер ID<n> из заголовка дефекта Hub (ADR-0124 п. 4): после снятия пометок рецензента в начале (в скобках;
    скобка из одного «ID<число>» – номер, не пометка) – первое «ID<число>»; разные номера – неоднозначен, номер не
    берётся. (номер или None, пояснение)."""
    title = str(summary or "")
    while True:
        mark = _REVIEWER_MARK.match(title)
        if mark is None or not mark.group(0):
            break
        title = title[mark.end():]
    numbers = list(dict.fromkeys(int(n) for n in _TITLE_ID.findall(title) if int(n) > 0))
    if not numbers:
        return None, NO_NUMBER
    if len(numbers) > 1:
        return None, ("номер ID в заголовке неоднозначен (" + ", ".join(f"ID{n}" for n in numbers)
                      + ") – номер не берётся")
    return numbers[0], ""


def import_kind(pairs: list[tuple[int, str]], summary: Any) -> tuple[str, str]:
    """Вид дефекта по полному прочитанному составу (ADR-0124 п. 4): все SAST – SAST, все SCA_S – SCA; SCA_L или
    смешанные типы – не поддерживается. Состав пуст – по окончанию заголовка «(SAST)» / «(SCA)», нет его – вид не
    определён. (вид или «», пояснение)."""
    types = {t for _, t in pairs}
    if types:
        if len(types) == 1 and next(iter(types)) in KIND_OF_TYPE:
            return KIND_OF_TYPE[next(iter(types))], ""
        return "", ("вид не поддерживается: в составе находки типов " + ", ".join(sorted(t or "«»" for t in types))
                    + " – занесение недоступно")
    title = hub_ops.normalize_text(summary)
    for kind in ("SAST", "SCA"):
        if title.endswith(f"({kind})"):
            return kind, ""
    return "", "состав пуст, а заголовок не кончается на «(SAST)» или «(SCA)» – вид не определён, занесение недоступно"


def _first_value(defect: dict, keys: tuple[str, ...]) -> str:
    for key in keys:
        value = defect.get(key)
        if isinstance(value, dict):
            value = value.get("login") or value.get("name") or value.get("username")
        if isinstance(value, (str, int)) and not isinstance(value, bool) and str(value).strip():
            return str(value).strip()[:200]
    return ""


def epoch_ms_iso(value: Any) -> str:
    """Время Hub в миллисекундах эпохи (целое, как updateTs и createTs в DefectDto) -> ISO UTC
    «2026-10-27T21:20:00+00:00» (для фильтра |ts); не целое, не больше нуля или вне диапазона дат – «»."""
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        return ""
    try:
        return datetime.fromtimestamp(value / 1000, UTC).isoformat(timespec="seconds")
    except (OverflowError, OSError, ValueError):
        return ""


def _time_value(defect: dict, keys: tuple[str, ...]) -> str:
    """Первое разобранное время из keys – всегда ISO UTC или «» (фильтр |ts режет строку по позициям): целое –
    миллисекунды эпохи (epoch_ms_iso), строка – ISO с часовым поясом, приведённое к UTC; прочее пропускается."""
    for key in keys:
        value = defect.get(key)
        out = ""
        if isinstance(value, int) and not isinstance(value, bool):
            out = epoch_ms_iso(value)
        elif isinstance(value, str) and value.strip():
            try:
                moment = datetime.fromisoformat(value.strip())
            except ValueError:
                moment = None
            if moment is not None and moment.tzinfo is not None:
                out = moment.astimezone(UTC).isoformat(timespec="seconds")
        if out:
            return out
    return ""


def import_answer(op: dict, row: dict) -> tuple[dict | None, str]:
    """Проверка ответа чтения (ADR-0124 п. 3): 200 с объектом, `id` равен запрошенному, `appId` равен приложению
    проекта (строки), `linkedIssues` – список (пустой допустим). (дефект, «») или (None, причина)."""
    number = str(row.get("hub_defect_id") or "")
    result = _result(op)
    if op["state"] != "done":
        try:
            status = int(result.get("status") or 0)
        except (TypeError, ValueError):
            status = 0
        if status == 404 and not result.get("not_sent"):
            return None, f"дефекта №{number} нет в Hub (404)"
        return None, f"{IMPORT_READ_FAILED} ({op.get('error') or 'ответа нет'})"
    defect = _body(op)
    if not isinstance(defect, dict):
        return None, "ответ Hub не разобран (не объект JSON) – повторите чтение"
    raw_id = defect.get("id")
    if isinstance(raw_id, bool) or not _DIGITS.fullmatch(str(raw_id)) or str(int(str(raw_id))) != number:
        return None, f"Hub вернул другой дефект (№{raw_id} вместо №{number}) – не заносится"
    raw_app = defect.get("appId")
    if (isinstance(raw_app, bool) or not _DIGITS.fullmatch(str(raw_app))
            or int(str(raw_app)) != int(row.get("app_id") or 0)):
        return None, (f"дефект №{number} – не из приложения Hub проекта (appId {raw_app}, у проекта "
                      f"{row.get('app_id')}) – не заносится")
    if not isinstance(defect.get("linkedIssues"), list):
        return None, "состав не прочитан: в ответе Hub нет списка linkedIssues – повторите чтение"
    return defect, ""


def block_repeated(description: Any) -> bool:
    """В описании граница служебного блока встречается больше одного раза (ADR-0137)."""
    return description_lines(description).count(IMPORT_BOUNDARY) > 1


def _read_of(defect: dict, repeated: bool = True) -> dict:
    """Снимок чтения: заголовок, исходное описание HTML, автор (author.login), время изменения (updateTs) и создания
    (createTs) – ISO UTC, полный состав linkedIssues с типами и разбор (вид, номер ID<n>, текст команды)."""
    summary = str(defect.get("summary") or "")
    pairs = sorted(linked_pairs(defect))
    command, hub_lines, text_note = split_description(defect.get("description"), repeated)
    number, number_note = title_number(summary)
    kind, kind_note = import_kind(pairs, summary)
    return {"object": defect, "defect_id": str(int(str(defect.get("id")))), "summary": summary,
            "description": str(defect.get("description") or ""), "author": _first_value(defect, _AUTHOR_KEYS),
            "modified": _time_value(defect, _MODIFIED_KEYS), "created": _time_value(defect, _CREATED_KEYS),
            "linked": [[i, t] for i, t in pairs], "kind": kind,
            "kind_note": kind_note, "number": number, "number_note": number_note, "command_text": command,
            "text_note": text_note, "hub_numbers": sorted({n for line in hub_lines for n in _NUMBER.findall(line)})}


def _holder_why(holder: dict, row: dict) -> str:
    """Почему находка не входит: она уже цель живой строки приложения – с указанием строки."""
    label = bound_label(holder)
    state = STATE_LABELS.get(holder["state"], holder["state"])
    if (str(holder.get("hub_defect_id") or "") == str(row.get("hub_defect_id") or "")
            and str(holder.get("hub_url") or "") == str(row.get("hub_url") or "")
            and int(holder.get("app_id") or 0) == int(row.get("app_id") or 0)):
        return f"уже в строке этого же дефекта Hub (строка {holder['id']}, «{state}»)"
    if holder["state"] in ("done", "mismatch") and holder.get("hub_defect_id"):
        return f"уже в другом дефекте {label} (строка {holder['id']})"
    return f"уже в незавершённой операции дефекта{' ' + label if label else ''} (строка {holder['id']}, «{state}»)"


def _versions_warning(found: dict[str, dict], hub_ids: list[str]) -> str:
    """У SCA – разные версии или компоненты среди находок дефекта: предупреждение (решение – после занесения)."""
    seen = list(dict.fromkeys(f"{found[h]['component']} {found[h]['version']}".strip() for h in hub_ids
                              if h in found and found[h]["kind"] == "SCA"))
    return ("находки разных версий: " + ", ".join(seen) + " – решение по такому дефекту – после занесения"
            if len(seen) > 1 else "")


def _hints(db: Database, row: dict, read: dict) -> list[str]:
    """Номера находок проекта из блока Hub, не привязанные в ответе (в linkedIssues – только находки со статусом Open) –
    только подсказка."""
    linked = {str(i) for i, _ in read.get("linked") or []}
    named = sorted(db.hub_ids_among(int(row["project_id"]), read.get("hub_numbers") or []) - linked, key=int)
    if not named:
        return []
    return ["в блоке Hub названы находки " + ", ".join(named) + ", которых нет в составе ответа (в составе – только "
            "находки со статусом Open): проверьте их в Hub, приложение их не добавляет"]


def import_snapshot(db: Database, row: dict, defect: dict, closed_at: str = "") -> dict:
    """Предпросмотр занесения (ADR-0124 п. 4): снимок чтения и сопоставление пар (номер, тип) с находками текущей
    выгрузки проекта по точному типу – принимаемые, отсутствующие в выгрузке, конфликтующие (уже цель живой строки
    приложения, с указанием строки); предупреждения (вид, номер, текст команды, разные версии SCA) и подсказки."""
    read = _read_of(defect)
    pid = int(row["project_id"])
    ids = [str(i) for i, _ in read["linked"]]
    found = db.import_findings(pid, ids)
    accepted, absent, conflicts = [], [], []
    for issue_id, issue_type in read["linked"]:
        hub_id = str(issue_id)
        f = found.get(hub_id)
        if f is None or f["missing"] or hub_status.HUB_ISSUE_TYPE.get(f["kind"]) != issue_type:
            absent.append({"hub_id": hub_id, "issue_type": issue_type, "why": NOT_IN_EXPORT})
            continue
        holder = db.hub_defect_holder(pid, hub_id, exclude_id=int(row["id"]))
        if holder is not None:
            conflicts.append({"hub_id": hub_id, "issue_type": issue_type, "why": _holder_why(holder, row),
                              "row": int(holder["id"])})
            continue
        accepted.append({"hub_id": hub_id, "issue_id": int(issue_id), "issue_type": issue_type})
    warnings = [note for note in (read["kind_note"], read["number_note"], read["text_note"],
                                  _versions_warning(found, [x["hub_id"] for x in accepted + conflicts])) if note]
    return {**read, "accepted": accepted, "absent": absent, "conflicts": conflicts, "warnings": warnings,
            "hints": _hints(db, row, read), "read_at": str(closed_at or "")}


def own_number_keys(db: Database, row: dict, entries: Any, unexported: Any = ()) -> set[str]:
    """Ключи номера собственных находок строки: SAST – «sast:<ID>», SCA – ключ набора находки
    (Database.defect_keys_of_findings) – их номер не «занят другим» (ADR-0124 п. 9). Собственные – цели (entries –
    записи с hub_id) и связанные в Hub с этим дефектом находки, которых не было в выгрузке на момент чтения
    (unexported – записи снимка с причиной NOT_IN_EXPORT: нет в базе, missing или другой тип): своя, если сейчас есть в
    базе, тип тот же и её не держит другая строка – в том числе вернувшаяся в выгрузку после предпросмотра. Названные
    только в блоке Hub, конфликтующие и другого типа – не свои."""
    return db.on_connection(lambda c: own_number_keys_in(c, row, entries, unexported))


def own_number_keys_in(c, row: dict, entries: Any, unexported: Any = ()) -> set[str]:
    """own_number_keys на соединении c – транзакция постановки `PUT` (ADR-0125 п. 2) повторяет проверку номера там же,
    где пишет."""
    pid = int(row["project_id"])
    ids = [str((e or {}).get("hub_id") or "") for e in entries or []]
    gone = [e for e in unexported or () if isinstance(e, dict) and e.get("why") == NOT_IN_EXPORT]
    found = Database.import_findings_in(c, pid, [str(e.get("hub_id") or "") for e in gone])
    for entry in gone:
        hub_id = str(entry.get("hub_id") or "")
        f = found.get(hub_id)
        if (f is not None and hub_status.HUB_ISSUE_TYPE.get(f["kind"]) == entry.get("issue_type")
                and Database.hub_defect_holder_in(c, pid, hub_id, exclude_id=int(row.get("id") or 0)) is None):
            ids.append(hub_id)
    return Database.defect_keys_of_findings_in(c, pid, ids)


def release_number_in(c, row: dict, number: Any, keys: Any, own: Any) -> list[str]:
    """Снять номер ID<number> дефекта row с ключей keys: только ключи, у которых сейчас этот номер, не свои (own – ключи
    собственных находок) и не числятся ключами номера другой записи; если тот же номер резервирует другая запись –
    ничего не снимается. Номер, поставленный карточкой находки без записи дефекта, этим не задевается: keys – ключи
    находок, ушедших из этого дефекта, или показанные оператору в карточке дефекта."""
    pid = int(row["project_id"])
    if not isinstance(number, int) or isinstance(number, bool) or number <= 0:
        return []
    owner_id = int(row.get("draft_owner_id") or row["id"])
    family = {int(r["id"]) for r in c.execute("SELECT id FROM hub_defects WHERE COALESCE(draft_owner_id, id) = ?", (owner_id,))}
    if any(int(r["id"]) not in family for r in Database.hub_defects_with_number_in(c, pid, number)):
        return []
    # ключи держат только действующие записи: отменённый предпросмотр и неудавшаяся попытка – нет (ревью 31.10)
    claimed = {k for r in c.execute("SELECT number_keys_json FROM hub_defects WHERE project_id = ?"
                                    " AND COALESCE(draft_owner_id, id) <> ? AND state NOT IN ('failed', 'cancelled', 'deleted')",
                                    (pid, owner_id))
               for k in loads(r["number_keys_json"], [])}
    holding = set(Database.defect_keys_with_number_in(c, pid, number))
    released = sorted(k for k in set(keys) if k in holding and k not in set(own) and k not in claimed)
    for key in released:
        c.execute("DELETE FROM defects WHERE project_id = ? AND defect_key = ? AND number = ?", (pid, key, number))
    return released


def number_releases_in(c, row: dict) -> int:
    """Сколько раз с семьи записи снимали номер кнопкой карточки: форма несёт это число, повтор старой формы после
    снятия – отказ (время выдачи номера – с точностью до секунды и повторную выдачу не отличает)."""
    owner_id = int(row.get("draft_owner_id") or row["id"])
    return sum(1 for r in c.execute("SELECT details_json FROM hub_defect_history WHERE defect_id = ? AND event = 'edit'",
                                    (owner_id,)) if "released_number" in loads(r["details_json"], {}))


def family_targets_in(c, row: dict) -> list[dict]:
    """Цели всей семьи записи (владелец и строки привязки), кроме неудавшихся, – состав, как его показывает карточка."""
    owner_id = int(row.get("draft_owner_id") or row["id"])
    return [t for r in c.execute("SELECT targets_json FROM hub_defects WHERE COALESCE(draft_owner_id, id) = ?"
                                 " AND state NOT IN ('failed', 'cancelled', 'deleted')", (owner_id,))
            for t in loads(r["targets_json"], [])]


def foreign_number_keys(db: Database, row: dict) -> list[dict]:
    """Ключи с номером ID<n> строки вне состава её семьи – «номер занят другим» (кнопка в карточке дефекта): ключ и время
    выдачи номера (форма снимает именно это назначение)."""
    number = row.get("number")
    if not isinstance(number, int) or isinstance(number, bool) or number <= 0:
        return []

    def read(c):
        own = own_number_keys_in(c, row, family_targets_in(c, row))
        return [{"key": r["defect_key"], "assigned_at": r["assigned_at"]} for r in c.execute(
            "SELECT defect_key, assigned_at FROM defects WHERE project_id = ? AND number = ? ORDER BY defect_key",
            (int(row["project_id"]), number)) if r["defect_key"] not in own]
    return db.on_connection(read)


def number_note(db: Database, row: dict, number: int | None, own_keys: Any = ()) -> str:
    """Занят ли номер ID<n> другим в приложении – ключами находок в defects, кроме own_keys (ключи собственных находок
    строки – own_number_keys), и резервами других строк hub_defects – справочно; при занесении и «Применить» –
    пояснение о конфликте в строке (ADR-0124 п. 5, 9)."""
    return db.on_connection(lambda c: number_note_in(c, row, number, own_keys))


def number_note_in(c, row: dict, number: int | None, own_keys: Any = ()) -> str:
    """Пояснение занятости номера на соединении проверки и записи строки."""
    if not isinstance(number, int) or isinstance(number, bool) or number <= 0:
        return ""
    pid = int(row["project_id"])
    parts = []
    own = {str(k) for k in own_keys or ()}
    keys = [k for k in Database.defect_keys_with_number_in(c, pid, number) if k not in own]
    if keys:
        parts.append("находки: " + ", ".join(keys[:5]) + (f" и ещё {len(keys) - 5}" if len(keys) > 5 else ""))
    family = family_ids_in(c, row) if row.get("id") else set()
    others = [o for o in Database.hub_defects_with_number_in(c, pid, number, exclude_id=int(row["id"]))
              if int(o["id"]) not in family]  # строки привязки того же дефекта – свои (ревью dev34, круг 1)
    for other in others[:5]:
        parts.append(f"дефект {bound_label(other) or 'из карточки'} (строка {other['id']})")
    if not parts:
        return ""
    return f"номер ID{number} уже занят в приложении ({'; '.join(parts)}) – это номер из заголовка Hub, он остаётся резервом"


def _on_import(db: Database, op: dict, first: dict) -> None:
    """Ответ чтения занесения (ADR-0124 п. 3): только если строка ещё import_reading и ждёт именно этой операции
    (expect_state, expect_op) – повторная и поздняя доставка ничего не меняют. Ответ не прошёл проверку, аренда истекла
    или исхода нет – «не принят» с причиной; иначе – предпросмотр import_preview. Ни записей в Hub, ни отметок."""
    row = db.hub_defect(int(first["import_defect"]))
    if (row is None or row.get("origin") != "import" or row["state"] != "import_reading"
            or row.get("read_op_id") != op["id"]):
        return
    mine = ("read_op_id", int(op["id"]))
    defect, error = import_answer(op, row)
    if defect is None:
        db.hub_defect_update(int(row["id"]), expect_state="import_reading", expect_op=mine, state="failed", error=error)
        return
    snapshot = import_snapshot(db, row, defect, str(op.get("closed_at") or ""))
    db.hub_defect_update(int(row["id"]), expect_state="import_reading", expect_op=mine, state="import_preview",
                         import_json=dumps(snapshot), error="")


def import_targets(db: Database, project_id: int, entries: list[dict]) -> list[dict]:
    """Цели строки занесённого дефекта: номер и тип находки, редакция решения и отпечаток данных на момент занесения;
    отпечатка текста и частей отметки нет – отметку «Внесено в Hub» занесение не ставит (ADR-0124 п. 5)."""
    found = db.import_findings(project_id, [str(e["hub_id"]) for e in entries])
    return [{"hub_id": str(e["hub_id"]), "issue_id": int(e["issue_id"]), "issue_type": str(e["issue_type"]),
             "revision": int((found.get(str(e["hub_id"])) or {}).get("revision") or 0), "entered_hash": "", "decision_hash": "",
             "entered_parts": "", "sig": str((found.get(str(e["hub_id"])) or {}).get("sig") or "")} for e in entries]


def _still_free(row: dict, entries: list[dict], changed: str, extra: Callable | None = None) -> Callable:
    """Проверка в транзакции «Занести» и «Применить»: каждая находка по-прежнему в выгрузке (тот же тип) и свободна
    (своя строка не в счёт); иначе ValueError(changed) с причиной."""
    pid, own = int(row["project_id"]), int(row["id"])

    def check(c) -> None:
        if extra is not None:
            extra(c)
        now = Database.import_findings_in(c, pid, [str(e["hub_id"]) for e in entries])
        for entry in entries:
            hub_id = str(entry["hub_id"])
            f = now.get(hub_id)
            if f is None or f["missing"] or hub_status.HUB_ISSUE_TYPE.get(f["kind"]) != entry["issue_type"]:
                raise ValueError(changed.format(why=f"находки {hub_id} {NOT_IN_EXPORT}"))
            holder = Database.hub_defect_holder_in(c, pid, hub_id, exclude_id=own)
            if holder is not None:
                raise ValueError(changed.format(why=f"находка {hub_id} {_holder_why(holder, row)}"))
    return check


def accept_import(db: Database, row: dict, *, op_id: int, shown: str, target_check: Callable | None = None) -> dict:
    """«Занести» (ADR-0124 п. 5) одной транзакцией: строка в import_preview и ждёт ту же операцию чтения (expect_op),
    показанный снимок тот же (shown – text_hash(import_json)), принимаемые находки по-прежнему в выгрузке и свободны;
    затем – done, origin 'import', вид, цели, заголовок Hub, текст команды, номер ID<n> (только резерв), подтверждающая
    операция – чтение, последствия доведены. Номер ключам находок не пишется, отметки не ставятся. Иначе ValueError."""
    if row.get("origin") != "import" or row["state"] != "import_preview":
        raise ValueError("Предпросмотра занесения нет: обновите страницу.")
    snap = loads(row.get("import_json"), {}) or {}
    if not snap.get("kind"):
        raise ValueError("Занесение недоступно: " + (snap.get("kind_note") or "вид дефекта не определён") + ".")
    if text_hash(str(row.get("import_json") or "")) != str(shown or ""):
        raise ValueError(IMPORT_SHOWN_CHANGED)
    pid = int(row["project_id"])
    accepted = list(snap.get("accepted") or [])
    targets = import_targets(db, pid, accepted)
    number = snap.get("number") if isinstance(snap.get("number"), int) else None

    def same_snapshot(c) -> None:
        if target_check is not None:
            target_check(c)
        current = c.execute("SELECT import_json FROM hub_defects WHERE id = ?", (int(row["id"]),)).fetchone()
        if current is None or text_hash(str(current["import_json"] or "")) != str(shown):
            raise ValueError(IMPORT_SHOWN_CHANGED)

    fresh, _ = db.hub_defect_advance(
        int(row["id"]), expect_state="import_preview", expect_op=("read_op_id", int(op_id)),
        check=_still_free(row, accepted, IMPORT_CHANGED, same_snapshot), state="done", kind=str(snap["kind"]),
        targets_json=dumps(targets), anchor_hub_id=str(accepted[0]["hub_id"]) if accepted else "",
        summary=str(snap.get("summary") or ""), command_text=str(snap.get("command_text") or ""), number=number,
        number_keys_json="[]", confirm_op_id=int(op_id), effects_done=1,
        fields_after_check=lambda c: {"error": number_note_in(
            c, row, number, own_number_keys_in(c, row, accepted, snap.get("absent")))},
        import_json=dumps({**snap, "accepted": accepted}),
        on_write=lambda c, fresh: defect_drafts.accept(c, fresh, snap, op_id))
    if fresh is None:
        raise ValueError("Предпросмотр занесения изменился в другой вкладке: обновите страницу.")
    return fresh


def cancel_import(db: Database, row: dict) -> dict:
    """«Отменить» предпросмотр занесения: в Hub ничего не уходило, строка отменена – дефект заносит синхронизация
    («Синхронизировать», «Принять состояние Hub»; форма номеров убрана в 0.10.0.dev13)."""
    fresh = (db.hub_defect_update(int(row["id"]), expect_state="import_preview", state="cancelled")
             if row.get("origin") == "import" else None)
    if fresh is None:
        raise ValueError("Предпросмотра занесения уже нет: обновите страницу.")
    return fresh


def retry_import(db: Database, row: dict, target_check: Callable | None = None) -> dict:
    """«Повторить чтение» у не удавшегося или отменённого занесения (ADR-0124 п. 3) одной транзакцией: нет другой живой
    строки этого дефекта (своя не в счёт), новая операция чтения, строка снова import_reading."""
    if row.get("origin") != "import" or row["state"] not in ("failed", "cancelled"):
        raise ValueError("Повторить чтение можно только у занесения, которое не удалось или отменено.")

    def free(c) -> None:
        if target_check is not None:
            target_check(c)
        live = Database.hub_defect_live_in(c, str(row.get("hub_url") or ""), row.get("app_id"),
                                           str(row.get("hub_defect_id") or ""), exclude_id=int(row["id"]))
        if live is not None:
            raise ValueError(f"Дефект №{row.get('hub_defect_id')} уже есть в приложении (строка {live['id']}, состояние "
                             f"«{STATE_LABELS.get(live['state'], live['state'])}»): повторное чтение не нужно.")

    fresh, _ = db.hub_defect_advance(int(row["id"]), expect_state=row["state"], check=free,
                                     item=import_item(row, str(row["hub_defect_id"])), op_field="read_op_id",
                                     state="import_reading", import_json="", error="")
    if fresh is None:
        raise ValueError("Состояние строки изменилось: обновите страницу.")
    return fresh


def import_view(row: dict) -> dict:
    """Состояние строки занесения для вкладки и карточки: {state, final, text, tone, verify}; «Сверить» результата
    неизвестен к занесению не применяется (verify всегда False). Предпросмотр без вида (kind в import_json пуст – вид
    не определён или не поддерживается) – «занесение недоступно» с причиной (kind_note), тон warn."""
    state, number, error = row["state"], str(row.get("hub_defect_id") or ""), str(row.get("error") or "")
    view_of = {"state": state, "final": True, "text": "", "tone": "", "verify": False}
    if state == "import_reading":
        return {**view_of, "final": False, "text": f"Читаю дефект №{number} из Hub…"}
    if state == "import_preview":
        snap = loads(row.get("import_json"), {}) or {}
        snap = snap if isinstance(snap, dict) else {}
        if not snap.get("kind"):  # вид не определён или не поддерживается: формы «Занести» нет – только «Отменить»
            why = str(snap.get("kind_note") or "") or "вид дефекта не определён"
            return {**view_of, "tone": "warn", "text": f"Дефект №{number} прочитан из Hub, занесение недоступно: {why}"
                                                       " – нажмите «Отменить»."}
        return {**view_of, "text": f"Дефект №{number} прочитан из Hub: проверьте предпросмотр и нажмите «Занести»."}
    if state == "failed":
        return {**view_of, "text": error or IMPORT_READ_FAILED, "tone": "err"}
    if state == "done":
        if row.get("sync_op_id"):
            return {**view_of, "final": False, "text": f"Сверяю с Hub: читаю дефект №{number}…"}
        update_text, update_tone, update_final = update_view(row)  # «Push в Hub» (ADR-0125)
        if not update_final:
            return {**view_of, "final": False, "text": update_text}
        sync_state = loads(row.get("sync_json"), {}) or {}
        note = ""
        if isinstance(sync_state, dict) and sync_state.get("error"):  # сверка не удалась: пояснение, состояние прежнее
            note = "сверка с Hub: " + str(sync_state["error"])
        tone = "ok"
        if update_tone in ("warn", "err") or error or note:
            tone = "err" if update_tone == "err" else "warn"
        return {**view_of, "text": " ".join(p for p in (update_text, error, note) if p), "tone": tone}
    return view_of


# ---------------------------------------------------------------------------- «Pull из Hub» (только добавление)


PULL_ONLY = "Pull из Hub доступен у созданного или занесённого дефекта с номером в Hub (строка-владелец)."


def pull_allowed(row: dict | None) -> bool:
    """«Pull из Hub» (ADR-0124 п. 6, с dev34 – и у дефектов из приложения): строка «создан» с номером в Hub,
    занесённая из Hub или созданная приложением; у созданного приложением – только строка-владелец семейства (строка
    привязки своего Pull не имеет: один дефект Hub – одна сверка)."""
    if not row or row.get("state") != "done" or not row.get("hub_defect_id"):
        return False
    if row.get("origin") == "import":
        return True
    return row.get("origin") == "app" and int(row.get("draft_owner_id") or row["id"]) == int(row["id"])


def pull_targets_in(c, row: dict) -> list[dict]:
    """Цели всех строк семейства дефекта (строка создания и строки привязки) – действующий состав в приложении; пара
    (номер, тип) – один раз, первой встретившейся строкой (владелец – первым)."""
    members = defect_drafts.family_in(c, row)
    members.sort(key=lambda m: (int(m["id"]) != int(row["id"]), int(m["id"])))
    seen, out = set(), []
    for member in members:
        for t in loads(member.get("targets_json"), []):
            pair = (str(t.get("hub_id") or ""), str(t.get("issue_type") or ""))
            if pair not in seen:
                seen.add(pair)
                out.append(t)
    return out


FAMILY_BUSY = ("У дефекта идёт привязка находок или проверка её итога: дождитесь ответа исполнителя, затем снова "
               "«Pull из Hub».")


def family_busy_in(c, row: dict) -> bool:
    """Строка семейства (кроме владельца) ещё не «создан»: привязка находок идёт или её итог не установлен (linking,
    unknown, unconfirmed, mismatch) либо у строки идёт проверка (verify_op_id) – «Pull из Hub» и «Применить» ждут (ревью
    dev34, круг 1): схлопывание иначе стёрло бы цели привязки, POST которой ещё может выполниться. Схлопнутая строка –
    история, семью не занимает (ADR-0136)."""
    owner_id = int(row.get("draft_owner_id") or row["id"])
    return c.execute("SELECT 1 FROM hub_defects WHERE draft_owner_id = ? AND id <> ? AND state NOT IN"
                     f" ('failed', 'cancelled', 'deleted') AND NOT ({Database.HUB_DEFECT_COLLAPSED})"
                     " AND (state <> 'done' OR verify_op_id IS NOT NULL) LIMIT 1", (owner_id, owner_id)).fetchone() is not None


def family_unmerged_in(c, row: dict, linked: Any = None) -> list[str]:
    """Находки строк привязки `done`, которые ещё не в составе владельца: «Применить» внесёт их туда (ADR-0136). linked – пары
    (номер, тип) прочитанного дефекта: только находки, которые в нём есть; снятые в Hub «Применить» уберёт."""
    owner_id = int(defect_drafts.owner_in(c, row)["id"])
    pairs = None if linked is None else {(str(i), str(t)) for i, t in linked}
    return [str(t.get("hub_id") or "") for member in defect_drafts.family_in(c, row)
            if int(member["id"]) != owner_id and member["state"] == "done"
            for t in loads(member.get("targets_json"), [])
            if pairs is None or (str(t.get("hub_id") or ""), str(t.get("issue_type") or "")) in pairs]


def family_running_problem(c, row: dict) -> str:
    """Почему к дефекту сейчас нельзя привязать находку: по его семье идёт операция, итог которой изменит состав или
    принятое состояние. Действует на все пути привязки, в транзакции постановки (ADR-0136); '' – можно."""
    owner = defect_drafts.owner_in(c, row)
    if update_unconfirmed(owner) or update_busy(owner):
        return "Обновление дефекта не подтверждено или ещё выполняется: сначала завершите его."
    if update_state(owner).get("phase") == "preview":
        return "Открыт предпросмотр «Push в Hub»: нажмите «Push в Hub» или «Отменить»."
    if owner.get("sync_op_id"):
        return "Идёт «Pull из Hub»: дождитесь её итога."
    if owner.get("verify_op_id"):
        return "Идёт проверка дефекта в Hub: дождитесь её итога."
    sync_state = loads(owner.get("sync_json"), {}) or {}
    if isinstance(sync_state, dict) and sync_state.get("read"):
        return UPDATE_SYNC_FIRST
    if family_busy_in(c, owner):
        return FAMILY_BUSY
    if family_effects_pending_in(c, owner):
        return EFFECTS_PENDING
    return ""


def add_problem(c, owner: dict, hub_id: str = "") -> str:
    """Почему в дефект нельзя добавить находку hub_id со страницы «Добавить в дефект» (ADR-0136), при показе и в транзакции
    постановки: конфликт состава, неотправленная правка (Pull после привязки обязателен, а её судьбу решает оператор
    заранее), неизвестная основа полей, номер дефекта, с которым находка не получит ID; ключ самой находки номер не
    занимает: её свой номер сверяет страница. '' – можно."""
    if loads(owner.get("conflicts_json"), []):
        return "У дефекта есть неразрешённые конфликты состава: сначала разрешите их в карточке дефекта."
    edit = defect_drafts.local_edit(owner)
    if edit["fields_unknown"]:
        return "Приложение ещё не знает, какие поля дефекта сейчас в Hub: сначала «Pull из Hub» в карточке дефекта."
    if edit["edited"]:
        return "В дефекте есть неотправленная правка: сначала «Push в Hub» или верните текст в карточке дефекта."
    entries = [*pull_targets_in(c, owner), *([{"hub_id": hub_id}] if hub_id else [])]
    return "; ".join(_number_refusals(c, owner, owner.get("summary"), entries))


def family_effects_pending_in(c, row: dict) -> bool:
    """У строки семейства (владелец или строка привязки) итог записан, а последствия подтверждения – отметки «Внесено в
    Hub» и номера – не доведены (effects_done = 0, сбой после записи итога): «Применить» ждёт их восстановления
    показом вкладки (ревью dev34, круги 6–7)."""
    owner_id = int(row.get("draft_owner_id") or row["id"])
    return c.execute("SELECT 1 FROM hub_defects WHERE (draft_owner_id = ? OR id = ?) AND state IN ('done', 'mismatch',"
                     " 'failed') AND COALESCE(effects_done, 1) = 0 LIMIT 1", (owner_id, owner_id)).fetchone() is not None


def family_ids_in(c, row: dict) -> set[int]:
    """Номера строк семейства дефекта (владелец и строки привязки)."""
    owner_id = int(row.get("draft_owner_id") or row["id"])
    return {int(r["id"]) for r in c.execute("SELECT id FROM hub_defects WHERE draft_owner_id = ? OR id = ?",
                                            (owner_id, owner_id))}


def family_number_keys_in(c, row: dict) -> list[str]:
    """Ключи номера всех строк семейства (объединение)."""
    keys: list[str] = []
    for member in defect_drafts.family_in(c, row):
        for key in loads(member.get("number_keys_json"), []):
            if key not in keys:
                keys.append(key)
    return keys


def start_import_sync(db: Database, row: dict, target_check: Callable | None = None) -> dict:
    """«Pull из Hub» у занесённого дефекта (ADR-0124 п. 6) одной транзакцией (expect_state done): сверка ещё не идёт,
    операция чтения с целью import_sync, её номер – в sync_op_id; прежний предпросмотр сверки снимается. Состояние,
    цели, номер и защита не меняются."""
    if not pull_allowed(row):
        raise ValueError(PULL_ONLY)

    def idle(c) -> None:
        if target_check is not None:
            target_check(c)
        current = c.execute("SELECT sync_op_id, update_op_id, update_json FROM hub_defects WHERE id = ?",
                            (int(row["id"]),)).fetchone()
        if current["sync_op_id"]:
            raise ValueError("Сверка уже идёт: дождитесь ответа исполнителя.")
        if update_busy(dict(current)):  # идёт «Push в Hub» (ADR-0125 п. 2): сверка подождёт его итога
            raise ValueError(UPDATE_IN_PROGRESS)
        if family_busy_in(c, row):  # идёт привязка находок к этому дефекту (dev34)
            raise ValueError(FAMILY_BUSY)
        # запись принята, подтверждения нет (ADR-0125 п. 2): успех «Повторить чтение» записал бы цели этой попытки
        # поверх добавленных сверкой находок
        if update_unconfirmed(dict(current)):
            raise ValueError(UPDATE_UNCONFIRMED_FIRST)

    fresh, _ = db.hub_defect_advance(int(row["id"]), expect_state="done", check=idle,
                                     item=import_item(row, str(row["hub_defect_id"]), sync=True),
                                     op_field="sync_op_id", sync_json="")
    if fresh is None:
        raise ValueError("Состояние дефекта изменилось: обновите страницу.")
    return fresh


def sync_snapshot(db: Database, row: dict, defect: dict, closed_at: str = "") -> dict:
    """Предпросмотр сверки (ADR-0124 п. 6): добавляемые находки (есть в ответе, в выгрузке, свободны, тип совпадает с
    видом строки); другого типа – «несовместимы с видом дефекта»; не добавляемые (нет в выгрузке, заняты); цели, не
    наблюдаемые в ответе, – только пояснение, цели остаются; новый заголовок, номер ID<n> и выделенный текст."""
    read = _read_of(defect)
    pid = int(row["project_id"])
    # состав в приложении – по всему семейству строк (строки привязки у дефекта из приложения, dev34)
    targets = db.on_connection(lambda c: pull_targets_in(c, row))
    own = {str(t.get("hub_id") or "") for t in targets}
    want = TYPE_OF_KIND.get(str(row.get("kind") or ""), "")
    found = db.import_findings(pid, [str(i) for i, _ in read["linked"]])
    added, incompatible, not_added = [], [], []
    for issue_id, issue_type in read["linked"]:
        hub_id = str(issue_id)
        if hub_id in own:
            continue
        if issue_type != want:
            incompatible.append({"hub_id": hub_id, "issue_type": issue_type, "why": SYNC_INCOMPATIBLE})
            continue
        f = found.get(hub_id)
        if f is None or f["missing"] or hub_status.HUB_ISSUE_TYPE.get(f["kind"]) != issue_type:
            not_added.append({"hub_id": hub_id, "issue_type": issue_type, "why": NOT_IN_EXPORT})
            continue
        holder = db.hub_defect_holder(pid, hub_id, exclude_id=int(row["id"]))
        if holder is not None:
            not_added.append({"hub_id": hub_id, "issue_type": issue_type, "why": _holder_why(holder, row)})
            continue
        added.append({"hub_id": hub_id, "issue_id": int(issue_id), "issue_type": issue_type})
    unobserved = [{"hub_id": str(t.get("hub_id") or ""), "why": SYNC_UNOBSERVED} for t in missing_targets(defect, targets)]
    warnings = [note for note in (read["number_note"], read["text_note"],
                                  number_shift_note(row.get("number"), read["number"], read["number_note"]),
                                  BLOCK_REPEATED if block_repeated(defect.get("description")) else "") if note]
    from app.defect_fields import diff, fields_of
    confirmed = loads(row.get("confirmed_object_json"), None)
    previous = _read_of(confirmed) if isinstance(confirmed, dict) else {}
    warnings_changed = [note for key in ("number_note", "text_note")
                        if (note := read[key]) and note != previous.get(key)]
    fields_diff = diff(fields_of(confirmed), fields_of(defect)) if isinstance(confirmed, dict) else []
    previous_links = linked_pairs(confirmed) if isinstance(confirmed, dict) else None
    current_links = linked_pairs(defect)
    remote_removed = []
    incompatible_diff, not_added_diff, unobserved_diff = incompatible, not_added, unobserved
    if previous_links is not None:
        new_links = current_links - previous_links
        incompatible_diff = [t for t in incompatible if (int(t["hub_id"]), t["issue_type"]) in new_links]
        not_added_diff = [t for t in not_added if (int(t["hub_id"]), t["issue_type"]) in new_links]
        removed_ids = {str(i) for i, _ in previous_links - current_links}
        unobserved_diff = [t for t in unobserved if t["hub_id"] in removed_ids]
        remote_removed = [{"hub_id": str(i), "issue_type": kind} for i, kind in sorted(previous_links - current_links)
                          if str(i) not in own]
    block_diff = _block_diff(row, defect)
    read["block_changed"] = bool(block_diff)  # «Применить» проверяет конфликт с черновиком (defect_drafts.apply_sync)
    return {"read": read, "added": added, "incompatible": incompatible, "not_added": not_added,
            "composition_changed": previous_links is not None and previous_links != current_links,
            "remote_removed": remote_removed,
            "incompatible_diff": incompatible_diff, "not_added_diff": not_added_diff, "unobserved_diff": unobserved_diff,
            "fields_diff": fields_diff, "fields_unknown": not isinstance(confirmed, dict),
            "local_snapshot": {k: row.get(k) for k in ("draft_revision", "draft_summary", "draft_command_text",
                "draft_fields_json", "draft_fields_basis_json", "confirmed_object_json", "targets_json", "conflicts_json")},
            # состав всех строк семейства на момент предпросмотра: «Применить» сверяет его в транзакции (dev34)
            "members_snapshot": db.on_connection(lambda c: defect_drafts.members_in(c, row)),
            "unobserved": unobserved, "warnings": warnings, "warnings_changed": warnings_changed,
            "hints": _hints(db, row, read),
            "summary_changed": read["summary"] != str(row.get("summary") or ""),
            # с принятым заголовком: резерв дефекта остаётся, когда ID пропал из заголовка (ADR-0138)
            "number_changed": read["number"] != (previous.get("number") if previous else row.get("number")),
            "text_changed": _text_changed(row, read), "block_diff": block_diff,
            "read_at": str(closed_at or ""),
            # находки строк привязки ещё не в составе владельца, но связанные в Hub: без «Применить» правка и Push закрыты
            # (ADR-0136); снятые в Hub показаны в unobserved
            "family_unmerged": db.on_connection(lambda c: family_unmerged_in(c, row, read["linked"]))}


def _below_boundary(lines: list[str]) -> list[str]:
    """Строки ниже первой границы служебного блока, в том числе второй блок, дописанный Hub; границы нет – []."""
    return lines[lines.index(IMPORT_BOUNDARY) + 1:] if IMPORT_BOUNDARY in lines else []


def _block_lines(description: Any) -> list[str]:
    """Строки служебного блока для показа различий оператору."""
    return [line for line in (hub_ops.normalize_text(part) for part in _below_boundary(description_for_reading(description))) if line]


def _block_diff(row: dict, defect: dict) -> list[str]:
    """Различия служебного блока в Hub и принятого описания (ADR-0132: описание синхронизируется целиком): строки
    «− было», «+ стало». База – принятое состояние `confirmed_object_json`: его обновляет «Применить», поэтому повторный Pull
    совпадает. Сравнивается текст: переформатирование HTML в Hub правкой не считается. Принятого описания нет – сравнивать не с чем."""
    accepted = loads(row.get("confirmed_object_json"), {}) or {}
    if not isinstance(accepted, dict) or "description" not in accepted:
        return []  # принятого описания нет; принятое пустое описание сравнивается как обычное
    base, seen = accepted.get("description"), (defect or {}).get("description")
    if _below_boundary(description_units(base)) == _below_boundary(description_units(seen)):
        return []
    old, new = _block_lines(base), _block_lines(seen)
    if old == new:  # различие есть, а в строках для чтения его не видно: показывается по единицам
        old, new = _below_boundary(description_units(base)), _below_boundary(description_units(seen))
        old, new = [line.replace(CELL_MARK, "[ячейка]") for line in old], [line.replace(CELL_MARK, "[ячейка]") for line in new]
    # всё, что примет «Применить», показывается целиком
    return [("− " if line[0] == "-" else "+ ") + line[2:] for line in ndiff(old, new) if line[:2] in ("- ", "+ ")]


def _text_changed(row: dict, read: dict) -> bool:
    """Текст команды в Hub другой (предпросмотр сверки, ADR-0124 п. 6): у занесённой строки – точное сравнение (её
    текст – всегда разбор описания Hub, ADR-0125 п. 4, вариант A); у созданной приложением текст – исходный текст
    оператора, а разбор описания Hub отличается от него переводами строк по краям и пробелами – сравнение по строкам
    с нормализацией (dev34)."""
    if row.get("origin") == "import":
        return str(read.get("command_text") or "") != str(row.get("command_text") or "")
    return _norm_lines(read.get("command_text")) != _norm_lines(row.get("command_text"))


def _on_import_sync(db: Database, op: dict, first: dict) -> None:
    """Ответ «Pull из Hub» (ADR-0124 п. 6): только если строка done, занесена из Hub и ждёт именно этой операции
    (sync_op_id) – повторная и поздняя доставка ничего не меняют. Проверки п. 3 не прошли (или аренда истекла, отмена)
    – в sync_json пояснение; иначе – предпросмотр добавления. sync_op_id очищается; принятое состояние не меняется."""
    row = db.hub_defect(int(first["import_sync"]))
    if row is None or not pull_allowed(row) or row.get("sync_op_id") != op["id"]:
        return
    mine = ("sync_op_id", int(op["id"]))
    defect, error = import_answer(op, row)
    state = ({"error": error, "read_at": str(op.get("closed_at") or "")} if defect is None
             else sync_snapshot(db, row, defect, str(op.get("closed_at") or "")))
    if defect is not None:
        state["read"]["op_id"] = op["id"]
    changes = {}
    if defect is not None and not any(state.get(k) for k in (
            "added", "composition_changed", "incompatible_diff", "not_added_diff", "unobserved", "warnings_changed", "summary_changed", "number_changed",
            "text_changed", "block_diff", "fields_diff", "fields_unknown", "family_unmerged")):
        changes["error"] = number_note(db, row, row.get("number"),
                                       own_number_keys(db, row, db.on_connection(lambda c: pull_targets_in(c, row)),
                                                       state.get("not_added")))
        # ниже текста в описании Hub может быть блок Hub и чужие строки: «Push в Hub» их заменит
        extra = [line for line in split_description(defect.get("description"))[1] if line.strip()]
        state = {"matches": True, "read_at": str(op.get("closed_at") or ""), "observation": state["read"],
                 "extra_lines": len(extra)}
    owner_id = int(row.get("draft_owner_id") or row["id"])
    db.hub_defect_update(int(row["id"]), expect_state="done", expect_op=mine, sync_op_id=None,
                         sync_json=dumps(state), **changes,
                         # дефект совпал с Hub – прошлый отказ подготовки Push устарел (ревью dev15, B2)
                         on_write=(lambda c, fresh: clear_stale_update_in(c, owner_id)) if state.get("matches") else None)


def apply_import_sync(db: Database, row: dict, *, shown: str, target_check: Callable | None = None) -> dict:
    """«Применить» предпросмотр сверки (ADR-0124 п. 6) одной транзакцией (expect_state done): в sync_json – тот же
    показанный снимок (shown – его text_hash), сверка не идёт; добавляемые находки – снова в выгрузке и свободны – входят
    в цели; цели, которых в Hub больше нет, убираются с пометкой «выбыла из дефекта» (Hub – источник истины);
    заголовок, снимок чтения, текст команды и номер ID<n> (резерв) – из ответа; sync_json очищается: повторное
    применение невозможно."""
    if not pull_allowed(row):
        raise ValueError(PULL_ONLY)
    raw = str(row.get("sync_json") or "")
    snap = loads(raw, {}) or {}
    if row.get("sync_op_id"):
        raise ValueError("Сверка ещё идёт: дождитесь ответа исполнителя.")
    if not isinstance(snap, dict) or not snap.get("read"):
        raise ValueError("Применять нечего: предпросмотра сверки нет – нажмите «Pull из Hub».")
    if text_hash(raw) != str(shown or ""):
        raise ValueError(IMPORT_SHOWN_CHANGED)
    pid, read = int(row["project_id"]), snap["read"]
    added = list(snap.get("added") or [])
    # состав – как в Hub (Hub – источник истины): цели, которых нет среди связей прочитанного
    # дефекта, убираются; им – пометка «выбыла из дефекта», их отметки и номер снимаются (on_write)
    hub_pairs = {(str(i), str(t)) for i, t in read.get("linked") or []}
    # прежний состав – всего семейства строк: у дефекта из приложения находки могут держать и строки привязки;
    # «Применить» собирает действующий состав у владельца, как принятие состояния Hub (hub_pull.accept_defect, dev34)
    previous = db.on_connection(lambda c: pull_targets_in(c, row))
    union_keys = db.on_connection(lambda c: family_number_keys_in(c, row))
    members_shown = snap.get("members_snapshot")
    kept = [t for t in previous if (str(t.get("hub_id") or ""), str(t.get("issue_type") or "")) in hub_pairs]
    removed = {(str(t.get("hub_id") or ""), str(t.get("issue_type") or "")) for t in previous if t not in kept}
    targets = kept + import_targets(db, pid, added)
    kept_ids = {str(t["hub_id"]) for t in targets}
    anchor = str(row.get("anchor_hub_id") or "")
    anchor = anchor if anchor in kept_ids else (str(targets[0]["hub_id"]) if targets else "")
    # ID пропал из заголовка в Hub – номер остаётся за дефектом (ADR-0138), Push вернёт его
    number = read.get("number") if isinstance(read.get("number"), int) else (
        row.get("number") if _is_number(row.get("number")) and read.get("number_note") == NO_NUMBER else None)
    command = str(read.get("command_text") or "")
    if row.get("origin") != "import" and _norm_lines(command) == _norm_lines(row.get("command_text")):
        # у дефекта из приложения текст – исходный текст оператора; разбор Hub отличается только формой (края строк,
        # пробелы): текст строки не меняется – по нему соседи группы находят дефект для привязки (ревью dev34, круг 2)
        command = str(row.get("command_text") or "")

    def same(c) -> None:
        if target_check is not None:
            target_check(c)
        current = c.execute("SELECT * FROM hub_defects WHERE id = ?", (int(row["id"]),)).fetchone()
        if (current is None or current["sync_op_id"] or text_hash(str(current["sync_json"] or "")) != str(shown)
                or str(current["targets_json"] or "") != str(row.get("targets_json") or "")
                or str(current["update_json"] or "") != str(row.get("update_json") or "")
                or str(current["command_text"] or "") != str(row.get("command_text") or "")
                or any(current[k] != row[k] for k in ("summary", "draft_owner_id", "draft_revision", "draft_summary",
                                                      "draft_command_text", "draft_fields_json", "draft_fields_basis_json", "confirmed_object_json",
                                                      "conflicts_json"))):
            raise ValueError(IMPORT_SHOWN_CHANGED)
        if any(current[k] != value for k, value in snap.get("local_snapshot", {}).items()):
            raise ValueError(IMPORT_SHOWN_CHANGED)
        # состав строк семейства тот же, что видел предпросмотр (строку привязки могли изменить отдельно, dev34)
        if members_shown is not None and defect_drafts.members_in(c, row) != members_shown:
            raise ValueError(IMPORT_SHOWN_CHANGED)
        if pull_targets_in(c, row) != previous:
            raise ValueError(IMPORT_SHOWN_CHANGED)
        if family_busy_in(c, row):  # привязка поставлена после предпросмотра (ревью dev34, круг 1)
            raise ValueError(FAMILY_BUSY)
        # последствия подтверждения (отметки, номера) ещё не доведены у какой-либо строки семейства: их доведёт показ
        # вкладки по прежнему составу, «Применить» (схлопывание целей строк привязки) его не меняет до этого (ревью
        # dev34, круги 6–7)
        if family_effects_pending_in(c, row):
            raise ValueError(EFFECTS_PENDING)
        if update_busy(dict(current)):  # идёт «Push в Hub» (ADR-0125 п. 2): строка не меняется
            raise ValueError(UPDATE_IN_PROGRESS)
        if update_unconfirmed(dict(current)):  # запись принята, подтверждения нет (ADR-0125 п. 2): строка не меняется
            raise ValueError(UPDATE_UNCONFIRMED_FIRST)

    accepted = [{"hub_id": str(t["hub_id"]), "issue_id": int(t["issue_id"]), "issue_type": str(t["issue_type"])}
                for t in targets]
    kept: list[bool] = []  # apply_sync: локальная правка осталась поверх принятого
    fresh, _ = db.hub_defect_advance(
        int(row["id"]), expect_state="done", check=_still_free(row, added, SYNC_CHANGED, same),
        targets_json=dumps(targets), anchor_hub_id=anchor,
        summary=str(read.get("summary") or ""), command_text=command, number=number,
        import_json=dumps({**read, "accepted": accepted, "read_at": snap.get("read_at") or ""}), sync_json="",
        # выбывшие – по строке до применения: номер и ключи номера снимаются прежние, даже если Hub сменил ID<n>
        on_write=lambda c, fresh: (_collapse_family(c, row, union_keys),
                                   kept.append(defect_drafts.apply_sync(c, row, read)),
                                   # добавленным находкам без решения – решение «из Hub»
                                   defect_drafts.give_hub_decisions(c, int(row["id"]), pid,
                                                                    [(t["hub_id"], t["issue_type"]) for t in added],
                                                                    {"defect": str(row.get("hub_defect_id") or ""),
                                                                     "sync": True, "row_id": int(row["id"])}),
                                   clear_stale_update_in(c, int(row.get("draft_owner_id") or row["id"])),
                                   defect_drafts.drop_removed(c, {**row, "kind": fresh["kind"],
                                                                  "number_keys_json": dumps(union_keys)},
                                                              hub_pairs, removed, targets),
                                   defect_drafts.renumber_keys(c, dict(c.execute("SELECT * FROM hub_defects WHERE id = ?",
                                                                                 (int(row["id"]),)).fetchone()),
                                                               row.get("number"), number, targets),
                                   _follow_owner(c, row, str(read.get("summary") or ""), command, number),
                                   # сохранённая локальная правка – событием после всех событий принятия (ревью dev34,
                                   # круг 3: drop_removed пишет hub_sync той же редакцией)
                                   defect_drafts.mark_kept_local(c, row) if kept and kept[0] else None),
        # ключи выбывающих находок ещё держат номер этого дефекта – свои, а не «занят другим» (их номер снимет on_write)
        fields_after_check=lambda c: {"error": number_note_in(
            c, row, number, own_number_keys_in(c, row, previous + targets, snap.get("not_added")))})
    if fresh is None:
        raise ValueError("Состояние дефекта изменилось: обновите страницу.")
    return fresh


def _collapse_family(c, owner: dict, union_keys: list[str]) -> None:
    """«Применить» у семейства строк (dev34): действующий состав и ключи номера – у владельца, у строк привязки цели и
    ключи пусты (как после принятия состояния Hub, hub_pull.accept_defect); строки и их история остаются."""
    c.execute("UPDATE hub_defects SET number_keys_json = ? WHERE id = ?", (dumps(union_keys), int(owner["id"])))
    c.execute("UPDATE hub_defects SET targets_json = '[]', number_keys_json = '[]' WHERE draft_owner_id = ? AND id <> ?"
              " AND state = 'done'", (int(owner["id"]), int(owner["id"])))


def _is_number(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


EFFECTS_PENDING = ("Отметки по подтверждению дефекта ещё не доведены: обновите страницу и снова нажмите "
                   "«Применить».")


def number_shift_note(old: Any, new: Any, why: str = NO_NUMBER) -> str:
    """ID в заголовке Hub пропал или появился (ADR-0138): пропавший номер остаётся за дефектом, Push вернёт его в заголовок;
    появившийся у дефекта без номера находкам сам не выдаётся (бэклог 70). Перенумерацию между номерами ведёт renumber_keys."""
    if _is_number(old) and not _is_number(new):
        if why != NO_NUMBER:  # номеров в заголовке несколько: возвращать нечего, причину называет сам разбор заголовка
            return ""
        return f"ID{old} пропал из заголовка в Hub. Номер остаётся за дефектом: следующий «Push в Hub» вернёт его в заголовок."
    if not _is_number(old) and _is_number(new):
        return f"В заголовке в Hub появился ID{new}. Находкам дефекта приложение само номер не выдаёт."
    return ""


def _follow_owner(c, owner: dict, summary: str, command: str, number: Any) -> None:
    """После «Применить» строки привязки семейства берут номер, заголовок и текст владельца (как после принятия
    состояния Hub, hub_pull.accept_defect): прежний ID<n> строки привязки иначе остался бы резервом (ревью dev34)."""
    c.execute("UPDATE hub_defects SET summary = ?, command_text = ?, number = ? WHERE draft_owner_id = ? AND id <> ?"
              " AND state = 'done'", (summary, command, number, int(owner["id"]), int(owner["id"])))


def cancel_import_sync(db: Database, row: dict, *, shown: str) -> dict:
    """«Отменить» предпросмотр сверки одной транзакцией (expect_state done): сверка не идёт и в sync_json – тот же
    показанный снимок (shown – его text_hash), иначе IMPORT_SHOWN_CHANGED: «Отменить» из старой вкладки не стирает
    более новый предпросмотр. sync_json очищается, принятое состояние не меняется."""
    if not pull_allowed(row):
        raise ValueError("Отменять нечего: обновите страницу.")

    def idle(c) -> None:
        current = c.execute("SELECT sync_op_id, sync_json FROM hub_defects WHERE id = ?", (int(row["id"]),)).fetchone()
        if current is None:
            raise ValueError("Отменять нечего: обновите страницу.")
        if current["sync_op_id"]:
            raise ValueError("Сверка ещё идёт: дождитесь ответа исполнителя.")
        if text_hash(str(current["sync_json"] or "")) != str(shown or ""):
            raise ValueError(IMPORT_SHOWN_CHANGED)

    fresh, _ = db.hub_defect_advance(int(row["id"]), expect_state="done", check=idle, sync_json="")
    if fresh is None:
        raise ValueError("Состояние дефекта изменилось: обновите страницу.")
    return fresh


# ============================================================================ «Push в Hub» (ADR-0125)
#
# Заголовок и описание дефекта, занесённого из Hub (origin 'import', одна живая строка), – по текущим решениям,
# запросом `PUT /defects/{id}` с телом второго чтения, где заменены только summary и description (блок Hub – исходная
# подстрока байт в байт). Строка остаётся «создан» (state 'done': цели и номер защищены, ADR-0121); ход попытки – в
# update_json (фаза, поколение попытки, ожидаемый шаг, номер PUT, снимки чтений, подготовленное и отправленное,
# подтверждённое содержимое), операция текущего шага – в update_op_id. Шаги: «Подготовить обновление» – чтение →
# предпросмотр; «Push в Hub» – второе чтение → PUT → подтверждающее чтение; «результат неизвестен» – «Сверить»
# (чтение). PUT само не повторяется: новая попытка – новое поколение («Подготовить обновление») и новый ключ операции.
# Цель операций – строка дефекта (тип DEFECT_UPDATE): ключ и блокировка – по строке; исполнитель получает только
# метод, путь и тело.

UPDATE_TYPE = "DEFECT_UPDATE"  # тип цели операций «Push в Hub»
# идёт обновление: взаимные запреты с привязкой, «Pull из Hub» и «Применить» сверки (п. 2) действуют и между
# шагами, когда операции нет (запись неизвестна, подтверждение не прочитано)
UPDATE_BUSY = ("putting", "confirming", "unknown")
UPDATE_SUCCESS = ("done", "done_diff")
UPDATE_NOTE_DONE = "сверено чтением: в Hub – отправленные заголовок и текст"
UPDATE_ONLY_IMPORTED = ("Обновляются только дефекты, занесённые из Hub (ADR-0125): дефект, созданный приложением, уже "
                        "написан текущим генератором.")
UPDATE_NOT_DONE = "Push в Hub можно только занесённый дефект «создан» с номером в Hub: обновите страницу."
UPDATE_SHOWN_CHANGED = "Предпросмотр обновления изменился (другая вкладка или новое чтение): обновите страницу."
UPDATE_ALREADY = "Обновление в Hub уже идёт: дождитесь его итога."
UPDATE_IN_PROGRESS = ("У дефекта идёт «Push в Hub»: дождитесь его итога (при неизвестном исходе – «Сверить», при "
                      "неудавшемся подтверждении – «Повторить чтение» во вкладке «Дефекты»).")
UPDATE_UNCONFIRMED_FIRST = ("Запись в Hub принята, но подтверждение не прочитано: сначала «Повторить чтение» или "
                            "заново «Push в Hub».")
UPDATE_PREVIEW_OPEN = "Предпросмотр обновления уже открыт: нажмите «Push в Hub» или «Отменить»."
UPDATE_SYNC_FIRST = "Сначала «Применить» или «Отменить» сверку с Hub: её предпросмотр не применён."
UPDATE_MANY_ROWS = ("У дефекта в приложении несколько строк (ещё строка {other}): это другая запись того же дефекта "
                    "Hub, обновление закрыто.")
BLOCK_REPEATED = ("Служебный блок в описании Hub встречается больше одного раза. Приложение сохраняет всё ниже первой границы как есть; "
                  "лишний блок можно убрать в Hub и нажать «Pull из Hub».")
UPDATE_NOT_OWNER = "Эта строка – привязка находок: «Push в Hub» и его шаги идут только из карточки дефекта."
UPDATE_FAMILY_UNMERGED = "Находка добавлена в дефект. Нажмите «Pull из Hub» и «Применить», затем Push."
UPDATE_FIX_NUMBER = "поправьте номер ID в заголовке в Hub и нажмите «Pull из Hub»"
UPDATE_CANCELLED_PUT = "запрос не отправлен – отменён до выдачи исполнителю"
UPDATE_OLD_WORKER = ("запрос не отправлен: исполнитель в ВМ не выполняет `PUT /defects/{id}` – обновите исполнитель в "
                     "ВМ (версия 0.9.23.dev4 или новее) и снова нажмите «Push в Hub»")
UPDATE_UNCONFIRMED = "запись принята Hub, но чтение не подтвердило отправленное содержимое – проверьте в Hub"
UPDATE_OBSERVED_OLD = "сейчас в Hub прежний текст – это не доказывает, что запрос не применился"
UPDATE_UNCLEAR = "содержимое в Hub отличается и от прежнего, и от отправленного – проверьте в Hub"
UPDATE_LOCAL_CHANGED = "решения, данные находок или текст набора изменились после предпросмотра"
_MANUAL = " – дефект правится в Hub вручную"
_VOID_TAGS = frozenset({"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source",
                        "track", "wbr"})


UPDATE_STALE = ("refused", "read_failed", "cancelled")


def clear_stale_update_in(c, owner_id: int) -> None:
    """После «Pull из Hub» и «Принять состояние Hub» итог прошлой подготовки Push (отказ, сбой чтения, «изменений
    нет») устарел: дефект приведён к Hub – строка его не показывает. Поколение сохраняется: формы
    прежних предпросмотров остаются устаревшими."""
    for r in c.execute("SELECT id, update_json FROM hub_defects WHERE COALESCE(draft_owner_id, id) = ?",
                       (int(owner_id),)).fetchall():
        state = loads(r["update_json"], {}) or {}
        if isinstance(state, dict) and state.get("phase") in UPDATE_STALE:
            c.execute("UPDATE hub_defects SET update_json = ? WHERE id = ?",
                      (dumps({"generation": int(state.get("generation") or 0)}), r["id"]))


def update_state(row: dict | None) -> dict:
    """Состояние попытки «Push в Hub» (update_json); нет – {}."""
    state = loads((row or {}).get("update_json"), {}) or {}
    return state if isinstance(state, dict) else {}


def update_busy(row: dict | None) -> bool:
    """Идёт «Push в Hub» (п. 2): операция шага в очереди или у исполнителя (update_op_id) либо фаза записи,
    подтверждения или неизвестного исхода – привязка, «Pull из Hub» и «Применить» сверки отказывают."""
    return bool((row or {}).get("update_op_id")) or str(update_state(row).get("phase") or "") in UPDATE_BUSY


def update_unconfirmed(row: dict | None) -> bool:
    """Фаза unconfirmed (п. 3, шаг 4): `PUT` выполнен, а чтение показало не отправленное. В UPDATE_BUSY её нет –
    «Подготовить обновление» (новое поколение) и «Повторить чтение» доступны, а «Pull из Hub» и «Применить» сверки
    отказывают: успех «Повторить чтение» пишет цели подготовки этой попытки и стёр бы добавленные сверкой находки."""
    return str(update_state(row).get("phase") or "") == "unconfirmed"


def update_confirmed(row: dict) -> bool:
    """Последствия строки – подтверждённое обновление текста (п. 4): text_generation > 0 и подтверждающая операция
    строки – подтверждающее чтение последнего успешного поколения. Первичное занесение (text_generation 0) – нет."""
    confirmed = update_state(row).get("confirmed") or {}
    return (int(row.get("text_generation") or 0) > 0 and isinstance(confirmed, dict) and bool(row.get("confirm_op_id"))
            and confirmed.get("op") == row.get("confirm_op_id"))


def _sentence(text: str) -> str:
    text = str(text or "").strip()
    return (text[:1].upper() + text[1:]) if text else ""


def update_view(row: dict) -> tuple[str, str, bool]:
    """Ход «Push в Hub» для строки вкладки и карточки: (текст, тон, конечное ли). Нет попытки – ('', '', True);
    шаг в очереди или у исполнителя – не конечное (вкладка опрашивает состояние)."""
    state = update_state(row)
    phase, note = str(state.get("phase") or ""), str(state.get("note") or "")
    number = str(row.get("hub_defect_id") or "")
    if not phase:
        return "", "", True
    if row.get("update_op_id"):
        step = str(state.get("step") or "")
        text = {"read1": f"Готовлю обновление: читаю дефект №{number} из Hub…",
                "read2": f"Перечитываю дефект №{number} перед записью в Hub…",
                "blank": f"Запрашиваю у Hub заготовку для служебного блока дефекта №{number}…",
                "model": f"Читаю у Hub данные находок для служебного блока дефекта №{number}: {len(state.get('model_done') or {})} из {len(state.get('model_for') or [])}…",
                "put": f"Записываю в Hub изменения дефекта №{number}…",
                "confirm": f"Запись принята Hub: проверяю дефект №{number} чтением…",
                "verify": f"Сверяю с Hub: читаю дефект №{number}…"}.get(step, f"Обновляю дефект №{number}…")
        return text, "", False
    refusals = "; ".join(str(x) for x in state.get("refusals") or [])
    diff = ", ".join(str(x) for x in state.get("diff") or [])
    texts = {
        "preview": ("Обновление подготовлено: проверьте предпросмотр и нажмите «Push в Hub»."
                    + (f" {_sentence(note)}." if note else ""), "warn" if note else ""),
        "refused": (f"Обновление не подготовлено: {refusals or note}.", "warn"),
        "read_failed": (f"Обновление не подготовлено: {note} – снова нажмите «Push в Hub».", "err"),
        "cancelled": (note or "Подготовка обновления отменена: в Hub ничего не уходило.", ""),
        "stale": (f"Обновление не отправлено: {note} – снова нажмите «Push в Hub», приложение подготовит "
                  "новый предпросмотр.", "warn"),
        "failed": (f"Обновление не выполнено: {note}.", "err"),
        "unknown": (f"Результат обновления неизвестен ({note or 'ответа нет'}): нажмите «Сверить» – приложение "
                    "прочитает дефект в Hub; повторно само не отправит.", "warn"),
        "confirming": (f"Запись принята Hub, но подтверждающее чтение не удалось ({note or 'ответа нет'}): нажмите "
                       "«Повторить чтение».", "warn"),
        "done": ("Обновлено в Hub: заголовок и текст – из сохранённого черновика.", "ok"),
        "done_diff": (f"Обновлено в Hub; в дефекте отличаются и другие поля ({diff}) – проверьте в Hub.", "warn"),
        "unconfirmed": (f"{_sentence(UPDATE_UNCONFIRMED)}."
                        + (" Отличаются поля: " + ", ".join(state["confirmation_diff"]) + "."
                           if state.get("confirmation_diff") else ""), "warn"),
        "observed_old": (f"{_sentence(UPDATE_OBSERVED_OLD)}: снова нажмите «Push в Hub».", "warn"),
        "unclear": (f"{_sentence(note or UPDATE_UNCLEAR)}.", "warn"),
    }
    text, tone = texts.get(phase, ("", ""))
    return text, tone, True


def update_read_item(row: dict) -> dict:
    """Чтение `GET /defects/{id}` шага обновления: цель – строка дефекта (DEFECT_UPDATE), ответ ведёт _on_update."""
    return dict(purpose="defect_read", request=read_request(str(row["hub_defect_id"])), hub_url=row["hub_url"],
                app_id=row.get("app_id"), project_id=int(row["project_id"]),
                targets=[{"defect_update": int(row["id"]), "issue_type": UPDATE_TYPE, "issue_id": int(row["id"])}])


def blank_target_ids(row: dict) -> list[int]:
    """Номера находок Hub целей строки – состав, по которому запрашивается и к которому привязана заготовка шага
    «blank» (`_targets` в blank_json, ревью dev31 круг 1)."""
    return sorted({int(t["issue_id"]) for t in loads(row.get("targets_json"), []) if isinstance(t, dict)
                   and str(t.get("issue_id") or "").isdigit() and int(t["issue_id"]) > 0})


def saved_blank_fits(row: dict) -> bool:
    """Сохранённая заготовка годится для нынешнего состава целей. Состав отмечается при создании и при шаге «blank»; заготовка другого состава не годится, шаг «blank» запросит новую."""
    blank = loads(row.get("blank_json"), {}) or {}
    if not isinstance(blank, dict) or not str(blank.get("description") or "").strip():
        return False
    recorded = blank.get("_targets")
    # прежняя заготовка без отметки годится как раньше: Hub отклоняет новую заготовку для уже привязанных находок (бэклог 67),
    # и у таких дефектов блок иначе потерялся бы при записи
    return recorded is None or recorded == blank_target_ids(row)


def update_blank_item(row: dict) -> tuple[dict | None, str]:
    """Заготовка `GET /defects/blank` по находкам дефекта – шаг «blank» обновления (dev31): у дефекта без блока Hub в
    описании и без годной заготовки блок берётся из свежей заготовки Hub по тем же находкам (ответ ведёт
    _on_update). (операция, '') или (None, почему нельзя: нет находок с номерами Hub, вид без типа Hub, нет
    приложения, слишком много находок для параметра issueIds)."""
    from app import hub_status
    targets = [{"issue_id": i} for i in blank_target_ids(row)]
    issue_type = hub_status.HUB_ISSUE_TYPE.get(str(row.get("kind") or ""))
    if not targets:
        return None, "у находок дефекта нет номеров Hub"
    if not issue_type:
        return None, f"вид дефекта «{row.get('kind') or '–'}» без типа находки Hub"
    if row.get("app_id") is None:
        return None, "у строки дефекта нет приложения Hub"
    try:
        request = blank_request(int(row["app_id"]), targets, issue_type)
    except (TypeError, ValueError, hub_ops.HubRequestRejected) as exc:
        return None, str(exc)
    return dict(purpose="defect_blank", request=request, hub_url=row["hub_url"], app_id=row.get("app_id"),
                project_id=int(row["project_id"]),
                targets=[{"defect_update": int(row["id"]), "issue_type": UPDATE_TYPE, "issue_id": int(row["id"])}]), ""


def put_request(defect_id: str, body: dict) -> dict:
    """`PUT /defects/{id}` – тело как у интерфейса Hub: объект чтения с новыми summary и description (п. 1)."""
    request = {"method": "PUT", "path": f"/defects/{int(defect_id)}", "body": body}
    hub_ops.check_request(request["method"], request["path"])
    return request


def update_put_item(row: dict, body: dict, generation: int) -> dict:
    """Операция записи defect_update: key_extra «строка:поколение» – новая явная попытка после выполненного PUT (новое
    поколение) не совпадает по ключу с прежней, повтор той же попытки отклоняется очередью."""
    return dict(purpose="defect_update", request=put_request(str(row["hub_defect_id"]), body), hub_url=row["hub_url"],
                app_id=row.get("app_id"), project_id=int(row["project_id"]),
                targets=[{"defect_update": int(row["id"]), "issue_type": UPDATE_TYPE, "issue_id": int(row["id"])}],
                text=str(body.get("summary") or ""), key_extra=f"defect-update:{int(row['id'])}:{int(generation)}")


# ---------------------------------------------------------------------------- блок Hub, описание, сравнение


class _TopLevel(HTMLParser):
    """Начала кусков описания верхнего уровня – абсолютные смещения в исходной строке: элемент верхнего уровня – от
    его открывающего тега до начала следующего куска; непустой текст вне элементов – свой кусок. Пустые элементы
    (br, img, hr…) глубину не меняют; закрывающий тег без открытого пропускается. Кусок текста начинается с первого
    непробельного знака: перевод строки перед ним (как между текстом команды и блоком Hub) в кусок не входит."""

    def __init__(self, text: str) -> None:
        super().__init__(convert_charrefs=True)
        self._text = text
        self._lines = [0]
        at = text.find("\n")
        while at != -1:
            self._lines.append(at + 1)
            at = text.find("\n", at + 1)
        self.starts: list[int] = []
        self._stack: list[str] = []
        self._in_text = False

    def _offset(self) -> int:
        line, col = self.getpos()
        return self._lines[line - 1] + col

    def _top(self) -> None:
        if not self._stack:
            self.starts.append(self._offset())
            self._in_text = False

    def handle_starttag(self, tag: str, attrs: list) -> None:
        self._top()
        if tag not in _VOID_TAGS:
            self._stack.append(tag)

    def handle_startendtag(self, tag: str, attrs: list) -> None:
        self._top()

    def handle_endtag(self, tag: str) -> None:
        if tag in self._stack:
            while self._stack.pop() != tag:
                pass

    def handle_data(self, data: str) -> None:
        if not self._stack and data.strip() and not self._in_text:
            at = self._offset()
            while at < len(self._text) and self._text[at].isspace():  # в исходной строке: сущность – не пробел
                at += 1
            self.starts.append(at)
            self._in_text = True


def _top_level_starts(text: str) -> list[int]:
    parser = _TopLevel(text)
    parser.feed(text)
    parser.close()
    return parser.starts or [0]


class _Canon(HTMLParser):
    """Каноническая форма HTML для сравнения блока Hub (dev33). Допуск – ровно то, что Hub делает с блоком:
    убирает форматирующие переносы и отступы между тегами и вставляет пустой `<tbody>`. Поэтому
    не учитываются только текстовые узлы из одних пробелов, где есть перенос строки (отступы разметки), и `tbody` без
    атрибутов; атрибуты идут по алфавиту. Остальное сохраняется: текст (пробелы внутри него сжимаются до одного, но
    пробел на границе со строчным элементом остаётся), пробел без переноса между элементами, содержимое `<pre>`
    как есть, атрибуты любых элементов, `thead`. Каждый токен помнит смещение в исходной строке – по ним
    block_start ищет блок за один разбор."""

    def __init__(self, text: str = "") -> None:
        super().__init__(convert_charrefs=True)
        self.out: list[str] = []
        self.offsets: list[int] = []
        self._pre = 0
        self._tbody: list[bool] = []  # открытые tbody: сохраняется ли тег (есть атрибуты) – ревью dev33, круг 2
        self._lines = [0]
        for i, ch in enumerate(text):
            if ch == "\n":
                self._lines.append(i + 1)

    def _pos(self) -> int:
        line, col = self.getpos()
        return self._lines[line - 1] + col if line - 1 < len(self._lines) else 0

    def _emit(self, token: str, offset: int | None = None) -> None:
        self.offsets.append(self._pos() if offset is None else offset)
        self.out.append(token)

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag == "tbody":
            self._tbody.append(bool(attrs))
            if not attrs:
                return
        if tag == "pre":
            self._pre += 1
        self._emit("<" + tag + "".join(f' {k}="{html.escape(v or "", quote=True)}"' for k, v in sorted(attrs)) + ">")

    def handle_startendtag(self, tag: str, attrs) -> None:
        self._emit("<" + tag + "".join(f' {k}="{html.escape(v or "", quote=True)}"' for k, v in sorted(attrs)) + ">")

    def handle_endtag(self, tag: str) -> None:
        if tag in _CANON_VOID:
            return
        if tag == "tbody" and not (self._tbody.pop() if self._tbody else True):
            return
        if tag == "pre" and self._pre:
            self._pre -= 1
        self._emit(f"</{tag}>")

    def handle_data(self, data: str) -> None:
        if self._pre:
            if data:
                self._emit(html.escape(data, quote=False))
            return
        if not data.strip(" \t\r\n"):
            if "\n" in data or "\r" in data:
                return  # отступ разметки между тегами – Hub его убирает
            self._emit(" ")
            return
        # ведущие пробелы – отдельным токеном: текстовый кусок верхнего уровня (и блок Hub) начинается с первого
        # непробельного знака, граница блока должна совпадать с границей токена (ревью dev33, круг 2)
        lead = len(data) - len(data.lstrip(" \t\r\n"))
        if lead:
            self._emit(" ")
        # смещение первого непробельного знака – по исходному HTML: пробелы могли прийти сущностями (&#10;, &#32;),
        # data их уже раскрыл (ревью dev33, круг 3)
        self._emit(html.escape(re.sub(r"[ \t\r\n]+", " ", data[lead:]), quote=False),
                   offset=_skip_space(self.rawdata, self._pos()) if lead else None)


_CANON_VOID = frozenset({"br", "hr", "img", "input", "meta", "link", "col", "wbr"})
_ENTITY = re.compile(r"&(?:#[0-9]+|#[xX][0-9a-fA-F]+|[A-Za-z][A-Za-z0-9]*);")


def _skip_space(text: str, i: int) -> int:
    """Смещение первого знака после пробелов и пробельных сущностей (&#10;, &#32; …), начиная с i, в исходном HTML."""
    while i < len(text):
        if text[i] in " \t\r\n":
            i += 1
            continue
        found = _ENTITY.match(text, i) if text[i] == "&" else None
        if found and html.unescape(found.group(0)) in (" ", "\t", "\r", "\n"):
            i = found.end()
            continue
        break
    return i


def _canon(value: Any) -> _Canon:
    text = str(value or "")
    parser = _Canon(text)
    parser.feed(text)
    parser.close()
    return parser


def canonical_html(value: Any) -> str:
    """HTML в канонической форме (_Canon) – для сравнения блока Hub с допуском переформатирования Hub."""
    return "".join(_canon(value).out)


def block_start(description: Any, block: Any) -> int:
    """Где в описании (как его вернул Hub) начинается блок, равный block с допуском переформатирования Hub: смещение
    куска верхнего уровня, с которого остаток описания в канонической форме равен блоку; нет – -1. Побайтное
    совпадение – сразу; иначе описание разбирается один раз, остаток сравнивается по смещениям токенов."""
    text, wanted = str(description or ""), str(block or "")
    if not wanted.strip():
        return -1
    if text.endswith(wanted):
        # совпадение байт в байт – та же граница, что ниже: начало куска верхнего уровня, а не середина чужого (бэклог 69)
        start = len(text) - len(wanted)
        first = _skip_space(text, start)
        return start if any(s <= first and _skip_space(text, s) == first for s in _top_level_starts(text)) else -1
    # ведущие пробелы блока (переносы, &#10;) – не содержание: сравнение идёт с первого непробельного токена
    canon = canonical_html(wanted).lstrip(" ")
    if not canon:
        return -1
    parser = _canon(text)
    whole = "".join(parser.out)
    if not whole.endswith(canon):
        return -1
    starts = _top_level_starts(text)
    pos = len(whole)
    for token, offset in zip(reversed(parser.out), reversed(parser.offsets), strict=True):
        pos -= len(token)
        if pos == len(whole) - len(canon):
            # остаток с этого токена равен блоку; граница – начало куска верхнего уровня, от которого после пробелов
            # и пробельных сущностей идёт этот токен (кусок может начинаться сущностью &#10; – ревью dev33, круги 3–4)
            first = _skip_space(text, offset)
            fits = [start for start in starts if start <= first and _skip_space(text, start) == first]
            return min(fits) if fits else -1
        if pos < len(whole) - len(canon):
            return -1
    return -1


def hub_block(description: Any) -> tuple[str, str]:
    """Исходная подстрока блока Hub в описании (п. 2): от начала куска верхнего уровня, где единственная строка
    «Информация об объекте сканирования:», до конца описания, без пересериализации – (подстрока, ''). Отказ – ('',
    причина: дефект правится вручную): строки нет или она не одна; она не выделяется в один кусок; в её куске до неё
    есть другой текст (блок Hub склеен с текстом команды)."""
    text = str(description or "")
    if IMPORT_BOUNDARY not in description_lines(text):
        return "", f"в описании нет строки «{IMPORT_BOUNDARY}»" + _MANUAL
    starts = _top_level_starts(text)
    hits = []
    for i, start in enumerate(starts):
        end = starts[i + 1] if i + 1 < len(starts) else len(text)
        lines = description_lines(text[start:end])
        if IMPORT_BOUNDARY in lines:
            hits.append((start, lines))
    if not hits:
        return "", f"строка «{IMPORT_BOUNDARY}» не выделяется в отдельный элемент описания" + _MANUAL
    start, lines = hits[0]  # блок повторён (ADR-0137): от первой границы до конца описания, байт в байт
    if IMPORT_BOUNDARY in description_lines(text[:start]):  # первая граница не выделилась: второй блок её не заменяет
        return "", f"строка «{IMPORT_BOUNDARY}» не выделяется в отдельный элемент описания" + _MANUAL
    if any(line.strip() for line in lines[:lines.index(IMPORT_BOUNDARY)]):
        return "", (f"блок Hub склеен с текстом команды: в одном элементе описания до «{IMPORT_BOUNDARY}» есть другой "
                    "текст" + _MANUAL)
    return text[start:], ""


def block_text_start(description: Any) -> int:
    """Где в описании Hub начинается его служебный блок – начало куска верхнего уровня с единственной строкой
    «Информация об объекте сканирования:» (как у hub_block); блок не выделяется – -1."""
    text = str(description or "")
    part, problem = hub_block(text)
    return len(text) - len(part) if part and not problem else -1


def block_units(value: Any) -> list[str]:
    """Служебный блок единицами текста со свёрнутыми пробелами (ADR-0146): так Hub переписывает блок, не меняя содержания, –
    вычищает декларации и «теги» из вставленного текста бюллетеня, заново экранирует сущности, табуляцию и неразрывный
    пробел заменяет пробелом. Текст, адреса ссылок и порядок единиц сравниваются полностью."""
    return [" ".join(unit.split()) for unit in description_units(value)]


def keep_hub_markup(defect: Any, description: str) -> str:
    """Текст дефекта в приложении тот же, что в Hub (по строкам разметки), – описание Hub не переписывается ни ради
    разметки, ни ради блока Hub ниже текста (без правки – никаких разниц): «Push в Hub»
    без правки текста – «Изменений для отправки нет». С dev30 собранное описание само несёт блок: сравниваются
    текстовые части обоих описаний."""
    hub = str((defect or {}).get("description") or "") if isinstance(defect, dict) else ""
    if not hub or not description:
        return description
    # сравнивается текстовая часть описания Hub (без его блока «Информация об объекте сканирования»): текст приложения
    # тот же – описание Hub целиком, с блоком, остаётся; правка текста заменяет описание целиком (ADR-0125)
    text, _, _ = split_description(hub)
    mine, _, _ = split_description(description)
    # по строкам: перенос строки или новый абзац – правка оператора, не разметка (ревью dev15, B1)
    if _norm_lines(text) == _norm_lines(mine):
        return hub
    return description


LAYOUT_KEPT = ("Пустые строки подряд и отступы в начале строк сравнение с Hub не учитывает: если правка касалась "
               "только их, описание в Hub не переписано – сохранит ли Hub такие правки, не проверялось")
# оформление описания Hub, которого не видит сравнение по строкам: пустой абзац, неразрывный пробел или пробелы в
# начале абзаца или строки – и обычные пробелы там же перед текстом (ревью Codex круга 5; перевод строки между
# тегами отступом не считается)
_HUB_LAYOUT = re.compile(r"<p>\s*(?:<br\s*/?>)?\s*</p>|(?:<p>|<br\s*/?>)\s*(?:&nbsp;|&#160;|\xa0)"
                         r"|(?:<p>|<br\s*/?>)[ \t]+(?=[^\s<])", re.IGNORECASE)


def layout_only_change(command_text: str, description: Any) -> bool:
    """Слова текста дефекта в приложении и в описании Hub те же, а в одном из них есть то, чего сравнение по строкам
    разметки не различает: пустые строки подряд или отступы в начале строк (ADR-0149). Такое отличие – добавленное
    или убранное – в Hub не уходит (keep_hub_markup), и Push говорит об этом прямо (LAYOUT_KEPT), а не молча
    (ревью круга 3: смотреть и на текст приложения, и на разметку Hub до её нормализации)."""
    hub = str(description or "")
    if not hub:
        return False
    text, _, _ = split_description(hub)
    mine = [line.rstrip() for line in str(command_text or "").replace("\r\n", "\n").strip("\n").split("\n")]
    words = [x for x in _norm_lines("\n".join(mine)) if x] == [x for x in _norm_lines(text) if x]
    if not words:
        return False
    start = block_text_start(hub)
    head = hub[:start] if start >= 0 else hub
    mine_layout = any(x and x[:1] in " \t" for x in mine) or "\n\n\n" in "\n".join(mine)
    return mine_layout or bool(_HUB_LAYOUT.search(head)) or _hub_indented(head)


def layout_warning(command_text: str, built: str, kept: str, hub_description: str) -> bool:
    """Push называет LAYOUT_KEPT: описание Hub оставлено как есть (kept – оно), собранное приложением описание другое
    (built), и разница – только в оформлении (layout_only_change). Описание Hub ровно то, что собрало бы приложение, –
    оформление не расходится, пояснять нечего (ревью Kimi круга 6). Признак приблизительный (ADR-0149 п. 5)."""
    return kept == hub_description and built != kept and layout_only_change(command_text, kept)


def _hub_indented(html_text: str) -> bool:
    """В описании Hub есть строка с отступом в начале – и во вложенной разметке (`<p><strong>&nbsp;…`): разбор той
    же разметки, что у сверки, до нормализации пробелов (ревью Codex круга 6)."""
    parser = _DescriptionLines()
    parser.feed(str(html_text or ""))
    parser.result()  # завершает и последнюю строку (без внешнего блочного тега), ревью Codex круга 7
    return parser.indented


def _norm_lines(text: str) -> list[str]:
    """Строки текста с нормализованными пробелами внутри строки; пустые строки по краям не учитываются."""
    lines = [hub_ops.normalize_text(line) for line in str(text or "").split("\n")]
    while lines and not lines[0]:
        lines.pop(0)
    while lines and not lines[-1]:
        lines.pop()
    return lines


def update_description(command_text: str, block: str = "") -> tuple[str, str]:
    """Новое описание (п. 2, с 0.9.26.dev30): текст дефекта из приложения в HTML и следом служебный
    блок Hub (block – исходная подстрока блока из описания Hub или блок заготовки, block_for_write; пусто – без
    блока). Сведения Hub об объекте сканирования из описания не пропадают; текст в приложении
    и в Hub один и тот же. Собранное проверяется: текст встречается в нём один раз.
    (описание, '') или ('', причина)."""
    if IMPORT_BOUNDARY in description_lines(command_html(command_text)):
        # так Hub отмечает начало своего блока: при чтении текст разделился бы по ней (ревью A2 31.10)
        return "", (f"в тексте дефекта есть отдельная строка «{IMPORT_BOUNDARY}» – уберите или перефразируйте её: "
                    "Hub отмечает ею начало своего блока")
    text_html = command_html(command_text)
    expected = command_plain(command_text)
    # текст встречается в текстовой части один раз; совпадения внутри блока Hub (например, цитата текста в сведениях
    # Hub) повтором не считаются (ревью dev30, круг 4)
    times = plain_text(text_html).count(expected) if expected else 0
    if times != 1:
        return "", f"в собранном описании текст команды встречается {times} раз" + _MANUAL
    return description_html(command_text, block), ""


def built_blank_outdated(row: dict, defect: dict | None) -> bool:
    """Блок, собранный приложением, описывает находки своего состава: в Hub к дефекту привязаны другие – он не годится (ADR-0139)."""
    built = (loads(row.get("blank_json"), {}) or {}).get("built_from_model") is True
    return built and isinstance(defect, dict) and isinstance(defect.get("linkedIssues"), list) and _target_pairs(row) != linked_pairs(defect)


def block_for_write(row: dict, defect: dict | None) -> tuple[str, str]:
    """Служебный блок Hub для описания при записи (dev30): у дефекта в Hub блок есть – его исходная подстрока
    (hub_block, байт в байт); в описании Hub границы нет – блок заготовки, полученной при создании (blank_json), если
    был; ни того, ни другого – «». Граница в описании Hub есть, а блок не выделяется (склеен с текстом, две границы) –
    уходит блок заготовки или только текст, с предупреждением (склеенный блок – не причина отказа).
    (блок, предупреждение или '')."""
    hub = str((defect or {}).get("description") or "") if isinstance(defect, dict) else ""
    # заготовка другого состава (шаг «blank» после «Pull из Hub») не годится: без неё – только текст (ревью dev31, круг 2)
    fits = saved_blank_fits(row) and not built_blank_outdated(row, defect)
    blank = str((loads(row.get("blank_json"), {}) or {}).get("description") or "") if fits else ""
    if hub and IMPORT_BOUNDARY in description_lines(hub):
        block, problem = hub_block(hub)
        if not problem:
            return block, ""
        why = problem.replace(_MANUAL, "")
        return blank, (f"блок Hub в описании не выделяется ({why}): в описание уйдёт "
                       + ("блок заготовки" if blank else "только текст приложения"))
    return blank, ""


def block_mode_of(defect: dict | None, block: str, block_note: str, description: str) -> str:
    """Что будет с блоком Hub при записи (подсказка предпросмотра Push, dev30): kept – описание Hub остаётся как есть;
    same – текст меняется, блок Hub остаётся исходной подстрокой; added – в Hub блока не было, добавляется блок
    заготовки; replaced – блок в Hub не выделяется, уходит блок заготовки; dropped – не выделяется и заготовки нет,
    уходит только текст; none – блока нет ни в Hub, ни в заготовке."""
    if description and description == str((defect or {}).get("description") or ""):
        return "kept"  # в том числе склеенный блок при неизменном тексте
    if block_note:
        return "replaced" if block else "dropped"
    if not block:
        return "none"
    return "same" if hub_has_block(defect) else "added"


def hub_has_block(defect: dict | None) -> bool:
    """В описании дефекта Hub есть граница блока «Информация об объекте сканирования:»."""
    hub = str((defect or {}).get("description") or "") if isinstance(defect, dict) else ""
    return bool(hub) and IMPORT_BOUNDARY in description_lines(hub)


def block_for_display(row: dict, defect: dict | None) -> tuple[str, str]:
    """Служебный блок Hub для карточки (dev30, ревью круг 2): (очищенная разметка, источник). Источник «hub» – блок
    из описания дефекта в Hub, выделенный как исходная подстрока; «blank» – блок заготовки, который уйдёт в описание
    при следующей записи (в Hub блока нет); «built» – то же, но блок собран приложением (ADR-0139); «» – блок не показывается: в Hub его нет и заготовки нет, либо блок в
    описании Hub не выделяется (склеен с текстом) – тогда карточка показывает все строки описания Hub как есть."""
    if hub_has_block(defect):
        block, problem = hub_block(str((defect or {}).get("description") or ""))
        return (sanitize_hub_html(block), "hub") if block and not problem else ("", "")
    if not saved_blank_fits(row) or built_blank_outdated(row, defect):  # заготовка другого состава в описание не уйдёт – и не показывается
        return "", ""
    built = (loads(row.get("blank_json"), {}) or {}).get("built_from_model") is True
    return sanitize_hub_html(blank_for_send(row).block), "built" if built else "blank"


_SAFE_TAGS = frozenset({"h1", "h2", "h3", "h4", "h5", "h6", "p", "br", "hr", "div", "span", "table", "thead", "tbody",
                        "tr", "th", "td", "ul", "ol", "li", "b", "strong", "i", "em", "code", "pre", "a", "blockquote"})
_SANITIZER_VOID = frozenset({"br", "hr"})
_SAFE_HREF = re.compile(r"^https?://", re.IGNORECASE)


class _HubHtmlSanitizer(HTMLParser):
    """HTML блока Hub → разметка из допустимого набора тегов без атрибутов (у ссылок – только href http(s) с
    rel/target), текст экранирован; script и style с содержимым выбрасываются. Стилей и скриптов в карточке нет
    (CSP, ADR-0015)."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.out: list[str] = []
        self.skip = 0
        self.open: list[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        tag = tag.lower()
        if tag in ("script", "style"):
            self.skip += 1
            return
        if self.skip or tag not in _SAFE_TAGS:
            return
        if tag in _SANITIZER_VOID:
            self.out.append(f"<{tag}>")
            return
        if tag == "a":
            href = str(dict(attrs).get("href") or "")
            if _SAFE_HREF.match(href):
                self.out.append(f'<a href="{html.escape(href, quote=True)}" rel="noopener noreferrer" target="_blank">')
            else:
                self.out.append("<a>")
        else:
            self.out.append(f"<{tag}>")
        self.open.append(tag)

    def handle_startendtag(self, tag: str, attrs) -> None:
        self.handle_starttag(tag, attrs)
        if tag.lower() not in _SANITIZER_VOID:
            self.handle_endtag(tag)

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag in ("script", "style"):
            self.skip = max(0, self.skip - 1)
            return
        if self.skip or tag not in _SAFE_TAGS or tag in _SANITIZER_VOID or tag not in self.open:
            return
        while self.open:  # закрываем вложенные незакрытые до этого тега
            last = self.open.pop()
            self.out.append(f"</{last}>")
            if last == tag:
                break

    def handle_data(self, data: str) -> None:
        if not self.skip:
            self.out.append(html.escape(data, quote=False))

    def result(self) -> str:
        while self.open:
            self.out.append(f"</{self.open.pop()}>")
        return "".join(self.out)


def sanitize_hub_html(value: Any) -> str:
    """HTML из Hub для показа в карточке: только допустимые теги, без атрибутов и скриптов (dev30)."""
    parser = _HubHtmlSanitizer()
    parser.feed(str(value or ""))
    parser.close()
    return parser.result().strip()


def update_content_new(defect: dict, sent: dict) -> bool:
    """В Hub – отправленное (п. 3, «новое содержимое»): summary равен отправленному заголовку; description равен
    отправленному точно либо – если Hub нормализовал HTML – текст команды по структурному разбору равен отправленному,
    а подстрока блока Hub – исходной."""
    if str(defect.get("summary") or "") != str(sent.get("summary") or ""):
        return False
    description = str(defect.get("description") or "")
    if description == str(sent.get("description") or ""):
        return True
    # всё описание целиком (с допуском нормализации HTML Hub): совпадение части выше блока Hub не доказывает, что
    # описание заменено – прежний объект с тем же текстом и хвостом был бы ложным успехом (ревью A3, B1 31.10);
    # по строкам: перенос строки – правка, прежний объект его не подтверждает; пустые строки (границы абзацев) Hub
    # может расставить по-своему (ревью dev15, круг 2)
    def lines(value: Any) -> list[str]:
        return [line for line in _norm_lines(_whole_text(value)) if line]

    sent_description = str(sent.get("description") or "")
    sent_head, seen_head = sent_description, description
    if IMPORT_BOUNDARY in description_lines(sent_description):
        # отправленное несёт блок Hub (dev30): в Hub он должен остаться исходной подстрокой, байт в байт (ADR-0125
        # п. 2); с допуском нормализации сверяется только текст выше него
        block, problem = hub_block(sent_description)
        if block and not problem:
            # Hub хранит блок, переформатировав HTML (убирает переносы и отступы между тегами,
            # вставляет tbody) – блок сверяется в канонической форме; другой текст или строки блока – не успех (dev33)
            start = block_start(description, block)
            if start < 0:
                # Hub переписал блок сильнее канонической формы (декларация DOCTYPE и «теги» из текста
                # бюллетеня вычищены, сущности экранированы заново, табуляция стала пробелом) – блок сверяется единицами
                # текста, как чужой блок (ADR-0124 п. 9; ADR-0146); текст выше него – по-прежнему строками
                start = block_text_start(description)
                if start < 0 or block_units(block) != block_units(description[start:]):
                    return False
            sent_head, seen_head = sent_description[:-len(block)], description[:start]
    # номера списка `<ol>` разбор подставляет сам: прежний список не доказывает, что дошли пункты «1)» текстом (ревью
    # dev14: PUT не применился, чтение вернуло прежний `<ol>` – не успех); обратное – отправленный раньше `<ol>`
    # прочитан пунктами текстом – нормализация, сверяется текстом (ADR-0125). Проверка – по текстовым частям: списки
    # внутри блока Hub её не отключают (ревью dev30, круг 5)
    if _LIST_TAG.search(seen_head) is not None and _LIST_TAG.search(sent_head) is None:
        return False
    return lines(seen_head) == lines(sent_head)


_LIST_TAG = re.compile(r"<\s*(?:ol|ul|li)\b", re.IGNORECASE)


def _whole_text(value: Any) -> str:
    """Всё описание текстом – строками разметки, без деления на текст и блок Hub."""
    return "\n".join(description_lines(value)).strip("\n")


def update_other_diffs(base: dict, defect: dict) -> list[str]:
    """«Прочие поля» (п. 3): поля объекта второго чтения, кроме summary, description и updateTs, которые в
    подтверждающем чтении другие – называются, без автоматических действий."""
    skip = {"summary", "description", "updateTs"}
    return sorted(str(k) for k in set(base) | set(defect)
                  if k not in skip and base.get(k, _MISSING) != defect.get(k, _MISSING))


def _changed_fields(first: dict, second: dict) -> list[str]:
    """Поля, в которых второе чтение отличается от первого, кроме updateTs (п. 3, шаг 2); поле, которого в одном из
    чтений нет, отличается и от null."""
    from app.defect_fields import equal
    return sorted(str(k) for k in set(first) | set(second)
                  if k != "updateTs" and not equal(first.get(k, _MISSING), second.get(k, _MISSING)))


_MISSING = object()  # поля нет в объекте – не то же, что null


def parts_without_app(parts) -> str:
    """Части отметки «Внесено в Hub» без версии приложения. Версия – пояснение к формату текста в карточке
    (entered_change_reasons); сам текст сверяется своим отпечатком. В отпечатке подготовки версия делала любой
    открытый предпросмотр «изменившимся» после развёртывания новой сборки."""
    raw = str(parts or "")
    data = loads(raw, None)
    if not isinstance(data, dict) or "app" not in data:
        return raw
    return json.dumps({k: v for k, v in data.items() if k != "app"}, sort_keys=True)


def update_prep_sig(prep: dict, *, fields_contract: bool = True) -> str:
    """Отпечаток подготовленного обновления: вид, заголовок, текст команды, ключи номера, цели (номер находки, редакция
    решения, отпечаток данных, отпечаток текста и части отметки без версии приложения), отпечаток набора SCA –
    предпросмотр и постановка `PUT` сравнивают его."""
    targets = [[str(t.get("hub_id") or ""), t.get("revision"), str(t.get("sig") or ""), str(t.get("decision_hash", t.get("entered_hash")) or ""),
                parts_without_app(t.get("entered_parts"))] for t in prep.get("targets") or []]
    return text_hash(dumps({"kind": str(prep.get("kind") or ""), "summary": str(prep.get("summary") or ""),
                            "command_text": str(prep.get("command_text") or ""),
                            "number_keys": sorted(str(k) for k in prep.get("number_keys") or []), "targets": targets,
                            "fingerprint": str(prep.get("fingerprint") or ""),
                            "draft_revision": prep.get("draft_revision"), "draft_fields_json": prep.get("draft_fields_json"),
                            **({"draft_fields_basis_json": prep.get("draft_fields_basis_json")} if fields_contract else {}),
                            "members_snapshot": prep.get("members_snapshot"), "conflicts_json": prep.get("conflicts_json")}))


def _observed(row: dict, defect: dict, closed_at: str = "") -> str:
    """Наблюдаемый снимок Hub (п. 4) для import_json – как его пишет «Применить» сверки: разбор чтения, цели строки
    (accepted) прежние – состав ответа целей не меняет."""
    previous = loads(row.get("import_json"), {}) or {}
    accepted = previous.get("accepted") if isinstance(previous, dict) else []
    return dumps({**_read_of(defect), "accepted": accepted or [], "read_at": str(closed_at or "")})


def _number_refusals(c, row: dict, summary: Any, entries: Any, unexported: Any = ()) -> list[str]:
    """Номер ID из заголовка: есть, однозначен, равен резерву строки, не занят другим – ключами defects вне собственных
    (entries – находки дефекта) и резервами строк вне семьи дефекта."""
    pid = int(row["project_id"])
    reserved = row.get("number")
    number, number_why = title_number(summary)
    if not isinstance(reserved, int) or isinstance(reserved, bool) or reserved <= 0:
        return ["нет номера: у строки нет номера ID" + (
            f" (в заголовке Hub теперь ID{number}) – сначала «Pull из Hub» и «Применить»" if number
            else f" – {UPDATE_FIX_NUMBER}")]
    if number is None and number_why != NO_NUMBER:
        return [f"{number_why} – {UPDATE_FIX_NUMBER}"]
    number = reserved if number is None else number  # в заголовке номера нет: Push вернёт номер дефекта (ADR-0138)
    if number != reserved:
        return [f"номер в заголовке Hub изменился (было ID{reserved}, стало ID{number}) – сначала «Pull из "
                "Hub» и «Применить»"]
    own = own_number_keys_in(c, row, entries, unexported)
    keys = [k for k in Database.defect_keys_with_number_in(c, pid, number) if k not in own]
    family = family_ids_in(c, row)
    others = [r for r in Database.hub_defects_with_number_in(c, pid, number, exclude_id=int(row["id"]))
              if int(r["id"]) not in family]
    if keys or others:
        who = (["находки: " + ", ".join(keys[:5]) + (f" и ещё {len(keys) - 5}" if len(keys) > 5 else "")]
               if keys else [])
        who += [f"дефект {bound_label(r) or 'из карточки'} (строка {r['id']})" for r in others[:5]]
        return [f"номер ID{number} занят другим в приложении ({'; '.join(who)}) – {UPDATE_FIX_NUMBER}"]
    return []


def update_hub_problems(c, row: dict, defect: dict, prep: dict) -> tuple[list[str], list[str]]:
    """Проверки свежего дефекта Hub (п. 2) на соединении c – до предпросмотра (общее соединение) и повторно в
    транзакции постановки `PUT`: состав (находка из выгрузки вне целей – отказ «сначала «Pull из Hub»», находки не из
    выгрузки – предупреждение; отсутствие цели в ответе – не отвязка), номер ID из заголовка (есть, однозначен, равен
    резерву строки, не занят другим – ключами defects вне собственных и резервами других строк), будущие ключи номера
    целей – без номера или с этим же. (отказы, предупреждения)."""
    pid = int(row["project_id"])
    refusals: list[str] = []
    warnings: list[str] = []
    targets = loads(row.get("targets_json"), [])
    own_ids = {str(t.get("hub_id") or "") for t in targets}
    linked = sorted(linked_pairs(defect))
    found = Database.import_findings_in(c, pid, [str(i) for i, _ in linked])
    added: list[str] = []
    unexported: list[dict] = []
    for issue_id, issue_type in linked:
        hub_id = str(issue_id)
        f = found.get(hub_id)
        if f is not None and not f["missing"] and hub_status.HUB_ISSUE_TYPE.get(f["kind"]) == issue_type:
            if hub_id not in own_ids:
                added.append(hub_id)
        else:
            unexported.append({"hub_id": hub_id, "issue_type": issue_type, "why": NOT_IN_EXPORT})
    if added:
        refusals.append(f"в Hub к дефекту добавлены находки {', '.join(added)}: сначала «Pull из Hub»")
    if unexported:
        warnings.append("в составе дефекта в Hub есть находки не из текущей выгрузки: "
                        + ", ".join(e["hub_id"] for e in unexported) + " – в обновлении они не участвуют")
    number_refusals = _number_refusals(c, row, defect.get("summary"), targets, unexported)
    refusals += number_refusals
    number = title_number(defect.get("summary"))[0] or row.get("number")
    if number is not None and number == row.get("number"):
        for key in prep.get("number_keys") or []:
            have = Database.defect_number_in(c, pid, str(key))
            if have is not None and have != number:
                refusals.append(f"у ключа {key} уже номер ID{have}, а не ID{number} – {UPDATE_FIX_NUMBER}")
    return refusals, warnings


PLACE_PENDING = ("Место находок {ids} в наборах нужно выбрать заново (после слияния пакетов): выберите его в карточке "
                 "находки, затем подготовьте обновление.")


def pending_place_problem(c, current: dict) -> str:
    """Общий серверный предикат (план dev17, п. 4.5): у целей дефекта место в наборах ждёт выбора оператора после
    слияния пакетов – подготовка обновления недоступна и кнопке, и прямому запросу, и открытому предпросмотру."""
    from app.defect_drafts import typed_ids
    # цели – только с тем же типом связи, что вид находки: SAST:73001 не ждёт места SCA-находки 73001 (проверяющий
    # агент ревью шага 4)
    ids = sorted(set(typed_ids(c, current["project_id"], loads(current.get("targets_json"), []))))
    if not ids:
        return ""
    marks = ",".join("?" * len(ids))
    rows = c.execute(f"SELECT hub_id FROM sca_set_members WHERE project_id = ? AND hub_id IN ({marks})"
                     " AND pending_reason <> '' ORDER BY hub_id", (current["project_id"], *ids)).fetchall()
    return PLACE_PENDING.format(ids=", ".join(str(r["hub_id"]) for r in rows)) if rows else ""


def _update_idle_problem(c, current: dict, own_op: int | None = None, *, local=False) -> str:
    """Почему шаг обновления не ставится (п. 2), по строке, прочитанной на соединении c: идёт «Pull из Hub» или
    «Проверить в Hub», идёт другой шаг обновления (кроме own_op – операции, ответ на которую сейчас применяется),
    незакрытая операция цепочки, неприменённый предпросмотр сверки, у дефекта несколько живых строк, место целей в
    наборах ждёт выбора после слияния пакетов; '' – можно."""
    if not local and loads(current.get("conflicts_json"), []):
        return "У дефекта есть неразрешённые конфликты."
    if problem := pending_place_problem(c, current):
        return problem
    if current.get("sync_op_id"):
        return "Идёт «Pull из Hub»: дождитесь её итога."
    if current.get("verify_op_id"):
        return "Идёт проверка дефекта в Hub: дождитесь её итога."
    if current.get("update_op_id") and current.get("update_op_id") != own_op:
        return UPDATE_ALREADY
    for field in ("blank_op_id", "create_op_id", "read_op_id", "link_op_id"):
        op_id = current.get(field)
        found = c.execute("SELECT state FROM hub_ops WHERE id = ?", (int(op_id),)).fetchone() if op_id else None
        if found is not None and found["state"] in hub_ops.OPEN_STATES:
            return f"У строки дефекта есть незакрытая операция №{op_id}: дождитесь её итога."
    sync_state = loads(current.get("sync_json"), {}) or {}
    if isinstance(sync_state, dict) and sync_state.get("read"):
        return UPDATE_SYNC_FIRST
    owner_id = int(current.get("draft_owner_id") or current["id"])
    if owner_id != int(current["id"]):  # Push и его шаги – только от владельца: остальной код читает его цели (ADR-0136)
        return UPDATE_NOT_OWNER
    if not defect_drafts.family_single_in(c, current):
        return UPDATE_FAMILY_UNMERGED
    live = Database.hub_defect_live_in(c, str(current.get("hub_url") or ""), current.get("app_id"),
                                       str(current.get("hub_defect_id") or ""), exclude_id=int(current["id"]), owner_id=owner_id)
    if live is not None:
        return UPDATE_MANY_ROWS.format(other=live["id"])
    return ""


def _current_in(c, row: dict) -> dict:
    found = c.execute("SELECT * FROM hub_defects WHERE id = ?", (int(row["id"]),)).fetchone()
    if found is None:
        raise ValueError("Дефект не найден: обновите страницу.")
    return dict(found)


def prep_changes(new: dict, prep: dict) -> list[str]:
    """Что именно изменилось между предпросмотром (new – сохранённая подготовка) и текущей подготовкой prep: словами
    для оператора (прежний отказ «изменилось после предпросмотра» не говорил, что изменилось)."""
    out: list[str] = []
    if str(new.get("summary") or "") != str(prep.get("summary") or ""):
        out.append("заголовок")
    if str(new.get("command_text") or "") != str(prep.get("command_text") or ""):
        out.append("текст дефекта")
    if "draft_revision" in new and new.get("draft_revision") != prep.get("draft_revision"):
        out.append("черновик сохранён заново")
    if "members_snapshot" in new and new.get("members_snapshot") != prep.get("members_snapshot"):
        out.append("состав дефекта в приложении")
    if str(new.get("fingerprint") or "") != str(prep.get("fingerprint") or ""):
        out.append("набор SCA")
    old_targets = [t for t in new.get("targets") or [] if isinstance(t, dict)]
    new_targets = [t for t in prep.get("targets") or [] if isinstance(t, dict)]
    before = {str(t.get("hub_id") or ""): t for t in old_targets}
    after = {str(t.get("hub_id") or ""): t for t in new_targets}
    added, removed = sorted(set(after) - set(before)), sorted(set(before) - set(after))
    if added:
        out.append("в дефект вошли находки " + ", ".join(added))
    if removed:
        out.append("из дефекта ушли находки " + ", ".join(removed))
    if not added and not removed and ([str(t.get("hub_id") or "") for t in old_targets]
                                      != [str(t.get("hub_id") or "") for t in new_targets]):
        out.append("порядок находок")  # отпечаток учитывает порядок целей

    def value(t: dict, key: str) -> str:
        # по тем же правилам, что update_prep_sig: прежний формат хранил текст решения как entered_hash, версия
        # приложения в частях отметки не сравнивается
        if key == "entered_parts":
            return parts_without_app(t.get(key))
        return str((t.get("decision_hash", t.get("entered_hash")) if key == "decision_hash" else t.get(key)) or "")

    kinds = (("revision", "решение сохранено заново"), ("sig", "данные находки (новая выгрузка или синхронизация)"),
             ("decision_hash", "текст решения"), ("entered_parts", "части отметки «Внесено в Hub»"))
    for key, label in kinds:
        changed = [h for h in sorted(set(before) & set(after)) if value(before[h], key) != value(after[h], key)]
        if changed:
            shown = ", ".join(changed[:5]) + (f" и ещё {len(changed) - 5}" if len(changed) > 5 else "")
            out.append(f"{label} – {'находка' if len(changed) == 1 else 'находки'} {shown}")
    if sorted(str(k) for k in new.get("number_keys") or []) != sorted(str(k) for k in prep.get("number_keys") or []):
        out.append("номера ID находок")
    return out


def _prep_problem(state: dict, prep: dict) -> str:
    """Подготовка по текущим решениям не та, что в предпросмотре (п. 3, шаг 2): отказ подготовки или другой отпечаток –
    с перечнем того, что изменилось (поля черновика и конфликты в предпросмотре не хранятся: если другого отличия
    нет, так и сказано)."""
    if prep.get("refusals"):
        return "; ".join(str(x) for x in prep["refusals"])
    new = state.get("new") or {}
    if update_prep_sig(prep, fields_contract="contract_version" in state) != str(new.get("prep_sig") or ""):
        changes = prep_changes(new, prep) or ["что именно – по сохранённому предпросмотру не определить (поля "
                                              "черновика, конфликты состава или формат прежней версии)"]
        return f"{UPDATE_LOCAL_CHANGED} (изменилось: {'; '.join(changes)})"
    return ""


WHERE_WITH_BLOCK = ("В тексте остался раздел «Где исправлять». Если вместе со служебным блоком он не нужен, нажмите «Отменить», уберите раздел в тексте "
                    "дефекта и снова нажмите «Push в Hub».")
WHERE_DIFFERS = ("Раздел «Где исправлять» в тексте отличается от сведений Hub и оставлен как есть. Чтобы собрать его заново, "
                 "удалите раздел из текста и сохраните черновик.")


def _where_places(c, row: dict, links: list[dict]) -> list[dict]:
    """Сведения находок дефекта для раздела «Где исправлять»: связь из дефекта Hub, принятое чтение находки, данные
    находки в приложении. Только чтение базы, в Hub запросов нет."""
    places = []
    for link in links:
        hub_id = str(link.get("id") or "")
        state = c.execute("SELECT confirmed_json FROM hub_issue_states WHERE project_id = ? AND hub_url = ? AND app_id = ?"
                          " AND issue_type = ? AND issue_id = ?", (row["project_id"], hub_ops.hub_base(row.get("hub_url")),
                                                                   row.get("app_id"), str(link.get("type") or ""), hub_id)).fetchone()
        finding = c.execute("SELECT data_json FROM findings WHERE project_id = ? AND hub_id = ?", (row["project_id"], hub_id)).fetchone()
        places.append(defect_where.place_of(link, loads(state[0], {}) if state else None, loads(finding[0], {}) if finding else None))
    return places


def with_where(db: Database, row: dict, defect: dict | None, prep: dict) -> dict:
    """Подготовка с разделом «Где исправлять» (план dev7, раздел 11): у дефекта нет служебного блока Hub ни в описании,
    ни в заготовке – раздел из сведений связанных находок дописывается в конец текста, оператор видит его в предпросмотре.
    Раздел уже есть в тексте – это текст оператора: он не заменяется, расхождение со сведениями Hub – предупреждение.
    Блок добавляется к дефекту, у которого его в Hub нет, – раздел остаётся, предпросмотр подсказывает убрать его вручную (ADR-0139)."""
    text = str(prep.get("command_text") or "")
    if not text or prep.get("refusals"):
        return prep
    if block_for_write(row, defect)[0]:
        if hub_has_block(defect) or not defect_where.own_tail(text):
            return prep
        return {**prep, "warnings": [*(prep.get("warnings") or []), WHERE_WITH_BLOCK]}
    links = (defect or {}).get("linkedIssues") if isinstance(defect, dict) else None
    if not isinstance(links, list):
        return prep
    places = db.on_connection(lambda c: _where_places(c, row, [x for x in links if isinstance(x, dict)]))
    section = defect_where.section(places)
    if not section:
        return prep
    body, own = defect_where.split(text)
    if not own and not defect_where.has_head(text):
        return {**prep, "command_text": defect_where.join(body, section), "where_added": True}
    if not defect_where.same(own, section):
        return {**prep, "warnings": [*(prep.get("warnings") or []), WHERE_DIFFERS]}
    return prep


def _prepared(prepare: Callable[[dict], dict], row: dict) -> dict:
    """Подготовка обновления маршрутом (prepare) – {refusals, warnings, kind, summary, command_text, targets,
    number_keys, fingerprint, anchor, tx_check}; отказ подготовки – отказ п. 2 с причиной."""
    try:
        prep = prepare(row)
    except ValueError as e:
        prep = {"refusals": [str(e)]}
    prep = {"refusals": [], "warnings": [], "targets": [], "number_keys": [], "summary": "", "command_text": "",
            "kind": str(row.get("kind") or ""), "fingerprint": "", "anchor": "", "tx_check": None, **prep}
    # номер – начало заголовка и выдаётся приложением (ADR-0138): пропал – Push возвращает его
    reserved = row.get("number")
    if _is_number(reserved) and str(prep["summary"]).strip() and title_number(prep["summary"])[1] == NO_NUMBER:
        prep = {**prep, "summary": f"ID{reserved} - {prep['summary']}",
                "warnings": [*prep["warnings"], NUMBER_RETURNED.format(number=reserved)]}
    return prep


# ---------------------------------------------------------------------------- действия оператора


def start_update(db: Database, row: dict, target_check: Callable | None = None) -> dict:
    """«Подготовить обновление» (п. 3, шаг 1) одной транзакцией: строка занесена из Hub и «создан», обновление не идёт,
    предпросмотр не открыт, у строки нет других операций, неприменённой сверки и второй живой строки (п. 2); новое
    поколение попытки и чтение `GET /defects/{id}` – номер в update_op_id. Подтверждённое содержимое прежнего успеха
    переносится в новое состояние. Иначе ValueError."""
    if row.get("origin") not in ("app", "import"):
        raise ValueError(UPDATE_ONLY_IMPORTED)
    if row["state"] != "done" or not row.get("hub_defect_id"):
        raise ValueError(UPDATE_NOT_DONE)
    if update_busy(row):
        raise ValueError(UPDATE_ALREADY)
    state = update_state(row)
    if state.get("phase") == "preview":
        raise ValueError(UPDATE_PREVIEW_OPEN)
    raw = str(row.get("update_json") or "")

    def idle(c) -> None:
        if target_check is not None:
            target_check(c)
        current = _current_in(c, row)
        if str(current.get("update_json") or "") != raw:
            raise ValueError(UPDATE_SHOWN_CHANGED)
        problem = _update_idle_problem(c, current)
        if problem:
            raise ValueError(problem)

    fresh, _ = db.hub_defect_advance(
        int(row["id"]), expect_state="done", check=idle, item=update_read_item(row), op_field="update_op_id",
        update_json=dumps({"phase": "reading", "step": "read1", "generation": int(state.get("generation") or 0) + 1,
                           "confirmed": state.get("confirmed") or {}}))
    if fresh is None:
        raise ValueError("Состояние дефекта изменилось: обновите страницу.")
    return fresh


def request_put(db: Database, row: dict, *, generation: str, shown: str, prep: dict,
                target_check: Callable | None = None) -> dict:
    """«Push в Hub» из предпросмотра (п. 3, шаг 2): тот же предпросмотр (поколение generation и отпечаток shown –
    text_hash(update_json), как их показала вкладка), подготовка по текущим решениям та же, что в предпросмотре; одной
    транзакцией – второе чтение `GET /defects/{id}`. Запись `PUT` ставит ответ на него после повторных проверок
    (_on_update_read2). Иначе ValueError."""
    if row.get("origin") not in ("app", "import") or row["state"] != "done":
        raise ValueError(UPDATE_ONLY_IMPORTED)
    state = update_state(row)
    raw = str(row.get("update_json") or "")
    if (state.get("phase") != "preview" or row.get("update_op_id") or str(state.get("generation")) != str(generation)
            or text_hash(raw) != str(shown or "")):
        raise ValueError(UPDATE_SHOWN_CHANGED)
    problem = _prep_problem(state, with_where(db, row, state.get("first"), _prepared(lambda _row: prep, row)))
    if problem:
        raise ValueError(f"Обновление не отправлено: {problem}. Нажмите «Отменить» в предпросмотре, затем снова "
                         "«Push в Hub» – приложение подготовит новый предпросмотр.")

    def idle(c) -> None:
        if target_check is not None:
            target_check(c)
        current = _current_in(c, row)
        if str(current.get("update_json") or "") != raw or current.get("update_op_id"):
            raise ValueError(UPDATE_SHOWN_CHANGED)
        problem = _update_idle_problem(c, current)
        if problem:
            raise ValueError(problem)

    fresh, _ = db.hub_defect_advance(int(row["id"]), expect_state="done", check=idle, item=update_read_item(row),
                                     op_field="update_op_id",
                                     update_json=dumps({**state, "phase": "checking", "step": "read2", "note": ""}))
    if fresh is None:
        raise ValueError("Состояние дефекта изменилось: обновите страницу.")
    return fresh


def cancel_update(db: Database, row: dict, *, generation: str, shown: str) -> dict:
    """«Отменить» предпросмотр обновления (п. 3, шаг 1а) одной транзакцией: фаза preview того же поколения и тот же
    показанный снимок, операции нет – фаза cancelled; строка «создан», цели, резерв номера и подтверждённое содержимое
    прежние. Из устаревшей вкладки (другие фаза или поколение, идёт второе чтение) – ValueError «обновите страницу»."""
    state = update_state(row)
    raw = str(row.get("update_json") or "")
    if (row.get("origin") not in ("app", "import") or row["state"] != "done" or state.get("phase") != "preview"
            or row.get("update_op_id") or str(state.get("generation")) != str(generation)
            or text_hash(raw) != str(shown or "")):
        raise ValueError(UPDATE_SHOWN_CHANGED)

    def same(c) -> None:
        current = _current_in(c, row)
        if str(current.get("update_json") or "") != raw or current.get("update_op_id"):
            raise ValueError(UPDATE_SHOWN_CHANGED)

    fresh, _ = db.hub_defect_advance(int(row["id"]), expect_state="done", check=same,
                                     update_json=dumps({**state, "phase": "cancelled", "step": "", "note": ""}))
    if fresh is None:
        raise ValueError(UPDATE_SHOWN_CHANGED)
    return fresh


def _restart_read(db: Database, row: dict, *, phases: tuple[str, ...], step: str, phase: str,
                  target_check: Callable | None, refusal: str) -> dict:
    state = update_state(row)
    raw = str(row.get("update_json") or "")
    if (row.get("origin") not in ("app", "import") or row["state"] != "done" or state.get("phase") not in phases
            or row.get("update_op_id")):
        raise ValueError(refusal)

    def idle(c) -> None:
        if target_check is not None:
            target_check(c)
        current = _current_in(c, row)
        if str(current.get("update_json") or "") != raw or current.get("update_op_id"):
            raise ValueError(UPDATE_SHOWN_CHANGED)
        sync_state = loads(current.get("sync_json"), {}) or {}
        if current.get("sync_op_id") or (isinstance(sync_state, dict) and sync_state.get("read")):
            raise ValueError("Сначала дождитесь итога «Pull из Hub» и нажмите «Отменить» у её предпросмотра: успех "
                             "чтения записал бы цели этой попытки поверх сверки.")

    fresh, _ = db.hub_defect_advance(int(row["id"]), expect_state="done", check=idle, item=update_read_item(row),
                                     op_field="update_op_id",
                                     update_json=dumps({**state, "phase": phase, "step": step, "note": ""}))
    if fresh is None:
        raise ValueError("Состояние дефекта изменилось: обновите страницу.")
    return fresh


def verify_update(db: Database, row: dict, target_check: Callable | None = None) -> dict:
    """«Сверить» при неизвестном исходе `PUT` (п. 3, шаг 5): чтение `GET /defects/{id}` одной транзакцией, фаза
    остаётся unknown, `PUT` – «результат неизвестен» до итога сверки. Иначе ValueError."""
    return _restart_read(db, row, phases=("unknown",), step="verify", phase="unknown", target_check=target_check,
                         refusal="Сверить можно только обновление с неизвестным исходом: обновите страницу.")


def reread_update(db: Database, row: dict, target_check: Callable | None = None) -> dict:
    """«Повторить чтение» (п. 3, шаг 4): запись принята Hub, а подтверждающее чтение не удалось или показало не
    отправленный текст – подтверждающее чтение снова одной транзакцией. Иначе ValueError."""
    return _restart_read(db, row, phases=("confirming", "unconfirmed"), step="confirm", phase="confirming",
                         target_check=target_check,
                         refusal="Повторить чтение можно, когда запись принята Hub и ждёт подтверждения: обновите "
                                 "страницу.")


# ---------------------------------------------------------------------------- ответы исполнителя


def _update_step(db: Database, row: dict, op: dict, state: dict, *, resolve: Iterable = (), **fields: Any) -> dict | None:
    """Итог шага, которого ждёт строка (expect_op – эта операция): операция шага закрыта (update_op_id пуст), новое
    состояние попытки и поля строки; resolve – операции, которые закрываются той же записью."""
    fresh, _ = db.hub_defect_advance(int(row["id"]), expect_state="done", expect_op=("update_op_id", int(op["id"])),
                                     resolve=resolve, update_op_id=None, update_json=dumps(state), **fields)
    return fresh


def _on_update(db: Database, op: dict, first: dict, prepare: Callable[[dict], dict] | None) -> None:
    """Ответ шага «Push в Hub» (п. 3): только если строка занесена, «создан» и ждёт именно эту операцию
    (update_op_id, у `PUT` – ещё и put_op_id в update_json): повторная и поздняя доставка, ответ прежнего поколения
    ничего не меняют; уже подтверждённое обновление доводит недостающие последствия. Сбой обработки не уходит в приём
    результата: строка получает пояснение своего шага."""
    row = db.hub_defect(int(first["defect_update"]))
    if row is None or row.get("origin") not in ("app", "import") or row["state"] != "done":
        return
    if row.get("update_op_id") != op["id"]:
        if row.get("confirm_op_id") == op["id"] and not int(row.get("effects_done")
                                                              if row.get("effects_done") is not None else 1):
            _apply_effects(db, row, str(op.get("closed_at") or ""))
        return
    state = update_state(row)
    step = str(state.get("step") or "")
    if op["purpose"] == "defect_update":
        handler = _on_update_put if step == "put" and state.get("put_op_id") == op["id"] else None
    elif op["purpose"] == "defect_blank":  # заготовка для служебного блока (dev31)
        handler = _on_update_blank if step == "blank" else None
    elif op["purpose"] == "read":  # данные находок для сборки служебного блока (ADR-0139)
        handler = _on_update_model if step == "model" else None
    elif op["purpose"] == "defect_read":
        handler = {"read1": _on_update_read1, "read2": _on_update_read2, "confirm": _on_update_confirm,
                   "verify": _on_update_verify}.get(step)
    else:
        handler = None
    if handler is None:
        return
    try:
        handler(db, row, op, state, prepare)
    except defect_drafts.hub_entity_versions.StaleObservation as exc:
        _update_step(db, row, op, {**state, "phase": "unconfirmed", "step": "", "note": str(exc)})
    except Exception as e:  # ответ исполнителя принимается всегда: сбой – пояснение шага, а не 500 и повтор доставки
        phase = {"read1": "read_failed", "blank": "read_failed", "model": "read_failed", "read2": "preview", "put": "unknown",
                 "confirm": "confirming", "verify": "unknown"}.get(step, "unknown")
        try:
            _update_step(db, row, op, {**state, "phase": phase, "step": "",
                                       "note": f"ответ Hub не обработан ({type(e).__name__})"})
        except Exception:  # строка доводится следующим показом вкладки (sync)
            return


def _on_update_read1(db: Database, row: dict, op: dict, state: dict, prepare) -> None:
    """Шаг 1: чтение для предпросмотра – проверки п. 2 по свежему дефекту и текущим решениям; preview, refused или
    read_failed. Подготовки нет (ответ доставлен без маршрута с запросом) – строка ждёт показа вкладки. У дефекта без
    блока Hub в описании и без сохранённой заготовки – сначала шаг «blank» (dev31)."""
    defect, error = import_answer(op, row)
    if defect is None:
        _update_step(db, row, op, {**state, "phase": "read_failed", "step": "", "note": f"чтение не удалось: {error}"})
        return
    if prepare is None:
        return
    closed_at = str(op.get("closed_at") or "")
    placed, why = _blank_step(db, row, op, state, defect, closed_at, prepare)
    if placed:
        return
    # заготовку нельзя запросить или поставить – предпросмотр без блока, причина в предупреждении (ревью dev31, круг 2)
    _preview_from(db, row, op, state, prepare, defect, closed_at, [blank_failure_text(why)] if why else [])


def blank_failure_text(why: str) -> str:
    """Предупреждение предпросмотра: заготовку для служебного блока не получить, в описание уйдёт только текст."""
    return f"заготовку Hub для служебного блока получить не удалось ({why}): в описание уйдёт только текст приложения"


def _blank_step(db: Database, row: dict, op: dict, state: dict, defect: dict, closed_at: str,
                prepare) -> tuple[bool, str]:
    """Дефект без блока Hub в описании и без годной заготовки (занесён из Hub; блок потерян записью только текста до
    dev30; или заготовка другого состава): вместо предпросмотра ставится заготовка
    `GET /defects/blank` по находкам дефекта – её блок уйдёт в описание следом за текстом (требование команды).
    Только после проверок п. 2 (подготовка и состав по свежему дефекту): отказ «сначала «Pull из Hub»» показывается
    без запроса, заготовка для устаревшего состава не запрашивается (ревью dev31, круг 1). Один раз за попытку
    (blank_tried). (True, '') – шаг поставлен; (False, '') – шаг не нужен или сначала отказ проверок; (False, почему) –
    заготовку нельзя запросить (нет номеров Hub, слишком много находок) или поставить (очередь отказала)."""
    if built_blank_outdated(row, defect) and not hub_has_block(defect):
        return False, BLOCK_COMPOSITION
    if state.get("blank_tried") or saved_blank_fits(row) or hub_has_block(defect):
        return False, ""
    prep = _prepared(prepare, row)
    if prep["refusals"] or db.on_connection(lambda c: update_hub_problems(c, row, defect, prep))[0]:
        return False, ""
    # в тексте уже есть раздел «Где исправлять» (ADR-0134): он заменяет блок, заготовка не запрашивается. Иначе каждый Push
    # такого дефекта ставил запрос, на который Hub отвечает отказом, и показывал предупреждение даже без изменений
    if defect_where.own_tail(prep.get("command_text")):
        # заготовку Hub здесь не выдаст: находки уже привязаны; блок собирается из данных находок (ADR-0139)
        return _model_step(db, row, op, state, defect, closed_at)
    item, why = update_blank_item(row)
    if item is None:
        # заготовку не запросить, например находок слишком много для issueIds: блок собирается из их данных (ADR-0139)
        placed, model_why = _model_step(db, row, op, state, defect, closed_at)
        return placed, "" if placed else (model_why or why)

    def check(c) -> None:
        idle = _update_idle_problem(c, _current_in(c, row), own_op=int(op["id"]))
        if idle:
            raise ValueError(idle)

    try:
        fresh, _ = db.hub_defect_advance(int(row["id"]), expect_state="done", expect_op=("update_op_id", int(op["id"])),
                                         check=check, item=item, op_field="update_op_id",
                                         update_json=dumps({**state, "step": "blank", "note": "", "blank_tried": True,
                                                            "blank_for": blank_target_ids(row),
                                                            "first_read": defect, "read_at": closed_at}),
                                         import_json=_observed(row, defect, closed_at))
    except ValueError as exc:
        return False, f"операция не поставлена: {exc}"
    return fresh is not None, ""


BLOCK_BUILT = ("Служебный блок собран приложением из данных Hub по образцу настоящих блоков: Hub мог бы оформить его иначе. "
               "Проверьте его в сравнении выше.")
BLOCK_COMPOSITION = "находки дефекта в Hub и в приложении различаются, сначала «Pull из Hub»"


def is_update_read(op: dict) -> bool:
    """Операция чтения – шаг «Push в Hub», а не сверка статуса и не отдельное чтение модели шаблона."""
    return isinstance(_first_target(op).get("defect_update"), int)


def _target_pairs(row: dict) -> set[tuple[int, str]]:
    return {(int(t["issue_id"]), str(t.get("issue_type") or "")) for t in loads(row.get("targets_json"), [])
            if isinstance(t, dict) and str(t.get("issue_id") or "").isdigit()}


def _model_targets(row: dict) -> list[int]:
    return blank_target_ids(row) if str(row.get("kind") or "") in ("SAST", "SCA") else []


def _model_item(row: dict, issue: int, generation: Any) -> dict:
    """Чтение модели шаблона по находке issue как шаг обновления: ответ идёт в _on_update, ключ операции – своей попытки."""
    return dict(purpose="read", request=hub_template_model.request_for(row, str(issue)), hub_url=row["hub_url"], app_id=row.get("app_id"),
                project_id=int(row["project_id"]), key_extra=f"defect-model:{int(row['id'])}:{generation}:{issue}",
                targets=[{"defect_update": int(row["id"]), "issue_type": UPDATE_TYPE, "issue_id": int(row["id"])}])


def _model_step(db: Database, row: dict, op: dict, state: dict, defect: dict, closed_at: str) -> tuple[bool, str]:
    """Первое чтение данных находок для сборки блока: дефект без блока, заготовку Hub не выдаёт (ADR-0139). Один раз за попытку.
    (True, '') – шаг поставлен; (False, почему) – поставить нельзя, предпросмотр без блока."""
    if state.get("model_tried"):
        return False, ""
    issues = _model_targets(row)
    if not issues:
        return False, "у находок дефекта нет номеров Hub или вид дефекта не поддерживается"
    if _target_pairs(row) != linked_pairs(defect):  # блок описывает находки: только те, что привязаны в Hub, и все они
        return False, BLOCK_COMPOSITION
    return _next_model(db, row, op, {**state, "model_tried": True, "model_for": issues, "model_done": {}, "first_read": defect, "read_at": closed_at},
                       issues[0], closed_at, defect)


def _next_model(db: Database, row: dict, op: dict, state: dict, issue: int, closed_at: str, defect: dict) -> tuple[bool, str]:
    try:
        item = _model_item(row, issue, state.get("generation"))
    except (TypeError, ValueError) as exc:
        return False, str(exc)

    def check(c) -> None:
        idle = _update_idle_problem(c, _current_in(c, row), own_op=int(op["id"]))
        if idle:
            raise ValueError(idle)

    try:
        fresh, _ = db.hub_defect_advance(int(row["id"]), expect_state="done", expect_op=("update_op_id", int(op["id"])), check=check, item=item,
                                         op_field="update_op_id", update_json=dumps({**state, "step": "model", "note": ""}),
                                         import_json=_observed(row, defect, closed_at))
    except ValueError as exc:
        return False, f"операция не поставлена: {exc}"
    return fresh is not None, ""


def _on_update_model(db: Database, row: dict, op: dict, state: dict, prepare) -> None:
    """Ответ на чтение данных находки: все находки прочитаны – блок собирается и сохраняется как заготовка этого состава, дальше обычный
    предпросмотр. Сбой или смена состава – предпросмотр без блока с причиной: из неполного набора блок не собирается. Следующее чтение
    ставится и без подготовки; предпросмотру она нужна: строка дождётся показа вкладки, ответ тот же."""
    defect = state.get("first_read")
    closed_at = str(state.get("read_at") or "")
    rest = {k: v for k, v in state.items() if k not in ("first_read", "model_done", "model_for", "read_at")}
    if not isinstance(defect, dict):
        _update_step(db, row, op, {**rest, "phase": "read_failed", "step": "", "note": "чтение не удалось: нет дефекта первого чтения"})
        return
    issues = list(state.get("model_for") or [])
    done = dict(state.get("model_done") or {})

    def without(why: str) -> None:
        if prepare is not None:
            _preview_from(db, row, op, rest, prepare, defect, closed_at, [f"служебный блок собрать не удалось ({why}): в описание уйдёт только текст приложения"])

    if issues != _model_targets(row):
        without("состав дефекта изменился, пока читались данные находок")
        return
    current = next((i for i in issues if str(i) not in done), None)
    if current is None:
        without("нет находки, которую ждало чтение")
        return
    result = loads(op.get("result_json"), {}) or {}
    if op["state"] != "done":
        old_worker = result.get("not_sent") and "белый список" in str(result.get("error") or "")
        without(hub_template_model.OLD_WORKER if old_worker else str(op.get("error") or "ответа нет"))
        return
    model = hub_template_model.model_of(_body(op), current)
    if model is None:
        without(f"ответ Hub по находке {current} не разобран")
        return
    done[str(current)] = model
    following = next((i for i in issues if str(i) not in done), None)
    if following is not None:
        placed, why = _next_model(db, row, op, {**state, "model_done": done}, following, closed_at, defect)
        if not placed:
            without(why or "состояние дефекта изменилось")
        return
    if prepare is None:
        return
    try:
        block = hub_block_builder.build_block(str(row.get("kind") or ""), [done[str(i)] for i in issues])
    except ValueError as exc:
        without(str(exc))
        return
    if hub_block(block)[1]:
        without("собранный блок не выделяется")
        return
    fields = {"blank_json": dumps({"description": block, "_targets": issues, "built_from_model": True})}
    _preview_from(db, {**row, **fields}, op, rest, prepare, defect, closed_at, **fields)


def _on_update_blank(db: Database, row: dict, op: dict, state: dict, prepare) -> None:
    """Шаг «blank» (dev31): ответ Hub на заготовку по находкам дефекта. Заготовка с описанием сохраняется в строке
    (blank_json – как у дефекта, созданного из приложения; карточка показывает её блок «из заготовки») и предпросмотр
    собирается по дефекту первого чтения с её блоком; заготовки нет (отказ Hub, исполнитель не отправил, пустое
    описание) – предпросмотр без блока с предупреждением, повторная подготовка спросит снова."""
    if prepare is None:
        return
    defect = state.get("first_read")
    rest = {k: v for k, v in state.items() if k != "first_read"}
    if not isinstance(defect, dict):
        _update_step(db, row, op, {**rest, "phase": "read_failed", "step": "",
                                   "note": "чтение не удалось: нет дефекта первого чтения"})
        return
    blank = _body(op) if op["state"] == "done" else None
    fields: dict[str, Any] = {}
    extra: list[str] = []
    if isinstance(blank, dict) and str(blank.get("description") or "").strip() \
            and state.get("blank_for") == blank_target_ids(row):
        # заготовка помечается составом запроса: после «Pull из Hub» с другим составом она не годится (ревью, круг 1)
        fields["blank_json"] = dumps({**blank, "_targets": blank_target_ids(row)})
        row = {**row, "blank_json": fields["blank_json"]}
        rest["blank_fetched"] = True
    else:
        if op["state"] != "done":
            why = str(op.get("error") or "ответа нет")
        elif not isinstance(blank, dict) or not str(blank.get("description") or "").strip():
            why = "в ответе Hub нет описания"
        else:
            why = "состав дефекта изменился, пока запрашивалась заготовка"
        # Hub отказал в заготовке (400) – находки уже привязаны: блок собирается из их данных (ADR-0139); сбой Hub или
        # исполнителя – прежний предпросмотр без блока
        if (loads(op.get("result_json"), {}) or {}).get("status") == 400:
            placed, model_why = _model_step(db, row, op, rest, defect, str(state.get("read_at") or ""))
            if placed:
                return
            why = model_why or why
        extra = [blank_failure_text(why)]
    _preview_from(db, row, op, rest, prepare, defect, str(state.get("read_at") or ""), extra, **fields)


def _preview_from(db: Database, row: dict, op: dict, state: dict, prepare, defect: dict, closed_at: str,
                  extra_warnings: list[str] | None = None, **fields: Any) -> None:
    """Предпросмотр по прочитанному дефекту (шаг 1 после чтения или после заготовки): проверки п. 2, описание с
    блоком, кандидат PUT; preview, refused или cancelled. fields – поля строки той же записью (blank_json)."""
    prep = with_where(db, row, defect, _prepared(prepare, row))
    hub_refusals, hub_warnings = db.on_connection(lambda c: update_hub_problems(c, row, defect, prep))
    refusals = list(prep["refusals"]) + hub_refusals
    block, block_note, problem, description = "", "", "", ""
    block_version = hub_block_version.Retarget("")
    if prep["command_text"]:
        # описание – текст приложения и следом служебный блок Hub (dev30): исходная подстрока блока из Hub или блок
        # заготовки, если в Hub его нет (у дефектов, созданных до dev30 только текстом, блок добавляется)
        block, block_note = block_for_write(row, defect)
        block_version = hub_block_version.for_defect(str(row.get("kind") or ""), prep["command_text"], block)
        block = block_version.block
        description, problem = update_description(prep["command_text"], block)
        # текст не правили, а в описании Hub есть граница блока (даже склеенная с текстом) – описание Hub как есть
        # (ревью dev30, круг 3); без блока в Hub и с заготовкой – блок добавляется
        # замена версии в блоке – правка описания: оно собирается заново (ADR-0132)
        if not problem and not block_version.places and (not block or hub_has_block(defect)):
            built = description
            description = keep_hub_markup(defect, description)
            if layout_warning(prep["command_text"], built, description, str((defect or {}).get("description") or "")):
                extra_warnings = [*(extra_warnings or []), LAYOUT_KEPT]  # не молча (ADR-0149, ревью круга 2)
    if problem:
        refusals.append(problem)
    observed = _observed(row, defect, closed_at)
    block_mode = block_mode_of(defect, block, block_note, description)
    block_built = block_mode == "added" and (loads(row.get("blank_json"), {}) or {}).get("built_from_model") is True
    # предупреждения подготовки, проверки Hub и выделения блока – один раз (ревью dev30, круг 2); описание Hub остаётся
    # как есть – о замене блока предупреждать нечего (ревью, круг 4)
    warnings = (list(prep["warnings"]) + list(hub_warnings)
                + ([block_note] if block_note and block_mode != "kept" else []) + list(block_version.notes)
                + ([BLOCK_REPEATED] if block_repeated(description) else [])
                + ([BLOCK_BUILT] if block_built else [])
                + list(extra_warnings or []))
    if refusals:
        _update_step(db, row, op, {**state, "phase": "refused", "step": "", "note": "", "refusals": refusals,
                                   "warnings": warnings}, import_json=observed, **fields)
        return
    from app import defect_fields
    from app.defect_dto import DEFECT_CONTRACT
    try:
        body, changes, local = defect_fields.candidate(defect, row, prep["summary"], description)
        from app import defect_references
        db.on_connection(lambda c: defect_references.check_candidate(c, row, body))
    except ValueError as exc:
        _update_step(db, row, op, {**state, "phase": "refused", "step": "", "refusals": [str(exc)],
                                   "note": "PUT не поставлен."}, import_json=observed, **fields)
        return
    if not changes:
        # без правки – никаких разниц: предупреждения формы в итог не идут; предупреждение о
        # неудавшейся заготовке (extra_warnings) остаётся в пояснении итога (ревью dev31, круг 1)
        extra = list(extra_warnings or []) + list(block_version.notes)
        _update_step(db, row, op, {**state, "phase": "cancelled", "step": "", "warnings": extra,
                                   "note": "Изменений для отправки нет" + ("; " + "; ".join(extra) if extra else "")},
                     import_json=observed, **fields)
        return
    new = {"kind": prep["kind"], "summary": prep["summary"], "command_text": prep["command_text"],
           "description": description, "number": row.get("number"), "targets": prep["targets"],
           "number_keys": prep["number_keys"], "fingerprint": prep["fingerprint"], "anchor": prep["anchor"],
           "prep_sig": update_prep_sig(prep), "draft_revision": prep.get("draft_revision"),
           "members_snapshot": prep.get("members_snapshot")}
    _update_step(db, row, op, {**state, "phase": "preview", "step": "", "note": "", "refusals": [], "warnings": warnings,
                               "first": defect, "block": block, "new": new, "contract_version": DEFECT_CONTRACT,
                               "candidate": body, "field_diff": changes, "local_changes": local,
                               "kept_description": description == str(defect.get("description") or ""),
                               "block_mode": block_mode, "block_version": block_version.view(), "where_added": bool(prep.get("where_added")),
                               "block_built": block_built,
                               "draft_fields_basis_json": row["draft_fields_basis_json"],
                               "references": defect_fields.basis_of(row)["references"],
                               "read_at": closed_at}, import_json=observed, **fields)


def _on_update_read2(db: Database, row: dict, op: dict, state: dict, prepare) -> None:
    """Шаг 2: второе чтение перед записью – объект Hub тот же, что в предпросмотре (кроме updateTs), подготовка по
    текущим решениям та же; тело `PUT` – этот объект с новыми summary и description. Проверки повторяются в транзакции
    постановки `PUT` (решения, данные, набор SCA, ADR-0123, адрес Hub и приложение, номер, состав, операции строки):
    иначе stale с причиной. Ошибка чтения – снова предпросмотр с пояснением."""
    defect, error = import_answer(op, row)
    if defect is None:
        _update_step(db, row, op, {**state, "phase": "preview", "step": "",
                                   "note": f"второе чтение не удалось: {error} – нажмите «Push в Hub» снова"})
        return
    if prepare is None:
        return
    observed = _observed(row, defect, str(op.get("closed_at") or ""))

    def stale(note: str) -> None:
        _update_step(db, row, op, {**state, "phase": "stale", "step": "", "note": note}, import_json=observed)

    changed = _changed_fields(state.get("first") or {}, defect)
    if changed:
        stale("дефект в Hub изменился после предпросмотра (поля: " + ", ".join(changed) + ")")
        return
    prep = with_where(db, row, defect, _prepared(prepare, row))
    problem = _prep_problem(state, prep)
    if problem:
        stale(problem)
        return
    # описание – текст приложения и следом блок Hub (dev30): тот же блок, что показал предпросмотр, иначе – заново
    block, block_note = block_for_write(row, defect)
    block_version = hub_block_version.for_defect(str(row.get("kind") or ""), prep["command_text"], block)
    block = block_version.block
    if block != str(state.get("block") or ""):
        stale("блок Hub в описании изменился после предпросмотра – подготовьте обновление заново")
        return
    description, problem = update_description(prep["command_text"], block)
    if problem:
        stale(problem)
        return
    if not block_version.places and (not block or hub_has_block(defect)):
        description = keep_hub_markup(defect, description)
    from app import defect_fields
    from app.defect_dto import DEFECT_CONTRACT
    # Предпросмотры dev1 без версии сохраняют прежний текстовый контракт до завершения.
    if "contract_version" in state:
        try:
            if state["contract_version"] != DEFECT_CONTRACT:
                raise ValueError("Неизвестная версия контракта предпросмотра.")
            body, changes, local = defect_fields.candidate(defect, row, prep["summary"], description)
            if (not defect_fields.equal(changes, state.get("field_diff"))
                    or not defect_fields.equal(local, state.get("local_changes"))
                    or _changed_fields(body, state.get("candidate") or {})):
                raise ValueError("Кандидат PUT отличается от показанного diff.")
        except ValueError as exc:
            stale(str(exc))
            return
    else:
        body = {**defect, "summary": prep["summary"], "description": description}
    generation = int(state.get("generation") or 0)
    raw = str(row.get("update_json") or "")

    def check(c) -> None:
        if prep.get("tx_check") is not None:
            prep["tx_check"](c)
        current = _current_in(c, row)
        if str(current.get("update_json") or "") != raw:
            raise ValueError(UPDATE_SHOWN_CHANGED)
        idle = _update_idle_problem(c, current, own_op=int(op["id"]))
        if idle:
            raise ValueError(idle)
        refusals, _ = update_hub_problems(c, current, defect, prep)
        if refusals:
            raise ValueError("; ".join(refusals))
        if "contract_version" in state:
            checked, checked_diff, _ = defect_fields.candidate(defect, current, prep["summary"], description)
            from app import defect_references
            defect_references.check_candidate(c, current, checked)
            if not defect_fields.equal(checked, body) or not defect_fields.equal(checked_diff, state["field_diff"]):
                raise ValueError("Тело PUT изменилось перед постановкой.")

    putting = {**state, "phase": "putting", "step": "put", "note": "", "base": defect,
               "sent_object": body, "sent": {"summary": prep["summary"], "description": description, "command_text": prep["command_text"],
                        "block": block}}
    if "contract_version" in state:
        putting["changed_roots"] = defect_fields.changed_roots(state["field_diff"])
        putting["expected_number"] = row["number"]
    item = update_put_item(row, body, generation)
    if "contract_version" in state:
        item["request"]["contract_version"] = state["contract_version"]
    try:
        db.hub_defect_advance(int(row["id"]), expect_state="done", expect_op=("update_op_id", int(op["id"])),
                              check=check, item=item, op_field="update_op_id",
                              with_op=lambda put: {"update_json": dumps({**putting, "put_op_id": int(put["id"])})},
                              import_json=observed)
    except ValueError as e:
        stale(f"запрос не поставлен: {e}")


def _on_update_put(db: Database, row: dict, op: dict, state: dict, prepare) -> None:
    """Шаг 3: ответ на `PUT` (исходное состояние операции – до общего преобразования отмены): 2xx – подтверждающее
    чтение; 4xx – failed «Hub не принял»; не отправлено исполнителем – failed с причиной (прежний исполнитель –
    «обновите исполнитель в ВМ»); отменено до выдачи – failed «не отправлен», операция остаётся cancelled; 3xx, 5xx,
    обрыв, усечение, аренда – unknown («Сверить»), операция держит блокировку."""
    error = str(op.get("error") or "")
    if op["state"] == "done":
        confirming = {**state, "phase": "confirming", "step": "confirm", "note": ""}
        try:
            db.hub_defect_advance(int(row["id"]), expect_state="done", expect_op=("update_op_id", int(op["id"])),
                                  item=update_read_item(row), op_field="update_op_id",
                                  update_json=dumps(confirming))
        except ValueError as e:
            _update_step(db, row, op, {**confirming, "step": "", "note": f"подтверждающее чтение не поставлено: {e}"})
        return
    if op["state"] == "cancelled":
        _update_step(db, row, op, {**state, "phase": "failed", "step": "", "note": UPDATE_CANCELLED_PUT})
        return
    if op["state"] == "failed":
        if _result(op).get("not_sent"):
            old_worker = "метод PUT не разрешён" in error or ("PUT /defects" in error and "белый список" in error)
            note = UPDATE_OLD_WORKER if old_worker else (error or "запрос в Hub не отправлен")
        else:
            note = f"Hub не принял: {error or 'отказ'}"
        _update_step(db, row, op, {**state, "phase": "failed", "step": "", "note": note})
        return
    _update_step(db, row, op, {**state, "phase": "unknown", "step": "", "note": error or "ответа от Hub нет"})


def _on_update_confirm(db: Database, row: dict, op: dict, state: dict, prepare) -> None:
    """Шаг 4: подтверждающее чтение – новое содержимое – успех (п. 4; прочие поля отличаются – done_diff); прежнее или
    иное – unconfirmed без отметок, `PUT` остаётся выполненным; ошибка чтения – confirming с пояснением."""
    defect, error = import_answer(op, row)
    if defect is None:
        _update_step(db, row, op, {**state, "phase": "confirming", "step": "",
                                   "note": f"чтение не удалось: {error}"})
        return
    observed = _observed(row, defect, str(op.get("closed_at") or ""))
    if update_confirmed_fields(row, state, defect):
        _update_success(db, row, op, state, defect, observed)
        return
    _update_step(db, row, op, {**state, "phase": "unconfirmed", "step": "", "note": UPDATE_UNCONFIRMED,
                               "confirmation_diff": _changed_fields(state.get("sent_object") or {}, defect)},
                 import_json=observed)


def _on_update_verify(db: Database, row: dict, op: dict, state: dict, prepare) -> None:
    """Шаг 5: «Сверить» – новое содержимое – как шаг 4 (`PUT` разрешается done последствиями); равно объекту второго
    чтения – observed_old, иное – unclear (`PUT` разрешается failed той же записью); ошибка чтения – unknown, `PUT`
    по-прежнему «результат неизвестен»."""
    defect, error = import_answer(op, row)
    if defect is None:
        _update_step(db, row, op, {**state, "phase": "unknown", "step": "",
                                   "note": f"сверка не удалась: {error} – нажмите «Сверить» ещё раз"})
        return
    observed = _observed(row, defect, str(op.get("closed_at") or ""))
    if _read_of(defect, block_repeated((state.get("sent") or {}).get("description")))["text_note"]:
        _update_step(db, row, op, {**state, "phase": "unknown", "step": "",
                                   "note": "текст команды не выделен при сверке; исход записи по-прежнему неизвестен"},
                     import_json=observed)
        return
    if update_confirmed_fields(row, state, defect):
        _update_success(db, row, op, state, defect, observed)
        return
    base = state.get("base") or {}
    changed = _changed_fields(base, defect)  # то же правило, что у шага 2: все поля, кроме updateTs
    old = not changed
    note = UPDATE_OBSERVED_OLD if old else f"{UPDATE_UNCLEAR} (отличаются поля: {', '.join(changed)})"
    put_op = state.get("put_op_id")
    _update_step(db, row, op, {**state, "phase": "observed_old" if old else "unclear", "step": "", "note": note},
                 resolve=[(int(put_op), "failed", f"сверка чтением: {note}")] if put_op else (), import_json=observed)


def update_confirmed_fields(row: dict, state: dict, defect: dict) -> bool:
    """Новая попытка требует полного контракта; отсутствие его части не включает старый режим."""
    if "contract_version" not in state:
        return update_content_new(defect, state.get("sent") or {})
    from app.defect_dto import DEFECT_CONTRACT, is_int64
    from app.defect_fields import changed_roots, confirmation_diffs, diff, equal
    required = ("base", "sent_object", "field_diff", "changed_roots", "sent", "expected_number", "generation", "put_op_id")
    if state.get("contract_version") != DEFECT_CONTRACT or any(k not in state for k in required):
        return False
    if (not isinstance(state["base"], dict) or not isinstance(state["sent_object"], dict)
            or not isinstance(state["sent"], dict) or not isinstance(state["field_diff"], list)
            or not equal(state["field_diff"], diff(state["base"], state["sent_object"]))
            or state["changed_roots"] != changed_roots(state["field_diff"])
            or not is_int64(state["expected_number"])):
        return False
    number, problem = title_number(defect.get("summary"))
    sent_description = str(state["sent"].get("description") or "")
    if (sent_description == str(state["base"].get("description") or "")
            and str(defect.get("description") or "") != sent_description):
        # описание Hub оставлено как есть (текст не правили) – подтверждается побайтно, вместе с блоком Hub (ADR-0125
        # п. 3; ревью dev15, A2)
        return False
    return (is_int64(defect.get("id")) and defect["id"] == int(row["hub_defect_id"])
            and is_int64(defect.get("appId")) and defect["appId"] == row["app_id"]
            and not problem and number == state["expected_number"] == row["number"]
            and update_content_new(defect, state["sent"])
            and not confirmation_diffs(defect, state["sent_object"], state["changed_roots"]))


def _update_success(db: Database, row: dict, op: dict, state: dict, defect: dict, observed: str) -> None:
    """Успех (п. 4) одной записью, только для текущего поколения: заголовок, текст команды, тело, цели с новыми
    редакциями и отпечатками, ключи номера, подтверждающая операция, последствия не доведены, text_generation + 1,
    подтверждённое содержимое (update_json) и наблюдаемый снимок (import_json) из подтверждающего чтения; затем
    последствия – закрытие операций попытки, отметки «Внесено в Hub» и номера ключам (_apply_effects). Сбой посередине
    доводят показ вкладки (sync) и повторная доставка."""
    new, sent = state.get("new") or {}, state.get("sent") or {}
    if "contract_version" in state:
        diffs = [k for k in _changed_fields(state["sent_object"], defect)
                 if k not in {"summary", "description", *state["changed_roots"]}]
    else:
        diffs = update_other_diffs(state.get("base") or {}, defect)
    # в строке занесённого дефекта – разбор подтверждающего чтения (ADR-0125 п. 4, вариант A): как после занесения
    # и «Применить» сверки; текст генератора – только в update_json (new) для `PUT` и подтверждения
    seen = loads(observed, {}) or {}
    confirmed = {"summary": str(sent.get("summary") or ""), "number": new.get("number"),
                 "text_hash": text_hash(str(seen.get("command_text") or "")),
                 "generation": int(state.get("generation") or 0), "op": int(op["id"])}
    done = {**state, "phase": "done_diff" if diffs else "done", "step": "", "note": "", "diff": diffs,
            "confirmed": confirmed}
    fresh = _update_step(db, row, op, done, import_json=observed, summary=str(sent.get("summary") or ""),
                         command_text=str(new.get("command_text") or "") if row["origin"] == "app" else str(seen.get("command_text") or ""),
                         on_write=lambda c, fresh: defect_drafts.confirm(c, fresh, seen, int(op["id"]), new.get("targets") or []),
                         body_html=str(sent.get("description") or ""), targets_json=dumps(new.get("targets") or []),
                         number_keys_json=dumps(new.get("number_keys") or []), confirm_op_id=int(op["id"]),
                         effects_done=0, text_generation=int(row.get("text_generation") or 0) + 1, error="")
    if fresh is not None:
        _apply_effects(db, fresh, str(op.get("closed_at") or ""))
