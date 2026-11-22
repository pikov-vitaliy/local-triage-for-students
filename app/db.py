"""Хранилище приложения: основная база PostgreSQL (app/storage, ADR-0128).

Транзакция записи – по одной на приложение, составное чтение – снимок; вызываются из веб-запросов и фонового потока триажа.

Таблицы:
  meta          – служебные значения: версия схемы, ревизии клонов, пояснения для страницы проекта;
  schema_version – журнал шагов обновления схемы (какая версия, когда);
  settings      – настройки из интерфейса (ключ – значение JSON), см. app/config.py;
  projects      – проекты: папка с клонами внутри REPOS_ROOT (repos_dir), модель проекта, архив, последняя
                  активность;
  imports       – загруженные выгрузки: листы, сводка, предупреждения;
  findings      – находки проекта с порядком разбора (pos); пропавшие из новой выгрузки остаются с пометкой
                  missing («нет в новой выгрузке») после найденных;
  codebase_map  – кодовая база из выгрузки → папка с клоном;
  cases         – последний контекст находки, отданный модели, и ссылка на вердикт;
  verdicts      – ответы модели; записи не меняются, кэш – последний ответ по (case_hash, model, prompt_version)
                  или по ключу запроса к модели целиком (request_key);
  reviews       – решения человека; ключ – ID находки в Hub, поэтому они переживают повторную загрузку;
                  finding_sig – версия находки и папки с её кодом, по которой человек принял решение; revision –
                  номер редакции решения (защита от перезаписи из устаревшей вкладки); отметки «Проверено»
                  и «Внесено в Hub» с датами; code_hash – отпечаток кода, который человек видел при решении;
  questions     – вопросы к модели по находке и её ответы («Спросить модель»);
  sca_answers   – ответы внешних агентов по пакетам SCA (экосистема + компонент + версия) и охват ответа – набор
                  уязвимостей, по которым агент отвечал (vulns_json);
  ast_map       – соответствие идентификаторов уязвимостей AST → CVE или GHSA;
  defects       – номера дефектов Hub («ID<n>»), которые человек дал находке SAST или библиотеке SCA;
  runs, run_items – прогоны триажа и их очередь; runs.control – принятая команда «пауза» или «стоп».
"""

from __future__ import annotations

import hashlib
import json
import re
import os
import secrets
import threading
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from app import cvss, defect_where
from app.storage import BUSY_TEXT, DatabaseBusy, IntegrityError, PostgresStore, conninfo_for  # noqa: F401
from app.storage import schema as storage_schema
from app.storage import migrate as storage_migrate
from app.storage.migrate import apply_baseline
from app.storage.postgresql import PAGE_VIEW, Connection, ReadContext, Row
from app.config import (ConfigError,
                        normalize_setting)
from app import package_identity
from app.ecosystem import finding_ecosystem, resolve_legacy
from app.defect import defect_key_sast, defect_key_sca, effective_kapo, export_label
from app.models import ScaAnswer
from app.codecmp import code_cmp

SCHEMA_VERSION = 36
DEFAULT_PROVIDER_ID = 1  # профиль 1 – «Адрес Ollama» и «Модель по умолчанию» страницы «Настройки» (П23)
STORED_TARGET_BASES = ("", "manual", "component", "research", "legacy", "no_fix")  # основания цели в
# sca_package_texts (ADR-0091 п. 14, ADR-0101 п. 4); форма пишет только "", manual и no_fix (sca_text.TARGET_BASES)

RUN_STATES = ("queued", "running", "paused", "stopped", "done", "error")
ACTIVE_RUN_STATES = ("queued", "running", "paused")
FINAL_RUN_STATES = ("stopped", "done", "error")
RUN_CONTROLS = ("pause", "stop")
ITEM_STATES = ("pending", "done", "cached", "skipped", "error")
QUESTION_STATES = ("pending", "done", "error")
# risk_accepted – «Риск принят»: решение человека, модель его не предлагает; без обоснования не сохраняется
RUN_ORIGINS = ("project", "card", "retry")  # откуда запущен прогон (ADR-0097); "" – не записано (до схемы 21)
DECISIONS = ("agree", "disagree", "later", "risk_accepted")
VERDICT_VALUES = ("true_positive", "false_positive", "uncertain")
# Уточнение решения SCA по ГОСТ Р КАПО (пп. 6.12, 6.14): не статус Hub, а смысл заключения. Допустимые пары с итогом
# решения (hub_verdict) – KAPO_STATES_BY_OUTCOME; у остальных итогов поле пустое
KAPO_STATES = ("", "not_finished", "actual", "not_actual", "neutralized", "false_positive")
KAPO_STATES_BY_OUTCOME = {"true_positive": ("not_finished", "actual"), "risk_accepted": ("not_actual", "neutralized"),
                          "false_positive": ("false_positive",)}

# Поля находки, от которых зависит контекст для модели. Если при повторной загрузке они не изменились,
# прежний вердикт остаётся привязан к находке (смена статуса в Hub его не сбрасывает).
CASE_KEYS = ("kind", "rule", "cwe", "codebase", "file", "line", "snippet", "language")
# Поля находки SCA, от которых зависит решение человека: компонент, версия и уязвимости
SCA_KEYS = ("kind", "component", "version", "cve", "vuln_ids", "codebase", "dep_path")

INTERRUPTED_NOTE = "Приложение перезапускалось, прогон поставлен на паузу. Нажмите «Продолжить»."
STOPPED_NOTE = "Прогон остановлен по команде «Стоп»: приложение перезапускалось до конца текущей находки."
QUESTION_INTERRUPTED = "Приложение перезапускалось, ответ не получен. Спросите ещё раз."
# К11: обращение к внешнему провайдеру ушло, ответа нет – находка не разбирается повторно ни «Продолжить», ни после
# перезапуска; явный «Повторить ошибочные» – новый платный запрос по решению оператора
UNKNOWN_RESULT_NOTE = ("Результат неизвестен: обращение к провайдеру ушло, ответ не получен – запрос мог быть принят "
                       "и оплачен. Повторно находка автоматически не отправляется; «Повторить ошибочные» – новый "
                       "платный запрос.")
UNKNOWN_AFTER_RESTART = ("Результат неизвестен: приложение перезапускалось после отправки запроса провайдеру – запрос "
                         "мог быть принят и оплачен. Повторно находка автоматически не отправляется; «Повторить "
                         "ошибочные» – новый платный запрос.")
QUESTION_UNKNOWN = ("Результат неизвестен: вопрос ушёл провайдеру, ответ не получен – запрос мог быть принят и "
                    "оплачен. Спросите ещё раз, если нужно: это новый платный запрос.")
QUESTION_UNKNOWN_RESTART = ("Результат неизвестен: приложение перезапускалось после отправки вопроса провайдеру – запрос "
                            "мог быть принят и оплачен. Спросите ещё раз, если нужно: это новый платный запрос.")
UNKNOWN_BEFORE_RESUME = ("Результат неизвестен: запрос провайдеру ушёл, а результат записать не удалось (база была "
                         "занята или приложение останавливалось) – запрос мог быть принят и оплачен. Повторно находка "
                         "автоматически не отправляется; «Повторить ошибочные» с отметкой – новый платный запрос.")

_CHUNK = 500  # сколько значений подставлять в один запрос IN (...)

SAVED_FILTERS_MAX = 30  # сохранённых отборов на проект


GROUP_ROWS_SQL = """
    SELECT f.hub_id, f.missing, COALESCE(r.decision, '') AS decision, COALESCE(r.final_verdict, '') AS final_verdict,
           COALESCE(r.final_comment, '') AS final_comment, COALESCE(r.final_fix, '') AS final_fix,
           r.verdict_id AS review_verdict_id, cs.verdict_id AS case_verdict_id,
           COALESCE((v.data_json::json ->> 'fix'), '') AS model_fix, d.number AS defect_number,
           COALESCE(cs.code_cmp, '') AS code_cmp, COALESCE(r.revision, 0) AS revision,
           COALESCE(NULLIF(d.assigned_at, ''), d.updated_at) AS defect_at,
           COALESCE(cs.case_hash, '') AS case_hash, COALESCE(r.finding_sig, '') AS finding_sig
      FROM findings f
      LEFT JOIN reviews r ON r.project_id = f.project_id AND r.hub_id = f.hub_id
      LEFT JOIN cases cs ON cs.project_id = f.project_id AND cs.hub_id = f.hub_id
      LEFT JOIN verdicts v ON v.id = r.verdict_id
      LEFT JOIN defects d ON d.project_id = f.project_id AND d.defect_key = 'sast:' || f.hub_id
     WHERE f.project_id = ? AND f.kind = 'SAST' AND f.group_key2 = ? AND f.hub_id <> ?
     ORDER BY f.pos"""


def group_key2_ok(group_key2: str) -> bool:
    """Ключ группы второй редакции образует группу, только если он непуст."""
    return bool(str(group_key2 or ""))


def _group2_columns(data: dict) -> tuple[str, str, str, int | None]:
    """group_key2, g2_cat, g2_file, g2_line по сохраняемым данным находки (ADR-0095 п. 2): вычисляются из data_json,
    поэтому сохранённое всегда равно вычисленному, кто бы ни звал запись."""
    from app.hub_import import group_key2, near_columns2
    if not isinstance(data, dict):
        return "", "", "", None
    return (group_key2(data), *near_columns2(data))


def now_iso() -> str:
    """Текущее время UTC в ISO 8601 с точностью до секунды."""
    return datetime.now(UTC).isoformat(timespec="seconds")


def dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def loads(text: str | None, default: Any) -> Any:
    if not text:
        return default
    try:
        return json.loads(text)
    except ValueError:
        return default


CODE_NOTICE_IDS = 5000  # номеров находок в пояснении о смене кода – не больше (пояснение уходит, когда все проверены)


def code_notice_version(notice: Mapping[str, Any]) -> str:
    """Редакция пояснения о смене кода для «Понятно»: rev (растёт при каждом дополнении); у пояснения прежнего
    формата – его время."""
    return f"rev:{int(notice['rev'])}" if notice.get("rev") else f"at:{notice.get('at') or ''}"
_MASK_LABEL = re.compile(r"<[A-Z][A-Z0-9]*_[0-9A-Za-z]+>")  # метка маскирования вида <SECRET_ab12>


def _chunks(items: list, size: int = _CHUNK) -> Iterator[list]:
    for start in range(0, len(items), size):
        yield items[start:start + size]


def case_signature(data: dict) -> str:
    """Отпечаток полей находки, от которых зависит срез кода (CASE_KEYS)."""
    return dumps({key: data.get(key) for key in CASE_KEYS})


def _expected_layout() -> dict[str, set[str]]:
    """Таблицы и колонки схемы – из манифеста app/storage/schema.py."""
    layout = {table: set(info["columns"])
              for table, info in {**storage_schema.TABLES, **storage_schema.ADDED_TABLES}.items()}
    for table, added in storage_schema.ADDED_COLUMNS.items():
        layout[table] |= {name for name, _ in added}
    return layout


def hub_verdict(decision: str, final_verdict: str) -> str:
    """Итог, по которому строится текст для Hub: у отложенной находки окончательного статуса нет – «неясно», как
    и без выбранного вердикта; «Риск принят» – отдельный статус (risk_accepted) при любом вердикте."""
    if decision == "risk_accepted":
        return "risk_accepted"
    return "uncertain" if decision == "later" else (final_verdict or "uncertain")


def finding_data_sig(raw: str | None) -> str:
    """Отпечаток данных находки (столбец findings.data_json, как записан): меняется, когда повторная выгрузка
    изменила находку. Статус из карточки (ADR-0115) уходит, только если данные те же, что видел оператор."""
    return hashlib.sha256(str(raw or "").encode("utf-8")).hexdigest()[:32]


def text_hash(text: str) -> str:
    """Отпечаток текста для Hub: по нему видно, что внесённый в Hub текст с тех пор изменился."""
    return hashlib.sha256(str(text or "").encode("utf-8", "replace")).hexdigest()[:32]


def review_signature(data: dict, repos_dir: str = "", folder: str = "", revision: str = "") -> str:
    """Отпечаток того, по чему принято решение: поля находки, от которых зависит срез (CASE_KEYS), и откуда
    берётся её код (папка проекта, папка клона кодовой базы и ревизия клона git, если она известна). У находки
    SCA кода нет: решение зависит от компонента, версии и уязвимостей (SCA_KEYS)."""
    if str(data.get("kind") or "").startswith("SCA"):
        # пакет – это экосистема, имя и версия (ADR-0049): смена Type при том же номере Hub – другая находка для решения
        payload = {"sca": {key: data.get(key) for key in SCA_KEYS}, "ecosystem": finding_ecosystem(data)}
        # эффективное имя пакета (план dev17, п. 4.2) – только когда отличается от компонента выгрузки: у неуточнённых
        # находок подпись прежняя
        name = package_identity.name_of(data)
        if name != str(data.get("component") or ""):
            payload["package"] = name
        return dumps(payload)
    return dumps({"case": {key: data.get(key) for key in CASE_KEYS},
                  "source": [repos_dir or "", folder or "", revision or ""]})


def finding_version(data: dict, repos_dir: str = "", folder: str = "", revision: str = "") -> str:
    """Короткая версия находки для форм: меняется, когда меняются код, место, папка или ревизия клона."""
    return hashlib.sha256(review_signature(data, repos_dir, folder, revision).encode("utf-8")).hexdigest()[:16]


def source_signature(source: dict) -> str:
    """review_signature по снимку case_input(): находка, папки и ревизия клона."""
    return review_signature(source["data"], source["repos_dir"], source["folder"], source.get("revision", ""))


def source_version(source: dict) -> str:
    """finding_version по снимку case_input() – версия для формы решения."""
    return finding_version(source["data"], source["repos_dir"], source["folder"], source.get("revision", ""))


def _revision_prefix(project_id: int) -> str:
    """Ключи meta с последней увиденной ревизией клона: rev:{проект}:{кодовая база}."""
    return f"rev:{int(project_id)}:"


def _detached_prefix(project_id: int) -> str:
    """Ключи meta отвязанных клонов (ADR-0072): detached:{проект}:{кодовая база} – код кодовой базы берётся только
    из срезов в базе, папка клона не читается."""
    return f"detached:{int(project_id)}:"


def _sca_confirmed_key(project_id: int) -> str:
    """Ключ meta со списком сомнительных имён библиотек, подтверждённых человеком для пакета SCA."""
    return f"scaok:{int(project_id)}"


NEW_SET = -1  # move_sca_member: перенос в новый набор дефекта SCA
NO_EXPECT = object()  # set_*_defect_number_checked: ожидаемый номер не сверяется (страница без поля number_shown)


class StaleReview(Exception):
    """Решение отправлено со страницы, которая устарела. reason – что изменилось с тех пор:
    "source" – находка, папка с её кодом или ревизия клона (новая выгрузка, другой клон);
    "verdict" – вердикт модели (новый прогон);
    "revision" – само решение (его сохранили из другой вкладки или окна);
    "code" – код в клоне (правки в рабочей копии; проверяет раздел находок, база к диску не обращается)."""

    def __init__(self, message: str = "", reason: str = "source") -> None:
        super().__init__(message)
        self.reason = reason


def _snapshot_confirmed(raw: Any, key: str | None = "confirmed") -> list[str]:
    """Подтверждённые адреса из options_json снимка (key = "confirmed") или из confirmed_addresses_json профиля
    (key = None) в едином виде."""
    from app.llm_net import normalize_addresses
    try:
        data = json.loads(str(raw or ("[]" if key is None else "{}")))
    except ValueError:
        return []
    values = data if key is None else (data.get(key) if isinstance(data, dict) else None)
    return normalize_addresses(values if isinstance(values, list) else [])


class ProfileChanged(Exception):
    """Профиль снимка выключили или сменили его адрес между проверкой и записью прогона: запись не сделана."""


READY_TIMEOUT = 3.0  # /healthz: короткий срок получения соединения
# Отметка о последней проверенной копии базы в settings: {"name": имя файла, "checked_at": время проверки, UTC}. Копии лежат на
# компьютере вне контейнера, приложение их не видит: отметку пишет сценарий копий командой backup-note (app/storage/tools.py)
BACKUP_NOTE_KEY = "last_checked_backup"
LOCK_TIMEOUT = 30.0  # сколько секунд запрос ждёт замок писателя или соединение пула, прежде чем отказать (DatabaseBusy)


class HubUnknownWrites(Exception):
    """Пауза записи не снята: есть операции записи с неизвестным исходом; число – в args[0]."""


class HubResyncRequired(Exception):
    """Пауза записи не снята: после восстановления копии ещё не прошла «Синхронизировать»; число проектов – в args[0]."""


HUB_DISABLED_TEXT = ("В учебном стенде Hub выключен: исполнителя Hub в стенде нет. Подключение к AppSec.Hub – в "
                     "Docker-установке приложения; выгрузку Excel из Hub в стенд загрузить можно.")


class HubDisabledInStand(ValueError):
    """Учебный стенд npm (ADR-0155): операции Hub не ставятся в очередь. ValueError – маршруты показывают текст как
    обычный отказ постановки."""


class ProjectBusy(Exception):
    """Проект нельзя удалить: у него идёт прогон. Текст – по-русски, для показа в интерфейсе."""


class DecisionStale(Exception):
    """Решение по исследованию компонента отправлено со страницы, которая устарела: между открытием карточки и
    сохранением решение изменили в другой вкладке или пришёл новый ответ агента. Само решение не пишется, текущая
    ревизия – в аргументе, чтобы страница показала её и попросила подтвердить заново."""


class SelectionChanged(Exception):
    """Строки, выбранные для исследования провайдером, к моменту записи согласия стали другими (компонент вошёл в
    дефект, появилось исследование): согласие давалось на другой состав – нужен новый предпросмотр."""


class TaskSuperseded(Exception):
    """Состав проекта сменился, пока отвечали на задание: задание больше не отвечает выгрузке, и ответ по нему
    сохранять нельзя. Нужно собрать задание заново и ответить на него."""


class ScaSnapshot:
    """Неизменяемый снимок состояния пакета SCA (Database.sca_snapshot). Методы повторяют те чтения Database, которыми строится
    дефект SCA, поэтому вместо базы в sca_defect можно передать снимок: текст строится из тех же данных, для которых снят
    отпечаток, и база после снимка не читается.

    row – находка (словарь Database.get_finding_by_hub_id) или None, если находки нет, она не SCA или проекта нет;
    review – её решение или None; project_exists – проект есть; latest_answer – последний ответ агента по пакету;
    fingerprint – отпечаток снимка (Database.set_sca_defect_number_checked)."""

    def __init__(self, project_id: int, hub_id: str, project_exists: bool, state: dict | None, *,
                 numbers: dict[str, int] | None = None, stats: dict | None = None, next_id: int | None = None,
                 fingerprint: str = "none", reserved: int = 0) -> None:
        self.project_id, self.hub_id, self.project_exists = project_id, hub_id, project_exists
        self._state = state
        self.row = state["own"] if state else None
        self.package = state["package"] if state else None
        self._members = state["members"] if state else []
        self._reviews = state["reviews"] if state else {}
        self._answers = state["answers"] if state else []
        self._mapping = state["mapping"] if state else []
        self.review = self._reviews.get(hub_id)
        self.latest_answer = self._answers[0] if self._answers else None
        self.numbers = numbers or {}
        self.stats = stats or {}
        self.next_id = next_id
        self.fingerprint = fingerprint
        self.reserved = int(reserved or 0)  # наибольший номер дефекта из карточки в работе (Database.reserved_defect_number)

    # --- чтения, которыми пользуется sca_defect
    def defect_number(self, project_id: int, key: str) -> int | None:
        return self.numbers.get(key)

    def next_defect_number(self, project_id: int) -> int:
        return max(max(self.numbers.values(), default=0), self.reserved) + 1

    def sca_answers(self, project_id: int, component: str | None = None, version: str | None = None,
                    ecosystem: str | None = None) -> list[dict]:
        if self.package is None or (ecosystem, component, version) != self.package:
            raise LookupError("снимок описывает другой пакет")
        return [dict(a) for a in self._answers]

    def get_finding_by_hub_id(self, project_id: int, hub_id: str) -> dict | None:
        return next((m for m in self._members if m["hub_id"] == hub_id), None)

    def get_finding(self, project_id: int, finding_id: int) -> dict | None:
        return next((m for m in self._members if m["id"] == finding_id), None)

    def get_review(self, project_id: int, hub_id: str) -> dict | None:
        return self._reviews.get(hub_id)

    def imports_meta(self, ids: Iterable[int]) -> dict[int, dict]:
        """Сведения о выгрузках {id: {filename, created_at}} из снимка – как Database.imports_meta."""
        found = (self._state or {}).get("imports") or {}
        return {int(i): found[int(i)] for i in ids if i is not None and int(i) in found}

    def sca_components(self, project_id: int, kinds: Iterable[str] = ("SCA",), include_missing: bool = False) -> list[dict]:
        """Группа пакета снимка (только она): ecosystem, component, version, hub_ids и finding_ids находок текущей выгрузки."""
        if self.package is None:
            return []
        rows = [m for m in self._members if include_missing or not m["missing"]]
        if not rows:
            return []
        eco, name, version = self.package
        return [{"ecosystem": eco, "component": name, "version": version, "findings": len(rows),
                 "hub_ids": [m["hub_id"] for m in rows], "finding_ids": [m["id"] for m in rows]}]

    @property
    def input_ref(self) -> str:
        return str((self._state or {}).get("input_ref") or "")

    @property
    def research_ref(self) -> str:
        """Ключ строки задания исследования этой версии (sca.package_key) – для ссылки на карточку компонента."""
        return str((self._state or {}).get("research_ref") or "")

    @property
    def current_members(self) -> list[dict]:
        """Находки пакета из текущей выгрузки (строки как Database.get_finding) в порядке выгрузки."""
        return [dict(m) for m in self._members if not m["missing"]]

    @property
    def research(self) -> dict | None:
        """Текущая ревизия исследования компонента (формат 2) или None (ADR-0091)."""
        return (self._state or {}).get("research")

    @property
    def component_decision(self) -> dict | None:
        """Действующее решение по компоненту (sca2_decisions) или None."""
        return (self._state or {}).get("component_decision")

    @property
    def placed(self) -> dict[str, dict]:
        """Явные места находок пакета в наборах дефекта: {hub_id: {set_no, no_defect_reason}}."""
        return dict((self._state or {}).get("placed") or {})

    @property
    def sets(self) -> dict[int, dict]:
        return dict((self._state or {}).get("sets") or {0: {"revision": 0, "excluded": []}})

    def package_text(self, set_no: int) -> dict | None:
        return ((self._state or {}).get("texts") or {}).get(int(set_no))

    @property
    def applicability(self) -> list[dict]:
        """Решения оператора о применимости уязвимостей пакета (ADR-0094 Р3): строки sca_applicability с ids."""
        return [dict(v) for _, v in sorted(((self._state or {}).get("applicability") or {}).items())]

    def ast_map(self, ids: Iterable[str] | None = None) -> dict[str, list[str]]:
        wanted = None if ids is None else {str(x) for x in ids}
        result: dict[str, list[str]] = {}
        for ast_id, vuln_id in self._mapping:
            if wanted is None or ast_id in wanted:
                result.setdefault(ast_id, []).append(vuln_id)
        return result


# Общие условия запросов с находкой f и срезом c: отсутствие клона не доказывает отсутствие файла.
_NO_REPO_INCOMPLETE = """((c.context_json::json ->> 'reason') = 'no_repo'
    AND EXISTS(SELECT 1 FROM codebase_map m WHERE m.project_id = f.project_id AND m.codebase = f.codebase
               AND trim(m.folder) <> '')
    AND NOT EXISTS(SELECT 1 FROM meta WHERE key = 'detached:' || f.project_id || ':' || f.codebase))"""
_SNAPSHOT_REPLACEABLE = f"""(COALESCE((c.context_json::json ->> 'status'), '') <> 'ok' AND (
    (c.verdict_id IS NULL AND COALESCE((c.context_json::json ->> 'reason'), '')
        IN ('missing', 'unreadable', '')) OR {_NO_REPO_INCOMPLETE}))"""
_SNAPSHOT_INCOMPLETE = f"""(c.hub_id IS NOT NULL
    AND COALESCE((c.context_json::json ->> 'status'), '') <> 'ok'
    AND (COALESCE((c.context_json::json ->> 'reason'), '') NOT IN ('missing', 'no_repo', 'empty')
         OR {_NO_REPO_INCOMPLETE}))"""


# Автоматическая отметка действует только в назначении подтверждающей операции.
# Ручная отметка остаётся заметкой оператора; status_in_hub её доказательством не считает.
_ENTERED_HUB_SQL = """(CASE WHEN r.entered_origin IN ('status', 'defect', 'hub_sync') THEN
    CASE WHEN COALESCE(r.entered_hub, 0) <> 0 AND EXISTS (
        SELECT 1 FROM hub_ops mark_op JOIN projects mark_project ON mark_project.id = r.project_id
        WHERE mark_op.id = r.entered_op_id AND mark_op.project_id = r.project_id
          AND mark_op.hub_url = hub_base(COALESCE((SELECT (value_json::json #>> '{}')
                                                FROM settings WHERE key = 'hub_url'), ''))
          AND mark_op.app_id IS NOT DISTINCT FROM mark_project.hub_app_id) THEN 1 ELSE 0 END
    ELSE COALESCE(r.entered_hub, 0) END)"""


# Как status_now_in: версия подтверждения, запись без версии, принятая сверка, выгрузка.
# Назначение берётся из базы; коррелированные чтения используют ключи существующих таблиц.
_CURRENT_HUB_STATUS_SQL = """COALESCE((
    SELECT CASE WHEN hv.accepted_source_json::json ->> 'origin' = 'status_confirmation'
        THEN NULLIF(w.request_json::json -> 'body' ->> 'status', '')
        ELSE COALESCE(NULLIF(old_write.status, ''),
            CASE WHEN hs.confirmed_presence = 'present'
                 THEN NULLIF(hs.confirmed_json::json -> 'detail' ->> 'status', '') END) END
    FROM projects hp
    CROSS JOIN LATERAL (SELECT (SELECT hub_base(COALESCE(
        (SELECT value_json::json #>> '{}' FROM settings WHERE key = 'hub_url'), ''))) AS base,
        CASE f.kind WHEN 'SCA' THEN 'SCA_S' WHEN 'SCA-license' THEN 'SCA_L'
                    WHEN 'SAST' THEN 'SAST' WHEN 'DAST' THEN 'DAST' END AS typ,
        CASE WHEN trim(f.hub_id) ~ '^[0-9]+$' THEN
            CASE WHEN trim(f.hub_id)::numeric > 0 AND trim(f.hub_id)::numeric < 1000000000000
                 THEN (trim(f.hub_id)::numeric)::text END END AS ident) target
    LEFT JOIN hub_entity_versions hv ON hv.project_id = hp.id AND hv.hub_url = target.base
        AND hv.app_id = hp.hub_app_id AND hv.entity_kind = 'issue'
        AND hv.entity_key = target.typ || ':' || target.ident
    LEFT JOIN hub_ops w ON w.id = (hv.accepted_source_json::json ->> 'op_id')::bigint
        AND w.project_id = hp.id AND w.hub_url = target.base AND w.app_id = hp.hub_app_id
        AND w.purpose = 'status' AND w.state = 'done'
    LEFT JOIN (
        SELECT DISTINCT ON (ho.project_id, ho.hub_url, ho.app_id, t.value ->> 'hub_id')
            ho.project_id, ho.hub_url, ho.app_id, t.value ->> 'hub_id' AS hub_id, ho.request_json::json -> 'body' ->> 'status' AS status
        FROM hub_ops ho, json_array_elements(ho.targets_json::json) t(value)
        WHERE ho.purpose = 'status' AND ho.state = 'done'
        ORDER BY ho.project_id, ho.hub_url, ho.app_id, t.value ->> 'hub_id', ho.id DESC
    ) old_write ON hv.entity_key IS NULL AND old_write.project_id = hp.id AND old_write.hub_url = target.base
        AND old_write.app_id = hp.hub_app_id AND old_write.hub_id = f.hub_id
    LEFT JOIN hub_issue_states hs ON hs.project_id = hp.id AND hs.hub_url = target.base
        AND hs.app_id = hp.hub_app_id AND hs.issue_type = target.typ AND hs.issue_id = target.ident
    WHERE hp.id = f.project_id AND hp.hub_app_id <> 0 AND target.typ IS NOT NULL AND target.ident IS NOT NULL
), f.data_json::json ->> 'status', '')"""

# Класс находки по действующему статусу Hub (план dev18, общие определения): Fixed – «исправлено»; статусы решений Hub
# (`hub_sync_compare.DECISION_STATUSES`, машинные значения API) – «закрыто решением»; пустой и прочие – «живая».
# Подписи `hub_status_map` – русские слова для текста, здесь не участвуют.
HUB_CLOSED_DECISION_STATUSES = ("false positive", "accepted risk")
_HUB_CLASS_SQL = ("(CASE lower(trim(" + _CURRENT_HUB_STATUS_SQL + ")) WHEN 'fixed' THEN 'fixed'"
                  + "".join(f" WHEN '{s}' THEN 'closed'" for s in HUB_CLOSED_DECISION_STATUSES) + " ELSE 'live' END)")


# Расхождение решения Hub и вердикта модели (бэклог 102, план dev18): False Positive в Hub и «истинная» у модели или
# Confirmed в Hub и «ложная» у модели. Accepted risk – истинное срабатывание без исправления кода: не расхождение.
_HUB_MODEL_DIFF_SQL = ("(CASE lower(trim(" + _CURRENT_HUB_STATUS_SQL + ")) WHEN 'false positive' THEN "
                       "COALESCE(v.verdict = 'true_positive', false) WHEN 'confirmed' THEN "
                       "COALESCE(v.verdict = 'false_positive', false) ELSE false END)")
# Без кода в клоне (бэклог 103): сохранённый срез есть, но код модель не видела; среза нет – не этот случай
_NO_CODE_SQL = "(c.hub_id IS NOT NULL AND COALESCE(c.context_json::json ->> 'status', '') <> 'ok')"
# Ключ причины отсутствия кода (бэклог 103) – то же, что view.code_reason_key; для среза без кода
_CODE_REASON_KEY_SQL = ("(CASE WHEN c.context_json::json ->> 'reason' = 'missing' THEN CASE WHEN "
                        "btrim(COALESCE(c.context_json::json ->> 'file', '')) <> '' THEN 'file_missing' ELSE 'no_file' END "
                        "WHEN c.context_json::json ->> 'reason' IN ('no_repo', 'ambiguous', 'unreadable', 'empty', "
                        "'line_out_of_range', 'binary', 'too_large') THEN c.context_json::json ->> 'reason' ELSE 'unknown' END)")
_IN_ARCHIVE_SQL = ("(COALESCE(c.context_json::json ->> 'reason', '') <> 'no_repo' AND "
                   "COALESCE(c.context_json::json ->> 'file', '') ~* '\\.(jar|war|ear|aar|zip)!?/')")

# То же, что _CURRENT_HUB_STATUS_SQL, но множеством для всех находок проекта (замер стоимости dev18: коррелированный
# подзапрос на 1500 находок – 0,7 с, из них 0,6 с – поиск последней записи статуса заново для каждой строки). Параметры:
# project_id дважды; {cond} – дополнительное условие на находку `f`. Совпадение с построчным выражением – тест
# test_hub_status_set_matches_row.
_HUB_STATUS_SET_SQL = """
    WITH settings_base AS (SELECT hub_base(COALESCE(
             (SELECT value_json::json #>> '{{}}' FROM settings WHERE key = 'hub_url'), '')) AS base),
    -- последняя выполненная запись статуса по находке – только для текущего назначения проекта (адрес Hub из
    -- настроек, номер приложения проекта): соединение ниже идёт по одному номеру находки и строится хешем, а не
    -- перебором всех записей на каждую находку (бэклог 123)
    old_write AS MATERIALIZED (
        SELECT DISTINCT ON (t.value ->> 'hub_id')
               t.value ->> 'hub_id' AS hub_id,
               ho.request_json::json -> 'body' ->> 'status' AS status
          FROM hub_ops ho
          JOIN projects op ON op.id = ho.project_id
          CROSS JOIN settings_base osb
          CROSS JOIN json_array_elements(ho.targets_json::json) t(value)
         WHERE ho.project_id = ? AND ho.purpose = 'status' AND ho.state = 'done'
           AND ho.hub_url = osb.base AND ho.app_id = op.hub_app_id
         ORDER BY t.value ->> 'hub_id', ho.id DESC)
    SELECT f.id, f.hub_id, f.pos, f.kind, COALESCE(CASE WHEN hp.hub_app_id <> 0 AND tg.typ IS NOT NULL AND tg.ident IS NOT NULL
        THEN CASE WHEN hv.accepted_source_json::json ->> 'origin' = 'status_confirmation'
            THEN NULLIF(w.request_json::json -> 'body' ->> 'status', '')
            ELSE COALESCE(NULLIF(ow.status, ''),
                 CASE WHEN hs.confirmed_presence = 'present'
                      THEN NULLIF(hs.confirmed_json::json -> 'detail' ->> 'status', '') END) END END,
        f.data_json::json ->> 'status', '') AS status
      FROM findings f
      JOIN projects hp ON hp.id = f.project_id
      CROSS JOIN settings_base sb
      CROSS JOIN LATERAL (SELECT
          CASE f.kind WHEN 'SCA' THEN 'SCA_S' WHEN 'SCA-license' THEN 'SCA_L'
                      WHEN 'SAST' THEN 'SAST' WHEN 'DAST' THEN 'DAST' END AS typ,
          CASE WHEN trim(f.hub_id) ~ '^[0-9]+$' THEN
              CASE WHEN trim(f.hub_id)::numeric > 0 AND trim(f.hub_id)::numeric < 1000000000000
                   THEN (trim(f.hub_id)::numeric)::text END END AS ident) tg
      LEFT JOIN hub_entity_versions hv ON hv.project_id = hp.id AND hv.hub_url = sb.base
          AND hv.app_id = hp.hub_app_id AND hv.entity_kind = 'issue' AND hv.entity_key = tg.typ || ':' || tg.ident
      LEFT JOIN hub_ops w ON w.id = (hv.accepted_source_json::json ->> 'op_id')::bigint
          AND w.project_id = hp.id AND w.hub_url = sb.base AND w.app_id = hp.hub_app_id
          AND w.purpose = 'status' AND w.state = 'done'
      LEFT JOIN old_write ow ON hv.entity_key IS NULL AND ow.hub_id = f.hub_id
      LEFT JOIN hub_issue_states hs ON hs.project_id = hp.id AND hs.hub_url = sb.base
          AND hs.app_id = hp.hub_app_id AND hs.issue_type = tg.typ AND hs.issue_id = tg.ident
     WHERE f.project_id = ? {cond}"""


def _hub_class(status_sql: str) -> str:
    """Класс находки по статусу: fixed / closed / live – как _HUB_CLASS_SQL."""
    return ("(CASE lower(trim(" + status_sql + ")) WHEN 'fixed' THEN 'fixed'"
            + "".join(f" WHEN '{s}' THEN 'closed'" for s in HUB_CLOSED_DECISION_STATUSES) + " ELSE 'live' END)")


def closed_status_sql() -> str:
    """Условие «находка закрыта в Hub» (Fixed или статус решения) для запроса с находкой `f` – одно для очереди, отбора,
    счётчиков формы и итога прогона (план dev18)."""
    return f"({_HUB_CLASS_SQL} <> 'live')"


class EmptyQueue(ValueError):
    """Для выбранного охвата нет находок SAST: прогон не создаётся."""


class Database:
    """Доступ к базе. Методы потокобезопасны; строки возвращаются обычными словарями."""

    def __init__(self, path: Path | str | None = None, write_guard: Callable[[], None] | None = None):
        """path – строка подключения или путь файла прежней базы (рабочее приложение: адрес из переменных libpq, тесты:
        своя база на каждый путь). write_guard – проверка перед каждой записью (замок папки данных, app/lockfile.py):
        бросает исключение, если этому экземпляру писать уже нельзя."""
        self.path = path
        self._write_guard = write_guard
        self._run_clocks: dict[int, tuple[float, str]] = {}
        # часы журнала в памяти процесса: переход состояния прогона (с COMMIT) и чтение строки журнала вместе с часами не
        # пересекаются; снимок базы часы не защищает (ADR-0128, п. 6.2). Порядок: сначала этот замок, затем транзакция
        self._run_clocks_lock = threading.RLock()
        self._store = PostgresStore(conninfo_for(path), lock_timeout=lambda: LOCK_TIMEOUT)
        self._lock = ReadContext(self._store)
        self.read_only = False  # режим обслуживания: страницы не пишут по пути (доведение последствий и т. п.)
        # учебный стенд npm (ADR-0155): исполнителя Hub нет – операции Hub не ставятся и не выдаются; ставит main
        self.hub_disabled = False
        try:
            version = self._inspect()  # только чтение: чужая или неподходящая база отвергается до любых изменений
            self._upgrade(version)
        except BaseException:
            self._store.close()
            raise

    # ------------------------------------------------------------------ служебное

    def close(self) -> None:
        self._store.close()

    @property
    def store(self) -> PostgresStore:
        """Хранилище для справочников (ADR-0133): та же база, тот же пул и замок экземпляра."""
        return self._store

    def secret(self, name: str) -> str | None:
        """Значение из app_state.secrets (ADR-0133): ключи приложения. Нет – None."""
        row = self._store.read(lambda c: c.execute("SELECT value FROM app_state.secrets WHERE name = ?", (name,)).fetchone())
        return row[0] if row else None

    def put_secret(self, name: str, value: str) -> None:
        with self._tx() as c:
            c.execute("INSERT INTO app_state.secrets(name, value, updated_at) VALUES (?, ?, ?) ON CONFLICT (name) DO UPDATE"
                      " SET value = EXCLUDED.value, updated_at = EXCLUDED.updated_at", (name, value, now_iso()))

    def drop_secret(self, name: str) -> bool:
        with self._tx() as c:
            return c.execute("DELETE FROM app_state.secrets WHERE name = ?", (name,)).rowcount > 0

    def ensure_secret(self, name: str, make: Callable[[], str]) -> str:
        """Значение или новое: при одновременном запуске все получают одно и то же. В режиме обслуживания база не меняется: новое значение
        действует только до перезапуска."""
        found = self.secret(name)
        if found is not None:
            return found
        fresh = make()
        if self.read_only:
            return fresh
        with self._tx() as c:
            c.execute("INSERT INTO app_state.secrets(name, value, updated_at) VALUES (?, ?, ?) ON CONFLICT (name) DO NOTHING",
                      (name, fresh, now_iso()))
        return self.secret(name) or fresh

    def mask_key(self) -> bytes:
        """Ключ HMAC для номеров плейсхолдеров. Повреждённое значение – ValueError: заменить молча нельзя, номера в новых срезах разойдутся
        с прежними."""
        from app.masking import KEY_SIZE
        from app.storage.local_state import MASK_SECRET
        value = self.ensure_secret(MASK_SECRET, lambda: os.urandom(KEY_SIZE).hex())
        try:
            key = bytes.fromhex(value)
        except ValueError:
            key = b""
        if len(key) != KEY_SIZE:
            raise ValueError("Ключ маскирования в базе повреждён: восстановите его из копии базы.")
        return key

    def hold_instance(self) -> None:
        """Один работающий экземпляр приложения на базу (ADR-0128, п. 6.5): вместе с замком папки данных при запуске."""
        self._store.hold_instance()

    @property
    def _conn(self) -> Any:
        """Соединение текущего контекста; вне контекста – отдельные запросы без транзакции."""
        return self._store.current()

    @contextmanager
    def _tx(self) -> Iterator[Any]:
        """Транзакция записи: всё или ничего, записи приложения идут по одной. Сбой откатывает
        транзакцию целиком; при обрыве на самом COMMIT её исход неизвестен (CommitUnknown). Право писать (write_guard) проверяется в начале и ещё раз перед COMMIT: если за время
        транзакции папку данных забрал другой экземпляр, изменения откатываются."""
        if self.read_only and PAGE_VIEW.get():
            with self._store.transaction(discard=True) as c:
                yield c
            return
        with self._store.transaction(self._write_guard) as c:
            yield c

    @contextmanager
    def snapshot(self) -> Iterator[None]:
        """Согласованное чтение нескольких таблиц: блок видит один снимок базы, записи других запросов в него не попадают.
        Внутри блока работают обычные методы чтения. Внутри блока – только чтения базы: форматирование текста, обогащение
        и обращения к справочникам делаются после выхода из него (см. sca_snapshot, который возвращает данные для этого)."""
        with self._lock:
            yield

    def _all(self, sql: str, params: Iterable[Any] = ()) -> list[dict]:
        return self._store.read(lambda c: [dict(row) for row in c.execute(sql, tuple(params))])

    def _one(self, sql: str, params: Iterable[Any] = ()) -> dict | None:
        def run(c: Any) -> dict | None:
            row = c.execute(sql, tuple(params)).fetchone()
            return dict(row) if row is not None else None
        return self._store.read(run)

    def _scalar(self, sql: str, params: Iterable[Any] = ()) -> Any:
        def run(c: Any) -> Any:
            row = c.execute(sql, tuple(params)).fetchone()
            return row[0] if row is not None else None
        return self._store.read(run)

    def _inspect(self) -> int | None:
        """Проверка базы без изменений: None – новая пустая база, иначе версия её схемы.

        Чужая база (таблицы есть, а таблицы meta нет), база другой версии, несовпадение колонок со схемой той же версии –
        понятная ошибка, база не трогается. Обновление существующей схемы – отдельная операция обслуживания с копией
        перед ней (ADR-0128, раздел 7), при обычном открытии её нет."""
        tables = self._tables()
        if not tables:
            return None
        if "meta" not in tables:
            raise RuntimeError("База PostgreSQL – не база этого приложения: в ней нет таблицы meta. Укажите другую базу.")
        version = int(self._scalar("SELECT value FROM meta WHERE key = 'schema_version'") or SCHEMA_VERSION)
        if version > SCHEMA_VERSION:
            raise RuntimeError(f"База создана более новой версией приложения (схема {version}, эта версия – "
                               f"{SCHEMA_VERSION}).")
        if version < SCHEMA_VERSION:
            raise RuntimeError(f"Схема базы {version}, этой версии приложения нужна {SCHEMA_VERSION}: обновите схему "
                               "командой обслуживания (start.ps1 делает это вместе с копией базы).")
        self._check_layout()
        return version

    def _upgrade(self, version: int | None) -> None:
        """Новая пустая база – базовая схема целиком одной транзакцией. Существующая база не меняется (_inspect)."""
        if version is not None:
            return
        with self._tx() as c:
            apply_baseline(c)
            c.execute("INSERT INTO meta(key, value) VALUES ('schema_version', ?)", (str(storage_migrate.BASELINE_SCHEMA),))
            c.execute("INSERT INTO meta(key, value) VALUES ('journal_installation', ?)", (secrets.token_hex(16),))
            c.execute("INSERT INTO schema_version(version, applied_at, note) VALUES (?, ?, ?)",
                      (storage_migrate.BASELINE_SCHEMA, now_iso(), "новая база"))
            for item in storage_migrate.available():
                storage_migrate.apply_one(c, item, mark="?")

    def schema_log(self) -> list[dict]:
        """Журнал обновлений схемы: [{version, applied_at, note}] по возрастанию версии."""
        with self._lock:
            if "schema_version" not in self._tables():
                return []
            return self._all("SELECT version, applied_at, note FROM schema_version ORDER BY version")

    def _tables(self) -> set[str]:
        return {row[0] for row in self._conn.execute(
            "SELECT table_name FROM information_schema.tables"
            " WHERE table_schema = current_schema() AND table_type = 'BASE TABLE'")}

    def _check_layout(self) -> None:
        """Колонки существующих таблиц должны включать все колонки схемы, иначе – понятная ошибка вместо сбоев SQL
        (например, база создана другой сборкой приложения)."""
        present: dict[str, set[str]] = {}
        for row in self._conn.execute("SELECT table_name, column_name FROM information_schema.columns"
                                      " WHERE table_schema = current_schema()"):
            present.setdefault(row[0], set()).add(row[1])
        for table, columns in _expected_layout().items():
            if table not in present:
                raise RuntimeError(f"База не подходит этой версии приложения: нет таблицы {table}. Восстановите базу из "
                                   "проверенной копии.")
            missing = sorted(columns - present[table])
            if missing:
                raise RuntimeError(f"База не подходит этой версии приложения: в таблице {table} нет колонок "
                                   f"{', '.join(missing)}.")

    def ready(self) -> dict[str, Any]:
        """Готовность для /healthz: база отвечает и её схема – та, что нужна этой версии. Ошибка связи – исключение."""
        row = self._store.read(lambda c: c.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone(),
                               timeout=READY_TIMEOUT)
        version = int(row[0]) if row else 0
        return {"schema": version, "ok": version == SCHEMA_VERSION, "instance_lost": self._store.instance_lost(READY_TIMEOUT)}

    def last_checked_backup(self) -> dict[str, Any] | None:
        """Отметка о последней проверенной копии базы для /healthz: {"name", "checked_at"} или None – отметки нет или она
        испорчена. Срок соединения – как у ready()."""
        row = self._store.read(lambda c: c.execute("SELECT value_json FROM settings WHERE key = ?", (BACKUP_NOTE_KEY,)).fetchone(),
                               timeout=READY_TIMEOUT)
        value = loads(row[0], None) if row is not None else None
        return value if isinstance(value, dict) else None

    @staticmethod
    def _touch(c: Connection, project_id: int, ts: str) -> None:
        """Последняя активность проекта (список проектов сортируется по ней)."""
        c.execute("UPDATE projects SET last_activity = ? WHERE id = ?", (ts, project_id))

    # ------------------------------------------------------------------ настройки

    def get_settings(self) -> dict[str, Any]:
        """Настройки из интерфейса: {ключ: значение} (значения хранятся в JSON). Испорченное значение пропускается."""
        result = {}
        for row in self._all("SELECT key, value_json FROM settings"):
            try:
                result[row["key"]] = json.loads(row["value_json"])
            except ValueError:
                continue
        return result

    def set_settings(self, values: Mapping[str, Any]) -> None:
        """Сохраняет настройки (значения – то, что умеет JSON) одной транзакцией. Проверку значений делает
        вызывающий: app.config.normalize_setting."""
        ts = now_iso()
        with self._tx() as c:
            c.executemany("INSERT INTO settings(key, value_json, updated_at) VALUES (?, ?, ?)"
                          " ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json,"
                          " updated_at = excluded.updated_at",
                          [(str(key), dumps(value), ts) for key, value in values.items()])
            if "ollama_url" in values or "default_model" in values:
                self._sync_default_profile(c, values, ts)

    # ------------------------------------------------------------------ профили провайдеров (ADR-0102)

    def ensure_default_profile(self, base_url: str, default_model: str) -> dict[str, Any]:
        """Профиль 1 (П11, П23): Ollama по адресу из «Настроек», класс local, оба назначения, параметры генерации
        «авто, как сейчас». Создаётся один раз – вместе с умолчаниями назначений (ключи default_provider_id и
        default_research_provider_id таблицы settings) одной транзакцией. Повторный вызов ничего не меняет: ни
        адрес, ни модель, ни версию, ни выключенность, ни уже выбранные умолчания. Возвращает профиль 1."""
        ts = now_iso()
        with self._tx() as c:
            if c.execute("SELECT 1 FROM llm_providers WHERE id = ?", (DEFAULT_PROVIDER_ID,)).fetchone() is None:
                c.execute("INSERT INTO llm_providers(id, name, kind, base_url, trust, auth, purposes_json, enabled,"
                          " version, default_model, capabilities_json, created_at, updated_at)"
                          " VALUES (?, ?, 'ollama', ?, 'local', 'none', ?, 1, 1, ?, ?, ?, ?)",
                          (DEFAULT_PROVIDER_ID, "Ollama из «Настроек»", str(base_url or ""), dumps(["code", "research"]),
                           str(default_model or ""), dumps({"supports_ps": True, "allows_unload": True}), ts, ts))
                # номер 1 задан явно: следующий профиль получит следующий номер, а не столкнётся с этим
                c.execute("SELECT setval(pg_get_serial_sequence('llm_providers', 'id'),"
                          " (SELECT MAX(id) FROM llm_providers))")
            c.executemany("INSERT INTO settings(key, value_json, updated_at) VALUES (?, ?, ?)"
                          " ON CONFLICT(key) DO NOTHING",
                          [(key, dumps(DEFAULT_PROVIDER_ID), ts)
                           for key in ("default_provider_id", "default_research_provider_id")])
        return self.get_provider(DEFAULT_PROVIDER_ID) or {}

    def get_provider(self, provider_id: int) -> dict[str, Any] | None:
        """Профиль провайдера по номеру (и выключенный: на него ссылается история) или None."""
        return self._one("SELECT * FROM llm_providers WHERE id = ?", (int(provider_id),))

    PROVIDER_FIELDS = ("name", "kind", "base_url", "trust", "auth", "purposes_json", "enabled", "default_model",
                       "models_json", "capabilities_json", "confirmed_addresses_json", "generation_json")

    def create_provider(self, values: Mapping[str, Any]) -> dict[str, Any]:
        """Новый профиль (поля PROVIDER_FIELDS; name обязателен), версия 1. Значения проверяет вызывающий
        (app/providers.py). Возвращает профиль."""
        fields = {k: v for k, v in values.items() if k in self.PROVIDER_FIELDS}
        unknown = set(values) - set(fields)
        if unknown or not str(fields.get("name") or "").strip():
            raise ValueError(f"поля профиля: неизвестные {sorted(unknown)} или нет названия")
        ts = now_iso()
        with self._tx() as c:
            columns = ", ".join([*fields, "created_at", "updated_at"])
            marks = ", ".join("?" * (len(fields) + 2))
            new_id = int(c.execute(f"INSERT INTO llm_providers({columns}) VALUES ({marks})" " RETURNING id",
                                   (*fields.values(), ts, ts)).fetchone()[0])
        return self.get_provider(new_id) or {}

    def update_provider(self, provider_id: int, values: Mapping[str, Any]) -> dict[str, Any]:
        """Записать поля профиля (только PROVIDER_FIELDS) и поднять версию, если что-то изменилось. Значения
        проверяет вызывающий (app/providers.py). Возвращает профиль после записи."""
        fields = {k: v for k, v in values.items() if k in self.PROVIDER_FIELDS}
        unknown = set(values) - set(fields)
        if unknown:
            raise ValueError(f"неизвестные поля профиля: {sorted(unknown)}")
        ts = now_iso()
        with self._tx() as c:
            row = c.execute("SELECT * FROM llm_providers WHERE id = ?", (int(provider_id),)).fetchone()
            if row is None:
                raise ValueError(f"профиля №{provider_id} нет")
            current = dict(zip([d[0] for d in c.execute("SELECT * FROM llm_providers LIMIT 0").description], row, strict=True))
            changed = {k: v for k, v in fields.items() if current.get(k) != v}
            if changed:
                sets = ", ".join(f"{k} = ?" for k in changed)
                c.execute(f"UPDATE llm_providers SET {sets}, version = version + 1, updated_at = ? WHERE id = ?",
                          (*changed.values(), ts, int(provider_id)))
        return self.get_provider(int(provider_id)) or {}

    def list_providers(self, enabled_only: bool = False) -> list[dict[str, Any]]:
        sql = "SELECT * FROM llm_providers" + (" WHERE enabled = 1" if enabled_only else "") + " ORDER BY id"
        return self._all(sql)

    @staticmethod
    def _check_profile_allows(c: Connection, provider_id: Any, base_url: str | None,
                              confirmed: list[str] | None = None) -> None:
        """Внутри транзакции записи прогона: профиль снимка включён и (для переносимого снимка) его адрес и, у lan,
        подтверждённые адреса не сменились. Иначе ProfileChanged – ничего не записано, прежний прогон не тронут
        (ADR-0102 п. 5)."""
        if provider_id is None:
            return
        row = c.execute("SELECT enabled, base_url, name, confirmed_addresses_json FROM llm_providers WHERE id = ?",
                        (int(provider_id),)).fetchone()
        if row is None or not row[0]:
            raise ProfileChanged(f"Профиль провайдера модели «{row[2] if row else provider_id}» выключен.")
        if base_url is not None and str(row[1]) != str(base_url):
            raise ProfileChanged(f"Адрес профиля «{row[2]}» изменился после этого прогона.")
        if confirmed is not None and set(_snapshot_confirmed(row[3], key=None)) != set(confirmed):
            raise ProfileChanged(f"Подтверждённые адреса профиля «{row[2]}» изменились после этого прогона.")

    @staticmethod
    def _insert_execution(c: Connection, values: Mapping[str, Any], ts: str) -> int:
        """Снимок исполнителя (ADR-0102 п. 3) – внутри транзакции вызывающего."""
        return int(c.execute(
            "INSERT INTO llm_executions(provider_id, provider_version, kind, base_url, trust, purpose, model,"
            " options_json, schema_mode, digest, note, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)" " RETURNING id",
            (values.get("provider_id"), values.get("provider_version"), str(values["kind"]),
             str(values.get("base_url") or ""), str(values.get("trust") or ""), str(values["purpose"]),
             str(values.get("model") or ""), str(values.get("options_json") or "{}"),
             str(values.get("schema_mode") or ""), str(values.get("digest") or ""), str(values.get("note") or ""),
             ts)).fetchone()[0])

    def get_execution(self, execution_id: int | None) -> dict[str, Any] | None:
        """Снимок исполнителя по номеру; пустой номер (прежние разборы) – None."""
        if execution_id is None:
            return None
        return self._one("SELECT * FROM llm_executions WHERE id = ?", (int(execution_id),))

    def get_executions(self, execution_ids: Iterable[int | None]) -> dict[int, dict[str, Any]]:
        """Снимки исполнителей одним запросом: для списков, где иначе был бы запрос на строку."""
        ids = sorted({int(i) for i in execution_ids if i is not None})
        if not ids:
            return {}
        marks = ",".join("?" * len(ids))
        return {int(row["id"]): row for row in self._all(f"SELECT * FROM llm_executions WHERE id IN ({marks})", ids)}

    def verdict_execution(self, verdict_id: int | None) -> dict[str, Any] | None:
        """Снимок исполнителя, которым получен ответ модели; ответ до 0.9.12 – None."""
        if verdict_id is None:
            return None
        row = self._one("SELECT execution_id FROM verdicts WHERE id = ?", (int(verdict_id),))
        return self.get_execution(row["execution_id"]) if row else None

    @staticmethod
    def _sync_default_profile(c: Connection, values: Mapping[str, Any], ts: str) -> None:
        """«Адрес Ollama» и «Модель по умолчанию» – представление профиля 1 (П23): сохранение пишет их и в профиль
        одной транзакцией с настройками; изменилось – новая версия профиля. Профиля 1 ещё нет (база до первого
        запуска 0.9.12) – его создаст запуск по этим же настройкам."""
        row = c.execute("SELECT base_url, default_model FROM llm_providers WHERE id = ?",
                        (DEFAULT_PROVIDER_ID,)).fetchone()
        if row is None:
            return
        base_url = str(values["ollama_url"]) if "ollama_url" in values else row[0]
        model = str(values["default_model"]) if "default_model" in values else row[1]
        if (base_url, model) != (row[0], row[1]):
            c.execute("UPDATE llm_providers SET base_url = ?, default_model = ?, version = version + 1, updated_at = ?"
                      " WHERE id = ?", (base_url, model, ts, DEFAULT_PROVIDER_ID))

    def seed_settings(self, defaults: Mapping[str, Any]) -> dict[str, Any]:
        """Первый запуск: недостающие настройки получают значения по умолчанию (из переменных окружения);
        сохранённые не меняются. Возвращает настройки после заполнения."""
        ts = now_iso()
        with self._tx() as c:
            c.executemany("INSERT INTO settings(key, value_json, updated_at) VALUES (?, ?, ?)"
                          " ON CONFLICT(key) DO NOTHING",
                          [(str(key), dumps(value), ts) for key, value in defaults.items()])
        return self.get_settings()

    # ------------------------------------------------------------------ проекты

    def create_project(self, name: str, model: str = "", mask_secrets: bool = False,
                       after: Callable[[Any, int], None] | None = None) -> int:
        """after(c, project_id) – запись в той же транзакции (связь проекта из каталога примеров, ADR-0156)."""
        ts = now_iso()
        with self._tx() as c:
            cur = c.execute("INSERT INTO projects(name, repos_dir, created_at, updated_at, model, last_activity)"
                            " VALUES (?, '', ?, ?, ?, ?)" " RETURNING id", (name.strip(), ts, ts, model.strip(), ts))
            project_id = int(cur.fetchone()[0])
            # маскирование при показе – решение оператора; по умолчанию выключено (слово владельца 21.11.2026):
            # колонка в базе со значением DEFAULT 1 (схема 35), поэтому значение пишется явно
            # (база старше схемы 35 – например, проверки шагов миграции – колонки ещё нет: писать нечего)
            if c.execute("SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema()"
                         " AND table_name = 'projects' AND column_name = 'mask_secrets'").fetchone():
                c.execute("UPDATE projects SET mask_secrets = ? WHERE id = ?", (1 if mask_secrets else 0, project_id))
            if after is not None:
                after(c, project_id)
            return project_id

    @staticmethod
    def set_json_entry_in(c: Any, setting: str, key: str, value: Any) -> None:
        """Одна запись словаря-настройки (значение JSON-объект) в переданной транзакции; value None – удалить запись."""
        row = c.execute("SELECT value_json FROM settings WHERE key = ?", (setting,)).fetchone()
        try:
            data = json.loads(row["value_json"]) if row is not None else {}
        except ValueError:
            data = {}
        if not isinstance(data, dict):
            data = {}
        if value is None:
            data.pop(key, None)
        else:
            data[key] = value
        c.execute("INSERT INTO settings(key, value_json, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET"
                  " value_json = excluded.value_json, updated_at = excluded.updated_at", (setting, dumps(data), now_iso()))

    def update_json_entry(self, setting: str, key: str, value: Any) -> None:
        with self._tx() as c:
            self.set_json_entry_in(c, setting, key, value)

    def restore_codebase_map(self, project_id: int, mapping: Mapping[str, str], expect: str | None = None) -> int:
        """Карта кодовых баз из связи примера – ручными соответствиями одной транзакцией; сколько отметок снято.
        expect – отпечаток страницы подтверждения (restore_fingerprint): показанные изменения и число удаляемых срезов
        сверяются в той же транзакции; не совпали – ValueError, ничего не записано (ревью сборки Б, круг 2)."""
        ts = now_iso()
        with self.source_gate(project_id), self._tx() as c:
            if expect is not None and self._restore_fingerprint_in(c, project_id, mapping) != expect:
                raise ValueError("Соответствия или сохранённые срезы изменились после страницы подтверждения.")
            return sum(self._set_codebase_folder_in(c, project_id, codebase, folder, True, ts)
                       for codebase, folder in mapping.items())

    def restore_fingerprint(self, project_id: int, mapping: Mapping[str, str]) -> str:
        with self._tx() as c:
            return self._restore_fingerprint_in(c, project_id, mapping)

    def restore_effects(self, project_id: int, mapping: Mapping[str, str]) -> dict[str, int]:
        """Что снимется при восстановлении: {cases: срезов, reviewed: отметок «Проверено»}."""
        with self._tx() as c:
            return self._restore_effects_in(c, project_id, mapping)

    def restore_preview(self, project_id: int, mapping: Mapping[str, str]) -> dict[str, Any]:
        """Страница подтверждения из одного снимка: текущие папки, последствия и отпечаток, посчитанный из этих же
        чисел (ревью сборки Б, круг 4): срез, сохранённый после показа, меняет отпечаток – POST его не удалит."""
        with self._tx() as c:
            current = {r["codebase"]: r["folder"] for r in c.execute(
                "SELECT codebase, folder FROM codebase_map WHERE project_id = ?", (project_id,)).fetchall()}
            effects = self._restore_effects_in(c, project_id, mapping)
        changing = sorted(cb for cb, folder in mapping.items() if current.get(cb) != folder)
        shown = [[cb, current.get(cb, ""), mapping[cb]] for cb in changing]
        return {"current": current, "effects": effects, "expect": self._fingerprint_of(shown, effects)}

    @staticmethod
    def _fingerprint_of(shown: list, effects: Mapping[str, int]) -> str:
        return hashlib.sha256(dumps({"changes": shown, "cases": int(effects["cases"]),
                                     "reviewed": int(effects["reviewed"])}).encode("utf-8")).hexdigest()[:32]

    @staticmethod
    def _restore_effects_in(c: Any, project_id: int, mapping: Mapping[str, str]) -> dict[str, int]:
        current = {r["codebase"]: r["folder"] for r in c.execute(
            "SELECT codebase, folder FROM codebase_map WHERE project_id = ?", (project_id,)).fetchall()}
        cases = reviewed = 0
        for cb in (cb for cb, folder in mapping.items() if current.get(cb) != folder):
            cases += int(c.execute("SELECT count(*) AS n FROM cases WHERE project_id = ? AND hub_id IN"
                                   " (SELECT hub_id FROM findings WHERE project_id = ? AND codebase = ?)",
                                   (project_id, project_id, cb)).fetchone()["n"] or 0)
            reviewed += int(c.execute("SELECT count(*) AS n FROM reviews WHERE project_id = ? AND reviewed = 1 AND hub_id IN"
                                      " (SELECT hub_id FROM findings WHERE project_id = ? AND codebase = ? AND kind = 'SAST'"
                                      " AND missing = 0)", (project_id, project_id, cb)).fetchone()["n"] or 0)
        return {"cases": cases, "reviewed": reviewed}

    @staticmethod
    def _restore_fingerprint_in(c: Any, project_id: int, mapping: Mapping[str, str]) -> str:
        """Что изменит восстановление: текущие и новые папки затронутых баз, число срезов, которые удалятся, и отметок
        «Проверено», которые снимутся."""
        current = {r["codebase"]: r["folder"] for r in c.execute(
            "SELECT codebase, folder FROM codebase_map WHERE project_id = ?", (project_id,)).fetchall()}
        changing = sorted(cb for cb, folder in mapping.items() if current.get(cb) != folder)
        cases = 0
        for cb in changing:
            row = c.execute("SELECT count(*) AS n FROM cases WHERE project_id = ? AND hub_id IN"
                            " (SELECT hub_id FROM findings WHERE project_id = ? AND codebase = ?)",
                            (project_id, project_id, cb)).fetchone()
            cases += int(row["n"] or 0)
        shown = [[cb, current.get(cb, ""), mapping[cb]] for cb in changing]
        effects = Database._restore_effects_in(c, project_id, mapping)
        return Database._fingerprint_of(shown, {"cases": cases, "reviewed": effects["reviewed"]})

    def get_project(self, project_id: int) -> dict | None:
        return self._one("SELECT * FROM projects WHERE id = ?", (project_id,))

    def list_projects(self, archived: bool | None = False) -> list[dict]:
        """Проекты по последней активности, с ходом разбора (по находкам текущей выгрузки, без пропавших из неё):
        findings, sast, reviewed и entered (SAST: проверено и внесено в Hub), sca, sca_reviewed, sca_entered,
        missing (нет в новой выгрузке), last_run_state. archived: False – действующие, True – архив, None – все."""
        where = "" if archived is None else f"WHERE p.archived = {1 if archived else 0}"
        # три простых запроса в одном снимке: единая инструкция с отметками тратила на планирование десятки миллисекунд при каждом показе
        def read(c: Connection) -> list[dict]:
            projects = c.execute(f"""
                SELECT p.*, (SELECT state FROM runs WHERE runs.project_id = p.id ORDER BY id DESC LIMIT 1) AS last_run_state
                  FROM projects p {where}
                 ORDER BY p.last_activity DESC, p.id DESC""").fetchall()
            found = {row["project_id"]: row for row in c.execute("""
                SELECT project_id,
                       COUNT(*) FILTER (WHERE missing = 0) AS findings,
                       COUNT(*) FILTER (WHERE missing = 0 AND kind = 'SAST') AS sast,
                       COUNT(*) FILTER (WHERE missing = 0 AND kind = 'SCA') AS sca,
                       COUNT(*) FILTER (WHERE missing = 1) AS missing
                  FROM findings GROUP BY project_id""").fetchall()}
            marked = {row["project_id"]: row for row in c.execute(f"""
                SELECT f.project_id,
                       COUNT(*) FILTER (WHERE f.kind = 'SAST' AND r.reviewed = 1) AS reviewed,
                       COUNT(*) FILTER (WHERE f.kind = 'SAST' AND {_ENTERED_HUB_SQL} = 1) AS entered,
                       COUNT(*) FILTER (WHERE f.kind = 'SCA' AND r.reviewed = 1) AS sca_reviewed,
                       COUNT(*) FILTER (WHERE f.kind = 'SCA' AND {_ENTERED_HUB_SQL} = 1) AS sca_entered
                  FROM reviews r
                  JOIN findings f ON f.project_id = r.project_id AND f.hub_id = r.hub_id AND f.missing = 0
                 GROUP BY f.project_id""").fetchall()}
            result = []
            for row in projects:
                one, two = found.get(row["id"]), marked.get(row["id"])
                result.append({**dict(row),
                               **{name: one[name] if one else 0 for name in ("findings", "sast", "sca", "missing")},
                               **{name: two[name] if two else 0 for name in ("reviewed", "entered", "sca_reviewed", "sca_entered")}})
            return result
        with self.snapshot():
            return self._store.read(read)

    def count_projects(self, archived: bool) -> int:
        return int(self._scalar("SELECT COUNT(*) FROM projects WHERE archived = ?", (1 if archived else 0,)) or 0)

    # ------------------------------------------------------------------ смена назначения Hub (план dev17, п. 4.5)

    def _hub_url_in(self, c) -> str:
        from app.hub_ops import hub_base
        row = c.execute("SELECT value_json FROM settings WHERE key = 'hub_url'").fetchone()
        return hub_base(str(loads(row["value_json"], "") or "")) if row is not None else ""

    def change_hub_assignment(self, project_id: int, hub_app_id: int | None, *, expect: str | None = None,
                              dry: bool = False) -> dict:
        """Смена номера приложения Hub у проекта – операция п. 4.5 одной транзакцией: решения из Hub прежнего
        назначения в архив и снимаются, сведения о библиотеках сбрасываются, переход к идентичности файла
        (package_transition.change_assignment). dry – только итог (транзакция откатывается) и отпечаток входов; expect
        – отпечаток, показанный в подтверждении: изменилось что-либо – ValueError «Итог изменился», ничего не
        записано. {"summary", "token", "affects"}; проекта нет – ValueError."""
        from app import package_transition as pt

        class _Dry(Exception):
            pass

        holder: dict = {}
        try:
            with self._tx() as c:
                row = c.execute("SELECT hub_app_id FROM projects WHERE id = ?", (project_id,)).fetchone()
                if row is None:
                    raise ValueError("Проекта нет.")
                hub_url = self._hub_url_in(c)
                old, new = pt.scope_of(hub_url, row["hub_app_id"]), pt.scope_of(hub_url, hub_app_id)
                token = pt.assignment_fingerprint(c, project_id, old, new)
                if old == new:  # назначение уже такое: перехода нет, данные действующего назначения не трогаются
                    holder.update(token=token, affects=False, unchanged=True, summary={})
                    return holder
                if expect is not None and expect != token:
                    raise ValueError("Итог изменился: откройте подтверждение смены назначения Hub заново.")
                holder.update(token=token, affects=pt.assignment_affects(c, project_id))
                holder["summary"] = pt.change_assignment(c, project_id, lambda cc: cc.execute(
                    "UPDATE projects SET hub_app_id = ?, updated_at = ? WHERE id = ?",
                    (hub_app_id, now_iso(), project_id)))
                if dry:
                    raise _Dry
        except _Dry:
            pass
        return holder

    def change_hub_url(self, value: str, *, expect: str | None = None, dry: bool = False, env_url: str = "") -> dict:
        """Смена адреса Hub в настройках – та же операция п. 4.5 для всех проектов (у проекта без номера приложения
        сведений Hub нет – для него это пустой шаг), одной транзакцией вместе с записью адреса; dry и expect – как у
        change_hub_assignment. env_url – адрес из окружения: действует, пока адреса в базе нет. Адрес тот же (по
        основе) – перехода нет, пишется только сама настройка ({"unchanged": True}). {"projects": {id: summary}, "token",
        "affects"}."""
        from app import package_transition as pt
        from app.hub_ops import hub_base

        class _Dry(Exception):
            pass

        holder: dict = {"projects": {}}
        try:
            with self._tx() as c:
                stored = c.execute("SELECT 1 FROM settings WHERE key = 'hub_url'").fetchone()
                old_url = self._hub_url_in(c) if stored is not None else hub_base(str(env_url or ""))
                new_url = hub_base(str(value or ""))
                rows = c.execute("SELECT id, hub_app_id FROM projects ORDER BY id").fetchall()
                ids = [int(r["id"]) for r in rows]
                # назначение каждого проекта целиком (адрес и номер приложения): сменили номер приложения после
                # предпросмотра – подтверждение недействительно (ревью Codex шага 4, круг 2)
                parts = [f'{int(r["id"])}:' + pt.assignment_fingerprint(
                    c, int(r["id"]), pt.scope_of(old_url, r["hub_app_id"]), pt.scope_of(new_url, r["hub_app_id"]))
                    for r in rows]
                token = __import__("hashlib").sha256("|".join(parts).encode("ascii")).hexdigest()[:32]
                unchanged = old_url == new_url
                if expect is not None and expect != token and not unchanged:
                    raise ValueError("Итог изменился: откройте подтверждение смены адреса Hub заново.")
                holder.update(token=token, unchanged=unchanged,
                              affects=not unchanged and any(pt.assignment_affects(c, pid) for pid in ids))
                if not unchanged:  # тот же адрес – данные действующего назначения не трогаются (ревью Codex, круг 2)
                    for pid in ids:
                        holder["projects"][pid] = pt.change_assignment(c, pid, lambda cc: None)
                c.execute("INSERT INTO settings(key, value_json, updated_at) VALUES ('hub_url', ?, ?)"
                          " ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json,"
                          " updated_at = excluded.updated_at", (dumps(str(value or "")), now_iso()))
                if dry:
                    raise _Dry
        except _Dry:
            pass
        return holder

    def update_project(self, project_id: int, *, name: str | None = None, model: str | None = None,
                       provider_id: int | None | bool = False,
                       research_provider_id: int | None | bool = False,
                       hub_app_id: int | None | bool = False, mask_secrets: bool | None = None) -> bool:
        """Название, модель ("" – модель из настроек), профиль модели проекта и профиль исследования компонентов
        (None – профиль по умолчанию приложения; False – не менять), номер приложения в Hub (None – убрать; False –
        не менять); name/model None – не менять; mask_secrets – показ кода с масками (None – не менять). False – проекта
        нет."""
        sets, params = [], []
        if mask_secrets is not None:
            sets.append("mask_secrets = ?")
            params.append(1 if mask_secrets else 0)
        if hub_app_id is not False:
            sets.append("hub_app_id = ?")
            params.append(None if hub_app_id is None else int(hub_app_id))
        if provider_id is not False:
            sets.append("provider_id = ?")
            params.append(None if provider_id is None else int(provider_id))
        if research_provider_id is not False:
            sets.append("research_provider_id = ?")
            params.append(None if research_provider_id is None else int(research_provider_id))
        if name is not None:
            sets.append("name = ?")
            params.append(name.strip())
        if model is not None:
            sets.append("model = ?")
            params.append(model.strip())
        if not sets:
            return self.get_project(project_id) is not None
        ts = now_iso()
        with self._tx() as c:
            changed = c.execute(f"UPDATE projects SET {', '.join(sets)}, updated_at = ?, last_activity = ?"
                                " WHERE id = ?", (*params, ts, ts, project_id)).rowcount
        return changed > 0

    def set_external_mark(self, project_id: int, reason: str) -> bool:
        """Отметка проекта «код не секретный» (ADR-0104 п. 3, К9) с обоснованием и временем подтверждения: код
        находок этого проекта может уходить внешнему провайдеру. Ревизия отметки растёт при каждой постановке и
        снятии (её подписывает метка страницы предпросмотра). False – проекта нет."""
        ts = now_iso()
        with self._tx() as c:
            changed = c.execute("UPDATE projects SET external_allowed = 1, external_reason = ?, external_confirmed_at = ?,"
                                " updated_at = ? WHERE id = ?", (" ".join(str(reason).split())[:1000], ts, ts, project_id)).rowcount
            if changed:
                self._bump_external_revision(c, project_id)
        return changed > 0

    def clear_external_mark(self, project_id: int) -> bool:
        """Снятие отметки – сразу; обоснование и время прежней отметки остаются историей (сменятся при новой).
        Вызывающий держит исключительную блокировку проекта (executors.project_gate, К2)."""
        ts = now_iso()
        with self._tx() as c:
            changed = c.execute("UPDATE projects SET external_allowed = 0, updated_at = ? WHERE id = ?",
                                (ts, project_id)).rowcount
            if changed:
                self._bump_external_revision(c, project_id)
        return changed > 0

    @classmethod
    def _clear_example_mark_in(cls, c: Any, project_id: int, ts: str) -> bool:
        """Проект из каталога учебных примеров (связь в settings, ключ examples_projects; ADR-0157): отметка «код не
        секретный» снимается в той же транзакции, что и смена источника кода – папки проекта, соответствий кодовых баз,
        импорта выгрузки. Ревизия отметки растёт: метки предпросмотра, подписанные до смены, не проходят. У прочих
        проектов ничего не меняется."""
        row = c.execute("SELECT value_json FROM settings WHERE key = 'examples_projects'").fetchone()
        try:
            links = json.loads(row["value_json"]) if row is not None else {}
        except ValueError:
            links = {}
        ids = {int(v.get("project_id") or 0) for v in (links.values() if isinstance(links, dict) else [])
               if isinstance(v, dict) and str(v.get("project_id") or "").isdigit()}
        if int(project_id) not in ids:
            return False
        changed = c.execute("UPDATE projects SET external_allowed = 0, updated_at = ? WHERE id = ? AND external_allowed = 1",
                            (ts, project_id)).rowcount
        # ревизия растёт и без стоявшей отметки: форма предпросмотра, открытая до смены источника, недействительна
        # (ревью сборки Б, круг 2)
        cls._bump_external_revision(c, project_id)
        return changed > 0

    def catalog_link(self, project_id: int) -> dict | None:
        """Запись связи проекта с каталогом примеров (settings, ключ examples_projects) или None."""
        value = self.get_settings().get("examples_projects")
        if not isinstance(value, dict):
            return None
        for record in value.values():
            if isinstance(record, dict) and str(record.get("project_id") or "") == str(project_id):
                return record
        return None

    def catalog_project(self, project_id: int) -> bool:
        """Проект связан с записью каталога учебных примеров (settings, ключ examples_projects)."""
        value = self.get_settings().get("examples_projects")
        return isinstance(value, dict) and any(isinstance(v, dict) and str(v.get("project_id") or "") == str(project_id)
                                               for v in value.values())

    def source_gate(self, project_id: int) -> Any:
        """Смена источника кода у проекта из каталога – под той же исключительной блокировкой проекта, что и ручное
        снятие отметки «код не секретный» (executors.project_gate): начатая отправка кода дописывает байты, следующая
        не проходит допуск. У прочих проектов – без блокировки, как раньше."""
        import contextlib

        if not self.catalog_project(project_id):
            return contextlib.nullcontext()
        from app.executors import project_gate
        return project_gate(project_id).write()

    @staticmethod
    def _bump_external_revision(c: Connection, project_id: int) -> None:
        key = f"external_rev:{int(project_id)}"
        row = c.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        c.execute("INSERT INTO meta(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                  (key, str(int(row["value"]) + 1 if row is not None else 1)))

    def external_mark_revision(self, project_id: int) -> int:
        """Номер ревизии отметки «код не секретный»: 0 – не ставилась; растёт при каждой постановке и снятии, поэтому
        форма предпросмотра, подписанная прежней ревизией, после любого изменения недействительна (ревью круга 5:
        одинаковое время двух постановок в одну секунду ревизию не повторяет)."""
        value = self._scalar("SELECT value FROM meta WHERE key = ?", (f"external_rev:{int(project_id)}",))
        return int(value) if value else 0

    def set_project_archived(self, project_id: int, archived: bool) -> bool:
        """Убрать проект в архив или вернуть из архива (данные не меняются). False – проекта нет."""
        ts = now_iso()
        with self._tx() as c:
            changed = c.execute("UPDATE projects SET archived = ?, archived_at = ?, updated_at = ? WHERE id = ?",
                                (1 if archived else 0, ts if archived else None, ts, project_id)).rowcount
        return changed > 0

    def delete_project(self, project_id: int) -> bool:
        """Удаляет проект со всеми его данными: выгрузками, находками, срезами кода, решениями, прогонами,
        вопросами к модели, ответами по SCA, ревизиями клонов и пояснениями. Ответы модели (verdicts) общие для
        проектов: удаляются те, на которые ссылался этот проект и больше никто не ссылается.

        Идущий прогон – ProjectBusy (сначала остановить); прогоны в очереди и на паузе удаляются вместе
        с проектом. False – проекта нет."""
        refs = ("SELECT verdict_id FROM cases WHERE verdict_id IS NOT NULL"
                " UNION SELECT verdict_id FROM run_items WHERE verdict_id IS NOT NULL"
                " UNION SELECT verdict_id FROM reviews WHERE verdict_id IS NOT NULL"
                " UNION SELECT verdict_id FROM questions WHERE verdict_id IS NOT NULL")
        with self._tx() as c:
            if c.execute("SELECT 1 FROM projects WHERE id = ?", (project_id,)).fetchone() is None:
                return False
            if c.execute("SELECT 1 FROM runs WHERE project_id = ? AND state = 'running'", (project_id,)).fetchone():
                raise ProjectBusy("У проекта идёт прогон: остановите его и дождитесь окончания текущей находки.")
            own = sorted({row[0] for row in c.execute(
                "SELECT verdict_id FROM cases WHERE project_id = ? AND verdict_id IS NOT NULL"
                " UNION SELECT ri.verdict_id FROM run_items ri JOIN runs u ON u.id = ri.run_id"
                "  WHERE u.project_id = ? AND ri.verdict_id IS NOT NULL"
                " UNION SELECT verdict_id FROM reviews WHERE project_id = ? AND verdict_id IS NOT NULL"
                " UNION SELECT verdict_id FROM questions WHERE project_id = ? AND verdict_id IS NOT NULL",
                (project_id, project_id, project_id, project_id))})
            c.execute("DELETE FROM projects WHERE id = ?", (project_id,))  # остальное – ON DELETE CASCADE
            prefix = _revision_prefix(project_id)
            detached = _detached_prefix(project_id)
            c.execute("DELETE FROM meta WHERE substr(key, 1, ?) = ? OR substr(key, 1, ?) = ? OR key IN (?, ?, ?)",
                      (len(prefix), prefix, len(detached), detached, f"notice:{int(project_id)}",
                       f"codechange:{int(project_id)}", _sca_confirmed_key(project_id)))
            for part in _chunks(own):
                marks = ",".join("?" * len(part))
                c.execute(f"DELETE FROM verdicts WHERE id IN ({marks}) AND id NOT IN ({refs})", part)
        return True

    def set_repos_dir(self, project_id: int, repos_dir: str) -> int:
        """Папка проекта внутри REPOS_ROOT. Смена папки меняет код всех кодовых баз: срезы и привязки
        к вердиктам сбрасываются (сами вердикты остаются в кэше), а у находок кодовых баз с выбранной папкой
        снимается отметка «проверено» – решение принималось по другому коду. Возвращает, у скольких снята."""
        with self.source_gate(project_id), self._tx() as c:
            return self._set_repos_dir_in(c, project_id, repos_dir, now_iso())

    @staticmethod
    def _set_repos_dir_in(c: Any, project_id: int, repos_dir: str, ts: str) -> int:
        """Тело set_repos_dir в переданной транзакции (общее с set_repos_dir_and_folder, бэклог 95)."""
        old = c.execute("SELECT repos_dir FROM projects WHERE id = ?", (project_id,)).fetchone()
        c.execute("UPDATE projects SET repos_dir = ?, updated_at = ?, last_activity = ? WHERE id = ?",
                  (repos_dir, ts, ts, project_id))
        if old is None or old["repos_dir"] == repos_dir:
            return 0
        Database._clear_example_mark_in(c, project_id, ts)
        c.execute("DELETE FROM cases WHERE project_id = ?", (project_id,))
        # ревизии и отвязка прежних клонов больше не относятся к проекту
        for prefix in (_revision_prefix(project_id), _detached_prefix(project_id)):
            c.execute("DELETE FROM meta WHERE substr(key, 1, ?) = ?", (len(prefix), prefix))
        # находки, которых нет в новой выгрузке, не считаются: вернувшись, они сверятся по версии (save_import);
        # решение по SCA от кода не зависит
        return c.execute("""
            UPDATE reviews SET reviewed = 0, reviewed_at = NULL, updated_at = ?
             WHERE project_id = ? AND reviewed = 1 AND hub_id IN (
                   SELECT f.hub_id FROM findings f
                     JOIN codebase_map m ON m.project_id = f.project_id AND m.codebase = f.codebase
                    WHERE f.project_id = ? AND f.kind = 'SAST' AND f.missing = 0 AND m.folder != '')""",
                         (ts, project_id, project_id)).rowcount

    @staticmethod
    def _clone_reset_counts_in(c: Any, project_id: int, codebase: str, repos_changed: bool) -> tuple[int, int]:
        """Что удалит set_repos_dir_and_folder (бэклог 95): (срезы, отметки «Проверено»). Смена папки проекта
        удаляет все срезы проекта и снимает «Проверено» у находок SAST кодовых баз с папкой; назначение папки
        кодовой базе – её срезы и её «Проверено». Те же условия, что у _set_repos_dir_in и _set_codebase_folder_in."""
        if repos_changed:
            cases = c.execute("SELECT COUNT(*) FROM cases WHERE project_id = ?", (project_id,)).fetchone()[0]
        else:
            cases = c.execute("SELECT COUNT(*) FROM cases WHERE project_id = ? AND hub_id IN"
                              " (SELECT hub_id FROM findings WHERE project_id = ? AND codebase = ?)",
                              (project_id, project_id, codebase)).fetchone()[0]
        reviewed = c.execute(
            "SELECT COUNT(*) FROM reviews r JOIN findings f ON f.project_id = r.project_id AND f.hub_id = r.hub_id"
            " WHERE r.project_id = ? AND r.reviewed = 1 AND f.kind = 'SAST' AND f.missing = 0 AND (f.codebase = ?"
            " OR (? = 1 AND f.codebase IN (SELECT codebase FROM codebase_map WHERE project_id = ? AND folder != '')))",
            (project_id, codebase, 1 if repos_changed else 0, project_id)).fetchone()[0]
        return int(cases), int(reviewed)

    def clone_reset_counts(self, project_id: int, codebase: str, repos_dir: str) -> tuple[int, int]:
        """Цена назначения клона для показа: (срезы, отметки «Проверено»), repos_dir – новая папка проекта."""
        with self._tx() as c:
            old = c.execute("SELECT repos_dir FROM projects WHERE id = ?", (project_id,)).fetchone()
            changed = old is not None and (old["repos_dir"] or "") != (repos_dir or "")
            return self._clone_reset_counts_in(c, project_id, codebase, changed)

    def set_repos_dir_and_folder(self, project_id: int, repos_dir: str, codebase: str, folder: str,
                                 expect_repos_dir: str, expect_counts: tuple[int, int] | None = None) -> int:
        """Папка проекта и клон кодовой базы одной транзакцией (бэклог 95: открыт клон одной кодовой базы – папка выше
        становится папкой проекта, этот клон – папкой кодовой базы). Прежнее состояние проверяется: папка проекта –
        expect_repos_dir, у кодовой базы папки нет; иначе ValueError и ничего не меняется. Последствия – как у
        set_repos_dir и set_codebase_folder (manual = 1); ошибка любой записи откатывает обе. Возвращает, у скольких
        находок снято «Проверено»."""
        ts = now_iso()
        with self.source_gate(project_id), self._tx() as c:
            old = c.execute("SELECT repos_dir FROM projects WHERE id = ?", (project_id,)).fetchone()
            if old is None or (old["repos_dir"] or "") != (expect_repos_dir or ""):
                raise ValueError("Папка проекта изменилась после открытия страницы: откройте её заново.")
            mapped = c.execute("SELECT folder FROM codebase_map WHERE project_id = ? AND codebase = ?",
                               (project_id, codebase)).fetchone()
            if mapped is not None and (mapped["folder"] or ""):
                raise ValueError("У кодовой базы уже выбрана папка: откройте страницу заново.")
            # показанная и подтверждённая цена (ревью Kimi, выпуск dev18): изменилась – ничего не удаляется
            changed = (old["repos_dir"] or "") != (repos_dir or "")
            if expect_counts is not None and self._clone_reset_counts_in(c, project_id, codebase, changed) \
                    != tuple(expect_counts):
                raise ValueError("Срезы или отметки «Проверено» изменились после предупреждения: откройте страницу "
                                 "заново и подтвердите снова.")
            reopened = self._set_repos_dir_in(c, project_id, repos_dir, ts)
            reopened += self._set_codebase_folder_in(c, project_id, codebase, folder, True, ts)
            return reopened

    # ------------------------------------------------------------------ ревизии клонов

    def revisions(self, project_id: int) -> dict[str, str]:
        """Последние увиденные ревизии клонов: {кодовая база: ревизия} ("" – папка не клон git)."""
        prefix = _revision_prefix(project_id)
        rows = self._all("SELECT key, value FROM meta WHERE substr(key, 1, ?) = ?", (len(prefix), prefix))
        return {row["key"][len(prefix):]: row["value"] for row in rows}

    def sync_revisions(self, project_id: int, observed: dict[str, str]) -> dict:
        """Сверяет ревизии клонов с сохранёнными. observed – {кодовая база: ревизия} для кодовых баз, папка которых
        сейчас на месте ("" – папка не клон git). Первая ревизия кодовой базы просто запоминается. Если ревизия
        сменилась (git pull, другая ветка, другая папка REPOS_ROOT с теми же именами), код под решениями другой:
        срезы и привязки к вердиктам находок этой кодовой базы удаляются (вердикты остаются в кэше), у проверенных
        находок снимается отметка «проверено», для страницы проекта сохраняется пояснение.
        Возвращает {"changed": [кодовые базы], "reopened": сколько отметок снято}."""
        ts = now_iso()
        prefix = _revision_prefix(project_id)
        changed: list[str] = []
        reopened = 0
        with self._tx() as c:
            stored = {row["key"][len(prefix):]: row["value"] for row in c.execute(
                "SELECT key, value FROM meta WHERE substr(key, 1, ?) = ?", (len(prefix), prefix))}
            for codebase, revision in sorted(observed.items()):
                revision = str(revision or "")
                if codebase not in stored:
                    c.execute("INSERT INTO meta(key, value) VALUES (?, ?)", (prefix + codebase, revision))
                    continue
                if stored[codebase] == revision:
                    continue
                if stored[codebase] and not revision:
                    # Клон был git, а ревизии теперь нет: удалена .git или клон удалён не целиком. Это потеря клона,
                    # а не новый код – срезы в базе не сбрасываются (ADR-0072); правки кода по-прежнему видны по
                    # отпечатку среза
                    continue
                c.execute("UPDATE meta SET value = ? WHERE key = ?", (revision, prefix + codebase))
                changed.append(codebase)
                c.execute("DELETE FROM cases WHERE project_id = ? AND hub_id IN"
                          " (SELECT hub_id FROM findings WHERE project_id = ? AND codebase = ?)",
                          (project_id, project_id, codebase))
                reopened += c.execute("UPDATE reviews SET reviewed = 0, reviewed_at = NULL, updated_at = ?"
                                      " WHERE project_id = ? AND reviewed = 1 AND hub_id IN"
                                      " (SELECT hub_id FROM findings WHERE project_id = ? AND codebase = ?"
                                      " AND kind = 'SAST' AND missing = 0)",
                                      (ts, project_id, project_id, codebase)).rowcount
            if changed:
                key = f"notice:{int(project_id)}"
                row = c.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
                notice = loads(row["value"], {}) if row is not None else {}
                notice = {"codebases": sorted(set(notice.get("codebases") or []) | set(changed)),
                          "reopened": int(notice.get("reopened") or 0) + reopened, "at": ts}
                c.execute("INSERT INTO meta(key, value) VALUES (?, ?)"
                          " ON CONFLICT(key) DO UPDATE SET value = excluded.value", (key, dumps(notice)))
        return {"changed": changed, "reopened": reopened}

    def revision_notice(self, project_id: int) -> dict | None:
        """Пояснение о сменившихся ревизиях клонов для страницы проекта: {codebases, reopened, at} или None."""
        value = self._scalar("SELECT value FROM meta WHERE key = ?", (f"notice:{int(project_id)}",))
        return loads(value, None) if value else None

    def sca_confirmed(self, project_id: int) -> set[str]:
        """Сомнительные имена библиотек (sca.doubt_key), которые человек подтвердил для пакета внешним агентам."""
        value = loads(self._scalar("SELECT value FROM meta WHERE key = ?", (_sca_confirmed_key(project_id),)), [])
        return {str(x) for x in value} if isinstance(value, list) else set()

    def set_sca_confirmed(self, project_id: int, keys: Iterable[str]) -> None:
        """Запоминает подтверждённые человеком сомнительные имена (пустой список – подтверждений нет)."""
        keys = sorted({str(k) for k in keys if str(k)})
        with self._tx() as c:
            if keys:
                c.execute("INSERT INTO meta(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value ="
                          " excluded.value", (_sca_confirmed_key(project_id), dumps(keys)))
            else:
                c.execute("DELETE FROM meta WHERE key = ?", (_sca_confirmed_key(project_id),))

    def clear_revision_notice(self, project_id: int) -> None:
        """Снимает пояснения о сменившихся ревизиях клонов и об изменившемся коде. Пояснение о коде не удаляется, а
        снимается с сохранением номера редакции (как «Понятно»): следующее пояснение продолжает номер, и устаревшая
        вкладка его не снимет (ревью Codex ветки долга, круг 4)."""
        key = f"codechange:{int(project_id)}"
        with self._tx() as c:
            c.execute("DELETE FROM meta WHERE key = ?", (f"notice:{int(project_id)}",))
            row = c.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
            if row is not None:
                rev = int((loads(row["value"], {}) or {}).get("rev") or 0)
                c.execute("UPDATE meta SET value = ? WHERE key = ?", (dumps({"cleared": True, "rev": rev}), key))

    # ------------------------------------------------------------------ выгрузки и находки

    def save_import(self, project_id: int, filename: str, fmt: str, sheets: list[dict], summary: dict,
                    warnings: list[str], rows: Iterable[dict],
                    after: Callable[[Any, int], None] | None = None) -> dict:
        """Сохраняет выгрузку: её находки становятся текущими находками проекта.

        rows – словари {hub_id, pos, kind, severity, cvss, urgent, codebase, group_key, data}; data – поля
        Finding. Находки с прежним ID обновляются на месте (их номер в базе не меняется), решения и отметки
        человека сохраняются. Находки, которых нет в новой выгрузке, не удаляются: они помечаются missing («нет
        в новой выгрузке», missing_since – с какой загрузки) и встают после найденных в прежнем порядке; вернувшаяся
        в выгрузку находка снова становится обычной. Если изменились поля, от которых зависит срез кода
        (CASE_KEYS), привязка к вердикту сбрасывается. Отметка «проверено» снимается у каждой находки, версия
        которой (поля находки и папка с её кодом) отличается от той, по которой принималось решение, – в том числе
        у находки, которая пропадала из выгрузки и вернулась другой или в другую папку клона (reopened).

        Итог: {import_id, total, new, updated, unchanged, removed (пропали в этой загрузке), returned (вернулись),
        missing (всего нет в выгрузке), reopened}.
        """
        ts = now_iso()
        stats = {"new": 0, "updated": 0, "unchanged": 0, "removed": 0, "returned": 0, "missing": 0, "reopened": 0}
        with self.source_gate(project_id), self._tx() as c:
            self._clear_example_mark_in(c, project_id, now_iso())
            import_id = int(c.execute(
                "INSERT INTO imports(project_id, filename, format, sheets_json, summary_json, warnings_json,"
                " created_at) VALUES (?, ?, ?, ?, ?, ?, ?)" " RETURNING id",
                (project_id, filename, fmt, dumps(sheets), dumps(summary), dumps(warnings), ts)).fetchone()[0])
            existing, packages = {}, {}
            for row in c.execute("SELECT hub_id, data_json, pkg_ecosystem, pkg_name, pkg_source, pkg_note, pkg_scope"
                                 " FROM findings WHERE project_id = ?", (project_id,)):
                existing[row["hub_id"]] = row["data_json"]
                # идентичность пакета не вычисляется и не меняется импортом (план dev17, п. 4.4): сохранённые
                # колонки входят в подписи обеих сторон
                packages[row["hub_id"]] = package_identity.package_of_row(dict(row))
            was_missing = {row["hub_id"] for row in
                           c.execute("SELECT hub_id FROM findings WHERE project_id = ? AND missing = 1", (project_id,))}
            reviewed = {row["hub_id"]: row["finding_sig"] for row in
                        c.execute("SELECT hub_id, finding_sig FROM reviews WHERE project_id = ? AND reviewed = 1",
                                  (project_id,))}
            project = c.execute("SELECT repos_dir FROM projects WHERE id = ?", (project_id,)).fetchone()
            repos_dir = project["repos_dir"] if project is not None else ""
            folders = {row["codebase"]: row["folder"] for row in
                       c.execute("SELECT codebase, folder FROM codebase_map WHERE project_id = ?", (project_id,))}
            prefix = _revision_prefix(project_id)
            revisions = {row["key"][len(prefix):]: row["value"] for row in c.execute(
                "SELECT key, value FROM meta WHERE substr(key, 1, ?) = ?", (len(prefix), prefix))}
            seen: set[str] = set()
            max_pos = -1
            for row in rows:
                hub_id = str(row["hub_id"])
                if hub_id in seen:
                    continue
                seen.add(hub_id)
                max_pos = max(max_pos, int(row["pos"]))
                data = row["data"]
                signature = case_signature(data)
                codebase = str(data.get("codebase") or "")
                effective = {**data, "package": packages.get(hub_id) or {}}  # подпись – по эффективным данным
                current = review_signature(effective, repos_dir, folders.get(codebase, ""), revisions.get(codebase, ""))
                if hub_id in reviewed and reviewed[hub_id] != current:
                    stats["reopened"] += c.execute(
                        "UPDATE reviews SET reviewed = 0, reviewed_at = NULL, updated_at = ?"
                        " WHERE project_id = ? AND hub_id = ?", (ts, project_id, hub_id)).rowcount
                values = (import_id, int(row["pos"]), row["kind"], row.get("severity") or "", row.get("cvss"),
                          1 if row.get("urgent") else 0, row.get("codebase") or "", row.get("group_key") or "",
                          dumps(data), *_group2_columns(data))
                if hub_id in existing:
                    old = loads(existing[hub_id], {})
                    if str(old.get("kind") or "").startswith("SCA") and not str(row["kind"]).startswith("SCA"):
                        c.execute("UPDATE reviews SET kapo_state = '' WHERE project_id = ? AND hub_id = ?",
                                  (project_id, hub_id))
                    pkg = packages.get(hub_id) or {}
                    if review_signature({**old, "package": pkg}) == review_signature({**data, "package": pkg}):
                        stats["unchanged"] += 1
                    else:
                        stats["updated"] += 1
                        if case_signature(old) != signature:
                            c.execute("DELETE FROM cases WHERE project_id = ? AND hub_id = ?", (project_id, hub_id))
                    if hub_id in was_missing:
                        stats["returned"] += 1
                    c.execute("UPDATE findings SET import_id = ?, pos = ?, kind = ?, severity = ?, cvss = ?,"
                              " urgent = ?, codebase = ?, group_key = ?, data_json = ?, group_key2 = ?, g2_cat = ?,"
                              " g2_file = ?, g2_line = ?, missing = 0,"
                              " missing_since = NULL WHERE project_id = ? AND hub_id = ?",
                              (*values, project_id, hub_id))
                else:
                    stats["new"] += 1
                    c.execute("INSERT INTO findings(import_id, pos, kind, severity, cvss, urgent, codebase,"
                              " group_key, data_json, group_key2, g2_cat, g2_file, g2_line, project_id, hub_id)"
                              " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                              (*values, project_id, hub_id))
            # Нет в новой выгрузке: находка остаётся с пометкой, после найденных, в прежнем порядке
            gone = [row["hub_id"] for row in c.execute(
                "SELECT hub_id FROM findings WHERE project_id = ? AND import_id != ? ORDER BY missing, pos, id",
                (project_id, import_id))]
            stats["removed"] = sum(1 for hub_id in gone if hub_id not in was_missing)
            stats["missing"] = len(gone)
            for offset, hub_id in enumerate(gone, start=1):
                c.execute("UPDATE findings SET missing = 1, missing_since = COALESCE(missing_since, ?), pos = ?"
                          " WHERE project_id = ? AND hub_id = ?", (ts, max_pos + offset, project_id, hub_id))
            c.execute("UPDATE imports SET total = ?, stats_json = ? WHERE id = ?", (len(seen), dumps(stats), import_id))
            c.execute("UPDATE findings SET file_checked_import_id=?,"
                      " file_import_id=CASE WHEN import_id=? THEN import_id ELSE file_import_id END,"
                      " file_presence=CASE WHEN missing=1 THEN 'absent' ELSE 'present' END,"
                      " file_missing_since=missing_since,file_data_json=CASE WHEN import_id=? THEN data_json"
                      " ELSE file_data_json END WHERE project_id=?",
                      (import_id, import_id, import_id, project_id))
            from app.hub_pull import overlay_file_import
            overlay_file_import(c, project_id)
            c.execute("UPDATE projects SET updated_at = ?, last_activity = ? WHERE id = ?", (ts, ts, project_id))
            if after is not None:  # номер импорта – в той же транзакции (связь проекта из каталога, ADR-0156)
                after(c, import_id)
        return {"import_id": import_id, "total": len(seen), **stats}

    def hub_ids(self, project_id: int) -> set[str]:
        """ID находок Hub в проекте (и тех, которых нет в последней выгрузке)."""
        return {str(row["hub_id"]) for row in
                self._all("SELECT hub_id FROM findings WHERE project_id = ?", (project_id,))}

    def latest_import(self, project_id: int) -> dict | None:
        row = self._one("SELECT * FROM imports WHERE project_id = ? AND source_kind='file' ORDER BY id DESC LIMIT 1", (project_id,))
        if row is None:
            return None
        row["sheets"] = loads(row.pop("sheets_json"), [])
        row["summary"] = loads(row.pop("summary_json"), {})
        row["warnings"] = loads(row.pop("warnings_json"), [])
        row["stats"] = loads(row.pop("stats_json"), {})
        return row

    @staticmethod
    def _finding_row(row: dict) -> dict:
        row["data"] = loads(row.pop("data_json"), {})
        # эффективная идентичность пакета SCA (план dev17, п. 4.3): выборка с колонками pkg_* кладёт их в data["package"]
        if "pkg_source" in row:
            row["data"]["package"] = package_identity.package_of_row(row)
        return row

    def get_finding(self, project_id: int, finding_id: int) -> dict | None:
        row = self._one("SELECT * FROM findings WHERE project_id = ? AND id = ?", (project_id, finding_id))
        return self._finding_row(row) if row else None

    def imports_meta(self, ids: Iterable[int]) -> dict[int, dict]:
        """Сведения о выгрузках {id: {filename, created_at}} – подпись области в тексте дефекта."""
        wanted = sorted({int(i) for i in ids if i is not None})
        result: dict[int, dict] = {}
        with self._lock:
            for part in _chunks(wanted):
                marks = ",".join("?" * len(part))
                for r in self._conn.execute(f"SELECT id, filename, created_at FROM imports WHERE id IN ({marks})", part):
                    result[int(r["id"])] = {"filename": r["filename"], "created_at": r["created_at"]}
        return result

    def get_finding_by_hub_id(self, project_id: int, hub_id: str) -> dict | None:
        row = self._one("SELECT * FROM findings WHERE project_id = ? AND hub_id = ?", (project_id, hub_id))
        return self._finding_row(row) if row else None

    def finding_refs(self, project_id: int, hub_ids) -> dict[str, dict]:
        """{hub_id: {id, kind}} находок проекта с этими номерами – одним запросом на пачку, без данных находок
        (адреса карточек на странице дефектов, бэклог 123). Номера, которых нет, в ответ не входят."""
        wanted = sorted({str(h) for h in hub_ids if str(h or "")})
        refs: dict[str, dict] = {}
        for start in range(0, len(wanted), 500):
            part = wanted[start:start + 500]
            for r in self._all(f"SELECT id, hub_id, kind FROM findings WHERE project_id = ? AND hub_id IN "
                               f"({','.join('?' * len(part))})", (project_id, *part)):
                refs[str(r["hub_id"])] = {"id": int(r["id"]), "kind": str(r["kind"])}
        return refs

    def count_findings(self, project_id: int) -> dict:
        """Находки текущей выгрузки по видам; missing – сколько находок нет в новой выгрузке (в счёт не входят)."""
        row = self._one("""
            SELECT COUNT(*) FILTER (WHERE missing = 0) AS total,
                   COUNT(*) FILTER (WHERE missing = 0 AND kind = 'SAST') AS sast,
                   COUNT(*) FILTER (WHERE missing = 0 AND kind = 'SAST' AND urgent = 1) AS sast_urgent,
                   COUNT(*) FILTER (WHERE missing = 0 AND kind LIKE 'SCA%') AS sca,
                   COUNT(*) FILTER (WHERE missing = 0 AND kind = 'SCA-license') AS sca_license,
                   COUNT(*) FILTER (WHERE missing = 0 AND kind = 'SCA' AND urgent = 1) AS sca_urgent,
                   COUNT(*) FILTER (WHERE missing = 0 AND kind = 'DAST') AS dast,
                   COUNT(*) FILTER (WHERE missing = 1) AS missing
              FROM findings WHERE project_id = ?""", (project_id,))
        counts = row or {"total": 0, "sast": 0, "sast_urgent": 0, "sca": 0, "sca_license": 0, "sca_urgent": 0,
                         "dast": 0, "missing": 0}
        counts["defects"] = self.hub_defect_count(project_id)  # число на вкладке «Дефекты» (ADR-0120)
        return counts

    def findings_data(self, project_id: int, kinds: Iterable[str] | None = None,
                      include_missing: bool = False) -> list[dict]:
        """Находки проекта в порядке разбора: [{id, hub_id, pos, kind, missing, data}] – например, чтобы заново
        упорядочить их после смены порога срочности (triage.reorder_project)."""
        sql = ("SELECT id, hub_id, pos, kind, missing, data_json, pkg_ecosystem, pkg_name, pkg_source, pkg_note,"
               " pkg_scope FROM findings WHERE project_id = ?")
        params: list[Any] = [project_id]
        if not include_missing:
            sql += " AND missing = 0"
        if kinds is not None:
            kinds = list(kinds)
            sql += f" AND kind IN ({','.join('?' * len(kinds))})"
            params += kinds
        return [self._finding_row(row) for row in self._all(sql + " ORDER BY pos, id", params)]

    def reorder_findings(self, project_id: int, rows: Iterable[dict]) -> int:
        """Новый порядок разбора находок проекта: rows – {hub_id, pos, urgent, group_key} (triage.order_findings).
        Находки, которых нет в rows (в том числе пропавшие из выгрузки), встают после, в прежнем порядке.
        Возвращает, у скольких находок изменились порядок или срочность."""
        rows = list(rows)
        changed = 0
        with self._tx() as c:
            listed = set()
            for row in rows:
                hub_id = str(row["hub_id"])
                listed.add(hub_id)
                changed += c.execute(
                    "UPDATE findings SET pos = ?, urgent = ?, group_key = ? WHERE project_id = ? AND hub_id = ?"
                    " AND (pos != ? OR urgent != ? OR group_key != ?)",
                    (int(row["pos"]), 1 if row.get("urgent") else 0, row.get("group_key") or "", project_id, hub_id,
                     int(row["pos"]), 1 if row.get("urgent") else 0, row.get("group_key") or "")).rowcount
                # ключ второй редакции и подсказка (ADR-0095) – по данным, которые сейчас в базе: импорт, успевший
                # между чтением находок и этой транзакцией, не получит ключ от прежних данных
                now = c.execute("SELECT data_json FROM findings WHERE project_id = ? AND hub_id = ?",
                                (project_id, hub_id)).fetchone()
                if now is not None:
                    c.execute("UPDATE findings SET group_key2 = ?, g2_cat = ?, g2_file = ?, g2_line = ?"
                              " WHERE project_id = ? AND hub_id = ?",
                              (*_group2_columns(loads(now["data_json"], None)), project_id, hub_id))
            last = max((int(row["pos"]) for row in rows), default=-1)
            rest = [r["hub_id"] for r in c.execute("SELECT hub_id FROM findings WHERE project_id = ?"
                                                   " ORDER BY missing, pos, id", (project_id,))
                    if r["hub_id"] not in listed]
            for offset, hub_id in enumerate(rest, start=1):
                changed += c.execute("UPDATE findings SET pos = ? WHERE project_id = ? AND hub_id = ? AND pos != ?",
                                     (last + offset, project_id, hub_id, last + offset)).rowcount
        return changed

    _LIST_FROM = """
          FROM findings f
          LEFT JOIN cases c ON c.project_id = f.project_id AND c.hub_id = f.hub_id
          LEFT JOIN verdicts v ON v.id = c.verdict_id
          LEFT JOIN reviews r ON r.project_id = f.project_id AND r.hub_id = f.hub_id"""
    # Признаки попытки повлиять на разбор и состояние среза хранятся в срезе находки (cases.context_json).
    _STEERING_SQL = ("(COALESCE(json_len(c.context_json::json -> 'steering_lines'), 0)"
                     " + COALESCE(json_len(c.context_json::json -> 'steering_fields'), 0) > 0)")

    @classmethod
    def _filter_sql(cls, project_id: int, filters: dict[str, Any]) -> tuple[str, list[Any]]:
        """Условие WHERE для отбора находок (FROM _LIST_FROM). filters: kind, verdict (вердикт модели, none или any),
        decision (решение или none), reviewed (yes/no), codebase (None – любая), urgent, steering (есть текст,
        похожий на указания для модели), copied (no – проверена, но текст в Hub не скопирован), entered (yes/no –
        отметка «Внесено в Hub»), missing (yes – только находки, которых нет в новой выгрузке, no – только
        текущие, пусто – все), run_error (1 – у находки ошибка в последнем прогоне проекта), hub_status (статус
        Hub по последней принятой версии; строка или кортеж – любое из значений), hub_live (живые в Hub),
        hub_model_diff (Hub и модель разошлись), no_code (срез без кода в клоне)."""
        where = ["f.project_id = ?"]
        params: list[Any] = [project_id]
        kind, verdict, decision = filters.get("kind") or "", filters.get("verdict") or "", filters.get("decision") or ""
        if kind:
            where.append("f.kind = ?")
            params.append(kind)
        if verdict == "none":
            where.append("v.id IS NULL")
        elif verdict == "any":
            where.append("v.id IS NOT NULL")
        elif verdict:
            where.append("v.verdict = ?")
            params.append(verdict)
        if decision == "none":
            where.append("COALESCE(r.decision, '') = ''")
        elif decision:
            where.append("r.decision = ?")
            params.append(decision)
        if filters.get("reviewed") == "yes":
            where.append("COALESCE(r.reviewed, 0) = 1")
        elif filters.get("reviewed") == "no":
            where.append("COALESCE(r.reviewed, 0) = 0")
        if filters.get("codebase") is not None:
            where.append("f.codebase = ?")
            params.append(filters["codebase"])
        if filters.get("urgent"):
            where.append("f.urgent = 1")
        if filters.get("steering"):
            where.append(cls._STEERING_SQL)
        if filters.get("copied") == "no":
            where.append("COALESCE(r.reviewed, 0) = 1 AND r.copied_at IS NULL")
        if filters.get("dropped"):
            where.append("COALESCE(r.defect_dropped, '') <> ''")
        if filters.get("entered") == "yes":
            where.append(f"{_ENTERED_HUB_SQL} = 1")
        elif filters.get("entered") == "no":
            where.append(f"{_ENTERED_HUB_SQL} = 0")
        if filters.get("missing") == "yes":
            where.append("f.missing = 1")
        elif filters.get("missing") == "no":
            where.append("f.missing = 0")
        if filters.get("group") is not None:
            # группа SAST находки с этим id по ключу второй редакции (ADR-0095); пустой ключ группы не образует
            where.append("f.kind = 'SAST' AND f.group_key2 <> '' AND f.group_key2 = (SELECT g.group_key2 FROM findings g"
                         " WHERE g.project_id = f.project_id AND g.id = ? AND g.kind = 'SAST')")
            params.append(int(filters["group"]))
        statuses = filters.get("hub_status")
        if isinstance(statuses, str):
            statuses = (statuses,) if statuses else ()
        if statuses:  # несколько значений – любое из них (бэклог 99)
            where.append(f"{_CURRENT_HUB_STATUS_SQL} IN ({','.join('?' * len(statuses))})")
            params.extend(statuses)
        if filters.get("hub_live"):  # живые в Hub: не Fixed и не статус решения (бэклог 99, 104)
            where.append(f"NOT {closed_status_sql()}")
        if filters.get("hub_model_diff"):  # Hub и модель разошлись (бэклог 102)
            where.append(_HUB_MODEL_DIFF_SQL)
        if filters.get("no_code"):  # без кода в клоне (бэклог 103)
            where.append(_NO_CODE_SQL)
        if filters.get("run_error"):
            # Последний прогон проекта – наибольший номер; состояние прогона не важно: ошибки уже записаны.
            where.append("EXISTS (SELECT 1 FROM run_items ri JOIN runs ru ON ru.id = ri.run_id"
                         " WHERE ru.project_id = f.project_id AND ri.hub_id = f.hub_id AND ri.state = 'error'"
                         " AND ru.id = (SELECT MAX(id) FROM runs WHERE project_id = f.project_id))")
        return " AND ".join(where), params

    def list_findings(self, project_id: int, *, kind: str = "", verdict: str = "", decision: str = "",
                      reviewed: str = "", codebase: str | None = None, urgent: bool = False, steering: bool = False,
                      copied: str = "", entered: str = "", missing: str = "", limit: int = 200,
                      offset: int = 0, ids: tuple[int, ...] | None = None) -> tuple[list[dict], int]:
        """Находки проекта в порядке разбора с вердиктом модели и решением человека; (строки, всего).
        У строки есть ctx_status (состояние среза, который видела модель), steering (1 – в коде или сведениях
        находки есть текст, похожий на указания для модели), отметки reviewed/reviewed_at, copied_at,
        entered_hub/entered_hub_at и missing/missing_since (нет в новой выгрузке; такие находки – в конце)."""
        cond, params = self._filter_sql(project_id, {
            "kind": kind, "verdict": verdict, "decision": decision, "reviewed": reviewed, "codebase": codebase,
            "urgent": urgent, "steering": steering, "copied": copied, "entered": entered, "missing": missing})
        if ids is not None:
            if not ids:
                return [], 0
            cond += " AND f.id IN (" + ",".join("?" for _ in ids) + ")"
            params = [*params, *ids]
        total = int(self._scalar(f"SELECT COUNT(*) {self._LIST_FROM} WHERE {cond}", params) or 0)
        rows = self._all(f"""
            SELECT f.id, f.hub_id, f.pos, f.kind, f.severity, f.cvss, f.urgent, f.codebase, f.data_json,
                   f.missing, f.missing_since, f.pkg_ecosystem, f.pkg_name, f.pkg_source, f.pkg_note, f.pkg_scope,
                   v.verdict AS model_verdict, v.confidence AS model_confidence, v.model AS model_name,
                   r.decision, r.final_verdict, COALESCE(r.reviewed, 0) AS reviewed, r.reviewed_at, r.copied_at,
                   {_ENTERED_HUB_SQL} AS entered_hub, r.entered_hub_at,
                   CASE WHEN COALESCE(r.defect_dropped, '') <> '' THEN 1 ELSE 0 END AS defect_dropped,
                   (c.context_json::json ->> 'status') AS ctx_status,
                   (c.context_json::json ->> 'reason') AS ctx_reason, (c.context_json::json ->> 'file') AS ctx_file,
                   json_len(c.context_json::json -> 'lines') AS ctx_lines,
                   CASE WHEN c.context_json IS NOT NULL AND {self._STEERING_SQL} THEN 1 ELSE 0 END AS steering
              {self._LIST_FROM}
             WHERE {cond}
             ORDER BY f.pos, f.id
             LIMIT ? OFFSET ?""", [*params, int(limit), int(offset)])
        return [self._finding_row(row) for row in rows], total

    def finding_descriptors(self, project_id: int, filters: dict) -> list[dict]:
        """Лёгкие поля для групп и сортировки: полный JSON читается только у строк показанной страницы."""
        cond, params = self._filter_sql(project_id, filters)
        fields = ("rule", "tool", "component", "version", "build_type", "extra", "cwe")
        projection = ",".join(f"'{key}',f.data_json::json -> '{key}'" for key in fields)
        return [self._finding_row(row) for row in self._all(f"""
            SELECT f.id, f.kind, f.cvss, f.severity, f.pos, f.hub_id, r.decision, r.final_verdict, f.codebase,
                   f.missing, COALESCE(r.reviewed,0) AS reviewed, {_ENTERED_HUB_SQL} AS entered_hub, f.pkg_ecosystem, f.pkg_name, f.pkg_source, f.pkg_note, f.pkg_scope,
                   json_build_object({projection}) AS data_json
              {self._LIST_FROM} WHERE {cond} ORDER BY f.pos, f.id""", params)]

    def import_count(self, project_id: int) -> int:
        return int(self._scalar("SELECT COUNT(*) FROM imports WHERE project_id = ?", (project_id,)) or 0)

    def finding_statuses(self, project_id: int) -> list[str]:
        """Статусы Hub для отбора списка находок: из выгрузки, принятой сверки и выполненных записей текущего Hub и приложения, без пустых,
        по алфавиту. Считается без действующего статуса каждой находки: список открывается часто, а статус из выгрузки может уже ни у кого
        не действовать (такой отбор просто пуст). Сам отбор – по действующему статусу, _CURRENT_HUB_STATUS_SQL."""
        target = ("hub_url = (SELECT hub_base(COALESCE((SELECT value_json::json #>> '{}' FROM settings WHERE key = 'hub_url'), '')))"
                  " AND app_id = (SELECT hub_app_id FROM projects WHERE id = ?)")
        return [row["status"] for row in self._all(
            "SELECT DISTINCT status FROM ("
            " SELECT data_json::json ->> 'status' AS status FROM findings WHERE project_id = ?"
            " UNION ALL SELECT confirmed_json::json #>> '{detail,status}' FROM hub_issue_states"
            f" WHERE project_id = ? AND confirmed_presence = 'present' AND {target}"
            " UNION ALL SELECT request_json::json -> 'body' ->> 'status' FROM hub_ops"
            f" WHERE project_id = ? AND purpose = 'status' AND state = 'done' AND {target}"
            ") known WHERE COALESCE(status, '') <> '' ORDER BY status",
            (project_id, project_id, project_id, project_id, project_id))]

    def codebase_counts(self, project_id: int) -> list[dict]:
        """Кодовые базы находок текущей выгрузки (без пропавших из неё) с числом находок по видам."""
        return self._all("""
            SELECT codebase, COUNT(*) AS total,
                   COUNT(*) FILTER (WHERE kind = 'SAST') AS sast,
                   COUNT(*) FILTER (WHERE kind LIKE 'SCA%') AS sca,
                   COUNT(*) FILTER (WHERE kind = 'DAST') AS dast
              FROM findings WHERE project_id = ? AND missing = 0
             GROUP BY codebase
             ORDER BY sast DESC, total DESC, codebase""", (project_id,))

    def neighbor_unreviewed(self, project_id: int, pos: int, direction: str = "next",
                            kinds: tuple[str, ...] = ("SAST",), filters: dict[str, Any] | None = None,
                            only_unreviewed: bool = True, wrap: bool = True, hub_ids=None) -> int | None:
        """Ближайшая непроверенная находка после (или до) позиции pos; по кругу, если wrap. filters – отбор списка
        находок (см. _filter_sql), в котором идёт обход; only_unreviewed=False – по всем находкам отбора как есть
        (например, проверенным, но не скопированным в Hub). Находки, которых нет в новой выгрузке, обходятся,
        только если отбор задаёт missing явно. None – таких находок нет."""
        if only_unreviewed:
            selection = {k: v for k, v in (filters or {}).items() if k not in ("reviewed", "copied", "entered")}
            selection["reviewed"] = "no"
        else:
            selection = dict(filters or {})
        if not selection.get("missing"):
            selection["missing"] = "no"
        cond, params = self._filter_sql(project_id, selection)
        marks = ",".join("?" * len(kinds))
        base = f"SELECT f.id {self._LIST_FROM} WHERE {cond} AND f.kind IN ({marks})"
        chosen: tuple = ()
        if hub_ids is not None:  # отбор «Синхронизация с Hub» списка (dev15): обход внутри него
            if not hub_ids:
                return None
            chosen = tuple(sorted(str(h) for h in hub_ids))
            base += f" AND f.hub_id IN ({','.join('?' * len(chosen))})"
        if direction == "prev":
            first = f"{base} AND f.pos < ? ORDER BY f.pos DESC LIMIT 1"
            wrap_sql = f"{base} AND f.pos > ? ORDER BY f.pos DESC LIMIT 1"
        else:
            first = f"{base} AND f.pos > ? ORDER BY f.pos ASC LIMIT 1"
            wrap_sql = f"{base} AND f.pos < ? ORDER BY f.pos ASC LIMIT 1"
        for sql in (first, wrap_sql) if wrap else (first,):
            found = self._scalar(sql, (*params, *kinds, *chosen, pos))
            if found is not None:
                return int(found)
        return None

    def count_unreviewed(self, project_id: int, filters: dict[str, Any] | None = None) -> tuple[int, int]:
        """(всего SAST в отборе, из них проверено) – для счётчика «Проверено N из M» в карточке. Находки, которых
        нет в новой выгрузке, не считаются, если отбор не задаёт missing явно."""
        selection = {k: v for k, v in (filters or {}).items() if k not in ("reviewed", "copied", "entered")}
        if not selection.get("missing"):
            selection["missing"] = "no"
        cond, params = self._filter_sql(project_id, {**selection, "kind": "SAST"})
        row = self._one(f"SELECT COUNT(*) AS total, COUNT(*) FILTER (WHERE COALESCE(r.reviewed, 0) = 1) AS reviewed"
                        f" {self._LIST_FROM} WHERE {cond}", params)
        return (int(row["total"] or 0), int(row["reviewed"] or 0)) if row else (0, 0)

    def sast_queue(self, project_id: int, scope: str, hub_ids: Iterable[str] = ()) -> list[str]:
        """ID находок SAST текущей выгрузки для прогона в порядке разбора: scope = live | all | urgent | selected.
        Находки, которых нет в новой выгрузке, в прогон не попадают."""
        with self._tx() as c:
            return self.sast_queue_in(c, project_id, scope, hub_ids)[0]

    @staticmethod
    def sast_queue_in(c: Any, project_id: int, scope: str, hub_ids: Iterable[str] = ()) -> tuple[list[str], dict | None]:
        """Очередь прогона одним чтением в переданной транзакции (бэклог 104): (ID в порядке разбора, исключённые охватом).
        live – живые в Hub (не Fixed и не статус решения), исключённые – {fixed, closed}; all – все SAST, сначала живые,
        внутри – по pos (он уже учитывает срочность, критичность и дубли); urgent – срочные; selected – выбранные по pos.
        У охватов кроме live статус Hub не отбирает – исключённых нет ({})."""
        if scope in ("live", "all"):
            sql = _HUB_STATUS_SET_SQL.format(cond="AND f.kind = 'SAST' AND f.missing = 0")
            rows = c.execute(f"SELECT s.hub_id, {_hub_class('s.status')} AS cls FROM ({sql}) s ORDER BY s.pos, s.id",
                             (project_id, project_id)).fetchall()
            live = [r["hub_id"] for r in rows if r["cls"] == "live"]
            if scope == "all":
                return live + [r["hub_id"] for r in rows if r["cls"] != "live"], {}
            return live, {"fixed": sum(r["cls"] == "fixed" for r in rows),
                          "closed": sum(r["cls"] == "closed" for r in rows)}
        if scope == "urgent":
            rows = c.execute("SELECT hub_id FROM findings WHERE project_id = ? AND kind = 'SAST' AND missing = 0"
                             " AND urgent = 1 ORDER BY pos", (project_id,)).fetchall()
            return [r["hub_id"] for r in rows], {}
        if scope == "selected":
            wanted = list(dict.fromkeys(str(h) for h in hub_ids))
            found: list[tuple[int, str]] = []
            for part in _chunks(wanted):
                marks = ",".join("?" * len(part))
                found += [(r["pos"], r["hub_id"]) for r in c.execute(
                    f"SELECT pos, hub_id FROM findings WHERE project_id = ? AND kind = 'SAST' AND missing = 0"
                    f" AND hub_id IN ({marks})", (project_id, *part)).fetchall()]
            return [hub_id for _, hub_id in sorted(found)], {}
        raise ValueError(f"неизвестный охват прогона: {scope}")

    def sast_hub_classes(self, project_id: int) -> dict:
        """Находки SAST текущей выгрузки по классу статуса Hub – для формы прогона (бэклог 104): {sast_live, sast_fixed,
        sast_closed}; выражение то же, что у очереди."""
        sql = _HUB_STATUS_SET_SQL.format(cond="AND f.kind = 'SAST' AND f.missing = 0")
        rows = self._all(f"SELECT {_hub_class('s.status')} AS cls, COUNT(*) AS n FROM ({sql}) s GROUP BY 1",
                         (project_id, project_id))
        got = {r["cls"]: int(r["n"]) for r in rows}
        return {"sast_live": got.get("live", 0), "sast_fixed": got.get("fixed", 0), "sast_closed": got.get("closed", 0)}

    def run_summary(self, run_id: int) -> dict:
        """Итог прогона (бэклог 102, 103): вердикты этого прогона (новые – done и готовые – cached, по run_items.verdict_id; отдельно new/cached), из «неясно» –
        без кода в клоне по текущим срезам, и сколько находок прогона разошлись с Hub по текущему статусу Hub."""
        run = self.get_run(run_id)
        project_id = int(run["project_id"]) if run else 0
        rows = self._all(f"""
            SELECT i.state, v.verdict, COUNT(*) AS n, COUNT(*) FILTER (WHERE {_NO_CODE_SQL}) AS no_code,
                   COUNT(*) FILTER (WHERE CASE lower(trim(st.status)) WHEN 'false positive' THEN v.verdict = 'true_positive'
                                    WHEN 'confirmed' THEN v.verdict = 'false_positive' ELSE false END) AS diff
              FROM run_items i JOIN runs ru ON ru.id = i.run_id JOIN verdicts v ON v.id = i.verdict_id
              JOIN ({_HUB_STATUS_SET_SQL.format(cond='')}) st ON st.hub_id = i.hub_id
              LEFT JOIN cases c ON c.project_id = ru.project_id AND c.hub_id = i.hub_id
             WHERE i.run_id = ? AND i.state IN ('done', 'cached') GROUP BY i.state, v.verdict""",
            (project_id, project_id, run_id))
        verdicts: dict[str, int] = {}
        for r in rows:
            verdicts[r["verdict"]] = verdicts.get(r["verdict"], 0) + int(r["n"])
        cached = sum(int(r["n"]) for r in rows if r["state"] == "cached")
        uncertain_no_code = sum(int(r["no_code"]) for r in rows if r["verdict"] == "uncertain")
        return {"verdicts": verdicts, "total": sum(verdicts.values()), "cached": cached,
                "new": sum(verdicts.values()) - cached, "uncertain_no_code": uncertain_no_code,
                "hub_model_diff": sum(int(r["diff"]) for r in rows)}

    def run_excluded(self, run_id: int) -> dict | None:
        """Исключённые охватом прогона из его паспорта (бэклог 104): {fixed, closed} или None – сведений нет."""
        row = self._one("SELECT payload_json::json -> 'excluded' AS excluded FROM run_journal WHERE run_id = ?", (run_id,))
        value = row["excluded"] if row else None
        if isinstance(value, str):
            value = loads(value, None)
        return value if isinstance(value, dict) else None

    # ------------------------------------------------------------------ кодовые базы

    def get_codebase_map(self, project_id: int, with_detached: bool = False) -> dict[str, dict]:
        """{кодовая база: {folder, manual}}; with_detached – ещё и detached: клон отвязан (ADR-0072)."""
        rows = self._all("SELECT codebase, folder, manual FROM codebase_map WHERE project_id = ?", (project_id,))
        result = {r["codebase"]: {"folder": r["folder"], "manual": bool(r["manual"])} for r in rows}
        if with_detached:
            detached = self.detached_codebases(project_id)
            for codebase, entry in result.items():
                entry["detached"] = codebase in detached
        return result

    def detached_codebases(self, project_id: int) -> set[str]:
        """Кодовые базы проекта с отвязанным клоном (ADR-0072)."""
        prefix = _detached_prefix(project_id)
        rows = self._all("SELECT key FROM meta WHERE substr(key, 1, ?) = ?", (len(prefix), prefix))
        return {row["key"][len(prefix):] for row in rows}

    def set_detached(self, project_id: int, codebases: Iterable[str]) -> None:
        """Отвязать клоны кодовых баз: их код берётся только из срезов в базе (triage.detach_removed_clones)."""
        ts = now_iso()
        prefix = _detached_prefix(project_id)
        with self._tx() as c:
            for codebase in codebases:
                c.execute("INSERT INTO meta(key, value) VALUES (?, ?) ON CONFLICT(key) DO NOTHING",
                          (prefix + codebase, ts))

    def clear_detached(self, project_id: int) -> int:
        """«Подключить клоны снова»: клоны кодовых баз проекта снова читаются. Ревизия, увиденная до удаления
        клона, остаётся: если в папке теперь другой код, сверка ревизий сбросит срезы, как при любой смене кода.
        Возвращает, сколько клонов было отвязано."""
        prefix = _detached_prefix(project_id)
        with self._tx() as c:
            return c.execute("DELETE FROM meta WHERE substr(key, 1, ?) = ?", (len(prefix), prefix)).rowcount

    def set_codebase_folder(self, project_id: int, codebase: str, folder: str, manual: bool) -> int:
        """Папка клона для кодовой базы. Если папка сменилась, срезы и привязки к вердиктам находок этой
        кодовой базы сбрасываются: они построены по другому коду (вердикты остаются в кэше). У её находок SAST
        текущей выгрузки снимается отметка «проверено» (решение и комментарий остаются; решение по SCA от кода
        не зависит, а пропавшая из выгрузки находка сверится по версии, когда вернётся). Возвращает, у скольких
        снята."""
        with self.source_gate(project_id), self._tx() as c:
            return self._set_codebase_folder_in(c, project_id, codebase, folder, manual, now_iso())

    def _set_codebase_folder_in(self, c: Any, project_id: int, codebase: str, folder: str, manual: bool, ts: str) -> int:
        """Тело set_codebase_folder в переданной транзакции (общее с set_repos_dir_and_folder, бэклог 95)."""
        old = c.execute("SELECT folder FROM codebase_map WHERE project_id = ? AND codebase = ?",
                        (project_id, codebase)).fetchone()
        if old is None or old["folder"] != folder:
            self._clear_example_mark_in(c, project_id, ts)
        c.execute("""
            INSERT INTO codebase_map(project_id, codebase, folder, manual, updated_at) VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(project_id, codebase) DO UPDATE SET
                folder = excluded.folder, manual = excluded.manual, updated_at = excluded.updated_at""",
                  (project_id, codebase, folder, 1 if manual else 0, ts))
        if (old["folder"] if old is not None else "") == folder:
            return 0
        self._touch(c, project_id, ts)
        c.execute("DELETE FROM cases WHERE project_id = ? AND hub_id IN"
                  " (SELECT hub_id FROM findings WHERE project_id = ? AND codebase = ?)",
                  (project_id, project_id, codebase))
        # ревизия и отвязка прежней папки к новой не относятся: ревизию запишет следующая сверка (sync_revisions)
        c.execute("DELETE FROM meta WHERE key IN (?, ?)",
                  (_revision_prefix(project_id) + codebase, _detached_prefix(project_id) + codebase))
        return c.execute("UPDATE reviews SET reviewed = 0, reviewed_at = NULL, updated_at = ?"
                         " WHERE project_id = ? AND reviewed = 1 AND hub_id IN"
                         " (SELECT hub_id FROM findings WHERE project_id = ? AND codebase = ? AND kind = 'SAST'"
                         " AND missing = 0)",
                         (ts, project_id, project_id, codebase)).rowcount

    # ------------------------------------------------------------------ контекст и вердикты

    def find_verdict(self, case_hash: str, model: str, prompt_version: str) -> dict | None:
        """Кэш: последний ответ модели на такой случай."""
        row = self._one("SELECT * FROM verdicts WHERE case_hash = ? AND model = ? AND prompt_version = ?"
                        " ORDER BY id DESC LIMIT 1", (case_hash, model, prompt_version))
        return self._verdict_row(row) if row else None

    def find_verdict_by_request(self, request_key: str) -> dict | None:
        """Кэш по ключу запроса к модели (prompts.request_key: модель, версия промпта, сообщения и параметры
        генерации целиком): последний ответ на точно такой же запрос."""
        if not request_key:
            return None
        row = self._one("SELECT * FROM verdicts WHERE request_key = ? ORDER BY id DESC LIMIT 1", (request_key,))
        return self._verdict_row(row) if row else None

    def get_verdict(self, verdict_id: int) -> dict | None:
        row = self._one("SELECT * FROM verdicts WHERE id = ?", (verdict_id,))
        return self._verdict_row(row) if row else None

    def finding_verdicts(self, project_id: int, hub_id: str) -> list[dict]:
        """Все ответы модели, которые человек мог видеть по находке: текущий, прежние привязанные (решения, история
        оценок, вопросы) и ответы других моделей по тому же срезу; новые – первыми. Для проверки, не написан ли
        комментарий моделью к другому вердикту (ADR-0088): после повторного разбора прежний ответ из решения уходит."""
        keys = (project_id, hub_id)
        # только то, что нужно для сверки комментария (Э6): без полного ответа модели и статистики
        rows = self._all(
            "SELECT id, verdict, COALESCE((data_json::json ->> 'hub_comment'), '') AS hub_comment"
            " FROM verdicts WHERE id IN ("
            "SELECT verdict_id FROM cases WHERE project_id = ? AND hub_id = ? AND verdict_id IS NOT NULL"
            " UNION SELECT verdict_id FROM reviews WHERE project_id = ? AND hub_id = ? AND verdict_id IS NOT NULL"
            " UNION SELECT verdict_id FROM run_review_events WHERE project_id = ? AND hub_id = ?"
            " UNION SELECT verdict_id FROM questions WHERE project_id = ? AND hub_id = ? AND verdict_id IS NOT NULL)"
            " OR case_hash IN (SELECT case_hash FROM cases WHERE project_id = ? AND hub_id = ?)"
            " ORDER BY id DESC", keys * 5)
        return [{"id": row["id"], "verdict": row["verdict"], "data": {"hub_comment": row["hub_comment"]}}
                for row in rows]

    ANSWER_IDS_SQL = """
        SELECT ri.hub_id, ri.verdict_id AS vid FROM run_items ri JOIN runs u ON u.id = ri.run_id
         WHERE u.project_id = ? AND ri.verdict_id IS NOT NULL AND ri.hub_id IN ({marks})
        UNION SELECT hub_id, verdict_id FROM cases WHERE project_id = ? AND verdict_id IS NOT NULL AND hub_id IN ({marks})
        UNION SELECT hub_id, verdict_id FROM reviews WHERE project_id = ? AND verdict_id IS NOT NULL AND hub_id IN ({marks})
        UNION SELECT hub_id, verdict_id FROM run_review_events WHERE project_id = ? AND hub_id IN ({marks})"""

    def _answer_ids(self, project_id: int, part: list[str]) -> tuple[str, tuple]:
        """Ответы модели по находкам part (ADR-0097): из прогонов, привязки среза и решения, журнала оценок решений –
        одно определение для истории в карточке и счётчика списка. Сохранённые, но не привязанные ответы не входят."""
        marks = ", ".join("?" * len(part))
        return self.ANSWER_IDS_SQL.format(marks=marks), (project_id, *part) * 4

    def model_answer_counts(self, project_id: int, hub_ids: Iterable[str], prompt_version: str) -> dict[str, dict]:
        """Для страницы списка (ADR-0097): {hub_id: {"answers": N, "kinds": K}} – N разных ответов модели по находке (то
        же множество, что история в карточке) и K разных вердиктов среди ответов по текущему срезу и текущей версии
        промпта. Одна выборка на страницу, не запрос на строку."""
        ids = [str(h) for h in hub_ids]
        out: dict[str, dict] = {}
        for start in range(0, len(ids), 200):
            part = ids[start:start + 200]
            sql, params = self._answer_ids(project_id, part)
            for row in self._all(f"""
                WITH ids(hub_id, vid) AS ({sql})
                SELECT ids.hub_id, COUNT(DISTINCT v.id) AS answers,
                       COUNT(DISTINCT CASE WHEN v.case_hash = c.case_hash AND v.prompt_version = ?
                                           THEN v.verdict END) AS kinds
                  FROM ids JOIN verdicts v ON v.id = ids.vid
                  LEFT JOIN cases c ON c.project_id = ? AND c.hub_id = ids.hub_id
                 GROUP BY ids.hub_id""", (*params, prompt_version, project_id)):
                out[row["hub_id"]] = {"answers": int(row["answers"]), "kinds": int(row["kinds"])}
        return out

    def finding_model_history(self, project_id: int, hub_id: str) -> dict:
        """Разборы находки моделью (ADR-0097): {"answers": [...], "attempts": [...]}. answers – по одному на ответ модели
        (verdict_id), новые первыми: модель, версия промпта, вердикт, уверенность, отпечаток среза (case_hash), время
        создания, разбор (data), статистика (stats) и где использован – uses: [{run_id, origin, state}] (state done –
        новый ответ, cached – взят из кэша). Входят ответы прогонов по этой находке и ответы, к которым привязаны срез
        и решение. attempts – элементы прогонов без ответа (ошибка, пропуск, в очереди) с прогоном и временем."""
        items = self._all("""
            SELECT ri.verdict_id, ri.state, ri.error, ri.finished_at, u.id AS run_id,
                   COALESCE(u.origin, '') AS origin, u.created_at AS run_at
              FROM run_items ri JOIN runs u ON u.id = ri.run_id
             WHERE u.project_id = ? AND ri.hub_id = ?
             ORDER BY ri.id""", (project_id, hub_id))
        sql, params = self._answer_ids(project_id, [hub_id])
        ids = sorted({int(r["vid"]) for r in self._all(sql, params)})
        answers: dict[int, dict] = {}
        for start in range(0, len(ids), 500):
            part = ids[start:start + 500]
            marks = ", ".join("?" * len(part))
            for row in self._all(
                    "SELECT id, model, prompt_version, verdict, confidence, case_hash, created_at,"
                    " COALESCE((data_json::json ->> 'summary'), '') AS summary,"
                    " COALESCE((data_json::json ->> 'why'), '[]') AS why,"
                    " COALESCE((data_json::json ->> 'explanation'), '') AS explanation,"
                    " COALESCE((data_json::json ->> 'fix'), '') AS fix,"
                    " (stats_json::json ->> 'total_s')::double precision AS total_s,"
                    " (stats_json::json ->> 'eval_tps')::double precision AS eval_tps"
                    f" FROM verdicts WHERE id IN ({marks})", part):
                why = loads(row["why"], []) if str(row["why"]).startswith("[") else [row["why"]]
                answers[int(row["id"])] = {
                    "id": int(row["id"]), "model": row["model"], "prompt_version": row["prompt_version"],
                    "verdict": row["verdict"], "confidence": row["confidence"], "case_hash": row["case_hash"],
                    "created_at": row["created_at"],
                    "data": {"summary": row["summary"], "why": why or ([row["explanation"]] if row["explanation"] else []),
                             "fix": row["fix"]},
                    "stats": {"total_s": row["total_s"], "eval_tps": row["eval_tps"]}, "uses": []}
        attempts = []
        for r in items:
            vid = int(r["verdict_id"]) if r["verdict_id"] else None
            if vid in answers:
                answers[vid]["uses"].append({"run_id": r["run_id"], "origin": r["origin"], "state": r["state"]})
            elif r["state"] in ("error", "skipped", "pending"):
                attempts.append({"run_id": r["run_id"], "origin": r["origin"], "state": r["state"],
                                 "error": r["error"], "at": r["finished_at"] or r["run_at"]})
        ordered = sorted(answers.values(), key=lambda a: (str(a["created_at"] or ""), a["id"]), reverse=True)
        return {"answers": ordered, "attempts": attempts}

    @staticmethod
    def _verdict_row(row: dict) -> dict:
        row["data"] = loads(row.pop("data_json"), {})
        row["raw"] = loads(row.pop("raw_json"), {})
        row["stats"] = loads(row.pop("stats_json"), {})
        return row

    def reserve_verdict_id(self) -> int:
        """Номер будущего вердикта. С ним запись безопасно повторить, если исход COMMIT неизвестен (ADR-0128, п. 6.4)."""
        with self._tx() as c:
            return int(c.execute("SELECT nextval(pg_get_serial_sequence('verdicts', 'id'))").fetchone()[0])

    def save_verdict(self, case_hash: str, model: str, prompt_version: str, verdict: dict, stats: dict,
                     request_key: str = "", execution_id: int | None = None, verdict_id: int | None = None) -> int:
        """Сохраняет ответ модели новой записью (verdict – поля Verdict, raw хранится отдельно); возвращает id.
        request_key – ключ запроса к модели (prompts.request_key) для кэша по запросу целиком.

        Записи не перезаписываются: решения и прогоны ссылаются на тот ответ, который видел человек, даже если
        позже модель спросили заново.
        """
        data = {k: v for k, v in verdict.items() if k != "raw"}
        with self._tx() as c:
            values = (case_hash, model, prompt_version, str(data.get("verdict") or ""), int(data.get("confidence") or 0),
                      dumps(data), dumps(verdict.get("raw") or {}), dumps(stats), request_key, execution_id)
            if verdict_id is None:
                return int(c.execute("""
                    INSERT INTO verdicts(case_hash, model, prompt_version, verdict, confidence, data_json, raw_json, stats_json,
                                         request_key, execution_id, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id""", (*values, now_iso())).fetchone()[0])
            saved = c.execute("""
                INSERT INTO verdicts(id, case_hash, model, prompt_version, verdict, confidence, data_json, raw_json, stats_json,
                                     request_key, execution_id, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (id) DO NOTHING RETURNING id""",
                              (verdict_id, *values, now_iso())).fetchone()
            if saved is None:  # номер получен заранее: это либо повтор той же записи, либо номер занят чужим ответом
                same = c.execute("""
                    SELECT 1 FROM verdicts WHERE id = ? AND case_hash = ? AND model = ? AND prompt_version = ? AND verdict = ?
                       AND confidence = ? AND data_json = ? AND raw_json = ? AND stats_json = ? AND request_key = ?
                       AND execution_id IS NOT DISTINCT FROM ?""", (verdict_id, *values)).fetchone()
                if same is None:
                    raise RuntimeError(f"Номер вердикта {verdict_id} занят другим ответом.")
            return int(verdict_id)

    @staticmethod
    def _source(c: Connection, project_id: int, hub_id: str) -> dict | None:
        """Снимок находки и того, откуда берётся её код (папки и последняя увиденная ревизия клона), одним запросом."""
        row = c.execute("""
            SELECT f.id, f.data_json, f.missing, p.repos_dir, COALESCE(m.folder, '') AS folder,
                   f.pkg_ecosystem, f.pkg_name, f.pkg_source, f.pkg_note, f.pkg_scope,
                   COALESCE((SELECT value FROM meta WHERE key = ? || f.codebase), '') AS revision,
                   EXISTS(SELECT 1 FROM meta WHERE key = ? || f.codebase) AS detached,
                   f.import_id, COALESCE(i.filename, '') AS import_filename, COALESCE(i.created_at, '') AS import_at,
                   COALESCE((SELECT r.revision FROM reviews r
                              WHERE r.project_id = f.project_id AND r.hub_id = f.hub_id), 0) AS review_revision
              FROM findings f
              JOIN projects p ON p.id = f.project_id
              LEFT JOIN codebase_map m ON m.project_id = f.project_id AND m.codebase = f.codebase
              LEFT JOIN imports i ON i.id = f.import_id
             WHERE f.project_id = ? AND f.hub_id = ?""",
                        (_revision_prefix(project_id), _detached_prefix(project_id), project_id, hub_id)).fetchone()
        if row is None:
            return None
        data = package_identity.with_package(dict(row))  # эффективная идентичность пакета (план dev17, п. 4.3)
        return {"finding_id": row["id"], "data": data, "signature": case_signature(data),
                "repos_dir": row["repos_dir"], "folder": row["folder"], "revision": row["revision"],
                "detached": bool(row["detached"]), "missing": bool(row["missing"]),
                # редакция решения на момент снимка (бэклог 117): в ключ источника не входит – по ней запись, которая
                # сняла бы «Проверено», узнаёт, что решение сохранено уже после чтения кода
                "review_revision": int(row["review_revision"] or 0),
                # выгрузка, из которой взята находка: подпись области в тексте дефекта (в отпечаток решения не входит)
                "import_id": row["import_id"], "import_filename": row["import_filename"], "import_at": row["import_at"]}

    @staticmethod
    def _source_key(source: dict) -> tuple:
        return (source["signature"], source["repos_dir"], source["folder"], source.get("revision", ""),
                bool(source.get("detached")), bool(source.get("missing")))

    @staticmethod
    def _review_moved(c: Connection, project_id: int, hub_id: str, source: dict | None) -> bool:
        """Решение находки сохранено после снимка source (бэклог 117): код читался до него, поэтому сравнение
        этого кода с решением ничего не доказывает. Снимок без редакции (source не задан) – не проверяется."""
        if source is None or "review_revision" not in source:
            return False
        row = c.execute("SELECT revision FROM reviews WHERE project_id = ? AND hub_id = ?",
                        (project_id, hub_id)).fetchone()
        return int(row["revision"] or 0 if row is not None else 0) != int(source["review_revision"] or 0)

    def case_input(self, project_id: int, hub_id: str) -> dict | None:
        """Согласованный снимок для разбора: {finding_id, data, signature, repos_dir, folder, revision, detached,
        missing}.

        Срез строится из этого снимка, а save_case(..., source=снимок) привяжет результат, только если находка,
        папка клона и его ревизия с тех пор не изменились. review_revision – редакция решения на момент снимка:
        «Проверено» по коду этого чтения снимается, только если решение с тех пор не сохранялось (бэклог 117)."""
        with self._lock:
            return self._source(self._conn, project_id, hub_id)

    def save_case(self, project_id: int, hub_id: str, case_hash: str, context: dict,
                  verdict_id: int | None, source: dict | None = None, only_new: bool = False,
                  replace_line_only: bool = False, no_downgrade: bool = False,
                  from_snapshot: bool = False) -> bool:
        """Сохраняет срез находки и привязку к вердикту.

        source – case_input() на момент сборки среза: если с тех пор находку заменила новая выгрузка или
        сменилась папка клона, срез устарел – ничего не сохраняется и возвращается False.

        only_new – только если среза у находки ещё нет («Сохранить срезы кода», ADR-0072): сохранённый срез, который
        видела модель, не перезаписывается; срез уже есть – False. replace_line_only – там же: заменить срез, только
        если он соответствует snapshot_candidates, а новый срез содержит код из файла; иначе False.
        no_downgrade – срез
        с кодом из файла не заменяется срезом без него (прогон, сверка): проверка в этой же транзакции, поэтому
        её не обходит параллельная запись; иначе False.

        Если у находки уже был срез с другим отпечатком (case_hash), код под решением другой: правки в рабочей
        копии без смены ревизии, git stash, папка без .git. Тогда отметка «проверено» снимается, а для страницы
        проекта сохраняется пояснение (code_change_notice). Так же, если среза ещё не было, а человек отметил
        находку проверенной по коду с другим отпечатком (reviews.code_hash при том же размере среза).

        Отметка снимается по коду, прочитанному вместе со снимком source. Если решение сохранено уже после снимка
        (редакция другая), а запись сняла бы отметку, – чтение устарело: ничего не сохраняется, возвращается False,
        следующий прогон или сверка прочитают код заново (бэклог 117).
        """
        ts = now_iso()
        with self._tx() as c:
            if source is not None:
                current = self._source(c, project_id, hub_id)
                if current is None or self._source_key(current) != self._source_key(source):
                    return False
            old = c.execute("SELECT case_hash FROM cases WHERE project_id = ? AND hub_id = ?",
                            (project_id, hub_id)).fetchone()
            if old is not None and only_new:
                return False
            if replace_line_only or no_downgrade:
                row = c.execute("SELECT verdict_id, (context_json::json ->> 'status') AS status,"
                                " COALESCE((context_json::json ->> 'reason'), '') AS reason FROM cases"
                                " WHERE project_id = ? AND hub_id = ?", (project_id, hub_id)).fetchone()
                if replace_line_only:
                    eligible = c.execute(f"""
                        SELECT 1 FROM findings f JOIN cases c
                          ON c.project_id = f.project_id AND c.hub_id = f.hub_id
                         WHERE f.project_id = ? AND f.hub_id = ? AND {_SNAPSHOT_REPLACEABLE}
                        """, (project_id, hub_id)).fetchone()
                    if not eligible or context.get("status") != "ok":
                        return False
                if no_downgrade and row is not None and row["status"] == "ok" and context.get("status") != "ok":
                    return False
            review = c.execute("SELECT code_hash, code_chars FROM reviews WHERE project_id = ? AND hub_id = ?"
                               " AND reviewed = 1", (project_id, hub_id)).fetchone()
            # отпечаток кода, по которому человек отметил решение, при том же размере среза
            comparable = bool(review is not None and review["code_hash"]
                              and int(review["code_chars"] or 0) == int(context.get("max_chars") or 0))
            # отметка «Проверено» относится к коду, который видел человек: известен его отпечаток при том же размере
            # среза (и размер известен, ревью Codex) – сравнение с ним (ADR-0147 п. 6: новый срез – тот самый код,
            # отметка остаётся; бэклог 114: код вернулся к срезу модели, но человек видел другой – снимается);
            # не известен – с прежним срезом
            known = comparable and int(review["code_chars"] or 0) > 0
            # причина снятия (бэклог 115): сравнение с прежним срезом позволяет отличить пересборку от правки кода,
            # сравнение с отпечатком решения – нет (кода решения в базе нет): причина тогда не установлена
            if old is None:  # среза ещё не было: решение принято по коду с другим отпечатком
                code_changed, reason = comparable and review["code_hash"] != case_hash, "unclear"
            elif known:
                code_changed, reason = review["code_hash"] != case_hash, "unclear"
            else:
                code_changed = old["case_hash"] != case_hash
                reason = self._slice_reason(c, project_id, hub_id, context) if code_changed else "code"
            # срез подставлен из сохранённого (клона нет): сменой кода не считается, отметка остаётся (ADR-0072,
            # ревью Codex); привязка нового вердикта сохраняется
            if code_changed and not from_snapshot:
                if self._review_moved(c, project_id, hub_id, source):
                    return False  # решение сохранено после чтения кода: это чтение его не опровергает
                self._reopen_for_code_change(c, project_id, hub_id, ts, reason=reason)
            c.execute("""
                INSERT INTO cases(project_id, hub_id, case_hash, context_json, verdict_id, updated_at, code_cmp)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(project_id, hub_id) DO UPDATE SET
                    case_hash = excluded.case_hash, context_json = excluded.context_json,
                    verdict_id = COALESCE(excluded.verdict_id,
                                          CASE WHEN cases.case_hash = excluded.case_hash
                                               THEN cases.verdict_id END),
                    updated_at = excluded.updated_at, code_cmp = excluded.code_cmp""",
                      (project_id, hub_id, case_hash, dumps(context), verdict_id, ts, code_cmp(context)))
            # новый ответ модели по тому же коду решение человека не ослабляет (ADR-0097): «Проверено» снимается только
            # при смене кода (_reopen_for_code_change выше) или версии находки
        return True

    @staticmethod
    def _reopen_for_code_change(c: Connection, project_id: int, hub_id: str, ts: str, reason: str = "code") -> int:
        """Код под решением другой: отметка «проверено» снимается, для страницы проекта копится пояснение
        (code_change_notice): кодовые базы, сколько отметок снято и по какой причине (reason, бэклог 115): code –
        код в клоне изменился, rebuilt – срез пересобран (тот же код, другие метки маскирования или сверка строки),
        unclear – код решения в базе не хранится, отличить нельзя; и номера находок – пояснение уходит, когда отметки
        у всех них вернулись (если номеров больше CODE_NOTICE_IDS – только по «Понятно»). Возвращает, снята ли
        отметка."""
        reopened = c.execute("UPDATE reviews SET reviewed = 0, reviewed_at = NULL, updated_at = ?"
                             " WHERE project_id = ? AND hub_id = ? AND reviewed = 1", (ts, project_id, hub_id)).rowcount
        if reopened:
            row = c.execute("SELECT codebase FROM findings WHERE project_id = ? AND hub_id = ?",
                            (project_id, hub_id)).fetchone()
            key = f"codechange:{int(project_id)}"
            stored = c.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
            notice = loads(stored["value"], {}) if stored is not None else {}
            if notice.get("cleared"):  # после «Понятно» – новое пояснение, редакция продолжается (ревью Codex)
                notice, stored = {"rev": int(notice.get("rev") or 0)}, None
            codebases = set(notice.get("codebases") or []) | {row["codebase"] if row else ""}
            hub_ids = list(dict.fromkeys([*(notice.get("hub_ids") or []), str(hub_id)]))
            truncated = bool(notice.get("truncated")) or len(hub_ids) > CODE_NOTICE_IDS
            # rev – редакция пояснения: растёт при каждом дополнении, по ней «Понятно» узнаёт показанное (время – до
            # секунды, два дополнения в одну секунду его не меняют, ревью Codex)
            notice = {"codebases": sorted(codebases), "reopened": int(notice.get("reopened") or 0) + reopened,
                      "rebuilt": int(notice.get("rebuilt") or 0) + (reopened if reason == "rebuilt" else 0),
                      "unclear": int(notice.get("unclear") or 0) + (reopened if reason == "unclear" else 0),
                      "hub_ids": hub_ids[-CODE_NOTICE_IDS:], "truncated": truncated,
                      "legacy": bool(notice.get("legacy")) or (stored is not None and "hub_ids" not in notice),
                      "rev": int(notice.get("rev") or 0) + 1, "at": ts}
            c.execute("INSERT INTO meta(key, value) VALUES (?, ?)"
                      " ON CONFLICT(key) DO UPDATE SET value = excluded.value", (key, dumps(notice)))
        return reopened

    @staticmethod
    def _slice_reason(c: Connection, project_id: int, hub_id: str, context: dict) -> str:
        """Почему прежний и новый срезы разные (бэклог 115): rebuilt – тот же файл, первая строка и текст строк в
        точности, изменились только сведения о срезе (сверка строки из выгрузки) – срез пересобран; unclear – строки
        совпадают, если не считать меток маскирования: номер метки зависит от значения (HMAC), поэтому это может быть
        и новое маскирование, и другое значение в коде (ревью Codex); code – строки другие."""
        row = c.execute("SELECT context_json FROM cases WHERE project_id = ? AND hub_id = ?",
                        (project_id, hub_id)).fetchone()
        old = loads(row["context_json"], {}) if row is not None else {}
        if (not old or not old.get("lines") or old.get("file") != context.get("file")
                or old.get("start_line") != context.get("start_line")):
            return "code"
        before, after = [str(x) for x in old.get("lines") or []], [str(x) for x in context.get("lines") or []]
        if before == after:
            return "rebuilt"
        if [_MASK_LABEL.sub("<MASK>", x) for x in before] == [_MASK_LABEL.sub("<MASK>", x) for x in after]:
            return "unclear"
        return "code"

    def clear_code_change_notice(self, project_id: int, shown: str) -> bool:
        """«Понятно» на странице проекта: показанное пояснение о смене кода больше не показывается (отметки не
        возвращаются). shown – редакция пояснения (rev; у пояснения прежнего формата – его время), которое видел
        оператор: если с тех пор прогон дополнил пояснение, оно остаётся (ревью Codex). Убрано ли."""
        key = f"codechange:{int(project_id)}"
        with self._tx() as c:
            row = c.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
            notice = loads(row["value"], {}) or {} if row is not None else {}
            if not notice or notice.get("cleared") or code_notice_version(notice) != str(shown or ""):
                return False
            # не удаляется, а снимается: номер редакции продолжается у следующего пояснения (ревью Codex)
            c.execute("UPDATE meta SET value = ? WHERE key = ?",
                      (dumps({"cleared": True, "rev": int(notice.get("rev") or 0)}), key))
            return True

    @staticmethod
    def _settle_code_notice(c: Connection, project_id: int) -> None:
        """Отметки «Проверено» у всех находок пояснения о смене кода вернулись – пояснение снимается в той же
        транзакции, что и отметка, с сохранением номера редакции (как «Понятно»). Иначе после ручного снятия отметки
        прежнее пояснение появилось бы снова и приписало снятие смене кода (ревью Codex ветки долга, круг 5).
        Пояснение без полного состава номеров (начатое до 0.10.0.dev21, усечённое) уходит только по «Понятно»."""
        key = f"codechange:{int(project_id)}"
        row = c.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        notice = (loads(row["value"], {}) or {}) if row is not None else {}
        ids = sorted({str(x) for x in notice.get("hub_ids") or []})
        if not ids or notice.get("cleared") or notice.get("legacy") or notice.get("truncated"):
            return
        marks = ",".join("?" * len(ids))  # не больше CODE_NOTICE_IDS номеров
        done = c.execute(f"SELECT COUNT(*) AS n FROM reviews WHERE project_id = ? AND reviewed = 1"
                         f" AND hub_id IN ({marks})", (project_id, *ids)).fetchone()["n"]
        if int(done or 0) >= len(ids):
            c.execute("UPDATE meta SET value = ? WHERE key = ?",
                      (dumps({"cleared": True, "rev": int(notice.get("rev") or 0)}), key))

    def reopen_for_decision_code(self, project_id: int, hub_id: str, case_hash: str, max_chars: int,
                                 source: dict) -> int:
        """Срез не меняется (тот же, что сохранён, и построен по клону), а решение принято по другому коду: известный
        отпечаток кода решения при том же размере среза отличается от текущего – отметка «проверено» снимается
        (бэклог 114: код вернулся к срезу модели). Для путей прогона, которые не вызывают save_case (готовый вердикт,
        модель недоступна). source – case_input(), по которому построен срез: если с тех пор сменились находка или
        клон, результат старого чтения пропускается, как в save_case (ревью Codex); так же – если после снимка
        сохранено решение (бэклог 117). Возвращает, снята ли отметка."""
        with self._tx() as c:
            current = self._source(c, project_id, hub_id)
            if current is None or self._source_key(current) != self._source_key(source):
                return 0
            review = c.execute("SELECT code_hash, code_chars FROM reviews WHERE project_id = ? AND hub_id = ?"
                               " AND reviewed = 1", (project_id, hub_id)).fetchone()
            if (review is None or not review["code_hash"] or int(review["code_chars"] or 0) <= 0
                    or int(review["code_chars"] or 0) != int(max_chars or 0) or review["code_hash"] == case_hash):
                return 0
            if self._review_moved(c, project_id, hub_id, source):
                return 0
            return self._reopen_for_code_change(c, project_id, hub_id, now_iso(), reason="unclear")

    def reviewed_among(self, project_id: int, hub_ids: Iterable[str]) -> int:
        """Сколько из находок hub_ids сейчас отмечены «Проверено»."""
        wanted = sorted({str(x) for x in hub_ids})
        total = 0
        for part in _chunks(wanted):
            marks = ",".join("?" * len(part))
            total += int(self._scalar(f"SELECT COUNT(*) FROM reviews WHERE project_id = ? AND reviewed = 1"
                                      f" AND hub_id IN ({marks})", (project_id, *part)) or 0)
        return total

    def reopen_for_code_change(self, project_id: int, hub_id: str, source: dict | None = None) -> int:
        """Код находки в клоне уже не тот, что в сохранённом срезе, а новый срез записывать нельзя (он хуже –
        triage.degrades): срез остаётся, а отметка «проверено» снимается с пояснением, как при смене кода.
        source – case_input(), по которому читался клон: если с тех пор сменились находка или клон либо оператор
        сохранил решение (бэклог 117), результат старого чтения пропускается, как в save_case."""
        with self._tx() as c:
            if source is not None:
                current = self._source(c, project_id, hub_id)
                if (current is None or self._source_key(current) != self._source_key(source)
                        or self._review_moved(c, project_id, hub_id, source)):
                    return 0
            return self._reopen_for_code_change(c, project_id, hub_id, now_iso())

    def code_change_notice(self, project_id: int) -> dict | None:
        """Пояснение для страницы проекта: код находок изменился без смены папки и ревизии клона и у скольких
        находок из-за этого снята отметка «проверено» – {codebases, reopened, at} или None."""
        value = self._scalar("SELECT value FROM meta WHERE key = ?", (f"codechange:{int(project_id)}",))
        notice = loads(value, None) if value else None
        return None if not notice or notice.get("cleared") else notice

    def snapshot_candidates(self, project_id: int) -> list[tuple[str, bool]]:
        """Находки SAST текущей выгрузки для «Сохранить срезы кода» в порядке разбора: (ID, upgrade). upgrade=False –
        среза нет; upgrade=True – срез без кода из файла и без вердикта с причиной missing, unreadable или
        неизвестной причиной; также no_repo при заданной папке и неотвязанном клоне, даже с вердиктом.
        Доступность файла перед заменой проверяет save_snapshots."""
        rows = self._all(f"""
            SELECT f.hub_id, c.hub_id IS NOT NULL AS has_case
              FROM findings f LEFT JOIN cases c ON c.project_id = f.project_id AND c.hub_id = f.hub_id
             WHERE f.project_id = ? AND f.kind = 'SAST' AND f.missing = 0
               AND (c.hub_id IS NULL OR {_SNAPSHOT_REPLACEABLE})
             ORDER BY f.pos""", (project_id,))
        return [(row["hub_id"], bool(row["has_case"])) for row in rows]

    def codebases_with_cases(self, project_id: int) -> set[str]:
        """Кодовые базы, у находок которых есть сохранённые срезы, – и у находок, которых нет в текущей выгрузке:
        смена папки удалила бы и их срезы (ADR-0072)."""
        return {row["codebase"] for row in self._all(
            "SELECT DISTINCT f.codebase FROM cases c JOIN findings f ON f.project_id = c.project_id"
            " AND f.hub_id = c.hub_id WHERE c.project_id = ?", (project_id,))}

    def case_reset_counts(self, project_id: int) -> dict[str, dict[str, int]]:
        """Срезы (включая пропавшие находки) и текущие отметки, удаляемые при смене папки кодовой базы."""
        rows = self._all("""
            SELECT f.codebase, COUNT(c.hub_id) AS cases,
                   COUNT(*) FILTER (WHERE f.kind = 'SAST' AND f.missing = 0 AND r.reviewed = 1) AS reviewed
              FROM findings f
              LEFT JOIN cases c ON c.project_id = f.project_id AND c.hub_id = f.hub_id
              LEFT JOIN reviews r ON r.project_id = f.project_id AND r.hub_id = f.hub_id
             WHERE f.project_id = ? GROUP BY f.codebase""", (project_id,))
        return {row["codebase"]: {"cases": int(row["cases"]), "reviewed": int(row["reviewed"])} for row in rows}

    def line_only_cases(self, project_id: int, limit: int = 500) -> list[dict]:
        """Находки SAST текущей выгрузки, у которых срез можно заменить: {hub_id, codebase,
        file, stored_file} – для проверки, нашёлся ли теперь их файл в клоне («Сохранить срезы кода»).
        Причины замены те же, что у snapshot_candidates."""
        return self._all(f"""
            SELECT f.hub_id, f.codebase, (f.data_json::json ->> 'file') AS file,
                   (c.context_json::json ->> 'file') AS stored_file
              FROM findings f JOIN cases c ON c.project_id = f.project_id AND c.hub_id = f.hub_id
             WHERE f.project_id = ? AND f.kind = 'SAST' AND f.missing = 0 AND {_SNAPSHOT_REPLACEABLE}
             ORDER BY f.pos LIMIT ?""", (project_id, int(limit)))

    def group_siblings(self, project_id: int, group_key: str, exclude: str, limit: int = 50) -> list[dict]:
        """Находки SAST текущей выгрузки с тем же ключом группы, кроме exclude: та же категория (правило и CWE), тот же
        файл и та же строка – в любых кодовых базах и коммитах (ADR-0089). В Hub это один дефект или одно решение
        о ложном срабатывании. Для каждой – id, hub_id, кодовая база, решение человека и номер дефекта, если его
        давали. Ключ без правила, файла или строки группы не образует."""
        if not group_key2_ok(group_key):
            return []
        return self._all(f"""
            SELECT f.id, f.hub_id, f.codebase, COALESCE(r.decision, '') AS decision,
                   COALESCE(r.final_verdict, '') AS final_verdict, COALESCE(r.final_comment, '') AS final_comment,
                   COALESCE(r.final_fix, '') AS final_fix, COALESCE(cs.code_cmp, '') AS code_cmp,
                   COALESCE(r.revision, 0) AS revision, f.missing, COALESCE(cs.case_hash, '') AS case_hash,
                   COALESCE(r.finding_sig, '') AS finding_sig,
                   {_ENTERED_HUB_SQL} AS entered_hub, d.number AS defect_number,
                   r.verdict_id AS review_verdict_id, cs.verdict_id AS case_verdict_id,
                   COALESCE((v.data_json::json ->> 'fix'), '') AS model_fix
              FROM findings f
              LEFT JOIN reviews r ON r.project_id = f.project_id AND r.hub_id = f.hub_id
              LEFT JOIN cases cs ON cs.project_id = f.project_id AND cs.hub_id = f.hub_id
              LEFT JOIN verdicts v ON v.id = r.verdict_id
              LEFT JOIN defects d ON d.project_id = f.project_id AND d.defect_key = 'sast:' || f.hub_id
             WHERE f.project_id = ? AND f.kind = 'SAST' AND f.missing = 0 AND f.group_key2 = ? AND f.hub_id <> ?
             ORDER BY f.pos LIMIT ?""", (project_id, group_key, exclude or "", max(0, int(limit))))

    def group_rows(self, project_id: int, group_key: str, exclude: str) -> list[dict]:
        """Все находки SAST группы, кроме exclude, включая пропавшие из выгрузки (missing): решение, своя
        рекомендация, «Как исправить» вердикта, по которому принято решение, и номер дефекта. По ним маршрут
        проверяет единство решения, текста и номера группы (ADR-0089). group_key – ключ второй редакции (ADR-0095)."""
        if not group_key2_ok(group_key):
            return []
        return self._all(GROUP_ROWS_SQL, (project_id, group_key, exclude or ""))

    def _group_neighbor_ids(self, c: Connection, project_id: int, hub_id: str) -> list[str]:
        """Соседи находки SAST по подгруппе «та же строка, категория и код» на соединении c (транзакция записи, по
        образцу _sca_package_state): тот же ключ группы находки (group_key2 – та же категория, строка и файл) и тот же
        отпечаток сравнения кода (cases.code_cmp), что у самой находки, – как same_code карточки; находки, которых нет
        в выгрузке, не считаются (ADR-0121 п. 5)."""
        own = c.execute("SELECT f.group_key2, COALESCE(cs.code_cmp, '') AS code_cmp FROM findings f"
                        " LEFT JOIN cases cs ON cs.project_id = f.project_id AND cs.hub_id = f.hub_id"
                        " WHERE f.project_id = ? AND f.hub_id = ?", (project_id, str(hub_id))).fetchone()
        if own is None:
            return []
        mine = str(own["code_cmp"] or "")
        return [str(r["hub_id"]) for r in self._group_rows(c, project_id, str(own["group_key2"] or ""), str(hub_id))
                if not r.get("missing") and str(r.get("code_cmp") or "") == mine]

    def _group_rows(self, c: Connection, project_id: int, group_key: str, exclude: str) -> list[dict]:
        """group_rows внутри транзакции записи: проверка группы и запись – одним снимком."""
        if not group_key2_ok(group_key):
            return []
        return [dict(r) for r in c.execute(GROUP_ROWS_SQL, (project_id, group_key, exclude or ""))]

    def review_text_history(self, project_id: int, hub_id: str, limit: int = 10) -> tuple[list[dict], int]:
        """Прежние редакции текста решения SAST по находке, новые первыми (О5): исход, комментарий, рекомендация,
        когда текст был принят и когда заменён; (последние limit, всего). В базе хранятся все."""
        rows = self._all("SELECT decision, final_verdict, final_comment, final_fix, decided_at, replaced_at"
                         " FROM review_texts WHERE project_id = ? AND hub_id = ? ORDER BY id DESC LIMIT ?",
                         (project_id, hub_id, max(0, int(limit))))
        total = int(self._scalar("SELECT COUNT(*) FROM review_texts WHERE project_id = ? AND hub_id = ?",
                                 (project_id, hub_id)) or 0)
        return rows, total

    def group_count(self, project_id: int, group_key: str, exclude: str) -> int:
        """Сколько находок SAST текущей выгрузки в группе, кроме exclude (список карточки ограничен)."""
        if not group_key2_ok(group_key):
            return 0
        return int(self._scalar("SELECT COUNT(*) FROM findings WHERE project_id = ? AND kind = 'SAST' AND missing = 0"
                                " AND group_key2 = ? AND hub_id <> ?", (project_id, group_key, exclude or "")) or 0)

    def near_category(self, project_id: int, f: Mapping[str, Any], code_cmp: str = "",
                      limit: int = 20) -> tuple[list[dict], int]:
        """Подсказка «Рядом та же категория» (ADR-0095 п. 6): находки SAST текущей выгрузки того же проекта не из
        группы f с той же категорией (правило и множество CWE) – A: тот же файл, строка ±10; B: тот же непустой
        отпечаток кода в другом месте. Объединение по id, первые limit по порядку разбора и общее число. Сведения, не
        решение: группу, номер и решения подсказка не меняет."""
        from app.hub_import import group_key2, near_columns2
        key = group_key2(f)
        cat, file2, line = near_columns2(f)
        if not key or not cat:
            return [], 0
        cmp = str(code_cmp or "")
        lo, hi = (line - 10, line + 10) if line is not None else (0, -1)
        cand = """
            SELECT f.id FROM findings f
             WHERE f.project_id = ? AND md5(f.g2_cat) = md5(?) AND md5(f.g2_file) = md5(?) AND f.g2_line BETWEEN ? AND ?
               AND f.g2_cat = ? AND f.g2_file = ?
               AND f.kind = 'SAST' AND f.missing = 0 AND f.group_key2 <> ?
            UNION
            SELECT f.id FROM cases c JOIN findings f ON f.project_id = c.project_id AND f.hub_id = c.hub_id
             WHERE c.project_id = ? AND ? <> '' AND c.code_cmp = ?
               AND f.g2_cat = ? AND f.kind = 'SAST' AND f.missing = 0 AND f.group_key2 <> ?"""
        cand_args = (project_id, cat, file2, lo, hi, cat, file2, key, project_id, cmp, cmp, cat, key)
        # объединение считается один раз (материализованный CTE): и список, и общее число – по нему
        rows = self._all(f"""
            WITH cand AS MATERIALIZED ({cand})
            SELECT f.id, f.hub_id, f.codebase, f.g2_file, f.g2_line, (SELECT COUNT(*) FROM cand) AS total,
                   CASE WHEN f.g2_file = ? AND f.g2_line BETWEEN ? AND ? THEN 1 ELSE 0 END AS near,
                   CASE WHEN ? <> '' AND EXISTS (SELECT 1 FROM cases c WHERE c.project_id = f.project_id
                        AND c.hub_id = f.hub_id AND c.code_cmp = ?) THEN 1 ELSE 0 END AS same_code
              FROM findings f JOIN cand ON cand.id = f.id ORDER BY f.pos LIMIT ?""",
                         (*cand_args, file2, lo, hi, cmp, cmp, max(0, int(limit))))
        total = int(rows[0]["total"]) if rows else 0
        return [{k: v for k, v in r.items() if k != "total"} for r in rows], total

    def group_merge(self, project_id: int, group_key2: str) -> dict | None:
        """Факт слияния группы при обновлении схемы 20 (ADR-0095 п. 3) или None."""
        if not group_key2_ok(group_key2):
            return None
        row = self._one("SELECT * FROM sast_group_merges WHERE project_id = ? AND group_key2 = ?",
                        (project_id, group_key2))
        if row is None:
            return None
        return {"old_keys": loads(row["old_keys_json"], []), "numbers": [int(n) for n in loads(row["numbers_json"], [])],
                "merged_at": row["merged_at"]}

    def incomplete_snapshots(self, project_id: int, limit: int = 50) -> list[dict]:
        """Неполные срезы SAST текущей выгрузки в порядке разбора (ADR-0073)."""
        return self._all(f"""
            SELECT f.hub_id, f.codebase, (f.data_json::json ->> 'file') AS file,
                   COALESCE((c.context_json::json ->> 'reason'), '') AS reason
              FROM findings f JOIN cases c ON c.project_id = f.project_id AND c.hub_id = f.hub_id
             WHERE f.project_id = ? AND f.kind = 'SAST' AND f.missing = 0
               AND {_SNAPSHOT_INCOMPLETE}
             ORDER BY f.pos LIMIT ?""", (project_id, max(0, int(limit))))

    def snapshot_reasons(self, project_id: int) -> dict:
        """Находки SAST текущей выгрузки со срезом без кода в клоне (бэклог 103, замечание 4): по причинам
        ({ключ: N}, view.CODE_REASON_KEYS), «внутри архива» и «строки выгрузки нет»."""
        rows = self._all(f"""
            SELECT {_CODE_REASON_KEY_SQL} AS reason_key, {_IN_ARCHIVE_SQL} AS archive,
                   COALESCE(json_len(c.context_json::json -> 'lines'), 0) = 0 AS no_line, COUNT(*) AS n
              FROM findings f JOIN cases c ON c.project_id = f.project_id AND c.hub_id = f.hub_id
             WHERE f.project_id = ? AND f.kind = 'SAST' AND f.missing = 0
               AND COALESCE(c.context_json::json ->> 'status', '') <> 'ok'
             GROUP BY 1, 2, 3""", (project_id,))
        out: dict = {"reasons": {}, "archive": 0, "no_line": 0, "total": 0}
        for r in rows:
            n = int(r["n"])
            out["reasons"][r["reason_key"]] = out["reasons"].get(r["reason_key"], 0) + n
            out["archive"] += n if r["archive"] else 0
            out["no_line"] += n if r["no_line"] else 0
            out["total"] += n
        return out

    def snapshot_counts(self, project_id: int) -> dict[str, dict[str, int]]:
        """Срезы кода в базе по кодовым базам (ADR-0072, ADR-0073): sast, code, line, empty, none – находок
        SAST текущей выгрузки, из них со срезом кода из файла клона, со срезом из одной строки выгрузки (файл
        не прочитан), со срезом без строк и без среза. incomplete – неполных срезов; missing – срезов из строки
        выгрузки, когда файла в клоне подтверждённо нет."""
        rows = self._all(f"""
            SELECT f.codebase, COUNT(*) AS sast,
                   COUNT(*) FILTER (WHERE (c.context_json::json ->> 'status') = 'ok'
                                AND json_len(c.context_json::json -> 'lines') > 0) AS code,
                   COUNT(*) FILTER (WHERE (c.context_json::json ->> 'status') <> 'ok'
                                AND json_len(c.context_json::json -> 'lines') > 0) AS line,
                   COUNT(*) FILTER (WHERE c.hub_id IS NOT NULL
                                AND COALESCE(json_len(c.context_json::json -> 'lines'), 0) = 0) AS empty,
                   COUNT(*) FILTER (WHERE {_SNAPSHOT_INCOMPLETE}) AS incomplete,
                   COUNT(*) FILTER (WHERE (c.context_json::json ->> 'status') <> 'ok'
                                AND (c.context_json::json ->> 'reason') = 'missing'
                                AND json_len(c.context_json::json -> 'lines') > 0) AS missing
              FROM findings f
              LEFT JOIN cases c ON c.project_id = f.project_id AND c.hub_id = f.hub_id
             WHERE f.project_id = ? AND f.kind = 'SAST' AND f.missing = 0
             GROUP BY f.codebase""", (project_id,))
        return {row["codebase"]: {"sast": int(row["sast"]), "code": int(row["code"]), "line": int(row["line"]),
                                  "empty": int(row["empty"]),
                                  "incomplete": int(row["incomplete"]), "missing": int(row["missing"]),
                                  "none": int(row["sast"]) - int(row["code"]) - int(row["line"]) - int(row["empty"])}
                for row in rows}

    def get_case(self, project_id: int, hub_id: str) -> dict | None:
        """Последний контекст находки и вердикт к нему (verdict – None, если вердикта нет)."""
        row = self._one("SELECT * FROM cases WHERE project_id = ? AND hub_id = ?", (project_id, hub_id))
        if row is None:
            return None
        row["context"] = loads(row.pop("context_json"), {})
        row["verdict"] = self.get_verdict(row["verdict_id"]) if row.get("verdict_id") else None
        return row

    # ------------------------------------------------------------------ решения человека

    def get_review(self, project_id: int, hub_id: str) -> dict | None:
        row = self._one(f"SELECT r.*, {_ENTERED_HUB_SQL} AS entered_current,"
                        " (SELECT hub_url FROM hub_ops WHERE id = r.entered_op_id) AS entered_hub_url,"
                        " (SELECT app_id FROM hub_ops WHERE id = r.entered_op_id) AS entered_app_id"
                        " FROM reviews r WHERE project_id = ? AND hub_id = ?", (project_id, hub_id))
        if row is not None:
            row["entered_recorded"] = row["entered_hub"]
            row["entered_hub"] = row.pop("entered_current")
            row["dropped_info"] = loads(row.get("defect_dropped") or "", {}) or {}
            row["entered_scope_note"] = ""
            if row["entered_recorded"] and not row["entered_hub"]:
                row["entered_scope_note"] = (f"Прежняя отметка относится к {row['entered_hub_url']}, "
                                             f"приложению {row['entered_app_id']}. В текущем назначении запись не подтверждена.")
            elif row["entered_hub"] and row["entered_origin"] not in ("status", "defect", "hub_sync"):
                row["entered_scope_note"] = "Ручная или прежняя отметка без назначения; статус в текущем Hub ею не подтверждён."
        return row

    def review_version(self, project_id: int, hub_id: str) -> str:
        """Версия находки для формы решения: поля находки и папка с её кодом сейчас ("" – находки нет)."""
        source = self.case_input(project_id, hub_id)
        return source_version(source) if source else ""

    @staticmethod
    def _check_expect(c: Connection, project_id: int, hub_id: str, source: dict | None,
                      expect: dict | None) -> None:
        """Проверка внутри транзакции записи: решение отправлено с той страницы, которая показывала текущее
        состояние. expect – {"version", "verdict_id", "revision", "answer_id"}; revision не задан – не проверяется;
        answer_id – номер последнего ответа агента по библиотеке находки SCA, который видел человек ("" – ответа не
        было): проверяется здесь же, в транзакции записи, а не в маршруте до неё, поэтому ответ, загруженный между
        проверкой страницы и записью решения, решение не пропускает (StaleReview, причина "answer"). Номера ответов
        не переиспользуются (AUTOINCREMENT), поэтому замена ответа того же источника – тоже другой номер."""
        if expect is None:
            return
        case = c.execute("SELECT verdict_id FROM cases WHERE project_id = ? AND hub_id = ?",
                         (project_id, hub_id)).fetchone()
        current_verdict = case["verdict_id"] if case is not None else None
        version = source_version(source) if source is not None else ""
        if source is None or version != expect.get("version"):
            raise StaleReview("Находка, папка с её кодом или ревизия клона изменились, пока страница была открыта.",
                              "source")
        if current_verdict != expect.get("verdict_id"):
            raise StaleReview("Вердикт модели изменился, пока страница была открыта.", "verdict")
        if expect.get("answer_id") is not None:
            if Database._main_answer(c, project_id, source["data"])[0] != str(expect["answer_id"]):
                raise StaleReview("Ответ агента по библиотеке изменился, пока страница была открыта.", "answer")
        if expect.get("revision") is not None:
            row = c.execute("SELECT revision FROM reviews WHERE project_id = ? AND hub_id = ?",
                            (project_id, hub_id)).fetchone()
            if int(row["revision"] if row is not None else 0) != int(expect["revision"]):
                raise StaleReview("Решение по находке изменили в другой вкладке или окне.", "revision")

    @staticmethod
    def _reopen_after_research(c: Connection, project_id: int, refs: set[str], ts: str) -> int:
        """Новая ревизия исследования строк refs – новый главный ответ пакетов без прежних ответов (ADR-0108): проверенные
        решения «Согласен с агентом», принятые по прежнему ответу исследования, возвращаются в непроверенные, а редакция
        решения растёт – страница с прежней редакцией его не сохранит и отметку не поставит (как save_sca_answers;
        ревью Codex, круг 20). Решения по прежним ответам агента (они главнее) не трогаются. Возвращает их число."""
        if not refs:
            return 0
        from app.sca import package_key
        from app.sca_contract import input_ref as package_ref
        reopened = 0
        for row in c.execute("SELECT f.hub_id, f.data_json, f.pkg_ecosystem, f.pkg_name, f.pkg_source, f.pkg_note,"
                             " f.pkg_scope FROM findings f JOIN reviews r ON r.project_id = f.project_id"
                             " AND r.hub_id = f.hub_id WHERE f.project_id = ? AND f.kind = 'SCA' AND r.decision = 'agree'"
                             " AND r.reviewed = 1 AND r.answer_sig LIKE 'research:%'", (project_id,)).fetchall():
            # эффективная тройка (план dev17, п. 4.3) – та же, что у ключа исследования и главного ответа
            data = package_identity.with_package(dict(row))
            key = package_identity.of(data)
            if package_ref(*package_key({"ecosystem": key[0], "component": key[1], "version": key[2]})) not in refs:
                continue
            reopened += c.execute(
                "UPDATE reviews SET reviewed = 0, reviewed_at = NULL, updated_at = ?, revision = revision + 1"
                " WHERE project_id = ? AND hub_id = ? AND decision = 'agree' AND reviewed = 1 AND answer_sig != ?",
                (ts, project_id, row["hub_id"], Database._main_answer(c, project_id, data)[1])).rowcount
        return reopened

    @staticmethod
    def _main_answer(c: Connection, project_id: int, data: dict) -> tuple[str, str]:
        """Номер и отпечаток главного ответа агента по пакету находки, прочитанные в транзакции записи: последний
        прежний ответ, а без прежних – ответ исследования компонента (ADR-0108, routes/sca.with_research); ответа нет –
        ("", "")."""
        key = package_identity.of(data)  # эффективная тройка (план dev17, п. 4.3)
        row = c.execute("SELECT * FROM sca_answers WHERE project_id = ? AND component = ? AND version = ?"
                        " AND ecosystem = ? ORDER BY id DESC LIMIT 1", (project_id, key[1], key[2], key[0])).fetchone()
        if row is not None:
            return str(row["id"]), Database._answer_from_row(row).signature()
        from app.sca import package_key, research_answer
        from app.sca_contract import input_ref as package_ref
        ref = package_ref(*package_key({"ecosystem": key[0], "component": key[1], "version": key[2]}))
        research = c.execute("SELECT * FROM sca2_research WHERE project_id = ? AND input_ref = ? ORDER BY revision DESC"
                             " LIMIT 1", (project_id, ref)).fetchone()
        found = research_answer(Database._research_row(dict(research)), key) if research is not None else None
        return (str(found["id"]), "research:" + found["research_sig"]) if found else ("", "")

    def _answer_moved(self, c: Connection, project_id: int, data: dict, saved_sig: str) -> bool:
        """Решение «Согласен с агентом» по находке SCA принято не по текущему главному ответу агента (отпечаток
        решения не совпал с отпечатком ответа, прочитанного в этой же транзакции)."""
        if not str(data.get("kind") or "").startswith("SCA"):
            return False
        return self._main_answer(c, project_id, data)[1] != (saved_sig or "")

    def save_review(self, project_id: int, hub_id: str, *, decision: str, final_verdict: str, final_comment: str,
                    reviewed: bool, verdict_id: int | None = None, expect: dict | None = None,
                    code_hash: str | None = None, code_chars: int = 0, answer_sig: str | None = None,
                    require_present: bool = False, kapo_state: str | None = None,
                    final_fix: str | None = None, group_key: str = "",
                    group_check: Callable[[list[dict]], None] | None = None, recheck: bool = False) -> dict:
        """Сохраняет решение человека вместе с версией находки, по которой оно принято; возвращает сохранённую
        строку (с номером редакции revision), прочитанную в той же транзакции.

        expect – {"version": review_version(...), "verdict_id": id или None, "revision": редакция решения или 0,
        если решения не было} со страницы, с которой отправлено решение. Если находка, папка с её кодом, ревизия
        клона, привязанный к ней вердикт модели или само решение с тех пор изменились (новая выгрузка, другой клон,
        новый прогон, сохранение из другой вкладки), решение не сохраняется: StaleReview с причиной (reason).

        code_hash, code_chars – отпечаток кода, который видел человек, и размер среза, по которому он считался
        (None – не менять). Отметки «скопировано для Hub» и «Внесено в Hub» сохраняются, только если текст для
        Hub – статус (с учётом «Отложить» и «Риск принят») и комментарий – не изменился: иначе в Hub уже другой текст.
        answer_sig – отпечаток ответа внешнего агента, по которому принято решение SCA (None – не менять): новый
        ответ с другим выводом возвращает решение «Согласен с агентом» на проверку (save_sca_answers).
        kapo_state – уточнение решения SCA по ГОСТ Р КАПО (KAPO_STATES; None – не менять). Смена уточнения, итога или
        комментария меняет дату решения decided_at и, как смена текста для Hub, снимает отметки «скопировано»
        и «Внесено в Hub».
        final_fix – рекомендация подтверждённого дефекта SAST своими словами (None – не менять, ADR-0089); её смена,
        как смена комментария, меняет текст дефекта, дату решения и снимает отметки «скопировано» и «Внесено в Hub».
        group_check – проверка находок той же группы group_key (ADR-0089) в той же транзакции, что и запись: бросает
        исключение, если решение или текст группы расходятся (тогда ничего не записывается).
        require_present – решение сохраняется ради копирования текста в Hub: находка должна быть в текущей выгрузке,
        и это проверяется здесь, в транзакции записи (StaleReview с причиной "missing"), а не до неё: флаг missing
        в версию находки не входит, и повторный импорт между проверкой и записью иначе не заметить.
        """
        if decision not in ("", *DECISIONS):
            raise ValueError(f"неизвестное решение: {decision}")
        if final_verdict not in ("", *VERDICT_VALUES):
            raise ValueError(f"неизвестный вердикт: {final_verdict}")
        if kapo_state is not None and kapo_state not in KAPO_STATES:
            raise ValueError(f"неизвестное уточнение по ГОСТ Р КАПО: {kapo_state}")
        with self._tx() as c:
            return self._save_review_in(c, project_id, hub_id, decision=decision, final_verdict=final_verdict,
                                        final_comment=final_comment, reviewed=reviewed, verdict_id=verdict_id,
                                        expect=expect, code_hash=code_hash, code_chars=code_chars,
                                        answer_sig=answer_sig, require_present=require_present,
                                        kapo_state=kapo_state, final_fix=final_fix, group_key=group_key,
                                        group_check=group_check, recheck=recheck)

    def save_reviews(self, project_id: int, items: list[dict],
                     check: Callable[[Connection], None] | None = None,
                     after: Callable[[Connection], None] | None = None) -> list[dict]:
        """Пакетное решение (ADR-0091 п. 4): решения нескольких находок одной транзакцией. items – аргументы
        save_review по находке (hub_id и именованные). check(c) – проверка снимка пакета в той же транзакции до записи:
        бросает исключение – не записывается ничего. Любой отказ по одной находке откатывает всё."""
        for item in items:
            if item.get("decision", "") not in ("", *DECISIONS):
                raise ValueError(f"неизвестное решение: {item.get('decision')}")
            if item.get("final_verdict", "") not in ("", *VERDICT_VALUES):
                raise ValueError(f"неизвестный вердикт: {item.get('final_verdict')}")
            if item.get("kapo_state") is not None and item["kapo_state"] not in KAPO_STATES:
                raise ValueError(f"неизвестное уточнение по ГОСТ Р КАПО: {item['kapo_state']}")
        with self._tx() as c:
            if check is not None:
                check(c)
            saved = [self._save_review_in(c, project_id, **item) for item in items]
            if after is not None:  # состояние сразу после своей записи, той же транзакцией (К6)
                after(c)
            return saved

    def _save_review_in(self, c: Connection, project_id: int, hub_id: str, *, decision: str,
                        final_verdict: str, final_comment: str, reviewed: bool, verdict_id: int | None = None,
                        expect: dict | None = None, code_hash: str | None = None, code_chars: int = 0,
                        answer_sig: str | None = None, require_present: bool = False, kapo_state: str | None = None,
                        final_fix: str | None = None, group_key: str = "",
                        group_check: Callable[[list[dict]], None] | None = None, recheck: bool = False) -> dict:
        """Запись решения в открытой транзакции c (save_review, save_reviews)."""
        ts = now_iso()
        source = self._source(c, project_id, hub_id)  # находка и источник её кода – одним снимком
        sig = source_signature(source) if source is not None else ""
        if require_present and (source is None or source.get("missing")):
            raise StaleReview("Находки нет в текущей выгрузке.", "missing")
        self._check_expect(c, project_id, hub_id, source, expect)
        if group_check is not None:
            group_check(self._group_rows(c, project_id, group_key, hub_id))
        old = c.execute("SELECT decision, reviewed, reviewed_at, copied_at, final_verdict, final_comment,"
                        " entered_hub, entered_hub_at, code_hash, code_chars, entered_text_hash, answer_sig,"
                        " kapo_state, decided_at, final_fix, verdict_id FROM reviews WHERE project_id = ? AND hub_id = ?",
                        (project_id, hub_id)).fetchone()
        if final_fix is None:
            final_fix = old["final_fix"] if old is not None else ""
        if kapo_state is None:
            kapo_state = old["kapo_state"] if old is not None else ""
        if not str(((source or {}).get("data") or {}).get("kind") or "").startswith("SCA"):
            kapo_state = ""  # уточнение по ГОСТ Р КАПО – только у решений SCA
        if (old is not None and not old["kapo_state"] and kapo_state
                and effective_kapo(hub_verdict(decision, final_verdict), kapo_state)
                == effective_kapo(hub_verdict(old["decision"], old["final_verdict"]), "")):
            # решение до 0.9.0 без уточнения: подставленное по умолчанию значение смысла не меняет – решение,
            # его дата и отметки остаются прежними
            kapo_state = ""
        # правка решения или явное «Сохранить» и «Дальше» оператора (recheck) – новая проверка; сохранение без правок (копирование, возврат
        # после Pull) дату не трогает (план dev7, раздел 5)
        # сравнивается итог: «Согласен» и «Не согласен» с тем же выводом – одно решение
        unchanged = (not recheck and old is not None and old["reviewed"] and old["reviewed_at"]
                     and hub_verdict(old["decision"], old["final_verdict"]) == hub_verdict(decision, final_verdict)
                     and old["final_comment"] == final_comment and old["final_fix"] == final_fix)
        reviewed_at = (old["reviewed_at"] if unchanged else ts) if reviewed else None
        # тот же текст для Hub – тот же статус (с учётом «Отложить»), тот же комментарий и та же рекомендация. У SAST
        # текст дефекта – исход, обоснование и своя рекомендация оператора (ADR-0092): переход между «Согласен» и
        # «Не согласен» (новый ответ модели) отметок не снимает (ADR-0097); снятие или иной вид решения – снимает
        sast = str(((source or {}).get("data") or {}).get("kind") or "") == "SAST"
        same_text = (old is not None
                     and hub_verdict(old["decision"], old["final_verdict"]) == hub_verdict(decision, final_verdict)
                     and old["final_comment"] == final_comment
                     and (old["final_fix"] or "") == (final_fix or "")
                     and (old["kapo_state"] or "") == (kapo_state or "")
                     and (not sast or old["decision"] == decision
                          or {old["decision"], decision} <= {"agree", "disagree"}))
        # дата решения: меняется вместе с итогом, уточнением или комментарием, а не с отметками
        decided_at = old["decided_at"] if same_text else ts
        if not (decision or final_verdict or final_comment.strip() or (final_fix or "").strip()):
            decided_at = None
        copied_at = old["copied_at"] if same_text else None
        entered, entered_at, entered_hash = ((old["entered_hub"], old["entered_hub_at"], old["entered_text_hash"])
                                             if same_text else (0, None, ""))
        if (sast and old is not None
                and ((old["final_comment"] or "").strip() or (old["final_fix"] or "").strip())
                and ((old["final_comment"] or "", old["final_fix"] or "", hub_verdict(old["decision"], old["final_verdict"]))
                     != (final_comment, final_fix or "", hub_verdict(decision, final_verdict)))):
            # прежний текст решения не теряется: история редакций (О5), текущая – в reviews
            c.execute("INSERT INTO review_texts(project_id, hub_id, decision, final_verdict, final_comment, final_fix,"
                      " decided_at, replaced_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                      (project_id, hub_id, old["decision"] or "", old["final_verdict"] or "", old["final_comment"] or "",
                       old["final_fix"] or "", old["decided_at"], ts))
        if code_hash is None:
            code_hash, code_chars = (old["code_hash"], old["code_chars"]) if old is not None else ("", 0)
        if answer_sig is None:
            answer_sig = old["answer_sig"] if old is not None else ""
        c.execute("""
            INSERT INTO reviews(project_id, hub_id, decision, final_verdict, final_comment, reviewed,
                                reviewed_at, copied_at, verdict_id, finding_sig, revision, updated_at,
                                entered_hub, entered_hub_at, code_hash, code_chars, entered_text_hash, answer_sig,
                                kapo_state, decided_at, final_fix, decision_origin)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'operator')
            ON CONFLICT(project_id, hub_id) DO UPDATE SET
                decision = excluded.decision, final_verdict = excluded.final_verdict,
                final_comment = excluded.final_comment, reviewed = excluded.reviewed,
                reviewed_at = excluded.reviewed_at, copied_at = excluded.copied_at,
                verdict_id = excluded.verdict_id, finding_sig = excluded.finding_sig,
                revision = reviews.revision + 1, updated_at = excluded.updated_at,
                entered_hub = excluded.entered_hub, entered_hub_at = excluded.entered_hub_at,
                code_hash = excluded.code_hash, code_chars = excluded.code_chars,
                entered_text_hash = excluded.entered_text_hash, answer_sig = excluded.answer_sig,
                kapo_state = excluded.kapo_state, decided_at = excluded.decided_at,
                final_fix = excluded.final_fix, decision_origin = 'operator', decision_source_json = '{}',
                defect_dropped = ''""",
                  (project_id, hub_id, decision, final_verdict, final_comment, 1 if reviewed else 0,
                   reviewed_at, copied_at, verdict_id, sig, ts, entered, entered_at, code_hash or "",
                   int(code_chars or 0), entered_hash or "", answer_sig or "", kapo_state or "", decided_at,
                   final_fix or ""))
        if reviewed:
            self._settle_code_notice(c, project_id)
        if not same_text:
            c.execute("UPDATE reviews SET entered_origin = '', entered_defect_id = NULL, entered_op_id = NULL,"
                      " entered_defect_revision = 0, entered_decision_hash = '' WHERE project_id = ? AND hub_id = ?",
                      (project_id, hub_id))
        data = (source or {}).get("data") or {}
        if (str(data.get("kind") or "").startswith("SCA") and old is not None
                and hub_verdict(old["decision"], old["final_verdict"]) == "true_positive"
                and hub_verdict(decision, final_verdict) != "true_positive"):
            # смена исхода «Обновить» выводит находку из её набора; правка комментария без смены исхода – нет
            from app.sca_contract import input_ref as package_ref
            ref = package_ref(*package_identity.of(data))  # эффективная тройка (план dev17, п. 4.3)
            self.sca_leave_sets(c, project_id, ref, [hub_id], ts)
        self._touch(c, project_id, ts)
        from app.journal import review_event
        review_event(c, project_id, hub_id)
        return dict(c.execute("SELECT * FROM reviews WHERE project_id = ? AND hub_id = ?",
                              (project_id, hub_id)).fetchone())

    # ------------------------------------------------------------------ наборы дефекта SCA (ADR-0091)

    def sca_members(self, project_id: int, input_ref: str) -> dict[str, dict]:
        """Явные места находок пакета: {hub_id: {set_no (None – «без дефекта»), no_defect_reason}}. Находки с
        исходом «Обновить», которых здесь нет, входят в набор по умолчанию (0)."""
        return {r["hub_id"]: {"set_no": r["set_no"], "no_defect_reason": r["no_defect_reason"]}
                for r in self._all("SELECT hub_id, set_no, no_defect_reason FROM sca_set_members"
                                   " WHERE project_id = ? AND input_ref = ?", (project_id, input_ref))}

    def sca_sets(self, project_id: int, input_ref: str) -> dict[int, dict]:
        """Наборы пакета: {set_no: {revision, excluded}}; набор по умолчанию (0) есть всегда."""
        out = {0: {"revision": 0, "excluded": []}}
        for r in self._all("SELECT set_no, revision, excluded_json FROM sca_defect_sets"
                           " WHERE project_id = ? AND input_ref = ? ORDER BY set_no", (project_id, input_ref)):
            out[int(r["set_no"])] = {"revision": int(r["revision"]), "excluded": loads(r["excluded_json"], [])}
        return out

    def sca_package_text(self, project_id: int, input_ref: str, set_no: int) -> dict | None:
        """Текст набора (Объяснение, выбор по AST, целевая версия и отметки) или None – текста ещё нет."""
        row = self._one("SELECT * FROM sca_package_texts WHERE project_id = ? AND input_ref = ? AND set_no = ?",
                        (project_id, input_ref, int(set_no)))
        if row is not None:
            row["ast"] = loads(row.pop("ast_json"), {})
        return row

    @staticmethod
    def _bump_set(c: Connection, project_id: int, input_ref: str, set_no: int, ts: str) -> None:
        c.execute("""INSERT INTO sca_defect_sets(project_id, input_ref, set_no, revision, updated_at)
                     VALUES (?, ?, ?, 1, ?) ON CONFLICT(project_id, input_ref, set_no) DO UPDATE SET
                     revision = sca_defect_sets.revision + 1, updated_at = excluded.updated_at""",
                  (project_id, input_ref, int(set_no), ts))

    @staticmethod
    def _set_revision(c: Connection, project_id: int, input_ref: str, set_no: int) -> int:
        row = c.execute("SELECT revision FROM sca_defect_sets WHERE project_id = ? AND input_ref = ? AND set_no = ?",
                        (project_id, input_ref, int(set_no))).fetchone()
        return int(row[0]) if row else 0

    def sca_leave_sets(self, c: Connection, project_id: int, input_ref: str, hub_ids: list[str],
                       ts: str) -> None:
        """Находки сменили исход с «Обновить» на другой (ADR-0091 п. 6): выходят из своих наборов, наборы получают
        новую редакцию; пометка «без дефекта» снимается. Вызывается в транзакции записи решения."""
        for hub_id in hub_ids:
            row = c.execute("SELECT set_no, pending_reason FROM sca_set_members WHERE project_id = ? AND hub_id = ?"
                            " AND input_ref = ?", (project_id, hub_id, input_ref)).fetchone()
            if row is not None and str(row["pending_reason"] or ""):
                # место нужно выбрать заново после слияния пакетов (план dev17, п. 4.1): участник остаётся в
                # выделенном наборе с причиной – перевод в набор 0 столкнул бы номера дефектов при принятии Hub
                continue
            set_no = 0 if row is None else row[0]  # None – «без дефекта»: в наборе находки не было
            c.execute("DELETE FROM sca_set_members WHERE project_id = ? AND hub_id = ? AND input_ref = ?",
                      (project_id, hub_id, input_ref))
            if set_no is not None:
                self._bump_set(c, project_id, input_ref, int(set_no), ts)

    def move_sca_member(self, project_id: int, input_ref: str, hub_id: str, set_no: int | None, reason: str,
                        expect: dict[int, int], *, expect_input_ref: str | None = None,
                        expect_pkg_rev: int | None = None) -> dict[int, dict]:
        """Перенос находки в набор set_no (0 – по умолчанию, NEW_SET – новый набор со следующим номером) или «без
        дефекта» (None, с обоснованием reason). expect – {set_no: редакция}, которые видел оператор, для обоих наборов: не совпало –
        StaleReview, ничего не меняется. Оба набора получают новую редакцию одной транзакцией."""
        if set_no is None and not str(reason or "").strip():
            raise ValueError("«Без дефекта» сохраняется только с обоснованием.")
        ts = now_iso()
        with self._tx() as c:
            # карточка показывала этот пакет и эту ревизию идентичности находки (план dev17, п. 4.3, 4.5): после
            # перехода идентичности номера и редакции наборов разных групп совпадают, поэтому сверяются оба
            from app.sca_contract import input_ref as package_ref
            own = c.execute("SELECT data_json, pkg_ecosystem, pkg_name, pkg_source, pkg_note, pkg_scope, pkg_rev"
                            " FROM findings WHERE project_id = ? AND hub_id = ?", (project_id, hub_id)).fetchone()
            if expect_input_ref is not None or expect_pkg_rev is not None:
                now_ref = package_ref(*package_identity.of(package_identity.with_package(dict(own)))) if own else ""
                if own is None or (expect_input_ref is not None and now_ref != expect_input_ref) or (
                        expect_pkg_rev is not None and int(own["pkg_rev"] or 0) != int(expect_pkg_rev)):
                    raise StaleReview("Пакет находки изменился после открытия карточки: обновите карточку.", "set")
            else:
                # форма без этих полей (страница до обновления) – только пока идентичность не менялась и место не ждёт
                # нового выбора после слияния (ревью Kimi, шаг 3, круг 5)
                waiting = c.execute("SELECT pending_reason FROM sca_set_members WHERE project_id = ? AND hub_id = ?",
                                    (project_id, hub_id)).fetchone()
                if (own is not None and int(own["pkg_rev"] or 0) != 0) or (
                        waiting is not None and str(waiting["pending_reason"] or "")):
                    raise StaleReview("Пакет находки изменился после открытия карточки: обновите карточку.", "set")
            row = c.execute("SELECT set_no, input_ref FROM sca_set_members WHERE project_id = ? AND hub_id = ?",
                            (project_id, hub_id)).fetchone()
            if row is not None and row["input_ref"] != input_ref:
                raise StaleReview("Находка относится к другой версии компонента: обновите карточку.", "set")
            current = 0 if row is None else (None if row[0] is None else int(row[0]))
            fresh = None
            if set_no == NEW_SET:  # новый набор: следующий номер – в этой же транзакции
                top = c.execute("SELECT MAX(n) FROM (SELECT set_no AS n FROM sca_defect_sets WHERE project_id = ?"
                                " AND input_ref = ? UNION ALL SELECT set_no FROM sca_set_members WHERE project_id = ?"
                                " AND input_ref = ? AND set_no IS NOT NULL)",
                                (project_id, input_ref, project_id, input_ref)).fetchone()[0]
                set_no = fresh = int(top or 0) + 1
            for number in {x for x in (current, set_no) if x is not None and x != fresh}:
                # редакции затронутых наборов обязательны: иначе перенос из устаревшей карточки прошёл бы молча
                if number not in expect or self._set_revision(c, project_id, input_ref, number) != int(expect[number]):
                    raise StaleReview("Набор дефекта изменили в другой вкладке: обновите карточку.", "set")
            if set_no == 0:
                c.execute("DELETE FROM sca_set_members WHERE project_id = ? AND hub_id = ?", (project_id, hub_id))
            else:
                c.execute("""INSERT INTO sca_set_members(project_id, hub_id, input_ref, set_no, no_defect_reason,
                                                         updated_at) VALUES (?, ?, ?, ?, ?, ?)
                             ON CONFLICT(project_id, hub_id) DO UPDATE SET input_ref = excluded.input_ref,
                             set_no = excluded.set_no, no_defect_reason = excluded.no_defect_reason,
                             pending_reason = '', updated_at = excluded.updated_at""",
                          (project_id, hub_id, input_ref, set_no, str(reason or "").strip() if set_no is None else "",
                           ts))
            for number in {x for x in (current, set_no) if x is not None}:
                self._bump_set(c, project_id, input_ref, number, ts)
            self._touch(c, project_id, ts)
        return self.sca_sets(project_id, input_ref)

    def save_sca_exclusion(self, project_id: int, hub_id: str, set_no: int, vuln_key: str, ids: Iterable[str],
                           reason: str, exclude: bool, *, expect_set_revision: int, expect_fp: str) -> dict[int, dict]:
        """Исключение уязвимости из текста набора с обоснованием или возврат в текст (ADR-0091 п. 9). Элемент списка
        исключений – {"id", "ids", "reason"}; прежние элементы с теми же идентификаторами заменяются. Одна транзакция
        со сверкой отпечатка пакета, который видел оператор, и редакции набора: не совпало – StaleReview, ничего не
        записано. Исключение меняет только текст, не применимость и не проверку цели (ADR-0094 Р3.3)."""
        reason = str(reason or "").strip()
        if exclude and not reason:
            raise ValueError("Исключение из текста сохраняется только с обоснованием.")
        ids = sorted({str(i) for i in ids if str(i or "").strip()})
        if not ids:
            raise ValueError("Нет идентификаторов уязвимости.")
        ts = now_iso()
        with self._tx() as c:
            state = self._sca_package_state(c, project_id, hub_id)
            if state is None:
                raise StaleReview("Проект или находка исчезли.", "deleted")
            if self._sca_state_fingerprint(state) != expect_fp:
                raise StaleReview("Пакет изменился после открытия карточки: обновите её.", "package")
            ref = state["input_ref"]
            if self._set_revision(c, project_id, ref, set_no) != int(expect_set_revision):
                raise StaleReview("Набор дефекта изменили в другой вкладке: обновите карточку.", "set")
            row = c.execute("SELECT excluded_json FROM sca_defect_sets WHERE project_id = ? AND input_ref = ?"
                            " AND set_no = ?", (project_id, ref, int(set_no))).fetchone()
            items = []
            for item in loads(row[0], []) if row else []:
                own = item.get("ids") or [item.get("id")] if isinstance(item, dict) else [item]
                if not {str(i) for i in own} & set(ids):
                    items.append(item)
            if exclude:
                items.append({"id": str(vuln_key), "ids": ids, "reason": reason})
            c.execute("""INSERT INTO sca_defect_sets(project_id, input_ref, set_no, revision, excluded_json, updated_at)
                         VALUES (?, ?, ?, 1, ?, ?) ON CONFLICT(project_id, input_ref, set_no) DO UPDATE SET
                         revision = sca_defect_sets.revision + 1, excluded_json = excluded.excluded_json,
                         updated_at = excluded.updated_at""", (project_id, ref, int(set_no), dumps(items), ts))
            self._touch(c, project_id, ts)
        return self.sca_sets(project_id, ref)

    def save_sca_package_text(self, project_id: int, input_ref: str, set_no: int, *, expect_revision: int,
                              explanation: str, ast: dict, target_version: str, target_basis: str,
                              version_checked_sig: str, text_checked_sig: str, text_sig: str,
                              member: str = "", residual_checked_sig: str = "",
                              recommendation_note: str = "", expect_fp: str | None = None) -> dict:
        """Текст набора (ADR-0091 п. 13): одна запись на набор, правка – с проверкой редакции (StaleReview). member –
        находка, из карточки которой правят текст: в той же транзакции сверяется, что она всё ещё в наборе set_no;
        expect_fp – отпечаток пакета, по которому построены подписи отметок: другой – StaleReview "package", ничего
        не записано (ADR-0094 Р4.5)."""
        if str(target_basis or "") not in STORED_TARGET_BASES:  # основание цели – из закрытого перечня
            raise ValueError(f"Неизвестное основание целевой версии: {target_basis!r}")
        ts = now_iso()
        with self._tx() as c:
            if expect_fp is not None and member and self._sca_defect_fingerprint(c, project_id, member) != expect_fp:
                raise StaleReview("Пакет изменился, пока сохранялся текст: обновите карточку.", "package")
            if member:
                place = c.execute("SELECT set_no, input_ref FROM sca_set_members WHERE project_id = ? AND hub_id = ?",
                                  (project_id, member)).fetchone()
                now = 0 if place is None else place["set_no"]
                if (place is not None and place["input_ref"] != input_ref) or now != int(set_no):
                    raise StaleReview("Находку перенесли в другой набор дефекта: обновите карточку.", "text")
            row = c.execute("SELECT revision FROM sca_package_texts WHERE project_id = ? AND input_ref = ?"
                            " AND set_no = ?", (project_id, input_ref, int(set_no))).fetchone()
            if (int(row[0]) if row else 0) != int(expect_revision):
                raise StaleReview("Текст дефекта изменили в другой вкладке: обновите карточку.", "text")
            c.execute("""INSERT INTO sca_package_texts(project_id, input_ref, set_no, revision, explanation, ast_json,
                                                       target_version, target_basis, version_checked_sig,
                                                       text_checked_sig, text_sig, updated_at, residual_checked_sig,
                                                       recommendation_note)
                         VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                         ON CONFLICT(project_id, input_ref, set_no) DO UPDATE SET
                         revision = sca_package_texts.revision + 1, explanation = excluded.explanation,
                         ast_json = excluded.ast_json, target_version = excluded.target_version,
                         target_basis = excluded.target_basis, version_checked_sig = excluded.version_checked_sig,
                         text_checked_sig = excluded.text_checked_sig, text_sig = excluded.text_sig,
                         updated_at = excluded.updated_at, residual_checked_sig = excluded.residual_checked_sig,
                         recommendation_note = excluded.recommendation_note""",
                      (project_id, input_ref, int(set_no), str(explanation or ""), dumps(ast or {}),
                       str(target_version or "").strip(), str(target_basis or ""), str(version_checked_sig or ""),
                       str(text_checked_sig or ""), str(text_sig or ""), ts, str(residual_checked_sig or ""),
                       str(recommendation_note or "")))
            self._touch(c, project_id, ts)
        return self.sca_package_text(project_id, input_ref, set_no) or {}

    APPLICABILITY_DECISIONS = ("applies", "not_current", "not_product")

    def save_sca_applicability(self, project_id: int, hub_id: str, vuln_key: str, ids: Iterable[str],
                               decision: str, reason: str, *, expect_revision: int, expect_research_revision: int,
                               expect_fp: str) -> dict:
        """Решение оператора о применимости класса уязвимости (ADR-0094 Р3, Р4.5). Одна транзакция со сверкой: отпечаток
        пакета, который видел оператор (expect_fp; в нём – все решения о применимости), ревизия исследования
        (expect_research_revision) и редакция решения с этим ключом (expect_revision, 0 – решения не было); не совпало
        – StaleReview, ничего не записано. Состав класса ids вычисляет маршрут по снимку того же отпечатка.
        Запись – по текущему основному идентификатору класса; прежние решения, чьи идентификаторы пересекаются с
        классом, снимаются: после сдвига основного идентификатора не остаётся действующих решений-сирот. decision "" –
        снять решение. Строки не удаляются: снятое решение – строка с пустым решением и новой редакцией, поэтому
        «решение → снятие» не возвращает пакет к прежнему отпечатку и устаревшая вкладка получает отказ.
        Возвращает строку решения."""
        decision = str(decision or "")
        if decision and decision not in self.APPLICABILITY_DECISIONS:
            raise ValueError("неизвестное решение о применимости")
        ids = sorted({str(i) for i in ids if str(i or "").strip()})
        if not str(vuln_key or "").strip() or str(vuln_key) not in ids:
            raise ValueError("ключ решения – основной идентификатор класса")
        ts = now_iso()
        with self._tx() as c:
            state = self._sca_package_state(c, project_id, hub_id)
            if state is None:
                raise StaleReview("Проект или находка исчезли.", "deleted")
            if self._sca_state_fingerprint(state) != expect_fp:
                raise StaleReview("Пакет изменился после открытия карточки: обновите её.", "package")
            research = state.get("research") or {}
            if int(research.get("revision") or 0) != int(expect_research_revision):
                raise StaleReview("Исследование компонента обновлено: обновите карточку.", "research")
            ref = state["input_ref"]
            rows = state.get("applicability") or {}
            now = rows.get(str(vuln_key))
            if (int(now["revision"]) if now else 0) != int(expect_revision):
                raise StaleReview("Решение о применимости изменили в другой вкладке: обновите карточку.", "revision")
            for key, row in rows.items():
                if key != str(vuln_key) and row.get("decision") and set(row.get("ids") or []) & set(ids):
                    c.execute("UPDATE sca_applicability SET decision = '', reason = '', revision = revision + 1,"
                              " updated_at = ? WHERE project_id = ? AND input_ref = ? AND vuln_key = ?",
                              (ts, project_id, ref, key))
            c.execute("""INSERT INTO sca_applicability(project_id, input_ref, vuln_key, ids_json, decision, reason,
                                                       research_revision, revision, updated_at)
                         VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)
                         ON CONFLICT(project_id, input_ref, vuln_key) DO UPDATE SET ids_json = excluded.ids_json,
                         decision = excluded.decision, reason = excluded.reason,
                         research_revision = excluded.research_revision, revision = sca_applicability.revision + 1,
                         updated_at = excluded.updated_at""",
                      (project_id, ref, str(vuln_key), dumps(ids), decision, str(reason or "").strip() if decision else "",
                       int(research.get("revision") or 0), ts))
            self._touch(c, project_id, ts)
            found = c.execute("SELECT * FROM sca_applicability WHERE project_id = ? AND input_ref = ? AND vuln_key = ?",
                              (project_id, ref, str(vuln_key))).fetchone()
        out = dict(found)
        out["ids"] = loads(out.pop("ids_json"), [])
        return out

    def set_reviewed(self, project_id: int, hub_id: str, reviewed: bool, *, expect: dict | None = None,
                     code_hash: str | None = None, code_chars: int = 0) -> dict:
        """Отметка «Проверено» отдельно от решения (клавиша v): решение и комментарий не меняются, номер редакции
        растёт. expect, code_hash, code_chars – как в save_review. Отложенную находку отметить проверенной
        нельзя: ValueError с текстом по-русски. Решения ещё не было – оно создаётся пустым."""
        ts = now_iso()
        with self._tx() as c:
            source = self._source(c, project_id, hub_id)
            if source is None:
                raise StaleReview("Находки нет в проекте.", "source")
            self._check_expect(c, project_id, hub_id, source, expect)
            old = c.execute("SELECT decision, final_verdict, final_comment, reviewed, reviewed_at, code_hash, code_chars,"
                            " answer_sig, finding_sig, verdict_id FROM reviews WHERE project_id = ? AND hub_id = ?",
                            (project_id, hub_id)).fetchone()
            if reviewed and old is not None and old["decision"] == "later":
                raise ValueError("Отложенная находка остаётся непроверенной: сначала выберите «Согласен» или "
                                 "«Не согласен».")
            if reviewed and old is not None and old["decision"] == "agree" and self._answer_moved(
                    c, project_id, source["data"], old["answer_sig"]):
                # «Согласен с агентом» принято по другому ответу: проверенным его не сделать, пока человек не
                # сверит решение с текущим ответом и не сохранит его заново (сохранение ставит новый отпечаток)
                raise StaleReview("Решение «Согласен с агентом» принято по прежнему ответу агента.", "answer")
            if reviewed:
                reviewed_at = old["reviewed_at"] if old is not None and old["reviewed"] and old["reviewed_at"] else ts
            else:
                reviewed_at = None
            if old is not None and (old["decision"] or old["final_verdict"] or old["final_comment"]):
                # Отметка не перепривязывает решение: finding_sig и отпечаток кода остаются теми, по которым человек
                # принял решение. Проверенным можно назвать только решение, принятое по текущей версии находки и по
                # коду, который в клоне сейчас; иначе его сначала подтверждают заново (сохраняют решение).
                if reviewed and old["finding_sig"] != source_signature(source):
                    raise StaleReview("Решение принято по прежней версии находки.", "source")
                if reviewed and code_hash is not None and old["code_hash"] != code_hash:
                    raise StaleReview("Код изменился после решения.", "code")
                c.execute("UPDATE reviews SET reviewed = ?, reviewed_at = ?, revision = revision + 1,"
                          " updated_at = ? WHERE project_id = ? AND hub_id = ?",
                          (1 if reviewed else 0, reviewed_at, ts, project_id, hub_id))
            else:
                if code_hash is None:
                    code_hash, code_chars = (old["code_hash"], old["code_chars"]) if old is not None else ("", 0)
                c.execute("""
                    INSERT INTO reviews(project_id, hub_id, reviewed, reviewed_at, finding_sig, revision, updated_at,
                                        code_hash, code_chars)
                    VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?)
                    ON CONFLICT(project_id, hub_id) DO UPDATE SET
                        reviewed = excluded.reviewed, reviewed_at = excluded.reviewed_at,
                        finding_sig = excluded.finding_sig, revision = reviews.revision + 1,
                        updated_at = excluded.updated_at, code_hash = excluded.code_hash,
                        code_chars = excluded.code_chars""",
                          (project_id, hub_id, 1 if reviewed else 0, reviewed_at, source_signature(source), ts,
                           code_hash or "", int(code_chars or 0)))
            if reviewed:
                self._settle_code_notice(c, project_id)
            self._touch(c, project_id, ts)
            from app.journal import review_event
            review_event(c, project_id, hub_id)
            return dict(c.execute("SELECT * FROM reviews WHERE project_id = ? AND hub_id = ?",
                                  (project_id, hub_id)).fetchone())

    def mark_entered(self, project_id: int, hub_id: str, entered: bool = True,
                     revision: int | None = None, entered_hash: str = "",
                     check: Callable[[Connection], None] | None = None,
                     entered_parts: str = "", entered_origin: str = "manual",
                     entered_defect_id: int | None = None, entered_op_id: int | None = None,
                     entered_defect_revision: int = 0, entered_decision_hash: str = "") -> dict | None:
        """Отметка «Внесено в Hub» (человек сам вставил статус и комментарий в Hub) с датой; снять – entered=False.

        Номер редакции решения не меняется: отметка подтверждает, что в Hub попал текст редакции revision. Если
        revision задан, а решение с тех пор сохранили заново (другая вкладка), отметка не ставится: None. Решения
        ещё не было (revision не задан) – оно создаётся пустым. entered_hash – отпечаток текста для Hub (text_hash)
        на момент отметки: если текст потом изменится, например после смены статусов Hub в настройках, карточка это
        покажет; entered_parts – из чего этот текст собран (JSON отпечатков, О8): по нему карточка называет, что
        изменилось. check(c) – дополнительная проверка в той же транзакции до записи (дефект SCA: снимок пакета тот же, по
        которому проверен текст); исключение откатывает запись. Возвращает строку решения."""
        if revision is not None and (not isinstance(revision, int) or isinstance(revision, bool) or revision < 0):
            raise ValueError("нужен номер редакции решения")
        ts = now_iso()
        with self._tx() as c:
            if c.execute("SELECT 1 FROM findings WHERE project_id = ? AND hub_id = ?",
                         (project_id, hub_id)).fetchone() is None:
                return None
            row = c.execute("SELECT revision FROM reviews WHERE project_id = ? AND hub_id = ?",
                            (project_id, hub_id)).fetchone()
            if revision is not None and int(row["revision"] if row is not None else 0) != revision:
                return None
            if check is not None:
                check(c)
            if row is None:
                c.execute("INSERT INTO reviews(project_id, hub_id, revision, updated_at) VALUES (?, ?, 0, ?)",
                          (project_id, hub_id, ts))
            c.execute("UPDATE reviews SET entered_hub = ?, entered_hub_at = ?, entered_text_hash = ?,"
                      " entered_parts = ?, entered_origin = ?, entered_defect_id = ?, entered_op_id = ?,"
                      " entered_defect_revision = ?, entered_decision_hash = ?, updated_at = ?,"
                      " defect_dropped = CASE WHEN ? <> 0 THEN '' ELSE defect_dropped END WHERE project_id = ? AND hub_id = ?",
                      (1 if entered else 0, ts if entered else None, entered_hash if entered else "",
                       entered_parts if entered else "", entered_origin if entered else "",
                       entered_defect_id if entered else None, entered_op_id if entered else None,
                       entered_defect_revision if entered else 0,
                       (entered_decision_hash if entered_origin == "defect" else entered_decision_hash or entered_hash) if entered else "", ts,
                       # пометку «выбыла из дефекта» снимает только отметка оператора; автоматическая (дефект, статус,
                       # позднее последствие прежнего подтверждения) её не трогает (ревью 31.10)
                       1 if entered and entered_origin == "manual" else 0, project_id, hub_id))
            self._touch(c, project_id, ts)
            return dict(c.execute("SELECT * FROM reviews WHERE project_id = ? AND hub_id = ?",
                                  (project_id, hub_id)).fetchone())

    def dropped_findings(self, project_id: int, defect_id: int | None = None) -> list[dict]:
        """Находки с пометкой «выбыла из дефекта» (все или одного дефекта – по владельцу записи): id, hub_id, kind и
        сведения пометки (dropped_info)."""
        rows = self._all("SELECT f.id, f.hub_id, f.kind, r.defect_dropped FROM reviews r JOIN findings f"
                         " ON f.project_id = r.project_id AND f.hub_id = r.hub_id"
                         " WHERE r.project_id = ? AND COALESCE(r.defect_dropped, '') <> ''"
                         " ORDER BY f.pos, f.id", (project_id,))
        found = []
        for row in rows:
            info = loads(row.pop("defect_dropped") or "", {}) or {}
            if defect_id is None or info.get("defect_id") == defect_id:
                found.append({**row, "dropped_info": info})
        return found

    def clear_defect_dropped(self, project_id: int, hub_id: str, shown: str) -> bool:
        """«Оставить как есть»: оператор решил, что находке дефект не нужен; shown – пометка, которую он видел (другая –
        отказ, обновите карточку)."""
        with self._tx() as c:
            changed = c.execute("UPDATE reviews SET defect_dropped = '' WHERE project_id = ? AND hub_id = ?"
                                " AND defect_dropped <> '' AND defect_dropped = ?", (project_id, hub_id, shown)).rowcount
            if changed:
                self._touch(c, project_id, now_iso())
        return bool(changed)

    def mark_copied(self, project_id: int, hub_id: str, revision: int) -> str | None:
        """Отмечает, что текст редакции revision скопирован в буфер обмена; возвращает время.

        Если решение с тех пор сохранили заново (другая вкладка, правка комментария), отметка не ставится: None.
        Отметку «Внесено в Hub» копирование не ставит: её ставит человек (mark_entered).
        """
        if not isinstance(revision, int) or isinstance(revision, bool) or revision < 1:
            raise ValueError("нужен номер редакции решения")
        ts = now_iso()
        with self._tx() as c:
            changed = c.execute("UPDATE reviews SET copied_at = ?, updated_at = ?"
                                " WHERE project_id = ? AND hub_id = ? AND revision = ?",
                                (ts, ts, project_id, hub_id, revision)).rowcount
            if changed:
                self._touch(c, project_id, ts)
        return ts if changed else None

    def review_stats(self, project_id: int) -> dict:
        """Ход разбора по находкам текущей выгрузки (без пропавших из неё). SAST: sast, reviewed, agree, disagree,
        later, copied, entered (внесено в Hub), with_verdict (есть вердикт модели); SCA: sca, sca_reviewed,
        sca_entered; missing – сколько находок нет в новой выгрузке. По происхождению решения (бэклог 98, план dev18):
        reviewed_operator / sca_reviewed_operator – решение оператора (не «Отложить», происхождение operator или прежнее
        пустое) с «Проверено»; entered_operator / sca_entered_operator – их подмножество с отметкой «Внесено в Hub»;
        hub_decisions / sca_hub_decisions – решения из Hub (hub_sync, hub_defect) независимо от отметок."""
        row = self._one(f"""
            SELECT COUNT(*) FILTER (WHERE f.kind = 'SAST') AS sast,
                   COUNT(*) FILTER (WHERE f.kind = 'SAST' AND COALESCE(r.reviewed, 0) = 1) AS reviewed,
                   COUNT(*) FILTER (WHERE f.kind = 'SAST' AND r.decision = 'agree') AS agree,
                   COUNT(*) FILTER (WHERE f.kind = 'SAST' AND r.decision = 'disagree') AS disagree,
                   COUNT(*) FILTER (WHERE f.kind = 'SAST' AND r.decision = 'later') AS later,
                   COUNT(*) FILTER (WHERE f.kind = 'SAST' AND r.copied_at IS NOT NULL) AS copied,
                   COUNT(*) FILTER (WHERE f.kind = 'SAST' AND {_ENTERED_HUB_SQL} = 1) AS entered,
                   COUNT(*) FILTER (WHERE f.kind = 'SAST' AND c.verdict_id IS NOT NULL) AS with_verdict,
                   COUNT(*) FILTER (WHERE f.kind = 'SCA') AS sca,
                   COUNT(*) FILTER (WHERE f.kind = 'SCA' AND COALESCE(r.reviewed, 0) = 1) AS sca_reviewed,
                   COUNT(*) FILTER (WHERE f.kind = 'SCA' AND {_ENTERED_HUB_SQL} = 1) AS sca_entered,
                   COUNT(*) FILTER (WHERE f.kind = 'SAST' AND COALESCE(r.reviewed, 0) = 1 AND COALESCE(r.decision, '') NOT IN ('', 'later') AND COALESCE(r.decision_origin, '') IN ('operator', '')) AS reviewed_operator,
                   COUNT(*) FILTER (WHERE f.kind = 'SAST' AND COALESCE(r.reviewed, 0) = 1 AND COALESCE(r.decision, '') NOT IN ('', 'later') AND COALESCE(r.decision_origin, '') IN ('operator', '')
                                    AND {_ENTERED_HUB_SQL} = 1) AS entered_operator,
                   COUNT(*) FILTER (WHERE f.kind = 'SAST' AND COALESCE(r.decision, '') <> '' AND r.decision_origin IN ('hub_sync', 'hub_defect')) AS hub_decisions,
                   COUNT(*) FILTER (WHERE f.kind = 'SCA' AND COALESCE(r.reviewed, 0) = 1 AND COALESCE(r.decision, '') NOT IN ('', 'later') AND COALESCE(r.decision_origin, '') IN ('operator', '')) AS sca_reviewed_operator,
                   COUNT(*) FILTER (WHERE f.kind = 'SCA' AND COALESCE(r.reviewed, 0) = 1 AND COALESCE(r.decision, '') NOT IN ('', 'later') AND COALESCE(r.decision_origin, '') IN ('operator', '')
                                    AND {_ENTERED_HUB_SQL} = 1) AS sca_entered_operator,
                   COUNT(*) FILTER (WHERE f.kind = 'SCA' AND COALESCE(r.decision, '') <> '' AND r.decision_origin IN ('hub_sync', 'hub_defect')) AS sca_hub_decisions
              FROM findings f
              LEFT JOIN reviews r ON r.project_id = f.project_id AND r.hub_id = f.hub_id
              LEFT JOIN cases c ON c.project_id = f.project_id AND c.hub_id = f.hub_id
             WHERE f.project_id = ? AND f.missing = 0""", (project_id,))
        stats = row or {}
        stats["missing"] = int(self._scalar("SELECT COUNT(*) FROM findings WHERE project_id = ? AND missing = 1",
                                            (project_id,)) or 0)
        return stats

    # ------------------------------------------------------------------ вопросы к модели

    @staticmethod
    def _question_row(row: dict) -> dict:
        row["answer_data"] = loads(row.pop("answer_json"), {})
        row["stats"] = loads(row.pop("stats_json"), {})
        return row

    def add_question(self, project_id: int, hub_id: str, question: str, model: str, *, case_hash: str = "",
                     verdict_id: int | None = None, execution: Mapping[str, Any] | None = None) -> int:
        """Вопрос к модели по находке («Спросить модель»), ответ ещё не получен (state = pending). case_hash и
        verdict_id – какой срез кода и какой прежний ответ модели получила вместе с вопросом. execution – снимок
        исполнителя вопроса (ADR-0102), пишется той же транзакцией."""
        ts = now_iso()
        with self._tx() as c:
            execution_id = self._insert_execution(c, execution, ts) if execution is not None else None
            question_id = int(c.execute(
                "INSERT INTO questions(project_id, hub_id, question, model, case_hash, verdict_id, created_at,"
                " execution_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)" " RETURNING id",
                (project_id, hub_id, question, model, case_hash, verdict_id, ts, execution_id)).fetchone()[0])
            self._touch(c, project_id, ts)
        return question_id

    def finish_question(self, question_id: int, *, answer: str = "", answer_data: dict | None = None,
                        stats: dict | None = None, error: str = "") -> bool:
        """Ответ модели на вопрос (state = done) или ошибка (error задан – state = error); stats – замеры ответа
        (LlmStats.to_dict(): скорость в ток/с и прочее). False – вопроса нет или он уже закрыт."""
        ts = now_iso()
        with self._tx() as c:
            return c.execute("UPDATE questions SET answer = ?, answer_json = ?, stats_json = ?, state = ?, error = ?,"
                             " answered_at = ? WHERE id = ? AND state = 'pending'",
                             (answer, dumps(answer_data or {}), dumps(stats or {}), "error" if error else "done",
                              error, ts, question_id)).rowcount > 0

    def get_question(self, question_id: int) -> dict | None:
        row = self._one("SELECT * FROM questions WHERE id = ?", (question_id,))
        return self._question_row(row) if row else None

    def list_questions(self, project_id: int, hub_id: str) -> list[dict]:
        """История вопросов к модели по находке, от ранних к поздним."""
        return [self._question_row(row) for row in self._all(
            "SELECT * FROM questions WHERE project_id = ? AND hub_id = ? ORDER BY id", (project_id, hub_id))]

    def next_pending_question(self) -> dict | None:
        """Самый ранний вопрос без ответа (для фоновой очереди вопросов)."""
        row = self._one("SELECT * FROM questions WHERE state = 'pending' ORDER BY id LIMIT 1")
        return self._question_row(row) if row else None

    #: Выборка находок SCA для сбора пакетов – одна на оба чтения: под замком соединения и внутри транзакции,
    #: поэтому состав проекта считается одинаково, где бы он ни считался.
    _SCA_COMPONENTS_SQL = """
            SELECT f.id, f.hub_id, f.cvss, f.urgent, f.codebase, f.data_json,
                   f.pkg_ecosystem, f.pkg_name, f.pkg_source, f.pkg_note, f.pkg_scope,
                   COALESCE(r.reviewed, 0) AS reviewed, {_ENTERED_HUB_SQL} AS entered_hub,
                   COALESCE(r.decision, '') AS decision
              FROM findings f
              LEFT JOIN reviews r ON r.project_id = f.project_id AND r.hub_id = f.hub_id
             WHERE f.project_id = ? AND f.kind IN ({marks}) {missing}
             ORDER BY f.pos, f.id"""
    _SCA_MISSING_CLAUSE = "AND f.missing = 0"

    @classmethod
    def _sca_component_sql(cls, kinds: list[str], include_missing: bool) -> str:
        return cls._SCA_COMPONENTS_SQL.format(_ENTERED_HUB_SQL=_ENTERED_HUB_SQL, marks=",".join("?" * len(kinds)),
                                              missing="" if include_missing else cls._SCA_MISSING_CLAUSE)

    # ------------------------------------------------------------------ SCA

    def sca_components(self, project_id: int, kinds: Iterable[str] = ("SCA",),
                       include_missing: bool = False) -> list[dict]:
        """Пакеты SCA проекта – группы «экосистема + компонент + версия» (app/ecosystem.py: пакеты с одним именем и
        версией в разных экосистемах – разные группы) по находкам текущей выгрузки, от самых опасных:
        [{ecosystem, component, version, findings, hub_ids, finding_ids, cvss (наибольший), urgent, cve, vuln_ids
        (AST-…, GHSA-…), fixed_versions (версии исправления из Hub), cwe, codebases, build_types, dep_paths,
        reviewed, entered, cvss_versions (наибольший балл каждой версии оценки, "" – версия не указана),
        cvss_counts (сколько находок с баллом этой версии)}]. Кода в этих сведениях нет."""
        kinds = list(kinds)
        return self._sca_component_groups(self._all(self._sca_component_sql(kinds, include_missing),
                                                    (project_id, *kinds)))

    def sca_usages(self, project_id: int, ref: str) -> list[dict]:
        """Где используется версия компонента (input_ref исследования, OR-04): находки SCA текущей выгрузки этого
        пакета – [{id, hub_id, codebase, dep_path, build_type}] по кодовым базам и ID. Только связи выгрузки."""
        from app.sca import package_key
        from app.sca_contract import input_ref as package_ref
        usages = []
        for row in self._all(self._sca_component_sql(["SCA"], False), (project_id, "SCA")):
            data = package_identity.with_package(dict(row))
            eco, name, ver = package_identity.of(data)  # эффективная тройка (план dev17, п. 4.3)
            # тот же ключ, что у строки задания (sca.package_key): имя и версия очищены одинаково
            key = package_key({"ecosystem": eco, "component": name, "version": ver})
            if package_ref(*key) != ref:
                continue
            usages.append({"id": row["id"], "hub_id": row["hub_id"], "codebase": row["codebase"] or "",
                           "dep_path": str(data.get("dep_path") or ""), "build_type": str(data.get("build_type") or "")})
        return sorted(usages, key=lambda u: (u["codebase"], u["hub_id"]))

    @staticmethod
    def _sca_component_groups(rows: Iterable[Mapping[str, Any]]) -> list[dict]:
        """Чистая агрегация уже прочитанных находок в пакеты: из базы здесь не берётся ничего, поэтому годится и под
        замком соединения, и внутри транзакции, где замок уже держится."""
        groups: dict[tuple[str, str, str], dict] = {}
        for row in rows:
            # эффективная тройка (план dev17, п. 4.3): строки без колонок pkg_* – по Type и компоненту, как раньше
            data = package_identity.with_package(dict(row))
            key = package_identity.of(data)
            g = groups.setdefault(key, {"ecosystem": key[0], "component": key[1], "version": key[2], "findings": 0,
                                        "hub_ids": [],
                                        "finding_ids": [], "cvss": None, "urgent": False, "cve": [], "vuln_ids": [],
                                        "fixed_versions": [], "cwe": [], "codebases": [], "build_types": [],
                                        "dep_paths": [], "reviewed": 0, "entered": 0, "todo": 0, "cvss_versions": {},
                                        "cvss_counts": {}, "identity_source": "", "identity_notes": [],
                                        "export_components": []})
            pkg = data["package"]
            if pkg.get("source") == "hub":
                g["identity_source"] = "hub"
            for note in package_identity.marks(data):
                if note not in g["identity_notes"]:
                    g["identity_notes"].append(note)
            component = str(data.get("component") or "")
            if component and component not in g["export_components"]:  # имя в выгрузке – для пометок (п. 4.6)
                g["export_components"].append(component)
            g["findings"] += 1
            g["hub_ids"].append(row["hub_id"])
            g["finding_ids"].append(row["id"])
            if row["cvss"] is not None:
                if g["cvss"] is None or row["cvss"] > g["cvss"]:
                    g["cvss"] = row["cvss"]
                # отдельного поля с версией оценки у находки нет (app/models.py): версия берётся из прочих
                # колонок выгрузки, а если её там нет – остаётся неизвестной (app/cvss.py)
                version = cvss.version_of(data)
                known = g["cvss_versions"].get(version)
                if known is None or row["cvss"] > known:
                    g["cvss_versions"][version] = row["cvss"]
                g["cvss_counts"][version] = g["cvss_counts"].get(version, 0) + 1
            g["urgent"] = g["urgent"] or bool(row["urgent"])
            g["reviewed"] += int(row["reviewed"])
            g["entered"] += int(row["entered_hub"])
            # «к разбору»: находка не внесена в Hub и не отложена оператором. Считается по находке, а не
            # разностью сумм: одна находка может быть и отложенной, и внесённой (ревью Codex 08.11)
            g["todo"] += int(not row["entered_hub"] and row["decision"] != "later")
            for field, values in (("cve", data.get("cve")), ("vuln_ids", data.get("vuln_ids")),
                                  ("cwe", data.get("cwe")), ("fixed_versions", [data.get("fixed_version")]),
                                  ("codebases", [row["codebase"]]), ("build_types", [data.get("build_type")]),
                                  ("dep_paths", [data.get("dep_path")])):
                for value in values or []:
                    if value and str(value) not in g[field]:
                        g[field].append(str(value))
        return sorted(groups.values(), key=lambda g: (not g["urgent"], -(g["cvss"] or 0.0), g["component"].casefold(),
                                                      g["version"], g["ecosystem"]))

    @staticmethod
    def _sca_answer_row(row: dict) -> dict:
        row["ids"] = loads(row.pop("ids_json"), {})
        row["links"] = loads(row.pop("links_json"), [])
        row["vulnerabilities"] = loads(row.pop("vulns_json"), [])
        return row

    @staticmethod
    def _answer_from_row(row: Mapping[str, Any]) -> ScaAnswer:
        return ScaAnswer.from_dict({"component": row["component"], "version": row["version"],
                                    "recommended_version": row["recommended_version"],
                                    "conclusion": row["conclusion"], "explanation": row["explanation"],
                                    "ids": loads(row["ids_json"], {}), "links": loads(row["links_json"], []),
                                    "vulnerabilities": loads(row["vulns_json"], [])})

    def save_sca_answers(self, project_id: int, source: str, answers: Iterable[Any]) -> dict:
        """Ответы внешнего агента по пакетам SCA (models.ScaAnswer или словари тех же полей) одной
        транзакцией. Ответ того же источника (source – подпись агента или файла) по тому же пакету (экосистема, имя,
        версия) заменяет прежний; ответы разных источников хранятся рядом. Ответ без экосистемы относится к экосистеме
        пакета проекта с тем же именем и версией, если она одна; если их несколько, ответ сохраняется как
        неоднозначный и не применяется ни к одному пакету (app/ecosystem.py).

        Неполный ответ (без вывода, без пояснения, «обновить» без версии – ScaAnswer.complete) не заменяет
        прежний полный ответ того же источника: прежний остаётся, а библиотека попадает в kept. Если у пакета
        сменился последний ответ по существу (вывод, версия, охват – ScaAnswer.signature), решения «Согласен
        с агентом», принятые по другому ответу, возвращаются на проверку: снимается отметка «Проверено» (само решение
        и комментарий остаются – это история).

        Возвращает {"saved": сколько ответов сохранено, "kept": ["имя@версия" – неполный ответ не заменил полный],
        "reopened": у скольких находок снята отметка «Проверено»}."""
        ts = now_iso()
        result: dict[str, Any] = {"saved": 0, "kept": [], "reopened": 0}
        touched: set[tuple[str, str, str]] = set()
        with self._tx() as c:
            for item in answers:
                answer = item if isinstance(item, ScaAnswer) else ScaAnswer.from_dict(item)
                if not answer.component:
                    continue
                ecosystem = answer.ecosystem or resolve_legacy(
                    self._package_ecosystems_in(c, project_id, answer.component, answer.version))
                key = (project_id, ecosystem, answer.component, answer.version, source.strip())
                old = c.execute("SELECT * FROM sca_answers WHERE project_id = ? AND ecosystem = ? AND component = ?"
                                " AND version = ? AND source = ?", key).fetchone()
                if old is not None and not answer.complete() and self._answer_from_row(old).complete():
                    result["kept"].append(f"{answer.component}@{answer.version}" if answer.version
                                          else answer.component)
                    continue
                # прежний ответ того же источника заменяется новой записью: номер записи – порядок ответов
                c.execute("DELETE FROM sca_answers WHERE project_id = ? AND ecosystem = ? AND component = ?"
                          " AND version = ? AND source = ?", key)
                c.execute("""
                    INSERT INTO sca_answers(project_id, ecosystem, component, version, source, recommended_version,
                                            conclusion, explanation, ids_json, links_json, created_at, updated_at,
                                            vulns_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                          (*key, answer.recommended_version, answer.conclusion, answer.explanation, dumps(answer.ids),
                           dumps(answer.links), old["created_at"] if old is not None else ts, ts,
                           dumps(answer.vulnerabilities)))
                result["saved"] += 1
                touched.add((ecosystem, answer.component, answer.version))
            for ecosystem, component, version in sorted(touched):
                latest = c.execute("SELECT * FROM sca_answers WHERE project_id = ? AND ecosystem = ? AND component = ?"
                                   " AND version = ? ORDER BY id DESC LIMIT 1",
                                   (project_id, ecosystem, component, version)).fetchone()
                sig = self._answer_from_row(latest).signature() if latest is not None else ""
                hub_ids = []
                for row in c.execute("SELECT hub_id, data_json, pkg_ecosystem, pkg_name, pkg_source, pkg_note,"
                                     " pkg_scope FROM findings WHERE project_id = ? AND kind = 'SCA'", (project_id,)):
                    # эффективная тройка (план dev17, п. 4.3) – как у _main_answer и _package_ecosystems_in
                    if package_identity.of(package_identity.with_package(dict(row))) == (ecosystem, component, version):
                        hub_ids.append(row["hub_id"])
                for part in _chunks(hub_ids):
                    marks = ",".join("?" * len(part))
                    result["reopened"] += c.execute(
                        f"UPDATE reviews SET reviewed = 0, reviewed_at = NULL, updated_at = ?,"
                        f" revision = revision + 1"  # страница с прежней редакцией решения больше не сохранит его
                        f" WHERE project_id = ? AND hub_id IN ({marks}) AND decision = 'agree' AND reviewed = 1"
                        f" AND answer_sig != ?", (ts, project_id, *part, sig)).rowcount
            if result["saved"]:
                self._touch(c, project_id, ts)
        return result

    def sca_answers(self, project_id: int, component: str | None = None, version: str | None = None,
                    ecosystem: str | None = None) -> list[dict]:
        """Ответы внешних агентов проекта (все источники), от новых к старым; component, version и ecosystem сужают
        выбор (ecosystem="" – пакеты с неизвестной экосистемой; не задана – ответы по всем экосистемам)."""
        sql, params = "SELECT * FROM sca_answers WHERE project_id = ?", [project_id]
        if ecosystem is not None:
            sql += " AND ecosystem = ?"
            params.append(ecosystem)
        if component is not None:
            sql += " AND component = ?"
            params.append(component)
        if version is not None:
            sql += " AND version = ?"
            params.append(version)
        return [self._sca_answer_row(row) for row in self._all(sql + " ORDER BY id DESC", params)]

    def latest_sca_answers(self, project_id: int) -> dict[tuple[str, str, str], dict]:
        """Последний ответ по каждому пакету: {(экосистема, компонент, версия): ответ}."""
        result: dict[tuple[str, str, str], dict] = {}
        for row in self.sca_answers(project_id):
            result.setdefault((row["ecosystem"], row["component"], row["version"]), row)
        return result

    def _package_ecosystems_in(self, c: Connection, project_id: int, component: str, version: str) -> set[str]:
        """Экосистемы пакетов проекта с этим именем и версией (по находкам SCA, в том числе пропавшим)."""
        found: set[str] = set()
        for row in c.execute("SELECT data_json, pkg_ecosystem, pkg_name, pkg_source, pkg_note, pkg_scope FROM findings"
                             " WHERE project_id = ? AND kind = 'SCA'", (project_id,)):
            eco, name, ver = package_identity.of(package_identity.with_package(dict(row)))  # план dev17, п. 4.3
            if (name, ver) == (component, version):
                found.add(eco)
        return found

    # ------------------------------------------- исследование компонентов (сценарий второй версии)

    @staticmethod
    def _task_row(row: Row | Mapping[str, Any]) -> dict:
        row = dict(row)
        row["ecosystems"] = loads(row.pop("ecosystems_json"), [])
        return row

    def current_task(self, project_id: int) -> dict | None:
        """Действующее задание внешнему агенту проекта (state = current) или None."""
        row = self._one("SELECT * FROM sca2_tasks WHERE project_id = ? AND state = 'current'"
                        " ORDER BY id DESC LIMIT 1", (project_id,))
        return self._task_row(row) if row else None

    def tasks(self, project_id: int, limit: int = 20) -> list[dict]:
        """Задания проекта, новые первыми (для страницы и истории)."""
        return [self._task_row(row) for row in self._all(
            "SELECT * FROM sca2_tasks WHERE project_id = ? ORDER BY id DESC LIMIT ?", (project_id, int(limit)))]

    def task(self, project_id: int, task_id: str) -> dict | None:
        """Задание проекта по подписи; None – такого нет или оно чужое."""
        row = self._one("SELECT * FROM sca2_tasks WHERE project_id = ? AND task_id = ?", (project_id, task_id))
        return self._task_row(row) if row else None

    def _composition(self, c: Connection, project_id: int) -> tuple[dict[str, str], str]:
        """Текущий состав проекта под транзакцией: {input_ref: подпись строки} и отпечаток состава.

        Читает находки, настройки отбора и подтверждения человека одним соединением c, поэтому отвечает тому, что
        в базе прямо сейчас, а не тому, что было видно до транзакции. Правила отбора и отпечаток берутся у сценария
        (app.sca_research): база и страница должны считать состав одинаково. Сценарий импортируется здесь, а не в
        шапке модуля, – хранилище не тянет правила отбора пакета при каждом обращении к базе."""
        from app import sca_research as research

        stored = c.execute("SELECT value_json FROM settings WHERE key = 'sca_internal_prefixes'").fetchone()
        try:
            prefixes = normalize_setting("sca_internal_prefixes", loads(stored[0], []) if stored is not None else [])
        except ConfigError:
            prefixes = []
        row = c.execute("SELECT value FROM meta WHERE key = ?", (_sca_confirmed_key(project_id),)).fetchone()
        confirmed = {str(item) for item in (loads(row[0], []) if row is not None else [])}
        components = self._sca_component_groups(
            [dict(item) for item in c.execute(self._sca_component_sql(["SCA"], False), (project_id, "SCA"))])
        rows, _ = research.task_rows(components, tuple(prefixes), confirmed)
        return {item["input_ref"]: item["input_sig"] for item in rows}, \
            research.sha256(research.composition(rows))

    @staticmethod
    def _task_composition(c: Connection, task_pk: int) -> str:
        """Состав сохранённого задания без переписывания его исторического отпечатка."""
        from app import sca_research as research
        rows = [dict(row) for row in c.execute("SELECT * FROM sca2_task_rows WHERE task_id=?", (task_pk,))]
        return research.sha256(research.composition(rows))

    def insert_task(self, project_id: int, import_id: int, task_id: str, rows: list[dict], ecosystems: list[str],
                    manifest_sha256: str, components_sha256: str, contract: str, answer_contract: str,
                    validator_version: str) -> dict:
        """Задание с его строками одной транзакцией; прежние задания проекта помечаются устаревшими – их состав
        уже не отвечает выгрузке, и выдать их за актуальные нельзя. Возвращает задание.

        Состав пересчитывается здесь же, под транзакцией: между чтением строк на странице и этой записью выгрузка
        могла смениться, и тогда в базу лёг бы не тот состав, который человек видел. Расхождение – TaskSuperseded,
        не пишется ничего, прежнее задание и его строки остаются как были.

        Тот же состав и тот же контракт дают то же задание: вторая кнопка не создаёт второго действующего задания,
        а возвращает прежнее. Задание прежнего контракта (до /3 – без публичных идентификаторов) не переиспользуется,
        даже если состав совпал. Переимпорт выгрузки с новыми находками и номерами AST тот же состав не меняет – на них
        исследование не опирается."""
        from app import sca_research as research

        ts = now_iso()
        with self._tx() as c:
            _, digest = self._composition(c, project_id)
            if (research.sha256(research.composition(rows)) != digest
                    or (manifest_sha256 and str(manifest_sha256) != digest)):
                raise TaskSuperseded(0, "состав изменился")
            current = c.execute("SELECT * FROM sca2_tasks WHERE project_id = ? AND state = 'current'"
                                " ORDER BY id DESC LIMIT 1", (project_id,)).fetchone()
            if (current is not None and str(current["contract"]) == str(contract)
                    and self._task_composition(c, current["id"]) == digest):
                created = self._task_row(current)  # тот же состав и контракт: задание прежнее, второго не создаём
            else:
                c.execute("UPDATE sca2_tasks SET state = 'superseded', superseded_at = ?, updated_at = ?"
                          " WHERE project_id = ? AND state = 'current'", (ts, ts, project_id))
                cur = c.execute("INSERT INTO sca2_tasks(project_id, import_id, task_id, contract, answer_contract,"
                                " validator_version, state, row_count, ecosystems_json, manifest_sha256,"
                                " components_sha256, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, 'current', ?,"
                                " ?, ?, ?, ?, ?)" " RETURNING id",
                                (project_id, int(import_id), task_id, contract, answer_contract, validator_version,
                                 len(rows), dumps(ecosystems), digest, components_sha256, ts, ts))
                task_pk = int(cur.fetchone()[0])
                c.executemany("INSERT INTO sca2_task_rows(task_id, input_ref, ecosystem, name, version, identity_kind,"
                              " input_sig, hub_fix_candidate, finding_count, codebase_count, position,"
                              " vulnerability_ids) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                              [(task_pk, item["input_ref"], item["ecosystem"], item["name"], item["version"],
                                item["identity_kind"], item["input_sig"], item["hub_fix_candidate"],
                                int(item["finding_count"]), int(item["codebase_count"]), index,
                                dumps(research.ids_of(item))) for index, item in enumerate(rows)])
                self._touch(c, project_id, ts)
                created = self._task_row(c.execute("SELECT * FROM sca2_tasks WHERE id = ?",
                                                   (task_pk,)).fetchone())
        return created

    def task_rows(self, task_pk: int) -> list[dict]:
        """Строки задания в том порядке, в каком они ушли агенту."""
        return self._all("SELECT * FROM sca2_task_rows WHERE task_id = ? ORDER BY position, input_ref", (task_pk,))

    def task_row(self, project_id: int, input_ref: str) -> dict | None:
        """Строка строки действующего задания проекта или None. Порядок – как у current_task: одно текущее задание держит
        запись, а при двух читается последнее."""
        row = self._one("SELECT r.* FROM sca2_task_rows r JOIN sca2_tasks t ON t.id = r.task_id"
                        " WHERE t.project_id = ? AND t.state = 'current' AND r.input_ref = ? ORDER BY t.id DESC LIMIT 1",
                        (project_id, input_ref))
        return dict(row) if row else None

    def historical_task_rows(self, project_id: int, refs: Iterable[str]) -> dict[str, dict]:
        """Последний сохранённый состав каждой строки – одним запросом: {input_ref: строка}."""
        refs = list(dict.fromkeys(str(r) for r in refs))
        out: dict[str, dict] = {}
        if not refs:
            return out
        for row in self._all("SELECT r.*, t.task_id AS public_task_id FROM sca2_task_rows r JOIN sca2_tasks t"
                             " ON t.id = r.task_id WHERE t.project_id = ? AND r.input_ref IN"
                             f" ({','.join('?' * len(refs))}) ORDER BY t.id DESC", (project_id, *refs)):
            if row["input_ref"] in out:
                continue
            result = dict(row)
            result['task_id'] = result.pop('public_task_id')
            out[row["input_ref"]] = result
        return out

    def historical_task_row(self, project_id: int, input_ref: str) -> dict | None:
        """Последний сохранённый состав строки, независимо от возраста задания."""
        row = self._one("SELECT r.*, t.task_id AS public_task_id FROM sca2_task_rows r JOIN sca2_tasks t ON t.id = r.task_id"
                        " WHERE t.project_id = ? AND r.input_ref = ? ORDER BY t.id DESC LIMIT 1",
                        (project_id,input_ref))
        if row is None:
            return None
        result = dict(row)
        result['task_id'] = result.pop('public_task_id')
        return result

    def save_research(self, project_id: int, task_pk: int, results: list[dict]) -> dict:
        """Ответы агента по строкам задания – новые ревизии одной транзакцией вместе с отметкой о загрузке.

        Ревизия неизменяема: прежние строки не трогаются, номер растёт. Строка, содержание которой совпало с
        текущей ревизией, новой не получает (повторный импорт того же ответа ничего не меняет).

        Актуальность проверяется по составу, а не по номеру файла выгрузки: переимпорт той же выгрузки с новыми
        строками и номерами AST даёт новый imports.id, но тот же состав, и ответ по заданию остаётся годным.
        На исследование опирается состав (экосистема, имя, версия, вид идентичности, подсказка из выгрузки), а не
        номера находок. Если между проверкой ответа и записью успел смениться состав или собрано другое задание,
        ответ уже не по тому, что сейчас в выгрузке: поднимается TaskSuperseded и не пишется ничего.

        results – [{"input_ref", "input_sig", "answer_sig", "status", "coverage_checked", "coverage_errors",
        "findings_total", "applicable", "gaps_count", "evidence_count", "payload"}].
        Возвращает {"saved": сколько новых ревизий, "unchanged": сколько без изменений, "revisions": {строка:
        номер ревизии}}."""
        from app.sca_contract import VALIDATOR_VERSION
        encoded = {item['input_ref']: dumps(item['payload']) for item in results}
        ts = now_iso()
        result: dict[str, Any] = {"saved": 0, "unchanged": 0, "revisions": {}}
        with self._tx() as c:
            task = c.execute("SELECT state, manifest_sha256 FROM sca2_tasks WHERE id = ? AND project_id = ?",
                             (task_pk, project_id)).fetchone()
            _, digest = self._composition(c, project_id)
            if task is None or task["state"] != "current" or self._task_composition(c, task_pk) != digest:
                raise TaskSuperseded(0, "состав изменился")
            own = {row["input_ref"] for row in
                   c.execute("SELECT input_ref FROM sca2_task_rows WHERE task_id = ?", (task_pk,))}
            if any(item["input_ref"] not in own for item in results):
                raise TaskSuperseded(0, "строка не из этого задания")
            saved_refs: set[str] = set()
            for item in results:
                current = c.execute("SELECT id, revision, answer_sig, content_sig, payload_json FROM sca2_research WHERE project_id = ? AND"
                                    " input_ref = ? ORDER BY revision DESC LIMIT 1",
                                    (project_id, item["input_ref"])).fetchone()
                if current is not None and current["content_sig"] == item["answer_sig"]:
                    c.execute("UPDATE sca2_research SET observation_json=?, observed_at=?, validation_rules=? WHERE id=?",
                              (encoded[item['input_ref']], ts, VALIDATOR_VERSION, current['id']))
                    result["unchanged"] += 1
                    result["revisions"][item["input_ref"]] = int(current["revision"])
                    continue
                revision = int(current["revision"]) + 1 if current is not None else 1
                c.execute("INSERT INTO sca2_research(project_id, task_id, input_ref, revision, answer_sig, input_sig,"
                          " status, coverage_checked, coverage_errors, findings_total, applicable, gaps_count,"
                          " evidence_count, payload_json, imported_at, content_sig, observed_at, validation_rules,"
                          " answer_schema, origin_ref) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,"
                          " ?)",
                          (project_id, int(task_pk), item["input_ref"], revision, item["answer_sig"],
                           item["input_sig"], item["status"], int(item["coverage_checked"]),
                           int(item["coverage_errors"]), int(item["findings_total"]), int(item["applicable"]),
                           int(item["gaps_count"]), int(item["evidence_count"]), encoded[item['input_ref']], ts,
                           item['answer_sig'], ts, VALIDATOR_VERSION, str(item.get("answer_schema") or ""),
                           item["input_ref"]))  # origin_ref – input_ref при создании (план dev17, п. 4.1)
                result["saved"] += 1
                result["revisions"][item["input_ref"]] = revision
                saved_refs.add(item["input_ref"])
            result["reopened"] = self._reopen_after_research(c, project_id, saved_refs, ts)
            # отметка о загрузке – часть той же записи: частичного импорта (ревизии без отметки или наоборот) не бывает
            c.execute("UPDATE sca2_tasks SET imported_at = ?, updated_at = ? WHERE id = ?", (ts, ts, task_pk))
            self._touch(c, project_id, ts)
        return result

    @staticmethod
    def _research_row(row: Mapping[str, Any]) -> dict:
        row = dict(row)
        original = row.pop("payload_json")
        observed = row.pop("observation_json", "{}")
        row["payload"] = loads(observed if observed != "{}" else original, {})
        return row

    def research(self, project_id: int) -> dict[str, dict]:
        """Текущая ревизия исследования по каждой строке: {input_ref: строка с разобранным ответом}."""
        return {row["input_ref"]: self._research_row(row) for row in self._all(
            "SELECT * FROM sca2_research r WHERE project_id = ? AND revision = (SELECT MAX(revision) FROM"
            " sca2_research x WHERE x.project_id = r.project_id AND x.input_ref = r.input_ref)",
            (project_id,))}

    def component_counts(self, project_id: int, refs: Iterable[str]) -> dict:
        """Счётчики компонентов для обзора проекта (ADR-0096 п. 10) коротким чтением, без разбора ответов агента:
        из refs – исследовано, с действующим решением, требуют пересмотра (ответ агента сменился после решения или
        наступила дата пересмотра)."""
        refs = set(refs)
        latest = {r["input_ref"]: r["answer_sig"] for r in self._all(
            "SELECT input_ref, answer_sig FROM sca2_research r WHERE project_id = ? AND revision = (SELECT MAX(revision)"
            " FROM sca2_research x WHERE x.project_id = r.project_id AND x.input_ref = r.input_ref)", (project_id,))
            if r["input_ref"] in refs}
        decisions = {r["input_ref"]: r for r in self._all(
            "SELECT input_ref, research_sig, review_at FROM sca2_decisions d WHERE project_id = ? AND state = 'current'"
            " AND revision = (SELECT MAX(revision) FROM sca2_decisions x WHERE x.project_id = d.project_id"
            " AND x.input_ref = d.input_ref)", (project_id,)) if r["input_ref"] in refs}
        from app.sca_research import review_due  # тот же разбор даты, что у карточки и списка
        stale = sum(1 for ref, d in decisions.items()
                    if (ref in latest and str(d["research_sig"] or "") != str(latest[ref] or ""))
                    or review_due(d["review_at"]))
        return {"total": len(refs), "researched": len(latest), "decided": len(decisions), "stale": stale}

    # ------------------------------------------------------------------ исследование провайдером (ADR-0105, B3)

    def create_research_consent(self, project_id: int, task_pk: int, execution: Mapping[str, Any],
                                consent: Mapping[str, Any], consent_key: str = "",
                                recheck: Callable[[], Sequence[str]] | None = None) -> dict:
        """Согласие оператора на исследование провайдером и снимок исполнителя – одной транзакцией. consent –
        {components_sha256, cutoff_date, instructions, instructions_sha256, rows (список input_ref), selection,
        include_unknown, model, search_mode, tool_steps}. consent_key – метка предпросмотра (sca_research_net
        .preview_token): повтор той же формы возвращает прежнее согласие, а не второе (отозванное – RuntimeError:
        нужен новый предпросмотр). Задание должно быть текущим с тем же составом (иначе TaskSuperseded); у проекта не
        должно быть идущего получения (RuntimeError). recheck – пересчёт строк выбора (их input_ref): вызывается
        внутри транзакции записи, когда другие записи приложения ждут; список отличается от consent["rows"] –
        SelectionChanged, согласие не сохраняется (ревью 0.10.0.dev24: выбор «без дефекта» зависит от дефектов,
        которых состав задания не отражает)."""
        ts = now_iso()
        with self._tx() as c:
            if consent_key:
                same = c.execute("SELECT * FROM sca_research_consents WHERE project_id = ? AND consent_key = ?"
                                 " ORDER BY id DESC LIMIT 1", (project_id, str(consent_key))).fetchone()
                if same is not None:
                    if same["state"] != "active":
                        raise RuntimeError("Это согласие отозвано: откройте предпросмотр заново.")
                    return self._consent_row(same)
            task = c.execute("SELECT state, components_sha256 FROM sca2_tasks WHERE id = ? AND project_id = ?",
                             (task_pk, project_id)).fetchone()
            _, digest = self._composition(c, project_id)
            if task is None or task["state"] != "current" or self._task_composition(c, task_pk) != digest:
                raise TaskSuperseded(0, "состав изменился")
            if recheck is not None and [str(r) for r in recheck()] != [str(r) for r in consent.get("rows") or []]:
                raise SelectionChanged("строки выбора изменились после предпросмотра")
            running = c.execute("SELECT id FROM sca2_research_runs WHERE project_id = ? AND state = 'running'",
                                (project_id,)).fetchone()
            if running is not None:
                raise RuntimeError(f"По проекту уже идёт получение №{running['id']}: остановите его или дождитесь конца.")
            self._check_profile_allows(c, execution.get("provider_id"), None)
            execution_id = self._insert_execution(c, execution, ts)
            cur = c.execute(
                "INSERT INTO sca_research_consents(project_id, task_id, execution_id, components_sha256, cutoff_date,"
                " instructions, instructions_sha256, rows_json, selection, include_unknown, model, search_mode,"
                " tool_steps, consent_key, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)" " RETURNING id",
                (project_id, int(task_pk), execution_id, str(consent["components_sha256"]),
                 str(consent["cutoff_date"]), str(consent["instructions"]), str(consent["instructions_sha256"]),
                 dumps([str(r) for r in consent.get("rows") or []]), str(consent.get("selection") or "all"),
                 1 if consent.get("include_unknown") else 0, str(consent["model"]),
                 str(consent.get("search_mode") or "none"), int(consent.get("tool_steps") or 0), str(consent_key), ts))
            return self._consent_row(c.execute("SELECT * FROM sca_research_consents WHERE id = ?",
                                               (cur.fetchone()[0],)).fetchone())

    def task_composition_current(self, project_id: int, task_pk: int) -> bool:
        """Задание текущее и его состав равен фактическому составу проекта прямо сейчас (новая выгрузка или
        подтверждения имён не меняют номер задания – сверяется отпечаток). Проверка перед каждой отправкой (К2)."""
        with self._lock:
            c = self._conn
            task = c.execute("SELECT state FROM sca2_tasks WHERE id = ? AND project_id = ?",
                             (int(task_pk), int(project_id))).fetchone()
            if task is None or task["state"] != "current":
                return False
            _, digest = self._composition(c, int(project_id))
            return self._task_composition(c, int(task_pk)) == digest

    def research_revision_tools(self, project_id: int, input_ref: str, revision: int) -> list[dict] | None:
        """Фактические вызовы инструментов строки получения, которая создала эту ревизию исследования (состояние
        saved, тот же исполнитель, что у ревизии); позднейшее наблюдение «без изменений» другим получением
        происхождение не подменяет. None – ревизия не от получения провайдером."""
        # строки получения не переписываются переходом идентичности: ревизия соединяется с ними по origin_ref – input_ref
        # при создании (план dev17, п. 4.1); input_ref – текущий ключ ревизии
        row = self._one("SELECT r.tools_json FROM sca2_research_run_rows r JOIN sca2_research_runs g ON g.id = r.run_id"
                        " JOIN sca2_research s ON s.project_id = g.project_id AND s.origin_ref = r.input_ref"
                        " AND s.revision = r.revision"
                        " WHERE g.project_id = ? AND s.input_ref = ? AND r.revision = ? AND r.state = 'saved'"
                        " AND g.execution_id = s.execution_id ORDER BY r.updated_at ASC, r.run_id ASC LIMIT 1",
                        (int(project_id), input_ref, int(revision)))
        return loads(row["tools_json"], []) if row else None

    @staticmethod
    def _consent_row(row: Row | Mapping[str, Any]) -> dict:
        row = dict(row)
        row["rows"] = loads(row.pop("rows_json"), [])
        return row

    def research_consent(self, consent_id: int) -> dict | None:
        row = self._one("SELECT * FROM sca_research_consents WHERE id = ?", (int(consent_id),))
        return self._consent_row(row) if row else None

    def revoke_research_consent(self, consent_id: int) -> None:
        """Отзыв согласия под исключительной блокировкой согласия (К2): начатая отправка дописывает байты, каждая
        следующая – отказ до сети (допуск под общей блокировкой); идущее получение – «остановлено»."""
        from app.sca_research_net import consent_gate
        ts = now_iso()
        with consent_gate(consent_id).write(), self._tx() as c:
            c.execute("UPDATE sca_research_consents SET state = 'revoked', revoked_at = ? WHERE id = ? AND state = 'active'",
                      (ts, int(consent_id)))
            c.execute("UPDATE sca2_research_runs SET state = 'stopped', reason = ?, updated_at = ?, finished_at = ?"
                      " WHERE consent_id = ? AND state = 'running'", ("согласие отозвано", ts, ts, int(consent_id)))

    def start_research_run(self, consent_id: int) -> dict:
        """Получение по согласию – ровно одно (повторное подтверждение возвращает прежнее, а не второе); строки
        согласия встают в очередь. Одно идущее получение на проект (частичный уникальный индекс) – иначе RuntimeError.
        Согласие на доисследование (selection = followup) без получения так не запускается – только вместе с отбором
        строк в start_followup_research (ревью Codex, круги 30–31): иначе между отбором и запуском другое получение
        успело бы сохранить те же строки, а список согласия устарел бы."""
        with self._tx() as c:
            return self._start_research_run(c, consent_id)

    def _start_research_run(self, c: Connection, consent_id: int, followup: bool = False) -> dict:
        ts = now_iso()
        consent = c.execute("SELECT * FROM sca_research_consents WHERE id = ?", (int(consent_id),)).fetchone()
        if consent is None or consent["state"] != "active":
            raise RuntimeError("Согласие не найдено или отозвано.")
        existing = c.execute("SELECT * FROM sca2_research_runs WHERE consent_id = ?", (int(consent_id),)).fetchone()
        if existing is not None:
            return dict(existing)
        if consent["selection"] == "followup" and not followup:
            raise RuntimeError("Доисследование запускается вместе с отбором строк (start_followup_research): "
                               "отдельный запуск согласия по номеру не выполняется.")
        rows = [str(r) for r in loads(consent["rows_json"], [])]
        try:
            cur = c.execute("INSERT INTO sca2_research_runs(project_id, task_id, consent_id, execution_id, state,"
                            " rows_total, started_at, updated_at) VALUES (?, ?, ?, ?, 'running', ?, ?, ?)" " RETURNING id",
                            (consent["project_id"], consent["task_id"], int(consent_id), consent["execution_id"],
                             len(rows), ts, ts))
        except IntegrityError as e:
            raise RuntimeError("По проекту уже идёт другое получение: остановите его или дождитесь конца.") from e
        run_id = int(cur.fetchone()[0])
        c.executemany("INSERT INTO sca2_research_run_rows(run_id, input_ref, position, state, updated_at)"
                      " VALUES (?, ?, ?, 'queued', ?)", [(run_id, ref, i, ts) for i, ref in enumerate(rows)])
        return dict(c.execute("SELECT * FROM sca2_research_runs WHERE id = ?", (run_id,)).fetchone())

    def research_run(self, run_id: int) -> dict | None:
        return self._one("SELECT * FROM sca2_research_runs WHERE id = ?", (int(run_id),))

    def active_research_run(self, project_id: int) -> dict | None:
        return self._one("SELECT * FROM sca2_research_runs WHERE project_id = ? AND state = 'running'", (project_id,))

    def running_research_runs(self) -> list[dict]:
        """Идущие получения исследования по всем проектам (полоса «идёт получение» на любой странице)."""
        return self._all("SELECT * FROM sca2_research_runs WHERE state = 'running' ORDER BY id")

    def latest_research_run(self, project_id: int) -> dict | None:
        return self._one("SELECT * FROM sca2_research_runs WHERE project_id = ? ORDER BY id DESC LIMIT 1", (project_id,))

    def research_run_rows(self, run_id: int) -> list[dict]:
        """Строки получения; later_saved – строка уже сохранена более поздним получением того же задания (история
        этого получения не переписывается, но доисследовать её снова не нужно)."""
        rows = self._all("SELECT * FROM sca2_research_run_rows WHERE run_id = ? ORDER BY position, input_ref",
                         (int(run_id),))
        later = self.later_saved_refs(run_id)
        for row in rows:
            row["tools"] = loads(row.pop("tools_json"), [])
            row["usage"] = loads(row.pop("usage_json"), {})
            row["later_saved"] = row["input_ref"] in later
        return rows

    def later_saved_refs(self, run_id: int) -> set[str]:
        """Строки, по которым получение того же задания с большим номером, чем run_id, получило годный ответ:
        «сохранена» или «без изменений» (годный ответ совпал с прежней ревизией – ревью Codex, круг 29)."""
        # порядок соединений – от получения к поздним получениям того же задания по индексу (project_id, task_id, id),
        # затем строки по (run_id, state): без условия по проекту планировщик перебирал бы строки всех поздних
        # получений всех проектов (ревью Codex, круг 32; бэклог п. 26)
        with self._lock:
            return {r[0] for r in self._conn.execute("""
                SELECT DISTINCT x.input_ref FROM sca2_research_runs r
                  JOIN sca2_research_runs n ON n.project_id = r.project_id AND n.task_id = r.task_id AND n.id > r.id
                  JOIN sca2_research_run_rows x ON x.run_id = n.id AND x.state IN ('saved', 'unchanged')
                 WHERE r.id = ?""", (int(run_id),))}

    def take_research_row(self, run_id: int) -> dict | None:
        """Следующая строка очереди – атомарным переходом «в очереди → отправлено» с меткой sending_at (К11: метка
        ставится до сетевого вызова). None – очередь пуста или получение не идёт."""
        ts = now_iso()
        with self._tx() as c:
            run = c.execute("SELECT state FROM sca2_research_runs WHERE id = ?", (int(run_id),)).fetchone()
            if run is None or run["state"] != "running":
                return None
            row = c.execute("SELECT input_ref FROM sca2_research_run_rows WHERE run_id = ? AND state = 'queued'"
                            " ORDER BY position LIMIT 1", (int(run_id),)).fetchone()
            if row is None:
                return None
            cur = c.execute("UPDATE sca2_research_run_rows SET state = 'sending', sending_at = ?, updated_at = ?"
                            " WHERE run_id = ? AND input_ref = ? AND state = 'queued'",
                            (ts, ts, int(run_id), row["input_ref"]))
            if cur.rowcount != 1:
                return None
            return dict(c.execute("SELECT * FROM sca2_research_run_rows WHERE run_id = ? AND input_ref = ?",
                                  (int(run_id), row["input_ref"])).fetchone())

    @staticmethod
    def _recount_research_run(c: Connection, run_id: int, ts: str) -> None:
        """Счётчики строк и итоговый расход получения – из строк, транзакционно (ревью B3: переходы состояний
        должны пересчитывать их, расход – сумма по всем сохранённым строкам, не только обычного выхода)."""
        counts = {s: n for s, n in c.execute("SELECT state, COUNT(*) FROM sca2_research_run_rows WHERE run_id = ?"
                                             " GROUP BY state", (int(run_id),))}
        usage: dict[str, int] = {}
        for (raw,) in c.execute("SELECT usage_json FROM sca2_research_run_rows WHERE run_id = ?", (int(run_id),)):
            for key, value in (loads(raw, {}) or {}).items():
                if isinstance(value, (int, float)):
                    usage[key] = usage.get(key, 0) + int(value)
        c.execute("UPDATE sca2_research_runs SET rows_saved = ?, rows_unchanged = ?, rows_failed = ?, rows_unknown = ?,"
                  " usage_json = ?, updated_at = ? WHERE id = ?",
                  (counts.get("saved", 0), counts.get("unchanged", 0), counts.get("failed", 0),
                   counts.get("unknown", 0), dumps(usage), ts, int(run_id)))

    def finish_research_row(self, run_id: int, input_ref: str, state: str, reason: str = "", tools: Any = (),
                            usage: Mapping[str, Any] | None = None, revision: int | None = None,
                            result: Mapping[str, Any] | None = None) -> dict:
        """Итог строки получения одной транзакцией: состояние строки (saved / unchanged / failed / unknown),
        причина, вызовы инструментов и расход ТОЛЬКО текущей попытки (они дописываются к прежним попыткам строки,
        вызывать один раз на попытку); при result – новая ревизия исследования с execution_id получения
        (или «без изменений», если содержание совпало), с проверкой актуальности задания (TaskSuperseded); счётчики
        получения. Снятие метки sending_at – в той же транзакции, что и запись результата (К11)."""
        from app.sca_contract import VALIDATOR_VERSION
        ts = now_iso()
        with self._tx() as c:
            run = c.execute("SELECT * FROM sca2_research_runs WHERE id = ?", (int(run_id),)).fetchone()
            if run is None:
                raise RuntimeError("Получение не найдено.")
            if result is not None:
                task_pk, project_id = int(run["task_id"]), int(run["project_id"])
                task = c.execute("SELECT state FROM sca2_tasks WHERE id = ? AND project_id = ?",
                                 (task_pk, project_id)).fetchone()
                _, digest = self._composition(c, project_id)
                if task is None or task["state"] != "current" or self._task_composition(c, task_pk) != digest:
                    raise TaskSuperseded(0, "состав изменился")
                current = c.execute("SELECT id, revision, content_sig FROM sca2_research WHERE project_id = ? AND"
                                    " input_ref = ? ORDER BY revision DESC LIMIT 1", (project_id, input_ref)).fetchone()
                if current is not None and current["content_sig"] == result["answer_sig"]:
                    c.execute("UPDATE sca2_research SET observation_json = ?, observed_at = ?, validation_rules = ?"
                              " WHERE id = ?", (dumps(result["payload"]), ts, VALIDATOR_VERSION, current["id"]))
                    state, revision = "unchanged", int(current["revision"])
                else:
                    revision = int(current["revision"]) + 1 if current is not None else 1
                    c.execute("INSERT INTO sca2_research(project_id, task_id, input_ref, revision, answer_sig, input_sig,"
                              " status, coverage_checked, coverage_errors, findings_total, applicable, gaps_count,"
                              " evidence_count, payload_json, imported_at, content_sig, observed_at, validation_rules,"
                              " answer_schema, execution_id, origin_ref) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,"
                              " ?, ?, ?, ?, ?, ?, ?, ?)",
                              (project_id, task_pk, input_ref, revision, result["answer_sig"], result["input_sig"],
                               result["status"], int(result["coverage_checked"]), int(result["coverage_errors"]),
                               int(result["findings_total"]), int(result["applicable"]), int(result["gaps_count"]),
                               int(result["evidence_count"]), dumps(result["payload"]), ts, result["answer_sig"], ts,
                               VALIDATOR_VERSION, str(result.get("answer_schema") or ""), run["execution_id"],
                               input_ref))  # origin_ref – input_ref при создании (план dev17, п. 4.1)
                    state = "saved"
                    self._reopen_after_research(c, project_id, {input_ref}, ts)
                c.execute("UPDATE sca2_tasks SET imported_at = ?, updated_at = ? WHERE id = ?", (ts, ts, task_pk))
                self._touch(c, project_id, ts)
            if state not in ("saved", "unchanged", "failed", "unknown", "queued"):
                raise ValueError(f"состояние строки получения {state!r}")
            # шаги и расход прежних попыток этой строки (строка побывала в очереди после остановки или отказа допуска)
            # сохраняются: новые дописываются, числа складываются – иначе запрос OSV или ход модели прежней попытки
            # пропал бы из истории и из суммы получения (ревью Codex, круг 36). Бюджет новой попытки это не трогает:
            # он считается в RowOutcome исполнителя.
            prior = c.execute("SELECT tools_json, usage_json FROM sca2_research_run_rows WHERE run_id = ? AND input_ref = ?",
                              (int(run_id), input_ref)).fetchone()
            all_tools = list(loads(prior["tools_json"], []) if prior else []) + list(tools or [])
            total_usage = dict(loads(prior["usage_json"], {}) if prior else {})
            for key, value in dict(usage or {}).items():
                if isinstance(value, (int, float)) and not isinstance(value, bool):
                    total_usage[key] = (total_usage.get(key) or 0) + value
                else:
                    total_usage[key] = value
            c.execute("UPDATE sca2_research_run_rows SET state = ?, reason = ?, tools_json = ?, usage_json = ?,"
                      " revision = ?, sending_at = NULL, updated_at = ? WHERE run_id = ? AND input_ref = ?",
                      (state, str(reason or "")[:2000], dumps(all_tools), dumps(total_usage),
                       revision, ts, int(run_id), input_ref))
            self._recount_research_run(c, run_id, ts)
            return dict(c.execute("SELECT * FROM sca2_research_run_rows WHERE run_id = ? AND input_ref = ?",
                                  (int(run_id), input_ref)).fetchone())

    def finish_research_run(self, run_id: int, state: str, reason: str = "") -> None:
        """Конец получения: done / stopped / interrupted с причиной; счётчики и расход – из строк."""
        if state not in ("done", "stopped", "interrupted"):
            raise ValueError(f"состояние получения {state!r}")
        ts = now_iso()
        with self._tx() as c:
            c.execute("UPDATE sca2_research_runs SET state = ?, reason = ?, updated_at = ?, finished_at = ?"
                      " WHERE id = ? AND state = 'running'", (state, str(reason or "")[:2000], ts, ts, int(run_id)))
            self._recount_research_run(c, run_id, ts)

    def reopen_research_run(self, run_id: int, reason: str) -> bool:
        """Завершённое получение – снова «остановлено» (перед «Доисследовать оставшиеся»): его можно продолжить."""
        ts = now_iso()
        with self._tx() as c:
            cur = c.execute("UPDATE sca2_research_runs SET state = 'stopped', reason = ?, updated_at = ?"
                            " WHERE id = ? AND state = 'done'", (str(reason)[:2000], ts, int(run_id)))
            return cur.rowcount == 1

    def resume_research_run(self, run_id: int) -> dict:
        """«Продолжить» остановленное или прерванное получение по тому же согласию: строки, оставшиеся «в очереди»,
        идут дальше; строки «отправлено» без результата получают «результат неизвестен» и в очередь не возвращаются
        (К11). Другое идущее получение проекта – RuntimeError."""
        ts = now_iso()
        with self._tx() as c:
            run = c.execute("SELECT * FROM sca2_research_runs WHERE id = ?", (int(run_id),)).fetchone()
            if run is None or run["state"] not in ("stopped", "interrupted"):
                raise RuntimeError("Продолжить можно только остановленное или прерванное получение.")
            consent = c.execute("SELECT state FROM sca_research_consents WHERE id = ?", (run["consent_id"],)).fetchone()
            if consent is None or consent["state"] != "active":
                raise RuntimeError("Согласие отозвано: нужно новое согласие.")
            c.execute("UPDATE sca2_research_run_rows SET state = 'unknown', reason = ?, sending_at = NULL, updated_at = ?"
                      " WHERE run_id = ? AND state = 'sending'",
                      ("обращение ушло, результат неизвестен – запрос мог быть оплачен", ts, int(run_id)))
            try:
                c.execute("UPDATE sca2_research_runs SET state = 'running', reason = '', updated_at = ?, finished_at = NULL"
                          " WHERE id = ?", (ts, int(run_id)))
            except IntegrityError as e:
                raise RuntimeError("По проекту уже идёт другое получение.") from e
            self._recount_research_run(c, run_id, ts)
            return dict(c.execute("SELECT * FROM sca2_research_runs WHERE id = ?", (int(run_id),)).fetchone())

    def interrupt_research_runs(self) -> int:
        """При старте приложения: идущие получения – «прервано», их строки «отправлено» – «результат неизвестен» (К11:
        повторной отправки после неизвестного исхода нет ни на каком пути)."""
        ts = now_iso()
        with self._tx() as c:
            # пересчитываются все получения, у которых были строки «отправлено», – и остановленные отзывом согласия
            # (ревью B3 круг 2), не только идущие
            with_sending = {r[0] for r in c.execute("SELECT DISTINCT run_id FROM sca2_research_run_rows"
                                                    " WHERE state = 'sending'")}
            c.execute("UPDATE sca2_research_run_rows SET state = 'unknown', reason = ?, sending_at = NULL, updated_at = ?"
                      " WHERE state = 'sending'",
                      ("приложение перезапускалось после отправки – результат неизвестен, запрос мог быть оплачен", ts))
            running = [r[0] for r in c.execute("SELECT id FROM sca2_research_runs WHERE state = 'running'")]
            c.execute("UPDATE sca2_research_runs SET state = 'interrupted', reason = ?, updated_at = ?,"
                      " finished_at = ? WHERE state = 'running'", ("приложение перезапускалось", ts, ts))
            for run_id in sorted(with_sending | set(running)):
                self._recount_research_run(c, run_id, ts)
            return len(running)

    def followup_research_consent(self, run_id: int, include_unknown: bool = False,
                                  consent_key: str = "") -> dict | None:
        """«Доисследовать оставшиеся»: новое согласие по тем же дате среза, тексту инструкций, модели, поиску и
        ограничителю – только на не получившиеся строки прежнего получения (failed; с неизвестным результатом – по
        явной отметке оператора); прежнее получение и его строки остаются историей. None – строк нет. consent_key –
        метка формы страницы хода: повтор той же формы возвращает прежнее согласие (и его получение), а не второе.
        Задание должно быть текущим с тем же составом (TaskSuperseded); идущее получение проекта – RuntimeError.
        Отбор и запуск одной транзакцией – start_followup_research (ревью Codex, круг 30)."""
        with self._tx() as c:
            return self._followup_consent(c, run_id, include_unknown, consent_key)

    def start_followup_research(self, run_id: int, include_unknown: bool = False,
                                consent_key: str = "") -> tuple[dict, dict] | None:
        """«Доисследовать оставшиеся» целиком: согласие по актуальному отбору и его получение – в одной транзакции,
        чтобы между отбором и запуском другое получение не успело сохранить те же строки (ревью Codex, круг 30).
        Повтор той же формы – прежние согласие и получение. None – строк нет."""
        with self._tx() as c:
            consent = self._followup_consent(c, run_id, include_unknown, consent_key)
            if consent is None:
                return None
            return consent, self._start_research_run(c, int(consent["id"]), followup=True)

    def _followup_consent(self, c: Connection, run_id: int, include_unknown: bool,
                          consent_key: str) -> dict | None:
        ts = now_iso()
        states = ("failed", "unknown") if include_unknown else ("failed",)
        run = c.execute("SELECT * FROM sca2_research_runs WHERE id = ?", (int(run_id),)).fetchone()
        if run is None or run["state"] == "running":
            raise RuntimeError("Получение не найдено или ещё идёт.")
        if consent_key:
            same = c.execute("SELECT * FROM sca_research_consents WHERE project_id = ? AND consent_key = ?"
                             " ORDER BY id DESC LIMIT 1", (int(run["project_id"]), str(consent_key))).fetchone()
            if same is not None:
                if same["state"] != "active":
                    raise RuntimeError("Это согласие отозвано: откройте страницу получения заново.")
                # согласие с запущенным получением – идемпотентный повтор формы; согласие, запуск которого не
                # состоялся (другое получение успело раньше), не возвращается как есть – отбор строк проверяется
                # заново, чтобы устаревший список не ушёл (ревью Codex, круг 29)
                if c.execute("SELECT 1 FROM sca2_research_runs WHERE consent_id = ?", (same["id"],)).fetchone():
                    return self._consent_row(same)
        marks = ",".join("?" for _ in states)
        # строка, уже сохранённая более поздним получением того же задания, в доисследование не идёт
        refs = [r[0] for r in c.execute(f"""
            SELECT x.input_ref FROM sca2_research_run_rows x
             WHERE x.run_id = ? AND x.state IN ({marks})
               AND NOT EXISTS (SELECT 1 FROM sca2_research_runs n JOIN sca2_research_run_rows y ON y.run_id = n.id
                                WHERE n.project_id = ? AND n.task_id = ? AND n.id > x.run_id
                                  AND y.input_ref = x.input_ref AND y.state IN ('saved', 'unchanged'))
             ORDER BY x.position""", (int(run_id), *states, int(run["project_id"]), int(run["task_id"])))]
        if not refs:
            return None
        if consent_key and same is not None and loads(same["rows_json"], []) == refs:
            return self._consent_row(same)  # отбор не изменился – то же согласие, без второго
        prior = c.execute("SELECT * FROM sca_research_consents WHERE id = ?", (run["consent_id"],)).fetchone()
        if prior is None:
            raise RuntimeError("Согласие прежнего получения не найдено.")
        project_id, task_pk = int(run["project_id"]), int(run["task_id"])
        task = c.execute("SELECT state FROM sca2_tasks WHERE id = ? AND project_id = ?", (task_pk, project_id)).fetchone()
        _, digest = self._composition(c, project_id)
        if task is None or task["state"] != "current" or self._task_composition(c, task_pk) != digest:
            raise TaskSuperseded(0, "состав изменился")
        if c.execute("SELECT 1 FROM sca2_research_runs WHERE project_id = ? AND state = 'running'",
                     (project_id,)).fetchone():
            raise RuntimeError("По проекту уже идёт получение.")
        self._check_profile_allows(c, c.execute("SELECT provider_id FROM llm_executions WHERE id = ?",
                                                (run["execution_id"],)).fetchone()[0], None)
        cur = c.execute(
            "INSERT INTO sca_research_consents(project_id, task_id, execution_id, components_sha256, cutoff_date,"
            " instructions, instructions_sha256, rows_json, selection, include_unknown, model, search_mode,"
            " tool_steps, consent_key, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)" " RETURNING id",
            (project_id, task_pk, run["execution_id"], prior["components_sha256"], prior["cutoff_date"],
             prior["instructions"], prior["instructions_sha256"], dumps(refs), "followup",
             1 if include_unknown else 0, prior["model"], prior["search_mode"], prior["tool_steps"],
             str(consent_key), ts))
        return self._consent_row(c.execute("SELECT * FROM sca_research_consents WHERE id = ?",
                                           (cur.fetchone()[0],)).fetchone())

# ------------------------------------------------------------------ сохранённые отборы компонентов (ADR-0110)

    def saved_component_filters(self, project_id: int) -> list[dict]:
        """Сохранённые отборы списка компонентов проекта, по имени."""
        return self._all("SELECT id, name, query, created_at, updated_at FROM saved_component_filters"
                         " WHERE project_id = ? ORDER BY name_key, id", (project_id,))

    def save_component_filter(self, project_id: int, name: str, query: str) -> dict:
        """Сохранить отбор одной транзакцией: то же имя (без учёта регистра) – обновить условия (id и created_at
        прежние), иначе при SAVED_FILTERS_MAX отборах – отказ, иначе вставить. -> {"state": "created" | "updated" |
        "limit", "id"}."""
        ts = now_iso()
        key = name.casefold()
        with self._tx() as c:
            old = c.execute("SELECT id FROM saved_component_filters WHERE project_id = ? AND name_key = ?",
                            (project_id, key)).fetchone()
            if old is not None:
                c.execute("UPDATE saved_component_filters SET name = ?, query = ?, updated_at = ? WHERE id = ?",
                          (name, query, ts, old["id"]))
                return {"state": "updated", "id": int(old["id"])}
            count = c.execute("SELECT COUNT(*) FROM saved_component_filters WHERE project_id = ?",
                              (project_id,)).fetchone()[0]
            if count >= SAVED_FILTERS_MAX:
                return {"state": "limit", "id": None}
            cur = c.execute("INSERT INTO saved_component_filters(project_id, name, name_key, query, created_at,"
                            " updated_at) VALUES (?, ?, ?, ?, ?, ?)" " RETURNING id", (project_id, name, key, query, ts, ts))
            return {"state": "created", "id": int(cur.fetchone()[0])}

    def delete_component_filter(self, project_id: int, filter_id: int) -> bool:
        """Удалить отбор этого проекта; чужого или уже удалённого нет – False."""
        with self._tx() as c:
            return c.execute("DELETE FROM saved_component_filters WHERE project_id = ? AND id = ?",
                             (project_id, int(filter_id))).rowcount > 0

    def research_row(self, project_id: int, input_ref: str) -> dict | None:
        """Текущая ревизия исследования по одной строке или None."""
        row = self._one("SELECT * FROM sca2_research WHERE project_id = ? AND input_ref = ? ORDER BY revision DESC"
                        " LIMIT 1", (project_id, input_ref))
        return self._research_row(row) if row else None

    def research_history(self, project_id: int, input_ref: str) -> list[dict]:
        """Все ревизии исследования строки, новые первыми: прежние никуда не деваются."""
        return [dict(row) for row in self._all(
            "SELECT id, task_id, revision, answer_sig, status, imported_at FROM sca2_research"
            " WHERE project_id = ? AND input_ref = ? ORDER BY revision DESC", (project_id, input_ref))]

    def decisions(self, project_id: int) -> dict[str, dict]:
        """Действующее решение по каждой строке: {input_ref: решение}. Одно текущее решение держит запись; при двух в словаре
        остаётся решение с большей ревизией – то же, что отдаёт decision()."""
        return {row["input_ref"]: dict(row) for row in self._all(
            "SELECT * FROM sca2_decisions WHERE project_id = ? AND state = 'current' ORDER BY revision, id", (project_id,))}

    def decision(self, project_id: int, input_ref: str) -> dict | None:
        """Действующее решение по строке (с большим номером ревизии) или None."""
        row = self._one("SELECT * FROM sca2_decisions WHERE project_id = ? AND input_ref = ? ORDER BY revision DESC"
                        " LIMIT 1", (project_id, input_ref))
        return dict(row) if row else None

    def decision_history(self, project_id: int, input_ref: str) -> list[dict]:
        """История решений по строке, новые первыми: решение человека не переписывается."""
        return [dict(row) for row in self._all(
            "SELECT * FROM sca2_decisions WHERE project_id = ? AND input_ref = ? ORDER BY revision DESC",
            (project_id, input_ref))]

    # таблицы, снятые строки которых видны в истории компонента (план dev17, п. 4.6)
    ARCHIVE_HISTORY_TABLES = ("sca2_research", "sca2_decisions")

    def identity_archive(self, project_id: int, refs: Iterable[str] | None = None,
                         tables: Iterable[str] = ARCHIVE_HISTORY_TABLES) -> list[dict]:
        """Строки, снятые переходом идентичности пакетов (план dev17, п. 4.6), новые первыми: key – ключ строки,
        row – строка на момент снятия, input_ref – группа, к которой она относилась. Только чтение: главный ответ и
        действующее решение строки архива не определяют. refs – только эти группы (отбор в SQL; None – все)."""
        tables = tuple(tables)
        sql = (f"SELECT id, run_id, archived_at, source_table, key_json, row_json, moved_to_ref, reason"
               f" FROM sca_identity_archive WHERE project_id = ? AND source_table IN ({','.join('?' * len(tables))})")
        params: list[Any] = [project_id, *tables]
        if refs is not None:
            refs = list(dict.fromkeys(str(r) for r in refs))
            if not refs:
                return []
            sql += f" AND (key_json::json ->> 'input_ref') IN ({','.join('?' * len(refs))})"
            params += refs
        out = []
        for r in self._all(sql + " ORDER BY id DESC", tuple(params)):
            key, row = loads(r["key_json"], {}) or {}, loads(r["row_json"], {}) or {}
            out.append({"id": r["id"], "run_id": r["run_id"], "archived_at": r["archived_at"],
                        "table": r["source_table"], "key": key, "row": row,
                        "input_ref": str(key.get("input_ref") or row.get("input_ref") or ""),
                        "moved_to_ref": r["moved_to_ref"] or "", "reason": r["reason"] or ""})
        return out

    def group_marks(self, project_id: int) -> list[dict]:
        """Отметки групп, которых коснулся переход идентичности, новые первыми: {from_ref, to_ref (пусто – группа не
        перенесена: расщепление или слияние), triple – прежняя тройка, archived_at, reason}."""
        return [{"from_ref": a["input_ref"], "to_ref": a["moved_to_ref"], "triple": list(a["row"].get("triple") or []),
                 "archived_at": a["archived_at"], "reason": a["reason"]}
                for a in self.identity_archive(project_id, tables=("group",))]

    def latest_group_marks(self, project_id: int) -> dict[str, dict]:
        """Последняя отметка каждой группы: она и определяет, куда ведёт прежний адрес (ревью Codex, круг 2 – позднее
        расщепление отменяет прежний перенос)."""
        out: dict[str, dict] = {}
        for m in self.group_marks(project_id):
            out.setdefault(m["from_ref"], m)
        return out

    def moved_ref(self, project_id: int, input_ref: str, live: Iterable[str] = (),
                  marks: Mapping[str, dict] | None = None) -> str:
        """Куда ведёт прежний адрес группы: по последним отметкам до первой живой группы или до конца цепочки;
        последняя отметка без назначения маршрут прекращает; цикл – пусто (адрес никуда не ведёт)."""
        latest = marks if marks is not None else self.latest_group_marks(project_id)
        live = set(live)
        cur, seen = input_ref, {input_ref}
        while True:
            nxt = (latest.get(cur) or {}).get("to_ref") or ""
            if not nxt:
                return "" if cur == input_ref else cur
            if nxt in seen:
                return ""
            seen.add(nxt)
            cur = nxt
            if cur in live:
                return cur

    def moved_from(self, project_id: int, input_ref: str, marks: Mapping[str, dict] | None = None) -> list[str]:
        """Все прежние группы, последние переносы которых цепочкой ведут в эту (ближние первыми, без циклов)."""
        latest = marks if marks is not None else self.latest_group_marks(project_id)
        reverse: dict[str, list[str]] = {}
        for ref, m in latest.items():
            if m["to_ref"]:
                reverse.setdefault(m["to_ref"], []).append(ref)
        out, queue, seen = [], [input_ref], {input_ref}
        while queue:
            for prev in reverse.get(queue.pop(0), []):
                if prev not in seen:
                    seen.add(prev)
                    out.append(prev)
                    queue.append(prev)
        return out

    def identity_pending(self, project_id: int, scope: str) -> int:
        """Находки SCA, к которым сведения Hub о библиотеке текущего назначения ещё не применены (план dev17,
        п. 4.4): правило не применялось или применялось при другом назначении."""
        return int(self._scalar("SELECT COUNT(*) FROM findings WHERE project_id = ? AND kind = 'SCA'"
                                " AND (pkg_source = '' OR pkg_scope <> ?)", (project_id, scope)) or 0)

    _MARKED_SCA_SQL = ("SELECT hub_id, data_json, pkg_ecosystem, pkg_name, pkg_source, pkg_note, pkg_scope FROM findings"
                       " WHERE project_id = ? AND kind = 'SCA' AND (pkg_source = 'hub' OR pkg_note <> '')")

    def package_marks(self, project_id: int) -> dict[str, list[str]]:
        """Пометки идентичности пакета по находкам SCA (план dev17, п. 4.6): {hub_id: [текст]} – только находки со
        сведениями Hub о библиотеке или пометками правила; одним запросом на страницу."""
        out: dict[str, list[str]] = {}
        for row in self._all(self._MARKED_SCA_SQL, (project_id,)):
            texts = package_identity.mark_texts(package_identity.with_package(dict(row)))
            if texts:
                out[str(row["hub_id"])] = texts
        return out

    def identity_report(self, project_id: int) -> dict:
        """Отчёт перехода идентичности пакетов по проекту (план dev17, шаг 5) – только чтение, без операций Hub:
        находки SCA по источнику идентичности и видам пометок, отметки групп (перенос, расщепление, слияние), снятые
        сущности по таблицам, дефекты SCA без единственного набора, места в наборах, которые нужно выбрать заново."""
        by_source = {str(r["pkg_source"] or ""): int(r["n"]) for r in self._all(
            "SELECT pkg_source, COUNT(*) AS n FROM findings WHERE project_id = ? AND kind = 'SCA' GROUP BY pkg_source",
            (project_id,))}
        kinds: dict[str, int] = {}
        for row in self._all(self._MARKED_SCA_SQL, (project_id,)):
            for kind in dict.fromkeys(k for k, _ in package_identity.mark_items(package_identity.with_package(dict(row)))):
                kinds[kind] = kinds.get(kind, 0) + 1
        groups = self.group_marks(project_id)
        latest = self.latest_group_marks(project_id)
        own = self.archive_owner_refs(project_id)
        for g in groups:  # ссылка «архив» – только на группу, у которой есть что открыть (ревью Codex, круг 3)
            g["has_archive"] = bool(own & {g["from_ref"], *self.moved_from(project_id, g["from_ref"], latest)})
        # история принятий с переходом: полный итог, как в блоке «Идентичность пакетов» (частичные расщепления,
        # последствия для решений и дефектов; план п. 4.5)
        # только принятия, которые меняли идентичность (сводка без перехода тоже сохраняется – с нулями); отбор –
        # до предела, чтобы принятия без перехода не вытесняли настоящие (ревью Codex, круг 4)
        accepts = []
        for r in self._all("SELECT id, applied_at, result_json FROM hub_defect_sync_runs WHERE project_id = ?"
                           " AND applied_at IS NOT NULL ORDER BY applied_at DESC, id DESC", (project_id,)):
            identity = (loads(r["result_json"], {}) or {}).get("identity")
            if identity and not identity.get("error") and (identity.get("findings") or identity.get("groups")):
                accepts.append({"run_id": r["id"], "applied_at": r["applied_at"], "identity": identity})
                if len(accepts) == 20:
                    break
        archived = self._all("SELECT source_table, COUNT(*) AS n, MAX(archived_at) AS last FROM sca_identity_archive"
                             " WHERE project_id = ? AND source_table <> 'group' GROUP BY source_table"
                             " ORDER BY source_table", (project_id,))
        defects = self._all("SELECT id, number, hub_defect_id, conflicts_json FROM hub_defects WHERE project_id = ?"
                            " AND kind = 'SCA' AND id = draft_owner_id AND sca_set_key = ''"
                            " AND state NOT IN ('failed', 'cancelled', 'deleted') ORDER BY id", (project_id,))
        pending = self._scalar("SELECT COUNT(*) FROM sca_set_members WHERE project_id = ? AND pending_reason <> ''",
                               (project_id,))
        return {"findings": sum(by_source.values()), "by_source": by_source,
                "marks": [(package_identity.MARK_LABELS.get(k, k), n) for k, n in kinds.items()],
                "identity_rev": int((self.get_project(project_id) or {}).get("identity_rev") or 0),
                "moved": [g for g in groups if g["to_ref"]], "not_moved": [g for g in groups if not g["to_ref"]],
                "archived": [dict(r) for r in archived],
                "defects": [{"id": r["id"], "number": r["number"], "hub_defect_id": r["hub_defect_id"],
                             "conflicts": loads(r["conflicts_json"], []) or []} for r in defects],
                "pending_places": int(pending or 0), "accepts": accepts}

    def archived_refs(self, project_id: int, marks: Mapping[str, dict] | None = None) -> set[str]:
        """Группы, исследования или решения которых сняты переходом и чья последняя отметка – не перенос: их
        история видна строкой списка с пометкой «архив»; перенесённая группа ведёт на новую карточку. Только
        адреса, без содержимого архива."""
        latest = marks if marks is not None else self.latest_group_marks(project_id)
        moved = {ref for ref, m in latest.items() if m["to_ref"]}
        own = self.archive_owner_refs(project_id)
        # и группа, чей архив лежит у предшественников по цепочке переносов (перенос, затем расщепление; ревью
        # Codex, круг 3)
        chained = {ref for ref in latest if ref not in moved
                   and own & {ref, *self.moved_from(project_id, ref, latest)}}
        return (own - moved) | chained

    def archive_owner_refs(self, project_id: int) -> set[str]:
        """Группы, под ключом которых в архиве лежат исследования или решения (только адреса)."""
        return {str(r["ref"]) for r in self._all(
            "SELECT DISTINCT (key_json::json ->> 'input_ref') AS ref FROM sca_identity_archive WHERE project_id = ?"
            " AND source_table IN (?, ?)", (project_id, *self.ARCHIVE_HISTORY_TABLES)) if r["ref"]}

    def identity_known(self, project_id: int) -> int:
        """Находки SCA со сведениями Hub о библиотеке или пометками правила – для ссылки на отчёт перехода."""
        return int(self._scalar("SELECT COUNT(*) FROM findings WHERE project_id = ? AND kind = 'SCA'"
                                " AND (pkg_source = 'hub' OR pkg_note <> '')", (project_id,)) or 0)

    def save_decision(self, project_id: int, input_ref: str, action: str, rationale: str, target_version: str,
                      replacement_name: str, replacement_version: str, review_at: str, input_sig: str,
                      research_sig: str, expected_revision: int | None,
                      expected_research_sig: str = "", expected_research_revision: int = 0,
                      expected_input_sig: str = "") -> dict:
        """Решение человека по строке как новая ревизия: прежнее решение остаётся в истории.

        expected_revision – номер ревизии решения, который человек видел на странице. expected_research_sig и
        expected_research_revision – отпечаток и номер ревизии исследования, которые человек видел. Если
        между открытием карточки и записью решение изменили в другой вкладке или пришёл новый ответ агента,
        ничего не пишется, а поднимается DecisionStale. Исследование при этом не требуется: решение можно
        принять и без ответа агента.

        Проверяется и сам состав: пакет должен быть в текущей выгрузке, а expected_input_sig – подписью той же
        строки, которую человек видел на карточке. Решение по пакету, ушедшему из выгрузки или сменившему
        версию, не принимается как решение по актуальному (DecisionStale), но прежние решения при этом не
        удаляются: история решения человека остаётся видимой.

        Возвращает сохранённое решение."""
        ts = now_iso()
        with self._tx() as c:
            return self._save_decision_tx(c, project_id, input_ref, action, rationale, target_version, replacement_name, replacement_version, review_at, input_sig, research_sig, expected_revision, expected_research_sig, expected_research_revision, expected_input_sig, ts)

    def _save_decision_tx(self, c, project_id, input_ref, action, rationale, target_version, replacement_name, replacement_version, review_at, input_sig, research_sig, expected_revision, expected_research_sig, expected_research_revision, expected_input_sig, ts, signatures=None):
        """Проверка и запись одной версии на уже открытом соединении."""
        from app.sca_research import decision_values
        fields = decision_values({"action": action, "target_version": target_version,
                                  "replacement_name": replacement_name, "replacement_version": replacement_version})
        target_version, replacement_name, replacement_version = (fields[name] for name in
            ("target_version", "replacement_name", "replacement_version"))
        current = c.execute("SELECT * FROM sca2_decisions WHERE project_id = ? AND input_ref = ?"
                            " ORDER BY revision DESC LIMIT 1", (project_id, input_ref)).fetchone()
        revision = int(current["revision"]) if current is not None else 0
        if expected_revision is not None and int(expected_revision) != revision:
            raise DecisionStale(revision)
        seen = c.execute("SELECT revision, answer_sig FROM sca2_research WHERE project_id = ? AND input_ref = ?"
                         " ORDER BY revision DESC LIMIT 1", (project_id, input_ref)).fetchone()
        if seen is not None:  # ответ агента пришёл или сменился уже после того, как страницу открыли
            if (not expected_research_sig or not expected_research_revision
                    or seen["answer_sig"] != expected_research_sig
                    or int(seen["revision"]) != int(expected_research_revision)):
                raise DecisionStale(revision)
            research_signature = expected_research_sig
        else:
            research_signature = ""  # решения без исследования бывают, привязывать не к чему
        if signatures is None:
            signatures, _ = self._composition(c, project_id)
        if input_ref not in signatures or (expected_input_sig
                                            and signatures[input_ref] != str(expected_input_sig)):
            raise DecisionStale(revision)  # пакета в выгрузке нет или строка стала другой
        if current is not None and current["state"] == "current":
            c.execute("UPDATE sca2_decisions SET state = 'superseded', superseded_at = ? WHERE id = ?",
                      (ts, current["id"]))
        cur = c.execute("INSERT INTO sca2_decisions(project_id, input_ref, revision, action, rationale,"
                        " target_version, replacement_name, replacement_version, review_at, input_sig,"
                        " research_sig, state, decided_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'current', ?)" " RETURNING id",
                        (project_id, input_ref, revision + 1, action, rationale, target_version,
                         replacement_name, replacement_version, review_at, input_sig,
                         research_signature, ts))
        self._touch(c, project_id, ts)
        row = c.execute("SELECT * FROM sca2_decisions WHERE id = ?", (int(cur.fetchone()[0]),)).fetchone()
        return dict(row) if row else {}

    def save_decisions(self, project_id: int, entries: list[dict], values: dict) -> list[dict]:
        """Пакет отдельных решений: любой конфликт откатывает все версии, включая историю."""
        if not entries or len(entries) > 200 or len({e["input_ref"] for e in entries}) != len(entries):
            raise ValueError("Выберите от 1 до 200 разных версий.")
        ts = now_iso()
        with self._tx() as c:
            signatures, _ = self._composition(c, project_id)
            saved = []
            for item in entries:
                saved.append(self._save_decision_tx(c, project_id, item["input_ref"], values["action"],
                    values["rationale"], values.get("target_version", ""), values.get("replacement_name", ""),
                    values.get("replacement_version", ""), values.get("review_at", ""), item["expected_input_sig"],
                    item["expected_research_sig"], item["revision"], item["expected_research_sig"],
                    item["expected_research_revision"], item["expected_input_sig"], ts, signatures))
            return saved


    # ------------------------------------------------------------------ номера дефектов Hub

    def defect_assigned_at(self, project_id: int, key: str) -> str:
        """Когда ключ key получил свой нынешний номер дефекта (повторная выдача того же номера время не меняет; ""
        – номера нет)."""
        return str(self._scalar("SELECT COALESCE(NULLIF(assigned_at, ''), updated_at) FROM defects WHERE project_id = ?"
                                " AND defect_key = ?", (project_id, key)) or "")

    def defect_number(self, project_id: int, key: str) -> int | None:
        """Номер дефекта Hub («ID<n>»), который человек дал находке или библиотеке (key – «sast:<ID находки>» или
        «sca:<компонент>@<версия>»); None – номера ещё нет."""
        value = self._scalar("SELECT number FROM defects WHERE project_id = ? AND defect_key = ?", (project_id, key))
        return int(value) if value is not None else None

    @staticmethod
    def defect_number_in(c: Connection, project_id: int, key: str) -> int | None:
        """defect_number на соединении c – транзакция постановки, которая повторяет проверку номера (ADR-0125 п. 2)."""
        row = c.execute("SELECT number FROM defects WHERE project_id = ? AND defect_key = ?",
                        (project_id, str(key))).fetchone()
        return int(row["number"]) if row is not None and row["number"] is not None else None

    def release_defect_number(self, project_id: int, key: str, hub_id: str, number: int,
                              check: Callable[[Connection], None] | None = None) -> list[str]:
        """«Снять номер» у находки без дефекта (ложное срабатывание, ADR-0125 «Уточнения»): одной транзакцией – у ключа
        key сейчас номер number (тот, что показан в карточке), check(c) прошла (решение – ложное срабатывание),
        находка hub_id не цель строки дефекта, которая держит находку или ключ номера (HUB_DEFECT_RESERVING: подготовка,
        предпросмотр, создание, привязка, создан), – тогда строка номера удаляется. Иначе ValueError, ничего не
        меняется. Возвращает ключи, у которых номер number остался (например, сосед по группе с решением «Подтверждаю
        дефект»): тогда номер для дефекта с ним в заголовке Hub не освободился."""
        with self._tx() as c:
            if self.defect_number_in(c, project_id, key) != int(number):
                raise ValueError("Номер дефекта изменили в другой вкладке: обновите карточку.")
            if check is not None:
                check(c)
            held = c.execute(
                f"SELECT id FROM hub_defects WHERE project_id = ? AND {self.HUB_DEFECT_RESERVING} AND ("
                " EXISTS (SELECT 1 FROM json_array_elements(hub_defects.targets_json::json) AS t(value) WHERE (t.value ->> 'hub_id') = ?)"
                " OR EXISTS (SELECT 1 FROM json_array_elements_text(hub_defects.number_keys_json::json) AS k(value) WHERE k.value = ?)) LIMIT 1",
                (project_id, str(hub_id), str(key))).fetchone()
            if held is not None:
                raise ValueError("Находка входит в дефект приложения: номер не снимается.")
            c.execute("DELETE FROM defects WHERE project_id = ? AND defect_key = ? AND number = ?",
                      (project_id, str(key), int(number)))
            return self.defect_keys_with_number_in(c, project_id, int(number))

    def defect_keys_with_number(self, project_id: int, number: int) -> list[str]:
        """Ключи дефектов проекта с номером number (по порядку ключей)."""
        with self._lock:
            return self.defect_keys_with_number_in(self._conn, project_id, number)

    @staticmethod
    def defect_keys_with_number_in(c: Connection, project_id: int, number: int) -> list[str]:
        """defect_keys_with_number на соединении c (транзакция постановки, ADR-0125 п. 2)."""
        return [r["defect_key"] for r in c.execute("SELECT defect_key FROM defects WHERE project_id = ? AND number = ?"
                                                   " ORDER BY defect_key", (project_id, int(number))).fetchall()]

    def on_connection(self, fn: Callable[[Connection], Any]) -> Any:
        """fn(соединение) на общем соединении под замком: правило, написанное для транзакции (варианты *_in), читает
        так же и вне её – предпросмотр показывает то, что потом повторит транзакция постановки."""
        with self._lock:
            return fn(self._conn)

    def next_defect_number(self, project_id: int) -> int:
        """Следующий номер дефекта по счётчику проекта: на единицу больше наибольшего выданного или занятого дефектом,
        который создаётся запросом в Hub и ещё не отменён (ADR-0120: два предпросмотра не получают один номер)."""
        return max(int(self._scalar("SELECT COALESCE(MAX(number), 0) FROM defects WHERE project_id = ?",
                                    (project_id,)) or 0), self.reserved_defect_number(project_id)) + 1

    def reserved_defect_number(self, project_id: int) -> int:
        """Наибольший номер, занятый дефектом из карточки в работе (hub_defects, не отменён и не отклонён Hub); 0 – нет."""
        return int(self._scalar(f"SELECT COALESCE(MAX(number), 0) FROM hub_defects WHERE project_id = ?"
                                f" AND {self.HUB_DEFECT_RESERVING}", (project_id,)) or 0)

    def set_defect_number_if_free(self, project_id: int, key: str, number: int, check: Callable | None = None) -> int | None:
        """Номер дефекта, созданного запросом, за ключом – только если у ключа номера нет или он тот же; другой номер
        (назначен позже человеком) не перезаписывается и возвращается (ADR-0120: повторное применение результата)."""
        if not isinstance(number, int) or isinstance(number, bool) or not 1 <= number <= 999_999:
            raise ValueError("номер дефекта – целое число от 1 до 999999")
        ts = now_iso()
        with self._tx() as c:
            if check is not None:
                check(c)
            row = c.execute("SELECT number FROM defects WHERE project_id = ? AND defect_key = ?",
                            (project_id, key)).fetchone()
            if row is not None:
                return None if int(row["number"]) == number else int(row["number"])
            c.execute("INSERT INTO defects(project_id, defect_key, number, updated_at, assigned_at) VALUES (?, ?, ?, ?, ?)",
                      (project_id, key, number, ts, ts))
            return None

    def sca_text_notes(self, project_id: int) -> list[dict]:
        """Наборы дефекта SCA проекта с сохранённым текстом (только чтение – отчёт о правилах текста 0.10.0.dev21; у
        набора без записи текст – заготовка, её края правила не меняют): input_ref, set_no, recommendation_note и
        размещение находок пакета {hub_id: set_no} (None – «без дефекта»; не перечисленные в sca_set_members – в
        наборе 0)."""
        notes = self._all("SELECT input_ref, set_no, recommendation_note FROM sca_package_texts WHERE project_id = ?"
                          " ORDER BY input_ref, set_no", (project_id,))
        placed: dict[str, dict[str, int | None]] = {}
        for r in self._all("SELECT input_ref, hub_id, set_no FROM sca_set_members WHERE project_id = ?", (project_id,)):
            placed.setdefault(r["input_ref"], {})[r["hub_id"]] = None if r["set_no"] is None else int(r["set_no"])
        return [{**r, "set_no": int(r["set_no"]), "placed": placed.get(r["input_ref"], {})} for r in notes]

    def _sca_package_state(self, c: Connection, project_id: int, hub_id: str) -> dict | None:
        """Всё, из чего строится дефект SCA по находке hub_id, одним чтением соединения c: сама находка, находки её пакета
        (экосистема, имя, версия; в том числе пропавшие из выгрузки) с решениями, ответы агента по пакету (от новых к
        старым) и соответствия AST → CVE по идентификаторам пакета. None – находки нет или она не SCA."""
        row = c.execute("SELECT * FROM findings WHERE project_id = ? AND hub_id = ?", (project_id, hub_id)).fetchone()
        if row is None or row["kind"] != "SCA":
            return None
        own = self._finding_row(dict(row))
        eco, name, version = package_identity.of(own["data"])  # эффективная тройка (план dev17, п. 4.3)
        members: list[dict] = []
        ids: set[str] = set()
        for member in c.execute("SELECT * FROM findings WHERE project_id = ? AND kind = 'SCA' ORDER BY id", (project_id,)):
            item = self._finding_row(dict(member))
            d = item["data"]
            if package_identity.of(d) == (eco, name, version):
                members.append(item)
                ids.update(str(x) for x in [*(d.get("cve") or []), *(d.get("vuln_ids") or [])])
        reviews: dict[str, dict] = {}
        for part in _chunks([m["hub_id"] for m in members]):
            marks = ",".join("?" * len(part))
            for r in c.execute(f"SELECT r.*, {_ENTERED_HUB_SQL} AS entered_current FROM reviews r"
                               f" WHERE project_id = ? AND hub_id IN ({marks})", (project_id, *part)):
                review = dict(r)
                review["entered_hub"] = review.pop("entered_current")
                reviews[r["hub_id"]] = review
        answers = [self._sca_answer_row(dict(r)) for r in c.execute(
            "SELECT * FROM sca_answers WHERE project_id = ? AND ecosystem = ? AND component = ? AND version = ?"
            " ORDER BY id DESC", (project_id, eco, name, version))]
        mapping: list[list[str]] = []
        for part in _chunks(sorted(ids)):
            marks = ",".join("?" * len(part))
            mapping += [[r["ast_id"], r["vuln_id"]] for r in c.execute(
                f"SELECT ast_id, vuln_id FROM ast_map WHERE ast_id IN ({marks}) ORDER BY ast_id, vuln_id", part)]
        imports: dict[int, dict] = {}
        for part in _chunks(sorted({int(m["import_id"]) for m in members if m.get("import_id") is not None})):
            marks = ",".join("?" * len(part))
            for r in c.execute(f"SELECT id, filename, created_at FROM imports WHERE id IN ({marks})", part):
                imports[int(r["id"])] = {"filename": r["filename"], "created_at": r["created_at"]}
        # ADR-0091: исследование компонента, решение по нему, наборы дефекта и их тексты – тем же чтением
        from app.sca import package_key
        from app.sca_contract import input_ref as package_ref
        ref = package_ref(eco, name, version)
        # исследование и решение компонента – по ключу строки задания (имя и версия очищены, sca.package_key): невидимый
        # знак в имени из выгрузки не отрывает карточку от исследования; наборы дефекта – по-прежнему по ref пакета
        research_ref = package_ref(*package_key({"ecosystem": eco, "component": name, "version": version}))
        research = c.execute("SELECT * FROM sca2_research WHERE project_id = ? AND input_ref = ? ORDER BY revision DESC"
                             " LIMIT 1", (project_id, research_ref)).fetchone()
        decision = c.execute("SELECT * FROM sca2_decisions WHERE project_id = ? AND input_ref = ? AND state = 'current'"
                             " ORDER BY revision DESC LIMIT 1", (project_id, research_ref)).fetchone()
        placed = {r["hub_id"]: {"set_no": r["set_no"], "no_defect_reason": r["no_defect_reason"]} for r in c.execute(
            "SELECT hub_id, set_no, no_defect_reason FROM sca_set_members WHERE project_id = ? AND input_ref = ?",
            (project_id, ref))}
        sets = {0: {"revision": 0, "excluded": []}}
        for r in c.execute("SELECT set_no, revision, excluded_json FROM sca_defect_sets WHERE project_id = ?"
                           " AND input_ref = ?", (project_id, ref)):
            sets[int(r["set_no"])] = {"revision": int(r["revision"]), "excluded": loads(r["excluded_json"], [])}
        texts = {}
        for r in c.execute("SELECT * FROM sca_package_texts WHERE project_id = ? AND input_ref = ?", (project_id, ref)):
            row_text = dict(r)
            row_text["ast"] = loads(row_text.pop("ast_json"), {})
            texts[int(row_text["set_no"])] = row_text
        base = defect_key_sca(name, version, eco)
        numbers = {r["defect_key"]: int(r["number"]) for r in c.execute(
            "SELECT defect_key, number FROM defects WHERE project_id = ? AND (defect_key = ? OR substr(defect_key, 1, ?) = ?)",
            (project_id, base, len(base) + 1, base + "#"))}
        # решения оператора о применимости уязвимостей пакета (ADR-0094 Р3)
        applicability = {}
        for r in c.execute("SELECT * FROM sca_applicability WHERE project_id = ? AND input_ref = ?", (project_id, ref)):
            item = dict(r)
            item["ids"] = loads(item.pop("ids_json"), [])
            applicability[item["vuln_key"]] = item
        research_row = self._research_row(dict(research)) if research else None
        # ответ исследования компонента – после прежних ответов пакета: главный, только если их нет (ADR-0108)
        from app.sca import research_answer
        from_research = research_answer(research_row, (eco, name, version))
        if from_research:
            answers.append(from_research)
        return {"own": own, "package": (eco, name, version), "members": members, "reviews": reviews, "answers": answers,
                "mapping": mapping, "imports": imports, "input_ref": ref, "research_ref": research_ref,
                "research": research_row,
                "component_decision": dict(decision) if decision else None,
                "placed": placed, "sets": sets, "texts": texts, "numbers": numbers, "applicability": applicability}

    @staticmethod
    def _sca_state_fingerprint(state: dict | None) -> str:
        """Отпечаток состояния _sca_package_state: данные и пометка «нет в выгрузке» находок пакета, редакции и подписи их
        решений, номер последнего ответа агента, соответствия AST → CVE."""
        if state is None:
            return "none"
        members = []
        for m in state["members"]:
            review = state["reviews"].get(m["hub_id"]) or {}
            # подпись выгрузки участника входит в отпечаток: текст дефекта называет её в области решения (повторная
            # загрузка того же файла с той же подписью текст не меняет и выдачу не закрывает)
            meta = (state.get("imports") or {}).get(m.get("import_id")) or {}
            label = export_label(meta.get("filename", ""), meta.get("created_at", ""))
            # идентичность пакета входит в отпечаток, только когда она из сведений Hub: без них – прежний отпечаток
            data = {k: v for k, v in m["data"].items() if k != "package"}
            if (m["data"].get("package") or {}).get("source") == "hub":
                data["package"] = m["data"]["package"]
            members.append([m["hub_id"], int(m["missing"]), hashlib.sha256(dumps(data).encode("utf-8")).hexdigest()[:16],
                            int(review.get("revision") or 0), review.get("finding_sig") or "", label,
                            review.get("decided_at") or "", review.get("kapo_state") or ""])
        latest = state["answers"][0]["id"] if state["answers"] else 0
        research = state.get("research") or {}
        decision = state.get("component_decision") or {}
        extra = [state.get("input_ref", ""),
                 [research.get("revision"), research.get("content_sig"), research.get("observed_at"),
                  research.get("imported_at")],
                 [decision.get("revision"), decision.get("action"), decision.get("target_version"),
                  decision.get("review_at"), decision.get("state")],
                 sorted([h, v["set_no"], v["no_defect_reason"]] for h, v in (state.get("placed") or {}).items()),
                 sorted([k, v["revision"], v["excluded"]] for k, v in (state.get("sets") or {}).items()),
                 sorted([k, v.get("revision"), v.get("text_sig"), v.get("version_checked_sig"),
                         v.get("text_checked_sig"), v.get("residual_checked_sig", ""), v.get("recommendation_note", "")]
                        for k, v in (state.get("texts") or {}).items()),
                 sorted([k, v] for k, v in (state.get("numbers") or {}).items()),
                 sorted([k, int(v.get("revision") or 0), v.get("decision"), int(v.get("research_revision") or 0),
                         sorted(v.get("ids") or []), v.get("reason")]
                        for k, v in (state.get("applicability") or {}).items())]
        return hashlib.sha256(dumps([members, latest, state["mapping"], extra]).encode("utf-8")).hexdigest()

    def _sca_defect_fingerprint(self, c: Connection, project_id: int, hub_id: str) -> str:
        return self._sca_state_fingerprint(self._sca_package_state(c, project_id, hub_id))

    def sca_defect_fingerprint(self, project_id: int, hub_id: str) -> str:
        with self._lock:
            return self._sca_defect_fingerprint(self._conn, project_id, hub_id)

    def sca_snapshot(self, project_id: int, hub_id: str) -> ScaSnapshot:
        """Согласованный снимок всего, из чего строятся ответ на сохранение решения SCA и текст дефекта: находка, решения и
        ответы её пакета, соответствия AST → CVE, номера дефектов, счётчики проекта, следующая непроверенная находка и
        отпечаток этого состояния. Читается одним захватом замка – ни импорт, ни загрузка ответа не вклиниваются между
        чтениями – и возвращается обычными данными: форматирование и обращения к справочникам идут уже без замка, на этих
        данных. Отпечаток, снятый здесь, описывает ровно то, из чего построен снимок."""
        with self._lock:
            exists = self._conn.execute("SELECT 1 FROM projects WHERE id = ?", (project_id,)).fetchone() is not None
            state = self._sca_package_state(self._conn, project_id, hub_id) if exists else None
            if state is None:
                return ScaSnapshot(project_id, hub_id, exists, None)
            numbers = {r["defect_key"]: int(r["number"]) for r in self._conn.execute(
                "SELECT defect_key, number FROM defects WHERE project_id = ?", (project_id,))}
            reserved = int(self._conn.execute(
                f"SELECT COALESCE(MAX(number), 0) FROM hub_defects WHERE project_id = ? AND {self.HUB_DEFECT_RESERVING}",
                (project_id,)).fetchone()[0] or 0)
            stats = self.review_stats(project_id)
            next_id = self.neighbor_unreviewed(project_id, state["own"]["pos"], "next", kinds=("SCA",))
            return ScaSnapshot(project_id, hub_id, exists, state, numbers=numbers, stats=stats, next_id=next_id,
                               fingerprint=self._sca_state_fingerprint(state), reserved=reserved)

    @staticmethod
    def _number_guard(c: Connection, project_id: int, key: str, number: int, expect_number: object,
                      foreign_check: Callable[[list[str]], None] | None) -> None:
        """Проверки номера в транзакции записи (Б9): номер ключа – тот, что видел человек (expect_number; NO_EXPECT –
        не сверяется), иначе StaleReview "number"; foreign_check(ключи других дефектов с этим номером) – отказ без
        подтверждения бросает исключение, и запись откатывается."""
        if expect_number is not NO_EXPECT:
            row = c.execute("SELECT number FROM defects WHERE project_id = ? AND defect_key = ?",
                            (project_id, key)).fetchone()
            if (int(row[0]) if row is not None else None) != expect_number:
                raise StaleReview("Номер дефекта изменили в другой вкладке.", "number")
        if foreign_check is not None:
            foreign_check([r[0] for r in c.execute(
                "SELECT defect_key FROM defects WHERE project_id = ? AND number = ? AND defect_key != ?"
                " ORDER BY defect_key", (project_id, number, key))])

    def set_sca_defect_number_checked(self, project_id: int, key: str, number: int, hub_id: str,
                                      fingerprint: str, *, expect_number: object = NO_EXPECT,
                                      foreign_check: Callable[[list[str]], None] | None = None) -> list[str]:
        """set_defect_number для SCA с повторной проверкой в той же транзакции: отпечаток находки, её пакета, решений
        участников группы, последнего ответа агента и соответствий AST → CVE (sca_defect_fingerprint) совпадает с тем,
        по которому построен текст, иначе номер не записывается (StaleReview). Удалённый проект – тоже StaleReview.
        expect_number и foreign_check – как в _number_guard."""
        if not isinstance(number, int) or isinstance(number, bool) or not 1 <= number <= 999_999:
            raise ValueError("номер дефекта – целое число от 1 до 999999")
        ts = now_iso()
        found = re.search(r"\]#\d+$", key)
        base = key[:key.rindex("#")] if found else key
        with self._tx() as c:
            if self._sca_defect_fingerprint(c, project_id, hub_id) != fingerprint:
                raise StaleReview("Состав группы, решения, ответ агента или соответствия изменились.", "source")
            # номер занят другим набором этого же пакета – отказ до записи (ADR-0091, таблица отказов)
            taken = c.execute("SELECT 1 FROM defects WHERE project_id = ? AND number = ? AND defect_key != ?"
                              " AND (defect_key = ? OR substr(defect_key, 1, ?) = ?)",
                              (project_id, number, key, base, len(base) + 1, base + "#")).fetchone()
            if key.startswith("sca:") and taken is not None:
                raise ValueError(f"Номер {number} уже у другого набора этого компонента: укажите другой номер.")
            self._number_guard(c, project_id, key, number, expect_number, foreign_check)
            try:
                c.execute("INSERT INTO defects(project_id, defect_key, number, updated_at, assigned_at) VALUES (?, ?, ?, ?, ?)"
                          " ON CONFLICT(project_id, defect_key) DO UPDATE SET number = excluded.number,"
                          " updated_at = excluded.updated_at, assigned_at = CASE WHEN defects.number = excluded.number AND defects.assigned_at <> '' THEN defects.assigned_at ELSE excluded.updated_at END", (project_id, key, number, ts, ts))
            except IntegrityError:
                raise StaleReview("Проект удалён.", "source") from None
            return [r["defect_key"] for r in c.execute(
                "SELECT defect_key FROM defects WHERE project_id = ? AND number = ? AND defect_key != ?"
                " ORDER BY defect_key", (project_id, number, key))]

    def set_defect_number_checked(self, project_id: int, key: str, number: int, hub_id: str, *, source_sig: str,
                                  revision: int, case_verdict_id: int | None, export: str | None = None,
                                  group_key: str = "",
                                  group_check: Callable[[list[dict], int | None, str], None] | None = None,
                                  expect_number: object = NO_EXPECT,
                                  foreign_check: Callable[[list[str]], None] | None = None) -> list[str]:
        """set_defect_number для SAST с повторной проверкой снимка в той же транзакции: текст дефекта собран из
        находки source_sig по решению редакции revision и вердикту case_verdict_id; если с тех пор находка исчезла,
        сменилась, решение сохранили заново или привязка вердикта изменилась, номер не записывается (StaleReview).
        Проект, удалённый во время выдачи, – тоже StaleReview, а не ошибка внешнего ключа."""
        if not isinstance(number, int) or isinstance(number, bool) or not 1 <= number <= 999_999:
            raise ValueError("номер дефекта – целое число от 1 до 999999")
        ts = now_iso()
        with self._tx() as c:
            source = self._source(c, project_id, hub_id)
            if source is None or source.get("missing"):
                raise StaleReview("Находки нет в текущей выгрузке.", "source")
            if source_signature(source) != source_sig:
                raise StaleReview("Находка или источник её кода изменились.", "source")
            if export is not None and export_label(source.get("import_filename", ""), source.get("import_at", "")) != export:
                # текст дефекта называет выгрузку находки: другая подпись выгрузки между сборкой и записью – другой текст
                raise StaleReview("Загружена новая выгрузка.", "source")
            row = c.execute("SELECT revision FROM reviews WHERE project_id = ? AND hub_id = ?",
                            (project_id, hub_id)).fetchone()
            if row is None or int(row["revision"]) != int(revision):
                raise StaleReview("Решение сохранили заново.", "revision")
            case = c.execute("SELECT verdict_id FROM cases WHERE project_id = ? AND hub_id = ?",
                             (project_id, hub_id)).fetchone()
            if (case["verdict_id"] if case is not None else None) != case_verdict_id:
                raise StaleReview("Вердикт модели изменился.", "verdict")
            if group_check is not None:  # группа (ADR-0089): решения, текст и номер – тем же снимком, что и запись
                own = c.execute("SELECT number, COALESCE(NULLIF(assigned_at, ''), updated_at) AS at FROM defects"
                                " WHERE project_id = ? AND defect_key = ?", (project_id, key)).fetchone()
                # собственные номер и время назначения – из этой же транзакции (ADR-0095 п. 4)
                group_check(self._group_rows(c, project_id, group_key, hub_id), int(own["number"]) if own else None,
                            str(own["at"] or "") if own else "")
            self._number_guard(c, project_id, key, number, expect_number, foreign_check)
            try:
                c.execute("INSERT INTO defects(project_id, defect_key, number, updated_at, assigned_at) VALUES (?, ?, ?, ?, ?)"
                          " ON CONFLICT(project_id, defect_key) DO UPDATE SET number = excluded.number,"
                          " updated_at = excluded.updated_at, assigned_at = CASE WHEN defects.number = excluded.number AND defects.assigned_at <> '' THEN defects.assigned_at ELSE excluded.updated_at END", (project_id, key, number, ts, ts))
            except IntegrityError:
                raise StaleReview("Проект удалён.", "source") from None
            return [r["defect_key"] for r in c.execute(
                "SELECT defect_key FROM defects WHERE project_id = ? AND number = ? AND defect_key != ?"
                " ORDER BY defect_key", (project_id, number, key))]

    def set_defect_number(self, project_id: int, key: str, number: int) -> list[str]:
        """Запоминает номер дефекта; возвращает ключи других находок проекта с тем же номером (предупреждение)."""
        if not isinstance(number, int) or isinstance(number, bool) or not 1 <= number <= 999_999:
            raise ValueError("номер дефекта – целое число от 1 до 999999")
        ts = now_iso()
        with self._tx() as c:
            c.execute("INSERT INTO defects(project_id, defect_key, number, updated_at, assigned_at) VALUES (?, ?, ?, ?, ?)"
                      " ON CONFLICT(project_id, defect_key) DO UPDATE SET number = excluded.number,"
                      " updated_at = excluded.updated_at, assigned_at = CASE WHEN defects.number = excluded.number AND defects.assigned_at <> '' THEN defects.assigned_at ELSE excluded.updated_at END", (project_id, key, number, ts, ts))
            return [row["defect_key"] for row in c.execute(
                "SELECT defect_key FROM defects WHERE project_id = ? AND number = ? AND defect_key != ?"
                " ORDER BY defect_key", (project_id, number, key))]

    def save_ast_map(self, pairs: Iterable[tuple[str, str]], source: str = "") -> int:
        """Соответствие идентификаторов AST → CVE или GHSA (например, из выгрузки поставщика: CSV с двумя
        колонками). Повторная пара не дублируется. Возвращает, сколько пар добавлено."""
        ts = now_iso()
        added = 0
        with self._tx() as c:
            for ast_id, vuln_id in pairs:
                ast_id, vuln_id = str(ast_id or "").strip(), str(vuln_id or "").strip()
                if ast_id and vuln_id:
                    added += c.execute("INSERT INTO ast_map(ast_id, vuln_id, source, created_at)"
                                       " VALUES (?, ?, ?, ?) ON CONFLICT(ast_id, vuln_id) DO NOTHING",
                                       (ast_id, vuln_id, source.strip(), ts)).rowcount
        return added

    def ast_map(self, ids: Iterable[str] | None = None) -> dict[str, list[str]]:
        """{AST-…: [CVE-… или GHSA-…]}; ids – только эти идентификаторы AST (None – все)."""
        rows: list[dict] = []
        if ids is None:
            rows = self._all("SELECT ast_id, vuln_id FROM ast_map ORDER BY ast_id, vuln_id")
        else:
            for part in _chunks(sorted({str(x) for x in ids})):
                marks = ",".join("?" * len(part))
                rows += self._all(f"SELECT ast_id, vuln_id FROM ast_map WHERE ast_id IN ({marks})"
                                  " ORDER BY ast_id, vuln_id", part)
        result: dict[str, list[str]] = {}
        for row in rows:
            result.setdefault(row["ast_id"], []).append(row["vuln_id"])
        return result

    # ------------------------------------------------------------------ прогоны

    def create_run(self, project_id: int, model: str, scope: str, prompt_version: str,
                   hub_ids: list[str], fresh: bool = False, origin: str = "", *,
                   execution: Mapping[str, Any] | None = None, execution_id: int | None = None,
                   parent_run_id: int | None = None, queue_scope: str | None = None) -> int:
        """Прогон в очереди. fresh – не брать вердикты, полученные до этого прогона (спросить модель заново). origin –
        откуда запущен (RUN_ORIGINS, ADR-0097): project, card (пересмотр из карточки), retry (повтор ошибок).

        Снимок исполнителя (ADR-0102) пишется той же транзакцией: execution – значения нового снимка
        (executors.execution_values), execution_id – уже существующий снимок («Повторить ошибочные» переносит снимок
        прежнего прогона). parent_run_id – прогон-продолжение: прежний прогон, если он в очереди или на паузе,
        останавливается в той же транзакции с отметкой, каким прогоном продолжен; прогон в другом состоянии
        (идёт) – RuntimeError, ничего не записано. queue_scope – охват: состав прогона и исключённые охватом считаются
        одним чтением в этой транзакции (бэклог 104), hub_ids – выбранные для охвата selected; пусто – EmptyQueue."""
        ts = now_iso()
        with self._tx() as c:
            excluded = None
            if queue_scope is not None:
                hub_ids, excluded = self.sast_queue_in(c, project_id, queue_scope, hub_ids)
                if not hub_ids:
                    raise EmptyQueue("Нет находок SAST для выбранного охвата.")
            if execution is not None:
                self._check_profile_allows(c, execution.get("provider_id"), None)
                execution_id = self._insert_execution(c, execution, ts)
            elif execution_id is not None:  # перенос снимка («Повторить ошибочные»): профиль включён, адрес прежний
                carried = c.execute("SELECT provider_id, base_url, trust, options_json FROM llm_executions WHERE id = ?",
                                    (execution_id,)).fetchone()
                if carried is None:
                    raise ProfileChanged("снимок исполнителя не найден")
                self._check_profile_allows(c, carried[0], carried[1],
                                           _snapshot_confirmed(carried[3]) if carried[2] == "lan" else None)
            run_id = int(c.execute(
                "INSERT INTO runs(project_id, state, scope, model, prompt_version, fresh, total, created_at,"
                " updated_at, origin, execution_id, parent_run_id) VALUES (?, 'queued', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)" " RETURNING id",
                (project_id, scope, model, prompt_version, 1 if fresh else 0, len(hub_ids), ts, ts,
                 origin if origin in RUN_ORIGINS else "", execution_id, parent_run_id)).fetchone()[0])
            if parent_run_id is not None:
                parent = c.execute("SELECT state FROM runs WHERE id = ?", (parent_run_id,)).fetchone()
                if parent is None or parent[0] == "running":
                    raise RuntimeError("прежний прогон идёт или не найден: продолжение не создано")
                if parent[0] in ("queued", "paused"):
                    c.execute("UPDATE runs SET state = 'stopped', control = '', last_error = ?, updated_at = ?,"
                              " finished_at = COALESCE(finished_at, ?) WHERE id = ?",
                              (f"Продолжен прогоном №{run_id}.", ts, ts, parent_run_id))
            c.executemany("INSERT INTO run_items(run_id, seq, hub_id) VALUES (?, ?, ?)",
                          [(run_id, seq, hub_id) for seq, hub_id in enumerate(hub_ids)])
            from app.journal import capture
            capture(c, run_id, project_id, hub_ids, excluded)
            self._touch(c, project_id, ts)
        return run_id

    def get_run(self, run_id: int) -> dict | None:
        return self._one("SELECT * FROM runs WHERE id = ?", (run_id,))

    def list_runs(self, project_id: int, limit: int = 10) -> list[dict]:
        return self._all("SELECT * FROM runs WHERE project_id = ? ORDER BY id DESC LIMIT ?", (project_id, limit))

    def active_runs(self, project_id: int | None = None) -> list[dict]:
        marks = ",".join("?" * len(ACTIVE_RUN_STATES))
        if project_id is None:
            return self._all(f"SELECT * FROM runs WHERE state IN ({marks}) ORDER BY id", ACTIVE_RUN_STATES)
        return self._all(f"SELECT * FROM runs WHERE project_id = ? AND state IN ({marks}) ORDER BY id",
                         (project_id, *ACTIVE_RUN_STATES))

    def next_queued_run(self) -> dict | None:
        return self._one("SELECT * FROM runs WHERE state = 'queued' ORDER BY id LIMIT 1")

    def set_run_state(self, run_id: int, state: str, *, last_error: str | None = None,
                      only_from: tuple[str, ...] | None = None) -> bool:
        """Меняет состояние прогона. only_from – допустимые прежние состояния; False – прогон в другом состоянии.
        Принятая команда (control) снимается: она относилась к прежнему состоянию идущего прогона."""
        if state not in RUN_STATES:
            raise ValueError(f"неизвестное состояние прогона: {state}")
        ts = now_iso()
        sets = ["state = ?", "updated_at = ?", "control = ''"]
        params: list[Any] = [state, ts]
        if state == "running":
            sets.append("started_at = COALESCE(started_at, ?)")
            params.append(ts)
        if state in FINAL_RUN_STATES:
            sets.append("finished_at = ?")
            params.append(ts)
        if last_error is not None:
            sets.append("last_error = ?")
            params.append(last_error)
        sql = f"UPDATE runs SET {', '.join(sets)} WHERE id = ?"
        params.append(run_id)
        if only_from:
            sql += f" AND state IN ({','.join('?' * len(only_from))})"
            params.extend(only_from)
        with self._run_clocks_lock, self._tx() as c:
            changed = c.execute(sql, params).rowcount > 0
            if changed:
                from app.journal import transition
                transition(c, run_id, state, ts, clocks=self._run_clocks)
            return changed

    def set_run_control(self, run_id: int, control: str) -> bool:
        """Принятая команда идущего прогона: 'pause' или 'stop' выполняется после текущей находки, '' – снять.
        Команда хранится в базе, поэтому принятый «Стоп» не теряется при перезапуске (recover_interrupted).
        False – прогон не идёт."""
        if control not in ("", *RUN_CONTROLS):
            raise ValueError(f"неизвестная команда прогона: {control}")
        with self._tx() as c:
            return c.execute("UPDATE runs SET control = ?, updated_at = ? WHERE id = ? AND state = 'running'",
                             (control, now_iso(), run_id)).rowcount > 0

    def recover_interrupted(self) -> int:
        """После перезапуска: прогон, у которого был принят «Стоп», останавливается; остальные прогоны «идёт»
        и «в очереди» ставятся на паузу. Вопросы к модели без ответа закрываются с пояснением. Возвращает, сколько
        прогонов изменено."""
        ts = now_iso()
        with self._run_clocks_lock, self._tx() as c:
            from app.journal import transition
            for row in c.execute("SELECT id,updated_at FROM runs WHERE state='running'").fetchall():
                transition(c, row['id'], 'paused', row['updated_at'], interrupted=True, clocks=self._run_clocks)
            stopped = c.execute("UPDATE runs SET state = 'stopped', control = '', last_error = ?, finished_at = ?,"
                                " updated_at = ? WHERE state = 'running' AND control = 'stop'",
                                (STOPPED_NOTE, ts, ts)).rowcount
            paused = c.execute("UPDATE runs SET state = 'paused', control = '', last_error = ?, updated_at = ?"
                               " WHERE state IN ('running', 'queued')", (INTERRUPTED_NOTE, ts)).rowcount
            # К11: находка, запрос по которой ушёл внешнему провайдеру до перезапуска (метка sending_at), – «результат
            # неизвестен», повторно не отправляется; счётчики её прогона – как у ошибки
            self._settle_sending(c, None, UNKNOWN_AFTER_RESTART, ts)
            # вопрос внешнему провайдеру без ответа – тоже «результат неизвестен» (запрос мог быть оплачен)
            c.execute("UPDATE questions SET state = 'error', error = ?, answered_at = ? WHERE state = 'pending' AND"
                      " execution_id IN (SELECT id FROM llm_executions WHERE trust = 'external')",
                      (QUESTION_UNKNOWN_RESTART, ts))
            c.execute("UPDATE questions SET state = 'error', error = ?, answered_at = ? WHERE state = 'pending'",
                      (QUESTION_INTERRUPTED, ts))
        return stopped + paused

    @staticmethod
    def _settle_sending(c: Connection, run_id: int | None, note: str, ts: str) -> int:
        """К11: находки с меткой отправки без результата (одного прогона или всех) – «результат неизвестен»: ошибка с
        неполными замерами, счётчики прогона – как у ошибки; повторной отправки нет."""
        where, params = ("state = 'pending' AND sending_at IS NOT NULL", [])
        if run_id is not None:
            where, params = where + " AND run_id = ?", [int(run_id)]
        unknown = c.execute(f"SELECT run_id, COUNT(*) AS n FROM run_items WHERE {where} GROUP BY run_id",
                            params).fetchall()
        c.execute(f"UPDATE run_items SET state = 'error', error = ?, finished_at = ?, sending_at = NULL,"
                  f" stats_partial = 1 WHERE {where}", [note, ts, *params])
        for row in unknown:
            c.execute("UPDATE runs SET done = done + ?, failed = failed + ?, partial_stats = partial_stats + ?,"
                      " last_error = ?, updated_at = ? WHERE id = ?",
                      (int(row["n"]), int(row["n"]), int(row["n"]), note, ts, int(row["run_id"])))
        return sum(int(row["n"]) for row in unknown)

    def settle_sending_items(self, run_id: int) -> int:
        """Перед «Продолжить» и новым прогоном вместо прежнего: находки прогона с меткой отправки без результата
        (ответ не записан – база была занята) – «результат неизвестен», в очередь не возвращаются."""
        with self._tx() as c:
            return self._settle_sending(c, int(run_id), UNKNOWN_BEFORE_RESUME, now_iso())

    def mark_item_sending(self, run_id: int, item_id: int, sending: bool = True) -> bool:
        """Метка отправки находки внешнему провайдеру (К11) – до сетевого вызова; снимается, если запрос не ушёл
        (отказ допуска, 402), и в finish_item вместе с результатом. Перезапуск с меткой – «результат неизвестен»."""
        ts = now_iso() if sending else None
        with self._tx() as c:
            return c.execute("UPDATE run_items SET sending_at = ? WHERE id = ? AND run_id = ? AND state = 'pending'",
                             (ts, int(item_id), int(run_id))).rowcount == 1

    def pending_hub_ids(self, run_id: int) -> list[str]:
        """ID находок, которые прогон ещё не разобрал, по порядку."""
        return [row["hub_id"] for row in self._all("SELECT hub_id FROM run_items WHERE run_id = ? AND state = 'pending'"
                                                   " ORDER BY seq", (run_id,))]

    def next_pending_item(self, run_id: int) -> dict | None:
        return self._one("SELECT * FROM run_items WHERE run_id = ? AND state = 'pending' ORDER BY seq LIMIT 1",
                         (run_id,))

    def finish_item(self, run_id: int, item_id: int, state: str, *, case_hash: str = "",
                    verdict_id: int | None = None, error: str = "", seconds: float | None = None,
                    eval_tps: float | None = None, output_tokens: int = 0, eval_seconds: float = 0.0,
                    model_call: bool = False, model_seconds: float | None = None,
                    stats_partial: bool = False, eta_sample: bool = True) -> None:
        """Отмечает находку прогона обработанной и обновляет счётчики прогона одной транзакцией.

        seconds – сколько заняла находка (для ленты и длительности прогона); model_seconds – сколько из них
        приходится на ответ модели без загрузки модели в память (для оценки оставшегося времени; не задано –
        seconds). output_tokens и eval_seconds входят в среднюю скорость прогона и у неудачного ответа: модель
        их всё равно сгенерировала. stats_partial – замеры неполные (ответ прерван сбоем связи: что успела
        сгенерировать прерванная попытка, неизвестно); прогон считает такие находки (runs.partial_stats).
        eta_sample=False – ответ не входит в выборку оценки времени: он медленный или первый после загрузки
        модели (app/triage.py)."""
        if model_seconds is None:
            model_seconds = seconds
        if state not in ITEM_STATES or state == "pending":
            raise ValueError(f"неверное состояние находки прогона: {state}")
        ts = now_iso()
        with self._tx() as c:
            changed = c.execute(
                "UPDATE run_items SET state = ?, case_hash = ?, verdict_id = ?, error = ?, seconds = ?,"
                " eval_tps = ?, finished_at = ?, stats_partial = ?, sending_at = NULL"
                " WHERE id = ? AND run_id = ? AND state = 'pending'",
                (state, case_hash, verdict_id, error, seconds, eval_tps, ts, 1 if stats_partial else 0, item_id,
                 run_id)).rowcount
            if not changed:
                return
            c.execute("""
                UPDATE runs SET done = done + 1,
                                failed = failed + ?, cached = cached + ?, skipped = skipped + ?,
                                model_calls = model_calls + ?, model_seconds = model_seconds + ?,
                                output_tokens = output_tokens + ?, eval_seconds = eval_seconds + ?,
                                last_tps = COALESCE(?, last_tps), partial_stats = partial_stats + ?, updated_at = ?
                 WHERE id = ?""",
                      (1 if state == "error" else 0, 1 if state == "cached" else 0, 1 if state == "skipped" else 0,
                       1 if model_call else 0, float(model_seconds or 0.0) if model_call else 0.0,
                       int(output_tokens or 0), float(eval_seconds or 0.0),
                       eval_tps if model_call and eval_tps else None, 1 if stats_partial else 0, ts, run_id))
            if error and state == "error":
                c.execute("UPDATE runs SET last_error = ? WHERE id = ?", (error, run_id))
            if model_call and state == 'done' and not stats_partial and eta_sample:
                from app.journal import call_sample
                call_sample(c, run_id, model_seconds)

    def recent_items(self, run_id: int, limit: int = 12) -> list[dict]:
        """Последние обработанные находки прогона (для ленты): с номером находки и вердиктом."""
        rows = self._all("""
            SELECT ri.id, ri.seq, ri.hub_id, ri.state, ri.error, ri.seconds, ri.eval_tps, ri.finished_at,
                   ri.stats_partial, f.id AS finding_id, f.data_json, v.verdict, v.confidence
              FROM run_items ri
              JOIN runs ru ON ru.id = ri.run_id
              LEFT JOIN findings f ON f.project_id = ru.project_id AND f.hub_id = ri.hub_id
              LEFT JOIN verdicts v ON v.id = ri.verdict_id
             WHERE ri.run_id = ? AND ri.state != 'pending'
             ORDER BY ri.finished_at DESC NULLS LAST, ri.id DESC
             LIMIT ?""", (run_id, limit))
        for row in rows:
            data = loads(row.pop("data_json"), {})
            row["rule"] = data.get("rule", "")
            row["file"] = data.get("file", "")
            row["line"] = data.get("line")
        return rows

    def run_errors(self, run_id: int) -> list[dict]:
        """Ошибки находок прогона для страницы: ID, правило, технический текст и признак возможности повтора.

        retryable – находка SAST есть в текущей выгрузке и после этого прогона её не разобрал другой: только такие
        находки берёт новый прогон по ошибкам. resolved_run – номер более позднего прогона того же проекта, где находка
        получила вердикт (иначе «Повторить ошибочные» отправил бы её ещё раз – платный
        дубль). Схема базы не меняется: всё читается из run_items.error и findings.
        """
        rows = self._all("""
            SELECT ri.hub_id, ri.error, ri.seq, f.id AS finding_id, f.kind, f.missing, f.data_json,
                   (SELECT MAX(later.run_id) FROM run_items later JOIN runs lr ON lr.id = later.run_id
                     WHERE lr.project_id = ru.project_id AND later.hub_id = ri.hub_id AND later.run_id > ri.run_id
                       AND later.state IN ('done', 'cached')) AS resolved_run
              FROM run_items ri
              JOIN runs ru ON ru.id = ri.run_id
              LEFT JOIN findings f ON f.project_id = ru.project_id AND f.hub_id = ri.hub_id
             WHERE ri.run_id = ? AND ri.state = 'error'
             ORDER BY ri.seq""", (run_id,))
        result = []
        for row in rows:
            data = loads(row.pop("data_json"), {})
            resolved = int(row["resolved_run"]) if row.get("resolved_run") else None
            result.append({
                "hub_id": row["hub_id"], "error": row["error"], "finding_id": row["finding_id"],
                "rule": data.get("rule", ""), "resolved_run": resolved,
                "retryable": bool(row["finding_id"] and row["kind"] == "SAST" and not row["missing"] and not resolved),
                # К11: «результат неизвестен» (запрос мог быть оплачен) – повтор только по отдельной отметке
                "unknown": str(row["error"] or "").startswith("Результат неизвестен"),
            })
        return result

    def run_work_seconds(self, run_id: int) -> float:
        """Сколько прогон работал: сумма времени обработанных находок (паузы и простой не входят)."""
        return float(self._scalar("SELECT COALESCE(SUM(seconds), 0) FROM run_items WHERE run_id = ?"
                                  " AND state != 'pending'", (run_id,)) or 0.0)

    def run_tps_samples(self, run_id: int, limit: int = 20) -> list[float]:
        """Скорость (ток/с) последних успешных ответов прогона, от старых к новым. Для ориентира медленного
        режима (app/triage.py): берутся только находки с вердиктом (state='done'), ошибки и кэш не считаются."""
        rows = self._all("SELECT eval_tps FROM run_items WHERE run_id = ? AND state = 'done'"
                         " AND eval_tps IS NOT NULL AND eval_tps > 0 ORDER BY id DESC LIMIT ?", (run_id, int(limit)))
        return [float(row["eval_tps"]) for row in reversed(rows)]

    def model_tps_samples(self, model: str, exclude_run_id: int | None = None, limit: int = 200,
                          executor: tuple[str, str] | None = None) -> list[float]:
        """Скорость (ток/с) успешных ответов этой модели в прошлых прогонах. Для ориентира, пока в текущем
        прогоне меньше трёх ответов. Текущий прогон исключается (exclude_run_id). executor – (протокол, адрес)
        исполнителя (ADR-0102, П24): одна конфигурация – одна статистика, независимо от профиля и его версии; другой
        адрес – своя; прогоны без снимка (адрес не установлен) в неё не входят."""
        sql = ("SELECT ri.eval_tps FROM run_items ri JOIN runs r ON r.id = ri.run_id"
               + (" JOIN llm_executions e ON e.id = r.execution_id" if executor else "")
               + " WHERE r.model = ? AND ri.state = 'done' AND ri.eval_tps IS NOT NULL AND ri.eval_tps > 0")
        params: list[Any] = [str(model)]
        if executor:
            sql += " AND e.kind = ? AND e.base_url = ?"
            params += [str(executor[0]), str(executor[1])]
        if exclude_run_id is not None:
            sql += " AND r.id != ?"
            params.append(int(exclude_run_id))
        sql += " ORDER BY ri.id DESC LIMIT ?"
        params.append(int(limit))
        rows = self._all(sql, params)
        return [float(row["eval_tps"]) for row in reversed(rows)]

    def verdict_by_request_in_run(self, run_id: int, request_key: str) -> dict | None:
        """Ответ модели на этот же запрос, полученный в этом прогоне (для прогона «заново, без кэша», ADR-0084):
        ответ того же запроса из другого прогона сюда не попадает."""
        if not request_key:
            return None
        row = self._one("SELECT v.* FROM run_items ri JOIN verdicts v ON v.id = ri.verdict_id"
                        " WHERE ri.run_id = ? AND ri.state = 'done' AND v.request_key = ? ORDER BY v.id DESC LIMIT 1",
                        (run_id, request_key))
        return self._verdict_row(row) if row else None

    def case_done_in_run(self, run_id: int, case_hash: str) -> bool:
        """Модель уже ответила на такой случай в этом прогоне (для прогона «заново, без кэша»)."""
        return self._scalar("SELECT 1 FROM run_items WHERE run_id = ? AND case_hash = ? AND state = 'done' LIMIT 1",
                            (run_id, case_hash)) is not None

    def pending_model_groups(self, run_id: int) -> tuple[int, int]:
        """(сколько находок ещё ждёт, сколько из них, по оценке, потребует вызова модели).

        Дубли (тот же ключ группы в той же кодовой базе, что у уже разобранной в этом прогоне находки) почти
        всегда берут готовый вердикт из кэша, поэтому в оценке считаются группы, а не находки.
        """
        row = self._one("""
            WITH items AS (
                SELECT ri.state,
                       COALESCE(f.codebase, '') || '|' || COALESCE(NULLIF(f.group_key2, ''), 'id:' || ri.hub_id) AS gk
                  FROM run_items ri
                  JOIN runs ru ON ru.id = ri.run_id
                  LEFT JOIN findings f ON f.project_id = ru.project_id AND f.hub_id = ri.hub_id
                 WHERE ri.run_id = ?
            )
            SELECT (SELECT COUNT(*) FROM items WHERE state = 'pending') AS pending,
                   (SELECT COUNT(DISTINCT gk) FROM items
                     WHERE state = 'pending'
                       AND gk NOT IN (SELECT gk FROM items WHERE state IN ('done', 'cached'))) AS calls""",
                        (run_id,))
        return (int(row["pending"] or 0), int(row["calls"] or 0)) if row else (0, 0)

    # ============================================================================ операции в Hub (ADR-0114)

    def hub_enqueue(self, *, purpose: str, request: dict, hub_url: str, app_id: int | None,
                    project_id: int | None = None, targets: list[dict] | None = None, text: str = "",
                    check: Callable[[Connection], None] | None = None, key_extra: str = "") -> dict:
        """Ставит операцию в очередь исполнителю; возвращает её строку. ValueError (по-русски), если такая операция
        уже есть (тот же ключ – открытая или выполненная) или у одной из находок есть открытая операция того же
        назначения (блокировка целей). check(c) – проверка в той же транзакции до записи (статус из карточки:
        редакции решений целей те же, что при сборке запроса); исключение откатывает постановку. Запись фиксируется до
        выдачи задания (ADR-0114 п. 3). key_extra – дополнительное отличие ключа операции (hub_ops.op_key)."""
        return self.hub_enqueue_many([dict(purpose=purpose, request=request, hub_url=hub_url, app_id=app_id,
                                           project_id=project_id, targets=targets, text=text, key_extra=key_extra)],
                                     check=check)[0]

    def hub_enqueue_many(self, items: list[dict], check: Callable[[Connection], None] | None = None
                         ) -> list[dict]:
        """Несколько операций одной транзакцией – все или ни одной (чтения одной сверки, ADR-0115); поля элемента –
        как у hub_enqueue."""
        with self._tx() as c:
            if check is not None:
                check(c)
            return [self._hub_insert(c, **item) for item in items]

    def _hub_insert(self, c: Connection, *, purpose: str, request: dict, hub_url: str, app_id: int | None,
                    project_id: int | None = None, targets: list[dict] | None = None, text: str = "",
                    key_extra: str = "") -> dict:
        from app import hub_ops
        if self.hub_disabled:  # единственная точка вставки в hub_ops: в стенде без Hub очередь не наполняется
            raise HubDisabledInStand(HUB_DISABLED_TEXT)
        if purpose not in hub_ops.PURPOSES:
            raise ValueError(f"Неизвестное назначение операции «{purpose}».")
        hub_ops.check_operation(purpose, request, app_id)
        targets = list(targets or [])
        if purpose == "sync_read" and (len(targets) != 1 or targets[0].get("issue_type") != "HUB_SYNC"
                                       or not targets[0].get("issue_id")):
            raise ValueError("sync_read: нужна непустая цель запуска HUB_SYNC.")
        key = hub_ops.op_key(hub_url, app_id, purpose, targets, text, request, key_extra)
        locks = hub_ops.lock_keys(hub_url, app_id, purpose, targets)
        base = hub_ops.hub_base(hub_url)
        writes = hub_ops.is_write(purpose)
        ts = now_iso()
        same = c.execute("SELECT id, state FROM hub_ops WHERE op_key = ?", (key,)).fetchone()
        if same is not None:
            if same["state"] in hub_ops.OPEN_STATES:
                raise ValueError(f"Такая операция уже в очереди (№{same['id']}, состояние «{same['state']}»).")
            if same["state"] == "done" and writes:
                raise ValueError(f"Такая операция уже выполнена (№{same['id']}): второй раз не отправляется.")
            # чтение после закрытия ставится снова; у записи failed или cancelled освобождает ключ:
            # прежняя строка переименовывается
            c.execute("UPDATE hub_ops SET op_key = op_key || ':' || id WHERE id = ?", (same["id"],))
        if locks:
            open_rows = c.execute("SELECT id, lock_keys FROM hub_ops WHERE hub_url = ? AND purpose = ?"
                                  " AND state IN ('queued', 'taken', 'unknown') ORDER BY id", (base, purpose)).fetchall()
            for row in open_rows:
                if set(loads(row["lock_keys"], [])) & set(locks):
                    raise ValueError(f"У находки уже есть незакрытая операция «{purpose}» (№{row['id']}): "
                                     "дождитесь её итога или сверьте результат.")
        cur = c.execute(
            "INSERT INTO hub_ops(project_id, purpose, op_key, lock_keys, targets_json, request_json, hub_url,"
            " app_id, text_hash, text_norm, state, created_at, updated_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'queued', ?, ?)" " RETURNING id",
            (project_id, purpose, key, dumps(locks), dumps(targets), dumps(request), base, app_id,
             hub_ops.text_hash(text) if text else "", hub_ops.normalize_text(text)[:20000], ts, ts))
        return dict(c.execute("SELECT * FROM hub_ops WHERE id = ?", (cur.fetchone()[0],)).fetchone())

    def hub_op(self, op_id: int) -> dict | None:
        row = self._one("SELECT * FROM hub_ops WHERE id = ?", (op_id,))
        if row is None:
            return None
        row["attempts"] = self._all("SELECT * FROM hub_attempts WHERE op_id = ? ORDER BY id", (op_id,))
        return row

    def hub_ops_list(self, project_id: int | None = None, states: Iterable[str] | None = None,
                     limit: int = 200) -> list[dict]:
        where, params = [], []
        if project_id is not None:
            where.append("project_id = ?")
            params.append(project_id)
        states = list(states or [])
        if states:
            where.append(f"state IN ({','.join('?' for _ in states)})")
            params.extend(states)
        sql = "SELECT * FROM hub_ops" + (" WHERE " + " AND ".join(where) if where else "") + " ORDER BY id DESC LIMIT ?"
        return self._all(sql, (*params, int(limit)))

    def hub_unchained_resets(self) -> list[dict]:
        """Первые шаги замены комментария (ADR-0130), выполненные без последствий: промежуточный статус с записанным вторым
        шагом (`then`), у которого нет отметки о постановке (`then.chained`). Все, без предела: восстановление при
        запуске (hub_effects.recover_chains)."""
        return self._all("SELECT * FROM hub_ops WHERE purpose = 'status' AND state = 'done'"
                         " AND (request_json::json ->> 'then') IS NOT NULL"
                         " AND (request_json::json -> 'then' ->> 'chained') IS NULL ORDER BY id")

    @staticmethod
    def _hub_write_paused_in(c: Any) -> bool:
        row = c.execute("SELECT value_json FROM settings WHERE key = 'hub_write_paused'").fetchone()
        return bool(row is not None and loads(row[0], False))

    def hub_write_paused(self) -> bool:
        """Пауза выдачи записи (ADR-0128, п. 6.6): исполнитель получает только операции чтения."""
        return self._store.read(self._hub_write_paused_in)

    def hub_unknown_writes(self) -> int:
        """Сколько операций записи с неизвестным исходом ещё не сверено с Hub."""
        from app import hub_ops
        marks = ",".join("?" * len(hub_ops.WRITE_PURPOSES))
        return int(self._scalar(f"SELECT COUNT(*) FROM hub_ops WHERE state = 'unknown' AND purpose IN ({marks})", hub_ops.WRITE_PURPOSES) or 0)

    def set_hub_write_paused(self, paused: bool, *, accept_unknown: bool = False) -> None:
        """Снять паузу при операциях записи с неизвестным исходом или до принятия состояния Hub после восстановления копии можно только отметкой
        accept_unknown (проверка в той же транзакции). Включить или снять паузу; признак хранится в базе и не снимается при запуске."""
        from app import hub_sync
        with self._tx() as c:
            if paused:
                c.execute("INSERT INTO settings(key, value_json, updated_at) VALUES ('hub_write_paused', 'true', ?)"
                          " ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json,"
                          " updated_at = excluded.updated_at", (now_iso(),))
            else:
                if not accept_unknown:
                    from app import hub_ops
                    marks = ",".join("?" * len(hub_ops.WRITE_PURPOSES))
                    unknown = c.execute(f"SELECT COUNT(*) FROM hub_ops WHERE state = 'unknown' AND purpose IN ({marks})",
                                        hub_ops.WRITE_PURPOSES).fetchone()[0]
                    if unknown:
                        raise HubUnknownWrites(int(unknown))
                    waiting = hub_sync.resync_pending_in(c)
                    if waiting:
                        raise HubResyncRequired(len(waiting))
                hub_sync.clear_resync_in(c)
                c.execute("DELETE FROM settings WHERE key = 'hub_write_paused'")

    def settle_after_restore(self) -> dict:
        """После восстановления копии (ADR-0128, п. 9): выданная после неё работа могла выполниться, а копия этого не знает. Ничто, бывшее в работе,
        не ведёт к записи: пауза выдачи записи; строка дефекта без итога и вся незавершённая запись снимаются, источник сведений – Hub (синхронизация
        и принятие её результата); чтение – сбой, его можно поставить снова. Отметок о том, что Hub что-то сделал или нет, это не добавляет."""
        from app import hub_defects, hub_ops, hub_sync
        ts = now_iso()
        note = "база восстановлена из копии: операция снята, текущее состояние покажет синхронизация с Hub"
        failed = cancelled = chains = 0
        with self._tx() as c:
            c.execute("INSERT INTO settings(key, value_json, updated_at) VALUES ('hub_write_paused', 'true', ?)"
                      " ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json, updated_at = excluded.updated_at", (ts,))
            hub_sync.require_resync_in(c, ts)
            defects = hub_defects.settle_restored_in(c, ts)  # первыми: у их операций своё пояснение
            for row in c.execute("SELECT id, purpose, state FROM hub_ops WHERE state IN ('queued', 'taken', 'unknown')").fetchall():
                if hub_ops.is_write(row["purpose"]):
                    cancelled += c.execute("UPDATE hub_ops SET state = 'cancelled', error = ?, updated_at = ?, closed_at = ? WHERE id = ?",
                                           (note, ts, ts, row["id"])).rowcount
                elif row["state"] != "unknown":
                    failed += c.execute("UPDATE hub_ops SET state = 'failed', error = ?, updated_at = ?, closed_at = ? WHERE id = ?",
                                        (note, ts, ts, row["id"])).rowcount
                    if row["purpose"] == "sync_read":
                        hub_sync.expire_in(c, row["id"], note)
            # второй шаг цепочки замены комментария мог уйти после копии: chain_replace снимет прежнюю отметку, а шаг не поставит; это решает оператор по Hub
            for row in c.execute("SELECT id, request_json FROM hub_ops WHERE state = 'done'").fetchall():
                request = loads(row["request_json"], {}) or {}
                link = request.get("then") if isinstance(request, dict) else None
                if isinstance(link, dict) and link.get("chained") is None:
                    request["then"] = {**link, "stop_after_restore": True}
                    chains += c.execute("UPDATE hub_ops SET request_json = ?, updated_at = ? WHERE id = ?", (dumps(request), ts, row["id"])).rowcount
        return {"hub_write_paused": True, "failed": failed, "cancelled": cancelled, "chains": chains, "defects": defects}

    def hub_expire_leases(self, now: str | None = None) -> int:
        """Истёкшие аренды: запись – «результат неизвестен» (повтор – только после сверки), чтение – «не удалось».
        Возвращает число."""
        from app import hub_ops
        ts = now or now_iso()
        with self._tx() as c:
            rows = c.execute("SELECT a.op_id, o.purpose FROM hub_attempts a JOIN hub_ops o ON o.id = a.op_id"
                             " WHERE o.state = 'taken' AND a.received_at IS NULL AND a.taken_until < ?",
                             (ts,)).fetchall()
            if self._hub_write_paused_in(c):  # пауза записи: опрос не меняет состояние операций записи
                rows = [r for r in rows if not hub_ops.is_write(r["purpose"])]
            for row in rows:
                # запись – исход неизвестен (повтор только после сверки); чтение без побочных эффектов – просто
                # не удалось, его можно поставить снова
                state = "unknown" if hub_ops.is_write(row["purpose"]) else "failed"
                c.execute("UPDATE hub_ops SET state = ?, error = ?, updated_at = ?, closed_at = ?"
                          " WHERE id = ? AND state = 'taken'",
                          (state, "исполнитель не вернул результат в срок аренды", ts,
                           ts if state == "failed" else None, row["op_id"]))
                if row["purpose"] == "sync_read":
                    from app import hub_sync
                    hub_sync.expire_in(c, row["op_id"], "Исполнитель не вернул результат в срок аренды.")
            return len(rows)

    def hub_claim(self, worker_id: str, hub_url: str, lease_s: int, now: str | None = None,
                  sync_protocol: int = 0) -> dict | None:
        """Атомарно выдаёт исполнителю первую операцию очереди для его Hub: операция – taken, попытка с арендой.
        Возвращает {op, attempt} или None, если очереди нет."""
        from app import hub_ops
        if self.hub_disabled:  # стенд без Hub: заданий исполнителю не выдаётся
            return None
        ts = now or now_iso()
        # формат now_iso (ISO 8601 с зоной): сравнение сроков аренды – строковое, в том же формате
        until = (datetime.fromisoformat(ts) + timedelta(seconds=int(lease_s))).isoformat(timespec="seconds")
        base = hub_ops.hub_base(hub_url)
        with self._tx() as c:
            from app import hub_sync, hub_entity_versions
            candidates = c.execute("SELECT * FROM hub_ops WHERE state = 'queued' AND hub_url = ? ORDER BY id",
                                   (base,)).fetchall()
            if self._hub_write_paused_in(c):  # пауза записи: чтение выдаётся – неизвестные исходы закрываются им
                candidates = [r for r in candidates if not hub_ops.is_write(r["purpose"])]
            row = next((r for r in candidates if r["purpose"] != "sync_read"
                        or hub_sync.claimable(c, r, sync_protocol)), None)
            if row is None:
                return None
            changed = c.execute("UPDATE hub_ops SET state = 'taken', updated_at = ? WHERE id = ? AND state = 'queued'",
                                (ts, row["id"])).rowcount
            if not changed:
                return None
            if row["purpose"] == "sync_read":
                hub_sync.capture(c, row)
            req = loads(row["request_json"], {})
            req = hub_entity_versions.capture_issues(c, row, req)
            c.execute("UPDATE hub_ops SET request_json=? WHERE id=?", (dumps(req), row["id"]))
            match = re.fullmatch(r"/defects/([0-9]+)", req.get("path", ""))
            if match and req.get("method") == "GET" and row["project_id"] is not None:
                req["accepted_base"] = hub_entity_versions.current(
                    c, row["project_id"], row["hub_url"], row["app_id"], "defect", match[1])
                c.execute("UPDATE hub_ops SET request_json=? WHERE id=?", (dumps(req), row["id"]))
            row = {**dict(row), "request_json": dumps(req)}
            token = secrets.token_hex(16)
            cur = c.execute("INSERT INTO hub_attempts(op_id, worker_id, lease_token, taken_at, taken_until)"
                            " VALUES (?, ?, ?, ?, ?)" " RETURNING id", (row["id"], str(worker_id)[:80], token, ts, until))
            attempt = dict(c.execute("SELECT * FROM hub_attempts WHERE id = ?", (cur.fetchone()[0],)).fetchone())
            return {"op": dict(row), "attempt": attempt}

    def hub_result(self, attempt_id: int, lease_token: str, result: dict, now: str | None = None) -> dict:
        """Результат от исполнителя -> {"outcome": accepted|duplicate|late|rejected, "op": строка или None}.
        accepted – операция закрыта как done (код 2xx без ошибки) или failed; duplicate – результат уже был
        (идемпотентно); late – аренда истекла: попытка записана, операция остаётся «результат неизвестен»;
        rejected – чужой или неверный токен аренды."""
        from app import hub_ops
        ts = now or now_iso()
        clipped = hub_ops.clip_result(result)
        with self._tx() as c:
            attempt = c.execute("SELECT * FROM hub_attempts WHERE id = ?", (attempt_id,)).fetchone()
            if attempt is None or not lease_token or not secrets.compare_digest(str(attempt["lease_token"]),
                                                                                str(lease_token)):
                return {"outcome": "rejected", "op": None}
            op = dict(c.execute("SELECT * FROM hub_ops WHERE id = ?", (attempt["op_id"],)).fetchone())
            if attempt["received_at"] is not None:
                return {"outcome": "duplicate", "op": op}
            late = op["state"] != "taken" or attempt["taken_until"] < ts
            c.execute("UPDATE hub_attempts SET result_json = ?, error = ?, received_at = ?, late = ? WHERE id = ?",
                      (dumps(clipped), clipped["error"], ts, 1 if late else 0, attempt_id))
            if late:
                if op["state"] == "taken":  # аренда истекла, а срок ещё не обработан: закрыть сразу
                    state = "unknown" if hub_ops.is_write(op["purpose"]) else "failed"
                    c.execute("UPDATE hub_ops SET state = ?, error = ?, updated_at = ?, closed_at = ? WHERE id = ?",
                              (state, "результат пришёл после истечения аренды", ts,
                               ts if state == "failed" else None, op["id"]))
                if op["purpose"] == "sync_read":
                    from app import hub_sync
                    hub_sync.expire_in(c, op["id"], "Результат пришёл после истечения аренды.")
                return {"outcome": "late", "op": dict(c.execute("SELECT * FROM hub_ops WHERE id = ?",
                                                                 (op["id"],)).fetchone())}
            state, error = hub_ops.outcome_state(op["purpose"], clipped)
            c.execute("UPDATE hub_ops SET state = ?, result_json = ?, error = ?, updated_at = ?, closed_at = ?"
                      " WHERE id = ?", (state, dumps(clipped), error, ts, ts if state != "unknown" else None, op["id"]))
            if op["purpose"] == "status" and state == "done":
                # версии целей – вместе с переходом в done, не в отдельной транзакции отметок (ревью dev16, A1)
                from app import hub_entity_versions
                hub_entity_versions.confirm_targets(c, dict(c.execute("SELECT * FROM hub_ops WHERE id = ?",
                                                                      (op["id"],)).fetchone()))
            if op["purpose"] == "sync_read":
                from app import hub_sync
                fresh_op = dict(c.execute("SELECT * FROM hub_ops WHERE id=?", (op["id"],)).fetchone())
                hub_sync.delivery_in(self, c, fresh_op)
            return {"outcome": "accepted",
                    "op": dict(c.execute("SELECT * FROM hub_ops WHERE id = ?", (op["id"],)).fetchone())}

    def hub_open_ops(self, hub_url: str, purpose: str) -> list[dict]:
        """Незакрытые операции назначения purpose по адресу Hub (та же выборка, что при постановке – hub_enqueue):
        предпросмотр массовой отправки сверяет с их ключами блокировки состав партии и исключает занятые находки
        заранее, одним чтением на партию."""
        from app import hub_ops  # как в hub_enqueue: модуль правил очереди импортируется на месте
        return self._all("SELECT id, state, lock_keys FROM hub_ops WHERE hub_url = ? AND purpose = ?"
                         " AND state IN ('queued', 'taken', 'unknown') ORDER BY id",
                         (hub_ops.hub_base(hub_url), purpose))

    def hub_last_op(self, project_id: int, hub_id: str, purpose: str, *,
                    hub_url: str | None = None, app_id: int | None = None, state: str | None = None) -> dict | None:
        """Последняя операция назначения purpose, в целях которой есть находка hub_id (карточка показывает её
        состояние). При заданном hub_url – только в указанном Hub и приложении; state – только в этом состоянии
        (срок последней выполненной записи статуса, dev29); история не меняется."""
        params: tuple = (project_id, purpose, str(hub_id))
        scope = ""
        if hub_url is not None:
            from app.hub_ops import hub_base
            scope = " AND hub_url = ? AND app_id IS NOT DISTINCT FROM ?"
            params += (hub_base(hub_url), app_id)
        if state is not None:
            scope += " AND state = ?"
            params += (str(state),)
        return self._one(
            "SELECT * FROM hub_ops WHERE project_id = ? AND purpose = ? AND EXISTS ("
            " SELECT 1 FROM json_array_elements(hub_ops.targets_json::json) AS t(value) WHERE (t.value ->> 'hub_id') = ?)"
            + scope + " ORDER BY id DESC LIMIT 1", params)

    def status_in_hub(self, project_id: int, hub_id: str, status: str, probe: Callable[..., bool], hub_url: str,
                      app_id: int | None) -> bool:
        """Статус уже стоит в Hub у находки: probe(соединение, project_id, hub_id, status, hub_url, app_id) – правило
        маршрутов статуса (hub_status_routes.status_in_hub), здесь – только соединение базы под замком."""
        with self._lock:
            return bool(probe(self._conn, project_id, hub_id, status, hub_url, app_id))

    def hub_verifications(self, origin_id: int) -> list[dict]:
        """Чтения сверки операции origin_id (в целях – verify_of), по порядку постановки."""
        return self._all(
            "SELECT * FROM hub_ops WHERE purpose = 'read' AND (targets_json::json -> 0 ->> 'verify_of') = ?"
            " ORDER BY id", (str(int(origin_id)),))

    def hub_note(self, op_id: int, note: str) -> None:
        """Пояснение к операции («результат неизвестен»: итог сверки); состояние не меняется."""
        with self._tx() as c:
            c.execute("UPDATE hub_ops SET error = ?, updated_at = ? WHERE id = ?", (str(note)[:2000], now_iso(), op_id))

    def finding_sig(self, project_id: int, hub_id: str) -> str:
        """Отпечаток данных находки (finding_data_sig); находки нет – «»."""
        row = self._one("SELECT data_json FROM findings WHERE project_id = ? AND hub_id = ?", (project_id, str(hub_id)))
        return finding_data_sig(row["data_json"]) if row else ""

    def hub_resolve(self, op_id: int, state: str, note: str = "",
                    check: Callable[[Connection], bool] | None = None) -> dict | None:
        """Операция «результат неизвестен» закрывается по сверке (done) – только из unknown; возвращает строку или
        None, если она уже не unknown или check(c) в той же транзакции вернул False (сверка: проверенный круг уже не
        последний)."""
        if state not in ("done", "failed"):
            raise ValueError("сверка закрывает операцию только как done или failed")
        ts = now_iso()
        with self._tx() as c:
            if check is not None and not check(c):
                return None
            changed = c.execute("UPDATE hub_ops SET state = ?, error = ?, updated_at = ?, closed_at = ?"
                                " WHERE id = ? AND state = 'unknown'", (state, str(note)[:2000], ts, ts, op_id)).rowcount
            if not changed:
                return None
            resolved = dict(c.execute("SELECT * FROM hub_ops WHERE id = ?", (op_id,)).fetchone())
            if state == "done":  # закрытие сверкой: версии целей – той же транзакцией (ревью dev16, A1)
                from app import hub_entity_versions
                hub_entity_versions.confirm_targets(c, resolved)
            return resolved

    def hub_cancel(self, op_id: int) -> bool:
        """Отмена – только операции, которую исполнитель ещё не забрал; «результат неизвестен» закрывается
        сверкой, не отменой."""
        ts = now_iso()
        with self._tx() as c:
            return c.execute("UPDATE hub_ops SET state = 'cancelled', updated_at = ?, closed_at = ? WHERE id = ?"
                             " AND state = 'queued'", (ts, ts, op_id)).rowcount > 0

    def hub_last_read(self, hub_url: str, path: str) -> dict | None:
        """Последняя выполненная операция чтения (purpose read) по пути path в этом Hub – например, справочник
        `GET /defects/serviceInfo`: результат сохраняется в операции и переиспользуется (ADR-0120)."""
        from app import hub_ops
        return self._one("SELECT * FROM hub_ops WHERE purpose = 'read' AND state = 'done' AND hub_url = ?"
                         " AND (request_json::json ->> 'path') = ? ORDER BY id DESC LIMIT 1",
                         (hub_ops.hub_base(hub_url), path))

    # ============================================================================ дефекты в Hub из карточки (ADR-0120)

    HUB_DEFECT_FIELDS = frozenset({
        "number", "summary", "anchor_hub_id", "targets_json", "left_out_json", "warnings_json", "number_keys_json",
        "command_text", "source_fingerprint", "body_html", "blank_json", "priority", "severity", "hub_url", "app_id",
        "hub_defect_id", "hub_link", "blank_op_id", "create_op_id", "read_op_id", "link_op_id", "verify_json", "state",
        "error", "created_by", "verify_op_id", "confirm_op_id", "effects_done",
        # схема 27 (ADR-0124): вид строки занесения определяется при «Занести»; происхождение, снимок чтения, сверка
        "kind", "origin", "import_json", "sync_json", "sync_op_id",
        # схема 28 (ADR-0125): «Push в Hub» – операция текущего шага, состояние попытки, подтверждённые обновления
        "update_op_id", "update_json", "text_generation",
        # схемы 29 и 30
        "draft_owner_id", "draft_summary", "draft_command_text", "draft_fields_json", "confirmed_object_json", "conflicts_json", "draft_revision", "sca_set_key", "draft_fields_basis_json"})
    # поля операций строки: expect_op=(поле, номер) – шаг применяется, только если строка всё ещё ждёт этой операции
    HUB_DEFECT_OP_FIELDS = frozenset({"blank_op_id", "create_op_id", "read_op_id", "link_op_id", "verify_op_id",
                                      "confirm_op_id", "sync_op_id", "update_op_id"})
    # дефект в работе держит свой номер ID<n>: следующий предпросмотр получает другой (ADR-0120, находка 6); чтение и
    # предпросмотр занесения из Hub (ADR-0124 п. 2) ни цели, ни номера не держат – только занесённый (done)
    HUB_DEFECT_RESERVING = "state NOT IN ('cancelled', 'failed', 'import_reading', 'import_preview')"
    # живая строка дефекта Hub: занесение того же дефекта (того же Hub и приложения) второй строкой не начинается
    HUB_DEFECT_LIVE = "state NOT IN ('cancelled', 'failed')"
    # находка привязана к дефекту: POST мог дойти до Hub (ADR-0121 п. 1); заготовка и предпросмотр не привязывают
    HUB_DEFECT_BOUND = ("creating", "created", "linking", "mismatch", "unknown", "unconfirmed", "done")
    HUB_DEFECT_FINAL = ("done", "mismatch", "failed", "cancelled")
    # строка семьи стала историей: находки и ключи номера у владельца («Применить», общая синхронизация); ту же проверку
    # на Python делает defect_drafts.collapsed (ADR-0136)
    HUB_DEFECT_COLLAPSED = ("state IN ('done', 'mismatch') AND COALESCE(targets_json, '[]') = '[]'"
                            " AND COALESCE(number_keys_json, '[]') = '[]'")

    def hub_defect_insert(self, project_id: int, *, kind: str, number: int | None, summary: str, anchor_hub_id: str,
                          targets: list[dict], number_keys: list[str], command_text: str, hub_url: str,
                          app_id: int | None, left_out: list[dict] | None = None,
                          warnings: list[str] | None = None, source_fingerprint: str = "") -> dict:
        """Строка дефекта в состоянии «заготовка запрошена» (blank) без операций (тесты схемы); маршрут ставит строку и
        заготовку вместе – hub_defect_start."""
        with self._tx() as c:
            return self._hub_defect_row(c, project_id, kind=kind, number=number, summary=summary,
                                        anchor_hub_id=anchor_hub_id, targets=targets, number_keys=number_keys,
                                        command_text=command_text, hub_url=hub_url, app_id=app_id, left_out=left_out,
                                        warnings=warnings, source_fingerprint=source_fingerprint)

    def _hub_defect_row(self, c: Connection, project_id: int, *, kind: str, number: int | None, summary: str,
                        anchor_hub_id: str, targets: list[dict], number_keys: list[str], command_text: str,
                        hub_url: str, app_id: int | None, left_out: list[dict] | None = None,
                        warnings: list[str] | None = None, source_fingerprint: str = "", state: str = "blank",
                        origin: str = "app", draft_owner_id: int | None = None) -> dict:
        """Новая строка дефекта: начальное состояние state (дефект приложения – «заготовка запрошена», занесение из Hub
        – import_reading) и происхождение origin ('app' или 'import'). Вид '' допустим только у занесения до «Занести»
        (ADR-0124 п. 2)."""
        from app import hub_ops
        if origin not in ("app", "import") or (not kind and origin != "import"):
            raise ValueError("вид дефекта не задан или неизвестное происхождение строки")
        ts = now_iso()
        cur = c.execute(
            "INSERT INTO hub_defects(project_id, kind, number, summary, anchor_hub_id, targets_json, left_out_json,"
            " warnings_json, number_keys_json, command_text, source_fingerprint, hub_url, app_id, state, origin,"
            " created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)" " RETURNING id",
            (project_id, kind, number, summary, str(anchor_hub_id), dumps(list(targets)), dumps(list(left_out or [])),
             dumps(list(warnings or [])), dumps(list(number_keys)), command_text, str(source_fingerprint or ""),
             hub_ops.hub_base(hub_url), app_id, state, origin, ts, ts))
        from app.defect_drafts import initialize
        row_id = cur.fetchone()[0]
        initialize(c, dict(c.execute("SELECT * FROM hub_defects WHERE id = ?", (row_id,)).fetchone()), draft_owner_id)
        return dict(c.execute("SELECT * FROM hub_defects WHERE id = ?", (row_id,)).fetchone())

    @classmethod
    def hub_defect_live_in(cls, c: Connection, hub_url: str, app_id: int | None, hub_defect_id: str,
                           exclude_id: int | None = None, owner_id: int | None = None) -> dict | None:
        """Живая строка (не «не принят» и не «отменён») того же дефекта Hub – того же Hub, приложения и номера дефекта
        в Hub, в любом проекте (ADR-0124 п. 3); exclude_id – своя строка («Повторить чтение»); owner_id – схлопнутые
        строки этой семьи не считаются (ADR-0136): они история, а чужая строка, в том числе без целей, держит дефект по
        прежнему. Нет – None."""
        from app import hub_ops
        history = f" AND NOT (COALESCE(draft_owner_id, id) = ? AND {cls.HUB_DEFECT_COLLAPSED})" if owner_id is not None else ""
        row = c.execute(
            f"SELECT * FROM hub_defects WHERE hub_url = ? AND COALESCE(app_id, 0) = ? AND hub_defect_id = ?"
            f" AND {cls.HUB_DEFECT_LIVE} AND id != ?{history} ORDER BY id LIMIT 1",
            (hub_ops.hub_base(hub_url), int(app_id or 0), str(hub_defect_id), int(exclude_id or 0),
             *(() if owner_id is None else (int(owner_id),)))).fetchone()
        return dict(row) if row is not None else None

    def hub_defect_live(self, hub_url: str, app_id: int | None, hub_defect_id: str,
                        exclude_id: int | None = None) -> dict | None:
        """hub_defect_live_in на общем соединении под замком: вкладка «Дефекты» не показывает «Повторить чтение», если
        у дефекта есть другая живая строка (ADR-0124 п. 9)."""
        with self._lock:
            return self.hub_defect_live_in(self._conn, hub_url, app_id, hub_defect_id, exclude_id)

    def hub_defect_import_start(self, project_id: int, *, numbers: list[str], hub_url: str, app_id: int,
                                item_of: Callable[[dict, str], dict], link_of: Callable[[str], str],
                                check: Callable[[Connection], None] | None = None,
                                label_of: Callable[[str], str | None] | None = None) -> list[dict]:
        """«Занести из Hub» (ADR-0124 п. 3) одной транзакцией: check(c) прошла; на каждый номер дефекта Hub нет другой
        живой строки этого Hub, приложения и номера (hub_defect_live_in); строка import_reading (вид '', origin
        'import', номер и ссылка дефекта в Hub) и операция чтения item_of(строка, номер) – номер операции в read_op_id.
        Иначе ValueError – ничего не записывается. label_of – подпись состояния для отказа (hub_defects.STATE_LABELS:
        модуль базы его не импортирует); нет её – состояние как есть."""
        rows: list[dict] = []
        with self._tx() as c:
            if check is not None:
                check(c)
            for number in numbers:
                live = self.hub_defect_live_in(c, hub_url, app_id, number)
                if live is not None:
                    label = (label_of(live["state"]) if label_of is not None else None) or live["state"]
                    raise ValueError(f"Дефект №{number} уже есть в приложении (строка {live['id']}, состояние "
                                     f"«{label}»): второй раз не заносится.")
                fresh = self._hub_defect_row(c, project_id, kind="", number=None, summary="", anchor_hub_id="",
                                             targets=[], number_keys=[], command_text="", hub_url=hub_url,
                                             app_id=app_id, state="import_reading", origin="import")
                op = self._hub_insert(c, **item_of(fresh, number))
                c.execute("UPDATE hub_defects SET hub_defect_id = ?, hub_link = ?, read_op_id = ?, updated_at = ?"
                          " WHERE id = ?", (str(number), str(link_of(number) or ""), int(op["id"]), now_iso(),
                                            int(fresh["id"])))
                rows.append(dict(c.execute("SELECT * FROM hub_defects WHERE id = ?", (int(fresh["id"]),)).fetchone()))
        return rows

    @classmethod
    def hub_defect_holder_in(cls, c: Connection, project_id: int, hub_id: str,
                             exclude_id: int | None = None) -> dict | None:
        """Строка дефекта, которая держит находку целью (HUB_DEFECT_RESERVING), кроме exclude_id; нет – None. Занесение
        и сверка с Hub (ADR-0124 п. 4–6) считают такую находку конфликтующей: она не добавляется."""
        row = c.execute(
            f"SELECT * FROM hub_defects WHERE project_id = ? AND {cls.HUB_DEFECT_RESERVING} AND id != ? AND EXISTS ("
            " SELECT 1 FROM json_array_elements(hub_defects.targets_json::json) AS t(value) WHERE (t.value ->> 'hub_id') = ?)"
            " ORDER BY id DESC LIMIT 1", (project_id, int(exclude_id or 0), str(hub_id))).fetchone()
        return dict(row) if row is not None else None

    @staticmethod
    def import_findings_in(c: Connection, project_id: int, hub_ids: Iterable[str]) -> dict[str, dict]:
        """Находки проекта по номерам Hub для занесения и сверки (ADR-0124 п. 4): {hub_id: {kind, missing, component,
        version, revision, sig}}; нет находки – номера нет в словаре."""
        wanted = sorted({str(i) for i in hub_ids if str(i or "").strip()})
        found: dict[str, dict] = {}
        for start in range(0, len(wanted), 500):
            chunk = wanted[start:start + 500]
            marks = ",".join("?" * len(chunk))
            for r in c.execute(
                    "SELECT f.hub_id, f.kind, f.missing, f.data_json,"
                    # эффективное имя пакета (план dev17, п. 4.3): сведения Hub, иначе компонент выгрузки
                    " CASE WHEN f.pkg_source = 'hub' THEN f.pkg_name"
                    " ELSE COALESCE((f.data_json::json ->> 'component'), '') END AS component,"
                    " COALESCE((f.data_json::json ->> 'version'), '') AS version,"
                    " COALESCE(r.revision, 0) AS revision"
                    " FROM findings f LEFT JOIN reviews r ON r.project_id = f.project_id AND r.hub_id = f.hub_id"
                    f" WHERE f.project_id = ? AND f.hub_id IN ({marks})", (project_id, *chunk)):
                found[str(r["hub_id"])] = {"kind": str(r["kind"]), "missing": bool(r["missing"]),
                                           "component": str(r["component"]), "version": str(r["version"]),
                                           "revision": int(r["revision"] or 0), "sig": finding_data_sig(r["data_json"])}
        return found

    def import_findings(self, project_id: int, hub_ids: Iterable[str]) -> dict[str, dict]:
        """import_findings_in на общем соединении под замком."""
        with self._lock:
            return self.import_findings_in(self._conn, project_id, hub_ids)

    def hub_defect_holder(self, project_id: int, hub_id: str, exclude_id: int | None = None) -> dict | None:
        """hub_defect_holder_in на общем соединении под замком."""
        with self._lock:
            return self.hub_defect_holder_in(self._conn, project_id, hub_id, exclude_id)

    def hub_defects_with_number(self, project_id: int, number: int, exclude_id: int | None = None) -> list[dict]:
        """Другие строки дефектов проекта, которые держат номер ID<n> (HUB_DEFECT_RESERVING), кроме exclude_id: занят ли
        номер из заголовка занесённого дефекта (ADR-0124 п. 4 – справочно)."""
        with self._lock:
            return self.hub_defects_with_number_in(self._conn, project_id, number, exclude_id)

    @classmethod
    def hub_defects_with_number_in(cls, c: Connection, project_id: int, number: int,
                                   exclude_id: int | None = None) -> list[dict]:
        """hub_defects_with_number на соединении c (транзакция постановки `PUT`, ADR-0125 п. 2)."""
        return [dict(r) for r in c.execute(
            f"SELECT * FROM hub_defects WHERE project_id = ? AND number = ? AND {cls.HUB_DEFECT_RESERVING}"
            " AND id != ? ORDER BY id", (project_id, int(number), int(exclude_id or 0))).fetchall()]

    def defect_keys_of_findings(self, project_id: int, hub_ids: Iterable[str]) -> set[str]:
        """Ключи номера дефекта находок hub_ids – как их пишет карточка: SAST – defect_key_sast, SCA – ключ набора
        находки (routes.sca.set_key: ключ пакета, у отдельного набора – «#<номер>»; набор – место находки в
        sca_set_members того же пакета, нет его, другой пакет или «без дефекта» – набор по умолчанию, как в sca_defect).
        Находки нет в базе – её ключа нет. Собственные находки строки занесения (hub_defects.own_number_keys) не
        считаются «другим» в number_note (ADR-0124 п. 9)."""
        with self._lock:
            return self.defect_keys_of_findings_in(self._conn, project_id, hub_ids)

    @staticmethod
    def defect_keys_of_findings_in(c: Connection, project_id: int, hub_ids: Iterable[str]) -> set[str]:
        """defect_keys_of_findings на соединении c (транзакция постановки `PUT`, ADR-0125 п. 2)."""
        from app.sca_contract import input_ref as package_ref
        wanted = sorted({str(i) for i in hub_ids if str(i or "").strip()})
        keys: set[str] = set()
        for start in range(0, len(wanted), 500):
            chunk = wanted[start:start + 500]
            marks = ",".join("?" * len(chunk))
            for r in c.execute(f"SELECT hub_id, kind, data_json, pkg_ecosystem, pkg_name, pkg_source, pkg_note,"
                               f" pkg_scope FROM findings WHERE project_id = ? AND hub_id IN ({marks})",
                               (project_id, *chunk)).fetchall():
                if r["kind"] == "SAST":
                    keys.add(defect_key_sast(str(r["hub_id"])))
                elif r["kind"] == "SCA":
                    eco, name, version = package_identity.of(package_identity.with_package(dict(r)))
                    place = c.execute(
                        "SELECT set_no FROM sca_set_members WHERE project_id = ? AND hub_id = ? AND input_ref = ?",
                        (project_id, str(r["hub_id"]), package_ref(eco, name, version))).fetchone()
                    set_no = 0 if place is None or place["set_no"] is None else int(place["set_no"])
                    base = defect_key_sca(name, version, eco)
                    keys.add(base if not set_no else f"{base}#{set_no}")
        return keys

    def hub_defect_start(self, project_id: int, *, items: list[dict],
                         check: Callable[[Connection], None] | None = None, **row: Any) -> tuple[dict, list[dict]]:
        """Строка дефекта «заготовка запрошена» и операции заготовки одной транзакцией (ADR-0120, находка 1 круга
        Codex): ни одна цель не занята другим не отменённым дефектом из карточки, номер ID<n> не занят другим дефектом
        в работе и не выдан другой находке; check(c) прошла. Иначе ValueError – ничего не записывается. Номер первой
        операции – blank_op_id строки."""
        with self._tx() as c:
            if check is not None:
                check(c)
            return self._hub_defect_start_in(c, project_id, items=items, **row)

    def _hub_defect_start_in(self, c, project_id: int, *, items: list[dict], **row) -> tuple[dict, list[dict]]:
        """Общий резерв, строка, черновик и очередь на соединении вызывающей транзакции."""
        self._hub_defect_targets_free(c, project_id, row.get("targets") or [])
        number, keys = row.get("number"), [str(k) for k in row.get("number_keys") or []]
        if isinstance(number, int) and not isinstance(number, bool):
            taken = c.execute(f"SELECT id FROM hub_defects WHERE project_id = ? AND number = ?"
                              f" AND {self.HUB_DEFECT_RESERVING} LIMIT 1", (project_id, number)).fetchone()
            own = {r["defect_key"] for r in c.execute(
                "SELECT defect_key FROM defects WHERE project_id = ? AND number = ?", (project_id, number))}
            if taken is not None or (own - set(keys)):
                raise ValueError(f"Номер ID{number} уже занят другим дефектом: обновите карточку – приложение "
                                 "предложит следующий.")
        fresh = self._hub_defect_row(c, project_id, **row)
        ops = [self._hub_insert(c, **item) for item in items]
        if ops:
            c.execute("UPDATE hub_defects SET blank_op_id = ? WHERE id = ?", (int(ops[0]["id"]), int(fresh["id"])))
            fresh = dict(c.execute("SELECT * FROM hub_defects WHERE id = ?", (int(fresh["id"]),)).fetchone())
        return fresh, ops

    def hub_defect_selected_start(self, project_id: int, *, check: Callable, build: Callable) -> dict:
        """ADR-0122: проверка, решения, резерв и операции откатываются вместе.

        check возвращает аргументы внутренних сохранений. build получает новые редакции решений;
        сетевых запросов здесь нет. Публичные методы с собственными транзакциями не вызываются.
        """
        with self._tx() as c:
            reviews = check(c)
            saved = [self._save_review_in(c, project_id, **item) for item in reviews]
            row, items = build(c, saved)
            fresh, _ = self._hub_defect_start_in(c, project_id, items=items, **row)
            return fresh

    def _hub_defect_targets_free(self, c: Connection, project_id: int, targets: list[dict]) -> None:
        """Ни одна цель не занята другой не отменённой и принятой строкой дефекта (HUB_DEFECT_RESERVING); иначе
        ValueError."""
        for target in targets:
            busy = c.execute(
                f"SELECT id, state FROM hub_defects WHERE project_id = ? AND {self.HUB_DEFECT_RESERVING} AND EXISTS ("
                " SELECT 1 FROM json_array_elements(hub_defects.targets_json::json) AS t(value) WHERE (t.value ->> 'hub_id') = ?)"
                " ORDER BY id DESC LIMIT 1", (project_id, str(target.get("hub_id") or ""))).fetchone()
            if busy is not None:
                raise ValueError(f"Находка {target.get('hub_id')} уже в другом дефекте из карточки "
                                 f"(состояние «{busy['state']}»): обновите карточку.")

    def hub_defect_link_start(self, project_id: int, parent_id: int, hub_defect_id: str, *, item: dict,
                              body_hash: str, hub_link: str = "",
                              check: Callable[[Connection], None] | None = None, allow_imported: bool = False,
                              **row: Any) -> dict:
        """Новая находка группы с готовым дефектом (ADR-0121 п. 5): строка дефекта сразу «привязываю» (linking) с
        номером дефекта в Hub hub_defect_id и ссылкой hub_link, операция привязки item (`POST /defects/{id}/link`) –
        одной транзакцией. parent_id – строка того же дефекта в Hub: она всё ещё «создан» или «привязка неполная» с тем
        же номером в Hub, и отпечаток её текста команды (text_hash(command_text)) равен body_hash – отпечатку тела
        дефекта новой находки по её сохранённому решению; цели не заняты другой строкой (HUB_DEFECT_RESERVING);
        check(c) прошла (свежесть целей, готовый дефект – дефект группы находки). Ключ операции привязки – со строкой
        дефекта (hub_ops.op_key). Иначе ValueError – ничего не записывается. Номер ID<n> (row["number"]) – номер того
        же дефекта: занятость не проверяется. Заготовка Hub готового дефекта (blank_json) копируется в строку
        привязки: groupId следующей привязки берётся из неё и тогда, когда готовый дефект для неё – строка привязки.
        Дефект, занесённый из Hub (origin 'import'), родителем не бывает (ADR-0124 п. 7, ADR-0125 п. 4, вариант A):
        находки к нему привязывают в Hub и добавляют «Pull из Hub»; исключение – явный выбор оператора на странице
        «Добавить в дефект» (allow_imported, ADR-0136). По семье не должно идти других операций
        (family_running_problem)."""
        with self._tx() as c:
            parent = c.execute("SELECT * FROM hub_defects WHERE id = ? AND project_id = ?",
                               (int(parent_id), project_id)).fetchone()
            if (parent is None or parent["state"] not in ("done", "mismatch")
                    or str(parent["hub_defect_id"] or "") != str(hub_defect_id)
                    or text_hash(defect_where.body_of(parent["command_text"])) != str(body_hash)):
                raise ValueError("Дефект, к которому привязывается находка, изменился (ещё не подтверждён или другой "
                                 "текст решения): обновите карточку.")
            from app.hub_defects import family_running_problem, update_unconfirmed, update_busy
            if update_unconfirmed(dict(parent)) or update_busy(dict(parent)):
                raise ValueError("Обновление дефекта не подтверждено или ещё выполняется: сначала завершите его.")
            if not allow_imported and (parent["origin"] == "import" or self.imported_defect_in(c, project_id, parent)):
                raise ValueError("Дефект занесён из Hub: привяжите находку к нему в Hub и нажмите «Pull из Hub» во "
                                 "вкладке «Дефекты».")
            running = family_running_problem(c, dict(parent))
            if running:
                raise ValueError(running)
            if check is not None:
                check(c)
            self._hub_defect_targets_free(c, project_id, row.get("targets") or [])
            from app.hub_defects import linked_pairs, split_description
            owner = c.execute("SELECT confirmed_object_json FROM hub_defects WHERE id=?",
                              (parent["draft_owner_id"] or parent["id"],)).fetchone()
            confirmed = loads(owner[0], {}) if owner else {}
            # Неполная привязка не подтверждает решение, но её завершающий GET фиксирует прежний состав.
            # Он может быть пустым; подменять его локальными целями нельзя.
            if parent["state"] == "mismatch" and parent["confirm_op_id"]:
                confirmed = loads(parent["import_json"], {}).get("object", {})
            from app.hub_sync_api import composition_problems
            if composition_problems(confirmed):
                raise ValueError("Прежний состав не подтверждён: сначала сверить дефект с Hub.")
            blank = {**loads(parent["blank_json"], {}), "expected_previous_links": sorted(linked_pairs(confirmed))}
            fresh = self._hub_defect_row(c, project_id, draft_owner_id=parent["draft_owner_id"] or parent["id"], **row)
            op = self._hub_insert(c, **{**item, "key_extra": f"defect-row:{int(fresh['id'])}"})
            c.execute("UPDATE hub_defects SET state = 'linking', hub_defect_id = ?, hub_link = ?, link_op_id = ?,"
                      " blank_json = ?, body_html = ?, summary = ?, command_text = ?, updated_at = ? WHERE id = ?",
                      (str(hub_defect_id), str(hub_link or ""), int(op["id"]), dumps(blank),
                       str(confirmed.get("description") or ""), str(confirmed.get("summary") or ""),
                       split_description(confirmed.get("description"))[0],
                       now_iso(), int(fresh["id"])))
            return dict(c.execute("SELECT * FROM hub_defects WHERE id = ?", (int(fresh["id"]),)).fetchone())

    def hub_defect_advance(self, defect_id: int, *, expect_state: str, item: dict | None = None, op_field: str = "",
                           check: Callable[[Connection], None] | None = None,
                           fields_after_check: Callable[[Connection], dict] | None = None,
                           expect_op: tuple[str, int] | None = None,
                           resolve: Iterable[tuple[int, str, str]] = (),
                           with_op: Callable[[dict], dict] | None = None,
                           on_write: Callable | None = None,
                           **fields: Any) -> tuple[dict | None, dict | None]:
        """Переход строки дефекта и постановка следующей операции цепочки одной транзакцией (ADR-0120): строка ещё в
        expect_state, check(c) прошла, операция записана, её номер – в поле op_field. Строка уже не в expect_state –
        (None, None), ничего не ставится (повторная доставка, другая вкладка); отказ очереди (такая операция уже есть,
        цель занята) или check – исключение, ничего не меняется. resolve – операции (номер, done или failed,
        пояснение), которые в той же транзакции закрываются из «результат неизвестен» (как hub_resolve): итог чтения
        и закрытие записи – одной записью (ADR-0125, «Сверить»). with_op(операция) – поля строки, которые зависят от
        номера поставленной операции (ADR-0125: номер `PUT` попытки в update_json).
        fields_after_check(c) – поля, вычисляемые после check на том же соединении."""
        unknown = set(fields) - self.HUB_DEFECT_FIELDS - {op_field}
        if unknown or (op_field and op_field not in self.HUB_DEFECT_FIELDS):
            raise ValueError(f"неизвестные поля дефекта: {', '.join(sorted(unknown | {op_field}))}")
        resolve = list(resolve)
        if any(state not in ("done", "failed") for _, state, _ in resolve):
            raise ValueError("сверка закрывает операцию только как done или failed")
        ts = now_iso()
        with self._tx() as c:
            current = c.execute("SELECT * FROM hub_defects WHERE id = ?", (int(defect_id),)).fetchone()
            if current is None or current["state"] != expect_state:
                return None, None
            if expect_op is not None:  # шаг – только от операции, которой строка ждёт (устаревший обработчик – ничего)
                if expect_op[0] not in self.HUB_DEFECT_OP_FIELDS:
                    raise ValueError(f"неизвестное поле операции дефекта: {expect_op[0]}")
                if current[expect_op[0]] != int(expect_op[1]):
                    return None, None
            if check is not None:
                check(c)
            if fields_after_check is not None:
                extra = fields_after_check(c)
                unknown = set(extra) - self.HUB_DEFECT_FIELDS
                if unknown:
                    raise ValueError(f"неизвестные поля дефекта: {', '.join(sorted(unknown))}")
                fields = {**fields, **extra}
            for op_id, state, note in resolve:
                c.execute("UPDATE hub_ops SET state = ?, error = ?, updated_at = ?, closed_at = ? WHERE id = ?"
                          " AND state = 'unknown'", (state, str(note)[:2000], ts, ts, int(op_id)))
            op = self._hub_insert(c, **item) if item is not None else None
            sets = {**fields, "updated_at": ts}
            if op is not None and op_field:
                sets[op_field] = int(op["id"])
            if op is not None and with_op is not None:
                extra = with_op(op)
                if set(extra) - self.HUB_DEFECT_FIELDS:
                    raise ValueError(f"неизвестные поля дефекта: {', '.join(sorted(set(extra) - self.HUB_DEFECT_FIELDS))}")
                sets.update(extra)
            if fields.get("state") in self.HUB_DEFECT_FINAL:
                sets["closed_at"] = ts
            elif "state" in fields:
                sets["closed_at"] = None
            assignment = ", ".join(f"{name} = ?" for name in sets)
            c.execute(f"UPDATE hub_defects SET {assignment} WHERE id = ?", [*sets.values(), int(defect_id)])
            if on_write is not None:
                on_write(c, dict(c.execute("SELECT * FROM hub_defects WHERE id = ?", (int(defect_id),)).fetchone()))
            return dict(c.execute("SELECT * FROM hub_defects WHERE id = ?", (int(defect_id),)).fetchone()), op

    def hub_defect_update(self, defect_id: int, *, expect_state: str | None = None,
                          expect_op: tuple[str, int] | None = None, on_write: Callable | None = None, **fields: Any) -> dict | None:
        """Поля строки дефекта (только из HUB_DEFECT_FIELDS); expect_state – только если строка ещё в этом состоянии
        (повторная доставка результата или другая вкладка успели раньше – None, ничего не меняется). Переход в
        конечное состояние ставит closed_at."""
        unknown = set(fields) - self.HUB_DEFECT_FIELDS
        if unknown:
            raise ValueError(f"неизвестные поля дефекта: {', '.join(sorted(unknown))}")
        ts = now_iso()
        sets = {**fields, "updated_at": ts}
        if fields.get("state") in self.HUB_DEFECT_FINAL:
            sets["closed_at"] = ts
        elif "state" in fields:
            sets["closed_at"] = None
        assignment = ", ".join(f"{name} = ?" for name in sets)
        params: list[Any] = list(sets.values()) + [int(defect_id)]
        where = " WHERE id = ?"
        if expect_state is not None:
            where += " AND state = ?"
            params.append(expect_state)
        if expect_op is not None:  # строка всё ещё ждёт именно этой операции (ADR-0120, круг 2 Codex)
            if expect_op[0] not in self.HUB_DEFECT_OP_FIELDS:
                raise ValueError(f"неизвестное поле операции дефекта: {expect_op[0]}")
            where += f" AND {expect_op[0]} = ?"
            params.append(int(expect_op[1]))
        with self._tx() as c:
            if not c.execute(f"UPDATE hub_defects SET {assignment}{where}", params).rowcount:
                return None
            if on_write is not None:
                on_write(c, dict(c.execute("SELECT * FROM hub_defects WHERE id = ?", (int(defect_id),)).fetchone()))
            return dict(c.execute("SELECT * FROM hub_defects WHERE id = ?", (int(defect_id),)).fetchone())

    def hub_defect(self, defect_id: int) -> dict | None:
        return self._one("SELECT * FROM hub_defects WHERE id = ?", (int(defect_id),))

    # порядок вкладки «Дефекты» (сортировка по номеру и по виду); строки без номера – в конце
    HUB_DEFECT_ORDERS = {
        "": "id DESC",
        "number_asc": "number IS NULL, number ASC, id DESC",
        "number_desc": "number IS NULL, number DESC, id DESC",
        "kind_asc": "kind ASC, number IS NULL, number ASC, id DESC",
        "kind_desc": "kind DESC, number IS NULL, number ASC, id DESC",
    }

    # отборы вкладки «Дефекты» («Все фильтры» как у находок); пустое значение – без отбора
    _HUB_DEFECT_WHERE = ("project_id = ? AND state != 'cancelled'"
                         " AND (?='' OR strpos(unicode_search(summary),unicode_search(?))>0 OR hub_defect_id=?)"
                         " AND (?='' OR kind=?) AND (?='' OR state=?)"
                         " AND (?='' OR (CASE WHEN origin='import' THEN 'import' ELSE 'app' END)=?)")

    @staticmethod
    def _hub_defect_args(project_id: int, query: str, kind: str, state: str, origin: str) -> tuple:
        return (project_id, query, query, query, kind, kind, state, state, origin, origin)

    def hub_defects(self, project_id: int, limit: int = 500, offset: int = 0, query: str = "",
                    order: str = "", kind: str = "", state: str = "", origin: str = "") -> list[dict]:
        """Дефекты проекта (вкладка «Дефекты»): по умолчанию от новых к старым, order – ключ HUB_DEFECT_ORDERS;
        отборы вида, состояния и происхождения (app – созданные в приложении, import – занесённые из Hub);
        отменённые заготовки не показываются."""
        by = self.HUB_DEFECT_ORDERS.get(order, self.HUB_DEFECT_ORDERS[""])
        return self._all(f"SELECT * FROM hub_defects WHERE {self._HUB_DEFECT_WHERE} ORDER BY {by} LIMIT ? OFFSET ?",
                         self._hub_defect_args(project_id, query, kind, state, origin) + (int(limit), int(offset)))

    def hub_defects_total(self, project_id: int, query: str = "", kind: str = "", state: str = "",
                          origin: str = "") -> int:
        """Число строк таблицы вкладки «Дефекты» под отборами – для страниц; дефекты считает hub_defect_families."""
        return int(self._scalar(f"SELECT COUNT(*) FROM hub_defects WHERE {self._HUB_DEFECT_WHERE}",
                                self._hub_defect_args(project_id, query, kind, state, origin)) or 0)

    # дефект – семья строк: владелец и строки его цепочки (замена, привязка) – один дефект Hub (ADR-0136, бэклог 106)
    _HUB_DEFECT_FAMILIES = "SELECT COUNT(DISTINCT COALESCE(draft_owner_id, id)) FROM hub_defects WHERE "

    def hub_defect_families(self, project_id: int, query: str = "", kind: str = "", state: str = "",
                            origin: str = "", live: bool = False) -> int:
        """Сколько дефектов под отборами вкладки: семья из нескольких строк – один дефект, как в Hub. live – без
        неудавшихся попыток (они в таблице остаются и называются отдельно)."""
        alive = " AND state != 'failed'" if live else ""
        return int(self._scalar(f"{self._HUB_DEFECT_FAMILIES}{self._HUB_DEFECT_WHERE}{alive}",
                                self._hub_defect_args(project_id, query, kind, state, origin)) or 0)

    def hub_defects_to_sync(self, project_id: int, open_states: Iterable[str]) -> list[dict]:
        """Строки дефектов, которые hub_defects.sync может довести: недоведённые последствия, текущая операция сверки,
        проверки или обновления у подтверждённого, сверка неизвестного исхода, незакрытые шаги создания, привязки и
        занесения. Остальные строки показ вкладки не перебирает (ревью 31.10). По номеру: доведение строки может поставить
        следующую операцию Hub, и очерёдность таких операций не должна зависеть от расположения строк в таблице."""
        states = list(open_states)
        marks = ",".join("?" * len(states))
        return self._all(
            "SELECT * FROM hub_defects WHERE project_id = ? AND state != 'cancelled' AND ("
            " (state IN ('done', 'mismatch', 'failed') AND COALESCE(effects_done, 1) = 0)"
            " OR (state = 'done' AND (verify_op_id IS NOT NULL OR sync_op_id IS NOT NULL OR update_op_id IS NOT NULL))"
            " OR (state IN ('unknown', 'unconfirmed') AND verify_op_id IS NOT NULL)"
            f" OR state IN ({marks})) ORDER BY id", (project_id, *states))

    def hub_defect_facets(self, project_id: int) -> dict:
        """Сколько дефектов каждого вида, состояния и происхождения (числа на фильтрах вкладки «Дефекты»)."""
        out: dict = {"kind": {}, "state": {}, "origin": {}}
        for row in self._all("SELECT kind, state, CASE WHEN origin='import' THEN 'import' ELSE 'app' END AS origin,"
                             " COUNT(*) AS n FROM hub_defects WHERE project_id = ? AND state != 'cancelled'"
                             " GROUP BY 1, 2, 3", (project_id,)):
            for key in ("kind", "state", "origin"):
                out[key][row[key]] = out[key].get(row[key], 0) + int(row["n"])
        return out

    def hub_defect_count(self, project_id: int) -> int:
        """Число на вкладке «Дефекты»: дефекты (семьи строк), кроме отменённых и не принятых Hub – то же число,
        что «Всего» на вкладке без отборов и число дефектов приложения в Hub (бэклог 106)."""
        return int(self._scalar(f"{self._HUB_DEFECT_FAMILIES}project_id = ? AND {self.HUB_DEFECT_LIVE}",
                                (project_id,)) or 0)

    def hub_defect_for(self, project_id: int, hub_ids: Iterable[str]) -> dict | None:
        """Последняя не отменённая строка дефекта, в целях которой есть хотя бы одна из находок hub_ids (карточка
        показывает её состояние; состав группы проверяется по ней)."""
        ids = [str(h) for h in hub_ids if str(h)]
        if not ids:
            return None
        marks = ",".join("?" * len(ids))
        return self._one(
            "SELECT * FROM hub_defects WHERE project_id = ? AND state != 'cancelled' AND EXISTS ("
            f" SELECT 1 FROM json_array_elements(hub_defects.targets_json::json) AS t(value) WHERE (t.value ->> 'hub_id') IN ({marks}))"
            " ORDER BY id DESC LIMIT 1", (project_id, *ids))

    @staticmethod
    def hub_defect_bound_in(c: Connection, project_id: int, hub_id: str) -> dict | None:
        """Дефект, к которому привязана находка (ADR-0121 п. 1): последняя строка, где находка – цель, в состоянии, когда
        POST мог дойти до Hub (HUB_DEFECT_BOUND: создаётся, проверка привязки, привязка, привязка неполная, результат
        неизвестен, создан). c – соединение или транзакция записи, которая проверяет привязку; нет – None."""
        marks = ",".join("?" * len(Database.HUB_DEFECT_BOUND))
        row = c.execute(
            f"SELECT * FROM hub_defects WHERE project_id = ? AND state IN ({marks}) AND EXISTS ("
            " SELECT 1 FROM json_array_elements(hub_defects.targets_json::json) AS t(value) WHERE (t.value ->> 'hub_id') = ?)"
            " ORDER BY id DESC LIMIT 1", (project_id, *Database.HUB_DEFECT_BOUND, str(hub_id))).fetchone()
        return dict(row) if row is not None else None

    @staticmethod
    def imported_defect_in(c: Connection, project_id: int, row) -> bool:
        """У дефекта Hub строки row (тот же Hub, приложение Hub и номер дефекта в Hub) есть живая занесённая строка
        (origin 'import', HUB_DEFECT_BOUND): к такому дефекту из приложения не привязывают – и через строку привязки
        origin 'app' того же дефекта (ADR-0125 п. 4, вариант A)."""
        if not row["hub_defect_id"]:
            return False
        marks = ",".join("?" * len(Database.HUB_DEFECT_BOUND))
        return c.execute(
            f"SELECT 1 FROM hub_defects WHERE project_id = ? AND origin = 'import' AND state IN ({marks})"
            " AND hub_defect_id = ? AND COALESCE(hub_url, '') = ? AND COALESCE(app_id, 0) = ? LIMIT 1",
            (project_id, *Database.HUB_DEFECT_BOUND, str(row["hub_defect_id"]), str(row["hub_url"] or ""),
             int(row["app_id"] or 0))).fetchone() is not None

    def imported_defect(self, project_id: int, row: dict) -> bool:
        """imported_defect_in на общем соединении под замком."""
        with self._lock:
            return self.imported_defect_in(self._conn, project_id, row)

    def hub_defect_bound(self, project_id: int, hub_id: str) -> dict | None:
        """hub_defect_bound_in на общем соединении под замком: вызванная из проверки внутри транзакции записи (например,
        save_review(group_check=…)) читает в той же транзакции – замок реентерабелен, соединение одно."""
        with self._lock:
            return self.hub_defect_bound_in(self._conn, project_id, hub_id)

    @staticmethod
    def hub_ids_among_in(c: Connection, project_id: int, ids: Iterable[str]) -> set[str]:
        """Какие из чисел ids – номера находок Hub проекта (и пропавших из выгрузки): проверка текста дефекта на
        внутренние номера (ADR-0123 п. 3.7). c – соединение или транзакция постановки, которая повторяет проверку."""
        wanted = sorted({str(i) for i in ids if str(i or "").strip()})
        found: set[str] = set()
        for start in range(0, len(wanted), 500):
            chunk = wanted[start:start + 500]
            marks = ",".join("?" * len(chunk))
            found |= {str(r["hub_id"]) for r in c.execute(
                f"SELECT hub_id FROM findings WHERE project_id = ? AND hub_id IN ({marks})", (project_id, *chunk))}
        return found

    def hub_ids_among(self, project_id: int, ids: Iterable[str]) -> set[str]:
        """hub_ids_among_in на общем соединении под замком."""
        with self._lock:
            return self.hub_ids_among_in(self._conn, project_id, ids)

    @staticmethod
    def hub_target_in(c: Connection, project_id: int) -> tuple[int | None, dict[str, Any]]:
        """Куда запись в Hub уходит сейчас (KIMI-12, бэклог 44): номер приложения Hub проекта (projects.hub_app_id;
        None – не задан или проекта нет) и сохранённая настройка «Адрес Hub» в виде {"hub_url": значение} – пусто, если
        её нет в базе или значение испорчено (тогда действует значение из окружения, как у get_settings и
        Settings.with_stored). c – транзакция постановки, которая сверяет цель записи с показанной оператору."""
        row = c.execute("SELECT hub_app_id FROM projects WHERE id = ?", (int(project_id),)).fetchone()
        app_id = int(row["hub_app_id"]) if row is not None and row["hub_app_id"] else None
        return app_id, Database.settings_in(c, ("hub_url",))

    @staticmethod
    def settings_in(c: Connection, keys: Iterable[str]) -> dict[str, Any]:
        """Сохранённые настройки keys на соединении c: {ключ: значение}, как get_settings – испорченное значение и
        отсутствующий ключ пропускаются (действует значение из окружения, Settings.with_stored). c – транзакция
        постановки, которая перечитывает настройку, от которой зависит её проверка (адрес Hub, название команды)."""
        wanted = [str(k) for k in keys]
        result: dict[str, Any] = {}
        if not wanted:
            return result
        marks = ",".join("?" * len(wanted))
        for row in c.execute(f"SELECT key, value_json FROM settings WHERE key IN ({marks})", wanted):
            try:
                result[row["key"]] = json.loads(row["value_json"])
            except ValueError:
                continue
        return result

    def hub_defect_by_op(self, op_id: int) -> dict | None:
        """Строка дефекта, в цепочке которой есть операция op_id (заготовка, создание, чтение или привязка)."""
        return self._one("SELECT * FROM hub_defects WHERE blank_op_id = ? OR create_op_id = ? OR read_op_id = ?"
                         " OR link_op_id = ? ORDER BY id DESC LIMIT 1", (int(op_id),) * 4)
