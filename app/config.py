"""Настройки приложения.

Переменные окружения задают то, что относится к запуску: папки данных и репозиториев, порт, имена хоста, пределы.
Настройки работы (адрес Ollama, модель по умолчанию, статусы Hub, порог срочности SCA) меняются в интерфейсе
и хранятся в базе (таблица settings): переменные окружения дают им только начальные значения при первом запуске
(Database.seed_settings), а действующие значения – Settings.with_stored(значения из базы).

Значения по умолчанию рассчитаны на запуск в контейнере (docker-compose.yml): данные в /data, клоны
репозиториев в /repos (только чтение), Ollama на хосте через host.docker.internal.
"""

from __future__ import annotations

import dataclasses
import json
import math
import os
import urllib.parse
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app import i18n

VERDICTS = ("true_positive", "false_positive", "uncertain")
# Итоги разбора, у которых есть статус Hub: вердикты и отдельное решение человека «Риск принят» (модель его
# не предлагает, ADR 0024)
HUB_OUTCOMES = (*VERDICTS, "risk_accepted")

# Статусы AppSec.Hub по итогу разбора – так, как их показывает интерфейс Hub. Значения по умолчанию; меняются
# на странице «Настройки». «Открыто» и «Исправлено» – жизненный цикл находки, при триаже не выбираются.
DEFAULT_STATUS_MAP = {
    "true_positive": "Подтверждено",
    "false_positive": "Ложное срабатывание",
    "uncertain": "Не подтверждено",
    "risk_accepted": "Риск принят",
}
# Модель по умолчанию – по замеру на наборе с известными ответами (ADR 0026, docs/model-benchmark.md). Режим
# рассуждения low приложение передаёт gpt-oss само (llm.is_gpt_oss).
DEFAULT_MODEL = "gpt-oss:20b"
# Единственное место выбора режима по умолчанию после замера модели.
DEFAULT_MODEL_JSON_SCHEMA = "always"
# Модель по умолчанию версий до 0.3.5: остаётся в базах установок, где её выбрали
LEGACY_DEFAULT_MODEL = "qwen2.5-coder:14b"

# Имена хостов, по которым открывается интерфейс (защита от подмены DNS). Порт опубликован только на 127.0.0.1.
DEFAULT_TRUSTED_HOSTS = ("127.0.0.1", "localhost", "::1")

# Настройки, которые меняются в интерфейсе и хранятся в базе (ключи таблицы settings)
EDITABLE_SETTINGS = ("ollama_url", "default_model", "hub_status_map", "sca_urgent_cvss", "team_name",
                     "sca_internal_prefixes", "hub_url", "affiliation_words")
# Настройки, которые хранятся в базе, но не заполняются из окружения при первом запуске: профили провайдеров по
# умолчанию для двух назначений (ADR-0102) – их создаёт db.ensure_default_profile вместе с профилем 1
STORED_SETTINGS = ("default_provider_id", "default_research_provider_id")
MAX_URL = 300
MAX_MODEL_NAME = 200
MAX_STATUS = 100
MAX_TEAM_NAME = 100
MAX_PREFIXES = 50  # префиксов внутренних компонентов SCA
MAX_PREFIX = 100
MAX_AFFILIATION_WORDS = 200  # слов принадлежности (ADR-0118)
# слово принадлежности: буквы любого алфавита, 2–50, в конце допустима «*» (совпадение по началу слова)
AFFILIATION_WORD = re.compile(r"[^\W\d_]{2,50}\*?")


class ConfigError(ValueError):
    """Неверное значение настройки или переменной окружения. Текст – по-русски, с именем настройки."""


@dataclass(frozen=True)
class Settings:
    data_dir: Path = Path("/data")
    tmp_root: Path | None = None
    repos_root: Path = Path("/repos")
    ollama_url: str = "http://host.docker.internal:11434"
    default_model: str = DEFAULT_MODEL
    max_upload_mb: int = 50
    hub_status_map: dict[str, str] = field(default_factory=lambda: dict(DEFAULT_STATUS_MAP))
    sca_urgent_cvss: float = 9.0
    num_ctx: int = 16384  # окно контекста модели, токенов (MODEL_NUM_CTX)
    trusted_hosts: tuple[str, ...] = DEFAULT_TRUSTED_HOSTS
    # Та же папка с репозиториями, как её видит пользователь на своём компьютере (REPOS_ROOT_HOST): в контейнере
    # она подключена как /repos, а подсказки «куда клонировать» нужны с путём хоста. Пусто – показывается repos_root.
    repos_root_host: str = ""
    # Подключена ли демо-папка приложения examples/demo/repos (REPOS_ROOT_IS_DEMO от start.ps1, бэклог 94): "1" – да,
    # "0" – нет, "" – источник не определён (запуск без скрипта). Только по нему – предупреждение «Демонстрационные
    # репозитории»: папки демо-комплекта в рабочем корне признаком демо не считаются.
    repos_root_is_demo: str = ""
    # Название команды в тексте дефекта для Hub («команда <название> приняла решение…»); пусто – без названия
    team_name: str = ""
    # Префиксы имён внутренних компонентов SCA (свои библиотеки организации): в пакет для внешних агентов
    # они не попадают
    sca_internal_prefixes: tuple[str, ...] = ()
    # Журнал обмена с моделью (MODEL_TRAFFIC_LOG): «on» – писать в папку model_traffic_dir, «off» – не писать
    model_traffic_log: str = "on"
    model_json_schema: str = DEFAULT_MODEL_JSON_SCHEMA
    osv_url: str = "https://api.osv.dev"  # точный запрос OSV перед исследованием провайдером (ADR-0112); «» – выключен
    # Слова принадлежности (ADR-0118): название организации, сокращение, город, домен – перед отправкой модели
    # заменяются на «org»/«орг» в любом запросе (app/affiliation.py); «*» в конце – совпадение по началу слова
    affiliation_words: tuple[str, ...] = ()
    # Адрес AppSec.Hub (https://host) для исполнителя и ссылок на дефекты (ADR-0114); «» – запись в Hub выключена.
    # Сейчас запросы выполняет исполнитель там, где Hub виден; прямой режим (основной,
    # ADR-0129) ещё не сделан
    hub_url: str = ""

    # Режим обслуживания (TRIAGE_MAINTENANCE=1, ADR-0128, п. 6.6): чтение без фоновых обработчиков и записей
    maintenance: bool = False

    # Учебный стенд, поставленный через npm (TRIAGE_STAND=npm, ADR-0155): приложение запущено обёрткой без Docker,
    # Hub выключен на стороне сервера; «» – обычная установка (Docker или режим разработки). TRIAGE_STAND_TOKEN –
    # идентификатор запуска стенда для /healthz: по нему обёртка узнаёт свой процесс на порту
    stand: str = ""
    stand_token: str = ""

    # Профили провайдеров по умолчанию (ADR-0102): разбор кода и исследование компонентов; 1 – профиль из
    # «Адреса Ollama» и «Модели по умолчанию»
    default_provider_id: int = 1
    default_research_provider_id: int = 1

    @property
    def db_path(self) -> Path:
        return self.data_dir / "triage.db"

    @property
    def tmp_dir(self) -> Path:
        """Копии загрузок на время разбора: вне папки данных (ADR-0133). В контейнере – том /scratch (TMP_DIR)."""
        return self.tmp_root or self.data_dir.parent / f"{self.data_dir.name}-tmp"

    @property
    def model_traffic_dir(self) -> Path:
        return self.data_dir / "model-traffic"

    @property
    def max_upload_bytes(self) -> int:
        return self.max_upload_mb * 1024 * 1024

    def editable(self) -> dict[str, Any]:
        """Настройки из интерфейса (EDITABLE_SETTINGS) с текущими значениями – для первого заполнения базы."""
        return {"ollama_url": self.ollama_url, "default_model": self.default_model,
                "hub_status_map": dict(self.hub_status_map), "sca_urgent_cvss": self.sca_urgent_cvss,
                "team_name": self.team_name, "sca_internal_prefixes": list(self.sca_internal_prefixes),
                "hub_url": self.hub_url, "affiliation_words": list(self.affiliation_words)}

    def with_stored(self, stored: Mapping[str, Any]) -> Settings:
        """Действующие настройки: сохранённые в базе значения поверх значений из переменных окружения.
        Испорченное значение в базе пропускается – действует значение из окружения."""
        changes = {}
        for key in EDITABLE_SETTINGS + STORED_SETTINGS:
            if key not in stored:
                continue
            try:
                changes[key] = normalize_setting(key, stored[key])
            except ConfigError:
                continue
        return dataclasses.replace(self, **changes) if changes else self

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Settings:
        """Настройки из переменных окружения; пустая переменная – значение по умолчанию."""
        env = os.environ if env is None else env

        def get(name: str) -> str:
            return (env.get(name) or "").strip()

        defaults = cls()
        return cls(
            data_dir=Path(get("DATA_DIR")) if get("DATA_DIR") else defaults.data_dir,
            tmp_root=Path(get("TMP_DIR")) if get("TMP_DIR") else None,
            repos_root=Path(get("REPOS_ROOT")) if get("REPOS_ROOT") else defaults.repos_root,
            ollama_url=get("OLLAMA_URL").rstrip("/") or defaults.ollama_url,
            default_model=get("DEFAULT_MODEL") or defaults.default_model,
            max_upload_mb=_positive_int("MAX_UPLOAD_MB", get("MAX_UPLOAD_MB"), defaults.max_upload_mb, 1, 1024),
            hub_status_map=_status_map(get("HUB_STATUS_MAP")),
            sca_urgent_cvss=_cvss("SCA_URGENT_CVSS", get("SCA_URGENT_CVSS"), defaults.sca_urgent_cvss),
            # меньше 4096 не поместятся системные указания, срез кода и ответ модели вместе
            num_ctx=_positive_int("MODEL_NUM_CTX", get("MODEL_NUM_CTX"), defaults.num_ctx, 4096, 262144),
            trusted_hosts=_hosts(get("TRUSTED_HOSTS")),
            repos_root_host=get("REPOS_ROOT_HOST").replace("\\", "/").rstrip("/"),
            repos_root_is_demo=get("REPOS_ROOT_IS_DEMO") if get("REPOS_ROOT_IS_DEMO") in ("0", "1") else "",
            model_traffic_log=_traffic_log(get("MODEL_TRAFFIC_LOG")),
            model_json_schema=model_json_schema_mode(get("MODEL_JSON_SCHEMA")),
            osv_url=osv_url_value(get("OSV_URL"), defaults.osv_url),
            maintenance=get("TRIAGE_MAINTENANCE").lower() in ("1", "true", "on", "yes"),
            stand=_stand(get("TRIAGE_STAND")),
            stand_token=_stand_token(get("TRIAGE_STAND_TOKEN")) if _stand(get("TRIAGE_STAND")) == "npm" else "",
        )

    @property
    def hub_disabled(self) -> bool:
        """В учебном стенде npm Hub выключен на стороне сервера (ADR-0155): исполнителя в стенде нет."""
        return self.stand == "npm"


STAND_TOKEN = re.compile(r"[0-9a-f]{16,64}")


def stand_mode(env: Mapping[str, str] | None = None) -> str:
    """«npm» – учебный стенд, «» – обычная установка: для текстов модулей без доступа к настройкам (замок папки данных,
    подсказки страниц). Неверное значение здесь – «»: его отвергает Settings.from_env при запуске."""
    value = ((os.environ if env is None else env).get("TRIAGE_STAND") or "").strip().lower()
    return "npm" if value == "npm" else ""


def _stand(raw: str) -> str:
    """TRIAGE_STAND: пусто – обычная установка; npm – учебный стенд из npm-пакета (ADR-0155)."""
    value = raw.strip().lower()
    if value not in ("", "npm"):
        raise ConfigError(i18n._("TRIAGE_STAND: допустимо только значение npm (учебный стенд) или пустое значение."))
    return value


def _stand_token(raw: str) -> str:
    value = raw.strip().lower()
    if value and not STAND_TOKEN.fullmatch(value):
        raise ConfigError(i18n._("TRIAGE_STAND_TOKEN: нужны от 16 до 64 шестнадцатеричных знаков."))
    return value


def osv_url_value(raw: str, default: str) -> str:
    """OSV_URL: пусто – адрес по умолчанию; off – запрос OSV выключен; иначе адрес http(s) без пути и параметров."""
    value = (raw or "").strip().rstrip("/")
    if not value:
        return default
    if value.casefold() == "off":
        return ""
    hint = i18n._("OSV_URL: нужен адрес вида https://api.osv.dev (схема и узел, при необходимости порт; без пути, параметров, якоря и имени пользователя) или off.")
    if any(ch.isspace() for ch in value) or "#" in value or "@" in value:
        raise ConfigError(hint)
    try:
        parts = urllib.parse.urlsplit(value)
        port = parts.port
    except ValueError:
        raise ConfigError(hint) from None
    if parts.scheme.lower() not in ("http", "https") or not parts.hostname or parts.path not in ("", "/") or parts.query:
        raise ConfigError(hint)
    if port is not None and not 1 <= port <= 65535:
        raise ConfigError(hint)
    return value


def model_json_schema_mode(raw: str) -> str:
    """Режим схемы ответа; пустое значение использует общий выбор по умолчанию."""
    value = raw.strip().casefold() or DEFAULT_MODEL_JSON_SCHEMA
    if value not in ("retry", "always", "off"):
        raise ConfigError(i18n._("MODEL_JSON_SCHEMA: допустимы retry, always или off"))
    return value


def _positive_int(name: str, raw: str, default: int, low: int, high: int) -> int:
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        raise ConfigError(i18n._("{name}: ожидается целое число, получено «{raw}»", name=name, raw=raw)) from None
    if not low <= value <= high:
        raise ConfigError(i18n._("{name}: допустимо от {low} до {high}, получено {value}", name=name, low=low, high=high,
                                  value=value))
    return value


def _cvss(name: str, raw: str, default: float) -> float:
    if not raw:
        return default
    try:
        value = float(raw.replace(",", "."))
    except ValueError:
        raise ConfigError(i18n._("{name}: ожидается число от 0 до 10, получено «{raw}»", name=name, raw=raw)) from None
    if not 0.0 <= value <= 10.0:
        raise ConfigError(i18n._("{name}: ожидается число от 0 до 10, получено {value}", name=name, value=value))
    return value


def _status_map(raw: str) -> dict[str, str]:
    """HUB_STATUS_MAP – JSON-объект итог разбора (вердикт или risk_accepted) → статус Hub; заданные ключи заменяют
    значения по умолчанию."""
    result = dict(DEFAULT_STATUS_MAP)
    if not raw:
        return result
    try:
        data = json.loads(raw)
    except ValueError:
        raise ConfigError(i18n._("HUB_STATUS_MAP: ожидается JSON-объект, например {example}",
                                  example='{"false_positive": "Ложное срабатывание"}')) from None
    if not isinstance(data, dict):
        raise ConfigError(i18n._("HUB_STATUS_MAP: ожидается JSON-объект «вердикт: статус»"))
    for key, value in data.items():
        if key not in HUB_OUTCOMES:
            raise ConfigError(i18n._("HUB_STATUS_MAP: неизвестный вердикт «{key}», допустимы: {allowed}", key=key,
                                      allowed=', '.join(HUB_OUTCOMES)))
        if not isinstance(value, str):
            raise ConfigError(i18n._("HUB_STATUS_MAP: статус для «{key}» должен быть строкой", key=key))
        result[key] = value.strip()
    return result


def normalize_setting(key: str, value: Any) -> Any:
    """Проверка и приведение значения настройки из интерфейса (EDITABLE_SETTINGS); ConfigError – с понятным текстом.

    ollama_url – адрес http или https без пробелов (какие хосты разрешены, проверяет клиент Ollama перед каждым
    запросом); default_model – имя модели или "" (первая модель из списка Ollama); hub_status_map – статусы Hub
    по итогам разбора (вердикты и risk_accepted), недостающие берутся по умолчанию; sca_urgent_cvss – число от 0
    до 10 (запятая допустима); team_name – одна строка до 100 знаков ("" – без названия); sca_internal_prefixes –
    список префиксов или строка, где они разделены запятыми, точками с запятой или переводами строк;
    affiliation_words – список слов принадлежности (ADR-0118) или такая же строка: буквы, 2–50, «*» в конце."""
    if key == "ollama_url":
        text = str(value or "").strip().rstrip("/")
        if not text.startswith(("http://", "https://")) or len(text) > MAX_URL or any(ch.isspace() for ch in text):
            raise ConfigError(i18n._("Адрес Ollama: ожидается адрес вида http://127.0.0.1:11434"))
        return text
    if key == "default_model":
        text = str(value or "").strip()
        if len(text) > MAX_MODEL_NAME or any(ord(ch) < 32 for ch in text):
            raise ConfigError(i18n._("Модель по умолчанию: слишком длинное или неверное имя модели"))
        return text
    if key == "hub_status_map":
        if not isinstance(value, Mapping):
            raise ConfigError(i18n._("Статусы Hub: ожидаются статусы для вердиктов «истинная», «ложная», «неясно»"))
        result = dict(DEFAULT_STATUS_MAP)
        for verdict, status in value.items():
            if verdict not in HUB_OUTCOMES:
                raise ConfigError(i18n._("Статусы Hub: неизвестный вердикт «{verdict}»", verdict=verdict))
            text = str(status or "").strip()
            if len(text) > MAX_STATUS or any(ord(ch) < 32 for ch in text):
                raise ConfigError(i18n._("Статусы Hub: статус – одна строка до 100 знаков"))
            result[verdict] = text
        return result
    if key == "sca_urgent_cvss":
        try:
            number = float(str(value).strip().replace(",", ".")) if isinstance(value, str) else float(value)
        except (TypeError, ValueError):
            raise ConfigError(i18n._("Порог срочности SCA: ожидается число от 0 до 10")) from None
        if isinstance(value, bool) or not math.isfinite(number) or not 0.0 <= number <= 10.0:
            raise ConfigError(i18n._("Порог срочности SCA: ожидается число от 0 до 10"))
        return number
    if key in STORED_SETTINGS:
        # номер профиля: целое 1–999999999 или строка из цифр ASCII («²» и прочие «цифры» Юникода – нет)
        if isinstance(value, bool) or not (isinstance(value, int) or isinstance(value, str)
                                           and re.fullmatch(r"[0-9]{1,9}", value.strip())):
            raise ConfigError(i18n._("Профиль провайдера по умолчанию: ожидается номер профиля"))
        number = int(value)
        if not 1 <= number <= 999_999_999:
            raise ConfigError(i18n._("Профиль провайдера по умолчанию: ожидается номер профиля"))
        return number
    if key == "team_name":
        text = " ".join(str(value or "").split())
        if len(text) > MAX_TEAM_NAME or any(ord(ch) < 32 for ch in text):
            raise ConfigError(i18n._("Название команды: одна строка до {limit} знаков", limit=MAX_TEAM_NAME))
        return text
    if key == "sca_internal_prefixes":
        items = value if isinstance(value, (list, tuple)) else re.split(r"[,;\s]+", str(value or ""))
        result: list[str] = []
        for item in items:
            text = str(item or "").strip()
            if not text:
                continue
            if len(text) > MAX_PREFIX or any(ord(ch) < 32 or ch.isspace() for ch in text):
                raise ConfigError(i18n._("Префиксы внутренних компонентов: «{prefix}» – без пробелов, до {limit} знаков",
                                          prefix=text[:40], limit=MAX_PREFIX))
            if text not in result:
                result.append(text)
        if len(result) > MAX_PREFIXES:
            raise ConfigError(i18n._("Префиксы внутренних компонентов: не больше {limit}", limit=MAX_PREFIXES))
        return tuple(result)
    if key == "affiliation_words":
        items = value if isinstance(value, (list, tuple)) else re.split(r"[,;\s]+", str(value or ""))
        found: list[str] = []
        seen: set[str] = set()
        for item in items:
            text = str(item or "").strip()
            if not text:
                continue
            if not AFFILIATION_WORD.fullmatch(text):
                raise ConfigError(i18n._("Слова принадлежности: «{word}» – слово из букв (от 2 до 50), в конце "
                                          "допустима «*»", word=text[:40]))
            if text.casefold() not in seen:
                seen.add(text.casefold())
                found.append(text)
        if len(found) > MAX_AFFILIATION_WORDS:
            raise ConfigError(i18n._("Слова принадлежности: не больше {limit}", limit=MAX_AFFILIATION_WORDS))
        return tuple(found)
    if key == "hub_url":
        text = str(value or "").strip().rstrip("/")
        if not text:
            return ""
        hint = i18n._("Адрес Hub: нужен адрес вида https://hub.example.org (только https, без пути, параметров и #).")
        if len(text) > MAX_URL or any(ch.isspace() for ch in text) or "#" in text or "@" in text:
            raise ConfigError(hint)
        try:
            parts = urllib.parse.urlsplit(text)
            port = parts.port
        except ValueError:
            raise ConfigError(hint) from None
        if parts.scheme != "https" or not parts.hostname or parts.path not in ("", "/") or parts.query:
            raise ConfigError(hint)
        if port is not None and not 1 <= port <= 65535:
            raise ConfigError(hint)
        return f"https://{parts.netloc}"
    raise ConfigError(i18n._("Неизвестная настройка «{key}»", key=key))


def _hosts(raw: str) -> tuple[str, ...]:
    """TRUSTED_HOSTS – дополнительные имена хоста через запятую (к 127.0.0.1, localhost, ::1)."""
    extra = [h.strip().lower().strip("[]") for h in raw.split(",") if h.strip()]
    return tuple(dict.fromkeys([*DEFAULT_TRUSTED_HOSTS, *extra]))


def _traffic_log(raw: str) -> str:
    """MODEL_TRAFFIC_LOG – журнал обмена с моделью: «on» (по умолчанию) или «off»."""
    value = raw.strip().casefold() if raw else "on"
    if value not in ("on", "off"):
        raise ConfigError(i18n._("MODEL_TRAFFIC_LOG: ожидается «on» или «off», получено «{raw}»", raw=raw))
    return value
