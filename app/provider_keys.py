"""Ключи профилей провайдеров моделей (ADR-0102 п. 8).

Ключ лежит в базе (app_state.secrets, ADR-0133) вместе с привязкой: адрес сервера (base_url) и
подтверждённые адреса, для которых он задан. В базе, снимке исполнителя, экспорте и интерфейсе ключа нет – в
интерфейсе только «задан, …последние 4 знака»; из журнала обмена вырезается заголовок авторизации, а ключ, который
сервер отразил в теле ответа, журнал хранит как есть (журнал – байт в байт, ADR-0102 п. 8). Заголовок авторизации уходит, только если адрес снимка совпадает
с привязкой; иначе запрос не отправляется вовсе (SendNotAllowed). Права файла – только владелец (0600 в контейнере
Linux); в Windows права файла не проверяются – это сказано в руководстве. Замена ключа – перезапись файла: она
действует и для незавершённых исполнений (ключа в снимке нет). Смена адреса или подтверждённых адресов профиля и
выключение профиля удаляют файл (app/providers.py). В резервные копии папки данных ключи входят.
"""

from __future__ import annotations

import json
import re
import secrets
import threading
import time
from typing import Any

from app.llm import SendNotAllowed
from app.llm_net import normalize_addresses

KEY_NOTE_MISSING = "Прогон на паузе. Задайте ключ профиля на странице «Настройки» и нажмите «Продолжить»."
KEY_NOTE_OTHER = ("Прогон на паузе. Ключ профиля задан для другого адреса сервера: нажмите «Продолжить» – "
                  "неразобранные находки пойдут новым прогоном на действующем профиле проекта.")
# Ключ – знаки token68 (RFC 7235): латиница, цифры и - . _ ~ + / =. Такой ключ годится для заголовка и в JSON не
# экранируется (кроме «/», который иные кодировщики пишут как «\/» – очистка учитывает и этот вид)
# Не короче 16 знаков: короткий ключ совпадал бы со словами ответов модели, и проверка ответа перед сохранением
# (model_traffic.shows_secret) отвергала бы обычные ответы
_KEY = re.compile(r"[A-Za-z0-9\-._~+/=]{16,4096}")
KEY_FORMAT = "Ключ – от 16 до 4096 знаков: латиница, цифры и - . _ ~ + / = (без пробелов и кавычек)."


class KeyRejected(ValueError):
    """Ключ не подходит для заголовка авторизации; текст – по-русски."""


class PendingKeys:
    """Ключ, введённый в форму профиля, до «Сохранить» (после «Проверить» ключ второй раз не
    вводится). Хранится только в памяти процесса по случайной метке формы вместе с привязкой – владелец метки
    (профиль или черновик нового профиля – отдельная случайная метка черновика), адрес сервера и подтверждённые адреса,
    для которых ключ введён: та же привязка, что у сохранённого ключа (save_key). Изменились адрес или подтверждённые
    адреса – ключ по метке не выдаётся, его вводят заново (ревью A8: иначе ключ ушёл бы на адрес, который человек не
    подтверждал при вводе). В страницу, базу и журнал ключ не попадает. Метка живёт 15 минут, «Сохранить» забирает
    ключ после успешной записи; перезапуск приложения метки стирает."""

    TTL_S = 900
    LIMIT = 16

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._items: dict[str, tuple[str, tuple, float]] = {}
        self._claimed: set[str] = set()  # метки, которые сейчас сохраняются: вторая попытка ключа не получит

    @staticmethod
    def binding(owner: str, base_url: str, addresses: Any) -> tuple:
        return (str(owner or ""), _base(base_url), tuple(sorted(normalize_addresses(addresses))))

    def _prune(self, now: float) -> None:
        for handle in [h for h, (_k, _b, until) in self._items.items() if until <= now]:
            del self._items[handle]
            self._claimed.discard(handle)

    def _owned(self, handle: str, owner: str) -> bool:
        item = self._items.get(str(handle or ""))
        return bool(item) and item[1][0] == str(owner or "")

    def remember(self, key: str, owner: str, base_url: str, addresses: Any = (), previous: str = "") -> str:
        """Новая метка для ключа с привязкой (прежняя метка этой формы отменяется)."""
        now = time.monotonic()
        with self._lock:
            self._prune(now)
            if previous and self._owned(previous, owner) and previous not in self._claimed:
                del self._items[previous]  # заменить можно только свою метку, и не ту, что сейчас сохраняется
            while len(self._items) >= self.LIMIT:  # старейшая метка уступает место
                oldest = min(self._items, key=lambda h: self._items[h][2])
                del self._items[oldest]
                self._claimed.discard(oldest)
            handle = secrets.token_urlsafe(24)
            self._items[handle] = (key, self.binding(owner, base_url, addresses), now + self.TTL_S)
            return handle

    def peek(self, handle: str, owner: str, base_url: str, addresses: Any = ()) -> str:
        """Ключ по метке с той же привязкой, без изъятия (проверка, сохранение); иначе пустая строка."""
        with self._lock:
            self._prune(time.monotonic())
            item = self._items.get(str(handle or ""))
            return item[0] if item and item[1] == self.binding(owner, base_url, addresses) else ""

    def claim(self, handle: str, owner: str, base_url: str, addresses: Any = ()) -> str:
        """Ключ по метке для сохранения – атомарно: метка резервируется, второе одновременное сохранение по той же
        метке ключа не получит (ревью A8, круг 2). После записи – forget (успех) или release (отказ)."""
        with self._lock:
            self._prune(time.monotonic())
            item = self._items.get(str(handle or ""))
            if not item or item[1] != self.binding(owner, base_url, addresses) or str(handle) in self._claimed:
                return ""
            self._claimed.add(str(handle))
            return item[0]

    def release(self, handle: str, owner: str) -> None:
        """Сохранение не удалось: метка снова доступна, ключ остаётся в памяти."""
        with self._lock:
            if self._owned(handle, owner):
                self._claimed.discard(str(handle))

    def forget(self, handle: str, owner: str) -> None:
        """Метка больше не нужна: ключ сохранён или человек от ключа отказался. Только своя метка."""
        with self._lock:
            if self._owned(handle, owner):
                del self._items[str(handle)]
                self._claimed.discard(str(handle))


def _base(url: Any) -> str:
    return str(url or "").strip().rstrip("/")


def secret_name(provider_id: int) -> str:
    return f"provider:{int(provider_id)}"


def save_key(keys: Any, provider_id: int, key: str, base_url: str, addresses: Any) -> None:
    """Записать (или заменить) ключ профиля с привязкой к адресу и подтверждённым адресам. keys – база (Database.put_secret)."""
    key = str(key or "").strip()
    if not _KEY.fullmatch(key):
        raise KeyRejected(KEY_FORMAT)
    keys.put_secret(secret_name(provider_id), json.dumps(
        {"addresses": sorted(normalize_addresses(addresses)), "base_url": _base(base_url), "key": key, "version": 1},
        ensure_ascii=True, sort_keys=True))


def parse_entry(raw: Any) -> dict[str, Any] | None:
    """{"key", "base_url", "addresses", "version"} из записанного значения; повреждено – None (ключ считается не заданным)."""
    try:
        if len(raw) > 16384:
            return None
        data = json.loads(raw.decode("ascii") if isinstance(raw, bytes) else raw)
    except (ValueError, TypeError):
        return None
    if not isinstance(data, dict) or not _KEY.fullmatch(str(data.get("key") or "")):
        return None
    return {"key": str(data["key"]), "base_url": _base(data.get("base_url")),
            "addresses": normalize_addresses(data.get("addresses") or []), "version": 1}


def load_key(keys: Any, provider_id: int) -> dict[str, Any] | None:
    """{"key", "base_url", "addresses"} или None: ключа нет или значение повреждено (тогда ключ считается не заданным)."""
    raw = keys.secret(secret_name(provider_id))
    entry = parse_entry(raw) if raw is not None else None
    if entry is None:
        return None
    return {"key": entry["key"], "base_url": entry["base_url"], "addresses": entry["addresses"]}


def delete_key(keys: Any, provider_id: int) -> bool:
    """Удалить ключ профиля; True – ключ был."""
    return keys.drop_secret(secret_name(provider_id))


def key_hint(keys: Any, provider_id: int) -> str:
    """Для интерфейса: «задан, …abcd» или "" (ключа нет)."""
    entry = load_key(keys, provider_id)
    return f"задан, …{entry['key'][-4:]}" if entry else ""


def key_headers(kind: str, key: str) -> dict[str, str]:
    """Секретные заголовки ключа по протоколу (ADR-0106): API чат-завершений и Ollama за ключом –
    «Authorization: Bearer», Messages API – «x-api-key». Служебные заголовки протокола (версия API) сюда не входят:
    их отдаёт клиент (ServerClient.protocol_headers), они не секрет."""
    if str(kind or "") == "messages":
        return {"x-api-key": str(key)}
    return {"Authorization": f"Bearer {key}"}


def auth_headers(keys: Any, provider_id: int, base_url: str, addresses: Any,
                 kind: str = "chat_completions") -> dict[str, str]:
    """Заголовок авторизации для запроса по снимку (адрес base_url, подтверждённые адреса addresses): только если
    привязка ключа совпадает. Ключа нет или он задан для другого адреса – SendNotAllowed, запрос не отправляется."""
    entry = load_key(keys, provider_id) if keys is not None else None
    if entry is None:
        raise SendNotAllowed("Ключ профиля провайдера модели не задан: запрос к модели не отправлен.",
                             note=KEY_NOTE_MISSING)
    if entry["base_url"] != _base(base_url) or set(entry["addresses"]) != set(normalize_addresses(addresses)):
        raise SendNotAllowed("Ключ профиля провайдера модели задан для другого адреса сервера: запрос к модели не "
                             "отправлен.", note=KEY_NOTE_OTHER)
    return key_headers(kind, entry["key"])
