"""Граница «допуск – отправка» и правка профиля провайдера модели (ADR-0102 п. 7–8).

Запрос к серверу профиля читает допуск (профиль включён), действующие подтверждённые адреса и ключ, разрешает имя и
передаёт байты запроса под общей блокировкой профиля (read); правка профиля, его выключение, замена и удаление ключа –
под исключительной (write). Правка ждёт, пока начатые запросы допишут байты, а запрос, начатый во время правки, ждёт её
конца и видит её целиком: код и ключ не уходят по состоянию, которое оператор уже отменил. Ответ модели читается уже
без блокировки. Ждущая правка пропускается вперёд новых запросов – запросы прогона не задерживают её бесконечно.
"""

from __future__ import annotations

import threading
from collections.abc import Iterator
from contextlib import contextmanager

# Сколько ждать блокировку: читатели держат её до конца передачи байтов запроса (соединение и отправка – со своими
# короткими сроками), писатель – на время записи правки. Дольше – TimeoutError: запрос или правку повторяют.
READ_WAIT_S = 120.0
WRITE_WAIT_S = 150.0


class ProfileGate:
    """Блокировка «много читателей – один писатель» с приоритетом писателя и ограниченным ожиданием."""

    def __init__(self) -> None:
        self._cond = threading.Condition()
        self._readers = 0
        self._writer = False
        self._waiting = 0

    @contextmanager
    def read(self, timeout: float = READ_WAIT_S) -> Iterator[None]:
        with self._cond:
            if not self._cond.wait_for(lambda: not self._writer and not self._waiting, timeout):
                raise TimeoutError("профиль правится слишком долго")
            self._readers += 1
        try:
            yield
        finally:
            with self._cond:
                self._readers -= 1
                if not self._readers:
                    self._cond.notify_all()

    @contextmanager
    def write(self, timeout: float = WRITE_WAIT_S) -> Iterator[None]:
        with self._cond:
            self._waiting += 1
            try:
                if not self._cond.wait_for(lambda: not self._writer and not self._readers, timeout):
                    raise TimeoutError("профиль занят отправкой запросов слишком долго")
            finally:
                self._waiting -= 1
                self._cond.notify_all()
            self._writer = True
        try:
            yield
        finally:
            with self._cond:
                self._writer = False
                self._cond.notify_all()


_gates: dict[int, ProfileGate] = {}
_lock = threading.Lock()


def gate(provider_id: int) -> ProfileGate:
    """Блокировка профиля provider_id (одна на процесс)."""
    with _lock:
        return _gates.setdefault(int(provider_id), ProfileGate())
