"""Соединение с сервером модели по проверенному адресу (вынесено из app/llm.py в 0.9.12, ADR-0102).

Код находок не должен покидать компьютер, поэтому:
  * адрес сервера – только http(s) с хостом из ALLOWED_HOSTS, без имени и пароля; проверка – до соединения;
  * имя хоста разрешается один раз на запрос, со своим сроком (зависшая служба имён не держит очередь), и
    соединение идёт только с проверенными адресами из этого разрешения. Принимаются конкретные адреса, а не целые
    частные диапазоны: localhost, 127.0.0.1 и ::1 – только loopback; host.docker.internal – loopback, а в контейнере
    адрес из его файла hosts (запись host-gateway из extra_hosts в docker-compose.yml), вне контейнера – адрес
    самого этого компьютера; ollama – loopback, а в контейнере адрес из подсети, к которой он подключён напрямую
    (сеть Docker). Адрес другого компьютера сети под этими именами не принимается;
  * запросы идут через http.client: системные прокси (HTTP_PROXY, настройки Windows) не используются,
    перенаправления не выполняются; у каждого запроса общий срок (сторож закрывает сокет, когда он истёк).

Точки подмены в тестах (_new_socket, _connect_any, in_container, hosts_file_addresses, local_networks,
is_own_address, time, CONTAINER_HOSTS_FILE, CONTAINER_MARKERS, RESOLVE_TIMEOUT_S, _resolve_slots) – атрибуты этого
модуля: функции модуля берут их отсюда при каждом вызове.
"""

from __future__ import annotations

import http.client
import ipaddress
import os
import socket
import sys
import threading
import time
from dataclasses import dataclass
from typing import Any

from app.llm import LlmError, ResolveError, SendNotAllowed, _seconds

try:
    import ssl
except ImportError:  # сборка Python без ssl: остаётся только http
    ssl = None  # type: ignore[assignment]

ALLOWED_HOSTS = ("localhost", "127.0.0.1", "::1", "host.docker.internal", "ollama")
# Имена, которые обязаны указывать на этот же компьютер (loopback). Остальные разрешённые имена – адреса Docker:
# host.docker.internal – шлюз к хосту из файла hosts контейнера, ollama – контейнер в одной сети Docker с приложением.
LOOPBACK_HOSTS = ("localhost", "127.0.0.1", "::1")
CONTAINER_HOSTS_FILE = "/etc/hosts"  # в контейнере его пишет Docker, в том числе записи extra_hosts
CONTAINER_MARKERS = ("/.dockerenv", "/run/.containerenv")  # файлы-метки, которые создают Docker и Podman
CONNECT_TIMEOUT_S = 10.0  # установка соединения: адрес, который молча отбрасывает пакеты, не держит запрос 900 с
# Соединение, рукопожатие TLS и передача байтов запроса идут под блокировкой профиля (app/profile_gate.py): у них свой
# короткий срок – сервер, который тянет рукопожатие или приём запроса, не задерживает правку профиля на весь срок ответа
SEND_TIMEOUT_S = 60.0
RESOLVE_TIMEOUT_S = 5.0  # разрешение имени хоста: зависшая служба имён не держит запрос и очередь триажа
RESOLVE_ATTEMPTS = 3  # отрицательный ответ службы имён (имени нет, временный сбой) повторяется: служба имён за туннелем
# VPN отвечает «нет такого имени» на доли секунды, и обращение срывалось до отправки
RESOLVE_RETRY_WAIT_S = (1.0, 2.0)  # паузы между попытками разрешения имени
_sleep = time.sleep  # пауза между попытками (тесты подменяют)
_now = time.monotonic  # часы цикла попыток (тесты подменяют)
RESOLVE_SLOTS = 4  # одновременных разрешений имён не больше: зависшие держат место до своего конца
MAX_RESPONSE_BYTES = 32 * 1024 * 1024


# ============================================================================ соединение с проверенным адресом

@dataclass(frozen=True)
class _Target:
    scheme: str
    host: str  # имя хоста в нижнем регистре, без скобок IPv6
    port: int
    prefix: str  # путь из адреса сервера без «/» в конце
    base: str  # адрес сервера для сообщений


# Частные сети, в которых бывают адреса Docker (шлюз к хосту, контейнеры): RFC 1918 и IPv6 ULA. Link-local,
# документационные и зарезервированные диапазоны, которые ipaddress тоже считает «частными», не входят. Это
# дополнительное условие, а не разрешение: адрес должен быть ещё и конкретным адресом Docker (см. _address_allowed).
_PRIVATE_NETWORKS = tuple(ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                                                            "fc00::/7"))


# Класс доверия lan (ADR-0102 п. 7): сервер в сети организации – только адреса этих частных сетей и только те, что
# оператор подтвердил в профиле. Точка подмены в тестах (поддельный сервер слушает loopback).
LAN_NETWORKS = _PRIVATE_NETWORKS
TRUST_CLASSES = ("local", "lan", "external")  # иные классы сервер отклоняет
EXTERNAL_ENV = "LLM_EXTERNAL"  # разрешение внешних провайдеров на установке: переменная окружения процесса (ADR-0104)
# Адреса компьютера, на котором работает контейнер (их задаёт start.ps1): изнутри контейнера адрес хоста не «свой» для
# bind(), а соединение с ним ведёт на сам компьютер – внешний профиль туда не ходит (ревью A3)
HOST_ADDRESSES_ENV = "TRIAGE_HOST_ADDRESSES"
HOST_UNKNOWN = ("Нет свежих адресов компьютера, на котором работает контейнер: их передаёт сборщик метрик компьютера, а он "
                "не работает или не прочитал адреса (после перезагрузки компьютера он сам не запускается). Внешний "
                "запрос не отправлен – иначе нельзя исключить обращение к самому компьютеру. Запустите сборщик в "
                "PowerShell из папки приложения: .\\scripts\\host-metrics.ps1 -Action Start – приложение "
                "перезапускать не нужно.")
# что делать оператору (текст паузы прогона): дело в сборщике, а не в профиле – совет «включите профиль» здесь ложный
HOST_UNKNOWN_NOTE = "Прогон на паузе. Когда сборщик заработает, нажмите «Продолжить»."
# Свежие адреса компьютера-хоста от сборщика метрик (scripts/host-metrics.ps1 → telemetry/host.json): функция,
# которую задаёт приложение при запуске (main.create_app); None – источника нет. Адреса меняются (временные IPv6,
# новый адрес после переподключения), поэтому снимка при запуске мало (ревью A3, круг 2).
HOST_SOURCE: Any = None
# Переходные диапазоны IPv6 со встроенным IPv4 (NAT64, 6to4, Teredo, IPv4-совместимые и SIIT): за ними может стоять
# внутренний или собственный адрес – внешнему профилю они не нужны и не принимаются (ревью A3)
_TRANSITION_V6 = tuple(ipaddress.ip_network(n) for n in ("64:ff9b::/96", "64:ff9b:1::/48", "2002::/16", "2001::/32",
                                                         "::/96", "::ffff:0:0:0/96"))
EXTERNAL_OFF = ("Внешние провайдеры моделей на этой установке выключены (в окружении приложения нет LLM_EXTERNAL=1): "
                "запрос не отправлен.")
CONFIRM_NOTE = ("Прогон на паузе. Подтвердите адреса сервера в профиле на странице «Настройки» и нажмите «Продолжить» – "
                "неразобранные находки пойдут новым прогоном.")


def lan_address_ok(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Адрес допустим для класса lan: из частных сетей (RFC 1918, ULA), не link-local, не групповой и не пустой."""
    return (not ip.is_link_local and not ip.is_multicast and not ip.is_unspecified
            and any(ip in network for network in LAN_NETWORKS if network.version == ip.version))


def external_enabled() -> bool:
    """Внешние провайдеры разрешены на этой установке: LLM_EXTERNAL=1 в окружении процесса (ADR-0104 п. 1). Читается
    при каждом вызове: снятая переменная действует с ближайшей отправки."""
    return os.environ.get(EXTERNAL_ENV, "").strip() == "1"


def external_address_ok(ip: ipaddress.IPv4Address | ipaddress.IPv6Address, hosts: list | None = None) -> bool:
    """Адрес допустим для класса external: глобальный адрес в интернете (ipaddress.is_global: не частные сети, не
    loopback, не link-local, не CGNAT 100.64/10, не документационные и не зарезервированные), не групповой и не
    собственный адрес этого компьютера (ADR-0104 п. 2). hosts – сети адресов хоста одного снимка (host_networks) на
    весь запрос; None – прочитать сейчас. is_own_address берётся из модуля при каждом вызове."""
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.version == 6 and any(ip in network for network in _TRANSITION_V6):
        return False
    hosts = host_networks() if hosts is None else hosts
    # зарезервированные (например 4000::/3, 8000::/1) ipaddress может считать и глобальными – не внешние (ревью D1)
    return (ip.is_global and not ip.is_multicast and not ip.is_reserved
            and not any(ip in network for network in hosts) and not is_own_address(ip))


def _fresh_host_addresses() -> list[str] | None:
    """Свежие адреса хоста от сборщика метрик или None (источника нет, данные устарели, сбой чтения)."""
    source = HOST_SOURCE
    if source is None:
        return None
    try:
        found = source()
    except Exception:  # noqa: BLE001 – сбой источника = данных нет: внешний запрос не уйдёт
        return None
    return None if found is None else list(found)


def host_addresses(fresh: list[str] | None = None) -> set[str]:
    """Адреса компьютера-хоста: из TRIAGE_HOST_ADDRESSES (start.ps1, при запуске) и свежие от сборщика метрик (fresh –
    уже прочитанный снимок; None – прочитать сейчас)."""
    listed = os.environ.get(HOST_ADDRESSES_ENV, "").replace(";", ",").split(",")
    if fresh is None:
        fresh = _fresh_host_addresses() or []
    return set(normalize_addresses([*listed, *fresh]))


def host_networks(fresh: list[str] | None = None) -> list:
    """Сети адресов хоста: IPv4 – адрес целиком, IPv6 – его /64 (временные адреса IPv6 меняются внутри префикса)."""
    networks = []
    for text in host_addresses(fresh):
        ip = _ip(text)
        if ip is None:
            continue
        networks.append(ipaddress.ip_network(f"{ip}/64", strict=False) if ip.version == 6 and ip.is_global
                        else ipaddress.ip_network(str(ip)))
    return networks


def normalize_addresses(values: Any) -> list[str]:
    """Подтверждённые адреса в едином виде (как их пишет ipaddress), без повторов; не адреса – пропускаются."""
    result: list[str] = []
    for value in values or ():
        ip = _ip(str(value))
        if ip is not None and str(ip) not in result:
            result.append(str(ip))
    return result


def _ip(text: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Адрес из текста (без индекса зоны «%eth0»); IPv4, записанный как IPv6 (::ffff:a.b.c.d), – как IPv4."""
    try:
        ip = ipaddress.ip_address(str(text).strip().split("%", 1)[0])
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def parse_hosts(text: str, name: str) -> set:
    """Адреса имени из текста файла hosts («адрес имя [имя…]», «#» – комментарий)."""
    wanted = name.casefold()
    result = set()
    for line in str(text or "").splitlines():
        parts = line.split("#", 1)[0].split()
        if len(parts) >= 2 and wanted in (p.casefold() for p in parts[1:]):
            ip = _ip(parts[0])
            if ip is not None:
                result.add(ip)
    return result


def hosts_file_addresses(name: str) -> set:
    """Адреса имени из файла hosts контейнера (/etc/hosts: туда Docker пишет записи extra_hosts)."""
    try:
        with open(CONTAINER_HOSTS_FILE, encoding="utf-8", errors="replace") as fh:
            return parse_hosts(fh.read(1_000_000), name)
    except OSError:
        return set()


def in_container() -> bool:
    """Приложение работает в контейнере: есть файл-метка, который создаёт Docker (/.dockerenv) или Podman."""
    return any(os.path.exists(path) for path in CONTAINER_MARKERS)


def is_own_address(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Адрес принадлежит этому компьютеру: к нему привязывается сокет (к адресу другой машины – нет). Пакеты при
    проверке не отправляются. Пустой, групповой, link-local и зарезервированный адреса не принимаются."""
    if ip.is_unspecified or ip.is_multicast or ip.is_link_local or ip.is_reserved:
        return False
    family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_STREAM) as probe:
            probe.bind((str(ip), 0))
    except OSError:
        return False
    return True


_RTF_UP, _RTF_GATEWAY = 0x1, 0x2  # флаги маршрута в /proc/net/route


def parse_routes(route: str, inet6: str) -> list:
    """Подсети прямого подключения из /proc/net/route (IPv4: действующие маршруты без шлюза) и /proc/net/if_inet6
    (IPv6: адреса интерфейсов с длиной префикса); без маршрута по умолчанию, loopback и link-local. Сеть, до которой
    идут через шлюз, – уже не сеть Docker этого контейнера."""
    networks = []
    for line in str(route or "").splitlines()[1:]:
        parts = line.split()
        if len(parts) < 8:
            continue
        try:
            flags = int(parts[3], 16)
            if not flags & _RTF_UP or flags & _RTF_GATEWAY or int(parts[2], 16):
                continue
            destination = int(parts[1], 16).to_bytes(4, sys.byteorder)  # ядро пишет адрес в порядке байт машины
            mask = int(parts[7], 16).to_bytes(4, sys.byteorder)
            network = ipaddress.ip_network((ipaddress.IPv4Address(destination),
                                            str(ipaddress.IPv4Address(mask))), strict=False)
        except (ValueError, OverflowError):
            continue
        if network.prefixlen > 0 and not network.is_loopback:
            networks.append(network)
    for line in str(inet6 or "").splitlines():
        parts = line.split()
        if len(parts) < 3 or len(parts[0]) != 32:
            continue
        try:
            network = ipaddress.ip_network((ipaddress.IPv6Address(int(parts[0], 16)), int(parts[2], 16)),
                                           strict=False)
        except ValueError:
            continue
        if network.prefixlen > 0 and not (network.is_loopback or network.is_link_local):
            networks.append(network)
    return networks


def local_networks() -> list:
    """Подсети, к которым этот компьютер или контейнер подключён напрямую (Linux; в Windows – пусто)."""
    texts = []
    for path in ("/proc/net/route", "/proc/net/if_inet6"):
        try:
            with open(path, encoding="ascii", errors="replace") as fh:
                texts.append(fh.read(1_000_000))
        except OSError:
            texts.append("")
    return parse_routes(*texts)


def _is_private(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return any(ip in network for network in _PRIVATE_NETWORKS if network.version == ip.version)


def _address_allowed(host: str, address: str) -> bool:
    """Можно ли соединяться с адресом под этим именем. Loopback – всегда; localhost, 127.0.0.1, ::1 – только
    loopback. Остальное – только конкретные адреса, а не целые частные диапазоны:
      * host.docker.internal: в контейнере – частный адрес, записанный для этого имени в файле hosts контейнера
        (host-gateway из extra_hosts); вне контейнера – адрес самого этого компьютера (так его пишет Docker Desktop
        в hosts Windows; устаревшая запись с чужим адресом не проходит);
      * ollama: в контейнере – частный адрес из подсети, к которой контейнер подключён напрямую (сеть Docker: туда
        пакеты идут без шлюза, к контейнерам этого же компьютера); вне контейнера – только loopback.
    Link-local, пустой и групповой адреса не принимаются. in_container, hosts_file_addresses, local_networks
    и is_own_address берутся из модуля при каждом вызове."""
    ip = _ip(address)
    if ip is None:
        return False
    if ip.is_loopback:
        return True
    if host in LOOPBACK_HOSTS or ip.is_link_local or ip.is_unspecified or ip.is_multicast:
        return False
    container = in_container()
    if host == "host.docker.internal":
        if container:
            return _is_private(ip) and ip in hosts_file_addresses(host)
        return is_own_address(ip)
    if host == "ollama":
        return container and _is_private(ip) and any(ip in network for network in local_networks()
                                                     if network.version == ip.version)
    return False


_resolve_slots = threading.BoundedSemaphore(RESOLVE_SLOTS)


def _resolve_error(host: str, text: str, trust: str = "local") -> ResolveError:
    """Сбой службы имён словами (ResolveError: запрос не отправлен). Совет указать адрес Ollama числом – только для
    Ollama этого компьютера; сервер в сети и внешний провайдер этим не чинятся."""
    if trust == "local":
        return ResolveError(f"Имя сервера «{host}» {text}. Проверьте сеть или укажите адрес Ollama числом, например "
                            "http://127.0.0.1:11434.")
    return ResolveError(f"Имя сервера «{host}» {text}. Проверьте сеть и адрес сервера в профиле.")


def _resolve_once(host: str, port: int, timeout: float, trust: str) -> list[tuple] | socket.gaierror:
    """Одна попытка разрешения имени в отдельном потоке: записи getaddrinfo или отрицательный ответ службы имён
    (socket.gaierror – его _getaddrinfo повторяет). Блокирующий getaddrinfo не прервать, поэтому по истечении срока
    запрос получает ResolveError, а поток дорабатывает сам (фоновый, остановке приложения не мешает). Одновременно идёт
    не больше RESOLVE_SLOTS разрешений: если служба имён зависла, следующие запросы сразу получают ошибку, а не копят
    потоки. Зависание, занятые места и прочие ошибки не повторяются."""
    slots = _resolve_slots  # освобождается тот же семафор, что занят, даже если модуль его заменил
    if not slots.acquire(blocking=False):
        raise _resolve_error(host, "не разрешается: служба имён (DNS) не ответила на прежние запросы", trust)
    box: dict[str, Any] = {}
    done = threading.Event()

    def work() -> None:
        try:
            box["infos"] = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except Exception as e:  # ошибка передаётся запросу
            box["error"] = e
        finally:
            slots.release()
            done.set()

    try:
        threading.Thread(target=work, name="ollama-resolve", daemon=True).start()
    except RuntimeError:  # поток не запустился (предел потоков)
        slots.release()
        raise _resolve_error(host, "не разрешено: не удалось запустить поток", trust) from None
    if not done.wait(max(0.0, timeout)):
        raise _resolve_error(host, f"не разрешилось за {_seconds(round(max(0.0, timeout), 1))}: служба имён (DNS) "
                                   "не отвечает", trust)
    error = box.get("error")
    if isinstance(error, socket.gaierror):
        return error
    if error is not None:
        raise _resolve_error(host, "не разрешено", trust) from None
    return box["infos"]


def _getaddrinfo(host: str, port: int, timeout: float, trust: str = "local") -> list[tuple]:
    """socket.getaddrinfo с общим сроком timeout (секунды) на все попытки и паузы.

    Адрес-число разбирается сразу, без службы имён. Отрицательный ответ службы имён («имени нет», временный сбой)
    повторяется до RESOLVE_ATTEMPTS раз с паузами RESOLVE_RETRY_WAIT_S (ADR-0113): служба имён за туннелем VPN отвечает
    отказом на доли секунды, и без повтора обращение срывалось до отправки. Зависание (срок), занятые места и прочие
    ошибки не повторяются. Все ошибки – ResolveError: ни один байт запроса не ушёл."""
    if _ip(host) is not None:
        try:
            return socket.getaddrinfo(host, port, type=socket.SOCK_STREAM, flags=socket.AI_NUMERICHOST)
        except OSError:
            raise _resolve_error(host, "не разобран как адрес", trust) from None
    error: socket.gaierror | None = None
    deadline = _now() + max(0.0, timeout)  # срок – на все попытки и паузы вместе (ревью круга 51, В2)
    attempts = 0
    for attempt in range(RESOLVE_ATTEMPTS):
        if attempt:
            wait = RESOLVE_RETRY_WAIT_S[min(attempt - 1, len(RESOLVE_RETRY_WAIT_S) - 1)]
            if deadline - _now() <= wait:
                break  # пауза съела бы остаток срока: повтор не успеет
            _sleep(wait)
        left = deadline - _now()
        if left <= 0:
            break
        attempts += 1
        got = _resolve_once(host, port, left, trust)
        if not isinstance(got, socket.gaierror):
            return got
        error = got
    tries = f" ({attempts} {'попытка' if attempts == 1 else 'попытки'} подряд)"
    if error is not None and error.errno == getattr(socket, "EAI_AGAIN", None):
        # временный сбой службы имён – не «имени нет»
        raise _resolve_error(host, "не разрешилось: служба имён (DNS) временно не ответила" + tries +
                             " – повторите через минуту", trust) from None
    if trust == "local":
        raise ResolveError(f"Имя сервера «{host}» не найдено{tries}. Если приложение запущено не в Docker, укажите адрес "
                           "Ollama http://127.0.0.1:11434 на странице «Настройки».") from None
    raise ResolveError(f"Имя сервера «{host}» не найдено службой имён (DNS){tries}: проверьте адрес сервера в профиле и "
                       "сеть; если имя верное, повторите через минуту.") from None


def _lan_entries(host: str, entries: list[tuple], confirmed: Any) -> list[tuple]:
    """Класс lan: все адреса имени – из частных сетей (иначе LlmError) и подтверждены в профиле (иначе SendNotAllowed –
    запрос не отправлен, профиль требует нового подтверждения)."""
    found = [(str(info[4][0]), _ip(str(info[4][0]))) for info in entries]
    outside = [text for text, ip in found if ip is None or not lan_address_ok(ip)]
    if outside or not found:
        raise LlmError(f"Имя «{host}» указывает на адрес {', '.join(outside) or 'неизвестно'} – это не частная сеть "
                       "(10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7). Запрос не отправлен: сервер в сети "
                       "организации принимается только с частным адресом.")
    allowed = set(normalize_addresses(confirmed))
    new = [str(ip) for _, ip in found if str(ip) not in allowed]
    if new:
        known = (f"в профиле подтверждены {', '.join(sorted(allowed))}" if allowed
                 else "адреса сервера в профиле не подтверждены")
        raise SendNotAllowed(f"Сервер «{host}» – это адрес {', '.join(new)}, а {known}: запрос к модели не "
                             "отправлен.", note=CONFIRM_NOTE)
    return entries


def _external_entries(host: str, entries: list[tuple], hosts: list) -> list[tuple]:
    """Класс external: все адреса имени – глобальные и не адреса хоста (hosts – сети одного снимка на запрос); иначе
    LlmError: имя внешнего сервера не должно вести во внутреннюю сеть или на этот компьютер."""
    found = [(str(info[4][0]), _ip(str(info[4][0]))) for info in entries]
    bad = [text for text, ip in found if ip is None or not external_address_ok(ip, hosts)]
    if bad or not found:
        raise LlmError(f"Имя «{host}» указывает на адрес {', '.join(bad) or 'неизвестно'} – это не адрес в интернете "
                       "(внутренняя сеть, этот компьютер или служебный диапазон). Запрос не отправлен: внешний "
                       "провайдер принимается только с публичным адресом.")
    return entries


def _resolve(host: str, port: int, timeout: float = RESOLVE_TIMEOUT_S, trust: str = "local",
             confirmed: Any = ()) -> list[tuple]:
    """Записи getaddrinfo для разрешённого имени: только допустимые адреса, IPv4 первым. Имя разрешается не дольше
    min(RESOLVE_TIMEOUT_S, timeout) секунд. Класс local (_address_allowed): имя указывает хоть на один недопустимый
    адрес – LlmError, такому имени не доверяем совсем. Класс lan (_lan_entries): только частные и подтверждённые
    адреса (confirmed). Соединение потом идёт только с этими записями (_connect_any): имя повторно не разрешается,
    поэтому подменить адрес между проверкой и соединением нельзя."""
    if trust not in TRUST_CLASSES:
        raise LlmError(f"Класс доверия «{trust}» не поддерживается: запрос к модели не отправлен.")
    if trust == "external" and not external_enabled():  # до службы имён: снятая переменная – ни одного обращения
        raise SendNotAllowed(EXTERNAL_OFF)
    hosts: list = []
    if trust == "external":
        # один снимок адресов хоста на весь запрос (ревью A3, круг 3): в контейнере без свежего снимка – отказ
        fresh = _fresh_host_addresses()
        if in_container() and fresh is None:
            raise SendNotAllowed(HOST_UNKNOWN, note=HOST_UNKNOWN_NOTE)
        hosts = host_networks(fresh or [])
    infos = _getaddrinfo(host, port, min(RESOLVE_TIMEOUT_S, timeout), trust)
    unique: dict[tuple, tuple] = {}
    for info in infos:
        unique.setdefault(tuple(info[4]), info)
    # IPv4 первым: Ollama в Windows слушает только 127.0.0.1, а отказ на ::1 там стоит около 2 с на каждый запрос
    entries = sorted(unique.values(), key=lambda info: info[0] != socket.AF_INET)
    if trust == "lan":
        return _lan_entries(host, entries, confirmed)
    if trust == "external":
        return _external_entries(host, entries, hosts)
    bad = [str(info[4][0]) for info in entries if not _address_allowed(host, str(info[4][0]))]
    if bad or not entries:
        container = in_container()
        if host == "host.docker.internal" and container:
            where = ("этот компьютер: такого адреса нет в файле hosts контейнера (запись "
                     "host.docker.internal:host-gateway в extra_hosts, docker-compose.yml)")
        elif host == "host.docker.internal":
            where = "адрес этого компьютера (запись host.docker.internal в файле hosts устарела?)"
        elif host == "ollama" and container:
            where = "этот компьютер и не сеть Docker, к которой подключён контейнер"
        elif host == "ollama":
            where = "этот компьютер: вне контейнера имя ollama принимается только с адресом loopback"
        else:
            where = "этот компьютер"
        raise LlmError(f"Имя «{host}» указывает на адрес {', '.join(bad) or 'неизвестно'} – это не {where}. "
                       "Запрос не отправлен: код находок не должен покидать компьютер.")
    return entries


def external_target(url: str) -> _Target:
    """Адрес внешнего сервера без сети (ADR-0104 п. 2): только https, без имени и пароля, без «?» и «#», порт числом;
    адрес-число – только глобальный. Куда указывает имя, проверяется при каждом запросе (_resolve). LlmError."""
    import urllib.parse
    hint = "нужен адрес вида https://api.example.com"
    url = str(url or "").strip()
    if not url:
        raise LlmError(f"Адрес внешнего сервера не задан: {hint}.")
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        raise LlmError(f"Адрес внешнего сервера не распознан: {hint}.") from None
    if parts.scheme.lower() != "https" or not parts.netloc:
        raise LlmError(f"Внешний сервер – только https: {hint}.")
    if ssl is None:  # pragma: no cover - сборка Python без ssl
        raise LlmError("В этой сборке Python нет поддержки https: внешний сервер недоступен.")
    if "@" in parts.netloc:
        raise LlmError(f"В адресе внешнего сервера не должно быть имени пользователя и пароля: {hint}.")
    host = (parts.hostname or "").lower()
    ip = _ip(host)
    if not host or ip is not None and not external_address_ok(ip):
        raise LlmError(f"Адрес «{host}» – не адрес в интернете: внешний сервер принимается только с публичным "
                       f"адресом, {hint}.")
    try:
        port = parts.port
    except ValueError:
        raise LlmError(f"В адресе внешнего сервера неверный порт: {hint}.") from None
    if parts.query or parts.fragment:
        raise LlmError(f"В адресе внешнего сервера не должно быть «?» и «#»: {hint}.")
    prefix = parts.path.rstrip("/")
    base = urllib.parse.urlunsplit(("https", parts.netloc, prefix, "", ""))
    return _Target("https", host, port or 443, prefix, base)


def resolve_allowed(host: str, port: int, timeout: float = RESOLVE_TIMEOUT_S) -> list[str]:
    """Адреса, с которыми клиент будет соединяться для разрешённого имени хоста (по порядку); иначе LlmError."""
    return [str(info[4][0]) for info in _resolve(host, port, timeout)]


class _ConnectTimeout(Exception):
    """Соединение не установлено за отведённое время."""


_new_socket = socket.socket  # точка подмены в тестах


def _connect_any(entries: list[tuple], deadline: float) -> socket.socket:
    """Соединение с первым ответившим из проверенных адресов. Адрес берётся из записи getaddrinfo целиком
    (с индексом интерфейса у IPv6 link-local) – имя повторно не разрешается."""
    last: OSError | None = None
    for family, socktype, proto, _, sockaddr in entries:
        sock = None
        try:
            sock = _new_socket(family, socktype, proto)
            sock.settimeout(min(CONNECT_TIMEOUT_S, _remaining(deadline)))
            sock.connect(sockaddr)
            sock.settimeout(_remaining(deadline))
            try:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except OSError:
                pass
            return sock
        except OSError as e:  # в том числе TimeoutError: пробуем следующий адрес
            last = e
            if sock is not None:
                sock.close()
    if isinstance(last, TimeoutError):
        raise _ConnectTimeout
    raise last or OSError("нет адресов для соединения")


class _Watchdog:
    """Общий срок запроса: по его истечении зарегистрированный сокет закрывается на уровне дескриптора (shutdown),
    и любое ожидание – рукопожатие TLS, заголовки, тело – прерывается.

    Сокет регистрируется через register() под той же блокировкой, что и срабатывание: если срок истёк раньше
    регистрации (например, между отсоединением дескриптора в wrap_socket и регистрацией TLS-сокета), новый сокет
    закрывается сразу и запрос прекращается (TimeoutError). socket.socket.shutdown вызывается напрямую и для
    TLS-сокета: закрывается сам дескриптор, а состояние TLS (SSLSocket._sslobj), которым в этот момент пользуется
    читающий поток, не трогается. После cancel() сторож ничего не делает.
    """

    def __init__(self, deadline: float) -> None:
        self.fired = False
        self._done = False
        self._sock: socket.socket | None = None
        self._lock = threading.Lock()
        self._timer = threading.Timer(max(0.0, deadline - time.monotonic()), self._fire)
        self._timer.daemon = True
        self._timer.start()

    @staticmethod
    def _shutdown(sock: socket.socket | None) -> None:
        if sock is not None:
            try:
                socket.socket.shutdown(sock, socket.SHUT_RDWR)
            except OSError:
                pass

    def _fire(self) -> None:
        with self._lock:
            if self._done:
                return
            self.fired = True
            self._shutdown(self._sock)

    def register(self, sock: socket.socket) -> None:
        """Сокет, который надо прервать по сроку (заменяет прежний). Срок уже истёк – закрыть и TimeoutError."""
        with self._lock:
            self._sock = sock
            expired = self.fired and not self._done
            if expired:
                self._shutdown(sock)
        if expired:
            raise TimeoutError

    def cancel(self) -> None:
        with self._lock:
            self._done = True
            self._sock = None
        self._timer.cancel()


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """HTTP-соединение только с заранее проверенными адресами; в заголовке Host – исходное имя.

    После успешного send() байты копируются в request_wire для журнала обмена с моделью. При сбое sendall
    отправленная часть неизвестна: блок не записывается как отправленный.
    """

    def __init__(self, host: str, port: int, entries: list[tuple], deadline: float, watchdog: _Watchdog) -> None:
        super().__init__(host, port, timeout=max(0.001, deadline - time.monotonic()))
        self._entries = entries
        self._deadline = deadline
        self._watchdog = watchdog
        self.request_wire = bytearray()
        # передача байтов запроса началась (первый send): после этого исход для сервера неизвестен, даже если
        # request_wire пуст – при сбое sendall отправленная часть неизвестна (К11 плана 0.9.13)
        self.send_started = False

    def connect(self) -> None:
        sock = _connect_any(self._entries, self._deadline)
        self.sock = sock
        self._watchdog.register(sock)
        settimeout = getattr(sock, "settimeout", None)
        if settimeout is not None:  # передача запроса – с коротким сроком (обычный срок вернёт _request)
            settimeout(min(SEND_TIMEOUT_S, _remaining(self._deadline)))

    def send(self, data: Any) -> None:
        if isinstance(data, str):
            data = data.encode("ascii")
        if self.sock is None and self.auto_open:  # http.client соединяется внутри send: соединение – до отметки
            self.connect()
        settimeout = getattr(self.sock, "settimeout", None)
        if settimeout is not None:  # передача запроса – с коротким сроком (обычный срок вернёт _request)
            settimeout(min(SEND_TIMEOUT_S, _remaining(self._deadline)))
        self.send_started = True  # сразу перед передачей: сбой подготовки срока байты не отправлял
        super().send(data)
        self.request_wire += data


def _tls_context():
    """Контекст TLS: системное хранилище сертификатов процесса (в контейнере – образа), проверка имени хоста.
    Точка подмены в тестах (тестовый удостоверяющий центр, tests/certs)."""
    return ssl.create_default_context()


if ssl is not None:
    class _PinnedHTTPSConnection(_PinnedHTTPConnection):
        """HTTPS с проверенными адресами; сертификат проверяется по исходному имени хоста."""

        default_port = http.client.HTTPS_PORT

        def connect(self) -> None:
            raw = _connect_any(self._entries, self._deadline)
            self.sock = raw
            self._watchdog.register(raw)
            # wrap_socket забирает дескриптор у raw: сторожу нужен уже TLS-сокет, и до рукопожатия – тогда
            # общий срок прерывает и затянутое рукопожатие
            tls = _tls_context().wrap_socket(raw, server_hostname=self.host, do_handshake_on_connect=False)
            self.sock = tls
            self._watchdog.register(tls)
            tls.settimeout(min(CONNECT_TIMEOUT_S, _remaining(self._deadline)))  # рукопожатие – как соединение
            tls.do_handshake()
            tls.settimeout(min(SEND_TIMEOUT_S, _remaining(self._deadline)))  # передача запроса – с коротким сроком
else:  # pragma: no cover - сборка Python без ssl
    _PinnedHTTPSConnection = None  # type: ignore[assignment,misc]


class _TooLarge(Exception):
    """Тело ответа больше MAX_RESPONSE_BYTES."""


def _remaining(deadline: float) -> float:
    left = deadline - time.monotonic()
    if left <= 0:
        raise TimeoutError
    return left


def _read_body(response: http.client.HTTPResponse, deadline: float) -> bytes:
    """Тело ответа целиком, не дольше общего срока и не больше MAX_RESPONSE_BYTES. Соединение закрылось раньше
    заявленной длины – http.client.IncompleteRead."""
    chunks, size = [], 0
    while True:
        _remaining(deadline)
        chunk = response.read1(65536)
        if not chunk:
            break
        size += len(chunk)
        if size > MAX_RESPONSE_BYTES:
            raise _TooLarge
        chunks.append(chunk)
    if response.length:  # read1 на обрыве возвращает пустые байты без ошибки: остаток заявленной длины не прочитан
        raise http.client.IncompleteRead(b"".join(chunks), response.length)
    return b"".join(chunks)


class _RecordedResponse:
    """HTTPResponse, у которого каждое чтение через read1 копирует полученные байты в read_wire: для журнала
    обмена с моделью тело ответа записывается ровно как пришло (до разбора JSON). Остальные поля и методы –
    как у настоящего ответа."""

    def __init__(self, inner: http.client.HTTPResponse) -> None:
        self._inner = inner
        self.read_wire = bytearray()
        self.chunk_count = 0

    def read1(self, size: int = -1) -> bytes:
        chunk = self._inner.read1(size)
        if chunk:
            self.read_wire += chunk
            self.chunk_count += 1
        return chunk

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


def _elapsed_ms(started: float) -> int:
    """Сколько миллисекунд прошло с started (монотонные часы)."""
    return max(0, int(round((time.monotonic() - started) * 1000)))


def _peer(conn: Any) -> str | None:
    """IP и порт, к которому установлено соединение (из сокета); соединения не было – None."""
    sock = getattr(conn, "sock", None)
    if sock is None:
        return None
    try:
        addr = sock.getpeername()
    except OSError:
        return None
    host, port = str(addr[0]), int(addr[1])
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def _response_headers(response: Any) -> dict[str, str]:
    """Заголовки ответа из HTTPResponse; повторённое имя соединяется через «, »."""
    result: dict[str, str] = {}
    for name, value in response.getheaders():
        key = str(name)
        result[key] = f"{result[key]}, {value}" if key in result else str(value)
    return result


def _wire_headers(wire: bytes) -> dict[str, str]:
    """Заголовки запроса, разобранные из точного потока wire (после строки запроса, до пустой строки)."""
    head = wire.split(b"\r\n\r\n", 1)[0]
    result: dict[str, str] = {}
    for line in head.split(b"\r\n")[1:]:
        name, sep, value = line.partition(b":")
        if not sep:
            continue
        key = name.decode("utf-8", "replace")
        text = value.strip().decode("utf-8", "replace")
        result[key] = f"{result[key]}, {text}" if key in result else text
    return result


def _os_error_text(error: OSError) -> str:
    """Системная ошибка соединения по-русски (текст системы бывает английским)."""
    if ssl is not None and isinstance(error, ssl.SSLError):
        return "ошибка TLS: сертификат сервера не прошёл проверку или протокол не поддерживается"
    if isinstance(error, (ConnectionResetError, ConnectionAbortedError, BrokenPipeError)):
        return "сервер закрыл соединение"
    code = getattr(error, "errno", None)
    return f"ошибка соединения{f' (код {code})' if code else ''}"
