"""Чтение журнала обмена приложения с моделью (папка `data/model-traffic`, файлы `ГГГГ-ММ-ДД.jsonl`).

Журнал пишет приложение (app/model_traffic.py): по одному событию JSON на строку, каждое обращение к модели –
событие `request` (до отправки) и `response` или `error` с тем же `id`. Сценарий только читает файлы,
в приложение не обращается и его модули не импортирует. Дата в имени файла и время событий – по UTC, а не
по местному времени: прогон после полуночи по местному времени в поясе восточнее UTC попадает в файл
предыдущего дня UTC.

Запуск: python scripts/model_traffic.py <команда> [--dir ПАПКА]

Команды:
  list     таблица обменов: время, id (8 знаков), назначение, прогон, находка, метод и путь, статус,
           длительность, размер запроса и ответа; фильтры --date ГГГГ-ММ-ДД, --run N, --hub ID, --purpose
  show ID  запрос и ответ целиком: заголовки и тела (JSON тел – с отступами; точные байты – командой dump)
  dump ID --part request|response --out ФАЙЛ
           точные байты: у request – весь поток запроса (wire), у response – тело ответа
  verify   сверка sha256 и длин всех событий (--date ГГГГ-ММ-ДД – один день); код выхода 1 при расхождении
  stats    сколько обменов по дням и назначениям, объём запросов и ответов

Папка журнала по умолчанию – `data/model-traffic` от корня репозитория.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DIR = ROOT / "data" / "model-traffic"

DATE = "ГГГГ-ММ-ДД"


def utf8_output() -> None:
    """Вывод в UTF-8 с заменой непечатаемых знаков.

    В консоли Windows с кодовой страницей 437/866 (или при перенаправлении вывода) argparse печатает справку
    через stdout и падает с UnicodeEncodeError на кириллице. Переключение потока на UTF-8 убирает трассировку:
    --help завершается кодом 0 на любой подкоманде.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError):
            pass


utf8_output()


def error(message: str) -> None:
    print(f"Ошибка: {message}", file=sys.stderr)
    raise SystemExit(2)


def decode(text: str, encoding: str | None) -> bytes:
    """Текст поля журнала -> точные байты: utf-8 как есть, base64 – раскодировать."""
    if not encoding or encoding == "utf-8":
        return text.encode("utf-8")
    if encoding == "base64":
        try:
            return base64.b64decode(text, validate=True)
        except binascii.Error as e:
            error(f"неверный base64: {e}")
    error(f"неизвестный вид кодирования «{encoding}»")
    return b""


def events_in(folder: Path, day: str | None = None) -> list[dict]:
    """Все события журнала по порядку: файлы дня (или всех дней), внутри файла – строки как записаны."""
    pattern = f"{day}.jsonl" if day else "????-??-??.jsonl"
    result: list[dict] = []
    if not folder.is_dir():
        return result
    for path in sorted(folder.glob(pattern)):
        with open(path, encoding="utf-8") as fh:
            for number, line in enumerate(fh, start=1):
                if not line.strip():
                    continue
                try:
                    event = json.loads(line)
                except ValueError as e:
                    error(f"{path.name}, строка {number}: не JSON ({e})")
                if isinstance(event, dict) and event.get("id"):
                    result.append(event)
    return result


def pairs(events: list[dict]) -> list[dict]:
    """События, сгруппированные по id: {request, response или error} по порядку событий request."""
    by_id: dict[str, dict] = {}
    for event in events:
        pair = by_id.setdefault(str(event["id"]), {})
        pair[event.get("event")] = event
    return [pair for _, pair in by_id.items() if "request" in pair]


def find(pairs_list: list[dict], wanted: str) -> dict:
    """Пара по id (полному или началу от 8 знаков); подходят несколько – ошибка с перечнем."""
    wanted = wanted.strip().casefold()
    found = [pair for pair in pairs_list if pair["request"]["id"].casefold().startswith(wanted)]
    if not found:
        error(f"id «{wanted}» в журнале нет")
    if len(found) > 1:
        ids = ", ".join(pair["request"]["id"][:8] for pair in found[:20])
        error(f"id «{wanted}» подходит нескольким обращениям ({ids}); укажите длиннее")
    return found[0]


def path_of(url: str) -> str:
    """Путь из полного адреса («http://127.0.0.1:11434/api/chat» -> «/api/chat»)."""
    from urllib.parse import urlsplit
    return urlsplit(url).path or "/"


def status_of(pair: dict) -> str:
    if "response" in pair:
        return str(pair["response"].get("status", ""))
    if "error" in pair:
        return "ошибка"
    return "–"


def duration_of(pair: dict) -> str:
    event = pair.get("response") or pair.get("error") or {}
    ms = event.get("duration_ms")
    return f"{ms} мс" if isinstance(ms, (int, float)) else "–"


def size_of(event: dict, key: str) -> str:
    length = event.get(key)
    return str(length) if isinstance(length, int) else "–"


def time_of(event: dict) -> str:
    return str(event.get("ts") or "")[:19]


def print_headers(headers: dict, indent: str = "") -> None:
    for name, value in (headers or {}).items():
        print(f"{indent}{name}: {value}")


def pretty_body(body: str, encoding: str | None) -> None:
    """Тело события: JSON с отступами, иначе как есть; пометка, что точные байты – в dump."""
    if encoding == "base64":
        print("(тело в base64: точные байты – командой dump)")
        print(body)
        return
    try:
        parsed = json.loads(body)
    except ValueError:
        print(body if body else "(тело пустое)")
        return
    print(json.dumps(parsed, ensure_ascii=False, indent=2))


def body_of(event: dict) -> tuple[str, str | None]:
    return str(event.get("body") or ""), event.get("body_encoding")


def request_headers(pair: dict) -> dict:
    """Заголовки запроса: разобранные из wire (событие response/error) или поля request_headers."""
    later = pair.get("response") or pair.get("error") or {}
    headers = later.get("request_headers")
    return headers if isinstance(headers, dict) else (pair["request"].get("headers") or {})


def cmd_list(args) -> None:
    events = events_in(args.dir, args.date)
    rows = pairs(events)
    if args.run is not None:
        rows = [p for p in rows if p["request"].get("run_id") == args.run]
    if args.hub:
        rows = [p for p in rows if str(p["request"].get("hub_id") or "") == args.hub]
    if args.purpose:
        rows = [p for p in rows if p["request"].get("purpose") == args.purpose]
    print("Время и дата файлов журнала – по UTC (не по местному времени).")
    print(f"{'время (UTC)':19} {'id':8} {'назнач.':9} {'прогон':6} {'находка':7} {'запрос':20} "
          f"{'статус':7} {'длит.':10} {'байт запр.':11} {'байт отв.':10}")
    for pair in rows:
        request = pair["request"]
        answer = pair.get("response") or pair.get("error") or {}
        print(f"{time_of(request):19} {request['id'][:8]:8} {str(request.get('purpose') or '–'):9} "
              f"{str(request.get('run_id') or '–'):6} {str(request.get('hub_id') or '–'):7} "
              f"{request.get('method', '') + ' ' + path_of(request.get('url', '')):20} "
              f"{status_of(pair):7} {duration_of(pair):10} {size_of(request, 'body_len'):11} "
              f"{size_of(answer, 'body_len' if answer.get('event') == 'response' else 'received_len'):10}")
    print(f"Обменов: {len(rows)}")


def cmd_show(args) -> None:
    pair = find(pairs(events_in(args.dir)), args.id)
    request = pair["request"]
    answer = pair.get("response")
    failure = pair.get("error")
    print(f"Обращение {request['id']}")
    print(f"  время: {time_of(request)} (UTC), назначение: {request.get('purpose')}, "
          f"прогон: {request.get('run_id')}, находка: {request.get('hub_id')}, проект: {request.get('project_id')}")
    peer = (answer or failure or {}).get("peer")
    if peer:
        print(f"  соединение: {peer}")
    print(f"  длительность: {duration_of(pair)}")
    print()
    print(f"ЗАПРОС {request.get('method')} {request.get('url')}")
    print_headers(request_headers(pair))
    body, encoding = body_of(request)
    if body or encoding:
        print()
        pretty_body(body, encoding)
    print()
    if failure:
        print(f"ОШИБКА: {failure.get('error_type')}: {failure.get('error')}")
        received = failure.get("received")
        print(f"Получено байт ответа до обрыва: {failure.get('received_len', 0)}")
        if received:
            print()
            pretty_body(received, failure.get("received_encoding"))
    elif answer:
        print(f"ОТВЕТ {answer.get('status')}")
        print_headers(answer.get("headers") or {})
        if answer.get("chunks") is not None:
            print(f"Потоковый ответ, кусков: {answer.get('chunks')}")
        print()
        pretty_body(*body_of(answer))
    else:
        print("Ответа нет: обращение не завершено.")
    print()
    print("Точные байты тела (или всего потока запроса) – "
          f"python scripts/model_traffic.py dump {request['id'][:8]} --part request|response --out ФАЙЛ")


def cmd_dump(args) -> None:
    pair = find(pairs(events_in(args.dir)), args.id)
    request = pair["request"]
    if args.part == "request":
        wire_event = pair.get("response") or pair.get("error") or {}
        wire = wire_event.get("request_wire")
        if wire is not None:
            data = decode(str(wire), wire_event.get("request_wire_encoding"))
        else:
            data = decode(str(request.get("body") or ""), request.get("body_encoding"))
    else:
        answer = pair.get("response")
        failure = pair.get("error")
        if answer is not None:
            data = decode(str(answer.get("body") or ""), answer.get("body_encoding"))
        elif failure is not None:
            received = failure.get("received")
            data = decode(str(received or ""), failure.get("received_encoding"))
        else:
            data = b""
    args.out.write_bytes(data)
    print(f"Записано байт: {len(data)} -> {args.out}")


def verify_events(events: list[dict]) -> list[str]:
    """Сверка sha256 и длин; возвращает перечень замечаний (пусто – всё сошлось)."""
    problems: list[str] = []
    for event in events:
        name = f"{event.get('event')} {str(event.get('id'))[:8]}"
        if event.get("event") in ("request", "response") and event.get("body") is not None:
            body = decode(str(event.get("body")), event.get("body_encoding"))
            if len(body) != event.get("body_len"):
                problems.append(f"{name}: длина тела {len(body)}, в журнале {event.get('body_len')}")
            if hashlib.sha256(body).hexdigest() != event.get("body_sha256"):
                problems.append(f"{name}: sha256 тела не совпадает")
        wire = event.get("request_wire")
        if wire is not None:
            data = decode(str(wire), event.get("request_wire_encoding"))
            if len(data) != event.get("request_wire_len"):
                problems.append(f"{name}: длина wire {len(data)}, в журнале {event.get('request_wire_len')}")
            if hashlib.sha256(data).hexdigest() != event.get("request_wire_sha256"):
                problems.append(f"{name}: sha256 wire не совпадает")
        received = event.get("received")
        if received is not None:
            data = decode(str(received), event.get("received_encoding"))
            if len(data) != event.get("received_len"):
                problems.append(f"{name}: длина полученных байт {len(data)}, в журнале {event.get('received_len')}")
            if hashlib.sha256(data).hexdigest() != event.get("received_sha256"):
                problems.append(f"{name}: sha256 полученных байт не совпадает")
    return problems


def cmd_verify(args) -> None:
    events = events_in(args.dir, args.date)
    problems = verify_events(events)
    checks = sum(1 for e in events
                 if e.get("body") is not None or e.get("request_wire") is not None or e.get("received") is not None)
    print(f"Проверок: {checks}, расхождений: {len(problems)}")
    for text in problems:
        print(f"  {text}")
    print(f"Совпало {checks - len(problems)} из {checks}." if checks else "Событий для сверки нет.")
    if problems:
        raise SystemExit(1)


def cmd_stats(args) -> None:
    table: dict[tuple[str, str], list[int]] = {}
    for pair in pairs(events_in(args.dir)):
        request = pair["request"]
        day = str(request.get("ts") or "")[:10]
        key = (day, str(request.get("purpose") or "–"))
        cells = table.setdefault(key, [0, 0, 0])
        cells[0] += 1
        cells[1] += int(request.get("body_len") or 0)
        answer = pair.get("response") or pair.get("error") or {}
        cells[2] += int(answer.get("body_len") if answer.get("event") == "response"
                        else answer.get("received_len") or 0)
    if not table:
        print("Журнал пуст.")
        return
    print(f"{'день':10} {'назнач.':9} {'обменов':8} {'запрос, байт':12} {'ответ, байт':11}")
    for (day, purpose), (count, sent, received) in sorted(table.items()):
        print(f"{day:10} {purpose:9} {count:8} {sent:12} {received:11}")
    total = [sum(cells[i] for cells in table.values()) for i in range(3)]
    print(f"{'итого':10} {'':9} {total[0]:8} {total[1]:12} {total[2]:11}")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Чтение журнала обмена приложения с моделью (data/model-traffic).")
    sub = parser.add_subparsers(dest="command", required=True)
    # --dir принимается после команды: python scripts/model_traffic.py list --dir ПАПКА
    folder_option = argparse.ArgumentParser(add_help=False)
    folder_option.add_argument("--dir", type=Path, default=DEFAULT_DIR,
                               help="папка журнала (по умолчанию data/model-traffic от корня репозитория)")

    p_list = sub.add_parser("list", parents=[folder_option], help="таблица обменов")
    p_list.add_argument("--date", metavar=DATE, help="один день журнала")
    p_list.add_argument("--run", type=int, help="только обращения этого прогона")
    p_list.add_argument("--hub", help="только обращения этой находки (ID из выгрузки)")
    p_list.add_argument("--purpose", help="назначение: triage, ask, models, status, reload, version, other")

    p_show = sub.add_parser("show", parents=[folder_option], help="запрос и ответ целиком")
    p_show.add_argument("id", help="id обращения (полный или первые 8 знаков)")

    p_dump = sub.add_parser("dump", parents=[folder_option], help="точные байты тела или всего потока запроса")
    p_dump.add_argument("id", help="id обращения (полный или первые 8 знаков)")
    p_dump.add_argument("--part", required=True, choices=("request", "response"), help="что выгрузить")
    p_dump.add_argument("--out", required=True, type=Path, help="файл, куда записать байты")

    p_verify = sub.add_parser("verify", parents=[folder_option], help="сверка sha256 и длин")
    p_verify.add_argument("--date", metavar=DATE, help="только один день журнала")

    sub.add_parser("stats", parents=[folder_option], help="обмены по дням и назначениям, объём")

    args = parser.parse_args(argv)
    if args.command == "list":
        cmd_list(args)
    elif args.command == "show":
        cmd_show(args)
    elif args.command == "dump":
        cmd_dump(args)
    elif args.command == "verify":
        cmd_verify(args)
    elif args.command == "stats":
        cmd_stats(args)


if __name__ == "__main__":
    main()
