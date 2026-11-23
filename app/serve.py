"""Запуск приложения учебным стендом npm (ADR-0155): uvicorn с параметрами образа и остановка по закрытию stdin.

Обёртка npm на Windows не может послать процессу Python сигнал остановки: kill() из Node завершает процесс, не дав
выполниться ни одной строке, и lifespan не закрыл бы базу и не отпустил бы замок папки данных. Поэтому канал
остановки – stdin: держатель стенда закрывает его, и сервер останавливается штатно, как по Ctrl+C.

    python -E -s -X utf8 -m app.serve --host 127.0.0.1 --port 8765

Параметры сервера – как у CMD в Dockerfile: фабрика app.main:create_app, без заголовка Server и журнала запросов,
3 секунды на закрытие потоков событий. Порт uvicorn занимает сам, как в образе: на Windows без SO_REUSEADDR, поэтому
порт, который уже слушает другая программа, не перехватывается. Коды выхода: 0 – штатная остановка; 75 – замок папки
данных держит другой экземпляр со свежей отметкой (LockBusy; после аварии отметка прежнего процесса ещё свежая –
держатель повторит запуск, когда она устареет); 76 – приложение запустилось, а порт занят (держатель возьмёт
следующий); 1 – прочие ошибки запуска. uvicorn завершает неудавшийся запуск через sys.exit(3): код уточняется здесь.
"""

from __future__ import annotations

import argparse
import sys
import threading

from app import i18n

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_LOCK_BUSY = 75
EXIT_PORT_BUSY = 76


def watch_stdin(server, stream=None) -> None:
    """Читает stdin до конца и просит сервер остановиться: держатель закрыл канал или сам завершился."""
    stream = stream if stream is not None else sys.stdin
    try:
        source = getattr(stream, "buffer", stream)
        while source.read(65536):
            pass
    except (OSError, ValueError):
        pass
    server.should_exit = True


def build_server(host: str, port: int):
    import uvicorn
    config = uvicorn.Config("app.main:create_app", factory=True, host=host, port=port, server_header=False,
                            access_log=False, timeout_graceful_shutdown=3)
    return uvicorn.Server(config)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.serve", description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--host", default="127.0.0.1", choices=["127.0.0.1"],
                        help=i18n._("адрес прослушивания: только 127.0.0.1 – защита проверяет заголовок Host, а не "
                                    "адрес клиента"))
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args(argv)
    server = build_server(args.host, args.port)
    threading.Thread(target=watch_stdin, args=(server,), name="stdin-stop", daemon=True).start()
    failed = False
    try:
        server.run()
    except SystemExit:  # uvicorn: запуск не удался (sys.exit(3) после неудачного lifespan или занятого порта)
        failed = True
    from app.main import STARTUP_COMPLETE, STARTUP_LOCK_BUSY
    if STARTUP_LOCK_BUSY.is_set():
        return EXIT_LOCK_BUSY
    if failed or not server.started:
        return EXIT_PORT_BUSY if STARTUP_COMPLETE.is_set() and not server.started else EXIT_FAILED
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
