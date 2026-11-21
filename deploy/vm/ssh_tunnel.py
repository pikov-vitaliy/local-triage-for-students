# -*- coding: utf-8 -*-
"""Команда на компьютере сборки через SSH-туннель к приложению в ВМ (порт приложения в ВМ – только 127.0.0.1).

  python ssh_tunnel.py <адрес ВМ> --known-hosts <файл> (--key <ключ> | --password-file <файл>)
      [--remote-port 8765] -- <команда> [аргументы]

Открывает на 127.0.0.1 компьютера свободный порт и пересылает его соединения на 127.0.0.1:<remote-port> внутри ВМ,
затем запускает команду; «{port}» в её аргументах заменяется номером локального порта. Код возврата – код команды.

Ключ SSH сервера сверяется строго: файл --known-hosts (строка «<имя> <тип> <ключ>», ключ получен через канал
гипервизора, а не по сети); другой ключ – соединение не открывается. Нужен paramiko.
"""
from __future__ import annotations

import argparse
import select
import socket
import socketserver
import subprocess
import sys
import threading

import paramiko
from paramiko.hostkeys import HostKeyEntry

USER = "triage"


def pinned_key(path: str) -> paramiko.PKey:
    lines = [x for x in open(path, encoding="utf-8").read().splitlines() if x.strip() and not x.startswith("#")]
    entry = HostKeyEntry.from_line(lines[0]) if lines else None
    if entry is None or entry.key is None:
        raise SystemExit(f"в {path} нет ключа SSH сервера")
    return entry.key


def connect(host: str, key: paramiko.PKey, key_file: str = "", password: str = "") -> paramiko.SSHClient:
    c = paramiko.SSHClient()
    c.get_host_keys().add(host, key.get_name(), key)
    c.set_missing_host_key_policy(paramiko.RejectPolicy())
    c.connect(host, username=USER, key_filename=key_file or None, password=password or None,
              look_for_keys=False, allow_agent=False, timeout=20, banner_timeout=30, auth_timeout=30)
    return c


def serve(transport: paramiko.Transport, remote_port: int) -> socketserver.ThreadingTCPServer:
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            try:
                chan = transport.open_channel("direct-tcpip", ("127.0.0.1", remote_port),
                                              self.request.getpeername())
            except Exception:
                return
            try:
                while True:
                    ready, _, _ = select.select([self.request, chan], [], [], 60)
                    if self.request in ready:
                        data = self.request.recv(65536)
                        if not data:
                            break
                        chan.sendall(data)
                    if chan in ready:
                        data = chan.recv(65536)
                        if not data:
                            break
                        self.request.sendall(data)
            except OSError:
                pass
            finally:
                chan.close()

    class Server(socketserver.ThreadingTCPServer):
        daemon_threads = True
        allow_reuse_address = True

    server = Server(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def main() -> int:
    argv = sys.argv[1:]
    if "--" not in argv:
        raise SystemExit("нужна команда после «--»")
    split = argv.index("--")
    p = argparse.ArgumentParser()
    p.add_argument("host")
    p.add_argument("--known-hosts", required=True)
    p.add_argument("--key", default="")
    p.add_argument("--password-file", default="")
    p.add_argument("--remote-port", type=int, default=8765)
    a = p.parse_args(argv[:split])
    command = argv[split + 1:]
    if not command or bool(a.key) == bool(a.password_file):
        raise SystemExit("нужны команда и ровно один способ входа: --key или --password-file")
    password = open(a.password_file, encoding="utf-8").read().strip() if a.password_file else ""
    client = connect(a.host, pinned_key(a.known_hosts), a.key, password)
    server = serve(client.get_transport(), a.remote_port)
    try:
        port = server.server_address[1]
        return subprocess.call([x.replace("{port}", str(port)) for x in command])
    finally:
        server.shutdown()
        client.close()


if __name__ == "__main__":
    socket.setdefaulttimeout(None)
    sys.exit(main())
