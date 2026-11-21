# -*- coding: utf-8 -*-
"""Первый вход на копию ВМ из OVA: система должна потребовать сменить пароль.

python first_login.py <адрес> <файл с исходным паролем> <файл с ключом SSH копии> [--change <файл для нового пароля>]

Без --change пароль не меняется: вход доходит до требования смены пароля и прерывается. С --change пароль
меняется на случайный, затем повторный вход и sudo; новый пароль записывается в указанный файл (в журнал
и на экран он не попадает), печатается только machine-id. Файл готовится до смены пароля и заменяет прежний
только после проверки входа и sudo; если после отправки нового пароля что-то не прошло, подготовленный файл
остаётся, и его путь печатается в поток ошибок.
Ключ SSH сервера закреплён: файл ключа – строка «<имя> <тип> <ключ>», полученная через канал гипервизора
(guestinfo ВМ), а не по сети; если копия предъявит другой ключ, вход прервётся. Код возврата 0 – всё прошло.
Нужен paramiko.
"""
import re
import secrets
import string
import sys
import time

import paramiko
from paramiko.hostkeys import HostKeyEntry

# рядом в deploy/vm: файл нового пароля – только для владельца, замена прежнего – явная и атомарная
from secret_file import commit_secret, discard_secret, prepare_secret

host, passfile, keyfile = sys.argv[1], sys.argv[2], sys.argv[3]
rest = sys.argv[4:]
change = "--change" in rest
newfile = rest[rest.index("--change") + 1] if change and len(rest) > rest.index("--change") + 1 else ""
if change and not newfile:
    raise SystemExit("после --change нужен файл для нового пароля")
USER = "triage"
old = open(passfile, encoding="utf-8").read().strip()

lines = [x for x in open(keyfile, encoding="utf-8").read().splitlines() if x.strip() and not x.startswith("#")]
entry = HostKeyEntry.from_line(lines[0]) if lines else None
if entry is None or entry.key is None:
    raise SystemExit(f"в {keyfile} нет ключа SSH сервера")
pinned = entry.key


def connect(password):
    c = paramiko.SSHClient()
    c.get_host_keys().add(host, pinned.get_name(), pinned)
    c.set_missing_host_key_policy(paramiko.RejectPolicy())
    c.connect(host, username=USER, password=password, look_for_keys=False, allow_agent=False, timeout=20,
              banner_timeout=30, auth_timeout=30)
    return c


def read_until(chan, pattern, timeout=30):
    buf, end = "", time.time() + timeout
    while time.time() < end:
        if chan.recv_ready():
            buf += chan.recv(4096).decode("utf-8", "replace")
            if re.search(pattern, buf):
                return buf
        elif chan.exit_status_ready() or chan.closed:
            break
        else:
            time.sleep(0.2)
    raise SystemExit(f"не дождались «{pattern}»; вывод: {buf[-400:]!r}")


c = connect(old)
ch = c.invoke_shell()
out = read_until(ch, r"(?i)current password:|\(current\)")
if not re.search(r"(?i)expired|change your password", out):
    raise SystemExit("система не потребовала сменить пароль при первом входе")
if not change:
    c.close()
    print("password-change-required=yes")
    sys.exit(0)

new = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(20))
# Новый пароль – на диск до смены на ВМ: файл рядом с newfile, права только владельца. Прежний newfile (пароль
# копии прошлой проверки) не трогается до подмены. Отказ до отправки нового пароля – файл удаляется; после –
# остаётся: пароль на ВМ мог уже смениться, и это единственная его копия.
pending = prepare_secret(newfile, new + "\n")
sent = False
try:
    ch.send((old + "\n").encode())
    read_until(ch, r"(?i)new password:")
    sent = True
    ch.send((new + "\n").encode())
    read_until(ch, r"(?i)retype new password:")
    ch.send((new + "\n").encode())
    read_until(ch, r"(?i)updated successfully")
    c.close()

    c = connect(new)
    stdin, stdout, stderr = c.exec_command("sudo -S -p '' -v && cat /etc/machine-id", timeout=30)
    stdin.write(new + "\n")
    stdin.flush()
    mid = stdout.read().decode().strip()
    rc = stdout.channel.recv_exit_status()
    c.close()
    if rc != 0 or not re.fullmatch(r"[0-9a-f]{32}", mid):
        raise SystemExit(f"sudo или machine-id: код {rc}, вывод {mid!r}")
except BaseException:
    if sent:
        print(f"пароль на ВМ мог уже смениться: новый пароль сохранён в {pending}", file=sys.stderr)
    else:
        discard_secret(pending)
    raise
commit_secret(pending, newfile)  # не удалось – файл с новым паролем остаётся, его путь – в сообщении
print(f"machine-id={mid}")
print("password-changed=yes")
