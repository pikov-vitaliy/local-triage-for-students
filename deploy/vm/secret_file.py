# -*- coding: utf-8 -*-
"""Файлы с секретами сборки (пароли учётной записи ВМ, ключ сборщика) – только для владельца.

write_secret – файл с секретом создаётся заново, сразу с правами только владельца, и только затем в него пишется
секрет. POSIX – os.open с O_EXCL и правами 0600 (umask права только сужает). Windows – CreateFileW с CREATE_NEW
и дескриптором безопасности «D:P(A;;FA;;;<SID текущего пользователя>)»: защищённый список разрешений с одной
записью, наследуемые права каталога к файлу не применяются; совместный доступ запрещён, пока файл открыт. Затем
restrict перечитывает список разрешений (ровно одна запись) и только после этого пишется секрет. Файл с прежними
правами не существует ни в какой момент, поэтому дескриптор другой обычной учётной записи, открытый до ограничения,
получить нельзя. Владельца и администратора компьютера (привилегия резервного копирования) это не ограничивает.
Файл с тем же именем уже есть – отказ (FileExistsError): существующий файл не удаляется и не перезаписывается.

Замена секрета – только явная и в два шага: prepare_secret создаёт новый файл рядом (той же функцией, с теми же
правами и проверкой) и записывает в него секрет, commit_secret атомарно подменяет им прежний (os.replace); до
подмены прежний файл не трогается. replace_secret – оба шага сразу; first_login.py готовит файл до смены пароля
на ВМ и подменяет после проверки, чтобы новый пароль не потерялся ни при каком отказе.

restrict – права файла или папки: POSIX – 600/700; Windows – наследование снято (icacls /inheritance:r), полный
доступ текущему пользователю (у папки – наследуемый, (OI)(CI)), явные разрешения всех остальных удалены
(/remove), затем список разрешений перечитывается: должна остаться ровно одна запись – текущего пользователя.
Иначе SystemExit (файл с секретом при этом удаляется).

  python secret_file.py restrict <путь>      (build.sh: папка secrets, пароль, ключ сборщика)
"""
from __future__ import annotations

import errno
import os
import re
import secrets
import subprocess
import sys

_ACE = re.compile(r"^(?P<who>[^\s(][^(]*?):\(")


def _user() -> str:
    return os.environ.get("USERNAME") or os.getlogin()


def _icacls(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["icacls", *args], capture_output=True, text=True, encoding="oem", errors="replace")


def acl_entries(path: str) -> list[str]:
    """Учётные записи в списке разрешений файла (Windows, icacls), по одной на запись."""
    out = _icacls(path)
    if out.returncode != 0:
        raise SystemExit(f"не удалось прочитать права {path}")
    entries = []
    for i, line in enumerate(out.stdout.splitlines()):
        text = line[len(path):] if i == 0 and line.startswith(path) else line
        found = _ACE.match(text.strip())
        if found:
            entries.append(found.group("who").strip())
    return entries


def _is_user(who: str, user: str) -> bool:
    return who.rsplit("\\", 1)[-1].casefold() == user.casefold()


def restrict(path: str) -> None:
    """Права только для владельца (см. описание модуля). Не вышло – SystemExit."""
    folder = os.path.isdir(path)
    os.chmod(path, 0o700 if folder else 0o600)
    if os.name != "nt":
        return
    user = _user()
    grant = f"{user}:(OI)(CI)F" if folder else f"{user}:F"
    if _icacls(path, "/inheritance:r", "/grant:r", grant).returncode != 0:
        raise SystemExit(f"не удалось ограничить права на {path}")
    for who in acl_entries(path):
        # учётная запись без имени показывается как SID: icacls принимает его со звёздочкой
        name = f"*{who}" if re.fullmatch(r"S-1-[0-9-]+", who) else who
        if not _is_user(who, user) and _icacls(path, "/remove", name).returncode != 0:
            raise SystemExit(f"не удалось убрать права «{who}» на {path}")
    left = acl_entries(path)
    if len(left) != 1 or not _is_user(left[0], user):
        raise SystemExit(f"на {path} остались права не только владельца: {', '.join(left)}")


def _user_sid() -> str:
    """SID текущего пользователя (Windows) строкой S-1-…: из маркера доступа процесса."""
    import ctypes
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi32.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
                                             ctypes.POINTER(wintypes.DWORD)]
    advapi32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), 0x0008, ctypes.byref(token)):  # TOKEN_QUERY
        raise SystemExit("не удалось прочитать маркер доступа процесса")
    try:
        size = wintypes.DWORD()
        advapi32.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))  # TokenUser: сначала размер
        buf = ctypes.create_string_buffer(size.value)
        if not advapi32.GetTokenInformation(token, 1, buf, size, ctypes.byref(size)):
            raise SystemExit("не удалось узнать учётную запись процесса")
        sid = ctypes.cast(buf, ctypes.POINTER(ctypes.c_void_p))[0]  # TOKEN_USER.User.Sid
        text = wintypes.LPWSTR()
        if not advapi32.ConvertSidToStringSidW(sid, ctypes.byref(text)):
            raise SystemExit("не удалось прочитать SID учётной записи")
        try:
            return str(text.value)
        finally:
            kernel32.LocalFree(text)
    finally:
        kernel32.CloseHandle(token)


def _create_owner_only(path: str) -> int:
    """Новый файл (его не должно быть) сразу с правами только владельца; дескриптор файла для записи."""
    if os.name != "nt":
        return os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    import ctypes
    import msvcrt
    from ctypes import wintypes

    class SecurityAttributes(ctypes.Structure):
        _fields_ = [("nLength", wintypes.DWORD), ("lpSecurityDescriptor", ctypes.c_void_p),
                    ("bInheritHandle", wintypes.BOOL)]

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
    kernel32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                     ctypes.POINTER(SecurityAttributes), wintypes.DWORD, wintypes.DWORD,
                                     wintypes.HANDLE]
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    # P – защищённый список: наследуемые разрешения каталога к файлу не применяются; FA – полный доступ владельцу
    sddl = f"D:P(A;;FA;;;{_user_sid()})"
    descriptor = ctypes.c_void_p()
    if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(descriptor), None):
        raise SystemExit(f"не удалось подготовить права для {path}")
    try:
        attrs = SecurityAttributes(ctypes.sizeof(SecurityAttributes), descriptor, False)
        # GENERIC_WRITE, без совместного доступа, CREATE_NEW (файл уже есть – отказ), FILE_ATTRIBUTE_NORMAL
        handle = kernel32.CreateFileW(path, 0x40000000, 0, ctypes.byref(attrs), 1, 0x80, None)
        if handle in (None, wintypes.HANDLE(-1).value):
            code = ctypes.get_last_error()
            if code in (80, 183):  # ERROR_FILE_EXISTS, ERROR_ALREADY_EXISTS – как O_EXCL на POSIX
                raise FileExistsError(errno.EEXIST, "файл уже существует", path)
            raise SystemExit(f"не удалось создать {path} (код {code})")
    finally:
        kernel32.LocalFree(descriptor)
    return msvcrt.open_osfhandle(handle, os.O_WRONLY)


def write_secret(path: str, text: str) -> None:
    """Новый файл с секретом (см. описание модуля). Файл с таким именем уже есть – FileExistsError, существующий
    файл не удаляется и не меняется: заменить секрет можно только явно (replace_secret или prepare_secret
    и commit_secret). Права не удалось проверить или запись не прошла – созданный файл удаляется."""
    fd = _create_owner_only(path)
    try:
        restrict(path)  # проверка прав до записи секрета: файл пока пустой, права – с момента создания
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fd = -1  # дескриптор теперь закрывает fh
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
    except BaseException:
        if fd >= 0:
            os.close(fd)
        os.remove(path)
        raise


def prepare_secret(path: str, text: str) -> str:
    """Первая половина замены секрета: новый файл рядом с path (та же папка, имя «<path>.new-<случайное>»), сразу
    с правами только владельца, проверенный и записанный (write_secret). Возвращает его путь; path не меняется.
    Дальше – commit_secret (подменить path) или discard_secret (отказаться)."""
    pending = f"{path}.new-{secrets.token_hex(6)}"
    write_secret(pending, text)
    try:
        _check_owner_only(pending)
    except BaseException:
        discard_secret(pending)
        raise
    return pending


def commit_secret(pending: str, path: str) -> None:
    """Вторая половина замены: подготовленный файл атомарно заменяет path (os.replace в той же папке; прежнего
    файла может и не быть). Права подготовленного файла переходят вместе с ним и проверяются ещё раз. Подмена
    не удалась – SystemExit, прежний path не тронут, подготовленный файл остаётся: в нём может быть единственная
    копия секрета (например, пароль уже сменён на ВМ)."""
    try:
        os.replace(pending, path)
    except OSError as e:
        raise SystemExit(f"не удалось заменить {path} ({type(e).__name__}); новый секрет остался в {pending}") from e
    _check_owner_only(path)


def discard_secret(pending: str) -> None:
    """Отказ от подготовленного файла (prepare_secret): он удаляется, прежний файл не меняется."""
    try:
        os.remove(pending)
    except FileNotFoundError:
        pass


def replace_secret(path: str, text: str) -> None:
    """Явная замена секрета: prepare_secret, затем commit_secret. Прежний файл остаётся нетронутым, пока новый
    не создан с правами владельца, не проверен и не записан; при любом отказе до подмены подготовленный файл
    удаляется, а прежний остаётся как был."""
    pending = prepare_secret(path, text)
    try:
        commit_secret(pending, path)
    except BaseException:
        if os.path.exists(pending):  # подмена не состоялась: секрет у вызывающего, прежний файл цел
            discard_secret(pending)
        raise


def _check_owner_only(path: str) -> None:
    """Проверка без изменений: у файла права только владельца (POSIX – нет прав группы и других; Windows – ровно
    одна запись в списке разрешений, текущего пользователя). Иначе SystemExit."""
    if os.name != "nt":
        if os.stat(path).st_mode & 0o077:
            raise SystemExit(f"у {path} есть права не только владельца")
        return
    left = acl_entries(path)
    if len(left) != 1 or not _is_user(left[0], _user()):
        raise SystemExit(f"на {path} есть права не только владельца: {', '.join(left)}")


def main() -> int:
    if len(sys.argv) != 3 or sys.argv[1] != "restrict":
        print("python secret_file.py restrict <путь>")
        return 2
    restrict(sys.argv[2])
    return 0


if __name__ == "__main__":
    sys.exit(main())
