"""LTA-005: ВМ – после отказа закрытия порта start.sh refresh повторяет восстановление.

Замечание аудита 15.10.2026 (реестр – docs/state/audit-2026-10-15.md): первый refresh находил, что ограничение источника
в DOCKER-USER не действует, записывал TRIAGE_BIND=127.0.0.1, но пересоздание контейнера не удавалось; второй refresh видел,
что .env уже не менялся, а контейнер работает, и возвращал 0, хотя старый контейнер продолжал публиковать порт на всех
адресах ВМ. Третья проверка добавила: отсутствие сценария или его исполняемого бита, публикация на «::», статус отказа
после восстановления. Проверка идёт на поддельных docker, ip, ss, iptables, curl, vmware-rpctool с состоянием (как в
tests/test_stage32_review.py); сеть настоящей ВМ не затрагивается, критерий приёмки «стенд ВМ» остаётся открытым.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from test_stage32_review import IPTABLES_FAKE, SS_FAKE, UFW_FAKE, VM, _git_bash, posix

# docker с состоянием: ps и inspect показывают работающий контейнер приложения и его публикацию (как в DOCKER_FAKE);
# compose up пересоздаёт его на адрес TRIAGE_BIND из .env, если не задано FAKE_COMPOSE_FAIL (отказ, состояние прежнее) или
# FAKE_COMPOSE_NOOP («успех» без перезапуска), FAKE_COMPOSE_FAIL_AFTER=N (пересоздание после N-го вызова не удаётся);
# compose stop останавливает контейнер; FAKE_PUBLISH_V6 добавляет к публичной публикации «::»; все вызовы compose пишутся
# в журнал.
DOCKER = r"""#!/bin/bash
[ -n "${FAKE_DOCKER_FAIL:-}" ] && exit 1
case "$1" in
  ps)
    [ -n "${FAKE_PS_FAIL_AFTER_STOP:-}" ] && [ -e "$FAKE_STATE/stopped" ] && exit 1
    [ -z "${FAKE_DOCKER_STOPPED:-}" ] && [ -s "$FAKE_STATE/publish" ] && echo c-app
    exit 0 ;;
  inspect)
    shift 3
    for id in "$@"; do
      case "$id" in
        c-app)
          [ -n "${FAKE_INSPECT_EMPTY:-}" ] && { echo "/local-triage"; continue; }
          a="$(cat "$FAKE_STATE/publish")"
          if [ "$a" = 0.0.0.0 ] && [ -n "${FAKE_PUBLISH_V6:-}" ]; then echo "/local-triage 0.0.0.0|8765 ::|8765"
          elif [ "$a" = :: ]; then echo "/local-triage ::|8765"
          elif [ "$a" = all ]; then echo "/local-triage |8765"
          else echo "/local-triage $a|8765"; fi ;;
        *) echo "Error: No such object: $id" >&2; exit 1 ;;
      esac
    done
    exit 0 ;;
  compose)
    echo "compose $*" >> "$FAKE_STATE/commands"
    case " $* " in
      *" stop "*) [ -n "${FAKE_STOP_NOOP:-}" ] && exit 0; : > "$FAKE_STATE/publish"; : > "$FAKE_STATE/listen"; : > "$FAKE_STATE/stopped"; exit 0 ;;
      *" up "*) ;;
      *) exit 0 ;;
    esac
    [ -n "${FAKE_COMPOSE_FAIL:-}" ] && exit 1
    if [ -n "${FAKE_COMPOSE_FAIL_FIRST:-}" ]; then
      n=$(cat "$FAKE_STATE/ups" 2>/dev/null || echo 0); n=$((n + 1)); echo "$n" > "$FAKE_STATE/ups"
      [ "$n" -eq 1 ] && exit 1
    fi
    if [ -n "${FAKE_COMPOSE_FAIL_AFTER:-}" ]; then
      n=$(cat "$FAKE_STATE/ups" 2>/dev/null || echo 0); n=$((n + 1)); echo "$n" > "$FAKE_STATE/ups"
      [ "$n" -gt "$FAKE_COMPOSE_FAIL_AFTER" ] && exit 1
    fi
    [ -n "${FAKE_COMPOSE_NOOP:-}" ] && exit 0
    bind=$(grep -E '^TRIAGE_BIND=' "$D/.env" | tail -n 1 | cut -d= -f2-)
    echo "$bind" > "$FAKE_STATE/publish"
    echo "$bind:8765" > "$FAKE_STATE/listen"
    exit 0 ;;
esac
exit 0
"""
IP = '#!/bin/bash\necho "2: ens33    inet 192.0.2.10/24 brd 192.0.2.255 scope global ens33"\n'
# канал гипервизора с состоянием: аргумент один, как его передаёт start.sh («info-set guestinfo.triage.<ключ> <значение>» или
# «info-get guestinfo.triage.<ключ>»); info-set записывает значение (и журнал), info-get возвращает его
RPC = r"""#!/bin/bash
mkdir -p "$FAKE_STATE/guestinfo"
read -r op key val <<< "$1"
name="${key#guestinfo.triage.}"
case "$op" in
  info-set) echo "rpc $1" >> "$FAKE_STATE/commands"; printf '%s' "$val" > "$FAKE_STATE/guestinfo/$name" ;;
  info-get) [ -f "$FAKE_STATE/guestinfo/$name" ] && cat "$FAKE_STATE/guestinfo/$name" ;;
esac
exit 0
"""
CURL = '#!/bin/bash\n[ -n "${FAKE_CURL_FAIL:-}" ] && exit 22\nexit 0\n'


@pytest.fixture
def vm(tmp_path: Path):
    bash = _git_bash()
    if bash is None:
        pytest.skip("нет Git Bash")
    tools, state, opt = tmp_path / "tools", tmp_path / "state", tmp_path / "opt"
    for d in (tools, state, opt, opt / "bin"):
        d.mkdir()
    fakes = {"docker": DOCKER, "ip": IP, "vmware-rpctool": RPC, "ss": SS_FAKE, "iptables": IPTABLES_FAKE,
             "ufw": UFW_FAKE, "curl": CURL}
    for name, body in fakes.items():
        (tools / name).write_text(body, encoding="utf-8", newline="\n")
    script = opt / "bin" / "network-access.sh"
    script.write_text((VM / "guest" / "network-access.sh").read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
    rules = tmp_path / "after.rules"
    rules.write_text("*filter\nCOMMIT\n", encoding="utf-8", newline="\n")
    (state / "commands").write_text("", encoding="utf-8")

    def setup(bind: str, publish: str, allow: str = "", hosts: str | None = None) -> None:
        text = f"TRIAGE_PORT=8765\nTRIAGE_BIND={bind}\nTRIAGE_ALLOW={allow}\n"
        hosts = hosts if hosts is not None else ("192.0.2.10,local-triage-demo" if bind != "127.0.0.1"
                                                  else "local-triage-demo")
        (opt / ".env").write_text(text + f"TRUSTED_HOSTS={hosts}\n", encoding="utf-8", newline="\n")
        (state / "publish").write_text(publish + "\n", encoding="utf-8", newline="\n")
        (state / "listen").write_text(f"{publish}:8765\n", encoding="utf-8", newline="\n")

    def guard(address: str) -> None:
        """Ограничение действует: правило DROP первым в DOCKER-USER для address."""
        (state / "docker-user").write_text(
            f"-A DOCKER-USER -i en+ -p tcp -m conntrack --ctorigdstport 8765 --ctdir ORIGINAL ! -s {address}/32 -j DROP\n",
            encoding="utf-8", newline="\n")

    path = os.pathsep.join([str(tools), os.environ["PATH"]])
    base = {**os.environ, "PATH": path, "D": posix(opt), "RULES": posix(rules), "FAKE_STATE": posix(state),
            "WAIT_S": "0", "CURL": posix(tools / "curl")}

    def refresh(**extra: str) -> subprocess.CompletedProcess:
        return subprocess.run([bash, posix(VM / "guest" / "start.sh"), "refresh"], env={**base, **extra},
                              capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60)

    def network(*args: str, **extra: str) -> subprocess.CompletedProcess:
        return subprocess.run([bash, posix(script), *args], env={**base, **extra}, capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=60)

    def env_value(key: str) -> str:
        return next((ln.split("=", 1)[1] for ln in (opt / ".env").read_text(encoding="utf-8").splitlines()
                     if ln.startswith(f"{key}=")), "")

    def commands() -> list[str]:
        return (state / "commands").read_text(encoding="utf-8").splitlines()

    def composes() -> int:
        return sum(1 for c in commands() if c.startswith("compose ") and " up " in c + " ")

    def guestinfo(key: str) -> str:
        f = state / "guestinfo" / key
        return f.read_text(encoding="utf-8") if f.exists() else ""

    def sets() -> int:
        return sum(1 for c in commands() if c.startswith("rpc info-set"))

    return {"setup": setup, "guard": guard, "refresh": refresh, "network": network, "env": env_value,
            "commands": commands, "composes": composes, "guestinfo": guestinfo, "sets": sets, "script": script,
            "publish": lambda: (state / "publish").read_text(encoding="utf-8").strip(), "state": state}


# ============================================================================ критерий 1: повтор после отказа

def test_audit_scenario_refresh_repeats_closing_after_compose_failure(vm):
    """Воспроизведение аудита: ранее открытый режим, ограничение пропало, пересоздание не удалось."""
    vm["setup"]("0.0.0.0", "0.0.0.0", allow="192.0.2.10")
    first = vm["refresh"](FAKE_COMPOSE_FAIL="1")
    assert first.returncode == 1 and vm["env"]("TRIAGE_BIND") == "127.0.0.1"
    assert vm["composes"]() == 1 and vm["publish"]() == "0.0.0.0", "старый контейнер всё ещё публикует порт"
    # раньше здесь возвращался 0 без попытки пересоздания
    second = vm["refresh"](FAKE_COMPOSE_FAIL="1")
    assert second.returncode == 1, "ложного успеха нет"
    assert vm["composes"]() == 2, "восстановление повторено"
    third = vm["refresh"]()
    assert third.returncode == 0, third.stdout + third.stderr
    assert vm["composes"]() == 3 and vm["publish"]() == "127.0.0.1"
    # теперь подтверждено: следующий проход ничего не перезапускает
    assert vm["refresh"]().returncode == 0 and vm["composes"]() == 3


def test_success_needs_the_confirmed_publication_even_when_compose_says_ok(vm):
    """compose «успешен», но порт по-прежнему на всех адресах (контейнер не пересоздан): отказ, повтор на следующем проходе."""
    vm["setup"]("0.0.0.0", "0.0.0.0", allow="192.0.2.10")
    r = vm["refresh"](FAKE_COMPOSE_NOOP="1")
    assert r.returncode == 1 and "не подтверждена" in r.stderr
    assert vm["guestinfo"]("status") == "bind-unconfirmed" and vm["guestinfo"]("bind") == "unconfirmed"
    again = vm["refresh"](FAKE_COMPOSE_NOOP="1")
    assert again.returncode == 1 and vm["composes"]() == 2
    assert vm["refresh"]().returncode == 0 and vm["publish"]() == "127.0.0.1"


# ============================================================================ критерий 2: неполная информация Docker

def test_docker_not_answering_never_gives_success(vm):
    vm["setup"]("127.0.0.1", "0.0.0.0")
    assert vm["refresh"](FAKE_DOCKER_FAIL="1").returncode == 1


def test_empty_publication_is_recreated_not_trusted(vm):
    vm["setup"]("127.0.0.1", "127.0.0.1")
    r = vm["refresh"](FAKE_INSPECT_EMPTY="1")
    assert vm["composes"]() == 1, "публикация не видна Docker: контейнер пересоздаётся"
    assert r.returncode == 1, "после пересоздания публикация по-прежнему не подтверждена"


def test_stopped_container_is_started_and_the_publication_confirmed(vm):
    vm["setup"]("127.0.0.1", "127.0.0.1")
    r = vm["refresh"](FAKE_DOCKER_STOPPED="1")
    assert vm["composes"]() == 1
    assert r.returncode == 1, "Docker по-прежнему не показывает работающий контейнер: публикация не подтверждена"


def test_foreign_container_on_the_port_is_not_a_confirmed_closing(vm):
    """Другой контейнер публикует тот же порт на всех адресах: network-access.sh local отказывает."""
    vm["setup"]("127.0.0.1", "127.0.0.1")
    tools = vm["state"].parent / "tools"
    docker = (tools / "docker").read_text(encoding="utf-8")
    docker = docker.replace("    [ -z \"${FAKE_DOCKER_STOPPED:-}\" ] && [ -s \"$FAKE_STATE/publish\" ] && echo c-app\n",
                            "    [ -s \"$FAKE_STATE/publish\" ] && echo c-app\n    echo c-other\n")
    docker = docker.replace("        *) echo \"Error: No such object: $id\" >&2; exit 1 ;;",
                            "        c-other) echo \"/other 0.0.0.0|8765\" ;;\n        *) echo \"Error: No such object: $id\" >&2; exit 1 ;;")
    (tools / "docker").write_text(docker, encoding="utf-8", newline="\n")
    r = vm["refresh"]()
    assert vm["composes"]() == 1 and r.returncode == 1


def test_closing_is_confirmed_by_docker_without_a_listening_socket(vm):
    """Без userland-proxy Docker публикует порт правилом DNAT, слушающего сокета на хосте нет: пустой список ss ничего не
    доказывает, закрытие подтверждает публикация по данным Docker."""
    vm["setup"]("127.0.0.1", "127.0.0.1")
    (vm["state"] / "listen").write_text("", encoding="utf-8")
    r = vm["refresh"]()
    assert r.returncode == 0 and vm["composes"]() == 0
    vm["setup"]("127.0.0.1", "0.0.0.0")
    (vm["state"] / "listen").write_text("", encoding="utf-8")
    r = vm["refresh"](FAKE_COMPOSE_NOOP="1")
    assert r.returncode == 1, "сокета нет, но Docker говорит: порт на всех адресах – закрытие не подтверждено"


# ============================================================================ критерий 4: рабочий режим не перезапускается

def test_working_loopback_mode_causes_no_restarts(vm):
    vm["setup"]("127.0.0.1", "127.0.0.1")
    for _ in range(3):
        assert vm["refresh"]().returncode == 0
    assert vm["composes"]() == 0 and vm["publish"]() == "127.0.0.1"


def test_working_public_mode_with_guard_causes_no_restarts(vm):
    vm["setup"]("0.0.0.0", "0.0.0.0", allow="192.0.2.10")
    vm["guard"]("192.0.2.10")
    for _ in range(3):
        assert vm["refresh"]().returncode == 0
    assert vm["composes"]() == 0 and vm["env"]("TRIAGE_BIND") == "0.0.0.0"
    assert vm["guestinfo"]("bind") == "public"


def test_public_mode_with_stale_loopback_container_is_recreated(vm):
    """Ограничение действует и порт должен быть на адресах ВМ, а контейнер опубликован на loopback: пересоздать."""
    vm["setup"]("0.0.0.0", "127.0.0.1", allow="192.0.2.10")
    vm["guard"]("192.0.2.10")
    r = vm["refresh"]()
    assert r.returncode == 0 and vm["composes"]() == 1 and vm["publish"]() == "0.0.0.0"


def test_address_change_still_recreates_the_container(vm):
    vm["setup"]("127.0.0.1", "127.0.0.1", hosts="old-name")
    assert vm["refresh"]().returncode == 0
    assert vm["composes"]() == 1 and vm["env"]("TRUSTED_HOSTS") == "local-triage-demo"


# ============================================================================ третья проверка (а): нет сценария или бита

def test_missing_script_never_gives_a_false_success(vm):
    """Сценария network-access.sh нет: ложного успеха нет, закрытие порта повторяется, подтверждает встроенная проверка Docker."""
    vm["setup"]("0.0.0.0", "0.0.0.0", allow="192.0.2.10")
    vm["script"].unlink()
    first = vm["refresh"](FAKE_COMPOSE_FAIL="1")
    assert first.returncode == 1 and vm["env"]("TRIAGE_BIND") == "127.0.0.1", "без сценария ограничения нет – loopback"
    second = vm["refresh"](FAKE_COMPOSE_FAIL="1")
    assert second.returncode == 1 and vm["composes"]() == 2, "повтор, а не ранний успех"
    assert vm["refresh"](FAKE_COMPOSE_NOOP="1").returncode == 1, "compose «успешен», публикация прежняя – не подтверждено"
    ok = vm["refresh"]()
    assert ok.returncode == 0 and vm["publish"]() == "127.0.0.1"
    steady = vm["composes"]()
    assert vm["refresh"]().returncode == 0 and vm["composes"]() == steady, "подтверждённый loopback без сценария не перезапускается"


def test_missing_script_with_unconfirmed_docker_is_a_failure(vm):
    vm["setup"]("127.0.0.1", "127.0.0.1")
    vm["script"].unlink()
    assert vm["refresh"](FAKE_DOCKER_FAIL="1").returncode == 1
    assert vm["refresh"](FAKE_INSPECT_EMPTY="1").returncode == 1


def test_script_without_the_executable_bit_still_checks(vm):
    """Исполняемого бита нет (файл читается, но не исполняется как программа): проверка запускается через bash и работает."""
    vm["setup"]("0.0.0.0", "0.0.0.0", allow="192.0.2.10")
    text = vm["script"].read_text(encoding="utf-8")
    vm["script"].write_text(text.split("\n", 1)[1], encoding="utf-8", newline="\n")  # без строки #!/bin/bash
    first = vm["refresh"](FAKE_COMPOSE_FAIL="1")
    assert first.returncode == 1
    second = vm["refresh"](FAKE_COMPOSE_FAIL="1")
    assert second.returncode == 1 and vm["composes"]() == 2
    assert vm["refresh"]().returncode == 0 and vm["publish"]() == "127.0.0.1"


# ============================================================================ третья проверка (б): IPv6

@pytest.mark.parametrize("publish", ["::", "all"])
def test_public_ipv6_or_all_addresses_publication_is_not_accepted(vm, publish):
    vm["setup"]("0.0.0.0", publish, allow="192.0.2.10")
    vm["guard"]("192.0.2.10")
    assert vm["network"]("public").returncode != 0, "ограничение проверяется только для IPv4"
    r = vm["refresh"](FAKE_COMPOSE_NOOP="1")
    assert r.returncode == 1


# ============================================================================ итоговая проверка: IPv6 не остаётся открытым

def test_unexpected_ipv6_publication_returns_the_port_to_loopback(vm):
    """Открытый режим, ограничение действует, но Docker публикует порт и на «::» (IPv6 никто не фильтрует): пересоздание на
    0.0.0.0 даёт тот же набор – порт возвращается на 127.0.0.1, закрытие проверяется по данным Docker."""
    vm["setup"]("0.0.0.0", "0.0.0.0", allow="192.0.2.10")
    vm["guard"]("192.0.2.10")
    r = vm["refresh"](FAKE_PUBLISH_V6="1")
    assert r.returncode == 1, "открытый режим не сохранён: проход отмечен отказом"
    assert vm["env"]("TRIAGE_BIND") == "127.0.0.1" and vm["env"]("TRUSTED_HOSTS") == "local-triage-demo"
    assert vm["publish"]() == "127.0.0.1", "закрытие проверено и состоялось: контейнер пересоздан на loopback"
    assert vm["composes"]() == 2 and (vm["guestinfo"]("status"), vm["guestinfo"]("bind")) == (
        "bind-reverted", "local-unsafe-publication")
    # следующий проход: подтверждённый loopback не перезапускается, статус возвращается в ok, причина остаётся видна
    again = vm["refresh"]()
    assert again.returncode == 0 and vm["composes"]() == 2
    assert (vm["guestinfo"]("status"), vm["guestinfo"]("bind")) == ("ok", "local-unsafe-publication")
    assert vm["env"]("TRIAGE_NET_NOTE") == "unsafe-publication"


SYSTEMCTL_FAKE = (
    '#!/bin/bash\n[ "$1" = restart ] || exit 0\n'
    "bind=$(grep -E '^TRIAGE_BIND=' \"$D/.env\" | tail -n 1 | cut -d= -f2-)\n"
    'echo "$bind" > "$FAKE_STATE/publish"\necho "$bind:8765" > "$FAKE_STATE/listen"\nexit 0\n')


def test_explicit_open_and_close_clear_the_note_about_the_withdrawn_mode(vm):
    vm["setup"]("127.0.0.1", "127.0.0.1")
    env = vm["state"].parent / "opt" / ".env"
    env.write_text(env.read_text(encoding="utf-8") + "TRIAGE_NET_NOTE=unsafe-publication\n", encoding="utf-8", newline="\n")
    tools = vm["state"].parent / "tools"
    (tools / "systemctl").write_text(SYSTEMCTL_FAKE, encoding="utf-8", newline="\n")
    tool_env = dict(SYSTEMCTL=posix(tools / "systemctl"), UFW=posix(tools / "ufw"), IPTABLES=posix(tools / "iptables"),
                    SS=posix(tools / "ss"), DOCKER=posix(tools / "docker"))
    # open в поддельной среде откатывается (нет правила в iptables), но пометку start.sh он уже снял: решает человек
    vm["network"]("open", "192.0.2.10", **tool_env)
    assert vm["env"]("TRIAGE_NET_NOTE") == ""
    env.write_text(env.read_text(encoding="utf-8") + "TRIAGE_NET_NOTE=unsafe-publication\n", encoding="utf-8", newline="\n")
    vm["network"]("close", **tool_env)
    assert vm["env"]("TRIAGE_NET_NOTE") == ""


def test_unconfirmable_recovery_stops_the_container_and_has_its_own_status(vm):
    """Вернуть порт на 127.0.0.1 не удалось (пересоздание не проходит): определённое безопасное поведение – контейнер
    приложения остановлен, порт не публикуется; отдельный статус; следующий проход восстанавливает loopback."""
    vm["setup"]("0.0.0.0", "0.0.0.0", allow="192.0.2.10")
    vm["guard"]("192.0.2.10")
    r = vm["refresh"](FAKE_PUBLISH_V6="1", FAKE_COMPOSE_FAIL_AFTER="1")
    assert r.returncode == 1
    assert vm["publish"]() == "", "контейнер остановлен: порт никому не открыт"
    assert any(c.startswith("compose ") and " stop " in c + " " for c in vm["commands"]())
    assert (vm["guestinfo"]("status"), vm["guestinfo"]("bind")) == ("stopped-bind-unconfirmed", "unconfirmed")
    assert vm["env"]("TRIAGE_BIND") == "127.0.0.1", "при следующем проходе порт поднимается только на loopback"
    ok = vm["refresh"]()
    assert ok.returncode == 0, ok.stdout + ok.stderr
    assert vm["publish"]() == "127.0.0.1"
    assert (vm["guestinfo"]("status"), vm["guestinfo"]("bind")) == ("ok", "local-unsafe-publication")


def test_unexpected_ipv6_publication_while_running_is_withdrawn_even_if_compose_is_a_noop(vm):
    """Сценарий проверки: refresh не может исправить публикацию (compose «успешен», ничего не меняя) – конфигурация не остаётся
    публичной: меняется .env, и пересоздание уже на loopback."""
    vm["setup"]("0.0.0.0", "all", allow="192.0.2.10")
    vm["guard"]("192.0.2.10")
    r = vm["refresh"]()
    # первое пересоздание на 0.0.0.0 даёт чистую публикацию 0.0.0.0 -> подтверждено, без отзыва
    assert r.returncode == 0 and vm["publish"]() == "0.0.0.0" and vm["env"]("TRIAGE_BIND") == "0.0.0.0"
    vm["setup"]("0.0.0.0", "::", allow="192.0.2.10")
    vm["guard"]("192.0.2.10")
    noop = vm["refresh"](FAKE_COMPOSE_NOOP="1")
    assert noop.returncode == 1 and vm["env"]("TRIAGE_BIND") == "127.0.0.1", "публичной конфигурация не осталась"
    assert vm["publish"]() == "", "ни одного способа вернуть loopback нет – контейнер остановлен, а не оставлен на IPv6"


def test_ipv4_only_publication_is_the_accepted_public_set(vm):
    vm["setup"]("0.0.0.0", "0.0.0.0", allow="192.0.2.10")
    assert vm["network"]("public").returncode == 0
    assert vm["network"]("public", FAKE_PUBLISH_V6="1").returncode != 0, "0.0.0.0 вместе с «::» – не тот набор"


def test_network_open_refuses_an_ipv6_publication(vm):
    """open: после перезапуска на всех адресах Docker показывает ещё и «::» – открытие откатывается на 127.0.0.1."""
    vm["setup"]("127.0.0.1", "127.0.0.1")
    for name in ("systemctl",):
        (vm["state"].parent / "tools" / name).write_text(
            '#!/bin/bash\n[ "$1" = restart ] || exit 0\nbind=$(grep -E \'^TRIAGE_BIND=\' "$D/.env" | tail -n 1 | cut -d= -f2-)\n'
            'echo "$bind" > "$FAKE_STATE/publish"\necho "$bind:8765" > "$FAKE_STATE/listen"\nexit 0\n',
            encoding="utf-8", newline="\n")
    tools = vm["state"].parent / "tools"
    r = vm["network"]("open", "192.0.2.10", SYSTEMCTL=posix(tools / "systemctl"), UFW=posix(tools / "ufw"),
                      IPTABLES=posix(tools / "iptables"), SS=posix(tools / "ss"), DOCKER=posix(tools / "docker"),
                      FAKE_PUBLISH_V6="1")
    assert r.returncode == 1 and vm["env"]("TRIAGE_BIND") == "127.0.0.1", r.stdout


# ============================================================================ третья проверка (в): статус после восстановления

def test_status_is_cleared_after_a_successful_recovery(vm):
    vm["setup"]("0.0.0.0", "0.0.0.0", allow="192.0.2.10")
    vm["refresh"](FAKE_COMPOSE_FAIL="1")
    assert (vm["guestinfo"]("status"), vm["guestinfo"]("bind")) == ("compose-failed", "unconfirmed")
    vm["refresh"](FAKE_COMPOSE_NOOP="1")
    assert (vm["guestinfo"]("status"), vm["guestinfo"]("bind")) == ("bind-unconfirmed", "unconfirmed")
    ok = vm["refresh"]()
    assert ok.returncode == 0
    assert (vm["guestinfo"]("status"), vm["guestinfo"]("bind")) == ("ok", "local"), "отказ не остаётся видимым"


def test_recovery_does_not_claim_a_healthy_app_when_it_does_not_answer(vm):
    """Сеть подтверждена, а приложение не отвечает: статус отказа не заменяется на ok."""
    vm["setup"]("0.0.0.0", "0.0.0.0", allow="192.0.2.10")
    vm["refresh"](FAKE_COMPOSE_FAIL="1")
    r = vm["refresh"](FAKE_CURL_FAIL="1")
    assert r.returncode == 1 and vm["guestinfo"]("status") == "app-not-responding"
    assert vm["guestinfo"]("bind") == "local", "состояние сети записано отдельно от здоровья приложения"
    assert vm["refresh"]().returncode == 0 and vm["guestinfo"]("status") == "ok"


def test_steady_state_does_not_rewrite_guestinfo_every_pass(vm):
    vm["setup"]("127.0.0.1", "127.0.0.1")
    assert vm["refresh"]().returncode == 0
    after_first = vm["sets"]()
    for _ in range(3):
        assert vm["refresh"]().returncode == 0
    assert vm["sets"]() == after_first, "в установившемся состоянии записей нет"
    assert vm["guestinfo"]("bind") == "local"


# ============================================================================ сценарий

def test_network_access_local_and_public_subcommands(vm):
    text = vm["script"].read_text(encoding="utf-8")
    assert "  local)" in text and "  public)" in text and "local_only" in text
    start = (VM / "guest" / "start.sh").read_text(encoding="utf-8")
    assert 'D="${D:-/opt/local-triage}"' in start and "bind_confirmed" in start
    assert "bind-unconfirmed" in start and "docker_local_only" in start and "settle_confirmed" in start


# ============================================================================ остатки LTA-005 (хвост В9, 25.10)

def test_compose_failure_in_open_mode_reverts_to_loopback(vm):
    """Отказ первого compose up в открытом режиме не оставляет открытый порт: режим отзывается (TRIAGE_BIND=127.0.0.1),
    контейнер пересоздаётся на loopback и проверяется."""
    vm["setup"]("0.0.0.0", "127.0.0.1", allow="192.0.2.10")  # .env – открытый режим, контейнер пока на loopback
    vm["guard"]("192.0.2.10")
    r = vm["refresh"](FAKE_COMPOSE_FAIL_FIRST="1")  # первое пересоздание (в открытый режим) не удаётся, второе – да
    assert r.returncode == 1, r.stdout + r.stderr
    assert vm["env"]("TRIAGE_BIND") == "127.0.0.1" and vm["env"]("TRIAGE_NET_NOTE") == "unsafe-publication"
    assert vm["guestinfo"]("status") == "bind-reverted" and vm["guestinfo"]("bind") == "local-unsafe-publication"
    assert vm["publish"]() == "127.0.0.1" and vm["composes"]() == 2


def test_failed_stop_after_unconfirmed_loopback_is_reported(vm):
    """Результат compose stop проверяется: если контейнер не остановился и порт всё ещё опубликован – статус об этом
    (stop-failed), а не «остановлен»."""
    vm["setup"]("0.0.0.0", "0.0.0.0", allow="192.0.2.10")
    vm["guard"]("192.0.2.10")
    r = vm["refresh"](FAKE_PUBLISH_V6="1", FAKE_COMPOSE_NOOP="1", FAKE_STOP_NOOP="1")
    assert r.returncode == 1
    assert vm["env"]("TRIAGE_BIND") == "127.0.0.1"
    assert vm["guestinfo"]("status") == "stop-failed" and vm["guestinfo"]("bind") == "unconfirmed"
    assert vm["publish"]() == "0.0.0.0", "порт действительно не закрыт – об этом и сказано"


def test_failed_docker_check_after_stop_is_not_a_confirmed_stop(vm):
    """compose stop прошёл, но «docker ps» завершился ошибкой без вывода: остановка не подтверждена – stop-failed,
    а не stopped-bind-unconfirmed (пустой вывод при ошибке – не доказательство)."""
    vm["setup"]("0.0.0.0", "0.0.0.0", allow="192.0.2.10")
    vm["guard"]("192.0.2.10")
    r = vm["refresh"](FAKE_PUBLISH_V6="1", FAKE_COMPOSE_NOOP="1", FAKE_PS_FAIL_AFTER_STOP="1")
    assert r.returncode == 1
    assert vm["guestinfo"]("status") == "stop-failed" and vm["guestinfo"]("bind") == "unconfirmed"


def test_stop_failed_is_cleared_after_a_confirmed_recovery(vm):
    """После stop-failed следующий проход, пересоздавший контейнер на loopback и получивший ответ приложения,
    возвращает статус ok; без ответа приложения – app-not-responding."""
    vm["setup"]("0.0.0.0", "0.0.0.0", allow="192.0.2.10")
    vm["guard"]("192.0.2.10")
    assert vm["refresh"](FAKE_PUBLISH_V6="1", FAKE_COMPOSE_NOOP="1", FAKE_STOP_NOOP="1").returncode == 1
    assert vm["guestinfo"]("status") == "stop-failed"
    r = vm["refresh"](FAKE_CURL_FAIL="1")
    assert r.returncode == 1 and vm["guestinfo"]("status") == "app-not-responding"
    assert vm["refresh"]().returncode == 0 and vm["guestinfo"]("status") == "ok"
    assert vm["env"]("TRIAGE_BIND") == "127.0.0.1" and vm["publish"]() == "127.0.0.1"
