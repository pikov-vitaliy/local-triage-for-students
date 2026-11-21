#!/bin/bash
# Доступ к приложению по сети с одного адреса – только после того, как ограничение источника установлено
# и проверено; при любом отказе приложение возвращается на 127.0.0.1 ВМ (доступ – SSH-туннель).
#
#   sudo /opt/local-triage/bin/network-access.sh open <IPv4 пользователя>
#   sudo /opt/local-triage/bin/network-access.sh close
#   sudo /opt/local-triage/bin/network-access.sh status
#   /opt/local-triage/bin/network-access.sh check    (start.sh при загрузке: 0 – ограничение действует)
#   /opt/local-triage/bin/network-access.sh local    (start.sh: 0 – Docker подтверждает, что приложение только на 127.0.0.1)
#   /opt/local-triage/bin/network-access.sh public   (start.sh: 0 – Docker подтверждает публикацию порта на всех адресах)
#
# open:
#   1. приложение – на 127.0.0.1 (сначала закрыть, потом открывать), и это подтверждено и Docker (публикация порта
#      работающим контейнером), и списком слушающих портов;
#   2. правило в /etc/ufw/after.rules между отметками (замена, а не дописывание): первым правилом цепочки DOCKER-USER
#      отбрасываются соединения к порту приложения не с адреса пользователя; SSH – только с этого адреса; ufw
#      включается; адрес пользователя – в .env (TRIAGE_ALLOW);
#   3. проверка достижимости: правило DROP с «! -s <адрес>/32» для порта приложения – ПЕРВОЕ в DOCKER-USER (перед
#      ним нет RETURN или ACCEPT, которые пропустили бы соединение), а переход в DOCKER-USER – ПЕРВОЕ правило FORWARD;
#   4. только затем порт публикуется на всех адресах ВМ (TRIAGE_BIND=0.0.0.0), приложение перезапускается,
#      и проверка повторяется вместе с публикацией порта на всех адресах по данным Docker.
# Любой сбой, в том числе непредвиденная ошибка команды, – TRIAGE_BIND=127.0.0.1, перезапуск, проверка, что порт
# опубликован и слушается только на 127.0.0.1, код возврата 1. Правило ограничения при отказе НЕ снимается: если вернуть
# приложение на 127.0.0.1 не удалось, ограничение остаётся действовать.
# close: правило снимается только после подтверждённого перехода приложения на 127.0.0.1 (перезапуск удался, Docker
# показывает публикацию порта работающим контейнером приложения только на 127.0.0.1 и порт не слушается на адресах
# ВМ); иначе правило остаётся, код возврата 1.
# Почему не только ss: без userland-proxy Docker публикует порт правилом DNAT, и слушающего сокета на хосте нет –
# пустой список ss ничего не доказывает. Публикацию знает Docker; Docker не ответил или ответ неполный – отказ.
# Правила ufw не учитывают порты, которые публикует Docker, поэтому ограничение – в DOCKER-USER (docs/vm-image.md,
# «Доступ к приложению»). Каталоги и команды можно подменить переменными окружения (D, RULES, UFW, IPTABLES,
# SYSTEMCTL, SS, DOCKER, APP, WAIT_S) – для проверки.
set -uo pipefail

D="${D:-/opt/local-triage}"
RULES="${RULES:-/etc/ufw/after.rules}"
UFW="${UFW:-ufw}"
IPTABLES="${IPTABLES:-iptables}"
SYSTEMCTL="${SYSTEMCTL:-systemctl}"
SS="${SS:-ss}"
DOCKER="${DOCKER:-docker}"
APP="${APP:-local-triage}"
BEGIN="# local-triage: begin"
END="# local-triage: end"

say() { echo "network-access: $*"; }
env_get() { grep -E "^$1=" "$D/.env" 2>/dev/null | tail -n 1 | cut -d= -f2-; }
# запись в .env с проверкой: значение перечитывается
env_set() {
  if grep -qE "^$1=" "$D/.env"; then
    sed -i "s|^$1=.*|$1=$2|" "$D/.env" || return 1
  else
    printf '%s=%s\n' "$1" "$2" >> "$D/.env" || return 1
  fi
  [ "$(env_get "$1")" = "$2" ]
}
PORT="$(env_get TRIAGE_PORT)"; PORT="${PORT:-8765}"

restart() { "$SYSTEMCTL" restart local-triage; }
settle() { sleep "${WAIT_S:-5}"; }
# адреса, на которых слушается порт приложения (столбец «Local Address:Port» ss -ltn)
listeners() {
  local out
  out="$("$SS" -ltn 2>/dev/null)" || return 1
  printf '%s\n' "$out" | awk -v p=":$PORT" 'length($4) > length(p) && substr($4, length($4) - length(p) + 1) == p { print $4 }'
}
# Публикации порта приложения работающими контейнерами по данным Docker: строки «<контейнер> <адрес>» (адрес –
# HostIp; пустой – все адреса). Ошибка docker ps или docker inspect (в том числе контейнер исчез между ними) – код 1.
published() {
  local ids out
  ids="$("$DOCKER" ps -q 2>/dev/null)" || return 1
  [ -n "$ids" ] || return 0
  # shellcheck disable=SC2086  # идентификаторы контейнеров – по одному слову
  out="$("$DOCKER" inspect -f '{{.Name}}{{range $p, $b := .NetworkSettings.Ports}}{{range $b}} {{.HostIp}}|{{.HostPort}}{{end}}{{end}}' $ids 2>/dev/null)" \
    || return 1
  printf '%s\n' "$out" | awk -v p="$PORT" '{ n = $1; sub(/^\//, "", n); for (i = 2; i <= NF; i++) { k = index($i, "|"); if (k && substr($i, k + 1) == p) print n " " substr($i, 1, k - 1) } }'
}
# Приложение подтверждённо только на 127.0.0.1: Docker ответил, контейнер приложения работает и публикует порт
# на 127.0.0.1 (или ::1), ни один работающий контейнер не публикует порт на другом адресе, и на адресах ВМ порт
# не слушается. Контейнер не работает, Docker не ответил, публикации нет – не подтверждено (неоднозначно – отказ).
local_only() {
  local pub list
  pub="$(published)" || return 1
  printf '%s\n' "$pub" | grep -qxE "$APP (127\.0\.0\.1|::1)" || return 1
  if printf '%s\n' "$pub" | grep -v '^$' | grep -vxE "[^ ]+ (127\.0\.0\.1|::1)" | grep -q .; then return 1; fi
  list="$(listeners)" || return 1
  ! printf '%s\n' "$list" | grep -vxE "(127\.0\.0\.1|\[::1\]):$PORT" | grep -q .
}
# Порт приложения опубликован на адресах ВМ – по данным Docker (без userland-proxy сокета может не быть). Допустим ровно
# один набор: публикация на 0.0.0.0 (так её создаёт TRIAGE_BIND=0.0.0.0 в compose). Публикация на «::» или с пустым
# адресом (все адреса, в том числе IPv6) не принимается: ограничение источника в DOCKER-USER проверяется только для IPv4
# (iptables), фильтрацию IPv6 никто не устанавливает и не проверяет.
public_listen() {
  local pub mine
  pub="$(published)" || return 1
  mine="$(printf '%s\n' "$pub" | grep -E "^$APP " | sort -u)"
  [ "$mine" = "$APP 0.0.0.0" ]
}
# Ограничение действует для адреса $1: ПЕРВОЕ правило DOCKER-USER – DROP соединений к порту приложения не с $1/32,
# и ПЕРВОЕ правило FORWARD – переход в DOCKER-USER. Правило дальше по цепочке не доказывает ничего: RETURN или
# ACCEPT перед ним пропустили бы соединение.
guard_ok() {
  local out first
  [ -n "${1:-}" ] || return 1
  out="$("$IPTABLES" -S DOCKER-USER 2>/dev/null)" || return 1
  first="$(printf '%s\n' "$out" | awk '/^-A DOCKER-USER / { if (!n++) print }')"
  [[ " $first " == *" --ctorigdstport $PORT "* && " $first " == *" ! -s $1/32 "* && " $first " == *" -j DROP " ]] \
    || return 1
  out="$("$IPTABLES" -S FORWARD 2>/dev/null)" || return 1
  first="$(printf '%s\n' "$out" | awk '/^-A FORWARD / { if (!n++) print }')"
  [ "$first" = "-A FORWARD -j DOCKER-USER" ]
}
valid_ipv4() {
  [[ "$1" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
  local n
  for n in "${BASH_REMATCH[@]:1}"; do [ "$n" -le 255 ] || return 1; done
  [[ "$1" != 0.* && "$1" != 127.* && "$1" != 255.255.255.255 ]]
}
write_rules() {
  local tmp
  tmp="$(mktemp)" || return 1
  # прежний блок – убрать, новый – дописать в конец (замена, а не повтор); правило – первым в DOCKER-USER
  if ! awk -v b="$BEGIN" -v e="$END" '$0 == b { skip = 1; next } $0 == e { skip = 0; next } !skip' "$RULES" > "$tmp"; then
    rm -f "$tmp"; return 1
  fi
  if [ -n "${1:-}" ]; then
    cat >> "$tmp" <<EOF
$BEGIN
*filter
:DOCKER-USER - [0:0]
-I DOCKER-USER 1 -i en+ -p tcp -m conntrack --ctorigdstport $PORT --ctdir ORIGINAL ! -s $1 -j DROP
COMMIT
$END
EOF
  fi
  if ! cat "$tmp" > "$RULES"; then rm -f "$tmp"; return 1; fi
  rm -f "$tmp"
}
# Отказ: приложение – на 127.0.0.1, правило ограничения не трогается. Код возврата 1.
fail() {
  trap - ERR INT TERM HUP
  say "ОТКАЗ: $*"
  env_set TRIAGE_BIND 127.0.0.1 || say "не удалось записать TRIAGE_BIND=127.0.0.1 в $D/.env"
  if restart && settle && local_only; then
    say "приложение – только на 127.0.0.1 ВМ, доступ – SSH-туннель"
  else
    say "ВНИМАНИЕ: не подтверждено, что приложение перешло на 127.0.0.1 ВМ; ограничение источника в DOCKER-USER" \
        "оставлено. Проверьте: systemctl status local-triage, docker port $APP, ss -ltn"
  fi
  exit 1
}

case "${1:-}" in
  open)
    addr="${2:-}"
    valid_ipv4 "$addr" || { say "укажите IPv4 компьютера пользователя: open <адрес>"; exit 2; }
    [ -f "$D/.env" ] || { say "нет $D/.env"; exit 1; }
    trap 'fail "непредвиденная ошибка (строка $LINENO)"' ERR
    trap 'fail "прервано"' INT TERM HUP
    env_set TRIAGE_NET_NOTE "" || fail "не удалось очистить TRIAGE_NET_NOTE"  # пометка start.sh об отозванном режиме
    env_set TRIAGE_BIND 127.0.0.1 || fail "не удалось записать TRIAGE_BIND=127.0.0.1"
    restart || fail "приложение не перезапустилось на 127.0.0.1"
    settle
    local_only || fail "не подтверждено, что порт $PORT опубликован и слушается только на 127.0.0.1"
    write_rules "$addr" || fail "не удалось записать $RULES"
    "$UFW" allow from "$addr" to any port 22 proto tcp >/dev/null || fail "ufw не принял правило для SSH"
    "$UFW" --force enable >/dev/null || fail "ufw не включился"
    "$UFW" reload >/dev/null || fail "ufw reload завершился ошибкой"
    guard_ok "$addr" || fail "правило в DOCKER-USER не установлено или стоит не первым (перед ним RETURN или" \
                             "ACCEPT; переход в DOCKER-USER не первый в FORWARD)"
    env_set TRIAGE_ALLOW "$addr" || fail "не удалось записать TRIAGE_ALLOW"
    env_set TRIAGE_BIND 0.0.0.0 || fail "не удалось записать TRIAGE_BIND=0.0.0.0"
    restart || fail "приложение не перезапустилось"
    settle
    guard_ok "$addr" || fail "после перезапуска ограничение в DOCKER-USER не действует"
    public_listen || fail "Docker не подтвердил публикацию порта $PORT на адресах ВМ"
    trap - ERR INT TERM HUP
    say "порт $PORT открыт только для $addr; проверьте с другого компьютера: соединение не должно устанавливаться"
    ;;
  close)
    [ -f "$D/.env" ] || { say "нет $D/.env"; exit 1; }
    keep="правило ограничения источника оставлено в $RULES и в DOCKER-USER"
    env_set TRIAGE_NET_NOTE "" || say "не удалось очистить TRIAGE_NET_NOTE в $D/.env"
    env_set TRIAGE_BIND 127.0.0.1 || { say "ОТКАЗ: не удалось записать TRIAGE_BIND=127.0.0.1; $keep"; exit 1; }
    if ! restart; then
      say "ОТКАЗ: приложение не перезапустилось – прежний контейнер может слушать адреса ВМ; $keep."
      say "Проверьте: systemctl status local-triage, docker port $APP, ss -ltn; затем повторите close"
      exit 1
    fi
    settle
    if ! local_only; then
      say "ОТКАЗ: не подтверждено, что порт $PORT опубликован и слушается только на 127.0.0.1; $keep." \
          "Проверьте: docker port $APP, ss -ltn"
      exit 1
    fi
    if ! write_rules ""; then say "ОТКАЗ: правило из $RULES убрать не удалось – проверьте файл"; exit 1; fi
    "$UFW" reload >/dev/null || { say "ОТКАЗ: ufw reload завершился ошибкой – проверьте ufw status"; exit 1; }
    env_set TRIAGE_ALLOW "" || say "не удалось очистить TRIAGE_ALLOW в $D/.env"
    say "приложение – только на 127.0.0.1 ВМ, доступ – SSH-туннель"
    ;;
  check)
    guard_ok "$(env_get TRIAGE_ALLOW)"
    ;;
  local)
    # start.sh refresh: что записано в .env, не доказывает, что запущено; доказывает публикация порта по данным Docker
    local_only
    ;;
  public)
    public_listen
    ;;
  status)
    say "TRIAGE_BIND=$(env_get TRIAGE_BIND) TRIAGE_ALLOW=$(env_get TRIAGE_ALLOW)"
    if guard_ok "$(env_get TRIAGE_ALLOW)"; then say "ограничение действует"; else say "ограничение не действует"; fi
    "$IPTABLES" -S DOCKER-USER 2>/dev/null | grep -- "--ctorigdstport $PORT" || say "правила для порта $PORT в DOCKER-USER нет"
    if pub="$(published)"; then
      if [ -n "$pub" ]; then printf '%s\n' "$pub" | sed 's/^/network-access: публикация Docker: /'
      else say "Docker: порт $PORT не опубликован"; fi
    else
      say "Docker не ответил"
    fi
    "$SS" -ltn 2>/dev/null | grep -E ":$PORT\b" || say "порт $PORT не слушается"
    ;;
  *)
    sed -n '2,8p' "$0"; exit 2 ;;
esac
