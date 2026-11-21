#!/bin/bash
# Запуск «Локального триажа» в демо-ВМ.
#   start.sh boot     – при каждой загрузке (local-triage.service): на первой загрузке – образы контейнеров
#                       из /opt/local-triage/images и случайный пароль базы в .env; затем база: поднять, дождаться,
#                       пустую восстановить из data/demo.dump, непустую не трогать; адрес ВМ в TRUSTED_HOSTS,
#                       контейнеры, проверка ответа, прогрев модели;
#   start.sh refresh  – раз в две минуты (local-triage-refresh.timer): прошлая загрузка не подготовила базу – сначала
#                       повторить это, приложение до тех пор не запускается (иначе оно создаст в пустой базе свою схему,
#                       и демо больше не восстановится); сменился адрес ВМ – обновить TRUSTED_HOSTS
#                       и пересоздать контейнер приложения; контейнер не запущен – запустить; публикация порта по
#                       данным Docker не совпала с требуемой (.env) – пересоздать и проверить снова. Успех – только
#                       после подтверждения публикации порта: запись в .env и работающий контейнер её не доказывают.
#                       Открытый режим, который Docker не подтвердил (в том числе публикация порта на «::», для которой
#                       ограничения источника нет), не остаётся: порт возвращается на 127.0.0.1, контейнер пересоздаётся
#                       и проверяется (triage.status = bind-reverted, triage.bind = local-unsafe-publication); если вернуть
#                       не удалось – контейнер приложения останавливается (stopped-bind-unconfirmed), порт не публикуется.
# Порт приложения по умолчанию опубликован только на 127.0.0.1 ВМ (TRIAGE_BIND), доступ – SSH-туннелем. Если порт
# открыт на адрес ВМ, приложение принимает запросы только с разрешёнными именами хоста (защита от подмены DNS),
# поэтому адрес ВМ, полученный по DHCP, вписывается в .env при каждой загрузке.
# Состояние видно с хоста без входа в ВМ: vmrun readVariable <vmx> guestVar triage.status -> loading | ok | ...;
# там же triage.ip, triage.machineid и triage.hostkey (ключ SSH сервера ed25519 – для строгой проверки ключа).
set -uo pipefail

D="${D:-/opt/local-triage}"  # переменной окружения D подменяется каталог – для проверки
MODE="${1:-boot}"
CURL="${CURL:-curl}"  # подменяется для проверки
cd "$D" || exit 1

report() {
  vmware-rpctool "info-set guestinfo.triage.$1 $2" >/dev/null 2>&1 || true
  echo "local-triage: $1=$2"
}
env_get() { grep -E "^$1=" .env | tail -n 1 | cut -d= -f2-; }
env_set() {
  if grep -qE "^$1=" .env; then sed -i "s|^$1=.*|$1=$2|" .env; else printf '%s=%s\n' "$1" "$2" >> .env; fi
}
compose() { docker compose -f docker-compose.yml -f docker-compose.vm.yml "$@"; }
vm_ip() { ip -4 -o addr show scope global | awk '$2 ~ /^en/ { sub(/\/.*/, "", $4); print $4; exit }'; }

PORT="$(env_get TRIAGE_PORT)"; PORT="${PORT:-8765}"
NA="$D/bin/network-access.sh"
# Проверки сети запускаются через bash: потерянный исполняемый бит их не отключает; сценария нет совсем – для loopback
# работает встроенная проверка Docker ниже, а открытый режим без сценария невозможен (см. проверку ограничения)
na() { [ -r "$NA" ] || return 2; D="$D" bash "$NA" "$@"; }
# Встроенная проверка Docker для 127.0.0.1 (когда network-access.sh нет): контейнер приложения публикует порт только на
# loopback, посторонних публикаций порта нет. Docker не ответил или ответ пуст – не подтверждено.
docker_local_only() {
  local ids out pub
  ids="$(docker ps -q 2>/dev/null)" || return 1
  [ -n "$ids" ] || return 1
  # shellcheck disable=SC2086  # идентификаторы контейнеров – по одному слову
  out="$(docker inspect -f '{{.Name}}{{range $p, $b := .NetworkSettings.Ports}}{{range $b}} {{.HostIp}}|{{.HostPort}}{{end}}{{end}}' $ids 2>/dev/null)" \
    || return 1
  pub="$(printf '%s\n' "$out" | awk -v p="$PORT" '{ n = $1; sub(/^\//, "", n); for (i = 2; i <= NF; i++) { k = index($i, "|"); if (k && substr($i, k + 1) == p) print n " " substr($i, 1, k - 1) } }')"
  printf '%s\n' "$pub" | grep -qxE "local-triage (127\.0\.0\.1|::1)" || return 1
  ! printf '%s\n' "$pub" | grep -v '^$' | grep -vxE "[^ ]+ (127\.0\.0\.1|::1)" | grep -q .
}
# Состояние сети в guestinfo пишется, только если изменилось (таймер идёт раз в две минуты)
report_changed() {
  local cur
  cur="$(vmware-rpctool "info-get guestinfo.triage.$1" 2>/dev/null)" || cur=""
  [ "$cur" = "$2" ] || report "$1" "$2"
}
TRIAGE_IMAGE="$(env_get TRIAGE_IMAGE)"
OLLAMA_IMAGE="$(env_get OLLAMA_IMAGE)"
TRIAGE_DB_IMAGE="$(env_get TRIAGE_DB_IMAGE)"
DB_VOLUME="${DB_VOLUME:-local-triage_pgdata}"  # подменяется для проверки
DB_WAIT_TRIES="${DB_WAIT_TRIES:-90}"  # попыток дождаться базы, по две секунды; подменяется для проверки
# Метка «база ещё не готова»: ставится в начале загрузки и снимается, когда база готова. Пока метка есть, refresh не запускает
# приложение, а повторяет подготовку базы.
DB_PENDING="$D/db-pending"

# Пароль основной базы: случайный, у каждой копии свой (из образа его убрал cleanup.sh). Уже заданный не меняется: том базы
# хранит его. Тома нет только у новой копии; том есть, а пароля нет – новый пароль к нему не подойдёт, это отказ.
ensure_db_password() {
  local password
  [ -n "$(env_get POSTGRES_PASSWORD)" ] && return 0
  if docker volume inspect "$DB_VOLUME" >/dev/null 2>&1; then
    echo "local-triage: в .env нет POSTGRES_PASSWORD, а том базы $DB_VOLUME уже есть: новый пароль к нему не подойдёт" >&2
    report status db-password-failed
    return 1
  fi
  password="$(LC_ALL=C tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 32)"
  if [ "${#password}" != 32 ] || ! env_set POSTGRES_PASSWORD "$password"; then
    echo "local-triage: пароль базы не записан в .env" >&2
    report status db-password-failed
    return 1
  fi
}
# База: поднять, дождаться готовности (по TCP: на сокете отвечает и временный сервер первичной настройки образа), пустую –
# восстановить из demo.dump одной транзакцией. Непустая не трогается. Сбой любого шага – приложение не запускается.
prepare_database() {
  local ready=0 tables
  if ! compose up -d --no-build --pull never db; then
    report status db-failed
    return 1
  fi
  for _ in $(seq 1 "$DB_WAIT_TRIES"); do
    if compose exec -T db pg_isready -q -h 127.0.0.1 -U triage -d triage; then ready=1; break; fi
    sleep 2
  done
  if [ "$ready" != 1 ]; then
    echo "local-triage: база не ответила за $((DB_WAIT_TRIES * 2)) с" >&2
    report status db-failed
    return 1
  fi
  tables="$(compose exec -T db psql -X -U triage -d triage -Atc \
    "SELECT count(*) FROM pg_tables WHERE schemaname NOT IN ('pg_catalog', 'information_schema')")" || tables=""
  case "$tables" in
    ''|*[!0-9]*)
      echo "local-triage: не удалось узнать, пуста ли база" >&2
      report status db-failed
      return 1 ;;
    0) ;;
    *) return 0 ;;
  esac
  if [ ! -s data/demo.dump ]; then
    echo "local-triage: база пуста, а файла data/demo.dump нет" >&2
    report status db-restore-failed
    return 1
  fi
  if ! compose exec -T db pg_restore --exit-on-error --single-transaction --no-owner -U triage -d triage < data/demo.dump; then
    echo "local-triage: demo.dump не восстановлен, база осталась пустой" >&2
    report status db-restore-failed
    return 1
  fi
  echo "local-triage: демо-база восстановлена из demo.dump"
}

if [ "$MODE" = boot ]; then
  : > "$DB_PENDING"
  report status loading
  [ -s /etc/machine-id ] && report machineid "$(cat /etc/machine-id)"
  # Ключ SSH сервера – через канал гипервизора (guestinfo): сборка и проверка сверяют по нему ключ, который ВМ
  # предъявляет по сети. У копии из OVA ключей ещё нет (их удалила очистка образа) – они создаются здесь,
  # не дожидаясь первого запуска sshd.
  [ -s /etc/ssh/ssh_host_ed25519_key.pub ] || ssh-keygen -A >/dev/null 2>&1 || true
  [ -s /etc/ssh/ssh_host_ed25519_key.pub ] && report hostkey "$(cut -d' ' -f1,2 /etc/ssh/ssh_host_ed25519_key.pub)"
  if ! docker image inspect "$TRIAGE_IMAGE" >/dev/null 2>&1 || ! docker image inspect "$OLLAMA_IMAGE" >/dev/null 2>&1 \
     || ! docker image inspect "$TRIAGE_DB_IMAGE" >/dev/null 2>&1; then
    for f in images/*.tar.gz; do
      [ -e "$f" ] || continue
      docker load -i "$f" || { report status load-failed; exit 1; }
    done
  fi
  # раньше любого вызова compose: docker-compose.yml требует пароль уже при чтении файла
  ensure_db_password || exit 1
fi

if [ "$MODE" = boot ]; then
  # В ВМ работает один экземпляр приложения. Замок папки данных, оставшийся от прошлого запуска (выключение без
  # остановки контейнера, часы ВМ ушли назад), снимается, пока контейнер приложения остановлен.
  compose stop triage >/dev/null 2>&1 || true
  rm -f "$D/data/telemetry/instance.lock" "$D/data/telemetry/instance.lock.change"
  prepare_database || exit 1
  rm -f "$DB_PENDING"
elif [ -e "$DB_PENDING" ]; then
  ensure_db_password && prepare_database || exit 1
  rm -f "$DB_PENDING"
fi

# адрес ВМ: после загрузки DHCP иногда отвечает не сразу
ip=""
for _ in $(seq 1 60); do
  ip="$(vm_ip)"
  [ -n "$ip" ] && break
  [ "$MODE" = refresh ] && break
  sleep 2
done
# 127.0.0.1 и localhost приложение принимает всегда (SSH-туннель). Адрес ВМ – только если порт опубликован
# не на 127.0.0.1 (TRIAGE_BIND в .env, см. docs/vm-image.md, «Доступ к приложению»)
BIND="$(env_get TRIAGE_BIND)"; BIND="${BIND:-127.0.0.1}"
# TRIAGE_NET_NOTE – причина, по которой открытый режим отозван (пишет start.sh, снимает network-access.sh open/close): состояние
# в guestinfo остаётся видимым хосту, а не затирается следующим проходом
NET_NOTE="$(env_get TRIAGE_NET_NOTE)"
NET_STATE=local; [ "$BIND" = 127.0.0.1 ] || NET_STATE=public
[ "$BIND" = 127.0.0.1 ] && [ -n "$NET_NOTE" ] && NET_STATE="local-$NET_NOTE"
# Порт на адресах ВМ – только пока ограничение источника в DOCKER-USER действует (network-access.sh check: правило
# DROP для адреса TRIAGE_ALLOW – первое в DOCKER-USER, переход в DOCKER-USER – первый в FORWARD). Не действует
# (сброшены правила ufw, правка вручную, нет сценария) – приложение остаётся на 127.0.0.1, статус в guestinfo это
# говорит.
if [ "$BIND" != 127.0.0.1 ]; then
  if ! na check; then
    env_set TRIAGE_BIND 127.0.0.1
    BIND=127.0.0.1
    NET_STATE=local-no-guard
    report bind "local-no-guard"
    echo "local-triage: ограничения источника в DOCKER-USER нет – приложение только на 127.0.0.1" >&2
  fi
fi
# Публикация порта работающим контейнером совпадает с требуемой (BIND) по данным Docker, а не по .env: на 127.0.0.1 –
# network-access.sh local (контейнер приложения публикует порт только на loopback, посторонних публикаций нет, порт не
# слушается на адресах ВМ); на адресах ВМ – public (ровно публикация на 0.0.0.0, без «::») и действующее ограничение
# источника (check). Docker не ответил или ответ неполный – не подтверждено. Нет сценария: для loopback – встроенная
# проверка Docker, для адресов ВМ – не подтверждено (сюда без сценария не попасть: выше порт возвращён на loopback).
bind_confirmed() {
  if [ "$BIND" = 127.0.0.1 ]; then
    if [ -r "$NA" ]; then na local; else docker_local_only; fi
  else
    na public && na check
  fi
}
# Публикация подтверждена: состояние сети в guestinfo; если прежний проход оставил статус отказа, проверяется ответ
# приложения, и только тогда статус возвращается в ok (подтверждение сети само по себе здоровье приложения не доказывает)
settle_confirmed() {
  report_changed bind "$NET_STATE"
  case "$(vmware-rpctool "info-get guestinfo.triage.status" 2>/dev/null)" in
    compose-failed|bind-unconfirmed|app-not-responding|bind-reverted|stopped-bind-unconfirmed|stop-failed|db-failed|db-restore-failed|db-password-failed)
      if "$CURL" -fsS -o /dev/null --max-time 5 -H "Host: 127.0.0.1" "http://127.0.0.1:${PORT}/healthz"; then
        report status ok
      else
        report status app-not-responding
        return 1
      fi ;;
  esac
  return 0
}
# Открытый режим, который Docker не подтвердил (публикация на «::» или посторонний набор адресов, пересоздание не помогло):
# порт возвращается на 127.0.0.1, имена хоста – только локальные, контейнер пересоздаётся и проверяется. Не удалось вернуть –
# контейнер приложения останавливается: порт не публикуется совсем. Возвращает 0 только если loopback подтверждён.
revert_open_mode() {
  echo "local-triage: открытый режим не подтверждён Docker – порт возвращается на 127.0.0.1" >&2
  env_set TRIAGE_BIND 127.0.0.1
  env_set TRUSTED_HOSTS "local-triage-demo"
  env_set TRIAGE_NET_NOTE "unsafe-publication"
  BIND=127.0.0.1
  NET_STATE="local-unsafe-publication"
  if compose up -d --no-build --pull never && bind_confirmed; then
    report bind "$NET_STATE"
    report status bind-reverted
    return 0
  fi
  echo "local-triage: порт на 127.0.0.1 не подтверждён – контейнер приложения останавливается, порт не публикуется" >&2
  report bind unconfirmed
  # результат остановки проверяется Docker: сама проверка не удалась или контейнер работает – статус говорит об этом,
  # следующий проход повторит (ошибка «docker ps» – не подтверждение остановки)
  if compose stop triage >/dev/null 2>&1; then
    running="$(docker ps -q -f name='^local-triage$' -f status=running 2>/dev/null)"
    if [ $? -eq 0 ] && [ -z "$running" ]; then
      report status stopped-bind-unconfirmed
      return 1
    fi
  fi
  echo "local-triage: остановка контейнера не подтверждена Docker (не остановлен или проверка не удалась) – повтор при следующем проходе" >&2
  report status stop-failed
  return 1
}
hosts="local-triage-demo"
if [ -n "$ip" ] && [ "$BIND" != 127.0.0.1 ]; then hosts="$ip,local-triage-demo"; fi
changed=0
if [ "$(env_get TRUSTED_HOSTS)" != "$hosts" ]; then
  env_set TRUSTED_HOSTS "$hosts"
  changed=1
fi
[ -n "$ip" ] && report_changed ip "$ip"

# Ничего не менялось и контейнер работает – ничего не делаем, но только если его публикация порта подтверждена. Иначе
# (прошлая попытка закрыть порт не удалась: .env уже говорит 127.0.0.1, а старый контейнер всё ещё публикует порт на
# адресах ВМ) пересоздание повторяется на каждом проходе, пока Docker не подтвердит требуемое.
if [ "$MODE" = refresh ] && [ "$changed" = 0 ] && [ -n "$(docker ps -q -f name='^local-triage$' -f status=running)" ] \
   && bind_confirmed; then
  settle_confirmed
  exit $?
fi

if ! compose up -d --no-build --pull never; then
  # пересоздание не удалось: в открытом режиме не оставлять старый контейнер с открытым портом – вернуть loopback
  # и проверить (LTA-005, остаток по повторной проверке 0.3.21); в закрытом – отказ с повтором на следующем проходе
  if [ "$BIND" != 127.0.0.1 ]; then
    revert_open_mode
    exit 1
  fi
  report bind unconfirmed; report status compose-failed; exit 1
fi
if ! bind_confirmed; then
  if [ "$BIND" != 127.0.0.1 ]; then  # открытый режим не подтверждён: не оставлять его, вернуть loopback и проверить
    revert_open_mode
    exit 1
  fi
  report bind unconfirmed
  report status bind-unconfirmed
  echo "local-triage: публикация порта не подтверждена Docker (TRIAGE_BIND=$BIND) – повтор при следующем проходе" >&2
  exit 1
fi
if [ "$MODE" = refresh ]; then
  settle_confirmed
  exit $?
fi

ok=0
for _ in $(seq 1 60); do
  if "$CURL" -fsS -o /dev/null --max-time 5 -H "Host: 127.0.0.1" "http://127.0.0.1:${PORT}/healthz"; then ok=1; break; fi
  sleep 2
done
if [ "$ok" != 1 ]; then report status app-not-responding; exit 1; fi
report status ok
report_changed bind "$NET_STATE"

# прогрев модели профиля по умолчанию – через приложение (ADR-0102 п. 10): только профиль local, под общим правом на
# генерацию; первый ответ в показе – без загрузки модели. POST – с Origin этого же адреса (защита запросов, ADR-0015)
WARM="$("$CURL" -fsS --max-time 700 -X POST -H "Origin: http://127.0.0.1:${PORT}" \
  "http://127.0.0.1:${PORT}/api/model/warmup" 2>/dev/null || true)"
case "$WARM" in
  *'"state":"warm"'*) report model warm ;;
  *) report model cold ;;
esac
exit 0
