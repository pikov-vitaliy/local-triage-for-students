#!/usr/bin/env bash
# Сборка демо-ВМ «Локального триажа» в OVA для VMware: Ubuntu Server 24.04, Docker, приложение, Ollama на процессоре
# с маленькой моделью и демо-проект (разобранный большой моделью при сборке, если она была доступна).
# Окружение: Windows, VMware Workstation Pro, Git Bash, Docker Desktop, Ollama с большой моделью, выход в интернет.
# Руководство – docs/vm-image.md.
#
#   deploy/vm/build.sh all        все шаги подряд (журнал отметок – <BUILD>/logs/chain.out)
#   deploy/vm/build.sh src        чистая копия приложения из git (коммит REV) в <BUILD>/src
#   deploy/vm/build.sh images     образы контейнеров: приложение, база и Ollama для процессора, архивы для ВМ
#   deploy/vm/build.sh model      маленькая модель для ВМ (SMALL_MODEL) в <BUILD>/stage/ollama
#   deploy/vm/build.sh data       demo.dump из демо-данных (временный PostgreSQL), вердикты – прогон BIG_MODEL (DEMO_VERDICTS)
#   deploy/vm/build.sh iso        ISO Ubuntu Server с автоустановкой и всем перечисленным
#   deploy/vm/build.sh vm         диск и .vmx в сборочном варианте (ISO подключён, консоль пишется в файл)
#   deploy/vm/build.sh install    автоустановка, ВМ выключается сама
#   deploy/vm/build.sh firstboot  первый запуск: образы загружаются, приложение отвечает через SSH-туннель
#   deploy/vm/build.sh finalize   итоговое оборудование, состав ПО, очистка, выключение, маркер выпуска
#   deploy/vm/build.sh export     OVA и SHA256 в <BUILD>/out – только после подтверждённого finalize
#   deploy/vm/build.sh verify     копия из OVA: порт закрыт из сети, ключ сборщика отвергнут, новые machine-id и ключ
#                                 SSH, смена пароля, приложение через туннель, вердикты, «Спросить модель»
#
# Пути и параметры – переменными окружения (значения по умолчанию ниже). Пути для ovftool – только латиницей.
# Приложение в ВМ опубликовано только на 127.0.0.1: проверки идут через SSH-туннель (ssh_tunnel.py). Ключ SSH
# сервера берётся из guestinfo ВМ (канал гипервизора) и проверяется строго, с отдельным known_hosts в <BUILD>/secrets.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
HERE="$REPO/deploy/vm"
REV="${REV:-HEAD}"
NAME="${NAME:-local-triage-demo}"
BUILD="${BUILD:-$HOME/vms/local-triage-build}"
VMDIR="${VMDIR:-$HOME/vms/$NAME}"
CHECKDIR="${CHECKDIR:-$HOME/vms/$NAME-check}"
ISO_SRC="${ISO_SRC:-$HOME/vms/iso/ubuntu-24.04.5-live-server-amd64.iso}"
# SHA256 из https://releases.ubuntu.com/24.04/SHA256SUMS для ubuntu-24.04.5-live-server-amd64.iso
ISO_SHA256="${ISO_SHA256:-97f3d7ffb032c3eb3b23d2c8be9cc76e60c2c1f2c0146ba5ba9fe01cafae0fd8}"
DISK_GB="${DISK_GB:-80}"
SMALL_MODEL="${SMALL_MODEL:-qwen2.5-coder:3b}"
BIG_MODEL="${BIG_MODEL:-gpt-oss:20b}"
HOST_OLLAMA="${HOST_OLLAMA:-http://127.0.0.1:11434}"
OLLAMA_VERSION="${OLLAMA_VERSION:-0.40.4}"
PREP_PORT="${PREP_PORT:-8771}"
# Временный контейнер PostgreSQL шага data: порт только на 127.0.0.1, удаляется в конце шага
DB_BUILD_CONTAINER="${DB_BUILD_CONTAINER:-lt-build-db}"
DB_BUILD_PORT="${DB_BUILD_PORT:-5436}"
DB_BUILD_WAIT_TRIES="${DB_BUILD_WAIT_TRIES:-60}"  # попыток дождаться контейнера, по две секунды
PY="${PY:-$REPO/.venv/Scripts/python.exe}"
# Python с paramiko – для проверки первого входа по SSH
PY_SSH="${PY_SSH:-python}"
APP_PORT=8765

STAGE="$BUILD/stage"
ISO_OUT="$BUILD/out/$NAME-autoinstall.iso"
OVA="$BUILD/out/$NAME.ova"
VMX="$VMDIR/$NAME.vmx"
WS="${WS:-/c/Program Files/VMware/VMware Workstation}"
# vmrun и ovftool можно подменить (проверки сценария без VMware – tests/test_deploy_vm.py)
VMRUN="${VMRUN:-$WS/vmrun.exe}"
VDISK="$WS/vmware-vdiskmanager.exe"
OVFTOOL="${OVFTOOL:-$WS/OVFTool/ovftool.exe}"
KEY="$BUILD/secrets/build_ed25519"
PASSFILE="$BUILD/secrets/triage-password"
LOG="$BUILD/logs/build.log"
SERIAL="$BUILD/logs/serial.log"
OLLAMA_IMAGE="local-triage-ollama-cpu:$OLLAMA_VERSION"

w() { cygpath -w "$1"; }
log() { mkdir -p "$BUILD/logs"; echo "$(date '+%Y-%m-%d %H:%M:%S') $*" | tee -a "$LOG"; }
die() { log "ОШИБКА: $*"; exit 1; }
# Файл или папка с секретами (пароли, ключ сборщика) – только для владельца: chmod 600/700 и, на Windows,
# ACL без наследования, с полным доступом одному текущему пользователю и без явных разрешений других (secret_file.py
# restrict перечитывает список и требует ровно одну запись). У папки право наследуемое ((OI)(CI)): файлы в ней
# с прошлой сборки (known_hosts) и новые получают доступ только владельца. Не вышло – сборка останавливается.
restrict() {
  if [ -d "$1" ]; then chmod 700 "$1" 2>/dev/null || true; else chmod 600 "$1" 2>/dev/null || true; fi
  if command -v icacls >/dev/null 2>&1; then
    "$PY" -X utf8 "$(w "$HERE/secret_file.py")" restrict "$(w "$1")" || die "не удалось ограничить права на $1"
  fi
}
app_version() { sed -n 's/^__version__ = "\(.*\)"/\1/p' "$BUILD/src/app/__init__.py"; }
# Образ базы – закреплённая ссылка из docker-compose.yml подготовленных исходников (версия и дайджест)
db_image() { grep -oE 'postgres:[^ "}]+@sha256:[0-9a-f]{64}' "$BUILD/src/docker-compose.yml" | head -n 1 || true; }
# Тег образа базы в ВМ (TRIAGE_DB_IMAGE в .env) и его архив: после docker load дайджест может не сохраниться
db_image_archive() { local tag="${1%%@*}"; echo "${tag//:/-}.tar.gz"; }
running() {
  local out target
  out="$("$VMRUN" -T ws list 2>&1)" || die "vmrun list: $out"
  out="${out//$'\r'/}"
  target="$(w "$1")"
  [[ "${out,,}" == *"${target,,}"* ]]
}
vmx_del() { awk -v p="$2" 'index(tolower($0), tolower(p)) != 1' "$1" > "$1.tmp" && mv "$1.tmp" "$1"; }
vmx_set() { vmx_del "$1" "$2 = "; printf '%s = "%s"\n' "$2" "$3" >> "$1"; }
wait_off() {
  local t=0
  while running "$1"; do
    sleep 30; t=$((t + 30))
    [ "$t" -ge "$2" ] && return 1
    [ -s "$SERIAL" ] && tail -n 1 "$SERIAL" | tr -d '\r' | cut -c1-150
  done
  return 0
}
guestvar() { "$VMRUN" -T ws readVariable "$(w "$1")" guestVar "triage.$2" 2>/dev/null | tr -d '\r' || true; }
guest_ip() {
  local start=$SECONDS left ip
  while :; do
    left=$(( $2 - (SECONDS - start) ))
    [ "$left" -gt 0 ] || return 1
    ip="$(timeout "$left" "$VMRUN" -T ws getGuestIPAddress "$(w "$1")" -wait 2>/dev/null | tr -d '\r' || true)"
    if [[ "$ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ && "$ip" != 169.254.* ]]; then
      echo "$ip"; return 0
    fi
    sleep 5
  done
}
wait_status_ok() {
  local t=0 st=""
  until [ "$st" = ok ]; do
    sleep 10; t=$((t + 10))
    st="$(guestvar "$1" status)"
    case "$st" in *failed|app-not-responding) die "статус приложения в ВМ: $st";; esac
    if [ "$t" -ge "$2" ]; then die "приложение в ВМ не поднялось за $2 с (статус '$st')"; fi
  done
  return 0
}
check_app() { "$PY" -X utf8 "$(w "$HERE/check_app.py")" "$@"; }
hostkey() { grep -v '^#' "$1" | awk 'NF >= 3 { print $2 " " $3; exit }'; }
# Ключ SSH сервера ВМ – только через канал гипервизора: start.sh публикует его в guestinfo (triage.hostkey).
# pin_hostkey <vmx> <адрес> <файл known_hosts>: ключ из guestinfo -> отдельный known_hosts (строка
# «<NAME> <тип> <ключ>» для HostKeyAlias); ssh-keyscan по сети – только перекрёстная проверка, другой ключ – отказ.
pin_hostkey() {
  local t=0 key scanned
  until [[ "$(guestvar "$1" hostkey)" =~ ^ssh-ed25519\ [A-Za-z0-9+/]+=*$ ]]; do
    sleep 5; t=$((t + 5))
    [ "$t" -ge 300 ] && die "ВМ не сообщила ключ SSH сервера через guestinfo (triage.hostkey)"
  done
  key="$(guestvar "$1" hostkey)"
  mkdir -p "$BUILD/secrets"
  echo "$NAME $key" > "$3"
  scanned="$(ssh-keyscan -T 20 -t ed25519 "$2" 2>/dev/null | awk 'NF >= 3 && $1 !~ /^#/ { print $2 " " $3; exit }')"
  [ -n "$scanned" ] || die "SSH ВМ по адресу $2 не отвечает"
  [ "$scanned" = "$key" ] || die "ключ SSH по адресу $2 не совпадает с ключом из guestinfo ВМ: на этом адресе другая машина"
}
KNOWN_BUILD="$BUILD/secrets/known_hosts-build"
KNOWN_COPY="$BUILD/secrets/known_hosts-copy"
ssh_opts() { echo "-o StrictHostKeyChecking=yes -o UserKnownHostsFile=$1 -o HostKeyAlias=$NAME -o LogLevel=ERROR -o ConnectTimeout=15"; }
# shellcheck disable=SC2046
ssh_vm() { ssh -i "$KEY" -o BatchMode=yes $(ssh_opts "$KNOWN_BUILD") "triage@$1" "${@:2}"; }
# check_app через SSH-туннель: порт приложения в ВМ открыт только на 127.0.0.1.
# tunnel_check <адрес> <known_hosts> <--key файл | --password-file файл> -- <аргументы check_app>
# Вердикты демо в образе: all – созданы моделью при сборке у всех находок SAST, none – вердиктов нет (шаг data
# пишет это в logs/demo-verdicts; проверки приложения ждут именно такой состав)
demo_verdicts() {
  local v; v="$(tr -d '\r\n' < "$BUILD/logs/demo-verdicts" 2>/dev/null)"
  case "$v" in all|none) echo "$v" ;; *) return 1 ;; esac
}
tunnel_check() {
  local ip="$1" known="$2" how="$3" cred="$4" expect; shift 5
  expect="$(demo_verdicts)" || die "нет $BUILD/logs/demo-verdicts – сначала шаг data"
  "$PY_SSH" -X utf8 "$(w "$HERE/ssh_tunnel.py")" "$ip" --known-hosts "$(w "$known")" "$how" "$(w "$cred")" -- \
    "$(w "$PY")" -X utf8 "$(w "$HERE/check_app.py")" 127.0.0.1 --port "{port}" --expect-verdicts "$expect" "$@"
}
# порт приложения не должен отвечать из сети: только 127.0.0.1 ВМ
port_closed() { ! timeout 5 bash -c "exec 3<>/dev/tcp/$1/$APP_PORT" 2>/dev/null; }
# Маркер подтверждённой очистки: export выпускает OVA только с диска, который прошёл finalize (ревизия, размер
# и время изменения диска и .vmx – как после очистки)
MARK="$BUILD/logs/finalized.json"
disk_state() {
  printf '{"rev": "%s", "vmdk": "%s", "vmx": "%s", "cleanup": "ok"}\n' "$(cat "$BUILD/src/.revision")" \
    "$(stat -c '%s:%Y' "$VMDIR/$NAME.vmdk")" "$(stat -c '%s:%Y' "$VMX")"
}

step_src() {
  log "src: чистая копия приложения, коммит $(git -C "$REPO" rev-parse --short "$REV")"
  rm -rf "$BUILD/src"
  mkdir -p "$BUILD/src"
  git -C "$REPO" archive --format=tar "$REV" | tar -x -C "$BUILD/src"
  git -C "$REPO" rev-parse "$REV" > "$BUILD/src/.revision"
  log "src: версия $(app_version)"
}

step_images() {
  local v; v="$(app_version)"
  [ -n "$v" ] || die "нет $BUILD/src – сначала шаг src"
  local db; db="$(db_image)"
  [ -n "$db" ] || die "в $BUILD/src/docker-compose.yml нет закреплённого образа базы"
  log "images: local-triage:$v из $BUILD/src, $OLLAMA_IMAGE, база $db"
  mkdir -p "$STAGE/images"
  # плашка «Версия · коммит» в образе – по ревизии подготовленных исходников (шаг src), а не по текущему REV
  local commit built
  commit="$(head -c 7 "$BUILD/src/.revision")"
  [[ "$commit" =~ ^[0-9a-f]{7}$ ]] || die "нет ревизии исходников $BUILD/src/.revision – сначала шаг src"
  built="$(date '+%d.%m.%Y %H:%M')"
  docker build -q -t "local-triage:$v" --build-arg "BUILD_COMMIT=$commit" --build-arg "BUILD_DIRTY=0" \
    --build-arg "BUILD_TIME=$built" "$(w "$BUILD/src")" >/dev/null
  docker build -q --build-arg "OLLAMA_VERSION=$OLLAMA_VERSION" -t "$OLLAMA_IMAGE" "$(w "$HERE/ollama-cpu")" >/dev/null
  docker image inspect "$db" >/dev/null 2>&1 || docker pull -q "$db" >/dev/null
  docker tag "$db" "${db%%@*}"
  rm -f "$STAGE/images/"*.tar.gz
  docker save "local-triage:$v" | gzip -1 > "$STAGE/images/local-triage-$v.tar.gz"
  docker save "$OLLAMA_IMAGE" | gzip -1 > "$STAGE/images/local-triage-ollama-cpu-$OLLAMA_VERSION.tar.gz"
  docker save "${db%%@*}" | gzip -1 > "$STAGE/images/$(db_image_archive "$db")"
  log "images: $(du -h "$STAGE/images/"*.tar.gz | tr '\n\t' '; ')"
}

step_model() {
  log "model: $SMALL_MODEL в $STAGE/ollama (Ollama для процессора в контейнере)"
  docker rm -f lt-build-ollama >/dev/null 2>&1 || true
  rm -rf "$STAGE/ollama"; mkdir -p "$STAGE/ollama"
  MSYS_NO_PATHCONV=1 docker run -d --name lt-build-ollama -v "$(w "$STAGE/ollama"):/root/.ollama/models" "$OLLAMA_IMAGE" >/dev/null
  sleep 3
  docker exec lt-build-ollama ollama pull "$SMALL_MODEL" | tr '\r' '\n' | tail -n 1
  docker exec lt-build-ollama ollama list | tee -a "$LOG"
  docker rm -f lt-build-ollama >/dev/null
}

# Временный контейнер PostgreSQL шага data – тот же образ и те же настройки базы, что у сервиса db (образец –
# scripts/test-db.ps1). Данные в памяти контейнера, пароль случайный и только в окружении этого шага: libpq берёт его из
# PGPASSWORD, в аргументы команд и журналы он не идёт.
db_build_down() { docker rm -f "$DB_BUILD_CONTAINER" >/dev/null 2>&1 || true; }
db_build_up() {
  local t
  db_build_down
  PGPASSWORD="$(LC_ALL=C tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 32 || true)"
  [ "${#PGPASSWORD}" = 32 ] || die "data: не создан пароль временной базы"
  POSTGRES_PASSWORD="$PGPASSWORD"
  export PGPASSWORD POSTGRES_PASSWORD
  docker run -d --name "$DB_BUILD_CONTAINER" -e POSTGRES_PASSWORD -e POSTGRES_DB=triage -e POSTGRES_USER=triage \
    -e 'POSTGRES_INITDB_ARGS=--encoding=UTF8 --locale=C --lc-ctype=C.UTF-8' -e TZ=UTC \
    -p "127.0.0.1:$DB_BUILD_PORT:5432" --tmpfs /var/lib/postgresql/data:rw,size=4g "$1" >/dev/null \
    || die "data: временная база не запустилась (занят порт $DB_BUILD_PORT? переменная DB_BUILD_PORT)"
  # готовность – по TCP: на сокете отвечает и временный сервер первичной настройки образа
  for t in $(seq 1 "$DB_BUILD_WAIT_TRIES"); do
    docker exec "$DB_BUILD_CONTAINER" pg_isready -q -h 127.0.0.1 -U triage -d triage && return 0
    sleep 2
  done
  die "data: временная база не ответила: docker logs $DB_BUILD_CONTAINER"
}
db_build_dsn() { echo "host=127.0.0.1 port=$DB_BUILD_PORT user=triage dbname=$1"; }
# Новая база из упаковываемой копии: так копия проверяется вместе с восстановлением
db_build_restore() {
  docker exec "$DB_BUILD_CONTAINER" psql -X -q -v ON_ERROR_STOP=1 -U triage -d postgres -c "CREATE DATABASE $1" \
    && docker exec "$DB_BUILD_CONTAINER" pg_restore --exit-on-error --single-transaction --no-owner -U triage -d "$1" /tmp/demo.dump \
    || die "data: копия базы не восстанавливается (база $1)"
}

# Демо-данные. База образа строится ЗАНОВО только из демо-данных (demo_db_build.py) во временном контейнере PostgreSQL:
# демо-выгрузка, ответ SCA из examples/demo, настройки по умолчанию, новый ключ маскирования. Ни одна готовая база не
# читается: вердикты демо-находок SAST создаёт только прогон модели BIG_MODEL на Ollama этого компьютера (HOST_OLLAMA) во
# время этого шага. DEMO_VERDICTS: auto (по умолчанию) – модель недоступна или занята чужими моделями: вердиктов в образе
# нет, демо разбирается при показе маленькой моделью, в журнале – пометка с причиной; require – тогда отказ; none – без
# прогона. Своя папка данных (прежний GIVEN_DATA) не принимается. В образ идёт копия pg_dump -Fc (demo.dump) и ключ
# маскирования; проверки идут на новых базах, восстановленных из этой копии.
step_data() {
  [ -z "${GIVEN_DATA:-}" ] || die "data: GIVEN_DATA больше не поддерживается – вердикты демо создаются только прогоном модели при сборке (DEMO_VERDICTS)"
  local mode="${DEMO_VERDICTS:-auto}" triage=() expect db
  case "$mode" in
    auto|require) triage=(--triage-url "$HOST_OLLAMA" --triage-model "$BIG_MODEL" --triage-mode "$mode") ;;
    none) ;;
    *) die "data: DEMO_VERDICTS – auto, require или none" ;;
  esac
  db="$(db_image)"
  [ -n "$db" ] || die "в $BUILD/src/docker-compose.yml нет закреплённого образа базы – сначала шаг src"
  rm -rf "$STAGE/data" "$STAGE/prep" "$STAGE/data-check" "$STAGE/repos-root" "$STAGE/data.tar.gz" "$STAGE/demo-plain.sql" \
    "$BUILD/logs/demo-verdicts"
  # демо – там, где его находит кнопка «Создать демо-проект»: <корень>/demo/examples/demo (в ВМ – /srv/repos/demo/…)
  mkdir -p "$STAGE/repos-root/demo/examples"
  cp -r "$BUILD/src/examples/demo" "$STAGE/repos-root/demo/examples/demo"
  # пути внутри контейнера (/tmp/demo.dump) Git Bash не должен переводить в пути Windows
  export MSYS_NO_PATHCONV=1
  trap db_build_down EXIT
  db_build_up "$db"
  log "data: база образа – заново из демо-данных, контейнер $DB_BUILD_CONTAINER ($db); вердикты демо – $mode (модель $BIG_MODEL, $HOST_OLLAMA)"
  "$PY" -X utf8 "$(w "$HERE/demo_db_build.py")" "$(w "$BUILD/src")" "$(w "$STAGE/repos-root")" \
    --conninfo "$(db_build_dsn triage)" --out "$(w "$STAGE/data")" --ollama-url http://ollama:11434 --model "$SMALL_MODEL" "${triage[@]}" \
    --summary "$(w "$BUILD/logs/data-composition.json")" > "$BUILD/logs/data-composition.out" \
    || die "данные: база образа не собрана – $(cat "$BUILD/logs/data-composition.out")"
  log "data: состав базы – $(cat "$BUILD/logs/data-composition.json")"
  if grep -q '"source": "модель при сборке"' "$BUILD/logs/data-composition.json"; then
    expect=all
    log "data: вердикты демо созданы моделью $BIG_MODEL во время этой сборки"
  else
    expect=none
    log "data: ПОМЕТКА – вердиктов демо в образе нет (модель $BIG_MODEL при сборке недоступна или прогон не задан," \
        "причина – в составе базы выше): демо разбирается при показе маленькой моделью $SMALL_MODEL"
  fi
  echo "$expect" > "$BUILD/logs/demo-verdicts"
  # упаковываемая копия: мёртвые строки и журнал временной базы в неё не попадают
  docker exec "$DB_BUILD_CONTAINER" pg_dump -Fc -U triage -d triage -f /tmp/demo.dump || die "данные: pg_dump не прошёл"
  docker cp "$DB_BUILD_CONTAINER:/tmp/demo.dump" "$(w "$STAGE/data/demo.dump")" || die "данные: копия базы не получена из контейнера"
  [ -s "$STAGE/data/demo.dump" ] || die "данные: копия базы пуста"
  [ "$(docker exec "$DB_BUILD_CONTAINER" sha256sum /tmp/demo.dump | cut -d' ' -f1)" = "$(sha256sum "$STAGE/data/demo.dump" | cut -d' ' -f1)" ] \
    || die "данные: копия базы на диске отличается от копии в контейнере"
  # проверка на этом компьютере – на новой базе из этой копии: проверочный демо-проект создаётся и удаляется там
  db_build_restore triage_check
  mkdir -p "$STAGE/data-check"
  "$PY" -X utf8 "$(w "$HERE/prepare_demo_data.py")" check --src "$(w "$BUILD/src")" --conninfo "$(db_build_dsn triage_check)" \
    --data "$(w "$STAGE/data-check")" --root "$(w "$STAGE/repos-root")" --port "$PREP_PORT" --model "$SMALL_MODEL" \
    --expect-verdicts "$expect" > "$BUILD/logs/data-check.json" || die "данные: проверка не прошла – $(cat "$BUILD/logs/data-check.json")"
  log "data: проверка – $(cat "$BUILD/logs/data-check.json")"
  rm -rf "$STAGE/data-check"
  # последняя проверка состава – уже упаковываемого файла, на отдельной новой базе из него (только чтение)
  db_build_restore triage_final
  "$PY" -X utf8 "$(w "$HERE/demo_db_check.py")" "$(w "$BUILD/src")" "$(db_build_dsn triage_final)" \
    > "$BUILD/logs/data-final-check.out" || die "данные: в базе не только демо – $(cat "$BUILD/logs/data-final-check.out")"
  ls -A "$STAGE/data" | grep -qvxE 'demo\.dump|mask\.key' && die "данные: в папке данных лишние файлы: $(ls -A "$STAGE/data" | tr '\n' ' ')"
  # в базе не должно быть путей сборочного компьютера: проверяется содержимое копии в простом тексте (сам файл сжат)
  docker exec "$DB_BUILD_CONTAINER" pg_restore -f - /tmp/demo.dump > "$STAGE/demo-plain.sql" || die "данные: копия базы не читается"
  [ -s "$STAGE/demo-plain.sql" ] || die "данные: копия базы в простом тексте пуста"
  if grep -a -E '(^|[^A-Za-z])[A-Za-z]:[\/][^/]|(^|[ "(=])/[a-z]/[A-Za-z0-9]|Users[\/]' "$STAGE/demo-plain.sql" >/dev/null; then
    die "данные: в базе есть путь с диска сборочного компьютера"
  fi
  rm -f "$STAGE/demo-plain.sql"
  (cd "$STAGE/data" && tar -czf ../data.tar.gz demo.dump)
  log "data: готово, $(du -h "$STAGE/data.tar.gz" | cut -f1)"
}

step_iso() {
  log "iso: сборка ISO с автоустановкой"
  [ -f "$ISO_SRC" ] || die "нет $ISO_SRC – скачайте ubuntu-24.04.5-live-server-amd64.iso с releases.ubuntu.com"
  [ "$(sha256sum "$ISO_SRC" | cut -d' ' -f1)" = "$ISO_SHA256" ] || die "SHA256 $ISO_SRC не совпадает с опубликованной"
  local v; v="$(app_version)"
  [ -s "$STAGE/data.tar.gz" ] || die "нет данных – шаг data"
  ls "$STAGE/images/local-triage-$v.tar.gz" >/dev/null || die "нет образа приложения – шаг images"
  local db; db="$(db_image)"
  [ -n "$db" ] || die "в $BUILD/src/docker-compose.yml нет закреплённого образа базы"
  ls "$STAGE/images/$(db_image_archive "$db")" >/dev/null || die "нет образа базы – шаг images"
  [ -d "$STAGE/ollama/manifests" ] || die "нет модели – шаг model"
  local T="$BUILD/iso-tree"
  rm -rf "$T"
  mkdir -p "$BUILD/secrets" "$T/nocloud" "$T/triage/app" "$T/triage-guest" "$BUILD/out"
  restrict "$BUILD/secrets"
  if [ ! -f "$PASSFILE" ]; then
    (umask 077; set +o pipefail; LC_ALL=C tr -dc 'A-HJ-NP-Za-km-z2-9' < /dev/urandom | head -c 14 > "$PASSFILE")
    log "iso: пароль учётной записи triage записан в $PASSFILE"
  fi
  restrict "$PASSFILE"
  [ -f "$KEY" ] || ssh-keygen -q -t ed25519 -N '' -C local-triage-build -f "$KEY"
  restrict "$KEY"
  local hash pub
  hash="$(openssl passwd -6 -stdin < "$PASSFILE")"
  pub="$(cat "$KEY.pub")"
  sed -e "s|@PASSWORD_HASH@|$hash|" -e "s|@BUILD_SSH_KEY@|$pub|" "$HERE/autoinstall/user-data.tmpl" > "$T/nocloud/user-data"
  : > "$T/nocloud/meta-data"
  cp "$BUILD/src/docker-compose.yml" "$HERE/guest/docker-compose.vm.yml" "$T/triage/app/"
  sed -e "s|@SMALL_MODEL@|$SMALL_MODEL|" -e "s|^TRIAGE_IMAGE=.*|TRIAGE_IMAGE=local-triage:$v|" \
      -e "s|^OLLAMA_IMAGE=.*|OLLAMA_IMAGE=$OLLAMA_IMAGE|" -e "s|^TRIAGE_DB_IMAGE=.*|TRIAGE_DB_IMAGE=${db%%@*}|" \
      "$HERE/guest/env.vm" > "$T/triage/app/.env"
  cp "$BUILD/src/.revision" "$T/triage/app/REVISION"
  cp "$HERE/guest/"{start.sh,cleanup.sh,network-access.sh,local-triage.service,local-triage-refresh.service,local-triage-refresh.timer,01-lan.yaml,ssh-hostkeys.conf,tools.conf,issue.append} "$T/triage-guest/"
  cp "$HERE/autoinstall/grub.cfg" "$T/grub.cfg"
  if ! docker image inspect local-triage-isotools:local >/dev/null 2>&1; then
    printf 'FROM ubuntu:24.04\nRUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq xorriso >/dev/null && rm -rf /var/lib/apt/lists/*\n' \
      | docker build -q -t local-triage-isotools:local - >/dev/null
  fi
  rm -f "$ISO_OUT"
  MSYS_NO_PATHCONV=1 docker run --rm \
    -v "$(w "$BUILD"):/build" -v "$(w "$(dirname "$ISO_SRC")"):/iso:ro" local-triage-isotools:local \
    xorriso -indev "/iso/$(basename "$ISO_SRC")" -outdev "/build/out/$(basename "$ISO_OUT")" \
      -map /build/iso-tree/grub.cfg /boot/grub/grub.cfg \
      -map /build/iso-tree/nocloud /nocloud \
      -map /build/iso-tree/triage /triage \
      -map /build/stage/images /triage/images \
      -map /build/stage/ollama /triage/ollama \
      -map /build/stage/data.tar.gz /triage/data.tar.gz \
      -map /build/stage/repos-root/demo /triage/demo-repos \
      -map /build/iso-tree/triage-guest /triage-guest \
      -boot_image any replay 2>&1 | tail -n 3
  [ -s "$ISO_OUT" ] || die "ISO не собран"
  log "iso: готов $ISO_OUT ($(du -h "$ISO_OUT" | cut -f1))"
}

step_vm() {
  running "$VMX" && die "ВМ запущена – сначала выключите"
  rm -f "$MARK"
  log "vm: диск $DISK_GB ГБ (растущий) и .vmx (сборочный вариант), сеть – мост"
  [ ! -e "$VMDIR/$NAME.vmdk" ] || die "в $VMDIR уже есть диск – сборка идёт с нуля: удалите прежнюю сборочную ВМ (vmrun deleteVM)"
  mkdir -p "$VMDIR"
  "$VDISK" -c -s "${DISK_GB}GB" -a lsilogic -t 0 "$(w "$VMDIR/$NAME.vmdk")" | tail -n 1
  cp "$HERE/$NAME.vmx" "$VMX"
  vmx_set "$VMX" ide1:0.deviceType cdrom-image
  vmx_set "$VMX" ide1:0.fileName "$(w "$ISO_OUT")"
  vmx_del "$VMX" "ide1:0.autodetect = "
  vmx_set "$VMX" ide1:0.startConnected TRUE
  vmx_del "$VMX" serial0.
  vmx_set "$VMX" serial0.present TRUE
  vmx_set "$VMX" serial0.fileType file
  vmx_set "$VMX" serial0.fileName "$(w "$SERIAL")"
  vmx_set "$VMX" serial0.yieldOnMsrRead TRUE
  log "vm: готово $VMX"
}

step_install() {
  running "$VMX" && die "ВМ уже запущена"
  rm -f "$MARK"
  log "install: автоустановка Ubuntu Server, обычно 10–40 минут"
  : > "$SERIAL"
  "$VMRUN" -T ws start "$(w "$VMX")" nogui
  wait_off "$VMX" 5400 || die "установка не закончилась за 90 минут – смотрите $SERIAL"
  grep -q "finish: subiquity/Install/install" "$SERIAL" && grep -q "subiquity/Shutdown/shutdown: mode=POWEROFF" "$SERIAL" \
    || die "ВМ выключилась, но в журнале консоли нет признаков успешной установки – смотрите $SERIAL"
  cp "$SERIAL" "$BUILD/logs/serial-install.log"
  log "install: установка завершена, ВМ выключилась"
}

step_firstboot() {
  running "$VMX" && die "ВМ запущена – сначала выключите"
  rm -f "$MARK"
  log "firstboot: первый запуск с диска"
  vmx_set "$VMX" ide1:0.startConnected FALSE
  "$VMRUN" -T ws start "$(w "$VMX")" nogui
  wait_status_ok "$VMX" 1500
  local ip
  ip="$(guest_ip "$VMX" 300)" || die "firstboot: ВМ не сообщила IPv4-адрес"
  echo "$ip" > "$BUILD/logs/vm-ip.txt"
  pin_hostkey "$VMX" "$ip" "$KNOWN_BUILD"
  port_closed "$ip" || die "firstboot: порт $APP_PORT отвечает из сети, а должен быть открыт только на 127.0.0.1 ВМ"
  # только чтение: главная страница, демо-проект, вердикты; база образа не меняется
  tunnel_check "$ip" "$KNOWN_BUILD" --key "$KEY" -- > "$BUILD/logs/check-build.json" \
    || die "firstboot: $(cat "$BUILD/logs/check-build.json")"
  log "firstboot: приложение отвечает через SSH-туннель, из сети порт $APP_PORT закрыт, $(cat "$BUILD/logs/check-build.json")"
}

step_finalize() {
  rm -f "$MARK"
  if running "$VMX"; then
    log "finalize: выключение"
    "$VMRUN" -T ws stop "$(w "$VMX")" soft
    wait_off "$VMX" 300 || die "ВМ не выключилась"
  fi
  log "finalize: итоговое оборудование (без последовательного порта, CD/DVD не подключается при включении)"
  vmx_del "$VMX" serial0.
  vmx_set "$VMX" serial0.present FALSE
  vmx_set "$VMX" ide1:0.deviceType cdrom-raw
  vmx_set "$VMX" ide1:0.fileName "auto detect"
  vmx_set "$VMX" ide1:0.autodetect TRUE
  vmx_set "$VMX" ide1:0.startConnected FALSE
  grep -q '^ethernet0.connectionType = "bridged"' "$VMX" || die "сеть ВМ не мост"
  "$VMRUN" -T ws start "$(w "$VMX")" nogui
  wait_status_ok "$VMX" 600
  local ip
  ip="$(guest_ip "$VMX" 600)" || die "ВМ не сообщила IPv4-адрес за 10 минут"
  pin_hostkey "$VMX" "$ip" "$KNOWN_BUILD"
  cp "$KNOWN_BUILD" "$BUILD/logs/hostkey-build.txt"
  port_closed "$ip" || die "finalize: порт $APP_PORT отвечает из сети, а должен быть открыт только на 127.0.0.1 ВМ"
  tunnel_check "$ip" "$KNOWN_BUILD" --key "$KEY" -- > "$BUILD/logs/check-finalize.json" \
    || die "приложение не отвечает: $(cat "$BUILD/logs/check-finalize.json")"
  guestvar "$VMX" machineid > "$BUILD/logs/machineid-build.txt"
  [[ "$(cat "$BUILD/logs/machineid-build.txt")" =~ ^[0-9a-f]{32}$ ]] || die "нет machine-id сборочной ВМ"
  # в выводе compose config есть пароль базы этой сборочной ВМ: cleanup.sh ниже удаляет и пароль, и том базы, у копии свой
  ssh_vm "$ip" 'grep -A2 "^\[powerops\]" /etc/vmware-tools/tools.conf; git config --system credential.helper; docker compose -f /opt/local-triage/docker-compose.yml -f /opt/local-triage/docker-compose.vm.yml --project-directory /opt/local-triage config --format json' > "$BUILD/logs/vm-config.txt" \
    || die "не удалось прочитать настройки ВМ"
  grep -qE '"host_ip": ?"127.0.0.1"' "$BUILD/logs/vm-config.txt" || die "порт приложения в ВМ опубликован не только на 127.0.0.1"
  # база работает, её порт наружу не опубликован
  local dbports
  dbports="$(ssh_vm "$ip" "docker ps --filter name=local-triage-db --format '{{.Ports}}'")" || die "не удалось прочитать порты базы"
  [[ "$dbports" == *5432/tcp* && "$dbports" != *"->"* ]] || die "finalize: база не работает или её порт опубликован: $dbports"
  # модель работает без интернета: сеть контейнера Ollama закрытая, наружу из него не выйти
  ssh_vm "$ip" 'docker network inspect local-triage_llm --format "{{.Internal}}"' | grep -q true || die "сеть Ollama не закрытая"
  if ssh_vm "$ip" "docker exec local-triage-ollama timeout 5 bash -c 'exec 3<>/dev/tcp/1.1.1.1/443'" 2>/dev/null; then
    die "из контейнера Ollama есть выход наружу"
  fi
  log "finalize: сеть Ollama закрытая, выхода наружу из контейнера модели нет"
  log "finalize: состав ПО – $BUILD/out/$NAME-packages.txt"
  {
    echo "# Состав ПО ВМ $NAME на $(date '+%d.%m.%Y')"
    echo "## Приложение"
    echo "Локальный триаж $(app_version), коммит $(cat "$BUILD/src/.revision")"
    echo "## Модель в Ollama"
    ssh_vm "$ip" "docker exec local-triage-ollama ollama list"
    echo "## Образы контейнеров"
    echo "База: $(db_image)"
    ssh_vm "$ip" "docker image ls --digests --format '{{.Repository}}:{{.Tag}} {{.ID}} {{.Size}}'"
    echo "## Пакеты Ubuntu (dpkg)"
    ssh_vm "$ip" "dpkg-query -W -f='\${Package} \${Version}\n'"
    echo "## Пакеты Python в контейнере приложения"
    ssh_vm "$ip" "docker exec local-triage python -m pip list --format=freeze 2>/dev/null"
  } > "$BUILD/out/$NAME-packages.txt" || die "не удалось снять состав ПО"
  log "finalize: очистка образа (cleanup.sh), ВМ выключится сама"
  ssh_vm "$ip" 'sudo /opt/local-triage/bin/cleanup.sh' > "$BUILD/logs/cleanup.out" 2>&1 || true
  cat "$BUILD/logs/cleanup.out" >> "$LOG"
  grep -q '^== очистка завершена' "$BUILD/logs/cleanup.out" || die "очистка не дошла до конца – смотрите $BUILD/logs/cleanup.out"
  wait_off "$VMX" 3600 || die "ВМ не выключилась после очистки"
  # очистка прошла, ВМ выключена: этот диск и эта ревизия можно выпускать (step_export сверяет маркер)
  disk_state > "$MARK"
  log "finalize: готово, ВМ очищена и выключена, маркер выпуска – $(cat "$MARK")"
}

step_export() {
  running "$VMX" && die "ВМ запущена – выгрузка только с выключенной"
  # Выпуск – только диска, прошедшего finalize: ключ сборщика и sudo без пароля удалены очисткой. Включали ВМ после
  # очистки, сменили ревизию или диск – маркер не совпадёт, нужен повторный finalize.
  [ -s "$MARK" ] || die "export: нет подтверждения очистки ($MARK) – сначала finalize"
  [ "$(disk_state)" = "$(cat "$MARK")" ] || die "export: диск или ревизия изменились после finalize – повторите finalize"
  log "export: выгрузка OVA"
  rm -f "$OVA" "$OVA.sha256"
  "$OVFTOOL" --name="$NAME" "$(w "$VMX")" "$(w "$OVA")" | tr '\r' '\n' | grep -v '^Disk progress' | tail -n 2
  (cd "$(dirname "$OVA")" && sha256sum "$(basename "$OVA")" > "$(basename "$OVA").sha256")
  tar -xOf "$OVA" "$NAME.ovf" > "$BUILD/logs/$NAME.ovf" || die "в OVA нет $NAME.ovf"
  grep -q '<rasd:ResourceType>10</rasd:ResourceType>' "$BUILD/logs/$NAME.ovf" || die "в OVF нет сетевого адаптера"
  [ "$(disk_state)" = "$(cat "$MARK")" ] || die "export: диск изменился во время выгрузки"
  log "export: $(cat "$OVA.sha256"), $(stat -c %s "$OVA") байт"
}

# Копия из OVA, как её развернёт человек. Сначала отрицательные проверки: порт приложения закрыт из сети, ключ
# сборщика не принимается, machine-id и ключ SSH – новые, вход по паролю из инструкции требует сменить пароль.
# Затем пароль копии меняется на случайный (новый – в <BUILD>/secrets/triage-password-copy, в журнал не пишется),
# и через SSH-туннель по паролю – полная проверка: вердикты демо-проекта (все или ни одного – по шагу data), «Создать демо-проект» находит демо-клоны
# (проект затем удаляется), живой разбор и «Спросить модель» маленькой моделью.
step_verify() {
  [ -f "$OVA" ] || die "нет $OVA"
  [ -s "$BUILD/logs/hostkey-build.txt" ] || die "нет ключа SSH сборочной ВМ – сначала finalize"
  log "verify: проверяется $(cat "$OVA.sha256")"
  if [ -d "$CHECKDIR" ]; then
    local old; old="$(find "$CHECKDIR" -name '*.vmx' | head -n 1)"
    if [ -n "$old" ] && running "$old"; then "$VMRUN" -T ws stop "$(w "$old")" hard || die "verify: не остановилась прежняя копия"; fi
    rm -rf "$CHECKDIR" || die "verify: не удалось удалить $CHECKDIR"
  fi
  mkdir -p "$CHECKDIR"
  "$OVFTOOL" --name="$(basename "$CHECKDIR")" "$(w "$OVA")" "$(w "$CHECKDIR")" | tr '\r' '\n' | grep -v '^Disk progress' | tail -n 2
  local cvmx ip mid out
  cvmx="$(find "$CHECKDIR" -name '*.vmx' | head -n 1)"
  [ -n "$cvmx" ] || die "verify: копия не развернулась"
  grep -q '^ethernet0.connectionType = "bridged"' "$cvmx" || die "verify: сеть копии не мост"
  "$VMRUN" -T ws start "$(w "$cvmx")" nogui || die "verify: копия не запустилась"
  wait_status_ok "$cvmx" 900
  ip="$(guest_ip "$cvmx" 600)" || die "verify: копия не сообщила IPv4-адрес"
  echo "$ip" > "$BUILD/logs/check-ip.txt"
  pin_hostkey "$cvmx" "$ip" "$KNOWN_COPY"
  cp "$KNOWN_COPY" "$BUILD/logs/hostkey-copy.txt"
  [ "$(hostkey "$BUILD/logs/hostkey-build.txt")" != "$(hostkey "$KNOWN_COPY")" ] || die "verify: ключ SSH копии совпадает со сборочным"
  mid="$(guestvar "$cvmx" machineid)"
  [[ "$mid" =~ ^[0-9a-f]{32}$ ]] || die "verify: нет machine-id копии"
  [ "$mid" != "$(cat "$BUILD/logs/machineid-build.txt")" ] || die "verify: machine-id копии совпадает со сборочным"
  log "verify: machine-id $mid и ключ SSH – новые"
  port_closed "$ip" || die "verify: порт $APP_PORT копии отвечает из сети"
  # ключ сборщика копия не принимает (authorized_keys удалён очисткой)
  # shellcheck disable=SC2046
  if out="$(ssh -i "$KEY" -o BatchMode=yes $(ssh_opts "$KNOWN_COPY") "triage@$ip" true 2>&1)"; then
    die "verify: копия принимает ключ сборщика"
  fi
  [[ "$out" == *"Permission denied"* ]] || die "verify: проверка ключа сборщика не дошла до входа: $out"
  log "verify: из сети порт $APP_PORT закрыт, ключ сборщика не принимается"
  "$PY_SSH" -X utf8 "$(w "$HERE/first_login.py")" "$ip" "$(w "$PASSFILE")" "$(w "$KNOWN_COPY")" \
    || die "verify: вход по паролю не потребовал смены пароля"
  log "verify: вход по паролю из инструкции требует сменить пароль"
  "$PY_SSH" -X utf8 "$(w "$HERE/first_login.py")" "$ip" "$(w "$PASSFILE")" "$(w "$KNOWN_COPY")" \
    --change "$(w "$BUILD/secrets/triage-password-copy")" > "$BUILD/logs/first-login-copy.txt" \
    || die "verify: смена пароля и sudo на копии не прошли"
  tunnel_check "$ip" "$KNOWN_COPY" --password-file "$BUILD/secrets/triage-password-copy" -- \
    --demo-button --live 2 --model "$SMALL_MODEL" > "$BUILD/logs/check-copy.json" || die "verify: $(cat "$BUILD/logs/check-copy.json")"
  log "verify: приложение через SSH-туннель, вердикты, «Создать демо-проект», живой разбор и «Спросить модель»: $(cat "$BUILD/logs/check-copy.json")"
  log "verify: копия оставлена запущенной, пароль triage – в $BUILD/secrets/triage-password-copy ($(w "$cvmx"))"
}

chain_note() { echo "$(date '+%Y-%m-%d %H:%M:%S') $*" >> "$BUILD/logs/chain.out"; }
step_all() {
  local s
  for s in src images model data iso vm install firstboot finalize export verify; do
    chain_note "начало $s"
    if bash "$0" "$s" > "$BUILD/logs/step-$s.out" 2>&1; then chain_note "готово $s"; else
      chain_note "ОШИБКА $s"; tail -n 25 "$BUILD/logs/step-$s.out" >> "$BUILD/logs/chain.out"; exit 1
    fi
  done
  chain_note "ЦЕПОЧКА ГОТОВА"
}

case "${1:-}" in
  all) step_all ;;
  src) step_src ;;
  images) step_images ;;
  model) step_model ;;
  data) step_data ;;
  iso) step_iso ;;
  vm) step_vm ;;
  install) step_install ;;
  firstboot) step_firstboot ;;
  finalize) step_finalize ;;
  export) step_export ;;
  verify) step_verify ;;
  *) sed -n '2,23p' "$0"; exit 2 ;;
esac
