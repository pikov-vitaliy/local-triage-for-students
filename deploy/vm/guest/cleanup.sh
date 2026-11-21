#!/bin/bash
# Очистка демо-ВМ перед выгрузкой в OVA. Запускать от root последним шагом сборки:
#   sudo /opt/local-triage/bin/cleanup.sh
# Последняя строка вывода – «== очистка завершена, выключение»: по ней сборка понимает, что всё прошло.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "Запускать через sudo"; exit 1; }

D=/opt/local-triage
PORT="$(grep -E '^TRIAGE_PORT=' "$D/.env" | cut -d= -f2-)"; PORT="${PORT:-8765}"
DB_VOLUME=local-triage_pgdata
app_ok() { curl -fsS -o /dev/null --max-time 10 -H "Host: 127.0.0.1" "http://127.0.0.1:${PORT}/healthz"; }
# База прогонов сборки в образ не идёт. Контейнеры удаляются, а не останавливаются: в их настройках записан пароль базы.
# Том базы удаляется, пароль снимается после этого (без него compose не читает docker-compose.yml). В папке данных остаются
# только demo.dump: журнал обмена с моделью, справочники и остальное – следы firstboot и finalize.
reset_database() {
  docker compose -f "$D/docker-compose.yml" -f "$D/docker-compose.vm.yml" --project-directory "$D" down -v --remove-orphans
  sed -i '/^POSTGRES_PASSWORD=/d' "$D/.env"
  find "$D/data" -mindepth 1 -maxdepth 1 ! -name demo.dump -exec rm -rf {} +
  rm -f "$D/db-pending"
}
# Первая загрузка копии восстанавливает демо заново: архив на месте, тома базы и пароля нет, контейнеров нет
check_database_reset() {
  [ -s "$D/data/demo.dump" ] || { echo "Нет demo.dump"; return 1; }
  local left
  left="$(find "$D/data" -mindepth 1 -maxdepth 1 ! -name demo.dump | wc -l)"
  [ "$left" = 0 ] || { echo "В папке данных посторонние файлы: $left"; return 1; }
  if grep -q '^POSTGRES_PASSWORD=' "$D/.env"; then echo "Пароль базы остался в .env"; return 1; fi
  if docker volume inspect "$DB_VOLUME" >/dev/null 2>&1; then echo "Том базы $DB_VOLUME остался"; return 1; fi
  [ -z "$(docker ps -aq)" ] || { echo "Контейнеры не удалены"; return 1; }
  [ ! -e "$D/db-pending" ] || { echo "Осталась метка db-pending"; return 1; }
}

echo "== приложение отвечает"
app_ok
docker ps --format '{{.Names}}: {{.Status}}'

echo "== пакеты"
apt-get -y autoremove --purge
apt-get clean
rm -rf /var/lib/apt/lists/*

echo "== образы контейнеров загружены в Docker: архивы с установочного диска больше не нужны"
docker image inspect "$(grep -E '^TRIAGE_IMAGE=' "$D/.env" | cut -d= -f2-)" >/dev/null
docker image inspect "$(grep -E '^OLLAMA_IMAGE=' "$D/.env" | cut -d= -f2-)" >/dev/null
docker image inspect "$(grep -E '^TRIAGE_DB_IMAGE=' "$D/.env" | cut -d= -f2-)" >/dev/null
rm -rf "$D/images"
docker builder prune -af >/dev/null 2>&1 || true

echo "== cloud-init выключен: сеть и учётная запись уже настроены в образе"
cloud-init clean --logs || true
touch /etc/cloud/cloud-init.disabled
rm -f /etc/cloud/cloud.cfg.d/99-installer.cfg /etc/cloud/cloud.cfg.d/90-installer-network.cfg
rm -f /etc/netplan/50-cloud-init.yaml

echo "== следы сборки"
rm -rf /var/log/installer
rm -f /etc/sudoers.d/90-triage-build
rm -f /home/triage/.ssh/authorized_keys
rm -f /root/.bash_history /home/triage/.bash_history /root/.lesshst /home/triage/.lesshst
rm -f /root/.wget-hsts /home/triage/.wget-hsts /home/triage/.sudo_as_admin_successful

echo "== ключи SSH сервера и идентификатор машины: у каждой копии будут свои"
rm -f /etc/ssh/ssh_host_*
truncate -s 0 /etc/machine-id
rm -f /var/lib/dbus/machine-id
ln -s /etc/machine-id /var/lib/dbus/machine-id
rm -f /var/lib/systemd/random-seed

echo "== пароль triage – сменить при первом входе"
chage -d 0 triage

echo "== контейнеры и том базы удалены, пароль базы снят, в папке данных только demo.dump и mask.key"
# Таймер refresh поднял бы остановленные контейнеры: на время очистки он останавливается (в образе остаётся включённым).
systemctl stop local-triage-refresh.timer local-triage-refresh.service
# Приложение держит замок /opt/local-triage/data/instance.lock с отметкой времени. Если оставить его в образе,
# копия с часами, отстающими от сборочной ВМ, примет замок за чужой и не запустится: он удаляется вместе с остальной папкой.
reset_database

echo "== журналы и временные файлы"
journalctl --rotate || true
journalctl --vacuum-time=1s || true
find /var/log -type f \( -name '*.gz' -o -name '*.[0-9]' -o -name '*.old' \) -delete
find /var/log -type f -exec truncate -s 0 {} +
find /var/lib/docker/containers -name '*-json.log' -exec truncate -s 0 {} + 2>/dev/null || true
rm -rf /tmp/* /var/tmp/*

echo "== нули на свободном месте (запас 1 ГБ): образ OVA станет меньше"
avail_mb="$(df --output=avail -BM / | tail -n 1 | tr -dc '0-9')"
fill_mb=$((avail_mb - 1024))
if [ "$fill_mb" -gt 0 ]; then
  dd if=/dev/zero of=/zero.fill bs=4M count="$((fill_mb / 4))" status=none || true
  sync
  rm -f /zero.fill
  sync
fi
df -h /

echo "== контроль после очистки"
[ ! -s /etc/machine-id ]
if ls /etc/ssh/ssh_host_* >/dev/null 2>&1; then echo "Ключи SSH сервера остались"; exit 1; fi
[ ! -e /home/triage/.ssh/authorized_keys ]
[ ! -e /etc/sudoers.d/90-triage-build ]
[ -s /etc/netplan/01-lan.yaml ]
check_database_reset
[ -d /srv/repos/demo/examples/demo/repos ]

echo "== очистка завершена, выключение"
systemctl poweroff
