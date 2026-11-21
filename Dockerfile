# Образ «Локального триажа»: веб-интерфейс на порту 8765, данные в /data, клоны репозиториев – в /repos (только чтение).
# Базовый образ закреплён по версии и дайджесту: пересборка в другой день даёт тот же Python и те же системные
# библиотеки. Обновление – осознанно: новый тег и дайджест (docker buildx imagetools inspect python:3.12-slim),
# затем пересчёт хешей в requirements.lock.
FROM python:3.12.15-slim-trixie@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    DATA_DIR=/data \
    REPOS_ROOT=/repos

WORKDIR /app

# Пакеты – только с совпавшими контрольными суммами (requirements.lock), только готовые колёса, без зависимостей
# сверх перечисленных
COPY requirements.lock ./
RUN python -m pip install --no-cache-dir --require-hashes --no-deps --only-binary=:all: -r requirements.lock

COPY app ./app
# Коммит и время сборки для плашки внизу страниц и /healthz (передаёт start.ps1 или deploy/vm/build.sh)
ARG BUILD_COMMIT=unknown
ARG BUILD_DIRTY=unknown
ARG BUILD_TIME=unknown
ENV LT_BUILD_COMMIT=$BUILD_COMMIT \
    LT_BUILD_DIRTY=$BUILD_DIRTY \
    LT_BUILD_TIME=$BUILD_TIME
# Демо-выгрузка для кнопки «Создать демо-проект»: выдуманные данные, код демо-репозиториев в образ не входит –
# приложение читает его из корня папок с репозиториями
COPY examples/demo/demo-hub-report.xlsx ./examples/demo/demo-hub-report.xlsx

# Непривилегированный пользователь; запись – только в /data
RUN useradd --system --uid 1000 --user-group --no-create-home --shell /usr/sbin/nologin triage \
 && mkdir -p /data /repos /scratch \
 && chown triage:triage /data /scratch

USER triage

EXPOSE 8765

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["python", "-c", "import sys, urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8765/healthz', timeout=3).status == 200 else 1)"]

# Открытая страница прогона держит поток событий (SSE): при остановке он закрывается через 3 с, после чего
# приложение останавливает очередь триажа (прогон встаёт на паузу) и закрывает базу. Запас Docker – stop_grace_period.
# Журнал запросов отключён: в адресах страниц бывают имена кодовых баз (фильтр списка находок), а журнал контейнера
# смотрят и пересылают при сбоях.
CMD ["uvicorn", "app.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8765", "--no-server-header", \
     "--no-access-log", "--timeout-graceful-shutdown", "3"]
