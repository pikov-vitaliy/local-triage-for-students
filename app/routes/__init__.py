"""Разделы веб-интерфейса: у каждого свой APIRouter, шаблоны – в своей подпапке app/templates.

  common.py   – общее для разделов: состояние приложения, действующие настройки, отрисовка, переходы, кэши
  projects.py – проекты, выгрузка, папка с репозиториями, кодовые базы (templates/projects/)
  findings.py – список находок, карточка, решение, текст для Hub (templates/findings/)
  runs.py     – прогоны триажа: запуск, страница, состояние, поток событий, управление (templates/runs/)
  settings.py – настройки (templates/settings/)
  sca.py      – разбор SCA (templates/sca/)
  api.py      – служебные JSON-адреса: /healthz, /api/metrics
"""
