"""Стенд не принимает ответ чужого сервера за успешный запуск своего."""

from contextlib import contextmanager

import pytest

from e2e import e2e_support as support


def test_other_health_cannot_confirm_failed_local_start(tmp_path, monkeypatch):
    class StartingProcess:
        def __init__(self):
            self.polls = 0

        def poll(self):
            self.polls += 1
            return None if self.polls == 1 else 1

    def start(*args, **kwargs):
        kwargs["stdout"].write(b"ERROR: LockBusy\nApplication startup failed.\n")
        kwargs["stdout"].flush()
        return StartingProcess()

    @contextmanager
    def other_health(*args, **kwargs):
        class Response:
            status = 200
        yield Response()

    monkeypatch.setattr(support.subprocess, "Popen", start)
    monkeypatch.setattr(support.urllib.request, "urlopen", other_health)
    with pytest.raises(support.AppStartError, match="LockBusy"):
        support.start_app(tmp_path, "", port=8769, team_name="")
