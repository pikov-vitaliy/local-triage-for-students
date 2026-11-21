"""Тексты в Hub как написаны (ADR-0149) вместе с идентичностью пакета (план dev17): прежние правила текста набора SCA
собираются с тем же коротким именем пакета, что и нынешние, и страница масштаба находит набор под ключом эффективной
идентичности (ревью Codex слияния main в dev17, круг 1)."""

from __future__ import annotations

from app import package_identity, sca_text
from app.models import Finding
from app.sca_contract import input_ref
from test_web import web  # noqa: F401


def _identity_set(web, monkeypatch, note: str):
    """Находка SCA npm «core 1.2.3», которой Hub сообщил область: эффективное имя «@scope/core». Набор 0 с решением
    «Обновить» и целевой версией вручную, проверка версии – «verified». (pid, view)."""
    from app.routes import sca as sca_routes
    from test_hub_status_routes import project as hub_project, sca as hub_sca
    monkeypatch.setattr(sca_text, "check_version", lambda *a, **k: sca_text.VersionCheck("verified", ""))
    f = hub_sca("81")
    f.component, f.build_type = "core", "npm"
    pid = hub_project(web, [f])
    db = web.app.state.db
    with db._tx() as c:
        c.execute("UPDATE findings SET pkg_ecosystem = 'npm', pkg_name = '@scope/core', pkg_source = 'hub',"
                  " pkg_note = '', pkg_scope = 'h|7' WHERE project_id = ? AND hub_id = '81'", (pid,))
    data = db.get_finding_by_hub_id(pid, "81")["data"]
    assert package_identity.of(data)[1] == "@scope/core", package_identity.of(data)
    ref = input_ref(*package_identity.of(data))
    monkeypatch.setattr(sca_routes, "decision_state", lambda f, review, latest, row=None: ("ok", "true_positive"))
    db.save_sca_package_text(pid, ref, 0, expect_revision=0, explanation="CVE-2099-0001: разбор архива читает записи "
                             "без проверки.", ast={}, target_version="2.0.0", target_basis="manual",
                             version_checked_sig="", text_checked_sig="", text_sig="", recommendation_note=note)
    finding = Finding.from_dict(db.get_finding_by_hub_id(pid, "81")["data"])
    return pid, sca_routes.sca_defect(db, web.app.state.feeds, pid, finding, db.get_review(pid, "81"))


def test_prior_set_body_uses_the_effective_package_name(web, monkeypatch):  # noqa: F811
    """Тело набора прежних правил (body_v4) – с тем же коротким именем пакета, что и нынешнее: до слияния dev17 уже
    называл пакет эффективным именем, и подписи «Текст проверен», поставленные тогда, должны узнаваться."""
    names: list[tuple[str, bool]] = []
    real = sca_text.body

    def spy(component, *args, **kwargs):
        names.append((component, bool(kwargs.get("legacy_note"))))
        return real(component, *args, **kwargs)
    monkeypatch.setattr(sca_text, "body", spy)
    _, view = _identity_set(web, monkeypatch, note="Первый абзац мер.\n\nВторой абзац.")
    assert view["ready"], view["problems"]
    assert "@scope/core" in view["body"]
    assert view["legacy_text_sig_v4"], "по прежним правилам пустая строка добавления не входила – тело другое"
    legacy = [name for name, is_legacy in names if is_legacy]
    assert legacy and set(legacy) == {"@scope/core"}, names


def test_scale_report_finds_a_set_under_the_effective_identity(web, monkeypatch):  # noqa: F811
    """Страница масштаба группирует находки по эффективной тройке, как сборщик карточки: набор, сохранённый под ключом
    «npm, @scope/core, 1.2.3», в отчёт попадает."""
    from app import hub_text_scale
    pid, view = _identity_set(web, monkeypatch, note="Первый абзац мер.\n\nВторой абзац.")
    assert view["legacy_text_sig_v4"], view["problems"]
    report = hub_text_scale.report(web.app.state.db, web.app.state.settings, pid, web.app.state.feeds)
    assert [m["hub_id"] for s in report["sets"] for m in s["members"]] == ["81"], report["sets"]
    assert report["sets"][0]["component"] == "@scope/core"
