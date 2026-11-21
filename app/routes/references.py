"""Отсутствующая запись текущего каталога: причина и возврат к рабочей задаче."""
from urllib.parse import urlencode, urlsplit

from fastapi.responses import JSONResponse

from app.navigation import PROJECT_PAGE, clean_url, reference_url
from app.routes.common import render


def missing_reference(request, kind, value, key, message, meta):
    """404 различает неверный ID, незагруженный фид и отсутствующую в нём запись."""
    reason = "invalid" if not key else "not-loaded" if not meta else "missing"
    if reason == "invalid":
        message = f"Это не номер записи {kind.upper()}."
    if "text/html" not in request.headers.get("accept", ""):
        return JSONResponse({"detail": message}, status_code=404)
    number = key.split("-")[-1] if key else ""
    original = f"https://{kind}.mitre.org/data/definitions/{number}.html" if key else ""
    back = clean_url(request.query_params.get("back", ""), article=True)
    if not reference_url(back) and not PROJECT_PAGE.fullmatch(urlsplit(back).path):
        back = ""
    return render(request, "reference-missing.html", {
        "kind": kind, "key": key, "requested": str(value)[:80], "reason": reason,
        "message": message, "meta": meta or {}, "original": original, "back_url": back,
        "search_url": f"/{kind}?" + urlencode({"q": key}) if key else f"/{kind}",
    }, status_code=404)
