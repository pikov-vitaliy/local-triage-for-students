"""Независимое состояние поддельного Hub для выбранного создания и синхронизации."""

from copy import deepcopy
import json
from urllib.parse import parse_qs, urlsplit

from app import hub_defects
from app.db import loads
from test_hub_defects import BLANK, SERVICE
from test_hub_pull import PullHub


class SelectedHub(PullHub):
    def __init__(self, count=3, extra_blank=False, lost_create=False, missing_first=False):
        super().__init__(count=count, defects=False)
        self.extra_blank = extra_blank
        self.lost_create = lost_create
        self.missing_first = missing_first
        for ident, issue in self.issues.items():
            issue["status"] = issue["issueBranchBriefData"][0]["status"] = "To verify"
            issue["fileName"], issue["lineNumber"] = f"part{ident}.c", str(ident + 2)

    def answer(self, request):
        path = urlsplit(request["path"])
        method = request["method"]
        if path.path == "/defects" and method == "GET":
            self.calls.append(deepcopy(request))
            entries = [{"id": i, "app": {"id": 7, "name": "Демо"}, "summary": d["summary"]}
                       for i, d in self.defects.items()]
            return 200, json.dumps({"filteredEntities": entries, "totalEntitiesCount": len(entries)})
        if path.path not in ("/defects/blank", "/defects/serviceInfo") and method == "GET":
            return super().answer(request)
        self.calls.append(deepcopy(request))
        if path.path == "/defects/blank":
            ids = parse_qs(path.query)["issueIds"][0].split(",")
            body = deepcopy(BLANK)
            body["linkedIssues"] = [{"id": int(i), "type": "SAST", "severity": 2,
                                     "lastScanTs": 1800000000000, "scanObject": {"id": 3, "url": None}} for i in ids]
            if self.extra_blank:
                body["linkedIssues"].append({"id": 999, "type": "SAST"})
            return 200, json.dumps(body)
        if path.path == "/defects/serviceInfo":
            return 200, json.dumps(SERVICE)
        if method == "POST" and path.path == "/defects":
            assert not self.defects, "второе создание"
            self.defects[555] = {**deepcopy(request["body"]), "id": 555, "createTs": 1800000000000,
                                 "updateTs": 1800000000000}
            if self.missing_first:
                self.defects[555]["linkedIssues"].pop()
            return (503, "") if self.lost_create else (200, '{"id":555}')
        if method == "POST" and path.path == "/defects/555/link":
            for ident in request["body"]["issueIds"]:
                self.defects[555]["linkedIssues"].append({"id": ident, "type": request["body"]["issueType"]})
            return 200, ""
        if method == "PUT" and path.path == "/defects/555":
            self.defects[555] = deepcopy(request["body"])
            return 200, ""
        raise AssertionError(request)


def drain(db, hub, project_id, progress=None):
    """Транспорт использует только сохранённый запрос. Ответы не дополняются локальными данными."""
    delivered = []
    for _ in range(20):
        if progress:
            progress()
        for row in db._all("SELECT * FROM hub_defects WHERE project_id=?", (project_id,)):
            hub_defects.sync(db, row)
        got = db.hub_claim("demo", "https://hub.example.org", 120, sync_protocol=2)
        if got is None:
            return delivered
        request = loads(got["op"]["request_json"], {})
        status, body = hub.answer(request)
        db.hub_result(got["attempt"]["id"], got["attempt"]["lease_token"],
                      {"status": status, "body_text": body, "error": "", "truncated": False})
        delivered.append(got["op"]["id"])
    raise AssertionError("цепочка не завершилась")
