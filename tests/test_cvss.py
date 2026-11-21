"""Оценка CVSS: версия из сохранённых сведений, диапазоны шкалы (3.x, 4.0 и 2.0), готовые отборы, свои границы,
отбор и числовая сортировка, разбор адреса страницы и его проверка.

Границы проверяются по spec из docs/sca-cvss-table.md: 0 · 0,1–3,9 · 4–6,9 · 7–8,9 · 9–10; «строго больше 7»
не равно «7 и выше»; нулевой балл не равен баллу отсутствующему; версия неизвестная не подменяется ни одной из
известных.
"""

from __future__ import annotations

import pytest

from app import cvss

V3 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
V4 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
V2 = "AV:N/AC:L/Au:N/C:P/I:P/A:P"


def group(**versions: float | None) -> dict:
    """Пакет с баллами по версиям: group(scores={"3.1": 9.8}) или group(scores={"": 5.0})."""
    scores = versions.pop("scores", None) or {}
    counts = versions.pop("counts", None) or {version: 1 for version in scores}
    return {"cvss_versions": scores, "cvss_counts": counts, **versions}


# ---------------------------------------------------------------------------- версия оценки

@pytest.mark.parametrize("value, expected", [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "3.1"),
    ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "3.0"),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "4.0"),
    ("  cvss:3.1/av:n/ac:l/pr:n/ui:n/s:u/c:h/i:h/a:h  ", "3.1"),
    ("AV:N/AC:L/Au:N/C:P/I:P/A:P", "2.0"),
    ("C:P/Au:N/AC:L/AV:N/I:P/A:P", "2.0"),                 # метрики в любом порядке
    # дополнительные (временные и средовые) метрики вектор не портят
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/CR:H/MAV:L", "3.1"),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:X/V:C", "4.0"),
])
def test_version_from_vector(value, expected):
    assert cvss.version_from_extra({"CVSS vector": value}) == expected
    assert cvss.version_of({"extra": {"Вектор CVSS": value}}) == expected


@pytest.mark.parametrize("value", [
    "CVSS:3.1garbage",                                     # версия есть, вектора нет
    "CVSS:3.1/AV:N",                                       # нет обязательных метрик
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",            # не хватает одной метрики
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/AV:L",   # повтор метрики
    "CVSS:3.1/AV:N/AC:X/PR:N/UI:N/S:U/C:H/I:H/A:H",        # значение не из своей шкалы
    "CVSS:3.1 AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",        # между версией и вектором посторонний текст
    "CVSS:9.9/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",        # такой версии нет
    "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",                 # вектор 3.1 без префикса – это не 2.0
])
def test_version_is_unknown_from_an_incomplete_or_wrong_vector(value):
    assert cvss.version_from_extra({"CVSS vector": value}) == cvss.UNKNOWN


@pytest.mark.parametrize("header, value, expected", [
    ("CVSS version", "3.1", "3.1"),
    ("Версия CVSS", "v4.0", "4.0"),
    ("CVSS", "CVSS 3.0", "3.0"),
    ("Версия оценки CVSS", "2.0", "2.0"),
    ("Версия оценки", "не указана", ""),
    ("Версия оценки", "1.0", ""),          # первой версии в отчётах нет
    ("Версия оценки", "4.1", ""),          # такой версии не существует
    ("Версия оценки", "3", ""),            # без десятых: 3.0 и 3.1 считаются по-разному
    ("Компонент", "3.1", ""),              # версия не берётся из колонки без названия версии
    ("CVSS metric", "2.0", ""),            # колонка метрики, а не версии оценки
    ("CVSS score", "3.1", ""),             # балл, а не версия: «3.1» здесь просто число
    ("Оценка CVSS", "9.8", ""),            # то же по-русски
    ("CVSS vector", "3.1", ""),            # вектор без метрик – не версия
    ("Component version", "3.1.5", ""),    # версия компонента, а не оценки
    ("Версия компонента", "3.1.5", ""),
    ("Версия библиотеки", "3.1", ""),
    ("Package version", "3.1.5", ""),
])
def test_version_from_version_column(header, value, expected):
    assert cvss.version_from_extra({header: value}) == expected


def test_version_without_any_data_is_unknown():
    assert cvss.version_from_extra({}) == cvss.UNKNOWN
    assert cvss.version_from_extra(None) == cvss.UNKNOWN
    assert cvss.version_of({}) == cvss.UNKNOWN
    assert cvss.version_of({"cvss": 9.8, "extra": {"Severity": "Critical"}}) == cvss.UNKNOWN
    # номер CVSS без версии и без вектора остаётся оценкой с неизвестной версией
    assert cvss.version_of({"cvss": 9.8}) == ""


def test_contradicting_metadata_leaves_the_version_unknown():
    # версия 3.1 в колонке и корректный вектор 4.0 – указания противоречат друг другу: балл один, версия
    # неизвестна. Порядок колонок в файле ничего не решает
    extra = {"CVSS version": "3.1", "Вектор": V4, "Severity": "Critical"}
    assert cvss.version_from_extra(extra) == cvss.UNKNOWN
    assert cvss.version_from_extra({key: extra[key] for key in ("Вектор", "Severity", "CVSS version")}) \
        == cvss.UNKNOWN


def test_vector_and_version_column_that_agree_give_the_version():
    assert cvss.version_from_extra({"CVSS version": "3.1", "CVSS vector": V3}) == "3.1"
    assert cvss.version_from_extra({"Версия CVSS": "v2.0", "Вектор": V2}) == "2.0"


def test_versions_never_above_four():
    assert cvss.VERSIONS == ("3.1", "3.0", "4.0", "2.0")
    assert all(version.split(".")[0] in {"2", "3", "4"} for version in cvss.VERSIONS)
    assert cvss.clean_version("CVSS:5.0/AV:N") == ""


# ---------------------------------------------------------------------------- шкала и готовые отборы

def test_bands_of_scale_3_and_4():
    keys = [band["key"] for band in cvss.bands("3.1")]
    assert keys == ["zero", "low", "medium", "high", "critical"]
    assert [band["key"] for band in cvss.bands("4.0")] == keys
    assert [band["key"] for band in cvss.bands("")] == keys


def test_bands_of_version_2_are_not_scale_3():
    keys = [band["key"] for band in cvss.bands("2.0")]
    assert keys == ["low", "medium", "high"]           # нулевой балл входит в низкий, критического нет
    assert not any(band["key"] in {"zero", "critical"} for band in cvss.bands("2.0"))
    high = cvss.preset("2.0", "high")
    assert (high["min"], high["max"]) == (7.0, 10.0)
    assert cvss.preset("2.0", "critical") is None
    assert cvss.preset("", "critical") is not None


def test_band_captions_come_from_the_bands_themselves():
    # подпись границ выводится из самих границ: у второй версии «высокий» – 7–10, а не 7–8,9 от другой шкалы
    assert [band["title"] for band in cvss.bands("3.1")] == ["0", "0,1–3,9", "4–6,9", "7–8,9", "9–10"]
    assert [band["title"] for band in cvss.bands("2.0")] == ["0–3,9", "4–6,9", "7–10"]


def test_version_title_is_honest_about_unknown():
    assert cvss.version_title("3.1") == "CVSS 3.1"
    assert cvss.version_title(cvss.UNKNOWN_CHOICE) == "без указания версии"
    assert cvss.version_title("") == ""                # без выбора версии подписи нет: балл из всех версий


def test_presets_separate_rule_from_scale():
    keys = [band["key"] for band in cvss.presets("")]
    assert keys == ["zero", "low", "medium", "high", "critical", "above7", "from7", "no_score"]
    above7, from7 = cvss.preset("", "above7"), cvss.preset("", "from7")
    assert above7["open_min"] is True and from7.get("open_min") is None
    assert above7["label"] == "Строго больше 7" and from7["label"] == "7 и выше"


@pytest.mark.parametrize("key, score, inside", [
    ("zero", 0.0, True), ("zero", 0.1, False), ("zero", None, False),
    ("low", 0.1, True), ("low", 3.9, True), ("low", 3.999, False), ("low", 4.0, False), ("low", 0.0, False),
    ("medium", 4.0, True), ("medium", 6.9, True), ("medium", 3.9, False), ("medium", 7.0, False),
    ("high", 7.0, True), ("high", 8.9, True), ("high", 6.9, False), ("high", 9.0, False),
    ("critical", 9.0, True), ("critical", 10.0, True), ("critical", 8.999, False),
    ("above7", 7.0, False), ("above7", 7.1, True), ("above7", 10.0, True),
    ("from7", 7.0, True), ("from7", 6.999, False), ("from7", 10.0, True),
    ("no_score", None, True), ("no_score", 0.0, False), ("no_score", 9.8, False),
])
def test_band_boundaries(key, score, inside):
    assert cvss.matches(score, cvss.preset("", key)) is inside


def test_band_boundaries_of_version_2():
    assert cvss.matches(0.0, cvss.preset("2.0", "low")) is True
    assert cvss.matches(3.9, cvss.preset("2.0", "low")) is True
    assert cvss.matches(4.0, cvss.preset("2.0", "medium")) is True
    assert cvss.matches(6.9, cvss.preset("2.0", "medium")) is True
    assert cvss.matches(7.0, cvss.preset("2.0", "high")) is True
    assert cvss.matches(10.0, cvss.preset("2.0", "high")) is True


def test_float_noise_at_the_border_does_not_split_band():
    # 3.9 в двоичном виде не ровно 3.9: сумма долей не должна выбрасывать балл из диапазона
    assert cvss.matches(0.1 + 0.2 + 0.3 + 0.3, cvss.preset("", "low")) is True
    assert cvss.matches(sum([0.1] * 39), cvss.preset("", "low")) is True


# ---------------------------------------------------------------------------- балл пакета по версиям

def test_score_without_version_is_maximum_of_all():
    view = group(scores={"3.1": 9.8, "4.0": 7.5, "": 5.0})
    assert cvss.score_of(view) == 9.8
    assert cvss.score_of(view, "4.0") == 7.5
    assert cvss.score_of(view, "2.0") is None       # оценок второй версии у пакета нет


def test_score_of_version_never_borrows_another_version():
    view = group(scores={"4.0": 7.5})
    assert cvss.score_of(view, "3.1") is None       # 7.5 – это 4.0, под 3.1 его не подставляем
    assert cvss.score_of(view, "4.0") == 7.5


def test_unknown_version_is_a_value_of_its_own():
    view = group(scores={"": 5.0})
    assert cvss.score_of(view) == 5.0
    assert cvss.score_of(view, "3.1") is None
    assert cvss.matches(cvss.score_of(view), cvss.preset("", "medium")) is True


def test_package_without_scores():
    assert cvss.score_of({"cvss_versions": {}, "cvss_counts": {}}) is None
    assert cvss.score_of({}) is None
    assert cvss.breakdown({}) == []
    assert cvss.score_of(group(scores={"": 9.8}), "") == 9.8


def test_breakdown_order_and_counts():
    view = group(scores={"2.0": 4.0, "4.0": 7.5, "3.1": 9.8, "": 2.0}, counts={"3.1": 2, "": 1})
    assert [part["version"] for part in cvss.breakdown(view)] == ["3.1", "4.0", "2.0", ""]
    assert cvss.breakdown(view)[0] == {"version": "3.1", "label": "CVSS 3.1", "score": 9.8, "count": 2}
    assert cvss.breakdown(view)[-1]["label"] == "версия не указана"


def test_versions_present_in_packages():
    views = [{"cvss_versions": {"2.0": 4.0}, "cvss_counts": {}},
             {"cvss_versions": {"3.1": 9.8}, "cvss_counts": {}},
             {"cvss_versions": {}, "cvss_counts": {}}]
    from app import sca
    choices = dict(sca.cvss_versions(views))
    assert choices["3.1"] == "CVSS 3.1" and choices["2.0"] == "CVSS 2.0"
    assert choices["4.0"] == "CVSS 4.0 (нет оценок)"
    assert set(choices) == {"3.1", "3.0", "4.0", "2.0", "?"}
    assert all("нет оценок" in label for _, label in sca.cvss_versions([]))


def test_cvss_views_keeps_an_iterable_that_is_not_a_list():
    from app import sca
    views = [group(component="a", scores={"3.1": 9.8, "": 5.0}), group(component="b", scores={})]
    prepared = sca.cvss_views(iter(views), "3.1")     # на входе может быть генератор: данные не теряются
    assert [view["component"] for view in prepared] == ["a", "b"]
    assert [view["cvss_score"] for view in prepared] == [9.8, None]
    assert [part["version"] for part in prepared[0]["cvss_parts"]] == ["3.1", ""]
    assert prepared[1]["cvss_parts"] == []


# ---------------------------------------------------------------------------- отбор и сортировка

def names(views) -> list[str]:
    return [view["component"] for view in views]


def test_select_by_band_and_bounds():
    views = [group(component="a", scores={"": 0.0}), group(component="b", scores={"": 3.9}),
             group(component="c", scores={"": 7.0}), group(component="d", scores={"": 9.8}),
             group(component="e", scores={})]
    high = cvss.select(views, "", cvss.preset("", "high"))
    assert names(high) == ["c"]
    assert names(cvss.select(views, "", cvss.preset("", "from7"))) == ["c", "d"]
    assert names(cvss.select(views, "", cvss.preset("", "above7"))) == ["d"]
    assert names(cvss.select(views, "", cvss.preset("", "no_score"))) == ["e"]
    assert names(cvss.select(views, "", cvss.bounds_item(3.9, 7.0))) == ["b", "c"]
    assert names(cvss.select(views, "", cvss.bounds_item(9.0, None))) == ["d"]
    assert names(cvss.select(views, "", cvss.bounds_item(None, 3.9))) == ["a", "b"]
    assert names(cvss.select(views, "", None)) == ["a", "b", "c", "d", "e"]


def test_select_with_version_counts_only_that_version():
    views = [group(component="a", scores={"3.1": 9.8, "4.0": 2.0}),
             group(component="b", scores={"4.0": 7.5}),
             group(component="c", scores={"3.1": 6.0})]
    assert names(cvss.select(views, "3.1", cvss.preset("3.1", "critical"))) == ["a"]
    assert names(cvss.select(views, "4.0", cvss.preset("3.1", "critical"))) == []
    assert names(cvss.select(views, "4.0", cvss.preset("4.0", "high"))) == ["b"]
    assert names(cvss.select(views, "4.0", cvss.preset("", "from7"))) == ["b"]
    # выбранная версия без отбора по баллу: показываются только пакеты с оценкой этой версии
    assert names(cvss.select(views, "3.1", None)) == ["a", "c"]
    assert names(cvss.select(views, "2.0", None)) == []


def test_sort_is_numeric_and_unknown_scores_go_last():
    views = [group(component="urgent-high", scores={"": 9.8}, urgent=True),
             group(component="zero", scores={"": 0.0}),
             group(component="none", scores={}),
             group(component="low", scores={"": 3.9}),
             group(component="high", scores={"": 7.0})]
    assert names(cvss.sort_views(views, "", "cvss_asc")) == ["zero", "low", "high", "urgent-high", "none"]
    assert names(cvss.sort_views(views, "", "cvss_desc")) == ["urgent-high", "high", "low", "zero", "none"]
    # без явного выбора порядок не меняется: срочные и по убыванию балла, как в отчёте
    assert names(cvss.sort_views(views, "", "")) == names(views)
    assert names(cvss.sort_views(views, "", "cvss_sideways")) == names(views)


def test_sort_ignores_urgent_first_and_uses_version():
    views = [group(component="a", scores={"3.1": 5.0, "4.0": 9.8}, urgent=True),
             group(component="b", scores={"3.1": 7.0, "4.0": 2.0}),
             group(component="c", scores={"": 1.0})]
    assert names(cvss.sort_views(views, "3.1", "cvss_desc")) == ["b", "a", "c"]
    assert names(cvss.sort_views(views, "4.0", "cvss_desc")) == ["a", "b", "c"]
    assert names(cvss.sort_views(views, "3.1", "cvss_asc")) == ["a", "b", "c"]


def test_sort_ties_broken_by_name():
    views = [group(component="beta", scores={"": 5.0}), group(component="Alpha", scores={"": 5.0})]
    assert names(cvss.sort_views(views, "", "cvss_desc")) == ["Alpha", "beta"]


# ---------------------------------------------------------------------------- разбор адреса

def test_parse_empty_address():
    result = cvss.parse({})
    assert (result["preset"], result["min"], result["max"], result["version"], result["sort"]) == ("", None, None, "", "")
    assert result["errors"] == [] and result["active"] is False


def test_parse_preset_and_version():
    result = cvss.parse({"cvss": "critical", "cvss_version": "4.0", "sort": "cvss_asc"})
    assert result["preset"] == "critical" and result["version"] == "4.0" and result["sort"] == "cvss_asc"
    assert result["item"] == cvss.preset("4.0", "critical")
    assert result["active"] is True


def test_parse_bounds_accept_comma_and_decimal():
    result = cvss.parse({"cvss_min": "7,5", "cvss_max": " 9 "})
    assert (result["min"], result["max"], result["errors"]) == (7.5, 9.0, [])
    assert cvss.parse({"cvss_min": "0"})["min"] == 0.0
    assert cvss.parse({"cvss_max": "10"})["max"] == 10.0
    assert cvss.parse({"cvss_min": ""})["min"] is None


@pytest.mark.parametrize("params, piece", [
    ({"cvss_min": "abc"}, "числом от 0 до 10"),
    ({"cvss_min": "nan"}, "числом от 0 до 10"),
    ({"cvss_min": "inf"}, "числом от 0 до 10"),
    ({"cvss_min": "-1"}, "от 0 до 10"),
    ({"cvss_max": "10.5"}, "от 0 до 10"),
    ({"cvss_min": "9", "cvss_max": "7"}, "Нижняя граница 9 больше верхней 7"),
    ({"cvss": "нет такого"}, "неизвестен"),
    ({"cvss": "critical", "cvss_version": "2.0"}, "не применим к CVSS 2.0"),
    ({"cvss_version": "5.0"}, "неизвестна"),
    ({"sort": "cvss_up"}, "неизвестна"),
])
def test_parse_reports_every_bad_value(params, piece):
    result = cvss.parse(params)
    assert any(piece in error for error in result["errors"]), result["errors"]


def test_parse_bad_value_is_not_a_silent_filter():
    result = cvss.parse({"cvss_min": "abc"})
    assert result["min"] is None and result["item"] is None and result["preset"] == ""
    assert result["raw"]["cvss_min"] == "abc"           # значение остаётся в поле, чтобы его исправили
    assert cvss.parse({"sort": "cvss_up"})["sort"] == ""
    assert cvss.parse({"cvss_version": "9.9"})["version"] == ""
    assert cvss.parse({"cvss": "critical", "cvss_version": "2.0"})["preset"] == ""
    flipped = cvss.parse({"cvss_min": "9", "cvss_max": "7"})
    assert (flipped["min"], flipped["max"]) == (None, None)


def test_parse_never_applies_half_of_a_wrong_range():
    # неверная нижняя граница при верной верхней: половину диапазона молча применять нельзя
    result = cvss.parse({"cvss_min": "abc", "cvss_max": "9"})
    assert (result["min"], result["max"], result["item"], result["preset"]) == (None, None, None, "")
    assert result["active"] is False and any("cvss_min" in error for error in result["errors"])
    other = cvss.parse({"cvss_max": "abc", "cvss_min": "7"})
    assert (other["min"], other["max"], other["item"]) == (None, None, None)
    assert cvss.parse({"cvss_max": "11", "cvss_min": "7"})["min"] is None   # весь диапазон снят
    # неверная граница снимает и готовый отбор из того же адреса: показывается полный список
    together = cvss.parse({"cvss": "from7", "cvss_min": "abc"})
    assert together["preset"] == "" and together["item"] is None


def test_field_number_shows_the_value_the_address_means():
    # поле типа number не показывает десятичную запятую: в форме должно быть то же число, что в отборе
    assert cvss.field_number("6,9") == "6.9"
    assert cvss.field_number(" 7 ") == "7"
    assert cvss.field_number("abc") == "abc"
    assert cvss.field_number(None) == "" and cvss.field_number("") == ""


def test_parse_bad_value_does_not_raise_on_junk():
    junk = {"cvss_min": "%00", "cvss_max": "1e999", "cvss": "…", "sort": "cvss;drop", "cvss_version": "3.2",
            "cvss_min ": " ", "": ""}
    for name, value in junk.items():
        result = cvss.parse({name: value})
        assert isinstance(result["errors"], list) and (result["preset"], result["sort"]) == ("", "")
        assert result["min"] is None and result["max"] is None and result["version"] == ""
