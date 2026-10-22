"""Country vocabulary shared by connectors and the Security Operations Center (v0.10.30).

Connectors hand NodeWatch whatever their logs say about where an address is ("US", "United States",
"10.0.0.0-10.255.255.255", "Korea Republic of" …); :func:`country_code` turns that into an ISO 3166-1
alpha-2 code, or "" for private ranges and anything unknown. Nothing here looks an address up: NodeWatch
ships no GeoIP database and never sends addresses anywhere to locate them. A source that reports no country
simply produces events without one.

``COUNTRIES`` holds a display name, an approximate centre (latitude, longitude) and a region per code, for
the SOC's origin map. Centres are deliberately rough (a few degrees): they place a country on a world-shaped
canvas, they are not a geography.
"""

from __future__ import annotations

import re
from typing import Any

# code: (name, lat, lon, region)
COUNTRIES: dict[str, tuple[str, float, float, str]] = {
    # North America
    "US": ("United States", 39.5, -98.5, "North America"),
    "CA": ("Canada", 56.0, -106.0, "North America"),
    "MX": ("Mexico", 23.6, -102.5, "North America"),
    "GT": ("Guatemala", 15.7, -90.2, "North America"),
    "HN": ("Honduras", 15.2, -86.2, "North America"),
    "SV": ("El Salvador", 13.8, -88.9, "North America"),
    "NI": ("Nicaragua", 12.9, -85.2, "North America"),
    "CR": ("Costa Rica", 9.7, -84.0, "North America"),
    "PA": ("Panama", 8.5, -80.8, "North America"),
    "CU": ("Cuba", 21.5, -79.5, "North America"),
    "DO": ("Dominican Republic", 18.7, -70.2, "North America"),
    "HT": ("Haiti", 19.0, -72.3, "North America"),
    "JM": ("Jamaica", 18.1, -77.3, "North America"),
    "PR": ("Puerto Rico", 18.2, -66.5, "North America"),
    "BS": ("Bahamas", 25.0, -77.4, "North America"),
    "TT": ("Trinidad and Tobago", 10.7, -61.2, "North America"),
    "BZ": ("Belize", 17.2, -88.5, "North America"),
    # South America
    "BR": ("Brazil", -10.8, -52.9, "South America"),
    "AR": ("Argentina", -35.4, -65.2, "South America"),
    "CL": ("Chile", -33.5, -71.0, "South America"),
    "CO": ("Colombia", 4.1, -73.0, "South America"),
    "PE": ("Peru", -9.2, -75.0, "South America"),
    "VE": ("Venezuela", 7.1, -66.2, "South America"),
    "EC": ("Ecuador", -1.4, -78.4, "South America"),
    "BO": ("Bolivia", -16.7, -64.7, "South America"),
    "PY": ("Paraguay", -23.4, -58.4, "South America"),
    "UY": ("Uruguay", -32.8, -56.0, "South America"),
    "GY": ("Guyana", 4.9, -58.9, "South America"),
    "SR": ("Suriname", 4.0, -56.0, "South America"),
    # Europe
    "GB": ("United Kingdom", 54.0, -2.5, "Europe"),
    "IE": ("Ireland", 53.2, -8.2, "Europe"),
    "FR": ("France", 46.6, 2.4, "Europe"),
    "DE": ("Germany", 51.1, 10.4, "Europe"),
    "NL": ("Netherlands", 52.2, 5.5, "Europe"),
    "BE": ("Belgium", 50.6, 4.6, "Europe"),
    "LU": ("Luxembourg", 49.8, 6.1, "Europe"),
    "CH": ("Switzerland", 46.8, 8.2, "Europe"),
    "AT": ("Austria", 47.6, 14.1, "Europe"),
    "ES": ("Spain", 40.2, -3.6, "Europe"),
    "PT": ("Portugal", 39.6, -8.0, "Europe"),
    "IT": ("Italy", 42.8, 12.6, "Europe"),
    "DK": ("Denmark", 56.0, 10.0, "Europe"),
    "NO": ("Norway", 61.5, 9.0, "Europe"),
    "SE": ("Sweden", 62.0, 15.0, "Europe"),
    "FI": ("Finland", 64.5, 26.0, "Europe"),
    "IS": ("Iceland", 64.9, -18.6, "Europe"),
    "PL": ("Poland", 52.1, 19.4, "Europe"),
    "CZ": ("Czechia", 49.8, 15.5, "Europe"),
    "SK": ("Slovakia", 48.7, 19.7, "Europe"),
    "HU": ("Hungary", 47.2, 19.4, "Europe"),
    "RO": ("Romania", 45.9, 24.9, "Europe"),
    "BG": ("Bulgaria", 42.7, 25.5, "Europe"),
    "GR": ("Greece", 39.1, 22.0, "Europe"),
    "HR": ("Croatia", 45.1, 15.6, "Europe"),
    "SI": ("Slovenia", 46.1, 14.8, "Europe"),
    "RS": ("Serbia", 44.0, 20.9, "Europe"),
    "BA": ("Bosnia and Herzegovina", 44.2, 17.8, "Europe"),
    "AL": ("Albania", 41.1, 20.0, "Europe"),
    "MK": ("North Macedonia", 41.6, 21.7, "Europe"),
    "ME": ("Montenegro", 42.8, 19.2, "Europe"),
    "XK": ("Kosovo", 42.6, 20.9, "Europe"),
    "MD": ("Moldova", 47.2, 28.5, "Europe"),
    "UA": ("Ukraine", 49.0, 31.4, "Europe"),
    "BY": ("Belarus", 53.7, 28.0, "Europe"),
    "LT": ("Lithuania", 55.2, 23.9, "Europe"),
    "LV": ("Latvia", 56.9, 24.6, "Europe"),
    "EE": ("Estonia", 58.6, 25.0, "Europe"),
    "RU": ("Russia", 60.0, 90.0, "Europe"),
    "CY": ("Cyprus", 35.1, 33.4, "Europe"),
    "MT": ("Malta", 35.9, 14.4, "Europe"),
    # Middle East
    "TR": ("Türkiye", 39.0, 35.2, "Middle East"),
    "IL": ("Israel", 31.4, 35.0, "Middle East"),
    "PS": ("Palestine", 31.9, 35.2, "Middle East"),
    "JO": ("Jordan", 31.2, 36.5, "Middle East"),
    "LB": ("Lebanon", 33.9, 35.9, "Middle East"),
    "SY": ("Syria", 35.0, 38.5, "Middle East"),
    "IQ": ("Iraq", 33.2, 43.7, "Middle East"),
    "IR": ("Iran", 32.4, 53.7, "Middle East"),
    "SA": ("Saudi Arabia", 23.9, 45.1, "Middle East"),
    "AE": ("United Arab Emirates", 23.4, 53.8, "Middle East"),
    "QA": ("Qatar", 25.3, 51.2, "Middle East"),
    "KW": ("Kuwait", 29.3, 47.5, "Middle East"),
    "BH": ("Bahrain", 26.0, 50.5, "Middle East"),
    "OM": ("Oman", 21.5, 55.9, "Middle East"),
    "YE": ("Yemen", 15.6, 48.5, "Middle East"),
    "GE": ("Georgia", 42.3, 43.4, "Middle East"),
    "AM": ("Armenia", 40.1, 45.0, "Middle East"),
    "AZ": ("Azerbaijan", 40.1, 47.6, "Middle East"),
    # Asia
    "CN": ("China", 35.9, 104.2, "Asia"),
    "HK": ("Hong Kong", 22.3, 114.2, "Asia"),
    "MO": ("Macao", 22.2, 113.5, "Asia"),
    "TW": ("Taiwan", 23.7, 121.0, "Asia"),
    "JP": ("Japan", 36.2, 138.3, "Asia"),
    "KR": ("South Korea", 35.9, 127.8, "Asia"),
    "KP": ("North Korea", 40.3, 127.5, "Asia"),
    "MN": ("Mongolia", 46.9, 103.8, "Asia"),
    "IN": ("India", 21.0, 78.9, "Asia"),
    "PK": ("Pakistan", 30.4, 69.3, "Asia"),
    "BD": ("Bangladesh", 23.7, 90.4, "Asia"),
    "LK": ("Sri Lanka", 7.9, 80.8, "Asia"),
    "NP": ("Nepal", 28.4, 84.1, "Asia"),
    "AF": ("Afghanistan", 33.9, 67.7, "Asia"),
    "KZ": ("Kazakhstan", 48.0, 66.9, "Asia"),
    "UZ": ("Uzbekistan", 41.4, 64.6, "Asia"),
    "TM": ("Turkmenistan", 38.97, 59.6, "Asia"),
    "KG": ("Kyrgyzstan", 41.2, 74.8, "Asia"),
    "TJ": ("Tajikistan", 38.9, 71.3, "Asia"),
    "TH": ("Thailand", 15.9, 100.99, "Asia"),
    "VN": ("Vietnam", 14.1, 108.3, "Asia"),
    "KH": ("Cambodia", 12.6, 104.99, "Asia"),
    "LA": ("Laos", 19.9, 102.5, "Asia"),
    "MM": ("Myanmar", 21.9, 95.96, "Asia"),
    "MY": ("Malaysia", 4.2, 102.0, "Asia"),
    "SG": ("Singapore", 1.35, 103.8, "Asia"),
    "ID": ("Indonesia", -0.8, 113.9, "Asia"),
    "PH": ("Philippines", 12.9, 121.8, "Asia"),
    # Africa
    "EG": ("Egypt", 26.8, 30.8, "Africa"),
    "LY": ("Libya", 26.3, 17.2, "Africa"),
    "TN": ("Tunisia", 33.9, 9.5, "Africa"),
    "DZ": ("Algeria", 28.0, 1.7, "Africa"),
    "MA": ("Morocco", 31.8, -7.1, "Africa"),
    "SD": ("Sudan", 12.9, 30.2, "Africa"),
    "ET": ("Ethiopia", 9.1, 40.5, "Africa"),
    "KE": ("Kenya", -0.02, 37.9, "Africa"),
    "TZ": ("Tanzania", -6.4, 34.9, "Africa"),
    "UG": ("Uganda", 1.4, 32.3, "Africa"),
    "NG": ("Nigeria", 9.1, 8.7, "Africa"),
    "GH": ("Ghana", 7.9, -1.0, "Africa"),
    "CI": ("Côte d'Ivoire", 7.5, -5.5, "Africa"),
    "SN": ("Senegal", 14.5, -14.5, "Africa"),
    "CM": ("Cameroon", 7.4, 12.4, "Africa"),
    "CD": ("DR Congo", -4.0, 21.8, "Africa"),
    "AO": ("Angola", -11.2, 17.9, "Africa"),
    "ZA": ("South Africa", -30.6, 22.9, "Africa"),
    "ZW": ("Zimbabwe", -19.0, 29.2, "Africa"),
    "ZM": ("Zambia", -13.1, 27.8, "Africa"),
    "MZ": ("Mozambique", -18.7, 35.5, "Africa"),
    "MG": ("Madagascar", -18.8, 46.9, "Africa"),
    "SO": ("Somalia", 5.2, 46.2, "Africa"),
    "ML": ("Mali", 17.6, -4.0, "Africa"),
    "NE": ("Niger", 17.6, 8.1, "Africa"),
    "TD": ("Chad", 15.5, 18.7, "Africa"),
    "BJ": ("Benin", 9.3, 2.3, "Africa"),
    "TG": ("Togo", 8.6, 0.8, "Africa"),
    "BF": ("Burkina Faso", 12.2, -1.6, "Africa"),
    "RW": ("Rwanda", -1.9, 29.9, "Africa"),
    "MU": ("Mauritius", -20.3, 57.6, "Africa"),
    "BW": ("Botswana", -22.3, 24.7, "Africa"),
    "NA": ("Namibia", -22.96, 18.5, "Africa"),
    # Oceania
    "AU": ("Australia", -25.3, 133.8, "Oceania"),
    "NZ": ("New Zealand", -41.0, 174.0, "Oceania"),
    "PG": ("Papua New Guinea", -6.3, 143.96, "Oceania"),
    "FJ": ("Fiji", -17.7, 178.1, "Oceania"),
}

# Names and spellings log sources use, lower-cased, with punctuation removed.
_ALIASES = {
    "usa": "US",
    "united states of america": "US",
    "uk": "GB",
    "great britain": "GB",
    "england": "GB",
    "russian federation": "RU",
    "korea republic of": "KR",
    "republic of korea": "KR",
    "korea": "KR",
    "korea democratic peoples republic of": "KP",
    "iran islamic republic of": "IR",
    "viet nam": "VN",
    "turkey": "TR",
    "turkiye": "TR",
    "czech republic": "CZ",
    "taiwan province of china": "TW",
    "hong kong sar": "HK",
    "moldova republic of": "MD",
    "syrian arab republic": "SY",
    "lao peoples democratic republic": "LA",
    "tanzania united republic of": "TZ",
    "congo the democratic republic of the": "CD",
    "venezuela bolivarian republic of": "VE",
    "bolivia plurinational state of": "BO",
    "macedonia": "MK",
    "the netherlands": "NL",
    "holland": "NL",
    "ivory coast": "CI",
    "cote divoire": "CI",
}
_BY_NAME = {re.sub(r"[^a-z ]", "", v[0].lower()).strip(): k for k, v in COUNTRIES.items()}
# Two-letter codes some sources use for regions rather than countries.
_NOT_COUNTRIES = {"EU", "AP", "A1", "A2", "O1", "ZZ", "XX", "--"}


def country_code(value: Any) -> str:
    """ISO 3166-1 alpha-2 code for a country code or name a source reports; "" for private ranges,
    regions and anything not recognised."""
    if isinstance(value, dict):
        value = value.get("value") or value.get("code") or value.get("name") or ""
    text = str(value or "").strip()
    if not text or any(ch.isdigit() for ch in text):  # "10.0.0.0-10.255.255.255", "192.168.0.0-…"
        return ""
    if len(text) == 2 and text.isalpha():
        code = text.upper()
        return "" if code in _NOT_COUNTRIES else code
    key = re.sub(r"[^a-z ]", "", text.lower().replace(",", " ")).strip()
    key = re.sub(r"\s+", " ", key)
    return _ALIASES.get(key) or _BY_NAME.get(key, "")


def country_name(code: str) -> str:
    row = COUNTRIES.get(str(code or "").upper())
    return row[0] if row else str(code or "")


def country_point(code: str) -> dict[str, Any] | None:
    row = COUNTRIES.get(str(code or "").upper())
    if not row:
        return None
    return {"code": code.upper(), "name": row[0], "lat": row[1], "lon": row[2], "region": row[3]}
