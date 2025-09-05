#!/usr/bin/env python3
"""
MITRE TTP Web Tracker — Streamlit-ready version.
Provides a fetch_news() function for import in dashboards.
"""
from __future__ import annotations
import re
import requests
import feedparser
import pandas as pd
from bs4 import BeautifulSoup
from datetime import datetime, timedelta, timezone
from dateutil import parser as dtparser
import tldextract
import unicodedata
import ipaddress
import warnings

warnings.filterwarnings("ignore")

# Optional country support
try:
    import pycountry
    PYCOUNTRY_OK = True
except Exception:
    pycountry = None
    PYCOUNTRY_OK = False

# Small alias tables
_ALIASES = {
    "usa": "United States", "us": "United States", "u.s.": "United States",
    "uk": "United Kingdom", "u.k.": "United Kingdom",
    "south korea": "South Korea", "north korea": "North Korea",
    "russia": "Russia", "china": "China", "india": "India",
    "iran": "Iran", "uae": "United Arab Emirates",
}

_NATIVE_ALIAS_TO_EN = {
    "sverige": "Sweden", "suomi": "Finland", "españa": "Spain", "deutschland": "Germany"
}

_NAME_TO_ALPHA = {}
_ALPHA_TO_NAME = {}
if PYCOUNTRY_OK:
    try:
        for c in pycountry.countries:
            names = {getattr(c, "name", "")}
            if hasattr(c, "official_name"):
                names.add(c.official_name)
            if hasattr(c, "common_name"):
                names.add(c.common_name)
            if hasattr(c, "alpha_2"):
                _ALPHA_TO_NAME[c.alpha_2.upper()] = c.name
            if hasattr(c, "alpha_3"):
                _ALPHA_TO_NAME[c.alpha_3.upper()] = c.name
            for n in names:
                if n:
                    _NAME_TO_ALPHA[n.lower()] = c.alpha_2
    except Exception:
        _NAME_TO_ALPHA = {}
        _ALPHA_TO_NAME = {}

# Optional spaCy NER
try:
    import spacy
    try:
        nlp = spacy.load("xx_ent_wiki_sm")
    except Exception:
        try:
            nlp = spacy.load("en_core_web_sm")
        except Exception:
            nlp = None
    SPACY_OK = nlp is not None
except Exception:
    SPACY_OK = False
    nlp = None

# Feeds
FEEDS = [
    "https://thecyberexpress.com/feed/",
    "https://cybersecuritynews.com/feed/",
    "https://dailycybersecuritynews.com/feed/",
    "https://securityriskadvisors.com/feed/",
]

# TTP mappings (simplified for brevity)
MAPPINGS = {
    r"\bsocial\s*engineering\b": {"desc": ["Social Engineering (T1566 / TA0001)"]},
    r"\bphishing\b": {"desc": ["Phishing (T1566.002)"]},
}

# Actor patterns (simplified)
ACTOR_PATTERNS = {
    "APT28 (Fancy Bear / Sofacy)": [r"\bapt28\b", r"\bsofacy\b"],
    "APT29 (Cozy Bear / The Dukes)": [r"\bapt29\b"],
}

HEADERS = {"User-Agent": "TTP-Tracker/1.0"}
REQ_TIMEOUT = 20

# ------------------ GeoIP Resolver ------------------
try:
    import geoip2.database
    class GeoIPResolver:
        def __init__(self, mmdb_path="GeoLite2-Country.mmdb"):
            self.reader = geoip2.database.Reader(mmdb_path)
        def resolve(self, ip):
            try:
                resp = self.reader.country(ip)
                return resp.country.name
            except Exception:
                return None
except Exception:
    class GeoIPResolver:
        def resolve(self, ip): return None

# ------------------ Utilities ------------------
def _normalize_text_for_match(s: str) -> str:
    if not isinstance(s, str):
        return ""
    s = unicodedata.normalize("NFKD", s)
    return "".join(ch for ch in s if not unicodedata.combining(ch)).lower().strip()

def parse_when(entry_date):
    if not entry_date:
        return None
    try:
        dt = dtparser.parse(str(entry_date))
        if not dt.tzinfo:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    except Exception:
        return None

def fetch_article_text(url):
    try:
        resp = requests.get(url, headers=HEADERS, timeout=REQ_TIMEOUT)
        resp.raise_for_status()
    except Exception:
        return ""
    soup = BeautifulSoup(resp.text, "html.parser")
    for tag in soup(["script", "style", "noscript", "svg", "footer", "nav", "aside", "form"]):
        tag.decompose()
    candidates = []
    for sel in ["article", "main", "div.post", "div.entry-content", "div#content"]:
        for el in soup.select(sel):
            text = el.get_text(" ", strip=True)
            if text:
                candidates.append(text)
    if not candidates:
        return soup.get_text(" ", strip=True)[:200000]
    return max(candidates, key=len)[:200000]

def classify(text):
    matched_desc = set()
    for pattern, info in MAPPINGS.items():
        if re.search(pattern, text, re.I):
            matched_desc.update(info.get("desc", []))
    return sorted(matched_desc)

def detect_actor(text):
    lowered = text.lower()
    for actor, patterns in ACTOR_PATTERNS.items():
        for p in patterns:
            if re.search(p, lowered):
                return actor
    return ""

def map_to_country(candidate: str):
    if not candidate or not isinstance(candidate, str):
        return None
    cand_norm = _normalize_text_for_match(candidate)
    if cand_norm in _ALIASES:
        return _ALIASES[cand_norm]
    if cand_norm in _NATIVE_ALIAS_TO_EN:
        return _NATIVE_ALIAS_TO_EN[cand_norm]
    if PYCOUNTRY_OK and cand_norm:
        if cand_norm in _NAME_TO_ALPHA:
            try:
                alpha = _NAME_TO_ALPHA[cand_norm]
                return _ALPHA_TO_NAME.get(alpha.upper())
            except Exception:
                pass
    return None

def detect_countries(text: str, url: str | None = None) -> list:
    seen = set()
    results = []
    if SPACY_OK and nlp is not None:
        try:
            doc = nlp(text)
            for ent in doc.ents:
                if ent.label_ in ("GPE", "LOC"):
                    mapped = map_to_country(ent.text.strip())
                    if mapped and mapped not in seen:
                        seen.add(mapped)
                        results.append(mapped)
        except Exception:
            pass
    # Aliases
    text_lower = text.lower()
    for native, eng in _NATIVE_ALIAS_TO_EN.items():
        if re.search(r"\b" + re.escape(native) + r"\b", text_lower, flags=re.I) and eng not in seen:
            seen.add(eng)
            results.append(eng)
    for alias, eng in _ALIASES.items():
        if re.search(r"\b" + re.escape(alias) + r"\b", text_lower, flags=re.I) and eng not in seen:
            seen.add(eng)
            results.append(eng)
    if url:
        try:
            ext = tldextract.extract(url)
            suffix = (ext.suffix or "").split(".")[-1]
            if suffix and len(suffix) == 2 and PYCOUNTRY_OK:
                cc = pycountry.countries.get(alpha_2=suffix.upper())
                if cc and cc.name not in seen:
                    seen.add(cc.name)
                    results.append(cc.name)
        except Exception:
            pass
    return results

def extract_ips(text):
    return re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)

def merge_listlike(series):
    out = []
    for v in series:
        if isinstance(v, list):
            out.extend(v)
        elif pd.isna(v) or v is None:
            continue
        elif isinstance(v, str) and v.strip() == "":
            continue
        else:
            out.append(v)
    seen = set()
    final = []
    for item in out:
        if item is None:
            continue
        s = str(item).strip()
        if not s:
            continue
        key = _normalize_text_for_match(s)
        if key in seen:
            continue
        seen.add(key)
        final.append(s)
    return final

def pad_lists(list_of_lists):
    def ensure_list(x):
        if x is None: return []
        if isinstance(x, list): return x
        if isinstance(x, str) and x.strip() == "": return []
        if isinstance(x, str): return [x]
        return [x]
    prepared = [ensure_list(x) for x in list_of_lists]
    max_len = max((len(l) for l in prepared), default=0)
    padded = [l + [""] * (max_len - len(l)) for l in prepared]
    return padded, max_len

def normalize_domain(url):
    try:
        ext = tldextract.extract(url)
        return ".".join(part for part in [ext.domain, ext.suffix] if part)
    except Exception:
        return ""

def poll_feed(url, since, GEOIP):
    items = []
    parsed = feedparser.parse(url)
    for e in parsed.entries:
        link = e.get("link")
        title = (e.get("title") or "").strip()
        published = parse_when(e.get("published") or e.get("updated"))
        if not published or published < since:
            continue
        summary = BeautifulSoup(e.get("summary", ""), "html.parser").get_text(" ", strip=True)
        full_text = fetch_article_text(link) if link else ""
        blob = "\n".join([title, summary, full_text])
        ttp_desc = classify(blob)
        countries = detect_countries(blob, link)
        for ip in extract_ips(blob):
            geo_country = GEOIP.resolve(ip)
            if geo_country and geo_country not in countries:
                countries.append(geo_country)
        actor = detect_actor(blob)
        items.append({
            "published_utc": published,
            "source": normalize_domain(link),
            "title": title,
            "url": link,
            "ttp_desc": ttp_desc,
            "threat_actor": actor,
            "affected_countries": countries,
        })
    return items

# ------------------ Public function ------------------
def fetch_news(days=7):
    """Fetches recent articles and returns a pandas DataFrame with merged TTPs and countries."""
    since = datetime.now() - timedelta(days=days)
    GEOIP = GeoIPResolver()
    all_items = []
    seen_urls = set()
    for feed in FEEDS:
        try:
            items = poll_feed(feed, since, GEOIP)
            for itm in items:
                if itm['url'] not in seen_urls:
                    all_items.append(itm)
                    seen_urls.add(itm['url'])
        except Exception:
            continue
    if not all_items:
        return pd.DataFrame()
    df = pd.DataFrame(all_items)
    df["affected_countries"] = df.get("affected_countries", [[] for _ in range(len(df))])
    df = df.groupby(['url', 'title'], as_index=False).agg({
        'published_utc': 'first',
        'source': 'first',
        'ttp_desc': lambda x: merge_listlike(x),
        'threat_actor': 'first',
        'affected_countries': lambda x: merge_listlike(x),
    })
    # Expand countries
    padded_countries, max_countries = pad_lists(df["affected_countries"].tolist())
    df_countries = pd.DataFrame(padded_countries, columns=[f"country_{i+1}" for i in range(max_countries)]) if max_countries > 0 else pd.DataFrame([[""]] * len(df), columns=["country_1"])
    # Expand TTP desc
    padded_desc, max_ttps = pad_lists(df["ttp_desc"].tolist())
    df_desc = pd.DataFrame(padded_desc, columns=[f"ttp_desc_{i+1}" for i in range(max_ttps)]) if max_ttps > 0 else pd.DataFrame([[""]] * len(df), columns=["ttp_desc_1"])
    df_final = pd.concat([df.drop(columns=["affected_countries", "ttp_desc"]), df_countries, df_desc], axis=1)
    return df_final

# Optional CLI
if __name__ == "__main__":
    df = fetch_news()
    if not df.empty:
        df.to_excel("ttp_reports.xlsx", index=False)
        print(f"Wrote {len(df)} articles to ttp_reports.xlsx")
    else:
        print("No recent articles found.")
