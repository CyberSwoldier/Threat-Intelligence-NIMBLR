#!/usr/bin/env python3
"""
Threat Intelligence News Fetcher for Streamlit Cloud
Provides fetch_news() that returns a DataFrame with TTP, actor, countries, etc.
Dependencies are optional and fail gracefully if not installed.
"""
from __future__ import annotations
import re
import warnings
import unicodedata
from datetime import datetime, timedelta, timezone

import pandas as pd

# Optional imports
try:
    import requests
except ImportError:
    requests = None

try:
    import feedparser
except ImportError:
    feedparser = None

try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None

try:
    import tldextract
except ImportError:
    tldextract = None

try:
    import pycountry
    PYCOUNTRY_OK = True
except Exception:
    pycountry = None
    PYCOUNTRY_OK = False

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
    nlp = None
    SPACY_OK = False

# GeoIP optional
try:
    import geoip2.database
    class GeoIPResolver:
        def __init__(self, mmdb_path="GeoLite2-Country.mmdb"):
            try:
                self.reader = geoip2.database.Reader(mmdb_path)
            except Exception:
                self.reader = None

        def resolve(self, ip):
            if not self.reader:
                return None
            try:
                resp = self.reader.country(ip)
                return resp.country.name
            except Exception:
                return None
except Exception:
    GeoIPResolver = None

warnings.filterwarnings("ignore")
HEADERS = {"User-Agent": "TTP-Tracker/1.0"}
REQ_TIMEOUT = 20

# Minimal feed list (extendable)
FEEDS = [
    "https://thecyberexpress.com/feed/",
    "https://cybersecuritynews.com/feed/",
]

# Minimal TTP mappings (expand as needed)
MAPPINGS = {
    r"\bphishing\b": {"desc": ["Phishing (T1566.002)"]},
    r"\bspear\s*phish(ing)?\b": {"desc": ["Spearphishing (T1566.001)"]},
}

ACTOR_PATTERNS = {
    "APT28 (Fancy Bear / Sofacy)": [r"\bapt28\b", r"\bfancy\s*bear\b"],
}

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
        from dateutil import parser as dtparser
        dt = dtparser.parse(str(entry_date))
        if not dt.tzinfo:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    except Exception:
        return None

def fetch_article_text(url):
    if not requests or not BeautifulSoup:
        return ""
    try:
        resp = requests.get(url, headers=HEADERS, timeout=REQ_TIMEOUT)
        resp.raise_for_status()
    except Exception:
        return ""
    soup = BeautifulSoup(resp.text, "html.parser")
    for tag in soup(["script", "style", "noscript", "svg", "footer", "nav", "aside", "form"]):
        tag.decompose()
    candidates = []
    for sel in ["article", "main", "div.post", "div.entry-content", "div#content", "div.content"]:
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

def fetch_news(days: int = 7) -> pd.DataFrame:
    """Fetch latest articles from feeds and return a DataFrame."""
    if not feedparser:
        return pd.DataFrame()
    since = datetime.utcnow() - timedelta(days=days)
    items = []

    GEOIP = GeoIPResolver() if GeoIPResolver else None

    for feed_url in FEEDS:
        try:
            parsed = feedparser.parse(feed_url)
        except Exception:
            continue
        for e in parsed.entries:
            link = e.get("link")
            title = (e.get("title") or "").strip()
            published = parse_when(e.get("published") or e.get("updated"))
            if not published or published < since:
                continue
            summary = ""
            if BeautifulSoup:
                summary = BeautifulSoup(e.get("summary", ""), "html.parser").get_text(" ", strip=True)
            full_text = fetch_article_text(link)
            blob = "\n".join([title, summary, full_text])
            ttp_desc = classify(blob)
            actor = detect_actor(blob)
            source = ""
            if tldextract and link:
                ext = tldextract.extract(link)
                source = ".".join(part for part in [ext.domain, ext.suffix] if part)
            items.append({
                "published_utc": published,
                "source": source,
                "title": title,
                "url": link,
                "ttp_desc": ttp_desc,
                "threat_actor": actor,
            })
    df = pd.DataFrame(items)
    return df
