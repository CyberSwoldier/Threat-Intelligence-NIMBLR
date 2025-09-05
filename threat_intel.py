#!/usr/bin/env python3
"""
MITRE TTP Web Tracker — 7-day span, merged articles, multi-country & multi-TTP description columns,
human/general split, and explicit affected-countries output (only real countries).
Enhanced: merges IP-detected countries with NER/alias/TLD-detected countries without skipping articles.
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
from openpyxl.utils import get_column_letter
from openpyxl.styles import Alignment
import warnings
import unicodedata
import ipaddress

warnings.filterwarnings("ignore")

# ------------------ Optional country detection support ------------------
try:
    import pycountry
    PYCOUNTRY_OK = True
except Exception:
    pycountry = None
    PYCOUNTRY_OK = False

# Small alias tables
_ALIASES = {
    # United States
    "usa": "United States",
    "us": "United States",
    "u.s.": "United States",
    "u.s.a.": "United States",
    "america": "United States",
    "united states of america": "United States",
    "the states": "United States",

    # United Kingdom
    "uk": "United Kingdom",
    "u.k.": "United Kingdom",
    "great britain": "United Kingdom",
    "england": "United Kingdom",
    "scotland": "United Kingdom",
    "wales": "United Kingdom",
    "northern ireland": "United Kingdom",
    "britain": "United Kingdom",

    # Korea
    "south korea": "South Korea",
    "republic of korea": "South Korea",
    "rok": "South Korea",
    "north korea": "North Korea",
    "democratic people's republic of korea": "North Korea",
    "dprk": "North Korea",

    # Russia
    "russia": "Russia",
    "russian federation": "Russia",

    # China
    "china": "China",
    "prc": "China",
    "people's republic of china": "China",

    # India
    "india": "India",

    # Iran
    "iran": "Iran",
    "islamic republic of iran": "Iran",

    # Others (common abbreviations)
    "uae": "United Arab Emirates",
    "u.a.e.": "United Arab Emirates",
    "emirates": "United Arab Emirates",
    "drc": "Democratic Republic of the Congo",
    "dr congo": "Democratic Republic of the Congo",
    "congo-kinshasa": "Democratic Republic of the Congo",
    "congo-brazzaville": "Republic of the Congo",
    "czechia": "Czech Republic",
    "viet nam": "Vietnam",
    "syria": "Syria",
    "burma": "Myanmar",
    "ivory coast": "Côte d'Ivoire",
    "cote d'ivoire": "Côte d'Ivoire",
    "bolivia": "Bolivia",
    "plurinational state of bolivia": "Bolivia",
    "venezuela": "Venezuela",
    "bolivarian republic of venezuela": "Venezuela",
}

_NATIVE_ALIAS_TO_EN = {
    # Nordic & Baltics
    "sverige": "Sweden",
    "suomi": "Finland",
    "danmark": "Denmark",
    "eesti": "Estonia",
    "latvija": "Latvia",
    "lietuva": "Lithuania",
    "norge": "Norway",
    "í­sland": "Iceland",
    "island": "Iceland",
    "islanda": "Iceland",

    # Western Europe
    "españa": "Spain",
    "espana": "Spain",
    "deutschland": "Germany",
    "italia": "Italy",
    "france": "France",
    "français": "France",
    "franca": "France",
    "suisse": "Switzerland",
    "schweiz": "Switzerland",
    "svizzera": "Switzerland",
    "österreich": "Austria",
    "austria": "Austria",
    "belgië": "Belgium",
    "belgie": "Belgium",
    "belgique": "Belgium",

    # South America
    "brasil": "Brazil",
    "brésil": "Brazil",
    "argentina": "Argentina",
    "colombia": "Colombia",
    "chile": "Chile",
    "perú": "Peru",
    "peru": "Peru",
    "venezuela": "Venezuela",
    "ecuador": "Ecuador",
    "paraguay": "Paraguay",
    "uruguay": "Uruguay",
    "bolivia": "Bolivia",

    # Eastern Europe
    "россия": "Russia",
    "беларусь": "Belarus",
    "ukraina": "Ukraine",
    "україна": "Ukraine",
    "polska": "Poland",
    "česká republika": "Czech Republic",
    "česko": "Czech Republic",
    "slovensko": "Slovakia",
    "magyarország": "Hungary",
    "românia": "Romania",
    "romania": "Romania",
    "bulgaria": "Bulgaria",
    "ελλάδα": "Greece",
    "elláda": "Greece",

    # Asia
    "中国": "China",
    "中华人民共和国": "China",
    "中國": "China",
    "日本": "Japan",
    "nippon": "Japan",
    "nihon": "Japan",
    "대한민국": "South Korea",
    "조선민주주의인민공화국": "North Korea",
    "भारत": "India",
    "hindustan": "India",
    "pakistan": "Pakistan",
    "افغانستان": "Afghanistan",
    "turkiye": "Turkey",
    "türkiye": "Turkey",

    # Middle East
    "المملكة العربية السعودية": "Saudi Arabia",
    "السعودية": "Saudi Arabia",
    "الإمارات": "United Arab Emirates",
    "مصر": "Egypt",
    "iraq": "Iraq",
    "ایران": "Iran",
    "israel": "Israel",

    # Africa
    "nigeria": "Nigeria",
    "south africa": "South Africa",
    "cameroun": "Cameroon",
    "côte d’ivoire": "Côte d'Ivoire",
    "cote d'ivoire": "Côte d'Ivoire",
    "marruecos": "Morocco",
    "maroc": "Morocco",
    "algérie": "Algeria",
    "algieria": "Algeria",
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

# ------------------ spaCy (optional multilingual NER) ------------------
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

# ------------------ Feeds ------------------
FEEDS = [
    "https://thecyberexpress.com/feed/",
    "https://cybersecuritynews.com/feed/",
    "https://dailycybersecuritynews.com/feed/",
    "https://securityriskadvisors.com/feed/",
    "https://www.reddit.com/r/netsec/new.rss",
    "https://www.reddit.com/r/cybersecurity/new.rss",
    "https://sogu.sec/feed/",
    "https://www.infosecurity-magazine.com/rss/news/",
    "https://redpacketsecurity.com/feed/",
    "https://hackmag.com/feed/",
    "https://securityaffairs.co/wordpress/feed/",
    "https://www.cisa.gov/news-events/alerts.rss",
    "https://www.cisa.gov/news-events/analysis-reports.rss",
    "https://www.microsoft.com/security/blog/feed/",
    "https://www.crowdstrike.com/blog/feed/",
    "https://unit42.paloaltonetworks.com/feed/",
    "https://www.proofpoint.com/us/blog/rss.xml",
    "https://www.mandiant.com/resources/blog/rss.xml",
    "https://securelist.com/feed/",
    "https://blog.talosintelligence.com/feed/",
    "https://www.malwarebytes.com/blog/feed",
    "https://isc.sans.edu/rssfeed.xml",
    "https://www.bleepingcomputer.com/feed/",
    "https://thehackernews.com/feeds/posts/default?alt=rss",
    "https://www.infosecurity-magazine.com/phishing/",
    "https://www.cybersecuritydive.com/",
    "https://www.bitdefender.com/en-us/blog/",
    "https://www.securityweek.com/",
    "https://sakerhetskollen.se/aktuella-brott",
    "https://darkreading.com/rss.xml",
    "https://threatpost.com/feed",
    "https://thecyberwire.com/rss",
    "https://krebsonsecurity.com/feed",
    "https://grahamcluley.com/feed",
    "https://isc.sans.edu/rssfeed_full.xml",
    "https://www.schneier.com/feed/atom/",
    "https://podcast.darknetdiaries.com/",
    "https://www.kyberturvallisuuskeskus.fi/en/ncsc-news/rss-feeds",
    "https://www.kyberturvallisuuskeskus.fi/feed/rss/fi/401",
    "https://www.cert.dk/feeds",
    "http://www.sitic.se/rss",
    "https://www.cert.ee/rss",
    "https://www.cert.lt/en/feed",
    "https://inuit.se/blogg/rss.xml",
    "https://cybernews.com",
    "https://www.thelocal.se/tag/cyberattack",
    "https://www.truesec.com/news",
    "https://www.thelocal.dk/tag/cyber-attack",
    "https://portswigger.net/daily-swig/denmark",
    "https://www.pst.no",
    "https://portswigger.net/daily-swig/norway",
    "https://portswigger.net/daily-swig/finland",
    "https://yle.fi/t/18-5609/en",
    "https://www.infosecurity-magazine.com/phishing/",
    "https://www.cert.se/2025/08/cert-se-veckobrev-v35.html",
    "https://theconversation.com/topics/dark-web-8437/",
    "https://www.newsnow.com/us/Tech/Cyber+Security/Dark+Web?type=ln",
    "https://app.cyberespresso.eu/2eBJtkaQdsHk9ZcJK5ror3V2tyvoXuHq/feeds/35a35a2d-4ebc-48b1-8f5d-0f33c5aa098f/atom.xml",
]

MAPPINGS = {
    # --- Human Targeted / Social Engineering ---
    r"\bsocial\s*engineering\b": {"desc": ["Social Engineering (T1566 / TA0001)"]},
    r"\bpretext(ing)?\b": {"desc": ["Pretexting (T1566.004)"]},
    r"\bbait(ing)?\b": {"desc": ["Baiting / Influence Operations (T1586.003)"]},
    r"\bscam(s)?\b|\bfraud(ulent)?\b": {"desc": ["Fraud / Social Engineering (TA0001)"]},
    r"\bimpersonat(e|ion|ing)\b": {"desc": ["Impersonation (T1656)"]},
    r"\bfake\s*persona(s)?\b|\bfake\s*profile(s)?\b": {"desc": ["Fake Online Persona (T1585.001)"]},
    r"\bid\s*theft\b|\bidentity\s*fraud\b": {"desc": ["Identity Theft (T1589)"]},
    r"\bCEO\s*fraud\b|\bBEC\b|\bbusiness\s*email\s*compromise\b": {"desc": ["Business Email Compromise (T1650)"]},
    r"\bpsychological\s*manipulation\b|\bpsyops\b": {"desc": ["Psychological Operations (T1642)"]},
    r"\bdisinformation\b|\bmisinformation\b": {"desc": ["Disinformation Campaigns (T1641)"]},

    # --- Phishing Variants ---
    r"\bphishing\b": {"desc": ["Phishing (T1566.002)"]},
    r"\bspear\s*phish(ing)?\b|\bspearphish(ing)?\b": {"desc": ["Spearphishing (T1566.001)"]},
    r"\bwhaling\b": {"desc": ["Whaling (T1566.001)"]},
    r"\bclone\s*phish(ing)?\b": {"desc": ["Clone Phishing (T1566.001)"]},
    r"\bsmish(ing)?\b|\bSMS\s*phish(ing)?\b": {"desc": ["Smishing (T1566.002 - via SMS)"]},
    r"\bvish(ing)?\b|\bvoice\s*phish(ing)?\b": {"desc": ["Vishing (T1566.004 - via phone/voice)"]},
    r"\bcallback\s*phish(ing)?\b": {"desc": ["Callback Phishing (Hybrid Social Engineering)"]},

    # --- Initial Access ---
    r"\bwatering\s*hole\b": {"desc": ["Drive-by Compromise (T1189)"]},
    r"\bmalvertis(ing|ement)\b": {"desc": ["Malvertising (T1189)"]},
    r"\bdrive-?by\s+download\b": {"desc": ["Drive-by Compromise (T1189)"]},

    # --- Credential Access ---
    r"\bbrute\s*force\b": {"desc": ["Brute Force (T1110)"]},
    r"\bpassword\s*spray(ing)?\b": {"desc": ["Password Spraying (T1110.003)"]},
    r"\bMFA\s*bypass\b": {"desc": ["MFA Bypass (T1621)"]},
    r"\baccount\s*take\s*over\b|\bATO\b": {"desc": ["Account Takeover (T1078)"]},

    # --- Execution ---
    r"\b(command( and)?|cmd)\s+(and\s+)?script(ing)?\b|\bcommand\s+line\b": {"desc": ["Command-Line Interface (T1059.003)"]},
    r"\bpowershell\b|\bpwsh\b": {"desc": ["PowerShell (T1059.001)"]},
    r"\boffice\s+macro(s)?\b|\bvba\b": {"desc": ["Malicious Macro (T1137.001)"]},

    # --- Impact ---
    r"\bfinancial\s+theft\b|\bfraud\b": {"desc": ["Financial Theft (T1650)"]},

    # --- General Malware ---
    r"\bmalware\b|\btrojan\b|\bspyware\b|\badware\b": {"desc": ["Malware (TA0002/TA0003)"]},
}

ACTOR_PATTERNS = {
    # --- Russia ---
    "APT28 (Fancy Bear / Sofacy)": [r"\bapt28\b", r"\bsofacy\b", r"\bfancy\s*bear\b", r"\bstrontium\b"],
    "APT29 (Cozy Bear / The Dukes)": [r"\bapt29\b", r"\bcozy\s*bear\b", r"\bthe\s*dukes\b", r"\bnobelium\b"],
    "Sandworm Team": [r"\bsandworm\b", r"\btelebots\b", r"\bblackenergy\b"],

    # --- China ---
    "APT1 (Comment Crew)": [r"\bapt1\b", r"\bcomment\s*crew\b", r"\bcomment\s*group\b"],
    "APT3 (Buckeye)": [r"\bapt3\b", r"\buckeye\b", r"\bgothic\s*panda\b"],
    "APT10 (Stone Panda)": [r"\bapt10\b", r"\bstone\s*panda\b", r"\bmenuPass\b"],
    "APT17": [r"\bapt17\b", r"\bAurora\b"],
    "APT41 (Double Dragon)": [r"\bapt41\b", r"\bdouble\s*dragon\b", r"\bbarium\b"],
    "Mustang Panda": [r"\bmustang\s*panda\b", r"\bredDelta\b"],

    # --- North Korea ---
    "Lazarus Group": [r"\blazarus\b", r"\bhidden\s*cobra\b", r"\blabyrinth\b"],
    "Kimsuky": [r"\bkimsuky\b", r"\bkimsook\b"],
    "Andariel": [r"\bandariel\b"],

    # --- Iran ---
    "APT33 (Elfin)": [r"\bapt33\b", r"\belfin\b", r"\breaper\b"],
    "APT34 (OilRig)": [r"\bapt34\b", r"\boilrig\b", r"\bgreenbug\b"],
    "APT35 (Charming Kitten)": [r"\bapt35\b", r"\bcharming\s*kitten\b", r"\bphosphorus\b"],
    "MuddyWater": [r"\bmuddy\s*water\b", r"\bstatic\s*kittens?\b"],

    # --- Cybercrime Groups ---
    "FIN4": [r"\bfin4\b"],
    "FIN5": [r"\bfin5\b"],
    "FIN6": [r"\bfin6\b"],
    "FIN7 (Carbanak)": [r"\bfin7\b", r"\bcarbanak\b", r"\bncq\b"],
    "Evil Corp (INDRIK SPIDER)": [r"\bevil\s*corp\b", r"\bindrik\s*spider\b", r"\bmaksim\s*yakubets\b"],
    "TA505": [r"\bta505\b"],

    # --- Other well-known groups ---
    "Turla (Snake / Uroburos)": [r"\bturla\b", r"\bsnake\b", r"\buroburos\b", r"\bvenerable\b"],
    "Gamaredon": [r"\bgamaredon\b", r"\bprimitive\s*bear\b"],
    "Wizard Spider (Ryuk/Conti)": [r"\bwizard\s*spider\b", r"\bryuk\b", r"\bconti\b"],
    "LockBit": [r"\blockbit\b"],
    "BlackCat (ALPHV)": [r"\bblackcat\b", r"\balphv\b"],
    "REvil (Sodinokibi)": [r"\brevil\b", r"\bsodinokibi\b"],
}

HEADERS = {"User-Agent": "TTP-Tracker/1.0"}
REQ_TIMEOUT = 20

# ------------------ GeoIP Resolver ------------------
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

def map_to_country(candidate: str):
    if not candidate or not isinstance(candidate, str):
        return None
    cand_norm = _normalize_text_for_match(candidate)
    if cand_norm in _ALIASES:
        return _ALIASES[cand_norm]
    if cand_norm in _NATIVE_ALIAS_TO_EN:
        return _NATIVE_ALIAS_TO_EN[cand_norm]
    if PYCOUNTRY_OK and cand_norm:
        if len(cand_norm) == 2:
            try:
                cc = pycountry.countries.get(alpha_2=cand_norm.upper())
                if cc:
                    return cc.name
            except Exception:
                pass
        if len(cand_norm) == 3:
            try:
                cc = pycountry.countries.get(alpha_3=cand_norm.upper())
                if cc:
                    return cc.name
            except Exception:
                pass
        if cand_norm in _NAME_TO_ALPHA:
            try:
                alpha = _NAME_TO_ALPHA[cand_norm]
                return _ALPHA_TO_NAME.get(alpha.upper(), pycountry.countries.get(alpha_2=alpha).name)
            except Exception:
                pass
        try:
            res = pycountry.countries.search_fuzzy(candidate)
            if res:
                return res[0].name
        except Exception:
            pass
    return None

def detect_countries(text: str, url: str | None = None) -> list:
    if not text:
        return []
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
    text_lower = text.lower()
    if PYCOUNTRY_OK:
        for name_lower, alpha in _NAME_TO_ALPHA.items():
            if re.search(r"\b" + re.escape(name_lower) + r"\b", text_lower, flags=re.I):
                try:
                    canonical = _ALPHA_TO_NAME.get(alpha.upper()) or pycountry.countries.get(alpha_2=alpha).name
                    if canonical not in seen:
                        seen.add(canonical)
                        results.append(canonical)
                except Exception:
                    pass
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

def normalize_domain(url):
    try:
        ext = tldextract.extract(url)
        return ".".join(part for part in [ext.domain, ext.suffix] if part)
    except Exception:
        return ""

def pad_lists(list_of_lists):
    def ensure_list(x):
        if x is None:
            return []
        if isinstance(x, list):
            return x
        if isinstance(x, str):
            if x.strip() == "":
                return []
            return [x]
        return [x]
    prepared = [ensure_list(x) for x in list_of_lists]
    max_len = max((len(l) for l in prepared), default=0)
    padded = [l + [""] * (max_len - len(l)) for l in prepared]
    return padded, max_len

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

def extract_ips(text):
    pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    return re.findall(pattern, text)

# ------------------ Poll feed ------------------
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
        countries = detect_countries(blob, link)  # existing detection

        # Merge MaxMind IP-resolved countries
        ips = extract_ips(blob)
        for ip in ips:
            try:
                ip_obj = ipaddress.ip_address(ip)
                geo_country = GEOIP.resolve(str(ip_obj))
                if geo_country and geo_country not in countries:
                    countries.append(geo_country)
            except Exception:
                continue

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

# ------------------ Main ------------------
def main():
    since = datetime.now() - timedelta(days=7)
    GEOIP = GeoIPResolver()  # MaxMind GeoIP

    all_items = []
    seen_urls = set()
    for feed in FEEDS:
        try:
            items = poll_feed(feed, since, GEOIP)
            for itm in items:
                if itm['url'] not in seen_urls:
                    all_items.append(itm)
                    seen_urls.add(itm['url'])
        except Exception as e:
            print(f"[warn] feed failed: {feed} → {e}")

    if not all_items:
        print("No articles found in the last 7 days.")
        return

    df = pd.DataFrame(all_items)

    # Ensure column exists
    if "affected_countries" not in df.columns:
        df["affected_countries"] = [[] for _ in range(len(df))]

    # Merge duplicates
    df = df.groupby(['url', 'title'], as_index=False).agg({
        'published_utc': 'first',
        'source': 'first',
        'ttp_desc': lambda x: merge_listlike(x),
        'threat_actor': 'first',
        'affected_countries': lambda x: merge_listlike(x),
    })

    # Expand affected countries
    padded_countries, max_countries = pad_lists(df["affected_countries"].tolist())
    if max_countries == 0:
        df_countries = pd.DataFrame([[""] for _ in range(len(df))], columns=["country_1"])
    else:
        df_countries = pd.DataFrame(padded_countries, columns=[f"country_{i+1}" for i in range(max_countries)])
    df = pd.concat([df.drop(columns=["affected_countries"]), df_countries], axis=1)

    # Expand TTP descriptions
    padded_desc, max_ttps = pad_lists(df["ttp_desc"].tolist())
    if max_ttps == 0:
        df_desc = pd.DataFrame([[""] for _ in range(len(df))], columns=["ttp_desc_1"])
    else:
        df_desc = pd.DataFrame(padded_desc, columns=[f"ttp_desc_{i+1}" for i in range(max_ttps)])
    df = pd.concat([df.drop(columns=["ttp_desc"]), df_desc], axis=1)

    # Split human-targeted vs general
    human_mask = df.filter(like="ttp_desc").apply(
        lambda row: any("Phishing" in str(x) or "Spearphishing" in str(x) for x in row),
        axis=1
    )
    human_df = df[human_mask].reset_index(drop=True)
    general_df = df[~human_mask].reset_index(drop=True)

    # Write to Excel
    output_file = "ttp_reports.xlsx"
    with pd.ExcelWriter(output_file, engine="openpyxl") as writer:
        human_df.to_excel(writer, sheet_name="Human_Attacks", index=False)
        general_df.to_excel(writer, sheet_name="General_Attacks", index=False)
        for sheet in writer.sheets.values():
            for col in sheet.columns:
                max_length = max(len(str(cell.value)) if cell.value else 0 for cell in col)
                adjusted_width = min(max_length + 2, 80)
                sheet.column_dimensions[get_column_letter(col[0].column)].width = adjusted_width
                for cell in col:
                    cell.alignment = Alignment(wrap_text=True, vertical="top")

    print(f"Wrote {len(df)} articles to {output_file} (country_1..country_N columns contain merged countries)")

if __name__ == "__main__":
    main()