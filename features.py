"""Extracts lexical features from a URL string (column names match the dataset)."""
import re
from urllib.parse import urlparse

SPECIAL = {
    "dot": ".", "hyphen": "-", "underline": "_", "slash": "/",
    "questionmark": "?", "equal": "=", "at": "@", "and": "&",
    "exclamation": "!", "space": " ", "tilde": "~", "comma": ",",
    "plus": "+", "asterisk": "*", "hashtag": "#", "dollar": "$",
    "percent": "%",
}
PARTS = ["url", "domain", "directory", "file", "params"]

TLDS = {"com", "org", "net", "edu", "gov", "io", "co", "in", "info", "biz",
        "xyz", "top", "site", "online", "club", "tk", "ml", "ga", "cf", "gq",
        "ru", "cn", "uk", "de", "br", "us", "me", "cc", "ws", "pw"}
SHORTENERS = {"bit.ly", "goo.gl", "tinyurl.com", "t.co", "ow.ly", "is.gd",
              "buff.ly", "cutt.ly", "rebrand.ly", "shorturl.at", "tiny.cc"}
IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")


def _feature_names():
    names = []
    for p in PARTS:
        names += [f"qty_{k}_{p}" for k in SPECIAL]
    names += ["qty_tld_url", "length_url", "qty_vowels_domain", "domain_length",
              "domain_in_ip", "server_client_domain", "directory_length",
              "file_length", "params_length", "tld_present_params",
              "qty_params", "email_in_url", "url_shortened"]
    return names


FEATURES = _feature_names()


def _split(url: str):
    url = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url
    p = urlparse(url)
    path = p.path
    i = path.rfind("/")
    directory, file = (path[: i + 1], path[i + 1:]) if i >= 0 else ("", path)
    return url, p.netloc, directory, file, p.query


def path_exists(full_url: str) -> bool:
    """True if the URL has a real path (more than just '/')."""
    return urlparse(full_url).path not in ("", "/")


def extract_features(url: str) -> dict:
    full, domain, directory, file, params = _split(url)
    parts = {"url": full, "domain": domain, "directory": directory,
             "file": file, "params": params}

    # Dataset convention: if a URL part does not exist, all its features are -1
    has_path = path_exists(full)
    has_params = bool(params)
    present = {"url": True, "domain": True, "directory": has_path,
               "file": has_path, "params": has_params}

    f = {}
    for p, text in parts.items():
        for name, ch in SPECIAL.items():
            f[f"qty_{name}_{p}"] = text.count(ch) if present[p] else -1

    tokens_url = re.split(r"[^a-zA-Z0-9]+", full.lower())
    tokens_params = re.split(r"[^a-zA-Z0-9]+", params.lower())
    host = domain.split(":")[0].lower()

    f["qty_tld_url"] = sum(t in TLDS for t in tokens_url)
    f["length_url"] = len(full)
    f["qty_vowels_domain"] = sum(c in "aeiou" for c in host)
    f["domain_length"] = len(domain)
    f["domain_in_ip"] = int(bool(IP_RE.match(host)))
    f["server_client_domain"] = int("server" in host or "client" in host)
    f["directory_length"] = len(directory) if has_path else -1
    f["file_length"] = len(file) if has_path else -1
    f["params_length"] = len(params) if has_params else -1
    f["tld_present_params"] = int(any(t in TLDS for t in tokens_params)) if has_params else -1
    f["qty_params"] = len([x for x in params.split("&") if x]) if has_params else -1
    f["email_in_url"] = int(bool(EMAIL_RE.search(full)))
    f["url_shortened"] = int(host.replace("www.", "") in SHORTENERS)
    return f