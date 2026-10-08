"""Live checks that go beyond the URL text: DNS, SSL certificate, domain age."""
import datetime
import socket
import ssl
import time
from urllib.parse import urlparse

import tldextract
import whois

# Use the bundled public-suffix list so no extra network call is needed
_extractor = tldextract.TLDExtract(suffix_list_urls=())


def get_host(url: str) -> str:
    url = url.strip()
    if "://" not in url:
        url = "http://" + url
    return (urlparse(url).hostname or "").lower()


def check_dns(host: str):
    """Returns (exists, ip)."""
    try:
        return True, socket.gethostbyname(host)
    except Exception:
        return False, None


def check_ssl(host: str, timeout: int = 4):
    """Returns (valid, days_left). valid is None if we could not connect."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as s:
                cert = s.getpeercert()
        expires = ssl.cert_time_to_seconds(cert["notAfter"])
        return True, int((expires - time.time()) / 86400)
    except ssl.SSLCertVerificationError:
        return False, None
    except Exception:
        return None, None


def domain_age_days(host: str):
    """Age of the registered domain in days, or None if it cannot be found."""
    try:
        ext = _extractor(host)
        domain = getattr(ext, "top_domain_under_public_suffix", None) or ext.registered_domain
        if not domain:
            return None
        created = whois.whois(domain).creation_date
        if isinstance(created, list):
            created = created[0]
        if created is None:
            return None
        if getattr(created, "tzinfo", None):
            created = created.replace(tzinfo=None)
        return max((datetime.datetime.now() - created).days, 0)
    except Exception:
        return None


def run_live_checks(url: str) -> dict:
    host = get_host(url)
    result = {"host": host, "dns_ok": False, "ip": None,
              "ssl_valid": None, "ssl_days_left": None, "age_days": None}
    if not host:
        return result
    result["dns_ok"], result["ip"] = check_dns(host)
    if result["dns_ok"]:
        result["ssl_valid"], result["ssl_days_left"] = check_ssl(host)
        result["age_days"] = domain_age_days(host)
    return result
