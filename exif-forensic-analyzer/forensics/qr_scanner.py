"""QR code detection/decoding and URL risk heuristics.

Reuses the scam-brand keyword list from the sibling SMS phishing detector
project (../src/features.py) so "does this QR code's domain impersonate a
known brand" isn't a second, drifting copy of that list.
"""

import ipaddress
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

from PIL import Image
from pyzbar import pyzbar

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.features import SCAM_BRAND_KEYWORDS  # noqa: E402

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.me", "goo.gl", "is.gd", "ow.ly",
    "cutt.ly", "tiny.cc", "buff.ly", "rebrand.ly", "rb.gy",
}

SUSPICIOUS_TLDS = {
    "info", "xyz", "top", "club", "link", "click", "work",
    "support", "win", "biz", "gq", "tk", "cf",
}

# A few major brands from SCAM_BRAND_KEYWORDS mapped to their real domain(s),
# used only to flag "this domain mentions the brand but isn't the brand's
# real domain" -- not an exhaustive registry, just enough to demonstrate the
# technique on well-known names.
CANONICAL_DOMAINS = {
    "gcash": {"gcash.com"},
    "paymaya": {"maya.ph", "paymaya.com"},
    "paypal": {"paypal.com"},
    "usps": {"usps.com"},
    "fedex": {"fedex.com"},
    "dhl": {"dhl.com"},
    "irs": {"irs.gov"},
    "hmrc": {"gov.uk"},
    "chase bank": {"chase.com"},
    "hsbc": {"hsbc.com"},
    "netflix": {"netflix.com"},
    "apple id": {"apple.com", "icloud.com"},
    "icloud": {"icloud.com"},
    "amazon prime": {"amazon.com"},
    "coinbase": {"coinbase.com"},
    "binance": {"binance.com"},
}


def decode_qr_codes(image: "Image.Image | str") -> list:
    """Return decoded payload strings for every QR code found in the image."""
    if isinstance(image, (str, Path)):
        image = Image.open(image)
    decoded = pyzbar.decode(image)
    return [d.data.decode("utf-8", errors="replace") for d in decoded]


def _registered_domain(hostname: str) -> str:
    """Best-effort second-level-domain extraction without a public suffix
    list (e.g. 'accounts.gcash-verify.info' -> 'gcash-verify.info')."""
    parts = hostname.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else hostname


_HOSTNAME_RE = re.compile(
    r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$",
    re.IGNORECASE,
)


def is_url(text: str) -> bool:
    """True only for text that actually looks like a URL/hostname -- not
    just "urlparse didn't crash", which is true for almost any string
    (urlparse('http://plain text').netloc == 'plain text')."""
    if not text or " " in text.strip() or "\t" in text:
        return False
    parsed = urlparse(text if "://" in text else f"http://{text}")
    hostname = parsed.hostname or ""
    if not hostname:
        return False
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        pass
    return bool(_HOSTNAME_RE.match(hostname))


def analyze_url(url: str) -> dict:
    """Score a decoded QR payload for phishing risk. Returns signals plus
    a 0-100 risk_score and a low/medium/high verdict."""
    result = {
        "url": url,
        "is_url": False,
        "signals": [],
        "risk_score": 0,
        "verdict": "not_a_url",
    }

    if not is_url(url):
        return result

    parsed = urlparse(url if "://" in url else f"http://{url}")
    result["is_url"] = True
    hostname = (parsed.hostname or "").lower()
    domain = _registered_domain(hostname)
    signals = []
    score = 0

    if domain in SHORTENER_DOMAINS or hostname in SHORTENER_DOMAINS:
        signals.append("uses a URL shortener (destination is hidden)")
        score += 25

    try:
        ipaddress.ip_address(hostname)
        signals.append("host is a raw IP address, not a domain name")
        score += 30
    except ValueError:
        pass

    tld = hostname.rsplit(".", 1)[-1] if "." in hostname else ""
    if tld in SUSPICIOUS_TLDS:
        signals.append(f"uses a TLD commonly abused for scam domains (.{tld})")
        score += 15

    if hostname.count("-") >= 2:
        signals.append("domain has multiple hyphens (common in generated scam domains)")
        score += 10

    if parsed.scheme != "https":
        signals.append("not using HTTPS")
        score += 5

    lower_full_url = url.lower()
    for brand in SCAM_BRAND_KEYWORDS:
        brand_token = re.sub(r"[^a-z0-9]", "", brand.lower())
        if not brand_token or len(brand_token) < 3:
            continue
        if brand_token in hostname.replace("-", "").replace(".", ""):
            canonical = CANONICAL_DOMAINS.get(brand)
            if canonical and domain not in canonical:
                signals.append(
                    f"domain mentions '{brand}' but is not {brand}'s real domain "
                    f"({', '.join(sorted(canonical))})"
                )
                score += 35
            elif not canonical:
                signals.append(f"domain/URL mentions scam-associated brand '{brand}'")
                score += 15
            break

    result["signals"] = signals
    result["risk_score"] = min(score, 100)
    if score >= 40:
        result["verdict"] = "high_risk"
    elif score >= 15:
        result["verdict"] = "medium_risk"
    else:
        result["verdict"] = "low_risk"
    return result
