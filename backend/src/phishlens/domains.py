"""Domain helpers shared by the sender and URL analyzers. Pure functions, no network."""

from __future__ import annotations

import contextlib
import ipaddress
import re
import unicodedata
from dataclasses import dataclass
from functools import lru_cache
from typing import Literal

import tldextract

from phishlens.knowledge import BRANDS, FREEMAIL_DOMAINS, Brand

# Offline: use the Public Suffix List snapshot bundled with tldextract instead of
# fetching it at runtime. Private suffixes (github.io, web.app, ...) are included so
# each tenant on shared hosting counts as its own domain, as it has its own owner.
_extract = tldextract.TLDExtract(
    suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True
)

# Characters that render like ASCII letters. Deliberately small and high-confidence;
# anything outside ASCII in a domain is flagged separately via punycode anyway.
_CONFUSABLES = str.maketrans(
    {
        "0": "o", "1": "l", "3": "e", "5": "s", "@": "a", "$": "s",
        "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i",
        "ј": "j", "ԁ": "d", "ѕ": "s", "ɡ": "g", "ⅼ": "l", "ı": "i", "ο": "o", "α": "a",
        "ν": "v", "τ": "t", "κ": "k", "ս": "u", "ո": "n",
    }
)  # fmt: skip
_MULTI_CHAR_CONFUSABLES = (("rn", "m"), ("vv", "w"))


@dataclass(frozen=True)
class Host:
    subdomain: str
    domain: str
    suffix: str

    @property
    def registered(self) -> str:
        """The part someone actually registered, e.g. 'login-secure.xyz'."""
        return f"{self.domain}.{self.suffix}" if self.suffix else self.domain


@lru_cache(maxsize=4096)
def split_host(host: str) -> Host:
    parts = _extract(host.lower().rstrip("."))
    return Host(parts.subdomain, parts.domain, parts.suffix)


def registered_domain(host: str) -> str:
    return split_host(host).registered


def is_ip_address(host: str) -> bool:
    host = host.strip("[]")
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    # Browsers also accept an IPv4 address written as a single decimal or hex number.
    return bool(re.fullmatch(r"\d{8,10}|0x[0-9a-f]{8}", host, re.IGNORECASE))


def to_unicode(host: str) -> str:
    """Decode punycode labels (xn--) to what the user would see in a browser."""
    labels = []
    for label in host.split("."):
        if label.startswith("xn--"):
            with contextlib.suppress(UnicodeError):
                label = label.encode("ascii").decode("idna")
        labels.append(label)
    return ".".join(labels)


def skeleton(text: str) -> str:
    """Collapse look-alike characters so 'pаypa1' (Cyrillic а, digit 1) becomes 'paypal'."""
    text = unicodedata.normalize("NFKD", text.lower())
    text = "".join(c for c in text if not unicodedata.combining(c))
    text = text.translate(_CONFUSABLES)
    for fake, real in _MULTI_CHAR_CONFUSABLES:
        text = text.replace(fake, real)
    return text


def brand_for_domain(registered: str, include_mailbox_domains: bool = False) -> Brand | None:
    """The brand that owns this registered domain, if any.

    Free mailbox domains don't count by default: 'Microsoft Support' at outlook.com
    is just someone with a free Outlook account. Pass include_mailbox_domains when
    asking about a website rather than a sender.
    """
    if registered in FREEMAIL_DOMAINS and not include_mailbox_domains:
        return None
    return next((b for b in BRANDS if registered in b.domains), None)


LookalikeTechnique = Literal["homoglyph", "typo", "combo", "tld_swap"]


@dataclass(frozen=True)
class BrandLookalike:
    brand: Brand
    technique: LookalikeTechnique

    @property
    def real_domain(self) -> str:
        return self.brand.primary


def organization_brand(domains: list[str]) -> tuple[Brand, ...]:
    """Treat the recipient's own organization as a brand, so 'acme-defense.co' is caught
    imitating 'acme-defense.com'. Free mailbox recipients are skipped."""
    registered = {registered_domain(d) for d in domains if d}
    registered = sorted(r for r in registered - FREEMAIL_DOMAINS if split_host(r).suffix)
    if not registered:
        return ()
    return (
        Brand(
            name="your organization",
            domains=frozenset(registered),
            display_names=(),
            labels=tuple(dict.fromkeys(split_host(r).domain for r in registered)),
            primary=registered[0],
        ),
    )


def find_lookalike(host: str, extra_brands: tuple[Brand, ...] = ()) -> BrandLookalike | None:
    """Does this host's registered domain imitate a known brand's domain?"""
    parts = split_host(to_unicode(host))
    site = registered_domain(host)
    if (
        not parts.domain
        or is_ip_address(host)
        or is_known_domain(site)
        or any(site in b.domains for b in extra_brands)
    ):
        return None
    label = parts.domain
    label_skeleton = skeleton(label)
    for brand in (*BRANDS, *extra_brands):
        for brand_label in brand.labels:
            technique = _compare_label(label, label_skeleton, brand_label)
            if technique:
                return BrandLookalike(brand, technique)
    return None


def find_brand_in_subdomain(host: str) -> Brand | None:
    """A brand name placed in front of someone else's domain: 'paypal.com.secure-login.xyz'."""
    parts = split_host(to_unicode(host))
    if not parts.subdomain or is_known_domain(registered_domain(host)):
        return None
    subdomain = skeleton(parts.subdomain)
    for brand in BRANDS:
        if any(_has_token(subdomain, skeleton(label)) for label in brand.labels):
            return brand
    return None


_ALL_BRAND_DOMAINS = frozenset().union(*(b.domains for b in BRANDS))


def is_known_domain(registered: str) -> bool:
    """Real brand and mailbox-provider domains are never lookalikes of anything."""
    return registered in _ALL_BRAND_DOMAINS or registered in FREEMAIL_DOMAINS


def _compare_label(label: str, label_skeleton: str, brand_label: str) -> LookalikeTechnique | None:
    brand_skeleton = skeleton(brand_label)
    if label == brand_label:
        return "tld_swap"  # paypal.xyz
    if label_skeleton == brand_skeleton:
        return "homoglyph"  # paypa1.com, pаypal.com
    # Typos only for longer names: 'apple' vs 'apply' or 'adobe' vs 'adore' are real words.
    if len(brand_skeleton) >= 6:
        max_distance = 2 if len(brand_skeleton) >= 9 else 1
        if _edit_distance(label_skeleton, brand_skeleton) <= max_distance:
            return "typo"  # micros0ft-ish, gooogle.com
    # Brand as a whole hyphen-separated word: 'paypal-secure.com', 'sam-gov-renewal.com'.
    if _has_token(label_skeleton, brand_skeleton):
        return "combo"
    # Longer brand names glued to other words: 'microsoftsupport.com'.
    if len(brand_skeleton) >= 8 and brand_skeleton in label_skeleton:
        return "combo"
    return None


def _has_token(text: str, token: str) -> bool:
    """Is `token` a whole word in a dotted, hyphenated name?

    Short brand names (UPS, DHL, AWS) must lead a label: 'ups-delivery' matches
    but 'sign-ups' does not.
    """
    for label in text.split("."):
        if len(token) <= 3:
            if label.split("-")[0] == token:
                return True
        elif f"-{token}-" in f"-{label}-":
            return True
    return False


def _edit_distance(a: str, b: str) -> int:
    """Optimal string alignment distance: insertions, deletions, substitutions, swaps."""
    if abs(len(a) - len(b)) > 2:
        return 3
    prev2: list[int] = []
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb))
            if i > 1 and j > 1 and ca == b[j - 2] and a[i - 2] == cb:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        prev2, prev = prev, cur
    return prev[-1]
