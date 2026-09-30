"""Reference data the deterministic analyzers check against.

Kept separate from the logic so it can be reviewed and extended on its own.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Brand:
    name: str
    domains: frozenset[str]
    """Registered domains the brand really sends mail and hosts pages from."""
    display_names: tuple[str, ...]
    """Phrases that, in a sender's display name, claim to be this brand. Avoid ones that
    are also ordinary words or names ("Outlook", "Apple", "Zoom", "UPS" alone)."""
    labels: tuple[str, ...]
    """Domain labels that, in someone else's domain, imitate this brand."""
    primary: str
    """The domain to show users as the real one."""


def _brand(name: str, domains: str, display_names: str, labels: str) -> Brand:
    return Brand(
        name=name,
        primary=domains.split()[0],
        domains=frozenset(domains.split()),
        display_names=tuple(display_names.split("|")),
        labels=tuple(labels.split()),
    )


# Brands most imitated in phishing, plus services small defense contractors
# depend on (SAM.gov registration renewals and PIEE/WAWF invoicing are common lures).
BRANDS: tuple[Brand, ...] = (
    _brand(
        "Microsoft",
        "microsoft.com microsoftonline.com office.com office365.com outlook.com live.com "
        "sharepoint.com onedrive.com azure.com microsoft365.com",
        "microsoft|microsoft 365|office 365|microsoft outlook|outlook team|onedrive|"
        "sharepoint|azure",
        "microsoft microsoftonline office365 microsoft365 m365 o365 onedrive sharepoint outlook",
    ),
    _brand(
        "Google",
        "google.com gmail.com googlemail.com youtube.com",
        "google|gmail|google drive|google workspace",
        "google gmail googledrive",
    ),
    _brand(
        "Apple", "apple.com icloud.com", "apple support|apple id|apple pay|icloud", "apple icloud"
    ),
    _brand(
        "Amazon",
        "amazon.com amazon.co.uk amazon.ca amazon.de amazonaws.com",
        "amazon|aws|amazon web services",
        "amazon aws",
    ),
    _brand("PayPal", "paypal.com paypal.me", "paypal", "paypal"),
    _brand("DocuSign", "docusign.com docusign.net", "docusign", "docusign"),
    _brand("Adobe", "adobe.com", "adobe|adobe sign|acrobat", "adobe"),
    _brand("Dropbox", "dropbox.com dropboxmail.com", "dropbox", "dropbox"),
    _brand("LinkedIn", "linkedin.com", "linkedin", "linkedin"),
    _brand("Zoom", "zoom.us zoom.com", "zoom video|zoom meetings|zoom support", "zoom"),
    _brand("Okta", "okta.com", "okta", "okta"),
    _brand("Netflix", "netflix.com", "netflix", "netflix"),
    _brand("Coinbase", "coinbase.com", "coinbase", "coinbase"),
    _brand("MetaMask", "metamask.io", "metamask", "metamask"),
    _brand("cPanel", "cpanel.net cpanel.com", "cpanel", "cpanel"),
    _brand("DHL", "dhl.com dhl.de", "dhl", "dhl"),
    _brand("FedEx", "fedex.com", "fedex", "fedex"),
    _brand(
        "UPS", "ups.com", "ups delivery|ups my choice|ups notification|united parcel service", "ups"
    ),
    _brand("Intuit", "intuit.com", "intuit|quickbooks", "intuit quickbooks"),
    _brand("Chase", "chase.com", "chase bank|jpmorgan chase|chase online", "chase"),
    _brand("Bank of America", "bankofamerica.com bofa.com", "bank of america", "bankofamerica"),
    _brand("Wells Fargo", "wellsfargo.com", "wells fargo", "wellsfargo"),
    _brand(
        "SAM.gov",
        "sam.gov",
        "sam.gov|system for award management",
        "samgov sam-gov",
    ),
    _brand("Login.gov", "login.gov", "login.gov", "logingov login-gov"),
    _brand(
        "PIEE",
        "eb.mil",
        "piee|wawf|procurement integrated enterprise environment",
        "piee wawf",
    ),
)

# Consumer mailbox providers: anyone can create an address here.
FREEMAIL_DOMAINS = frozenset(
    """gmail.com googlemail.com yahoo.com ymail.com outlook.com hotmail.com live.com msn.com
    aol.com icloud.com me.com mac.com proton.me protonmail.com gmx.com gmx.net mail.com
    yandex.com yandex.ru zoho.com tutanota.com""".split()
)

# Display names that claim an internal role, which a free mailbox never legitimately holds.
ROLE_DISPLAY_NAMES = (
    "it department", "it support", "it helpdesk", "it help desk", "helpdesk", "help desk",
    "service desk", "it admin", "administrator", "system administrator", "payroll",
    "human resources", "hr department", "accounts payable", "accounts receivable",
    "finance department", "billing department", "security team", "ceo", "cfo", "president",
)  # fmt: skip

# Display names that claim to run the recipient's own email or IT. From an outside
# domain, that is the classic "your mailbox is full / password expires" pretext.
MAILBOX_ROLE_NAMES = (
    "email server", "mail server", "webmail", "web mail", "mail admin", "email admin",
    "mail administrator", "email administrator", "postmaster", "mailbox", "mail delivery",
    "email support", "mail support", "it helpdesk", "it help desk", "helpdesk", "help desk",
    "it support", "it department", "it admin", "system administrator", "administrator",
    "server admin", "account team", "security team",
)  # fmt: skip

# Services where anyone can publish a page for free. Legitimate companies rarely
# send links to them; fake sign-in pages very often live there.
FREE_HOSTING_DOMAINS = frozenset(
    """ipfs.io cloudflare-ipfs.com dweb.link r2.dev pages.dev workers.dev vercel.app
    netlify.app glitch.me web.app firebaseapp.com firebasestorage.googleapis.com appspot.com
    000webhostapp.com weebly.com wixsite.com square.site godaddysites.com blogspot.com
    github.io herokuapp.com onrender.com replit.app repl.co page.link azurewebsites.net
    web.core.windows.net ngrok.io ngrok-free.app trycloudflare.com translate.goog""".split()
)

URL_SHORTENERS = frozenset(
    """bit.ly tinyurl.com t.co goo.gl ow.ly is.gd buff.ly rebrand.ly cutt.ly shorturl.at
    rb.gy t.ly tiny.cc bl.ink s.id lnkd.in qrco.de v.gd shorte.st""".split()
)

# TLDs heavily over-represented in abuse reports (Spamhaus, Interisle). Low weight:
# plenty of legitimate sites use them too.
SUSPICIOUS_TLDS = frozenset(
    """zip mov xyz top click link country gq ml cf ga tk icu cyou buzz rest sbs cfd lol
    quest monster support bond cam work online site shop live""".split()
)

# --- Attachment extensions ---

EXECUTABLE_EXTENSIONS = frozenset(
    """exe scr com bat cmd pif msi msp js jse vbs vbe wsf wsh hta ps1 psm1 lnk jar cpl dll
    reg appx appxbundle msix application gadget scf url inf""".split()
)
HTML_EXTENSIONS = frozenset("html htm shtml xhtml svg mht mhtml".split())
DISK_IMAGE_EXTENSIONS = frozenset("iso img vhd vhdx".split())
MACRO_OFFICE_EXTENSIONS = frozenset("docm dotm xlsm xltm xlam pptm potm ppam ppsm sldm one".split())
ARCHIVE_EXTENSIONS = frozenset("zip rar 7z ace gz tgz tar cab arj z".split())
# Extensions a user expects to be a harmless document; used to spot "invoice.pdf.exe".
DOCUMENT_EXTENSIONS = frozenset(
    "pdf doc docx xls xlsx ppt pptx txt rtf csv jpg jpeg png gif odt".split()
)
