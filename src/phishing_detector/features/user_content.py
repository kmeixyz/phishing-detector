"""Hosts where a brand serves content written by strangers.

`is_known_brand_domain` asks who registered the name. On `sites.google.com`
the answer is Google, so the feature fires and the page inherits Google's
reputation -- but the *page* was written by whoever signed up. That is the gap
a credential kit at `sites.google.com/view/paypal-account-verify` walks
through, and it is not covered by `on_shared_hosting`: the Public Suffix List
has no private entry under `google.com`, so `sites.google.com` and
`www.google.com` are indistinguishable to it.

These hosts are therefore listed by hand. The list is deliberately narrow --
an exact-host match, no wildcards on the registrable domain -- because the
cost of a wrong entry is a legitimate brand host being treated as untrusted.
`accounts.google.com` is Google's own login page and must never appear here;
`sites.google.com` is a page builder anyone can publish to and must.
"""

from __future__ import annotations

# Exact hostnames only. A brand's operational subdomains (accounts, login,
# mail, api) are the brand speaking; these are the brand hosting strangers.
USER_CONTENT_HOSTS = frozenset({
    # Google
    "sites.google.com",       # page builder, open signup
    "docs.google.com",        # shared documents, published to web
    "drive.google.com",       # shared files
    "script.google.com",      # Apps Script web apps
    "groups.google.com",
    "forms.gle",
    # Microsoft
    "forms.office.com",
    "onedrive.live.com",
    "1drv.ms",
    "sway.office.com",
    # Where those now redirect. Microsoft moved Forms, Sway and Loop onto
    # cloud.microsoft, and a form link on forms.office.com lands on
    # forms.cloud.microsoft -- a host that, unlisted, read as Microsoft's own.
    "forms.cloud.microsoft",
    "forms.microsoft.com",
    "sway.cloud.microsoft",
    "loop.cloud.microsoft",
    # Publishing platforms on their own brand domains
    "notion.site",
    "canva.site",
    # IPFS path gateways: every page under them is someone's upload.
    "ipfs.io",
    "gateway.ipfs.io",
    "gateway.pinata.cloud",
    "cloudflare-ipfs.com",
})

# Domains where the host itself AND everything under it is a stranger's page.
#
# An exact-host list alone left the largest category open. Tenant platforms
# hand every customer their own subdomain -- `contoso.sharepoint.com`,
# `victim.zendesk.com` -- so there is no fixed hostname to list, and the whole
# point of the kit is that the tenant is attacker-chosen. Publishing platforms
# have the mirror-image problem: the user page sits on the brand's *apex*
# domain, so `is_known_brand_domain` fires on the registrable name itself.
#
# The same care as above applies: an entry here means the brand's reputation
# stops transferring to anything under this name, so it must be somewhere the
# brand publishes strangers' content and nothing else.
USER_CONTENT_DOMAINS = frozenset({
    # Tenant subdomain platforms
    "sharepoint.com",
    "zendesk.com",
    "atlassian.net",
    "myshopify.com",
    "weebly.com",
    "wixsite.com",
    "webflow.io",
    "freshdesk.com",
    "statuspage.io",
    "surveymonkey.com",
    "typeform.com",
    "jotform.com",
    # Publishing platforms whose user pages sit on the brand's own apex domain
    "linktr.ee",
    "medium.com",
    "substack.com",
    "tumblr.com",
    "blogger.com",
    "blogspot.com",
    "wordpress.com",
    "github.io",
    "gitbook.io",
    "glitch.me",
    "replit.app",
    "codepen.io",
    "carrd.co",
    "bio.link",
    "beacons.ai",
    # Brand names by coincidence: the regional list files these under Google
    # Forms (forms.gle) and archive.org because they share the label, and
    # every page on them is someone else's -- a form built on forms.app, a
    # snapshot on archive.today's mirrors.
    "forms.app",
    "archive.ph",
    "archive.is",
    "archive.today",
})

# Hosting platforms, where every customer site is a subdomain of the
# platform's own brand domain: `kit.sourceforge.io`, `box5432.bluehost.com/~kit/`,
# `<name>-8080.app.github.dev`. The registrable name is a brand key, so without
# this a credential kit there was "the real, official address" for SourceForge
# or GitHub. The platform's apex and operational hosts stay its own; a tenant
# subdomain withholds the brand's reputation but is not, alone, proof of
# anything -- people do run real logins on these.
HOSTING_DOMAINS = frozenset({
    "sourceforge.io",
    "squarespace.com",
    "cdn.ampproject.org",     # the AMP cache republishes any AMP page
    "app.github.dev",         # Codespaces port forwarding
    "hostgator.com",          # temporary server URLs, gatorNNNN.hostgator.com/~user
    "bluehost.com",           # boxNNNN.bluehost.com/~user
    "core.windows.net",       # Azure storage and static websites
    # Site builders and free hosts that put every customer on a subdomain of
    # their own name, and are not on the Public Suffix List, so without an
    # entry a customer's page was dated by the platform's registration: a
    # jimdofree.com page asking, in German, for an email and password was
    # "established" on Jimdo's 2018 domain and called safe. Here, not in
    # USER_CONTENT_DOMAINS, because several apexes are the company's own site
    # and login, which must not read as a stranger's page.
    "jimdofree.com", "jimdosite.com", "jimdo.com",
    "weeblysite.com", "godaddysites.com", "myftpupload.com",
    "site123.me", "strikingly.com", "mystrikingly.com",
    "webnode.page", "webnode.com", "tilda.ws", "durable.co", "mozello.com",
    "simdif.com", "ukit.me", "ucoz.net", "zyrosite.com", "hostingersite.com",
    "webador.site", "weblium.site", "site.pro", "flazio.com", "websitehome.co.uk",
    "webador.com", "webador.nl", "webador.de", "webador.fr", "webador.be",
    "webador.co.uk", "webador.es", "webador.it", "b12sites.com",
    "hubspotpagebuilder.com", "hs-sites.com", "zohosites.com",
    "notion.site", "canva.site", "gamma.site", "glide.page", "softr.app",
    "tiiny.site", "static.app", "w3spaces.com", "neocities.org",
    "myportfolio.com", "pixieset.com", "beehiiv.com", "odoo.com",
    "teachable.com", "thinkific.com", "mykajabi.com", "gumroad.com",
    "codesandbox.io", "csb.app", "stackblitz.io", "edgeone.dev", "pastehtml.dev",
    # Shared and temporary hosting names for customers' sites and servers
    "mybluehost.me", "dothome.co.kr", "contaboserver.net", "cloudclusters.net",
    # InfinityFree and its sibling free-hosting names
    "rf.gd", "epizy.com", "wuaze.com", "free.nf", "infinityfreeapp.com",
    # IPFS gateways that serve any content under a subdomain
    "w3s.link", "nftstorage.link", "mypinata.cloud", "4everland.app", "fleek.co",
})


# Subdomains that are the platform speaking rather than a customer publishing.
# `www.weebly.com/app/login` is Weebly's own login page; matching it as user
# content made a credential form there decisive evidence of phishing, and the
# scanner called Weebly's sign-in a scam. The list is deliberately generous:
# a missed tenant costs a withheld benign rule, a wrongly matched operational
# host costs a false accusation against a real login page.
OPERATIONAL_SUBDOMAINS = frozenset({
    "www", "login", "signin", "sign-in", "accounts", "account", "auth", "id",
    "sso", "oauth", "my", "secure", "admin", "api", "app", "apps", "portal",
    "dashboard", "console", "help", "support", "status", "docs", "developer",
    "developers", "blog", "about", "legal", "billing", "static", "cdn",
    "assets", "img", "mail", "email", "go", "get", "shop", "store",
})


def _matches_domain(host: str) -> tuple[bool, bool]:
    """(is user content, is a host a stranger was given).

    The two are not the same question and conflating them convicted real login
    pages. `contoso.sharepoint.com` is a host handed to a customer -- nobody but
    that customer serves anything there, so a credential form on it is
    conclusive. `linktr.ee` is the platform's *own* apex: user pages live at
    paths under it, and so does Linktree's own sign-in form. The brand's
    reputation must not clear a page there, but neither can a password field on
    it be treated as proof of anything.
    """
    for domain in USER_CONTENT_DOMAINS:
        if host == domain:
            return True, False
        if host.endswith("." + domain):
            nearest = host[: -(len(domain) + 1)].rsplit(".", 1)[-1]
            if nearest in OPERATIONAL_SUBDOMAINS:
                return False, False
            return True, True
    for domain in HOSTING_DOMAINS:
        if host.endswith("." + domain):
            nearest = host[: -(len(domain) + 1)].rsplit(".", 1)[-1]
            return nearest not in OPERATIONAL_SUBDOMAINS, False
    return False, False


def serves_user_content(hostname: str) -> bool:
    """True when `hostname` is a brand host that publishes strangers' pages.

    Used to withhold the brand's reputation, never on its own to accuse.
    """
    host = hostname.lower().strip(".")
    if host in USER_CONTENT_HOSTS:
        return True
    return _matches_domain(host)[0]


def stranger_controls_host(hostname: str) -> bool:
    """True when the *host itself* was handed to someone who is not the brand.

    This is the stronger claim, and the one a decisive rule may rest on. An
    exact entry in `USER_CONTENT_HOSTS` qualifies: `sites.google.com` is a page
    builder and is never where Google asks for a password -- `accounts.google.com`
    is, and is deliberately absent from that list.
    """
    host = hostname.lower().strip(".")
    if host in USER_CONTENT_HOSTS:
        return True
    return _matches_domain(host)[1]


def tenant_platform(hostname: str, cloud_hosts: frozenset[str] = frozenset()) -> str:
    """The platform whose customer this host is, or "".

    `kit-x.sourceforge.io` is a SourceForge customer's site, not SourceForge's,
    in the same way `kit.vercel.app` is a Vercel customer's -- but the public
    suffix list only knows the second, so an address breakdown marked
    `sourceforge.io` as "the site you are really visiting".
    """
    host = hostname.lower().strip(".")
    for domain in (*USER_CONTENT_DOMAINS, *HOSTING_DOMAINS, *cloud_hosts):
        if host.endswith("." + domain):
            nearest = host[: -(len(domain) + 1)].rsplit(".", 1)[-1]
            if nearest not in OPERATIONAL_SUBDOMAINS:
                return domain
    return ""
