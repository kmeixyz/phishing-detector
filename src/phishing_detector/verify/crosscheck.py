"""The second opinion.

WHAT THIS CANNOT DO

It cannot guarantee that no false positive or false negative ever happens. No
classifier can, and any component claiming to would just be a second
classifier with its own errors. Perfect separation is not available at any
level of effort: legitimate login pages and credential phishing share most of
their observable surface, which is precisely why this problem is hard.

WHAT IT DOES INSTEAD

It runs a rule engine that shares no machinery with the model — hand-written
conditions over raw evidence, no learned weights, no training data — and then
compares the two verdicts. Three outcomes:

  * both agree            -> the verdict stands, and is marked corroborated
  * rules override        -> a small set of near-unambiguous conditions that
                             outrank a learned score in both directions
  * they disagree         -> ABSTAIN. The scan returns "needs review" and says
                            exactly what disagreed, instead of picking a side

Abstention is the actual safety mechanism. A system that refuses to answer
when its two independent estimates conflict produces far fewer confident
mistakes than one that always commits — at the cost of answering less often,
which is the right trade when a false positive lands on a real bank.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..features.base import FeatureSet
from ..i18n import bi, of_zh, pad, zh

CONFIRMED_PHISH = "confirmed_phish"
CONFIRMED_BENIGN = "confirmed_benign"
NEEDS_REVIEW = "needs_review"

# How far below the operating threshold the "too close to call" zone reaches.
# 0.7 rather than something tighter because the threshold itself is already
# tuned to precision >= 0.95: scores just under it are still meaningfully
# risky, not noise. Lives here rather than in `model.score` (which would be
# the more obvious home) because `explain.plain` needs it too, and importing
# it from `model.score` there would be circular - `model.score` imports
# `explain.plain` to build the summary it attaches to each verdict.
MID_BAND_RATIO = 0.7


@dataclass
class Rule:
    name: str
    direction: int          # +1 toward phishing, -1 toward benign
    weight: str             # "decisive" | "strong" | "supporting"
    why: str


@dataclass
class Review:
    decision: str
    rule_verdict: str
    model_verdict: str
    agreed: bool
    fired: list[Rule] = field(default_factory=list)
    concerns: list[str] = field(default_factory=list)      # advisory only
    blocking: list[str] = field(default_factory=list)      # force abstention
    override: str = ""

    @property
    def abstained(self) -> bool:
        return self.decision == NEEDS_REVIEW


def _on(fs: FeatureSet, name: str) -> bool:
    """True only if the feature is present AND set. Absent is never True."""
    return name in fs and fs[name].present and bool(fs[name].value)


def same_company(fs: FeatureSet, brands: list[str]) -> bool:
    """True when every brand named belongs to the company that owns this page.

    Microsoft's sign-in page loads Microsoft's CDN and Gmail's sign-in page on
    accounts.google.com is titled Gmail. Neither is borrowing anything.
    """
    owners = set(fs["page_owner_brands"].detail.split(",")) if _on(fs, "page_owner_brands") else set()
    named = {b for b in brands if b}
    return bool(owners) and bool(named) and named <= owners


def _val(fs: FeatureSet, name: str, default: float | None = None) -> float | None:
    if name in fs and fs[name].present and fs[name].value is not None:
        return float(fs[name].value)
    return default


def registration_describes_page(fs: FeatureSet) -> bool:
    """Whether the domain's registration is evidence about *this page*.

    It is not when the page sits on a provider's domain or behind a shortener
    or a cross-domain redirect -- those inherited Backblaze's and goo.su's
    registration and cleared real phishing as "established" -- nor on a host
    that publishes strangers' pages. Public so the plain-language summary asks
    the same question before it says "this website was set up years ago".
    """
    return (
        not _on(fs, "on_shared_hosting")
        and not _on(fs, "is_shortener")
        # After a redirect the lookups describe the submitted address -- unless
        # they were repeated for the destination.
        and (not _on(fs, "final_domain_changed") or _on(fs, "evidence_follows_redirect"))
        # A page a stranger published under a brand's name is the same case as
        # a provider subdomain: the registration describes whoever owns the
        # name, and that is not whoever wrote this.
        and not _on(fs, "user_content_on_brand_domain")
        # The same for a host that publishes strangers' pages under a name the
        # brand list does not know -- onedrive.live.com, forms.cloud.microsoft.
        and not _on(fs, "user_content_host")
    )


def run_rules(fs: FeatureSet) -> list[Rule]:
    """Hand-written conditions over raw evidence. No learned weights."""
    fired: list[Rule] = []
    has_pw = (_on(fs, "has_password_input") or _on(fs, "js_injected_password")
              or _on(fs, "concealed_password_input"))

    # Whether the registration evidence is about *this site* (see
    # `registration_describes_page`). Every benign rule further down relies on
    # it, and so do the exemptions for long-lived names.
    registration_is_ours = registration_describes_page(fs)
    age = _val(fs, "domain_age_days")
    ct_age = _val(fs, "ct_age_days")
    # A brand's name on a suffix the list does not know is a kit's favourite
    # shape -- unless the name is years old. The list holds one domain per
    # brand, so HSBC's hsbc.co.uk reads as "hsbc on the wrong suffix" against
    # hsbc.com; a kit cannot have registered it in 1996. Registration age is
    # the first witness. Certificate Transparency is the second, for the
    # registries that publish no dates at all (.de, .hk): a certificate
    # logged for this very name three years ago is something no kit has.
    # The CT lookup falls back only as far as the registrable name, never to
    # a hosting provider's apex, so a kit on a provider subdomain does not
    # inherit the provider's history here. Nor, after a redirect to another
    # domain, does the page inherit the history of the name that redirected:
    # CT is looked up for the submitted address, and an aged redirector in
    # front of `paypal.cfd` was vouching for it.
    old_enough = 3 * 365
    ct_is_ours = not _on(fs, "final_domain_changed") or _on(fs, "evidence_follows_redirect")
    long_lived = (
        (registration_is_ours and age is not None and age > old_enough)
        or (ct_age is not None and ct_age > old_enough and ct_is_ours)
    )
    # Positive evidence of youth, for the rules that only exist to catch new
    # names. Registries like .de publish no dates and the CT services fail
    # often, so "no age known" must not count as "young": a real regional
    # brand site would lose its standing whenever crt.sh had a bad minute.
    # CT counts here only when its history is complete: Certspotter lists
    # unexpired certificates alone, so every age it gives is under about a
    # year and would have called every undated (.de, .ac.uk) site young.
    known_age = (age if registration_is_ours and age is not None
                 else ct_age if ct_is_ours and _on(fs, "ct_history_complete") else None)
    proven_young = known_age is not None and known_age <= old_enough

    # ---- decisive, toward phishing ---------------------------------------
    # Decisive for a channel no real page uses, or for any channel on a page
    # that asks for a password or other sensitive details. A form service or
    # a chat id alone is also an ordinary contact form or support widget.
    asks = has_pw or _val(fs, "sensitive_field_count", 0) > 0
    if _on(fs, "exfil_endpoint") and (_on(fs, "exfil_strong_channel") or asks):
        fired.append(Rule("exfil_endpoint", +1, "decisive",
                          bi(f"Credentials are posted to {fs['exfil_endpoint'].detail}. "
                             "No legitimate sign-in form does this.",
                             f"账号密码会被提交到 {fs['exfil_endpoint'].detail}。"
                             "没有任何正规的登录表单会这样做。")))
    if _on(fs, "homograph_brand_match"):
        fired.append(Rule("homograph_brand_match", +1, "decisive",
                          bi(f"The domain is a look-alike of a brand name "
                             f"({fs['homograph_brand_match'].detail}).",
                             f"这个域名是某个品牌名称的仿冒（{fs['homograph_brand_match'].detail}）。")))
    # The model's flag compares the icon's brand with the page's name, so a kit
    # at `paypal.cfd` or `paypal.vercel.app` serving PayPal's exact icon was
    # "on PayPal's own name" and never flagged. `favicon_on_brand_named_domain`
    # covers that shape, and gives it the same allowance for years of history
    # that `brand_wrong_suffix` gives: a brand's real regional site can be
    # missing from the regional list, a kit cannot be a decade old.
    copied_icon = _on(fs, "favicon_brand_impersonation") or (
        _on(fs, "favicon_on_brand_named_domain") and proven_young)
    # A name on the regional list only by its label, and known to be new.
    unproven_regional = _on(fs, "brand_domain_regional") and proven_young
    if copied_icon and (not _on(fs, "favicon_on_owner_domain") or unproven_regional):
        icon_brand = (fs["favicon_brand_impersonation"].detail
                      if "favicon_brand_impersonation" in fs else "")
        # Strong, not decisive, on the front door of a domain registered
        # years ago: there an unlisted domain of the brand's own is likelier
        # than a kit (vk.com wearing VKontakte's icon, ya.ru Yandex's), while
        # kits on old, hacked sites live on pages inside them.
        long_held = (registration_is_ours and age is not None and age >= 5 * 365
                     and _on(fs, "site_home_page"))
        fired.append(Rule("favicon_impersonation", +1, "strong" if long_held else "decisive",
                          bi(f"The page serves {icon_brand or 'a brand'}'s "
                             "exact favicon from a domain that is not theirs.",
                             f"这个页面在一个不属于{pad(icon_brand, '该品牌')}的域名上，"
                             f"使用了和{pad(icon_brand, '该品牌')}一模一样的网站图标。")))
    if _val(fs, "brand_cdn_asset_ratio", 0.0) >= 0.10 and not same_company(
            fs, [fs["brand_cdn_asset_count"].detail] if "brand_cdn_asset_count" in fs else []):
        # The spec's "most reliable signal": a page serving assets from the CDN
        # of the brand it is impersonating. Distinct from `foreign_asset_ratio`,
        # which counts any other domain and fires on legitimate sites using
        # Google Fonts or their own asset host.
        #
        # Two thresholds set by measurement rather than intuition. The ratio
        # floor removes embedded widgets — a single Twitter or Apple asset among
        # dozens is a share button, not a copied page — and took precision from
        # 0.864 to 0.941 on the corpus.
        #
        # And it deliberately does NOT require a password field. That was the
        # original design and the data contradicted it: adding the requirement
        # dropped precision to 0.833, because many re-hosted brand pages are
        # lures and landing pages with no form on them at all.
        #
        # Strong rather than decisive: 16 of 17 fires were phishing, and the one
        # miss may itself be mislabelled. Two strong rules still reach a verdict.
        fired.append(Rule("brand_cdn_assets", +1, "strong",
                          bi(f"The page loads {fs['brand_cdn_asset_ratio'].detail}, the signature of a "
                             "page copied from that brand and re-hosted here.",
                             f"这个页面加载的资源中，{zh(fs['brand_cdn_asset_ratio'].detail)}，"
                             "这是照抄那个品牌的页面再放到这里托管的典型特征。")))
    if _on(fs, "asks_for_seed_phrase"):
        fired.append(Rule("asks_for_seed_phrase", +1, "decisive",
                          bi("The page asks for a wallet seed phrase or private key.",
                             "这个页面索要钱包助记词或私钥。")))
    if _on(fs, "has_userinfo"):
        # http://paypal.com@evil.ru/ renders as "paypal.com..." to a reader
        # skimming the address bar. There is no legitimate reason for a login
        # link to carry userinfo, and `has_userinfo` is held out of the model
        # as collection-biased, so nothing else was catching this.
        detail = fs["has_userinfo"].detail
        looks_like_host = "." in detail
        fired.append(Rule(
            "userinfo_deception", +1,
            "decisive" if looks_like_host else "strong",
            bi(f"The URL embeds {detail!r} before the real hostname, which makes the link "
               "read as though it points somewhere else.",
               f"这个网址在真正的主机名前面嵌入了“{detail}”，让链接看起来像是指向别处。")))
    if has_pw and (_on(fs, "form_action_insecure") or _on(fs, "form_posts_over_http")):
        fired.append(Rule("password_over_http", +1, "decisive",
                          bi("A password field posts over plain HTTP.",
                             "密码框通过普通 HTTP 提交。")))

    # ---- strong, toward phishing ------------------------------------------
    # A brand's own domain hosting a stranger's page. The name carries the
    # brand's reputation and the content carries none of it, which is the whole
    # appeal of these hosts to a kit author: `sites.google.com/view/...` reads
    # as Google to a person and resolves as Google to a checker. Strong rather
    # than decisive, so an ordinary Google Sites page lands at "not sure"
    # instead of being called a scam, while a credential form on one convicts.
    if _on(fs, "user_content_on_brand_domain"):
        fired.append(Rule("user_content_on_brand_domain", +1, "strong",
                          bi(f"The page is published on {fs['user_content_on_brand_domain'].detail}, "
                             "where anyone can host a page under the brand's name. The address "
                             "belongs to the brand; the page does not.",
                             f"这个页面发布在 {fs['user_content_on_brand_domain'].detail} 上，"
                             "任何人都可以在那里以这个品牌的名义托管页面。地址属于品牌，页面却不是。")))
    # `user_content_stranger_host`, not `user_content_on_brand_domain`. The
    # weaker feature is true of a platform's own apex, where the platform's own
    # sign-in form also lives -- resting a decisive rule on it called Linktree's
    # and Weebly's login pages scams.
    if has_pw and _on(fs, "user_content_stranger_host"):
        fired.append(Rule("credential_form_on_user_content", +1, "decisive",
                          bi("A password field on a page a stranger published under a brand's "
                             "domain. A real brand does not collect credentials through its "
                             "own public page builder.",
                             "一个陌生人在品牌域名下发布的页面上出现了密码框。"
                             "真正的品牌不会通过自己面向公众的建站工具收集账号密码。")))
    # The page moved itself after load. Content features describe what was
    # painted here; the address bar ends up somewhere else. That is a standard
    # cloaking shape and nothing else in the engine was looking at it.
    # Strong, not decisive, even with a password field present: single-page
    # login flows really do hand off to an identity provider after painting a
    # form, and calling those a scam outright is the expensive mistake here.
    # Strong is enough to do the job -- it stops a decisive benign rule and
    # convicts alongside any second strong signal.
    # The same, seen in the markup rather than by rendering: a meta refresh, or
    # on a doorway page a scripted navigation, to another domain. The page
    # that was scored is one the visitor does not stay on.
    if _on(fs, "client_redirect") and not _on(fs, "js_redirected"):
        fired.append(Rule("client_redirect", +1, "strong",
                          bi(f"As soon as it loads, the page sends the browser on to "
                             f"{fs['client_redirect'].detail}. That page was not examined.",
                             f"页面一加载就把浏览器转到了 {fs['client_redirect'].detail}。"
                             "那个页面没有被检查。")))
    if _on(fs, "js_redirected"):
        fired.append(Rule("js_redirected", +1, "strong",
                          bi(f"After loading, the page sent the browser to "
                             f"{fs['js_redirected'].detail or 'another site'}. The page that was "
                             "examined is not the page the address leads to.",
                             f"页面加载后把浏览器转到了{pad(fs['js_redirected'].detail, '另一个网站')}。"
                             "被检查的页面并不是这个地址最终通往的页面。")))
    if has_pw and _on(fs, "form_action_cross_domain"):
        fired.append(Rule("cross_domain_credential_post", +1, "strong",
                          bi("A password field posts to a different registrable domain.",
                             "密码框会提交到另一个可注册域名。")))
    # Not on the brand's own domain. These rules exist to catch a brand's name
    # somewhere it does not belong -- in a subdomain, in a path, in a query
    # string. On `login.microsoftonline.com`, every one of those is Microsoft
    # writing its own name on its own site, and a federated sign-in URL carries
    # the partner brand in `redirect_uri` as a matter of course. Left unguarded
    # they fired as two strong rules, which under the new precedence cancelled
    # the decisive "this is the brand's own domain" rule and convicted the real
    # Microsoft, Google and eBay sign-in pages.
    own_brand_domain = _on(fs, "is_known_brand_domain")
    if has_pw and _on(fs, "brand_in_wrong_position") and not own_brand_domain:
        fired.append(Rule("brand_outside_domain_with_login", +1, "strong",
                          bi(f"A login form on a domain that puts a brand name "
                             f"({fs['brand_in_wrong_position'].detail}) outside the "
                             "registrable domain.",
                             f"这个域名把品牌名称（{fs['brand_in_wrong_position'].detail}）放在"
                             "可注册域名之外，而页面上有登录表单。")))
    effective_age = age if age is not None else ct_age
    if has_pw and effective_age is not None and effective_age <= 14:
        fired.append(Rule("new_domain_with_login", +1, "strong",
                          bi(f"A credential form on a site first seen "
                             f"{int(effective_age)} days ago.",
                             f"一个 {int(effective_age)} 天前才首次出现的网站上有登录表单。")))
    if _on(fs, "asks_for_card") and has_pw:
        fired.append(Rule("card_and_password", +1, "strong",
                          bi("The page collects a card number alongside a password.",
                             "这个页面在索要密码的同时还索要银行卡号。")))
    # What Google has already concluded. Decisive, because it is a verdict
    # from a party that saw the page when the scanner may not have: a kit
    # behind a bot wall shows this scanner nothing and Google everything.
    # Kept out of the model on purpose (see verify/reputation.py); absent
    # unless a key is configured, and "not listed" fires nothing.
    if _on(fs, "safe_browsing_listed"):
        fired.append(Rule("safe_browsing_listed", +1, "decisive",
                          bi(f"Google Safe Browsing lists this address "
                             f"({fs['safe_browsing_listed'].detail}).",
                             f"Google 安全浏览（Safe Browsing）列出了这个地址"
                             f"（{zh(fs['safe_browsing_listed'].detail)}）。")))
    tsq = _val(fs, "typosquat_distance")
    # One or two edits is a lookalike. Zero is the brand's own name, and what
    # that means depends on the suffix: on the brand's domain it is the brand
    # (`is_known_brand_domain`), on any other it is `brand_sld_wrong_suffix`
    # below. Firing here at zero called bankofamerica.com a typosquat of
    # itself for as long as the brand list had no domain for it.
    # Nor on a company's own listed domain: office.com lands on
    # m365.cloud.microsoft, and "cloud" is one edit from "icloud". A domain
    # Microsoft owns is not a lookalike of Apple, whatever the edit distance --
    # and that holds on its user-content hosts too, since this is a claim about
    # the name, not the page (`domain_owner_brands`, not `page_owner_brands`).
    if tsq is not None and 1 <= tsq <= 2 and not _on(fs, "is_known_brand_domain") \
            and not _on(fs, "domain_owner_brands") and not _on(fs, "restricted_registry"):
        fired.append(Rule("typosquat", +1, "strong",
                          bi(f"The domain is {fs['typosquat_distance'].detail}.",
                             f"这个域名{zh(fs['typosquat_distance'].detail)}。")))
    if _on(fs, "brand_sld_wrong_suffix") and not long_lived and not _on(fs, "restricted_registry"):
        fired.append(Rule("brand_wrong_suffix", +1, "strong",
                          bi(f"A brand name on an unexpected suffix "
                             f"({fs['brand_sld_wrong_suffix'].detail}).",
                             f"品牌名称用在了意料之外的后缀上（{fs['brand_sld_wrong_suffix'].detail}）。")))

    # ---- page-intrinsic, added on temporal evidence -----------------------
    #
    # The leave-one-out ablation put `title_domain_mismatch` first by a clear
    # margin (removing it costs 0.074 temporal recall), with
    # `sensitive_field_count`, `brand_embedded_in_domain`, `external_link_ratio`
    # and `dead_anchor_ratio` close behind. All describe what the page *is*,
    # which is why they survive infrastructure churn — and the rule engine's
    # precision improves across time (0.900 -> 0.962) where the model's decays.
    if has_pw and _on(fs, "title_domain_mismatch") and not same_company(
            fs, fs["title_domain_mismatch"].detail.split(", ")):
        fired.append(Rule("title_claims_another_brand", +1, "strong",
                          bi(f"The page titles itself as {fs['title_domain_mismatch'].detail} "
                             "while asking for a password on a domain that is not theirs.",
                             f"页面标题自称是 {fs['title_domain_mismatch'].detail}，"
                             "却在一个不属于他们的域名上要求输入密码。")))
    if has_pw and _on(fs, "brand_embedded_in_domain") and not own_brand_domain:
        fired.append(Rule("brand_in_domain_with_login", +1, "strong",
                          bi(f"A credential form on a domain with the brand name "
                             f"{fs['brand_embedded_in_domain'].detail} buried inside it.",
                             f"一个夹带了品牌名称 {fs['brand_embedded_in_domain'].detail} 的域名上有登录表单。")))
    dead = _val(fs, "dead_anchor_ratio")
    if has_pw and dead is not None and dead > 0.6:
        fired.append(Rule("mirrored_page", +1, "strong",
                          bi(f"{fs['dead_anchor_ratio'].detail} of the links go nowhere, the shape of a "
                             "kit that mirrored one page and dropped the rest of the site, "
                             "and the page asks for a password.",
                             f"链接中，{of_zh(fs['dead_anchor_ratio'].detail)}打不开，"
                             "这是钓鱼工具包只复制一个页面、丢掉网站其余部分的样子，而且页面要求输入密码。")))
    # A "high foreign asset ratio + password field" rule was tried here and
    # removed: it scored 0.717 precision on the temporal test set (33 phishing,
    # 13 benign). Large legitimate sites serve assets from a separate domain —
    # wikipedia.org pulls from wikimedia.org — exactly as noted in
    # features/content.py. The signal the spec actually describes is assets
    # loading from *the impersonated brand's* CDN, which needs a feature that
    # knows whose CDN it is. `foreign_asset_ratio` cannot distinguish the two,
    # so it stays a weighted model feature and does not get a rule.
    if _val(fs, "sensitive_field_count", 0) >= 2 and has_pw:
        # Supporting, not strong: 0.600 precision on the temporal test set.
        # Retail and banking pages legitimately collect card details next to a
        # password, so this corroborates rather than decides.
        fired.append(Rule("multiple_sensitive_fields", +1, "supporting",
                          bi(f"The page collects several categories of sensitive data "
                             f"({fs['sensitive_field_count'].detail}) alongside a password.",
                             f"这个页面在索要密码的同时，还收集多类敏感信息"
                             f"（{zh(fs['sensitive_field_count'].detail)}）。")))

    # ---- supporting -------------------------------------------------------
    if _on(fs, "b64_hidden_exfil"):
        fired.append(Rule("hidden_exfil", +1, "supporting",
                          bi("An exfiltration endpoint was hidden in a base64 blob.",
                             "一个外传数据的地址被藏在了 base64 数据块里。")))
    if _val(fs, "kit_marker_count", 0) >= 2:
        fired.append(Rule("kit_markers", +1, "supporting",
                          bi(f"Multiple phishing-kit markers: {fs['kit_marker_count'].detail}.",
                             f"发现多个钓鱼工具包的标记：{fs['kit_marker_count'].detail}。")))
    if _on(fs, "js_download_attempt"):
        fired.append(Rule("download_attempt", +1, "supporting",
                          bi("The page attempted to start a file download.",
                             "页面试图开始下载文件。")))

    # ---- toward benign -----------------------------------------------------
    # Every benign rule below must first establish that the registration it is
    # about actually belongs to *this site*. It does not when the page sits on
    # a provider's domain or behind a shortener — those inherited Backblaze's
    # and goo.su's registration and cleared real phishing as "established".

    # A brand's registration says who owns the name, never who wrote the page.
    # On a host that publishes strangers' pages those are different parties, so
    # the brand's reputation must not clear the content: the rule is withheld,
    # and `user_content_on_brand_domain` above argues the other way instead.
    if _on(fs, "is_known_brand_domain") and not _on(fs, "user_content_on_brand_domain") \
            and not unproven_regional:
        fired.append(Rule("known_brand_domain", -1, "decisive",
                          bi(f"{fs['is_known_brand_domain'].detail} is the brand's own "
                             "registered domain.",
                             f"{fs['is_known_brand_domain'].detail} 是这个品牌自己注册的域名。")))
    # The same trust for a domain the brand-owner table lists: x.com is
    # Twitter's and m365.cloud.microsoft is Microsoft's, but neither is the
    # one canonical domain `brands.json` records, so after twitter.com or
    # office.com redirected there the scan had no benign rule to stand on and
    # came back "not sure". Never on a host that publishes strangers' pages:
    # `page_owner_company` is empty there by construction.
    # Strong, not decisive: the company chose the destination, but a page can
    # change after a link is made, so what it does still counts against it.
    if _on(fs, "sent_by_company_shortener"):
        who = fs["sent_by_company_shortener"].detail
        fired.append(Rule("company_shortener", -1, "strong",
                          bi(f"The link is {who}'s own shortener, where only {who} can create "
                             f"links, so {who} chose where it leads.",
                             f"这是{pad(who)}自己的短链接服务，只有{pad(who)}能在上面生成链接，"
                             f"所以链接通往哪里是{pad(who)}决定的。")))
    if _on(fs, "page_owner_company") and not _on(fs, "is_known_brand_domain"):
        fired.append(Rule("company_owned_domain", -1, "decisive",
                          bi(f"{fs['page_owner_company'].detail}.",
                             f"{zh(fs['page_owner_company'].detail)}。")))
    if registration_is_ours and age is not None and age > 730 and _on(fs, "has_mx"):
        fired.append(Rule("established_domain", -1, "strong",
                          bi(f"Registered {int(age // 365)} years ago and receives mail.",
                             f"{int(age // 365)} 年前注册，并且能接收邮件。")))
    if not registration_is_ours:
        fired.append(Rule("registration_not_ours", +1, "supporting",
                          bi("The page sits on a provider domain or behind a redirect, so "
                             "its registration history describes the host, not this site.",
                             "这个页面位于服务商的域名上，或者藏在一次跳转之后，"
                             "所以它的注册历史描述的是托管方，而不是这个网站。")))
    if registration_is_ours and has_pw and not _on(fs, "form_action_cross_domain") and \
            not _on(fs, "form_action_insecure") and not _on(fs, "form_posts_over_http") and \
            _on(fs, "tls_hostname_match"):
        fired.append(Rule("clean_login_form", -1, "supporting",
                          bi("The login form posts to its own domain over valid TLS.",
                             "登录表单通过有效的 TLS 加密提交到它自己的域名。")))
    return fired


def _weighing(fired: list[Rule], direction: int, weight: str) -> list[Rule]:
    """The fired rules of one weight pointing one way (+1 phishing, -1 benign)."""
    return [r for r in fired if r.direction * direction > 0 and r.weight == weight]


def rule_verdict(fired: list[Rule]) -> str:
    """Collapse the fired rules into one of the three outcomes."""
    decisive_bad = _weighing(fired, +1, "decisive")
    decisive_good = _weighing(fired, -1, "decisive")
    strong_bad = _weighing(fired, +1, "strong")
    strong_good = _weighing(fired, -1, "strong")

    # Incriminating evidence is weighed before the benign rules, and a single
    # strong phishing rule is enough to stop a decisive benign one.
    #
    # It used to be the other way around: "this is the brand's own registered
    # domain" cleared a page outright no matter how much fired against it. But
    # that rule answers who registered a *name*, and every strong rule here is
    # about what the *page* does -- a credential form posting off-domain, a
    # brand's icon on someone else's site. When those disagree, the page wins,
    # or at minimum nobody wins and the scan says so. Being unsure is a usable
    # answer here; a confident green on a credential harvester is not.
    if decisive_bad:
        return CONFIRMED_PHISH
    if len(strong_bad) >= 2:
        return CONFIRMED_PHISH
    if decisive_good and not strong_bad:
        return CONFIRMED_BENIGN
    if strong_good and not strong_bad:
        return CONFIRMED_BENIGN
    return NEEDS_REVIEW


def _wall(who: str) -> str:
    """How the page was withheld: a named bot-detection vendor, or a bare status."""
    if who.startswith("HTTP 5"):
        return bi(f"The site failed to serve the page ({who})", f"这个网站没能提供页面（{who}）")
    if who.startswith("HTTP "):
        return bi(f"The site refused to serve the page ({who})", f"这个网站拒绝提供页面（{who}）")
    return bi(f"The site answered with a bot-detection page ({who}) instead of its content",
              f"这个网站返回的是一个机器人检测页面（{who}），而不是它的内容")


def evidence_concerns(fs: FeatureSet, collectors_ok: int,
                      collectors_total: int) -> tuple[list[str], list[str]]:
    """(blocking, advisory).

    Blocking means the evidence is genuinely insufficient to decide, so the
    scan should abstain. Advisory means the verdict is worth caveating but not
    withholding — treating every caveat as blocking made the system abstain on
    google.com, which is not a useful safety property, it is just noise.
    """
    blocking: list[str] = []
    advisory: list[str] = []

    if collectors_total and collectors_ok < collectors_total * 0.6:
        blocking.append(bi(f"Only {collectors_ok} of {collectors_total} collectors returned.",
                           f"{collectors_total} 项查询中只有 {collectors_ok} 项返回了结果。"))
    if _on(fs, "fetch_failed"):
        blocking.append(bi("The page could not be fetched, so there is no content evidence.",
                           "页面无法获取，所以没有任何内容方面的证据。"))
    if _on(fs, "fetch_blocked"):
        # Advisory, not blocking. The site is up and declined to serve a
        # scanner; registration, DNS and TLS evidence all still stand, and
        # both real brands and kits put up walls, so the wall itself decides
        # nothing. What it does mean is that no content feature was observed.
        advisory.append(_wall(fs["fetch_blocked"].detail)
                        + bi(", so nothing about the page itself was checked.",
                             "，所以页面本身的内容没有被检查。"))
    if _on(fs, "body_truncated"):
        advisory.append(
            bi(f"The page was larger than the fetch limit ({fs['body_truncated'].detail}), so "
               "content features describe only the part that was read.",
               f"页面超过了获取上限（{zh(fs['body_truncated'].detail)}），"
               "所以内容特征只描述了读取到的那一部分。"))
    if _on(fs, "destination_unreached"):
        # Blocking, not advisory. The evidence describes an earlier hop than
        # the one the visitor lands on, and the last hop is chosen by the site
        # under investigation -- so left unblocked this is a way to have some
        # other domain's good name attached to the verdict.
        blocking.append(bi(f"The redirect chain did not complete: {fs['destination_unreached'].detail}. "
                           "The evidence describes an earlier hop, not the final destination.",
                           f"跳转过程没有完成：{zh(fs['destination_unreached'].detail)}。"
                           "证据描述的是中途的一站，而不是最终目的地。"))
    if _on(fs, "page_missing"):
        blocking.append(bi(f"The page at this address does not exist ({fs['page_missing'].detail}), "
                           "so there is nothing here to check.",
                           f"这个地址上的页面不存在（{fs['page_missing'].detail}），所以这里没有可以检查的东西。"))
    if _on(fs, "short_link_dead_end"):
        blocking.append(bi(f"The short link on {fs['short_link_dead_end'].detail} does not lead "
                           "anywhere now, so its destination could not be checked.",
                           f"{fs['short_link_dead_end'].detail} 上的这个短链接现在已经不指向任何地方，"
                           "所以无法检查它的目的地。"))
    if _on(fs, "client_redirect") and not _on(fs, "js_redirected"):
        # Blocking for the same reason as an unfinished redirect chain: the
        # evidence describes a page the visitor is moved off, and the site
        # under investigation chose where they go instead.
        blocking.append(bi(f"The page immediately forwards visitors to "
                           f"{fs['client_redirect'].detail}, which was not checked.",
                           f"这个页面会立刻把访问者转到 {fs['client_redirect'].detail}，而那里没有被检查。"))
    if _on(fs, "render_empty") and not _on(fs, "js_rendered"):
        advisory.append(bi("The page renders client-side and was not rendered, so content "
                           "features describe an empty shell rather than the real page.",
                           "这个页面需要在浏览器端渲染，但没有被渲染，所以内容特征描述的是一个空壳，"
                           "而不是真正的页面。"))
    if _on(fs, "serves_download"):
        # Blocking: a download is not a page, and every content feature, rule
        # and score here is about pages. "Nothing suspicious found" on a link
        # that hands over an executable was an answer to a question nobody
        # asked, in the voice of one they did.
        blocking.append(bi(f"The address serves a file ({fs['serves_download'].detail}) rather "
                           "than a web page. This check reads pages; it cannot tell whether a "
                           "file is safe to open, or what a document says.",
                           f"这个地址提供的是一个文件（{fs['serves_download'].detail}），而不是网页。"
                           "本检查读取的是网页，无法判断一个文件打开是否安全，也看不到文档里写了什么。"))
    if _on(fs, "tls_problem"):
        advisory.append(bi(f"The site's security certificate is not valid: "
                           f"{fs['tls_problem'].detail}. Browsers warn before opening it.",
                           f"这个网站的安全证书无效：{zh(fs['tls_problem'].detail)}。"
                           "浏览器在打开它之前会发出警告。"))
    if _on(fs, "connection_unencrypted"):
        advisory.append(bi("The page is served over plain HTTP, so anything typed into it "
                           "travels unencrypted.",
                           "这个页面通过普通 HTTP 提供，所以在上面输入的任何内容都会以未加密的方式传输。"))
    if _val(fs, "domain_age_days") is None and _val(fs, "ct_age_days") is None:
        advisory.append(bi("No age signal: registration lookup failed and CT history was "
                           "unavailable.",
                           "没有关于网站年龄的信号：注册信息查询失败，也无法获取证书透明度历史。"))
    return blocking, advisory


def single_signal_share(contributions: dict[str, float]) -> tuple[str, float]:
    """The largest single contributor's share of total absolute movement."""
    total = sum(abs(v) for v in contributions.values())
    if total <= 0:
        return "", 0.0
    name, value = max(contributions.items(), key=lambda kv: abs(kv[1]))
    return name, abs(value) / total


def _opposed(fired: list[Rule], model: str) -> bool:
    """Whether a fired rule points the other way from the model.

    Against a phishing call only a rule that could decide something counts.
    `clean_login_form` -- a password form posting to its own host over valid
    TLS -- is true of every self-hosted kit, and as a veto it turned a 0.99
    score with a tight interval into "not sure" on exactly the pages it
    describes. Against a benign call any rule still counts: a supporting
    reason for doubt is enough not to clear a page.
    """
    if model == CONFIRMED_PHISH:
        return any(r.direction < 0 and r.weight != "supporting" for r in fired)
    return any(r.direction > 0 for r in fired)


def _model_stands_alone(model: str, probability: float, threshold: float,
                        interval, fs: FeatureSet) -> bool:
    """Whether a verdict with no rule behind it may rest on the model.

    Both directions need a bootstrap interval that does not straddle the
    line. Toward phishing the point must also sit well past it -- halfway to
    certainty -- because the operating point was chosen for precision at the
    line, not beyond it. Toward benign the page must have been fully seen: a
    site that withheld its page or could not be fetched has shown the model
    nothing, and a low score on nothing clears nothing.
    """
    if interval is None or interval.straddles(threshold):
        return False
    if model == CONFIRMED_PHISH:
        # Not on a page that asks for nothing: a scam page has to ask for
        # something, and a score with no rule behind it is mostly the
        # address's age and hosting, which a new site of any kind shares.
        if not (interval.low >= threshold and probability >= (1.0 + threshold) / 2):
            return False
        if _on(fs, "asks_for_nothing"):
            return False
        # A page built by scripts that were not run showed the model a shell:
        # "1 of 1 links dead" and "2 of 2 assets foreign" describe the shell.
        # On a site's own domain known to be days or weeks old that is still a
        # kit's shape (four of a day's feed, all under four days old); on an
        # older one it is how a year-old casino site was called a scam. On a
        # host strangers publish to (weebly.com, vercel.app, github.io) the
        # age is the platform's and says nothing either way, and nine of the
        # same day's kits were shells there: the model's call stands.
        if (_on(fs, "render_empty") and not _on(fs, "content_from_render")
                and registration_describes_page(fs)):
            age = _val(fs, "domain_age_days")
            return age is not None and age <= 90
        return True
    if _on(fs, "fetch_blocked") or _on(fs, "fetch_failed") or _on(fs, "destination_unreached"):
        return False
    return interval.high < threshold * MID_BAND_RATIO


def review(fs: FeatureSet, model_probability: float, threshold: float,
           contributions: dict[str, float], collectors_ok: int,
           collectors_total: int, interval=None) -> Review:
    fired = run_rules(fs)
    rules = rule_verdict(fired)
    model = CONFIRMED_PHISH if model_probability >= threshold else CONFIRMED_BENIGN

    blocking, concerns = evidence_concerns(fs, collectors_ok, collectors_total)

    # The design's "borderline" state, derived rather than hand-set: when the
    # bootstrap interval contains the operating threshold, the point estimate
    # is not stable enough to act on. Which side of the line it lands on is
    # then an artifact of which URLs happened to be collected.
    unstable: list[str] = []
    if interval is not None and interval.straddles(threshold):
        unstable.append(
            bi(f"The 90% interval [{interval.low:.2f}, {interval.high:.2f}] straddles the "
               f"{threshold:.2f} threshold, so the score is not stable.",
               f"90% 区间 [{interval.low:.2f}, {interval.high:.2f}] 横跨了 {threshold:.2f} 的阈值，"
               "所以分数并不稳定。")
        )
    elif interval is not None and interval.width > 0.4:
        concerns.append(
            bi(f"Wide 90% interval [{interval.low:.2f}, {interval.high:.2f}]. The score "
               "depends heavily on which training data was collected.",
               f"90% 区间 [{interval.low:.2f}, {interval.high:.2f}] 很宽。"
               "分数在很大程度上取决于收集到的是哪些训练数据。")
        )

    top_name, share = single_signal_share(contributions)
    if share > 0.7 and top_name:
        concerns.append(
            bi(f"The score is {share:.0%} driven by one feature ({top_name}). "
               "Single-signal verdicts are brittle.",
               f"分数有 {share:.0%} 是由单个特征（{top_name}）决定的。只靠一个信号得出的结论很脆弱。")
        )

    decisive_good = _weighing(fired, -1, "decisive")
    decisive_bad = _weighing(fired, +1, "decisive")

    override = ""
    if decisive_bad:
        # Decisive incriminating evidence means we *saw* something, so it
        # outranks everything including thin coverage elsewhere.
        decision = CONFIRMED_PHISH
        if model == CONFIRMED_BENIGN:
            override = bi("a decisive rule overrides a low model score",
                          "一条决定性规则推翻了模型给出的低分")
    elif blocking and rules != CONFIRMED_PHISH:
        # Missing *evidence* outranks the decisive benign rules. "This is the
        # brand's own registered domain" answers a different question from "is
        # this page safe" — a legitimate domain serving a compromised page is
        # exactly the case that matters, and an ftp:// URL we could not fetch
        # at all was being cleared on the strength of who owns the domain.
        #
        # It does not outrank a phishing verdict, though, and that exemption is
        # load-bearing. Some of these concerns are things the scanned page can
        # cause on purpose: one `Location: http://127.0.0.1/` makes the chain
        # end somewhere unreachable, and without this a kit could turn "This
        # looks like a scam" into "Not sure" by adding a redirect. Evidence we
        # already have is not made unreliable by evidence we failed to get.
        decision = NEEDS_REVIEW
    elif decisive_good and not _weighing(fired, +1, "strong"):
        # Deliberately ahead of `unstable`. An interval straddling the
        # threshold is a statement about the *model*, and a decisive
        # known-good rule exists precisely to outrank the model. google.com
        # was being sent to review on a wide interval while the rule engine
        # had already established it is Google's own registered domain, with
        # every collector reporting.
        #
        # It does not outrank the *rules*, though: if a strong incriminating
        # rule fired, the same reasoning as in `rule_verdict` applies and this
        # falls through to an abstention rather than a green verdict.
        decision = CONFIRMED_BENIGN
        if model == CONFIRMED_PHISH:
            override = bi("known-good domain overrides an unstable model score",
                          "已知可信的域名推翻了模型不稳定的分数")
    elif unstable:
        decision = NEEDS_REVIEW
    elif not _opposed(fired, model) and \
            _model_stands_alone(model, model_probability, threshold, interval, fs):
        # Neither silence nor agreement is disagreement. The abstention exists
        # for the case where the rules and the model *disagree*, or where the
        # evidence is thin. A page where no rule points against the model --
        # none fired, or only ones on its side too weak to decide alone -- with
        # a stable interval clear of the line, is the model's call. Saying "not
        # sure" about a 1.00 because the one rule that fired *agreed* with it
        # was withholding an answer it had.
        decision = model
        concerns.append(
            (bi("No rule settled it on its own; ", "没有哪条规则能单独定论；") if fired
             else bi("No rule fired either way; ", "没有触发任何方向的规则；"))
            + bi(f"this rests on the model, whose 90% interval "
                 f"[{interval.low:.2f}, {interval.high:.2f}] is clear of the "
                 f"{threshold:.2f} line.",
                 f"这个结论依据的是模型，它的 90% 区间 [{interval.low:.2f}, {interval.high:.2f}] "
                 f"完全在 {threshold:.2f} 判定线的一侧。"))
    elif rules != model:  # including a rule abstention: `model` never is one
        decision = NEEDS_REVIEW
    else:
        decision = model

    # A server error is no page at all, and a page that showed nothing cannot
    # be cleared on circumstantial evidence: a tunnelled kit answering 502 was
    # called "an ordinary website" on its address's age. Only the benign side,
    # though -- a kit can answer 503 to a scanner on purpose, and must not buy
    # its way out of a phishing call by doing so -- and not over a brand's or
    # company's own domain, where the address itself is the answer.
    #
    # A refusal (403 and the like) is the same for a page inside a site or on
    # a subdomain: kits planted on old, hacked sites answer a scanner with 403
    # and were cleared on the site's age (`/negocios.php`, `cyr.<site>.it`).
    # Not for the front door of a site registered five years or more, which
    # ordinary sites refuse to checkers often (43 of 500): there the address's
    # age is about the page, and a kit would have to replace the home page of
    # a long-held site.
    age = _val(fs, "domain_age_days")
    long_held_front_door = (_on(fs, "site_home_page") and registration_describes_page(fs)
                            and age is not None and age >= 5 * 365)
    if (decision == CONFIRMED_BENIGN and not decisive_good and _on(fs, "fetch_blocked")
            and (fs["fetch_blocked"].detail.startswith("HTTP 5") or not long_held_front_door)):
        decision = NEEDS_REVIEW
        blocking.append(_wall(fs["fetch_blocked"].detail)
                        + bi(", so nothing about the page itself could be checked.",
                             "，所以无法检查页面本身的任何内容。"))

    # The same for evidence that could not be read (see `evidence_unreadable`):
    # it may have been the part that would have shown a scam, and the page
    # chose what was there to read.
    if decision == CONFIRMED_BENIGN and not decisive_good and _on(fs, "evidence_unreadable"):
        decision = NEEDS_REVIEW
        blocking.append(bi(f"Part of the evidence could not be read "
                           f"({fs['evidence_unreadable'].detail}), so it was not checked.",
                           f"部分证据无法读取（{fs['evidence_unreadable'].detail}），所以没有被检查。"))
    # An error or takedown page served as if it were content, and a page in a
    # CMS's plugin or upload folders -- where kits planted on hacked sites
    # live -- say nothing that could clear the link. Benign side only, again.
    if decision == CONFIRMED_BENIGN and not decisive_good and _on(fs, "soft_error_page"):
        decision = NEEDS_REVIEW
        blocking.append(bi(f"The page shows an error instead of content "
                           f"(\"{fs['soft_error_page'].detail}\"), so there was nothing to check.",
                           f"页面显示的是错误信息而不是正常内容（“{fs['soft_error_page'].detail}”），"
                           "所以没有可以检查的东西。"))
    if decision == CONFIRMED_BENIGN and not decisive_good and _on(fs, "served_from_cms_folder"):
        decision = NEEDS_REVIEW
        blocking.append(bi(f"The page is served from inside the site's software folders "
                           f"({fs['served_from_cms_folder'].detail}), where a site's own pages do "
                           "not live and pages planted on hacked sites often do.",
                           f"这个页面来自网站程序的系统文件夹（{fs['served_from_cms_folder'].detail}）。"
                           "网站自己的页面不会放在那里，而被入侵的网站上植入的页面却常常放在那里。"))

    if decision == CONFIRMED_BENIGN and not decisive_good and _on(fs, "document_lure"):
        decision = NEEDS_REVIEW
        blocking.append(bi(f"The page offers a shared document and asks for your email or password "
                           f"to open it (\"{fs['document_lure'].detail}\"), the first step of many "
                           "scams, so nothing else here can clear it.",
                           f"这个页面声称有一份共享文档，要求你输入邮箱或密码才能打开"
                           f"（“{fs['document_lure'].detail}”）。这是很多诈骗的第一步，"
                           "所以这里的其他任何迹象都不能证明它安全。"))

    # Over a brand's own domain too, this one: the brand's site is what the
    # checker was shown, not what the address is (see
    # `evidence._redirector_names_brand`).
    if decision == CONFIRMED_BENIGN and _on(fs, "redirector_names_brand"):
        decision = NEEDS_REVIEW
        blocking.append(bi(f"The address is on another site but names a brand and sends this "
                           f"checker to that brand's real website "
                           f"({fs['redirector_names_brand'].detail}), which is how scam pages "
                           "hide from checks like this one.",
                           f"这个地址位于另一个网站上，却打着某个品牌的名号，并把检查工具引向那个品牌的真实网站"
                           f"（{fs['redirector_names_brand'].detail}）。诈骗页面就是这样躲避这类检查的。"))

    # `unstable` is shown to the user either way; it just no longer overrules a
    # decisive known-good finding.
    return Review(
        decision=decision, rule_verdict=rules, model_verdict=model,
        agreed=(rules == model), fired=fired,
        concerns=concerns + ([] if decision == NEEDS_REVIEW else unstable),
        blocking=blocking + (unstable if decision == NEEDS_REVIEW else []),
        override=override,
    )
