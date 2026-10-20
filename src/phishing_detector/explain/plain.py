"""A second explanation, written for someone who knows nothing about any of this.

The main panel is written for a reader who knows what a registrable domain is,
what a log-odds contribution means, and why a bootstrap interval might straddle
a threshold. Most people do not, and a verdict nobody can read is not much of a
verdict.

Rules this module follows:

  * no jargon at all - no "domain", "TLS", "ASN", "probability", "model"
  * say what was found, not what the system concluded
  * every line has to be true; simplifying is not the same as overstating
  * end with what the reader should actually do
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..features.base import FeatureSet
from ..features.user_content import tenant_platform
from ..i18n import Text, age_zh, bi, pad, zh
# `_on` and `_val` are the rule engine's own readers, so a sentence here and
# the rule beside it can never disagree about whether a feature is set.
from ..verify.crosscheck import (CONFIRMED_BENIGN, CONFIRMED_PHISH, MID_BAND_RATIO,
                                 NEEDS_REVIEW, _on, _val, registration_describes_page,
                                 run_rules, same_company)


@dataclass
class PlainSummary:
    headline: str
    subhead: str
    findings: list[tuple[str, str]] = field(default_factory=list)  # (good|bad|neutral, text)
    advice: str = ""
    confidence: str = ""


def _age_phrase(days: float) -> Text:
    return bi(_age_en(days), age_zh(days))


def _age_en(days: float) -> str:
    days = int(days)
    if days < 1:
        return "today"
    if days == 1:
        return "yesterday"
    if days < 31:
        return f"{days} days ago"
    if days < 60:
        return "about a month ago"
    if days < 365:
        return f"about {days // 30} months ago"
    years = days // 365
    return "about a year ago" if years == 1 else f"about {years} years ago"


def _is_pdf(fs: FeatureSet) -> bool:
    return "application/pdf" in (fs["serves_download"].detail if "serves_download" in fs else "")


def _why_unsure(fs: FeatureSet, verdict) -> str:
    """The reason in the subhead, not a stock line.

    It used to say "the score landed too close to the line" for every
    abstention, including a link that downloads a file and a page that never
    loaded -- a reason that was not the reason. Ordered as the abstentions are
    most usefully explained: what the link *is* first, then what could not be
    seen, then the score.
    """
    if _on(fs, "serves_download"):
        if _is_pdf(fs):
            return bi("This link opens a document, and this check can only judge web pages.",
                      "这个链接打开的是一份文档，而本检查只能判断网页。")
        return bi("This link downloads a file, and this check can only judge web pages.",
                  "这个链接会下载一个文件，而本检查只能判断网页。")
    if _on(fs, "fetch_failed"):
        return bi("We could not load the page, so there was not enough to go on.",
                  "我们没能加载这个页面，所以没有足够的依据。")
    if _on(fs, "destination_unreached"):
        return bi("The link sends you somewhere we could not follow, so we could not see "
                  "where it really goes.",
                  "这个链接把你带去了一个我们无法跟随的地方，所以我们看不到它真正通往哪里。")
    if _on(fs, "page_missing"):
        return bi("This page does not exist any more. If the link came in a message, that "
                  "message may still have been a scam.",
                  "这个页面已经不存在了。如果这个链接是别人发给你的，那条消息仍然可能是诈骗。")
    if _on(fs, "short_link_dead_end"):
        return bi("This short link does not lead anywhere now, so we could not see where it "
                  "was meant to go.",
                  "这个短链接现在已经不指向任何地方，所以我们看不到它原本要带你去哪里。")
    if _on(fs, "fetch_blocked"):
        who = fs["fetch_blocked"].detail
        if who.startswith("HTTP 5"):
            return bi(f"The site failed to show the page ({who}), so there was not enough to go on.",
                      f"这个网站没能显示页面（{who}），所以没有足够的依据。")
        return bi("The site would not show the page to this checker, so there was not enough to go on.",
                  "这个网站不肯向检查工具显示页面，所以没有足够的依据。")
    if _on(fs, "document_lure"):
        return bi("This page offers a shared document and asks for your email to open it, "
                  "which is how many scams start, so we will not call it safe.",
                  "这个页面声称有一份共享文档，并要求你输入邮箱才能打开。很多诈骗都是这样开始的，所以我们不会说它安全。")
    if _on(fs, "redirector_names_brand"):
        return bi("This address names a company but sent our check to that company's real "
                  "website, which is how scam pages hide from checks, so we will not call it.",
                  "这个地址打着某家公司的名号，却把我们的检查引向了那家公司的真实网站。诈骗页面常用这种方法躲避检查，所以我们不下结论。")
    if _on(fs, "client_redirect"):
        return bi("This page sends you straight on to another site, and that site was "
                  "not checked.",
                  "这个页面会直接把你转到另一个网站，而那个网站没有被检查。")
    if _on(fs, "soft_error_page"):
        return bi("The page shows an error instead of its content, so there was nothing to "
                  "check. If the link came in a message, that message may still have been a scam.",
                  "这个页面显示的是错误信息而不是正常内容，所以没有可以检查的东西。如果这个链接是别人发给你的，那条消息仍然可能是诈骗。")
    if _on(fs, "served_from_cms_folder"):
        return bi("This page sits inside the website's software folders, where hacked sites "
                  "often hide scam pages, so we will not call it safe.",
                  "这个页面位于网站程序的系统文件夹里，被入侵的网站常把诈骗页面藏在这种地方，所以我们不会说它安全。")
    if _on(fs, "evidence_unreadable"):
        return bi("Part of what we collected could not be read, so there was not enough to go on.",
                  "我们收集到的部分内容无法读取，所以没有足够的依据。")
    if (_on(fs, "render_empty") and not _on(fs, "content_from_render")
            and getattr(verdict, "probability", 0) >= getattr(verdict, "threshold", 1)):
        return bi("The page is built by scripts this check does not run, so there was too "
                  "little of it to call it either way.",
                  "这个页面是由脚本生成的，而本检查不运行这些脚本，所以能看到的内容太少，无法下结论。")
    if _on(fs, "asks_for_nothing") and getattr(verdict, "probability", 0) >= getattr(
            verdict, "threshold", 1):
        return bi("Its address is new, but the page asks for nothing and its links all work, "
                  "so we will not call it a scam.",
                  "它的地址是新注册的，但页面没有要求你提供任何信息，链接也都能正常打开，所以我们不会说它是诈骗。")
    total = getattr(verdict, "collectors_total", 0)
    if total and getattr(verdict, "collectors_ok", total) < total * 0.6:
        return bi("Too many of our checks could not get an answer to call it either way.",
                  "我们有太多项检查没能得到答复，无法下结论。")
    # Only say the score was close when it was. A 0.99 held back because a
    # rule pointed the other way is a disagreement, not a near miss.
    low, high = getattr(verdict, "interval_low", None), getattr(verdict, "interval_high", None)
    threshold = getattr(verdict, "threshold", None)
    if None not in (low, high, threshold) and not (low <= threshold <= high):
        return bi("Some of the signs point one way and some the other, so we will not call it.",
                  "有些迹象指向一边，有些指向另一边，所以我们不下结论。")
    return bi("The score landed too close to the line to call it either way.",
              "分数离判定线太近，无法下结论。")


def build(verdict) -> PlainSummary:
    fs = verdict.features
    decision = verdict.review.decision if verdict.review else ""
    bad: list[tuple[str, str]] = []
    good: list[tuple[str, str]] = []

    # --- the things that would alarm a person, in plain words ---------------
    if _on(fs, "exfil_endpoint"):
        bad.append(("bad", bi("Anything typed into this page gets sent to a chat app, "
                              "not to a real company.",
                              "在这个页面上输入的任何内容，都会被发送到一个聊天软件，而不是真正的公司。")))
    # The three "borrowed from a brand" sentences stay silent where the rules
    # do: on the company's own domains, x.com loading Twitter's CDN or Gmail's
    # sign-in page titled Gmail is not a copy, and saying so under a "safe"
    # verdict would contradict it.
    brand = fs["brand_cdn_asset_count"].detail if "brand_cdn_asset_count" in fs else ""
    if _val(fs, "brand_cdn_asset_ratio", 0.0) > 0.1 and not same_company(fs, [brand]):
        bad.append(("bad", bi(f"The pictures on this page are being loaded from "
                              f"{brand or 'another company'}'s real "
                              "website. That usually means someone copied their page.",
                              f"这个页面上的图片是从{pad(brand, '另一家公司')}的真实网站加载的。"
                              "这通常说明有人照抄了他们的页面。")))
    if _on(fs, "has_password_input") and _on(fs, "form_action_cross_domain"):
        bad.append(("bad", bi("It asks for a password, and sends it to a different website "
                              "than the one you are on.",
                              "它要求你输入密码，却把密码发送到另一个网站，而不是你正在访问的这个。")))
    if _on(fs, "form_action_insecure"):
        bad.append(("bad", bi("What you type would be sent unprotected, so other people "
                              "could read it.",
                              "你输入的内容会在没有保护的情况下发送出去，别人可能看得到。")))
    if _on(fs, "homograph_brand_match") or (_val(fs, "typosquat_distance", 9) <= 2
                                            and not _on(fs, "domain_owner_brands")):
        bad.append(("bad", bi("The web address is a near-copy of a well-known company's, "
                              "with a letter or two changed.",
                              "这个网址几乎照抄了一家知名公司的网址，只改动了一两个字母。")))
    claimed = fs["title_domain_mismatch"].detail.split(", ") if "title_domain_mismatch" in fs else []
    owners = set(fs["domain_owner_brands"].detail.split(",")) if _on(fs, "domain_owner_brands") else set()
    # "The web address does not belong to them" is false when it does: the
    # OneDrive viewer on onedrive.live.com is titled OneDrive. What is wrong
    # there is that anyone can publish, which the sentence below says instead.
    platform_title = _on(fs, "user_content_host") and bool(claimed) and set(claimed) <= owners
    # Only over a password field, as the rule has it. The brand list is built
    # from traffic rank and so holds plain words -- "example", "forms" -- and
    # without the condition any page titled "Microsoft Forms" was told it was
    # impersonating someone. Over a password field the claim is what the rule
    # was measured on.
    asks_password = (_on(fs, "has_password_input") or _on(fs, "js_injected_password")
                     or _on(fs, "concealed_password_input"))
    if (asks_password and _on(fs, "title_domain_mismatch")
            and not same_company(fs, claimed) and not platform_title):
        who = fs["title_domain_mismatch"].detail
        bad.append(("bad", bi(f"The page calls itself {who or 'a company'}, but the web address does not "
                              "belong to them.",
                              f"这个页面自称是{pad(who, '某家公司')}，但这个网址并不属于他们。")))
    age = _val(fs, "domain_age_days")
    if age is not None and age <= 60:
        bad.append(("bad", bi(f"This website was set up {_age_phrase(age)}. Real companies "
                              "have usually been around much longer.",
                              f"这个网站是{pad(zh(_age_phrase(age)))}建立的。真正的公司通常已经存在很久了。")))
    elif age is not None and age <= 400:
        bad.append(("bad", bi(f"This website was set up {_age_phrase(age)}, which is fairly "
                              "recent. That is not proof of anything, but most established "
                              "companies have been online far longer.",
                              f"这个网站是{pad(zh(_age_phrase(age)))}建立的，时间比较短。这本身并不能证明什么，"
                              "但大多数成熟的公司上线的时间要长得多。")))
    if _on(fs, "asks_for_seed_phrase"):
        bad.append(("bad", bi("It asks for a crypto wallet recovery phrase. No legitimate "
                              "service ever asks for that.",
                              "它要求你提供加密货币钱包的助记词。任何正规服务都绝不会要这个。")))
    if _on(fs, "asks_for_card") and _on(fs, "has_password_input"):
        bad.append(("bad", bi("It asks for card details as well as a password.",
                              "它既要你的密码，又要你的银行卡信息。")))
    if _val(fs, "dead_anchor_ratio", 0.0) > 0.6:
        bad.append(("bad", bi("Most links on the page go nowhere, which is what happens when "
                              "someone copies a single page and nothing else.",
                              "页面上的大多数链接都打不开。只照抄一个页面、其他什么都不抄的时候，就会这样。")))
    if _on(fs, "user_content_on_brand_domain"):
        where = fs["user_content_on_brand_domain"].detail
        platform = tenant_platform(where)
        if platform:
            # A customer's own subdomain: say whose name it is and whose page.
            bad.append(("bad", bi(f"This page is on {platform}, which gives anyone who signs up an "
                                  "address like this one. The name is the platform's; the page is "
                                  "whoever made it.",
                                  f"这个页面位于 {platform} 上，任何注册的人都能得到一个这样的地址。"
                                  "名字是平台的，页面却是任何人都可以做的。")))
        else:
            bad.append(("bad", bi(f"The address belongs to a real company, but {where} lets anyone "
                                  "publish a page there. The address is theirs; the page is not.",
                                  f"这个地址属于一家真实的公司，但 {where} 允许任何人在上面发布页面。"
                                  "地址是他们的，页面却不是。")))
    elif _on(fs, "user_content_host"):
        where = fs["user_content_host"].detail
        bad.append(("bad", bi(f"Anyone can publish a page on {where}, so the address says "
                              "nothing about who made this one.",
                              f"任何人都可以在 {where} 上发布页面，所以这个地址说明不了这个页面是谁做的。")))

    if _on(fs, "serves_download"):
        # First, not appended: only three findings are shown, and for a
        # download this is the answer rather than one reason among several.
        # A PDF opens in the browser rather than downloading, so it is not
        # described as a download -- but it is still unread: a PDF lure is a
        # page of links this check never sees.
        if _is_pdf(fs):
            bad.insert(0, ("bad", bi("This link opens a PDF document rather than a web page. This "
                                     "check cannot read what the document says or where its links "
                                     "go, so be careful with any link or form inside it.",
                                     "这个链接打开的是一份 PDF 文档，而不是网页。本检查无法读取文档的内容，"
                                     "也看不到其中的链接通往哪里，所以对文档里的任何链接或表单都要小心。")))
        else:
            bad.insert(0, ("bad", bi("Opening this link downloads a file instead of showing a web "
                                     "page. This check looks for fake websites and cannot tell "
                                     "whether a file is safe, so do not open it unless you were "
                                     "expecting it.",
                                     "打开这个链接会下载一个文件，而不是显示网页。本检查是用来识别假网站的，"
                                     "无法判断文件是否安全，所以除非你本来就在等这个文件，否则不要打开它。")))
    if _on(fs, "tls_problem"):
        bad.append(("bad", bi(f"Its security certificate is not valid ({fs['tls_problem'].detail}), "
                              "so your browser will warn you before opening it. Do not click past "
                              "that warning.",
                              f"它的安全证书无效（{zh(fs['tls_problem'].detail)}），所以浏览器在打开它之前会发出警告。"
                              "不要无视那个警告继续访问。")))
    if _on(fs, "connection_unencrypted"):
        bad.append(("bad", bi("The connection to this site is not encrypted, so do not type "
                              "anything private into it.",
                              "与这个网站的连接没有加密，所以不要在上面输入任何私人信息。")))

    # --- the things that are reassuring -------------------------------------
    # Said only when the rule that means it fired: it is withheld on hosts
    # that publish strangers' pages and on regional names with no history,
    # and the sentence must not vouch where the verdict would not.
    official = (_on(fs, "is_known_brand_domain")
                and any(r.name == "known_brand_domain" for r in run_rules(fs)))
    if _on(fs, "sent_by_company_shortener"):
        who = fs["sent_by_company_shortener"].detail
        good.append(("good", bi(f"This short link is {who}'s own. Only {who} can make links "
                                "on it, so it chose where this one leads.",
                                f"这个短链接是{pad(who)}自己的。只有{pad(who)}能在上面生成链接，所以这个链接通往哪里是它自己决定的。")))
    if official:
        who = fs["is_known_brand_domain"].detail
        good.append(("good", bi(f"This is the real, official address for {who}.",
                                f"这是{pad(who)}真正的官方地址。")))
    elif _on(fs, "page_owner_company"):
        # x.com, m365.cloud.microsoft: the company's own, just not the one
        # domain the brand list records. Empty on user-content hosts.
        who = fs["page_owner_company"].detail.rsplit(" belongs to ", 1)[-1]
        good.append(("good", bi(f"This is one of {who}'s own official addresses.",
                                f"这是{pad(who)}自己的官方地址之一。")))
    # Both of these describe the registered domain. On a host that publishes
    # strangers' pages that domain is the platform's, so its age and its mail
    # say nothing about whoever posted this page.
    # Nor, after a redirect to another domain, is the age the destination's.
    # The rules ask exactly this question before calling a domain established.
    shared_page = not registration_describes_page(fs)
    if age is not None and age > 730 and not shared_page:
        good.append(("good", bi(f"This website was set up {_age_phrase(age)} and is still "
                                "running. Scam sites are usually days or weeks old.",
                                f"这个网站是{pad(zh(_age_phrase(age)))}建立的，至今仍在运行。诈骗网站通常只存在几天或几周。")))
    if _on(fs, "has_mx") and not shared_page:
        good.append(("good", bi("It has working email set up, which throwaway scam sites "
                                "usually do not.",
                                "它设置了可用的电子邮箱，用完即弃的诈骗网站通常不会这样做。")))
    # Both of these are claims about a form, so they may only be made when a
    # form was actually seen. `form_action_cross_domain == 0` is also 0 for a
    # page with no form at all, which turned "no form" into "sends it to
    # itself, which is normal" -- reassurance manufactured out of absence.
    # `form_count == 1`, because nothing associates a password field with a
    # particular form: with two forms on the page, "it posts to itself" may be
    # describing the newsletter signup while the credential form posts
    # elsewhere. One form is the only case where the sentence is certainly true.
    if (_on(fs, "has_password_input") and _val(fs, "form_action_cross_domain") == 0
            and _val(fs, "form_count", 0) == 1 and not _on(fs, "form_action_empty")):
        good.append(("good", bi("It asks for a password, but sends it to itself rather than "
                                "somewhere else, which is normal.",
                                "它要求输入密码，但密码是发送给它自己，而不是别的地方，这是正常的。")))
    # And this one may only be made about a page we actually saw. An unrendered
    # client-side shell has no password field *yet*; saying it does not ask for
    # one describes the empty shell, not the page the visitor gets.
    if (_val(fs, "has_password_input") == 0
            and not _on(fs, "render_empty")
            and not _on(fs, "js_injected_password")
            and not _on(fs, "concealed_password_input")
            # Only the part of the page that fit under the cap was read, and
            # the page chose where the cut fell.
            and not _on(fs, "body_truncated")):
        good.append(("good", bi("The page does not ask for a password.", "这个页面没有要求输入密码。")))

    # --- headline -----------------------------------------------------------
    # A decisive rule decision always wins regardless of the raw score, same
    # as the badge colour: that is what lets a decisive known-good rule clear
    # a domain the model scored high. An abstention also wins, and says so --
    # the checks declined to back the number, so the copy reports that rather
    # than reading the number back out.
    #
    # Only with no rule decision at all does the score decide, and a score
    # sitting within MID_BAND_RATIO of the threshold gets its own headline
    # rather than being forced into "scam" or "nothing found" - a 52-out-of-100
    # is not the same claim as a 5 or a 99, and saying so is more honest than
    # erring silently toward either word. Keyed on the same threshold the
    # colour and the meter's line use, so the copy never disagrees with them.
    decisive = decision in (CONFIRMED_PHISH, CONFIRMED_BENIGN)
    # An abstention is a conclusion. The rule engine read the evidence and
    # declined to back the score, so the copy says that rather than reading the
    # score back out -- otherwise the model overrules the check that exists to
    # overrule it, and a real brand page at 0.909 is called a scam. Matches
    # `web.app._tone`, which every surface keys its colour off.
    abstained = decision == NEEDS_REVIEW
    unsure = abstained or (
        not decisive
        and verdict.probability is not None
        and verdict.threshold * MID_BAND_RATIO <= verdict.probability < verdict.threshold
    )
    # The mid band is strictly below the threshold, so `unsure` and this
    # clause can never both hold - no need to guard one against the other.
    dangerous = decision == CONFIRMED_PHISH or (
        not abstained
        and decision != CONFIRMED_BENIGN
        and verdict.probability is not None
        and verdict.probability >= verdict.threshold
    )
    if unsure:
        headline = bi("We're not sure about this one", "这个链接我们无法确定")
        subhead = _why_unsure(fs, verdict)
        advice = bi("Treat it with caution: do not type a password or card details in until "
                    "you have checked the address some other way, such as typing the company's "
                    "real address in yourself rather than following this link.",
                    "请谨慎对待：在用其他方式核实这个地址之前，不要输入密码或银行卡信息。"
                    "例如，自己手动输入那家公司的真实网址，而不是点这个链接。")
    elif dangerous:
        headline = bi("This looks like a scam", "这看起来像诈骗")
        subhead = bi("The checks found reasons to treat this link as suspicious.",
                     "检查发现了一些理由，说明这个链接值得怀疑。")
        advice = bi("Do not type anything into this page. No passwords, no card details, "
                    "no codes. Close the tab. If you got here from an email or a text, "
                    "that message was probably fake too.",
                    "不要在这个页面上输入任何东西：不要输入密码，不要输入银行卡信息，也不要输入验证码。"
                    "关掉这个标签页。如果你是通过邮件或短信来到这里的，那条消息很可能也是假的。")
    else:
        headline = bi("Nothing suspicious found", "没有发现可疑之处")
        subhead = bi("This looks like an ordinary website.", "这看起来是一个普通网站。")
        advice = bi("Nothing here looked wrong. That is not a guarantee, so still check the "
                    "web address at the top of your browser before typing a password.",
                    "这里没有发现异常。但这并不是保证，所以在输入密码之前，仍然要看一下浏览器顶部的网址。")
        if _on(fs, "tls_problem"):
            # Nothing phishing-like -- but a browser will stop the visitor at a
            # full-page warning, and "an ordinary website" beside that reads as
            # permission to click through it.
            subhead = bi("Nothing about it looks like a scam, but its security "
                         "certificate is not valid.",
                         "它看起来不像诈骗，但它的安全证书无效。")
            advice = bi("Your browser will show a warning before opening it. Do not click past "
                        "that warning or type anything into the site until the owner fixes it.",
                        "浏览器在打开它之前会显示警告。在网站所有者修复这个问题之前，不要无视警告继续访问，也不要在网站上输入任何内容。")

    findings = bad[:3] + good[:3 - min(len(bad), 2)]

    # A "this looks like a scam" verdict with nothing but reassuring findings
    # reads as a contradiction - say plainly that the call came from the score
    # rather than from anything visible on the page.
    if dangerous and not bad:
        findings.append(("neutral", bi("Nothing on the page itself looked wrong, but it scored "
                                       "high enough on other signals that we are treating it as "
                                       "dangerous rather than risk missing something.",
                                       "页面本身看起来没有问题，但它在其他信号上的分数足够高，"
                                       "所以我们宁可把它当作危险网站，也不愿冒漏掉的风险。")))
    if not findings:
        findings = [("neutral", bi("We could not find anything clearly good or bad about "
                                   "this page.",
                                   "关于这个页面，我们没有找到明显好或明显不好的地方。"))]

    thin = verdict.collectors_total and verdict.collectors_ok < verdict.collectors_total * 0.6
    confidence = (bi("We could not check everything about this page, so treat the answer "
                     "above as a partial one.",
                     "我们没能检查这个页面的所有方面，所以请把上面的答案当作不完整的结论。")
                  if thin else "")

    return PlainSummary(headline=headline, subhead=subhead, findings=findings,
                        advice=advice, confidence=confidence)
