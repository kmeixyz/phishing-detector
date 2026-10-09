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


def _age_phrase(days: float) -> str:
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
            return "This link opens a document, and this check can only judge web pages."
        return "This link downloads a file, and this check can only judge web pages."
    if _on(fs, "fetch_failed"):
        return "We could not load the page, so there was not enough to go on."
    if _on(fs, "destination_unreached"):
        return ("The link sends you somewhere we could not follow, so we could not see "
                "where it really goes.")
    if _on(fs, "page_missing"):
        return ("This page does not exist any more. If the link came in a message, that "
                "message may still have been a scam.")
    if _on(fs, "short_link_dead_end"):
        return ("This short link does not lead anywhere now, so we could not see where it "
                "was meant to go.")
    if _on(fs, "fetch_blocked"):
        who = fs["fetch_blocked"].detail
        if who.startswith("HTTP 5"):
            return f"The site failed to show the page ({who}), so there was not enough to go on."
        return "The site would not show the page to this checker, so there was not enough to go on."
    if _on(fs, "document_lure"):
        return ("This page offers a shared document and asks for your email to open it, "
                "which is how many scams start, so we will not call it safe.")
    if _on(fs, "redirector_names_brand"):
        return ("This address names a company but sent our check to that company's real "
                "website, which is how scam pages hide from checks, so we will not call it.")
    if _on(fs, "client_redirect"):
        return ("This page sends you straight on to another site, and that site was "
                "not checked.")
    if _on(fs, "soft_error_page"):
        return ("The page shows an error instead of its content, so there was nothing to "
                "check. If the link came in a message, that message may still have been a scam.")
    if _on(fs, "served_from_cms_folder"):
        return ("This page sits inside the website's software folders, where hacked sites "
                "often hide scam pages, so we will not call it safe.")
    if _on(fs, "evidence_unreadable"):
        return "Part of what we collected could not be read, so there was not enough to go on."
    if (_on(fs, "render_empty") and not _on(fs, "content_from_render")
            and getattr(verdict, "probability", 0) >= getattr(verdict, "threshold", 1)):
        return ("The page is built by scripts this check does not run, so there was too "
                "little of it to call it either way.")
    if _on(fs, "asks_for_nothing") and getattr(verdict, "probability", 0) >= getattr(
            verdict, "threshold", 1):
        return ("Its address is new, but the page asks for nothing and its links all work, "
                "so we will not call it a scam.")
    total = getattr(verdict, "collectors_total", 0)
    if total and getattr(verdict, "collectors_ok", total) < total * 0.6:
        return "Too many of our checks could not get an answer to call it either way."
    # Only say the score was close when it was. A 0.99 held back because a
    # rule pointed the other way is a disagreement, not a near miss.
    low, high = getattr(verdict, "interval_low", None), getattr(verdict, "interval_high", None)
    threshold = getattr(verdict, "threshold", None)
    if None not in (low, high, threshold) and not (low <= threshold <= high):
        return "Some of the signs point one way and some the other, so we will not call it."
    return "The score landed too close to the line to call it either way."


def build(verdict) -> PlainSummary:
    fs = verdict.features
    decision = verdict.review.decision if verdict.review else ""
    bad: list[tuple[str, str]] = []
    good: list[tuple[str, str]] = []

    # --- the things that would alarm a person, in plain words ---------------
    if _on(fs, "exfil_endpoint"):
        bad.append(("bad", "Anything typed into this page gets sent to a chat app, "
                           "not to a real company."))
    # The three "borrowed from a brand" sentences stay silent where the rules
    # do: on the company's own domains, x.com loading Twitter's CDN or Gmail's
    # sign-in page titled Gmail is not a copy, and saying so under a "safe"
    # verdict would contradict it.
    brand = fs["brand_cdn_asset_count"].detail if "brand_cdn_asset_count" in fs else ""
    if _val(fs, "brand_cdn_asset_ratio", 0.0) > 0.1 and not same_company(fs, [brand]):
        brand = brand or "another company"
        bad.append(("bad", f"The pictures on this page are being loaded from {brand}'s real "
                           "website. That usually means someone copied their page."))
    if _on(fs, "has_password_input") and _on(fs, "form_action_cross_domain"):
        bad.append(("bad", "It asks for a password, and sends it to a different website "
                           "than the one you are on."))
    if _on(fs, "form_action_insecure"):
        bad.append(("bad", "What you type would be sent unprotected, so other people "
                           "could read it."))
    if _on(fs, "homograph_brand_match") or (_val(fs, "typosquat_distance", 9) <= 2
                                            and not _on(fs, "domain_owner_brands")):
        bad.append(("bad", "The web address is a near-copy of a well-known company's, "
                           "with a letter or two changed."))
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
        who = fs["title_domain_mismatch"].detail or "a company"
        bad.append(("bad", f"The page calls itself {who}, but the web address does not "
                           "belong to them."))
    age = _val(fs, "domain_age_days")
    if age is not None and age <= 60:
        bad.append(("bad", f"This website was set up {_age_phrase(age)}. Real companies "
                           "have usually been around much longer."))
    elif age is not None and age <= 400:
        bad.append(("bad", f"This website was set up {_age_phrase(age)}, which is fairly "
                           "recent. That is not proof of anything, but most established "
                           "companies have been online far longer."))
    if _on(fs, "asks_for_seed_phrase"):
        bad.append(("bad", "It asks for a crypto wallet recovery phrase. No legitimate "
                           "service ever asks for that."))
    if _on(fs, "asks_for_card") and _on(fs, "has_password_input"):
        bad.append(("bad", "It asks for card details as well as a password."))
    if _val(fs, "dead_anchor_ratio", 0.0) > 0.6:
        bad.append(("bad", "Most links on the page go nowhere, which is what happens when "
                           "someone copies a single page and nothing else."))
    if _on(fs, "user_content_on_brand_domain"):
        where = fs["user_content_on_brand_domain"].detail
        platform = tenant_platform(where)
        if platform:
            # A customer's own subdomain: say whose name it is and whose page.
            bad.append(("bad", f"This page is on {platform}, which gives anyone who signs up an "
                               "address like this one. The name is the platform's; the page is "
                               "whoever made it."))
        else:
            bad.append(("bad", f"The address belongs to a real company, but {where} lets anyone "
                               "publish a page there. The address is theirs; the page is not."))
    elif _on(fs, "user_content_host"):
        where = fs["user_content_host"].detail
        bad.append(("bad", f"Anyone can publish a page on {where}, so the address says "
                           "nothing about who made this one."))

    if _on(fs, "serves_download"):
        # First, not appended: only three findings are shown, and for a
        # download this is the answer rather than one reason among several.
        # A PDF opens in the browser rather than downloading, so it is not
        # described as a download -- but it is still unread: a PDF lure is a
        # page of links this check never sees.
        if _is_pdf(fs):
            bad.insert(0, ("bad", "This link opens a PDF document rather than a web page. This "
                                  "check cannot read what the document says or where its links "
                                  "go, so be careful with any link or form inside it."))
        else:
            bad.insert(0, ("bad", "Opening this link downloads a file instead of showing a web "
                                  "page. This check looks for fake websites and cannot tell "
                                  "whether a file is safe, so do not open it unless you were "
                                  "expecting it."))
    if _on(fs, "tls_problem"):
        bad.append(("bad", f"Its security certificate is not valid ({fs['tls_problem'].detail}), "
                           "so your browser will warn you before opening it. Do not click past "
                           "that warning."))
    if _on(fs, "connection_unencrypted"):
        bad.append(("bad", "The connection to this site is not encrypted, so do not type "
                           "anything private into it."))

    # --- the things that are reassuring -------------------------------------
    # Said only when the rule that means it fired: it is withheld on hosts
    # that publish strangers' pages and on regional names with no history,
    # and the sentence must not vouch where the verdict would not.
    official = (_on(fs, "is_known_brand_domain")
                and any(r.name == "known_brand_domain" for r in run_rules(fs)))
    if _on(fs, "sent_by_company_shortener"):
        who = fs["sent_by_company_shortener"].detail
        good.append(("good", f"This short link is {who}'s own. Only {who} can make links "
                             "on it, so it chose where this one leads."))
    if official:
        who = fs["is_known_brand_domain"].detail
        good.append(("good", f"This is the real, official address for {who}."))
    elif _on(fs, "page_owner_company"):
        # x.com, m365.cloud.microsoft: the company's own, just not the one
        # domain the brand list records. Empty on user-content hosts.
        who = fs["page_owner_company"].detail.rsplit(" belongs to ", 1)[-1]
        good.append(("good", f"This is one of {who}'s own official addresses."))
    # Both of these describe the registered domain. On a host that publishes
    # strangers' pages that domain is the platform's, so its age and its mail
    # say nothing about whoever posted this page.
    # Nor, after a redirect to another domain, is the age the destination's.
    # The rules ask exactly this question before calling a domain established.
    shared_page = not registration_describes_page(fs)
    if age is not None and age > 730 and not shared_page:
        good.append(("good", f"This website was set up {_age_phrase(age)} and is still "
                             "running. Scam sites are usually days or weeks old."))
    if _on(fs, "has_mx") and not shared_page:
        good.append(("good", "It has working email set up, which throwaway scam sites "
                             "usually do not."))
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
        good.append(("good", "It asks for a password, but sends it to itself rather than "
                             "somewhere else, which is normal."))
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
        good.append(("good", "The page does not ask for a password."))

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
        headline = "We're not sure about this one"
        subhead = _why_unsure(fs, verdict)
        advice = ("Treat it with caution: do not type a password or card details in until "
                  "you have checked the address some other way, such as typing the company's "
                  "real address in yourself rather than following this link.")
    elif dangerous:
        headline = "This looks like a scam"
        subhead = "The checks found reasons to treat this link as suspicious."
        advice = ("Do not type anything into this page. No passwords, no card details, "
                  "no codes. Close the tab. If you got here from an email or a text, "
                  "that message was probably fake too.")
    else:
        headline = "Nothing suspicious found"
        subhead = "This looks like an ordinary website."
        advice = ("Nothing here looked wrong. That is not a guarantee, so still check the "
                  "web address at the top of your browser before typing a password.")
        if _on(fs, "tls_problem"):
            # Nothing phishing-like -- but a browser will stop the visitor at a
            # full-page warning, and "an ordinary website" beside that reads as
            # permission to click through it.
            subhead = ("Nothing about it looks like a scam, but its security "
                       "certificate is not valid.")
            advice = ("Your browser will show a warning before opening it. Do not click past "
                      "that warning or type anything into the site until the owner fixes it.")

    findings = bad[:3] + good[:3 - min(len(bad), 2)]

    # A "this looks like a scam" verdict with nothing but reassuring findings
    # reads as a contradiction - say plainly that the call came from the score
    # rather than from anything visible on the page.
    if dangerous and not bad:
        findings.append(("neutral", "Nothing on the page itself looked wrong, but it scored "
                                    "high enough on other signals that we are treating it as "
                                    "dangerous rather than risk missing something."))
    if not findings:
        findings = [("neutral", "We could not find anything clearly good or bad about "
                                "this page.")]

    thin = verdict.collectors_total and verdict.collectors_ok < verdict.collectors_total * 0.6
    confidence = ("We could not check everything about this page, so treat the answer "
                  "above as a partial one." if thin else "")

    return PlainSummary(headline=headline, subhead=subhead, findings=findings,
                        advice=advice, confidence=confidence)
