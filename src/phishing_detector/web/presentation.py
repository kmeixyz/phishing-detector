"""Arrange existing scan information for the web interface without rescoring it."""

import json
import re

from ..i18n import Text, bi


# The fetched page itself is one of these values, up to the collector's 2 MB
# cap, and HTML-escaping can quadruple it: a page of angle brackets made a
# result page past Vercel's 4.5 MB response limit, and every saved history
# entry carries the page it came from, so ten ordinary scans filled the
# browser's quota. A value is shown up to this many characters.
MAX_SHOWN = 50_000


def _field(key, value) -> dict:
    """One observed value, rendered for display."""
    if value is None:
        display = bi("Not reported", "未报告")
    elif isinstance(value, (dict, list, tuple, bool)):
        display = json.dumps(value, ensure_ascii=False, indent=2, default=str)
    else:
        display = str(value)
    # A slice of a `Text` is a plain str, and would drop the translation.
    shown = display if isinstance(display, Text) else display[:MAX_SHOWN]
    return {"key": key, "value": shown, "length": len(display),
            "truncated": len(display) > MAX_SHOWN,
            "large": len(display) > 200 or "\n" in display}


# What a source's failure means, for the plain-language list of what could
# not be checked. The collector's own wording -- "refusing to fetch: x does
# not resolve: [Errno 8] nodename nor servname provided, or not known" -- is
# for the technical record, which still shows it. First match wins.
_PLAIN_FAILURES = (
    (r"not resolve to a public", bi(
        "The name points to a private or reserved network address, so it was not contacted.",
        "这个域名指向内部或保留的网络地址，所以没有去连接它。")),
    (r"did not resolve within|lookups are stalled", bi(
        "Looking up the name took too long.", "查询这个域名花的时间太长了。")),
    (r"does not resolve|no address resolved|no a or aaaa|resolved to nothing|nodename|not known", bi(
        "The name has no address on the internet, so there was nothing to connect to.",
        "这个域名在互联网上没有对应的地址，所以没有可以连接的地方。")),
    (r"queued too deep", bi(
        "Too many checks were waiting on this source. Try again in a minute.",
        "等待这个来源的检查太多了。请过一分钟再试。")),
    (r"page was not fetched", bi(
        "The page could not be loaded, so there was nothing to read.",
        "页面无法加载，所以没有可以读取的内容。")),
    (r"download refused", bi(
        "The link starts a file download, which this checker does not open.",
        "这个链接会开始下载文件，本检查工具不会打开文件。")),
    (r"redirect cap", bi("It redirected too many times to follow.", "它跳转的次数太多，无法继续跟随。")),
    (r"not a web address|non-http scheme", bi(
        "It sends you to something that is not a web page.", "它把你带去的地方不是网页。")),
    (r"does not serve https|not an https url", bi(
        "The site does not offer a secure (HTTPS) connection.", "这个网站不提供安全的（HTTPS）连接。")),
    (r"no ct source answered", bi("The certificate logs did not answer.", "证书日志没有回应。")),
    (r"no certificates logged", bi(
        "No certificates have been logged for this name.", "这个域名没有任何记录在案的证书。")),
    (r"no mx or ns", bi(
        "The name has no mail or name-server records.", "这个域名没有邮件服务器或域名服务器记录。")),
    (r"no rdap record|no registration date|no parseable creation date|no whois server|rdap http", bi(
        "The registry did not publish when the name was registered.",
        "域名注册局没有公布这个域名的注册时间。")),
    (r"certificate|ssl|tls", bi(
        "Its security certificate could not be read or verified.", "它的安全证书无法读取或验证。")),
    (r"timeout|timed out|exceeded|budget", bi("It did not answer in time.", "它没有及时回应。")),
    (r"refused|connecterror|connect", bi("The server could not be reached.", "无法连接到服务器。")),
)


def plain_failure(detail: str) -> str:
    """A failed source's detail, said for someone who is not an engineer."""
    low = (detail or "").lower()
    for pattern, text in _PLAIN_FAILURES:
        if re.search(pattern, low):
            return text
    return re.sub(r"\[Errno -?\d+\]\s*", "", detail or "")


def _evidence_sources(bundle) -> list[dict]:
    """One record per collector, in the order the bundle holds them."""
    return [{"id": f"source-{i}", "name": c.name, "status": c.status,
             "answered": c.answered,
             "detail": c.detail, "elapsed_s": c.elapsed_s,
             "fields": [_field(key, value) for key, value in c.data.items()]}
            for i, c in enumerate(bundle.results.values())]


def _hops(hops) -> list[dict]:
    """The redirect chain as the template walks it: a list of records."""
    return [h for h in hops if isinstance(h, dict)] if isinstance(hops, list) else []


def result_details(verdict, tone):
    groups = {"bad": [], "neutral": [], "good": []}
    for kind, text in (verdict.plain.findings if verdict.plain else []):
        groups.setdefault(kind, []).append(text)
    order = ("good", "neutral", "bad") if tone == "safe" else ("bad", "neutral", "good")
    #  The lead sentence is the strongest plain-English finding for the tone
    #  actually shown, so a dangerous result leads with a concern and a safe one
    #  leads with what reassured it.
    #
    #  An override does not become the lead. "Known-good domain overrides an
    #  unstable model score" is true, and it is why the verdict came out the way
    #  it did, but it is written for someone who knows there is a model — which
    #  is exactly who this line is not for. The override still gets said, as its
    #  own note beside the verdict and again beside the score.
    reason = next((groups[k][0] for k in order if groups[k]), verdict.note)
    bundle = verdict.bundle
    sources = _evidence_sources(bundle)
    missing = [c for c in sources if c["status"] != "skipped" and not c["answered"]]
    return {
        "finding_groups": [(k, groups[k]) for k in order if groups[k]],
        "main_reason": reason,
        "evidence_sources": sources,
        "missing_sources": missing,
        "collected_at": bundle.collected_at,
        "redirect_hops": _hops(bundle.data("HTTP chain").get("hops")),
        "destination": verdict.final_url if bundle.get("HTTP chain").ok else "",
        "scan_limits": list(bundle.envelope.items()),
        "observation_rows": list(verdict.features.features.values()),
    }
