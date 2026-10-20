"""The Chinese edition: the same pages, with every word in Simplified Chinese.

`/zh` is not a second application. A request under it is stripped of the
prefix before anything else sees it (web/app.py, `_LanguagePrefix`), so the
rate limits, the cross-origin guard and every route answer it exactly as they
answer the English page, and only the words change.

Prose is written in both languages where it is written, as a `Text`: a str
that reads as the English it always was -- to the tests, to comparisons, to
the log -- and carries its Chinese beside it. Keeping the pair together is
what stops the two drifting apart; a sentence edited in English is edited
next to its translation. The templates pick a side through Jinja's finalize
hook, so `{{ v.note }}` needs no filter to come out in Chinese.

What a source said about itself -- a collector's status line, a feature's
detail -- is machine wording assembled from data, not prose, and is
translated by pattern in `fragment`. Anything it does not recognise (a raw
exception, a registrar's name) is data and is left as it came.
"""

from __future__ import annotations

import re
from typing import Callable

EN = "en"
ZH = "zh"
# Where each edition lives. English is the root; nothing under it links here.
PREFIXES = {ZH: "/zh"}
HTML_LANG = {EN: "en", ZH: "zh-CN"}


class Text(str):
    """English that knows its Chinese."""

    zh: str

    def __new__(cls, en: str, zh_text: str) -> "Text":
        obj = super().__new__(cls, en)
        obj.zh = zh_text
        return obj

    # Sentences are built up with `+` in a few places. Without these the sum is
    # a plain str and the Chinese half is silently dropped.
    def __add__(self, other):
        if isinstance(other, str):
            return Text(str.__add__(self, other), self.zh + zh(other))
        return NotImplemented

    def __radd__(self, other):
        if isinstance(other, str):
            return Text(other + str(self), zh(other) + self.zh)
        return NotImplemented

    def __reduce__(self):
        return (Text, (str(self), self.zh))


def bi(en: str, zh_text: str) -> Text:
    """One sentence in both languages."""
    return Text(en, zh_text)


def zh(value) -> str:
    """The Chinese for `value`: its own when it carries one, else by pattern."""
    if isinstance(value, Text):
        return value.zh
    if isinstance(value, str):
        return fragment(value)
    return value


def say(value, lang: str):
    """`value` in `lang`. English is the value itself."""
    return zh(value) if lang == ZH else value


def lang_of(request) -> str:
    """Which edition a request is for. Set by the prefix middleware."""
    try:
        return request.scope.get("state", {}).get("lang", EN)
    except AttributeError:
        return EN


def pad(name: str, fallback: str = "") -> str:
    """A name set into a Chinese sentence: `name`, with a space either side
    where it meets Han characters in Latin letters (PayPal, paypal.com), or
    `fallback` -- itself Chinese, so unspaced -- when there is no name."""
    if not name:
        return fallback
    left = " " if name[0].isascii() and name[0].isalnum() else ""
    right = " " if name[-1].isascii() and name[-1].isalnum() else ""
    return f"{left}{name}{right}"


# --- the browser scripts' words ---------------------------------------------

# What static/*.js says, keyed by its English. The scripts are shared by both
# editions and hold English only: anyone can read a script, and Chinese in it
# would announce that a Chinese edition exists. These are handed to a page in
# a JSON blob only when the page is Chinese (base.html). `{name}` is filled in
# by the script. The scripts carry no comment about any of this: a comment in
# a shared file is read by every visitor, and "the words come from the page
# when it is not English" says an edition in another language exists.
SCRIPT_WORDS: dict[str, str] = {
    # scanning.js
    "Phishing Detector | Interrupted": "钓鱼网站检测 | 已中断",
    "The check was interrupted": "检查被中断了",
    "There is no completed result from this attempt.": "这次尝试没有得到完整的结果。",
    "Interrupted": "已中断",
    "Not completed": "未完成",
    "No progress update arrived for 90 seconds. Try again in a moment.":
        "已经 90 秒没有收到进度更新。请稍后再试。",
    "The service sent an unreadable progress update. Try again.":
        "服务发来了一条无法读取的进度更新。请重试。",
    "Returned data": "返回了数据",
    "Failed": "失败",
    "Timed out": "超时",
    "Skipped": "已跳过",
    "Finished": "已完成",
    "{label}: {detail}": "{label}：{detail}",
    "{done} of {total} checks finished": "{total} 项检查中已完成 {done} 项",
    "{done} finished": "已完成 {done} 项",
    "Evidence gathered. Preparing your result...": "证据已收集完毕。正在准备你的结果……",
    "The checker stopped before it could finish this address.":
        "检查工具在完成这个地址的检查之前停止了。",
    "The connection to the checker was lost. Try again in a moment.":
        "与检查工具的连接中断了。请稍后再试。",
    "The check stopped when you left this page. Check the link again to see a result.":
        "你离开这个页面时检查就停止了。请重新检查这个链接以查看结果。",
    # site.js
    "That looks like more than one address. Paste one at a time.":
        "这看起来不止一个地址。请一次只粘贴一个。",
    "That address is too long to check. Addresses of up to 2000 characters can be checked.":
        "这个地址太长，无法检查。最多可以检查 2000 个字符的地址。",
    "Enter a web address, such as example.com. Only HTTP and HTTPS links can be checked.":
        "请输入一个网址，例如 example.com。只能检查 HTTP 和 HTTPS 链接。",
    "Paste a link to check.": "请粘贴要检查的链接。",
    # result.js
    "Copy was unavailable. Select the text you need and copy it manually.":
        "无法复制。请选中需要的文字，手动复制。",
    "Copied.": "已复制。",
    "{shown} of {total} sources shown": "显示 {total} 个来源中的 {shown} 个",
    "Preparing the complete report...": "正在准备完整的报告……",
    "Link assessment": "链接评估",
    "This report includes the full submitted link and collected evidence. Review it before sharing.":
        "这份报告包含提交的完整链接和收集到的证据。分享之前请先检查一遍。",
    "Report downloaded. It includes the full link and evidence; review it before sharing.":
        "报告已下载。它包含完整的链接和证据，分享之前请先检查一遍。",
    "The report could not be prepared. Try again.": "无法准备报告。请重试。",
}


# --- counted phrases ---------------------------------------------------------

_OF = re.compile(r"^\s*(\d+) of (\d+)\s*$")


def of_zh(detail: str) -> str:
    """'3 of 40' as Chinese reads a count: 40 个中有 3 个."""
    m = _OF.match(detail or "")
    if not m:
        return fragment(detail)
    return f"{m.group(2)} 个中有 {m.group(1)} 个"


def age_zh(days: float) -> str:
    """How long ago, the way plain.py's `_age_phrase` says it in English."""
    days = int(days)
    if days < 1:
        return "今天"
    if days == 1:
        return "昨天"
    if days < 31:
        return f"{days} 天前"
    if days < 60:
        return "大约一个月前"
    if days < 365:
        return f"大约 {days // 30} 个月前"
    return f"大约 {days // 365} 年前"


# --- machine wording ---------------------------------------------------------

# Words a source reports that read the same everywhere they appear.
_EXACT: dict[str, str] = {
    # collector/base.py, collector/run.py
    "malformed result": "结果格式有误",
    "not run": "未运行",
    "its reply could not be read": "它的回复无法读取",
    "the scan budget was spent": "本次检查的时间预算已用完",
    "page was not fetched": "页面未能获取",
    "not needed, RDAP answered": "无需查询，RDAP 已有答复",
    "not needed, the page returned real markup": "无需运行，页面已返回真实内容",
    "rendering disabled for this scan": "本次检查未启用脚本渲染",
    "PHISHING_DETECTOR_ALLOW_JS is not set": "未设置 PHISHING_DETECTOR_ALLOW_JS",
    "playwright is not installed": "未安装 playwright",
    # asn.py
    "no address resolved": "未解析到任何地址",
    "Cymru lookup returned nothing": "Cymru 查询没有返回结果",
    "ASN unavailable": "无法获取 ASN",
    # dns_records.py
    "hostname is an IP literal": "主机名是一个 IP 地址",
    "the name did not resolve in time": "域名未能及时解析",
    "the address does not resolve to a public host": "该地址没有解析到公网主机",
    "the name does not resolve": "该域名无法解析",
    "no A or AAAA record": "没有 A 或 AAAA 记录",
    "no domain to query": "没有可查询的域名",
    "no MX or NS records": "没有 MX 或 NS 记录",
    # ctlog.py
    "no hostname to query": "没有可查询的主机名",
    "no hostname to resolve": "没有可解析的主机名",
    "nodename nor servname provided, or not known": "这个域名不存在",
    "Name or service not known": "这个域名不存在",
    "No address associated with hostname": "这个域名没有对应的地址",
    "Temporary failure in name resolution": "域名解析暂时失败",
    "the fetch ran past its deadline": "获取页面超过了时限",
    "uncalibrated": "未校准",
    "certificate log lookups are queued too deep on this instance":
        "本服务的证书日志查询排队过多",
    "no CT source answered (Certspotter and crt.sh both unavailable)":
        "证书透明度日志没有响应（Certspotter 和 crt.sh 均不可用）",
    "no timestamped certificate found": "没有找到带时间戳的证书",
    # favicon.py
    "the page uses an inline icon; no separate image was requested":
        "页面使用内嵌图标，没有单独请求图片",
    "the icon address does not use HTTP or HTTPS": "图标地址不是 HTTP 或 HTTPS",
    "icon exceeds size cap": "图标超出大小上限",
    # rdap.py
    "no registrable domain": "没有可注册的域名",
    "registry lookups are queued too deep on this instance": "本服务的注册局查询排队过多",
    "no RDAP record for this domain": "该域名没有 RDAP 记录",
    "RDAP returned non-JSON": "RDAP 返回的不是 JSON",
    "RDAP record carried no registration date": "RDAP 记录中没有注册日期",
    "WHOIS lookups are queued too deep on this instance": "本服务的 WHOIS 查询排队过多",
    "WHOIS response carried no parseable creation date": "WHOIS 回复中没有可读的创建日期",
    # render.py, tls.py, http_chain.py
    "not an HTTP URL": "不是 HTTP 地址",
    "not an https URL": "不是 HTTPS 地址",
    "no certificate": "没有证书",
    "unknown issuer": "未知签发者",
    "page was not rendered": "页面未渲染",
    "static markup": "静态页面代码",
    "rendered DOM": "渲染后的页面",
    # redirect hops (collector/http_chain.py)
    "non-HTTP scheme, not followed": "非 HTTP 协议，未跟随",
    "redirected to something that is not a web address": "跳转到了一个不是网址的东西",
    "redirect cap reached": "已达到跳转次数上限",
    # the safety envelope (config.py)
    "Redirect depth cap": "最多跟随的跳转次数",
    "Response size cap": "响应大小上限",
    "Per-collector timeout": "每项查询的超时时间",
    "Javascript execution": "执行 JavaScript",
    "Render timeout": "渲染超时",
    "Form submission": "提交表单",
    "Downloads": "下载",
    "RDAP rate limit": "RDAP 查询频率上限",
    "WHOIS rate limit": "WHOIS 查询频率上限",
    "ENABLED": "已启用",
    "disabled": "已关闭",
    "permitted": "允许",
    "never": "从不",
    "allowed": "允许",
    "blocked": "已拦截",
    # features
    "no registration record returned": "没有返回注册记录",
    "no brand list available": "没有可用的品牌列表",
    "risk table not fitted yet": "风险表尚未训练",
    "own brand domain": "品牌自己的域名",
    "exfil endpoint found inside a base64 blob": "在 base64 数据块中发现了外传端点",
    "no page content": "没有页面内容",
    # verify/reputation.py
    "no Safe Browsing key configured": "未配置 Safe Browsing 密钥",
    "Safe Browsing sent an unreadable answer": "Safe Browsing 返回了无法读取的答复",
    "phishing or deception": "网络钓鱼或欺诈",
    "malware": "恶意软件",
    "unwanted software": "有害软件",
    # sensitive field categories (features/detectors.py)
    "card number": "银行卡号",
    "CVV": "CVV 安全码",
    "card expiry": "银行卡有效期",
    "SSN": "社会安全号码",
    "bank details": "银行账户信息",
    "OTP / 2FA code": "一次性验证码",
    "identity question": "身份验证问题",
    "wallet seed phrase": "钱包助记词",
    # crosscheck verdict names, shown with underscores replaced
    "confirmed_phish": "确认为钓鱼",
    "confirmed_benign": "确认安全",
    "needs_review": "需要人工复核",
    "phish": "钓鱼",
    "benign": "安全",
    "unsure": "不确定",
    "abstain": "无法判断",
    "none": "无",
    # model/persist.py
    "Calibrated probability": "校准后的概率",
    "Uncalibrated score": "未校准的分数",
    "Probability": "概率",
    "Score": "分数",
    # the model's own caveat (models/manifest.json)
    ("Fitted on collected evidence, including Tranco domains scanned as https://domain/ so "
     "that established sites on their own infrastructure are in the benign class. Not "
     "comparable with the URL-only numbers — a different population as well as a different "
     "feature set."):
        ("基于实际收集到的证据训练，其中包括以 https://域名/ 方式扫描的 Tranco 热门域名，"
         "让运行在自有基础设施上的成熟网站进入安全一类。与只看网址的模型数字不可比："
         "样本群体和特征集都不同。"),
}

# (pattern, replacement). A replacement is a format string over the groups, or
# a callable taking the match. First match wins; anchored at both ends, so a
# pattern never translates half of a line and leaves the rest in English.
_Sub = str | Callable[[re.Match], str]
_PATTERNS: list[tuple[re.Pattern, _Sub]] = []


def _p(pattern: str, sub: _Sub) -> None:
    _PATTERNS.append((re.compile(rf"^{pattern}$", re.S), sub))


def _f(m: re.Match, i: int) -> str:
    """A group that is itself a fragment, translated in turn."""
    return fragment(m.group(i))


# collector/run.py
_p(r"exceeded (\d+)s scan budget", "超出 {0} 秒的检查时间预算")
_p(r"no answer in time \(for (.+), where the address leads\)",
   "没有及时回应（针对 {0}，即该地址最终到达的网站）")
_p(r"(.+) \(for (.+), where the address leads\)",
   lambda m: f"{_f(m, 1)}（针对 {m.group(2)}，即该地址最终到达的网站）")
# asn.py
_p(r"not an address: (.+)", "不是有效地址：{0}")
# netguard.py, quoted inside "refusing to fetch: ..."
_p(r"(\S+) did not resolve: its domain's lookups are stalled", "{0} 无法解析：它所属域名的查询卡住了")
_p(r"(\S+) did not resolve within (\d+)s", "{0} 在 {1} 秒内没有解析出来")
_p(r"(\S+) does not resolve: (.+)", lambda m: f"{m.group(1)} 无法解析：{_f(m, 2)}")
# The operating system's resolver, quoted inside the line above
_p(r"\[Errno -?\d+\] (.+)", lambda m: _f(m, 1))
_p(r"(\S+) resolved to nothing", "{0} 没有解析到任何地址")
_p(r"(\S+) resolved to (.+)", "{0} 解析到了 {1}")
_p(r"(\S+) does not resolve to a public address", "{0} 没有解析到公网地址")
_p(r"redirect cap reached after (\d+) hops", "跳转 {0} 次后达到上限")
# http_chain.py hops
_p(r"not followed: (.+)", lambda m: f"未跟随：{_f(m, 1)}")
_p(r"not fetched: (.+)", lambda m: f"未获取：{_f(m, 1)}")
# config.py, the envelope's values
_p(r"([\d.]+) req/s", "每秒 {0} 次请求")
_p(r"(\d+) MB", "{0} MB")
# dns_records.py
_p(r"(\d+) record\(s\), TTL (\S+?)s", "{0} 条记录，TTL {1} 秒")
_p(r"(\d+) MX, (\d+) NS", "{0} 条 MX，{1} 条 NS")
_p(r"no MX, (\d+) NS", "没有 MX，{0} 条 NS")
# ctlog.py
_p(r"no certificates logged for this hostname \((.+)\)", "该主机名没有记录在案的证书（{0}）")
_p(r"(\d+) cert\(s\) via (.+), no timestamps", "通过 {1} 找到 {0} 张证书，没有时间戳")
_p(r"(\d+) cert\(s\) via (.+), first seen (\d+)d ago",
   "通过 {1} 找到 {0} 张证书，最早出现于 {2} 天前")
_p(r"(\d+) current cert\(s\) via (.+), oldest (\d+)d old \(expired ones not listed\)",
   "通过 {1} 找到 {0} 张当前有效的证书，最早的已有 {2} 天（过期的未列出）")
# http_chain.py
_p(r"refusing non-HTTP scheme: (.+)", "拒绝非 HTTP 协议：{0}")
_p(r"refusing to fetch: (.+)", lambda m: f"拒绝获取：{_f(m, 1)}")
_p(r"fetch failed: (.+)", "获取失败：{0}")
_p(r"download refused \((.+)\)", "已拒绝下载（{0}）")
_p(r"(\d+) hop\(s\), (\d+) cross-domain, (\d+) KB of (\d+) MB cap(.*)",
   lambda m: (f"{m.group(1)} 次跳转，{m.group(2)} 次跨域，{m.group(3)} KB"
              f"（上限 {m.group(4)} MB）{fragment(m.group(5)) if m.group(5) else ''}"))
_p(r", page withheld \((.+)\)", "，页面被拒绝提供（{0}）")
_p(r", page withheld by (.+) \(HTTP (\d+)\)", "，页面被 {0} 拦截（HTTP {1}）")
# favicon.py
_p(r"icon address not fetched: (.+)", lambda m: f"图标地址未获取：{_f(m, 1)}")
_p(r"no icon \(HTTP (\d+)\)", "没有图标（HTTP {0}）")
_p(r"matches (.+)'s favicon", "与 {0} 的网站图标一致")
_p(r"(\d+) bytes, no brand match", "{0} 字节，未匹配任何品牌")
# rdap.py
_p(r"timeout after (\d+)s", "{0} 秒后超时")
_p(r"RDAP HTTP (\d+)", "RDAP 返回 HTTP {0}")
_p(r"created (\S+), (\d+)d old", "创建于 {0}，已有 {1} 天")
_p(r"no WHOIS server published for (.+)", "没有为 {0} 公布 WHOIS 服务器")
_p(r"created (\S+) via (.+)", "创建于 {0}（来自 {1}）")
# render.py
_p(r"refusing to render: (.+)", lambda m: f"拒绝渲染：{_f(m, 1)}")
_p(r"navigation exceeded (\d+)s", "页面加载超过 {0} 秒")
_p(r"render failed: (.+)", "渲染失败：{0}")
_p(r"(\d+) chars text, (\d+) password field\(s\), (\d+) third-party host\(s\)(.*)",
   lambda m: (f"{m.group(1)} 个文本字符，{m.group(2)} 个密码框，{m.group(3)} 个第三方主机"
              + (re.sub(r", (\d+) download blocked", r"，已拦截 \1 个下载", m.group(4))
                 if m.group(4) else "")))
# tls.py
_p(r"refusing to connect: (.+)", lambda m: f"拒绝连接：{_f(m, 1)}")
_p(r"the site does not serve HTTPS \((.+)\)", "该网站不提供 HTTPS（{0}）")
_p(r"unparseable certificate: (.+)", "证书无法解析：{0}")
_p(r"(.+), (\d+) SAN, (-?\d+)d old",
   lambda m: f"{_f(m, 1)}，{m.group(2)} 个 SAN，已签发 {m.group(3)} 天")
# features
_p(r"(\d+) of (\d+)", "{1} 个中有 {0} 个")
_p(r"(\d+) of (\d+) from (.+)", "{1} 个中有 {0} 个来自 {2}")
_p(r"(\d+) marker\(s\), (\d+) base64 blob\(s\)", "{0} 个标记，{1} 个 base64 数据块")
_p(r"(\d+) chars of visible text", "{0} 个可见文本字符")
_p(r"(\d+)s", "{0} 秒")
_p(r"(\d+) bytes, cut at the cap", "{0} 字节，已在上限处截断")
_p(r"(\d+) -> (\d+) chars", "{0} → {1} 个字符")
_p(r"(\S+) belongs to (.+)", "{0} 属于 {1}")
_p(r"(\d+) to (.+)", "与 {1} 相差 {0} 个字符")
_p(r"(\d+), no near match", "{0}，没有相近的品牌")
_p(r"registration belongs to (.+), not this site", "注册记录属于 {0}，而不是这个网站")
_p(r"Safe Browsing did not answer \((.+)\)", "Safe Browsing 没有回应（{0}）")
_p(r"Safe Browsing refused the request \(HTTP (\d+)\)", "Safe Browsing 拒绝了请求（HTTP {0}）")
# model/persist.py and the manifest
_p(r"(.+?) / (.+?) / threshold ([\d.]+)",
   lambda m: f"{m.group(1)} / {_f(m, 2)} / 阈值 {m.group(3)}")
_p(r"(\w+) calibration", "{0} 校准")
_p(r"precision >= ([\d.]+) on the held-out split \(recall ([\d.]+)\)",
   "在留出数据集上精确率 ≥ {0}（召回率 {1}）")


def _listed(m: re.Match) -> str:
    """A list of categories, rendered with the Chinese enumeration comma --
    but only when its items are words this module knows. A list of hostnames
    or a sentence with commas in it is data, and is left alone."""
    items = m.group(1).split(", ")
    done = [fragment(x) for x in items]
    return "、".join(done) if done != items else m.group(0)


_p(r"([^,]+(?:, [^,]+)+)", _listed)


# Machine wording is a short status line. Anything longer is data -- a page's
# text, a `Location` header the scanned site wrote -- and is left alone
# without being matched: several patterns here backtrack, and a crafted
# 16 KB value cost a fifth of a second each.
MAX_FRAGMENT = 600


def fragment(text: str) -> str:
    """Machine wording in Chinese, or exactly as it came when unrecognised."""
    if not isinstance(text, str):
        return text
    if isinstance(text, Text):
        return text.zh
    if len(text) > MAX_FRAGMENT:
        return text
    if text in _EXACT:
        return _EXACT[text]
    for pattern, sub in _PATTERNS:
        m = pattern.match(text)
        if m:
            if callable(sub):
                return sub(m)
            return sub.format(*m.groups())
    return text
