"""Turning a decision into ranked, plain-language reasons.

This module is the product. A probability of 0.96 tells a user nothing they
can act on; "the password field posts to a domain unrelated to the page" tells
them exactly what is wrong and lets them judge it themselves.

Each template renders a feature's *actual value* into a sentence. Templates
never restate the model's opinion ("this looks suspicious") — they state the
observation and let the ranked contribution carry the weight.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from ..features.base import FeatureSet
from ..i18n import Text, bi, of_zh, pad, zh


@dataclass
class Reason:
    rank: int
    text: str
    feature: str
    contribution: float
    toward_phishing: bool


def _days(n: float) -> str:
    n = int(n)
    if n < 1:
        return "today"
    if n == 1:
        return "1 day ago"
    if n < 60:
        return f"{n} days ago"
    if n < 730:
        return f"{n // 30} months ago"
    return f"{n // 365} years ago"


def _days_zh(n: float) -> str:
    n = int(n)
    if n < 1:
        return "今天"
    if n < 60:
        return f"{n} 天前"
    if n < 730:
        return f"{n // 30} 个月前"
    return f"{n // 365} 年前"


def _plural(n: float, one: str, many: str) -> str:
    return one if int(n) == 1 else many


def _none(detail: str) -> bool:
    """Whether a "k of n" detail counts out of nothing."""
    return detail.strip().endswith(" of 0")


# value -> sentence. `d` is the feature's detail string, which carries the
# concrete particulars (which brand, which host, which date). Every sentence
# is written in both languages (see i18n); `zh(d)` is the detail in Chinese
# where it is machine wording, and itself where it is data.
TEMPLATES: dict[str, Callable[[float, str], str]] = {
    "domain_age_days": lambda v, d: bi(
        f"The registrable domain was registered {_days(v)}.",
        f"这个可注册域名是{pad(_days_zh(v))}注册的。"),
    "registration_period_days": lambda v, d: (
        bi(f"It was registered for {int(v) // 365} year(s). Phishers buy 12 months, not five years.",
           f"它的注册期限是 {int(v) // 365} 年。钓鱼者一般只买 12 个月，而不是五年。")
        if v else bi("Registration period is unavailable.", "无法获取注册期限。")),
    "days_to_expiry": lambda v, d: bi(
        f"The registration expires in {int(v)} days.", f"注册将在 {int(v)} 天后到期。"),
    "registrar_privacy": lambda v, d: (
        bi("Registrant details are hidden behind a privacy service.",
           "注册人信息被隐私保护服务隐藏了。")
        if v else bi("Registrant details are published rather than privacy-protected.",
                     "注册人信息是公开的，没有使用隐私保护。")),
    "favicon_brand_impersonation": lambda v, d: (
        bi(f"The page serves {d}'s exact favicon without being {d}'s domain, so the icon "
           "was copied from the real site.",
           f"这个页面使用的网站图标和{pad(d)}的一模一样，但它并不是{pad(d)}的域名，所以图标是从真网站上抄来的。")
        if v else bi("The favicon does not match any known brand's icon.",
                     "网站图标与任何已知品牌的图标都不一致。")),
    "on_shared_hosting": lambda v, d: (
        bi(f"The page is hosted on a free {d} subdomain, which requires no domain "
           "registration at all, so there is no registration history to check.",
           f"这个页面托管在 {d} 的免费子域名上，完全不需要注册域名，所以没有注册历史可查。")
        if v else bi("The site is on its own registered domain.", "这个网站使用的是自己注册的域名。")),
    "whois_lookup_failed": lambda v, d: (
        bi("Neither RDAP nor WHOIS returned a record, so domain age is unavailable. "
           "The failure itself carries weight: phishing sits disproportionately on "
           "TLDs with poor RDAP coverage.",
           "RDAP 和 WHOIS 都没有返回记录，所以无法得知域名年龄。查询失败本身也有分量："
           "钓鱼网站格外集中在 RDAP 覆盖较差的顶级域名上。")
        if v else bi("Registration records were retrieved successfully.", "成功获取了注册记录。")),

    "has_mx": lambda v, d: (
        bi("The domain has mail records, so it receives email like a real organisation.",
           "这个域名有邮件记录，所以它能像真正的机构一样接收电子邮件。")
        if v else bi("The domain has no MX records, so it receives no mail at all.",
                     "这个域名没有 MX 记录，所以它完全收不到邮件。")),
    "low_ttl": lambda v, d: (
        bi(f"DNS records carry a very short TTL ({d}), which is characteristic of fast-flux hosting.",
           f"DNS 记录的 TTL 非常短（{zh(d)}），这是快速变换托管（fast-flux）的典型特征。")
        if v else bi(f"DNS TTLs are ordinary ({d}).", f"DNS 的 TTL 很正常（{zh(d)}）。")),
    "a_record_count": lambda v, d: bi(
        f"{int(v)} address {_plural(v, 'record', 'records')} resolved.",
        f"解析出 {int(v)} 条地址记录。"),

    "cert_age_days": lambda v, d: bi(
        f"The TLS certificate was issued {_days(v)}" + (f" ({d})." if d else "."),
        f"TLS 证书是{pad(_days_zh(v))}签发的" + (f"（{zh(d)}）。" if d else "。")),
    "cert_validity_days": lambda v, d: bi(
        f"The certificate is valid for {int(v)} days.", f"证书的有效期为 {int(v)} 天。"),
    "san_count": lambda v, d: (
        bi(f"The certificate covers {int(v)} SAN entries, consistent with a bulk-issued wildcard.",
           f"证书覆盖了 {int(v)} 个 SAN 条目，符合批量签发的通配证书的特征。")
        if v >= 50 else bi(f"The certificate covers {int(v)} SAN {_plural(v, 'entry', 'entries')}.",
                           f"证书覆盖了 {int(v)} 个 SAN 条目。")),
    "tls_hostname_match": lambda v, d: (
        bi("The certificate matches the hostname being served.", "证书与所访问的主机名一致。")
        if v else bi("The certificate does NOT match the hostname being served.",
                     "证书与所访问的主机名并不一致。")),
    "tls_self_signed": lambda v, d: (
        bi("The certificate is self-signed.", "证书是自签名的。") if v
        else bi("The certificate is not self-signed.", "证书不是自签名的。")),
    "tls_chain_trusted": lambda v, d: (
        bi("The certificate chain verifies against the public trust store.",
           "证书链可以通过公共信任库的验证。")
        if v else bi("The certificate chain does not verify against the public trust store.",
                     "证书链无法通过公共信任库的验证。")),
    "tls_present": lambda v, d: (
        bi("The page is served over TLS.", "页面通过 TLS 加密传输。") if v
        else bi("The page is not served over TLS.", "页面没有通过 TLS 加密传输。")),

    "redirect_hops": lambda v, d: (
        bi(f"The request passed through {int(v)} {_plural(v, 'redirect', 'redirects')}.",
           f"请求经过了 {int(v)} 次跳转。")
        if v else bi("The URL resolved directly, with no redirects.", "这个网址直接打开，没有任何跳转。")),
    "redirect_cross_domain": lambda v, d: (
        bi("The redirect chain crosses to a different registrable domain.",
           "跳转过程中转到了另一个可注册域名。")
        if v else bi("No redirect left the original domain.", "没有任何跳转离开原来的域名。")),
    "https_downgrade": lambda v, d: (
        bi("The chain downgrades from HTTPS to plain HTTP.", "跳转过程中从 HTTPS 降级到了普通 HTTP。")
        if v else bi("No HTTPS-to-HTTP downgrade occurred.", "没有发生从 HTTPS 到 HTTP 的降级。")),
    "final_domain_changed": lambda v, d: (
        bi(f"The final page is served from {d}, not the domain submitted.",
           f"最终页面来自 {d}，而不是提交的域名。")
        if v else bi("The final page is on the domain that was submitted.", "最终页面就在提交的域名上。")),
    "fetch_failed": lambda v, d: (
        bi("The page could not be fetched, so no content evidence is available.",
           "页面无法获取，所以没有任何内容方面的证据。")
        if v else bi("The page was retrieved successfully.", "成功获取了页面。")),
    "safe_browsing_listed": lambda v, d: (
        bi(f"Google Safe Browsing lists this address ({d}).",
           f"Google 安全浏览（Safe Browsing）列出了这个地址（{zh(d)}）。")
        if v else bi("Google Safe Browsing does not list this address.",
                     "Google 安全浏览（Safe Browsing）没有列出这个地址。")),
    "fetch_blocked": lambda v, d: (
        (bi(f"The site refused to serve the page ({d})", f"这个网站拒绝提供页面（{d}）")
         if d.startswith("HTTP ")
         else bi(f"The site served a bot-detection page ({d}) instead of its content",
                 f"这个网站返回的是一个机器人检测页面（{d}），而不是它的内容"))
        + bi(", so the page itself was not seen.", "，所以没能看到页面本身。")
        if v else bi("The site served its page rather than a refusal or a bot-detection wall.",
                     "这个网站正常提供了页面，没有拒绝访问，也没有显示机器人检测。")),
    "serves_download": lambda v, d: (
        bi(f"The URL serves a file download rather than a page ({d}). It was not retrieved.",
           f"这个网址提供的是文件下载，而不是页面（{d}）。文件没有被下载。")
        if v else bi("The URL serves a page rather than a download.", "这个网址提供的是页面，而不是下载。")),

    "has_password_input": lambda v, d: (
        bi("The page contains a password field.", "页面上有一个密码框。")
        if v else bi("The page has no password field, so it is not collecting credentials directly.",
                     "页面上没有密码框，所以它没有直接收集账号密码。")),
    "form_action_cross_domain": lambda v, d: (
        bi("A form on this page posts to a different registrable domain than the page itself.",
           "页面上有一个表单，会把内容提交到与页面本身不同的可注册域名。")
        if v else bi("Forms post back to the page's own domain.", "表单提交回页面自己的域名。")),
    "form_action_insecure": lambda v, d: (
        bi("A form posts over plain HTTP, so anything typed into it travels unencrypted.",
           "有表单通过普通 HTTP 提交，所以在里面输入的任何内容都会以未加密的方式传输。")
        if v else bi("No form posts over plain HTTP.", "没有表单通过普通 HTTP 提交。")),
    "form_action_empty": lambda v, d: (
        bi("A form has an empty or javascript: action, so its destination is set at runtime.",
           "有表单的提交地址为空或是 javascript:，所以它的目的地是在运行时才确定的。")
        if v else bi("Form actions point at real destinations.", "表单的提交地址指向真实的目的地。")),
    # "0 of 0 links are dead" was said about pages with no links at all.
    "foreign_asset_ratio": lambda v, d: (
        bi("The page loads no stylesheets, scripts or images.", "页面没有加载任何样式表、脚本或图片。")
        if _none(d)
        else bi(f"{d} stylesheets, scripts and images load from a domain other than this one, "
                "the signature of a page that was saved and re-hosted.",
                f"样式表、脚本和图片中，{of_zh(d)}是从其他域名加载的，这是页面被另存后重新托管的典型特征。")
        if v > 0.5 else bi(f"{d} resources load from another domain.",
                           f"资源中，{of_zh(d)}是从其他域名加载的。")),
    "dead_anchor_ratio": lambda v, d: (
        bi("The page has no links.", "页面上没有链接。") if _none(d)
        else bi(f"{d} links go nowhere, which is what happens when a kit mirrors one page "
                "and drops the rest of the site.",
                f"链接中，{of_zh(d)}打不开。钓鱼工具包只复制一个页面、丢掉网站其余部分时，就会这样。")
        if v > 0.3 else bi(f"{d} links are dead.", f"链接中，{of_zh(d)}是无效的。")),
    "favicon_foreign": lambda v, d: (
        bi(f"The favicon is loaded from {d}, a domain this page does not own.",
           f"网站图标是从 {d} 加载的，而这个页面并不拥有那个域名。")
        if v else bi("The favicon is served from the page's own origin.", "网站图标来自页面自己的域名。")),
    "title_domain_mismatch": lambda v, d: (
        bi(f"The page title names {d}, which does not appear in the registrable domain.",
           f"页面标题提到了 {d}，但它并没有出现在可注册域名中。")
        if v else bi("The page title is consistent with the domain.", "页面标题与域名相符。")),
    "hidden_iframe_count": lambda v, d: (
        bi(f"The page contains {int(v)} hidden or zero-dimension {_plural(v, 'iframe', 'iframes')}.",
           f"页面上有 {int(v)} 个隐藏的或尺寸为零的内嵌框架（iframe）。")
        if v else bi("No hidden iframes are present.", "页面上没有隐藏的内嵌框架。")),
    "meta_refresh": lambda v, d: (
        bi("The page uses a meta refresh redirect.", "页面使用了 meta refresh 跳转。") if v
        else bi("No meta refresh redirect.", "没有 meta refresh 跳转。")),
    # Three wordings, not two. At zero the scripts are plain; a single marker
    # (one `atob(` or `\x` escape) is common in ordinary bundles, and calling
    # that "not obfuscated" beside a number pushing toward a scam read as a
    # contradiction.
    "obfuscation_score": lambda v, d: (
        bi(f"Scripts on the page show obfuscation ({d}).", f"页面上的脚本有混淆的迹象（{zh(d)}）。")
        if v > 0.2
        else bi(f"Scripts show a trace of obfuscation ({d}).", f"脚本有轻微的混淆痕迹（{zh(d)}）。")
        if v > 0
        else bi("Scripts are not obfuscated.", "脚本没有被混淆。")),
    "right_click_disabled": lambda v, d: (
        bi("The page disables the right-click context menu.", "页面禁用了右键菜单。")
        if v else bi("The context menu is not disabled.", "右键菜单没有被禁用。")),
    "render_empty": lambda v, d: (
        bi(f"The page returned almost no markup to a plain fetch ({d}), so it renders "
           "client-side. Content features are unreliable for this page.",
           f"普通获取时，页面几乎没有返回任何内容（{zh(d)}），说明它是在浏览器端用脚本生成的。"
           "对这个页面来说，内容方面的特征不可靠。")
        if v else bi("The page returned real markup without needing JavaScript.",
                     "页面不需要 JavaScript 就返回了真实的内容。")),

    "js_rendered": lambda v, d: (
        bi("The page was rendered with JavaScript, so content features reflect the "
           "live DOM rather than the raw markup.",
           "页面已用 JavaScript 渲染，所以内容特征反映的是实际显示的页面，而不是原始代码。")
        if v else bi(f"The page was not rendered ({d}).", f"页面没有被渲染（{zh(d)}）。")),
    "js_dom_growth": lambda v, d: (
        bi(f"JavaScript built most of this page ({d}). The raw response was close to empty.",
           f"这个页面的大部分内容是由 JavaScript 生成的（{zh(d)}）。原始响应几乎是空的。")
        if v > 5 else bi(f"JavaScript changed the page only marginally ({d}).",
                         f"JavaScript 只对页面做了很小的改动（{zh(d)}）。")),
    "js_injected_password": lambda v, d: (
        bi("A password field exists only after JavaScript runs, so a plain fetch "
           "would not see the credential form at all.",
           "密码框只有在 JavaScript 运行之后才会出现，所以普通获取根本看不到这个登录表单。")
        if v else bi("No password field appears after rendering.", "渲染之后也没有出现密码框。")),
    "js_redirected": lambda v, d: (
        bi(f"JavaScript navigated the browser to {d}, a different registrable domain.",
           f"JavaScript 把浏览器转到了 {d}，这是另一个可注册域名。")
        if v else bi("JavaScript did not redirect off the domain.", "JavaScript 没有把浏览器转离这个域名。")),
    "js_third_party_hosts": lambda v, d: (
        bi(f"Rendering pulled resources from {int(v)} third-party host(s): {d}.",
           f"渲染时从 {int(v)} 个第三方主机加载了资源：{d}。")
        if v else bi("Rendering pulled no third-party resources.", "渲染时没有加载任何第三方资源。")),
    "js_download_attempt": lambda v, d: (
        bi(f"The page tried to start a file download ({d}). It was blocked, not followed.",
           f"页面试图开始下载文件（{d}）。下载已被拦截，没有继续。")
        if v else bi("The page did not attempt a download.", "页面没有尝试下载任何文件。")),
    "js_dialog_attempt": lambda v, d: (
        bi("The page opened a JavaScript dialog, which was dismissed.",
           "页面弹出了一个 JavaScript 对话框，已被关闭。")
        if v else bi("The page opened no dialogs.", "页面没有弹出任何对话框。")),
    "content_from_render": lambda v, d: bi(
        f"Content features were read from the {d}.", f"内容特征读取自{zh(d)}。"),

    "brand_in_wrong_position": lambda v, d: (
        bi(f"The brand name{'s' if int(v) > 1 else ''} {d} appear in the subdomain or path, "
           "but not in the registrable domain.",
           f"品牌名称 {d} 出现在子域名或路径中，却没有出现在可注册域名里。")
        if v else bi("No brand name appears outside the registrable domain.",
                     "可注册域名之外没有出现任何品牌名称。")),
    "brand_embedded_in_domain": lambda v, d: (
        bi(f"The registrable domain has the brand name {d} buried inside it.",
           f"可注册域名里夹带了品牌名称 {d}。")
        if v else bi("No brand name is embedded in the registrable domain.",
                     "可注册域名里没有夹带任何品牌名称。")),
    "is_known_brand_domain": lambda v, d: (
        bi(f"{d} is the brand's own registered domain, not a lookalike of it.",
           f"{d} 是这个品牌自己注册的域名，而不是仿冒的。")
        if v else bi("The domain is not a known brand's own domain.", "这个域名不是任何已知品牌自己的域名。")),
    "user_content_on_brand_domain": lambda v, d: (
        bi(f"The page is published on {d}, where anyone can put a page under the "
           "brand's name. The address belongs to the brand; the page does not.",
           f"这个页面发布在 {d} 上，任何人都可以在那里以这个品牌的名义放置页面。地址属于品牌，页面却不是。")
        if v else bi("The page is not on a host that publishes strangers' pages.",
                     "这个页面不在允许陌生人发布页面的平台上。")),
    "brand_sld_wrong_suffix": lambda v, d: (
        bi(f"The domain uses a brand name on the wrong suffix ({d}).",
           f"这个域名把品牌名称用在了不对的后缀上（{d}）。")
        if v else bi("The domain does not put a brand name on an unexpected suffix.",
                     "这个域名没有把品牌名称用在意料之外的后缀上。")),
    "typosquat_distance": lambda v, d: (
        bi(f"The domain is {d}, within edit distance of a well-known brand.",
           f"这个域名{zh(d)}，非常接近一个知名品牌。")
        if v <= 2 else bi("The domain is not close to any well-known brand name.",
                          "这个域名与任何知名品牌的名称都不相近。")),
    "domain_entropy": lambda v, d: (
        bi(f"The domain name looks randomly generated (entropy {v:.2f}).",
           f"这个域名看起来像是随机生成的（熵 {v:.2f}）。")
        if v > 3.5 else bi(f"The domain name reads like words rather than random characters ({v:.2f}).",
                           f"这个域名读起来像是单词，而不是随机字符（{v:.2f}）。")),
    "num_digits_domain": lambda v, d: (
        bi(f"The registrable domain contains {int(v)} digit(s).", f"可注册域名中有 {int(v)} 个数字。")
        if v else bi("The registrable domain contains no digits.", "可注册域名中没有数字。")),
    "digit_ratio_domain": lambda v, d: (
        bi(f"{v:.0%} of the registrable domain is digits.", f"可注册域名中有 {v:.0%} 是数字。")
        if v > 0.2 else bi("The registrable domain is mostly letters.", "可注册域名主要由字母组成。")),
    "brand_cdn_asset_count": lambda v, d: (
        bi(f"{int(v)} resource(s) load from {d}'s own infrastructure, which is what a "
           "saved and re-hosted copy of their page looks like.",
           f"有 {int(v)} 个资源是从{pad(d)}自己的服务器加载的，这正是另存并重新托管他们页面的样子。")
        if v else bi("No resources load from a recognised brand's own infrastructure.",
                     "没有资源是从已知品牌自己的服务器加载的。")),
    "brand_cdn_asset_ratio": lambda v, d: (
        bi(f"{d}, served from the brand's infrastructure rather than this site's.",
           f"{zh(d)}，来自品牌自己的服务器，而不是这个网站的。")
        if v else bi("No assets are served from another brand's infrastructure.",
                     "没有资源来自其他品牌的服务器。")),
    "external_link_ratio": lambda v, d: (
        bi("The page has no links to other websites, or to anywhere.",
           "页面上没有指向其他网站的链接，也没有指向任何地方的链接。") if _none(d)
        else bi(f"{v:.0%} of the page's links point off this domain.",
                f"页面上 {v:.0%} 的链接指向这个域名之外。")
        if v > 0.5 else bi(f"Most links stay on this domain ({v:.0%} point elsewhere).",
                           f"大多数链接都留在这个域名内（{v:.0%} 指向别处）。")),
    "script_count": lambda v, d: (
        bi("The page runs no scripts.", "页面没有运行任何脚本。") if int(v) == 0
        else bi("The page carries 1 script tag.", "页面上有 1 个脚本标签。") if int(v) == 1
        else bi(f"The page carries {int(v)} script tags.", f"页面上有 {int(v)} 个脚本标签。")),
    "domain_token_count": lambda v, d: (
        bi(f"The registrable domain is built from {int(v)} hyphen-separated words.",
           f"可注册域名由 {int(v)} 个用连字符隔开的单词组成。")
        if v > 1 else bi("The registrable domain is a single word.", "可注册域名只有一个单词。")),
    "homograph_brand_match": lambda v, d: (
        bi(f"The domain is a look-alike of a brand name once confusable characters are "
           f"normalised ({d}).",
           f"把容易混淆的字符还原之后，这个域名就是某个品牌名称的仿冒（{d}）。")
        if v else bi("The domain is not a character-level look-alike of any brand.",
                     "这个域名在字符层面上不是任何品牌的仿冒。")),
    "exfil_endpoint": lambda v, d: (
        bi(f"Credentials are posted to {d}. No legitimate sign-in form does this.",
           f"账号密码会被提交到 {d}。没有任何正规的登录表单会这样做。")
        if v else bi("No credential-exfiltration endpoint was found in the page.",
                     "页面中没有发现窃取账号密码的外传地址。")),
    "sensitive_field_count": lambda v, d: (
        bi(f"The page asks for {int(v)} {_plural(v, 'category', 'categories')} "
           f"of sensitive data ({d}).",
           f"页面索要 {int(v)} 类敏感信息（{zh(d)}）。")
        if v else bi("The page asks for no card, identity or one-time-code fields.",
                     "页面没有索要银行卡、身份信息或一次性验证码。")),
    "kit_marker_count": lambda v, d: (
        bi(f"{int(v)} phishing-kit marker(s) present: {d}.", f"发现 {int(v)} 个钓鱼工具包的标记：{d}。")
        if v else bi("No phishing-kit markers were found.", "没有发现钓鱼工具包的标记。")),
    "asn_risk_score": lambda v, d: bi(
        f"The hosting network ({d}) carries a {v:.0%} phishing rate in the training "
        "data. Large clouds host both sides, so this is weak evidence on its own.",
        f"在训练数据中，这个托管网络（{d}）的钓鱼比例是 {v:.0%}。大型云服务商同时托管正规网站和钓鱼网站，"
        "所以单凭这一点只是很弱的证据。"),
    "ct_age_days": lambda v, d: bi(
        f"The oldest certificate found for this hostname was logged {_days(v)}"
        + (f" ({d})." if d else "."),
        f"这个主机名能找到的最早证书是{pad(_days_zh(v))}记录的" + (f"（{zh(d)}）。" if d else "。")),
    "ct_cert_count": lambda v, d: bi(
        f"{int(v)} certificate(s) recorded in Certificate Transparency logs.",
        f"证书透明度日志中记录了 {int(v)} 张证书。"),
    "tld_risk_score": lambda v, d: bi(
        f"The .{d} TLD carries a {v:.0%} phishing rate in the training data.",
        f"在训练数据中，.{d} 顶级域名的钓鱼比例是 {v:.0%}。"),
    "is_shortener": lambda v, d: (
        bi(f"The URL uses the link shortener {d}.", f"这个网址使用了短链接服务 {d}。") if v
        else bi("The URL is not shortened.", "这个网址不是短链接。")),
    "is_ip_hostname": lambda v, d: (
        bi("The URL uses a raw IP address instead of a hostname.", "这个网址直接使用了 IP 地址，而不是主机名。")
        if v else bi("The URL uses a hostname rather than a raw IP.", "这个网址使用的是主机名，而不是 IP 地址。")),
    "has_userinfo": lambda v, d: (
        bi(f"The URL embeds '{d}@' before the real hostname, a classic way to make a link "
           "look like it points somewhere else.",
           f"这个网址在真正的主机名前面嵌入了“{d}@”，这是让链接看起来指向别处的典型手法。")
        if v else bi("The URL contains no embedded userinfo.", "这个网址中没有嵌入用户信息。")),
    "domain_is_punycode": lambda v, d: (
        bi("The domain is punycode-encoded, which can render as look-alike characters.",
           "这个域名使用了 punycode 编码，可能显示成看起来相似的字符。")
        if v else bi("The domain is not punycode-encoded.", "这个域名没有使用 punycode 编码。")),
    "lure_word_count": lambda v, d: (
        bi(f"The path contains {int(v)} urgency/credential {_plural(v, 'word', 'words')} ({d}).",
           f"路径中有 {int(v)} 个制造紧迫感或与账号密码有关的词（{d}）。")
        if v else bi("The path contains no credential-related keywords.", "路径中没有与账号密码有关的关键词。")),
    "domain_length": lambda v, d: bi(
        f"The registrable domain is {int(v)} characters long.", f"可注册域名长 {int(v)} 个字符。"),
    "num_hyphens_domain": lambda v, d: (
        bi(f"The domain contains {int(v)} {_plural(v, 'hyphen', 'hyphens')}.",
           f"这个域名中有 {int(v)} 个连字符。") if v else
        bi("The domain contains no hyphens.", "这个域名中没有连字符。")),
}


# What each scored signal is, in words, for when it could not be measured.
# "domain age days could not be determined" was the column name with its
# underscores removed, shown to people who have never seen the column.
UNMEASURED: dict[str, Text] = {
    "foreign_asset_ratio": bi("How much of the page loads from other websites",
                              "页面有多少内容是从其他网站加载的"),
    "brand_cdn_asset_ratio": bi("Whether the page loads pictures from a known brand's servers",
                                "页面是否从已知品牌的服务器加载图片"),
    "dead_anchor_ratio": bi("How many of the page's links go nowhere", "页面上有多少链接打不开"),
    "obfuscation_score": bi("Whether the page's scripts are disguised", "页面的脚本是否经过伪装"),
    "favicon_brand_impersonation": bi("Whether the site's icon is copied from a brand",
                                      "网站图标是否抄自某个品牌"),
    "has_password_input": bi("Whether the page asks for a password", "页面是否要求输入密码"),
    "form_action_cross_domain": bi("Where the page's forms send what is typed",
                                   "页面表单把输入的内容发送到哪里"),
    "form_action_insecure": bi("Whether the page's forms send data unencrypted",
                               "页面表单是否以未加密的方式发送数据"),
    "title_domain_mismatch": bi("Whether the page's title names another company",
                                "页面标题是否提到了另一家公司"),
    "hidden_iframe_count": bi("Whether the page hides embedded frames", "页面是否隐藏了内嵌框架"),
    "external_link_ratio": bi("How many links point to other websites", "有多少链接指向其他网站"),
    "script_count": bi("How many scripts the page runs", "页面运行了多少个脚本"),
    "render_empty": bi("Whether the page is an empty shell filled in by scripts",
                       "页面是否只是一个靠脚本填充内容的空壳"),
    "domain_age_days": bi("How long ago the website's name was registered", "网站的域名是多久以前注册的"),
    "registrar_privacy": bi("Whether the owner's details are hidden", "所有者的信息是否被隐藏"),
    "has_mx": bi("Whether the website's name can receive email", "网站的域名能否接收电子邮件"),
    "low_ttl": bi("How often the website's address records change", "网站的地址记录多久变化一次"),
    "a_record_count": bi("How many server addresses the name points to", "域名指向多少个服务器地址"),
    "exfil_endpoint": bi("Whether typed details are sent to a messaging service",
                         "输入的信息是否会被发送到聊天软件"),
    "sensitive_field_count": bi("What kinds of personal details the page asks for",
                                "页面索要哪些类型的个人信息"),
    "kit_marker_count": bi("Whether the page carries phishing-kit traces", "页面是否带有钓鱼工具包的痕迹"),
    "fetch_blocked": bi("Whether the site refused to show the page", "网站是否拒绝显示页面"),
    "typosquat_distance": bi("How close the name is to a known brand", "域名与已知品牌有多接近"),
}


def describe(name: str, fs: FeatureSet) -> str:
    """One sentence for one feature, or a readable fallback."""
    pretty = name.replace("_", " ")
    if name not in fs or not fs[name].present:
        what = UNMEASURED.get(name)
        if what:
            return bi(f"{what} could not be checked.", f"无法检查：{what.zh}。")
        return bi(f"{pretty} could not be determined.", f"无法确定 {name}。")
    feat = fs[name]
    if (name == "favicon_brand_impersonation" and feat.value
            and "favicon_on_owner_domain" in fs and fs["favicon_on_owner_domain"].value):
        # The model still weighs the icon match; the sentence must not claim a
        # copy when the icon is on its owner's own domain.
        return bi(f"The page serves {feat.detail}'s favicon on one of {feat.detail}'s own domains.",
                  f"这个页面在{pad(feat.detail)}自己的一个域名上使用了{pad(feat.detail)}的网站图标。")
    tmpl = TEMPLATES.get(name)
    if tmpl is None:
        return f"{pretty} = {feat.value:g}" + (f" ({feat.detail})" if feat.detail else "")
    try:
        return tmpl(feat.value, feat.detail)
    except Exception:  # noqa: BLE001 - a broken template must not break a scan
        return f"{pretty} = {feat.value:g}"


# Below this magnitude a contribution is numerical noise rather than evidence.
_NEGLIGIBLE = 1e-9


def rank(contributions: dict[str, float], fs: FeatureSet, top: int = 5) -> list[Reason]:
    """Top contributors by magnitude, both directions.

    Showing only the incriminating features would make every verdict read as
    guilty. The negatives are what make a low score legible.
    """
    ordered = sorted(contributions.items(), key=lambda kv: abs(kv[1]), reverse=True)
    picked = [kv for kv in ordered if abs(kv[1]) > _NEGLIGIBLE][:top]

    # Guarantee at least one counterweight when one exists.
    if picked and all(v > 0 for _, v in picked):
        counterweight = next((kv for kv in ordered if kv[1] < -_NEGLIGIBLE), None)
    elif picked and all(v < 0 for _, v in picked):
        counterweight = next((kv for kv in ordered if kv[1] > _NEGLIGIBLE), None)
    else:
        counterweight = None
    if counterweight:
        picked.append(counterweight)

    return [
        Reason(rank=i + 1, text=describe(name, fs), feature=name,
               contribution=value, toward_phishing=value > 0)
        for i, (name, value) in enumerate(picked)
    ]
