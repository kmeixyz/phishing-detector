"""URL -> verdict. The path the interface actually calls.

An important honesty constraint is enforced here. The collector gathers 82
observations, and the evidence panel shows all of them, but the *model* is
currently fitted on ten registrable-domain features (see dataset.py for why).
So the ranked reasons are drawn only from features the model actually used —
never from evidence it never saw. Presenting "the form posts to another
domain" as a reason for a score that did not consider form actions would be a
fabricated explanation, which is worse than no explanation.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone

import numpy as np
from threadpoolctl import threadpool_limits

from ..collector.base import FAILED, UNREADABLE, EvidenceBundle
from ..collector.run import RENDER_AUTO, scan
from ..explain.plain import PlainSummary, build as build_plain
from ..explain.reasons import Reason, rank
from ..features.base import FeatureSet
from ..features.evidence import extract_all
from ..i18n import bi, zh
from ..urls import without_credentials
from ..verify import reputation
from ..verify.crosscheck import (CONFIRMED_BENIGN, CONFIRMED_PHISH,
                                 MID_BAND_RATIO, NEEDS_REVIEW, Review, review)
from . import interval as interval_mod
from .persist import (Manifest, contributions as compute_contributions,
                      is_trained, load_base_pipeline, load_pipeline)

BAND_HIGH = bi("Credential phish", "窃取账号密码的钓鱼网站")
BAND_LOW = bi("No phishing signal", "没有钓鱼迹象")
BAND_MID = bi("Inconclusive", "无法定论")
BAND_THIN = bi("Likely phish, thin evidence", "可能是钓鱼网站，但证据不足")
NEEDS_REVIEW_LABEL = bi("Needs review", "需要人工复核")


@dataclass
class Verdict:
    url: str
    final_url: str
    probability: float
    threshold: float
    label: str
    note: str
    reasons: list[Reason]
    features: FeatureSet
    bundle: EvidenceBundle
    scored_features: list[str]
    collectors_ok: int
    collectors_total: int
    features_present: int
    features_total: int
    scanned_at: str
    model_header: str
    operating_note: str
    probability_label: str = "Probability"
    explain_error: str = ""
    interval_low: float | None = None
    interval_high: float | None = None
    interval_members: int = 0
    plain: PlainSummary | None = None
    untrained: bool = False
    collectors_skipped: list[str] = field(default_factory=list)
    review: Review | None = None
    evidence_groups: list[tuple[str, list[tuple[str, str, bool]]]] = field(default_factory=list)

    @property
    def thin(self) -> bool:
        """Registration evidence missing is what makes a verdict thin."""
        return _is_thin(self.bundle)


def _is_thin(bundle: EvidenceBundle) -> bool:
    """True when neither registration source came back."""
    return not (bundle.get("RDAP").ok or bundle.get("WHOIS fallback").ok)


def _band(p: float, threshold: float, thin: bool) -> tuple[str, str]:
    if p >= threshold and thin:
        return BAND_THIN, bi("Above the operating point, but registration evidence never came "
                             "back. The score rests on the remaining features.",
                             "高于判定线，但注册信息始终没有返回。这个分数依据的是其余特征。")
    if p >= threshold:
        return BAND_HIGH, bi("Above the operating point for this model.", "高于这个模型的判定线。")
    if p >= threshold * MID_BAND_RATIO:
        return BAND_MID, bi("Below the operating point, so the pipeline would not flag it, but "
                            "close enough that it warrants a human look.",
                            "低于判定线，所以不会被标记，但离判定线足够近，值得人工看一看。")
    return BAND_LOW, bi("Well below the operating point.", "远低于判定线。")


# One evidence row: (label, what to show, whether the value is missing).
Row = tuple[str, str, bool]


UNAVAILABLE = bi("unavailable", "无法获取")
YES, NO = bi("yes", "是"), bi("no", "否")
NOT_PUBLISHED = bi("not published", "未公开")


def _yes(value) -> str:
    return YES if value else NO


def _shown(fs: FeatureSet, name: str, fallback: str = UNAVAILABLE) -> str:
    """A feature's own wording, or `fallback` when it was never observed."""
    if name in fs and fs[name].present:
        f = fs[name]
        return f.detail or f"{f.value:g}"
    return fallback


def _url_rows(bundle: EvidenceBundle, fs: FeatureSet) -> list[Row]:
    p = bundle.parsed
    return [
        (bi("registrable domain", "可注册域名"), p.registrable, False),
        (bi("subdomain depth", "子域名层数"), str(len(p.subdomain_labels)), False),
        (bi("hostname length", "主机名长度"), str(len(p.hostname)), False),
        (bi("domain entropy", "域名随机度（熵）"),
         f"{fs['domain_entropy'].value:.2f}" if "domain_entropy" in fs else "-", False),
        (bi("typosquat distance", "与知名品牌的拼写差距"),
         fs["typosquat_distance"].detail if "typosquat_distance" in fs else "-", False),
        (bi("shortener", "短链接服务"),
         _yes(fs.features.get("is_shortener") and fs["is_shortener"].value), False),
        _safe_browsing_row(fs),
    ]


def _safe_browsing_row(fs: FeatureSet) -> Row:
    """Flagged (third item) only when Google lists the address."""
    if "safe_browsing_listed" not in fs:
        return ("Google Safe Browsing", bi("not checked (no key configured)",
                                           "未检查（未配置密钥）"), False)
    listed = fs["safe_browsing_listed"]
    if not listed.present:
        return ("Google Safe Browsing", bi(f"not checked ({listed.detail})",
                                           f"未检查（{zh(listed.detail)}）"), False)
    return ("Google Safe Browsing", listed.detail, bool(listed.value))


def _registration_rows(bundle: EvidenceBundle) -> list[Row]:
    p = bundle.parsed
    reg = bundle.get("RDAP") if bundle.get("RDAP").ok else bundle.get("WHOIS fallback")
    dns_a, dns_m = bundle.get("DNS A / AAAA"), bundle.get("DNS MX / NS")
    asn = bundle.get("ASN / geo")

    if reg.ok and not reg.data.get("describes_site", True):
        # The record belongs to the hosting provider. Say so, rather than
        # printing a 2020 creation date next to a page made this morning.
        host = reg.data.get("lookup_domain", "the host")
        rows: list[Row] = [
            (bi("hosted on", "托管于"), bi(f"{p.hosting_provider} (free subdomain)",
                                           f"{p.hosting_provider}（免费子域名）"), True),
            (bi("site registered", "网站注册"), bi("none: subdomains are not registered",
                                                   "无：子域名不需要注册"), True),
            (bi(f"{host} created", f"{host} 创建于"), reg.data.get("created", "")[:10], False),
            (bi("registrar (of host)", "注册商（托管方的）"),
             reg.data.get("registrar") or NOT_PUBLISHED, False),
        ]
    elif reg.ok:
        rows = [
            (bi("created", "创建于"),
             reg.data.get("created", "")[:10] + f" ({reg.data.get('source','')})", False),
            (bi("expires", "到期于"), reg.data.get("expires", "")[:10], False),
            (bi("registrar", "注册商"), reg.data.get("registrar") or NOT_PUBLISHED, False),
            (bi("privacy", "隐私保护"), bi("enabled", "已开启") if reg.data.get("privacy_enabled")
             else bi("disabled", "未开启"), False),
        ]
    else:
        rows = [
            ("RDAP", bundle.get("RDAP").detail, True),
            (bi("WHOIS fallback", "WHOIS（备用）"), bundle.get("WHOIS fallback").detail, True),
            (bi("domain age", "域名年龄"), UNAVAILABLE, True),
        ]

    if not dns_m.ok:
        mx = UNAVAILABLE
    elif dns_m.data.get("has_mx"):
        mx = str(len(dns_m.data.get("mx_records", [])))
    else:
        mx = bi("none", "无")

    return rows + [
        (bi("MX records", "MX 记录"), mx, not dns_m.ok),
        (bi("A records / TTL", "A 记录 / TTL"),
         bi(f"{len(dns_a.data.get('a_records', []))} / {dns_a.data.get('min_ttl')}s",
            f"{len(dns_a.data.get('a_records', []))} / {dns_a.data.get('min_ttl')} 秒")
         if dns_a.ok else UNAVAILABLE, not dns_a.ok),
        (bi("hosting ASN", "托管网络（ASN）"),
         f"{asn.data.get('asn','')}, {asn.data.get('country','')}"
         if asn.ok else UNAVAILABLE, not asn.ok),
    ]


def _tls_rows(bundle: EvidenceBundle) -> list[Row]:
    tls = bundle.get("TLS certificate")
    if not tls.ok:
        return [("TLS", tls.detail, True)]
    return [
        (bi("issuer", "签发者"), tls.data.get("issuer", ""), False),
        (bi("notBefore", "生效日期"), tls.data.get("not_before", "")[:10], False),
        (bi("validity", "有效期"), bi(f"{tls.data.get('validity_days')} days",
                                      f"{tls.data.get('validity_days')} 天"), False),
        (bi("hostname match", "与主机名匹配"), _yes(tls.data.get("hostname_match")), False),
        (bi("SAN entries", "SAN 条目数"), str(tls.data.get("san_count", "")), False),
        (bi("self-signed", "自签名"), _yes(tls.data.get("self_signed")), False),
        (bi("chain trusted", "证书链可信"), _yes(tls.data.get("chain_trusted")), False),
    ]


def _page_rows(bundle: EvidenceBundle, fs: FeatureSet) -> list[Row]:
    http = bundle.get("HTTP chain")
    if not http.ok:
        return [("HTTP", http.detail, True)]
    return [
        (bi("redirect hops", "跳转次数"),
         bi(f"{http.data.get('hop_count',0)}, {http.data.get('cross_domain_hops',0)} cross-domain",
            f"{http.data.get('hop_count',0)}，其中 {http.data.get('cross_domain_hops',0)} 次跨域"),
         False),
        (bi("downgrade", "HTTPS 降级"),
         YES if http.data.get("https_downgrade") else bi("none", "无"), False),
        (bi("final status", "最终状态码"), str(http.data.get("final_status", "")), False),
        (bi("password inputs", "密码框"), _shown(fs, "has_password_input"), False),
        (bi("form cross-domain", "表单跨域提交"), _shown(fs, "form_action_cross_domain"), False),
        (bi("dead anchors", "无效链接"), _shown(fs, "dead_anchor_ratio", "-"), False),
        (bi("foreign assets", "外部资源"), _shown(fs, "foreign_asset_ratio", "-"), False),
        (bi("favicon origin", "网站图标来源"), _shown(fs, "favicon_foreign", "-"), False),
        (bi("hidden iframes", "隐藏的内嵌框架"), _shown(fs, "hidden_iframe_count", "-"), False),
        (bi("obfuscation", "代码混淆"), _shown(fs, "obfuscation_score", "-"), False),
    ]


def _evidence_groups(bundle: EvidenceBundle, fs: FeatureSet) -> list[tuple[str, list[Row]]]:
    """The four-column evidence table. Raw observations, not model opinion.

    Each group is built from one source's reply, which can arrive malformed
    (a damaged cache file, a registry answering with the wrong types); that
    group says so instead of failing the whole result.
    """
    def rows(build, *args) -> list[Row]:
        try:
            return build(*args)
        except Exception:  # noqa: BLE001 - malformed evidence, any shape
            return [(bi("evidence", "证据"), bi("could not be read", "无法读取"), True)]
    return [
        (bi("URL", "网址"), rows(_url_rows, bundle, fs)),
        (bi("Registration and DNS", "注册信息与 DNS"), rows(_registration_rows, bundle)),
        ("TLS", rows(_tls_rows, bundle)),
        (bi("HTTP and page", "HTTP 与页面"), rows(_page_rows, bundle, fs)),
    ]


def score(url: str, use_cache: bool = True,
          render_mode: str = RENDER_AUTO) -> Verdict:
    """Scan `url` and score what came back."""
    return score_bundle(scan(url, use_cache=use_cache, render_mode=render_mode), url=url)


_log = logging.getLogger("phishing_detector.score")


_ONE_THREAD = False


def _one_openmp_thread() -> None:
    """One OpenMP thread for scoring, set once, after the model has loaded.

    A verdict predicts one row through ~300 trees 78 times (the model plus the
    bootstrap band), and scikit-learn's tree predictor starts a thread team
    across every core for each tree: 23,400 team starts a verdict. On an
    8-core machine one score took 1.5-4.7 s instead of 0.24 s, with identical
    output, and thirty visitors at once queued for over a minute on the result
    page. Here rather than at import: the runtime is loaded by unpickling the
    model, and importing scikit-learn up front drags pandas onto the serving
    path. Training does not score, and keeps its threads.
    """
    global _ONE_THREAD
    if not _ONE_THREAD:
        threadpool_limits(limits=1, user_api="openmp")
        _ONE_THREAD = True


def score_bundle(bundle, url: str | None = None) -> Verdict:
    """Score evidence that has already been collected.

    Split from `score` so the interface can hand the bundle its progress
    stream just finished straight to the result page, rather than scanning
    the same address a second time to show what the first scan found.

    Every source's answer is someone else's reply, or a file read back from
    the cache, and one field of an unexpected type -- a list of mail servers
    that is a number, a block reason that is a list -- raised out of scoring
    from wherever it was first read. If scoring fails, each answered source is
    set aside in turn, marked as a reply that could not be read, until the
    rest can be scored: one bad source costs its own evidence, not the check.
    A failure that no single source explains (a missing model) still raises.
    """
    try:
        return _score_bundle(bundle, url)
    except Exception as first:  # noqa: BLE001 - see above
        _log.exception("scoring failed; looking for a malformed source")
        for name, result in list(bundle.results.items()):
            if not result.ok:
                continue
            saved = (result.status, result.detail, result.data)
            result.status, result.detail, result.data = FAILED, UNREADABLE, {}
            try:
                verdict = _score_bundle(bundle, url)
            except Exception:  # noqa: BLE001
                result.status, result.detail, result.data = saved
                continue
            _log.warning("scored without %s, whose evidence was malformed", name)
            return verdict
        raise first


def _score_bundle(bundle, url: str | None = None) -> Verdict:
    url = url or bundle.url
    manifest = Manifest.load()
    pipe = load_pipeline()          # calibrated: the number shown to the user
    base_pipe = load_base_pipeline()  # uncalibrated: reachable coefficients
    _one_openmp_thread()

    fs = extract_all(bundle)
    http = bundle.data("HTTP chain")
    # A second opinion, kept out of the model's columns (EVIDENCE_FEATURES
    # never lists it) and read by one decisive rule. Absent entirely when no
    # key is configured, so a feature vector never changes shape.
    if reputation.configured():
        chain = [url] + [h["url"] for h in http.get("hops", [])
                         if h.get("status") is not None]
        listed, why = reputation.lookup(
            list(dict.fromkeys(without_credentials(u) for u in chain))[:20])
        if listed is None:
            fs.add_missing("safe_browsing_listed", why)
        else:
            fs.add("safe_browsing_listed", listed, detail=why)
    ok, total = bundle.coverage()
    final_url = http.get("final_url") or bundle.url

    if not is_trained() or manifest is None or pipe is None:
        present, ftotal = fs.presence()
        untrained = Verdict(
            url=url, final_url=final_url, probability=0.0, threshold=0.5,
            label=bi("No model trained", "尚未训练模型"),
            note=bi("Run `make baseline` to fit one.", "运行 `make baseline` 训练一个模型。"),
            reasons=[], features=fs, bundle=bundle, scored_features=[],
            collectors_ok=ok, collectors_total=total,
            collectors_skipped=bundle.skipped(),
            features_present=present, features_total=ftotal,
            scanned_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            model_header=bi("no model", "没有模型"), probability_label=bi("Score", "分数"),
            operating_note="", untrained=True,
            evidence_groups=_evidence_groups(bundle, fs),
        )
        untrained.plain = build_plain(untrained)
        return untrained

    cols = manifest.columns
    x = fs.vector(cols)
    prob = float(pipe.predict_proba(x.reshape(1, -1))[0, 1])
    # Attributions come from the uncalibrated pipeline. A calibrator wraps its
    # estimator, so `named_steps` is unreachable through it; and the
    # attribution scale is log-odds either way, which is what the reasons
    # panel reports.
    explain_error = ""
    try:
        contributions = compute_contributions(base_pipe, x, np.array(manifest.means), cols)
    except (AttributeError, KeyError) as exc:
        # Never swallow this quietly. Silently returning {} emptied the reasons
        # panel while everything else looked healthy, and the explanation is
        # the product — an empty panel has to announce itself.
        contributions = {}
        explain_error = bi(f"attributions unavailable ({type(exc).__name__}: {exc})",
                           f"无法计算各项贡献（{type(exc).__name__}: {exc}）")

    present, ftotal = fs.presence()
    thin = _is_thin(bundle)
    label, note = _band(prob, manifest.threshold, thin)

    # Second opinion. Runs on rules only — no learned weights — and can send
    # the whole verdict to "needs review" when it disagrees with the model.
    iv = interval_mod.predict(interval_mod.load(), x, prob)
    rev = review(fs, prob, manifest.threshold, contributions, ok, total, interval=iv)

    # The headline must state the decision that was actually reached, not the
    # band the raw probability falls in. Those diverge: google.com scored 0.909
    # (its own ASN carries a high learned risk) and the band read
    # "Inconclusive", while the cross-check had already confirmed it benign on
    # the decisive known-brand rule. Showing the band there is just wrong.
    if rev.decision == NEEDS_REVIEW:
        label = NEEDS_REVIEW_LABEL
        note = bi("The model and the independent rule check did not agree, or the "
                  "evidence was too thin to be confident. Details below.",
                  "模型和独立的规则检查意见不一致，或者证据太少，无法确定。详情见下方。")
    elif rev.decision == CONFIRMED_BENIGN:
        label = BAND_LOW
        if rev.override:
            note = bi(f"Overridden by the rule check: {rev.override}.",
                      f"已被规则检查推翻：{zh(rev.override)}。")
        else:
            note = bi("The model and the independent rule check agree this is not phishing.",
                      "模型和独立的规则检查一致认为这不是钓鱼网站。")
            if prob >= manifest.threshold * MID_BAND_RATIO:
                note += bi(f" The score itself was {prob:.2f}.", f"分数本身是 {prob:.2f}。")
    elif rev.decision == CONFIRMED_PHISH:
        label = BAND_THIN if thin else BAND_HIGH
        if rev.override:
            note = bi(f"Overridden by the rule check: {rev.override}.",
                      f"已被规则检查推翻：{zh(rev.override)}。")
        else:
            note = bi("The model and the independent rule check agree this is phishing.",
                      "模型和独立的规则检查一致认为这是钓鱼网站。")
            if thin:
                note += bi(" Registration evidence never came back, so the finding rests on "
                           "the remaining features.",
                           "注册信息始终没有返回，所以这个结论依据的是其余特征。")

    verdict = Verdict(
        url=url, final_url=final_url, probability=prob, threshold=manifest.threshold,
        label=label, note=note, reasons=rank(contributions, fs, top=5),
        features=fs, bundle=bundle, scored_features=cols,
        collectors_ok=ok, collectors_total=total,
        collectors_skipped=bundle.skipped(),
        features_present=present, features_total=ftotal,
        scanned_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        model_header=bi(manifest.header(), zh(manifest.header())),
        probability_label=bi(manifest.probability_label(), zh(manifest.probability_label())),
        explain_error=explain_error,
        interval_low=iv.low if iv else None,
        interval_high=iv.high if iv else None,
        interval_members=iv.members if iv else 0,
        operating_note=bi(f"{manifest.threshold_basis}. {manifest.caveat}",
                          f"{zh(manifest.threshold_basis)}。{zh(manifest.caveat)}"),
        evidence_groups=_evidence_groups(bundle, fs),
        review=rev,
    )
    # Attached after construction because it is derived from the finished
    # verdict — the plain summary reads the review decision and the features.
    verdict.plain = build_plain(verdict)
    return verdict
