"""SQLite corpus index.

The point of this file is `first_seen`. A URL is recorded the first time a
feed shows it to us and never re-dated afterwards, which is what makes a
temporal train/test split possible later: train on everything first seen
before date X, test on what appeared after. A random split over this same
table would leak — phishing kits reuse infrastructure, so sibling URLs from
one campaign would land on both sides of the split and flatter the model.
"""

from __future__ import annotations

import json
import random
import sqlite3
from contextlib import contextmanager
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable, Iterator

from ..config import CORPUS, stateless

DB_PATH = CORPUS / "corpus.sqlite"

SCHEMA = """
CREATE TABLE IF NOT EXISTS feed_urls (
    url          TEXT PRIMARY KEY,
    source       TEXT NOT NULL,
    label        TEXT NOT NULL,
    first_seen   TEXT NOT NULL,
    last_seen    TEXT NOT NULL,
    times_seen   INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_feed_first_seen ON feed_urls(first_seen);
CREATE INDEX IF NOT EXISTS idx_feed_label ON feed_urls(label);

CREATE TABLE IF NOT EXISTS tranco_ranks (
    domain        TEXT NOT NULL,
    rank          INTEGER NOT NULL,
    snapshot_date TEXT NOT NULL,
    PRIMARY KEY (domain, snapshot_date)
);
CREATE INDEX IF NOT EXISTS idx_tranco_rank ON tranco_ranks(rank);

-- Registration and CT answers are properties of a domain, not of a URL, and
-- the corpus holds hundreds of URLs per shared-hosting domain. Without this,
-- scanning 500 *.vercel.app sites issues 500 identical RDAP queries against a
-- volunteer-run service at 0.5 req/s. Keyed by lookup name and source.
CREATE TABLE IF NOT EXISTS lookup_cache (
    source     TEXT NOT NULL,      -- 'rdap' | 'whois' | 'ct'
    key        TEXT NOT NULL,      -- registrable domain or hostname
    status     TEXT NOT NULL,
    detail     TEXT NOT NULL DEFAULT '',
    payload    TEXT NOT NULL DEFAULT '{}',
    fetched_at TEXT NOT NULL,
    PRIMARY KEY (source, key)
);

-- Scans, kept for one purpose: the earned-render gate asks whether a previous
-- scan of this URL abstained, and the client cannot be trusted to answer that
-- about itself. It is not a history list -- history lives in the visitor's
-- browser -- and nothing lists this table to anyone. Rows are only written when
-- PHISHING_DETECTOR_ALLOW_JS is set, since otherwise nothing can read them.
CREATE TABLE IF NOT EXISTS runs (
    url         TEXT PRIMARY KEY,
    host        TEXT NOT NULL,
    scanned_at  TEXT NOT NULL,
    label       TEXT NOT NULL DEFAULT '',
    decision    TEXT NOT NULL DEFAULT '',
    probability REAL,
    abstained   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_runs_scanned ON runs(scanned_at);

CREATE TABLE IF NOT EXISTS feedback (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    url           TEXT NOT NULL,
    url_hash      TEXT NOT NULL,
    kind          TEXT NOT NULL,      -- false_positive | false_negative | bad_evidence
    submitted_at  TEXT NOT NULL,
    verdict_label TEXT NOT NULL DEFAULT '',
    probability   REAL,
    threshold     REAL,
    abstained     INTEGER NOT NULL DEFAULT 0,
    note          TEXT NOT NULL DEFAULT '',
    resolved      INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_feedback_kind ON feedback(kind);
CREATE INDEX IF NOT EXISTS idx_feedback_hash ON feedback(url_hash);

CREATE TABLE IF NOT EXISTS collection_runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at  TEXT NOT NULL,
    source      TEXT NOT NULL,
    status      TEXT NOT NULL,
    fetched     INTEGER NOT NULL DEFAULT 0,
    new_rows    INTEGER NOT NULL DEFAULT 0,
    note        TEXT NOT NULL DEFAULT ''
);
"""


@contextmanager
def connect(path: Path | None = None) -> Iterator[sqlite3.Connection]:
    conn = sqlite3.connect(path or DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        conn.executescript(SCHEMA)
        yield conn
        conn.commit()
    finally:
        conn.close()


def upsert_urls(conn: sqlite3.Connection, entries: Iterable[dict]) -> int:
    """Insert unseen URLs, refresh last_seen on ones we already hold.

    Returns the count of genuinely new URLs. first_seen is never overwritten:
    a URL that reappears in the feed for a week keeps the date it was first
    observed, because that is the date the temporal split has to key on.
    """
    new = 0
    for e in entries:
        url = e.get("url")
        if not url:
            continue
        exists = conn.execute("SELECT 1 FROM feed_urls WHERE url = ?", (url,)).fetchone()
        if exists:
            # A later phishing report relabels a row that came in as benign.
            #
            # Without this the first feed to mention a URL owned its label for
            # good, which made every contamination check a one-shot test run at
            # build time: a host that gets itself into a benign source before it
            # is reported stays benign in the training table no matter what
            # arrives afterwards. The reverse is deliberately not allowed --
            # appearing in a benign feed never clears a URL a phishing feed has
            # named.
            conn.execute(
                "UPDATE feed_urls SET last_seen = :seen, times_seen = times_seen + 1,"
                " source = CASE WHEN :label = 'phish' AND label <> 'phish'"
                "               THEN :source ELSE source END,"
                " label  = CASE WHEN :label = 'phish' THEN 'phish' ELSE label END"
                " WHERE url = :url",
                {"seen": e["first_seen"], "label": e["label"],
                 "source": e["source"], "url": url},
            )
        else:
            conn.execute(
                "INSERT INTO feed_urls (url, source, label, first_seen, last_seen, times_seen)"
                " VALUES (?, ?, ?, ?, ?, 1)",
                (url, e["source"], e["label"], e["first_seen"], e["first_seen"]),
            )
            new += 1
    return new


def reported_hosts(conn: sqlite3.Connection) -> set[str]:
    """Every hostname any phishing feed has named, at any path."""
    from ..urls import parse

    return {parse(r["url"]).hostname
            for r in conn.execute("SELECT url FROM feed_urls WHERE label = 'phish'")}


def drop_reported(rows: list, reported: set[str]) -> list:
    """Benign rows minus any on a host a phishing feed has since named.

    `upsert_urls` relabels on an exact URL only, and a presumed-benign host is
    stored as its bare root, `https://host/`, while the feeds report paths
    under it -- so the two never met, and a host reported the week after it
    was collected kept its benign label into every table built from then on.
    This is checked whenever rows are drawn for training rather than once when
    they were collected. Rows are anything whose first item is the URL.
    """
    from ..urls import parse

    return [r for r in rows if parse(r[0]).hostname not in reported]


def upsert_tranco(conn: sqlite3.Connection, entries: Iterable[dict], snapshot: date) -> int:
    day = snapshot.isoformat()
    rows = [(e["domain"], e["rank"], day) for e in entries if e.get("domain")]
    conn.executemany(
        "INSERT OR REPLACE INTO tranco_ranks (domain, rank, snapshot_date) VALUES (?, ?, ?)",
        rows,
    )
    return len(rows)


def record_run(conn: sqlite3.Connection, started_at: str, source: str, status: str,
               fetched: int = 0, new_rows: int = 0, note: str = "") -> None:
    conn.execute(
        "INSERT INTO collection_runs (started_at, source, status, fetched, new_rows, note)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        (started_at, source, status, fetched, new_rows, note),
    )


def lookup_get(source: str, key: str, max_age_days: float = 14) -> dict | None:
    """Cached answer for a domain-level lookup, or None if absent/stale.

    `max_age_days` is fractional so a caller can hold a failed lookup for an
    hour while keeping a successful one for a fortnight.

    A stateless instance has no database to ask. Answering "not cached" here,
    rather than letting `sqlite3.connect` fail on a read-only tree, is what
    keeps RDAP and CT working there: the collector would otherwise record the
    lookup as failed on every scan, and the model would lose domain age and
    certificate history without anything saying why.
    """
    if stateless():
        return None
    with connect() as conn:
        row = conn.execute(
            "SELECT status, detail, payload, fetched_at FROM lookup_cache"
            " WHERE source = ? AND key = ?", (source, key)).fetchone()
    if row is None:
        return None
    try:
        age = datetime.now(timezone.utc) - datetime.fromisoformat(row["fetched_at"])
    except ValueError:
        return None
    if age > timedelta(days=max_age_days):
        return None
    try:
        payload = json.loads(row["payload"])
    except json.JSONDecodeError:
        return None
    return {"status": row["status"], "detail": row["detail"], "data": payload}


def lookup_put(source: str, key: str, status: str, detail: str, payload: dict) -> None:
    if stateless():
        return
    with connect() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO lookup_cache (source, key, status, detail, payload,"
            " fetched_at) VALUES (?, ?, ?, ?, ?, ?)",
            (source, key, status, detail, json.dumps(payload, default=str),
             datetime.now(timezone.utc).isoformat(timespec="seconds")),
        )


def record_scan(conn: sqlite3.Connection, url: str, host: str, scanned_at: str,
                label: str, decision: str, probability: float | None,
                abstained: bool) -> None:
    """One scan verdict, for the idle page's recent list.

    Named apart from `record_run`, which records a *feed collection* run. The
    first version of this reused that name and silently shadowed it, which
    would have broken every scheduled collection the next time one fired.
    """
    # Upsert rather than INSERT OR REPLACE, so a rescan updates the verdict in
    # place. One row per URL is the whole point: `last_scan` looks it up by URL
    # to decide whether a render has been earned.
    conn.execute(
        "INSERT INTO runs (url, host, scanned_at, label, decision, probability,"
        " abstained) VALUES (?, ?, ?, ?, ?, ?, ?)"
        " ON CONFLICT(url) DO UPDATE SET host=excluded.host,"
        " scanned_at=excluded.scanned_at, label=excluded.label,"
        " decision=excluded.decision, probability=excluded.probability,"
        " abstained=excluded.abstained",
        (url, host, scanned_at, label, decision, probability, int(abstained)),
    )


def last_scan(conn: sqlite3.Connection, url: str) -> dict | None:
    """The most recent verdict recorded for this exact URL, or None.

    `url` is the primary key on runs, so there is only ever one row. Used to
    decide whether JavaScript rendering has been earned - see
    `_render_permitted` in the web layer.
    """
    row = conn.execute(
        "SELECT url, host, scanned_at, label, decision, probability, abstained"
        " FROM runs WHERE url = ?", (url,),
    ).fetchone()
    return dict(row) if row is not None else None


# `recent_runs`, `set_nickname` and `delete_run` were here. Scan history moved
# into the visitor's browser, so there is nothing to list, name or delete
# server-side. `record_scan` and `last_scan` remain because the earned-render
# gate has to answer "did a previous scan of this URL abstain" without asking
# the client, which is the party that gains from the answer being yes.


def record_feedback(conn: sqlite3.Connection, url: str, url_hash: str, kind: str,
                    submitted_at: str, verdict_label: str = "", probability: float | None = None,
                    threshold: float | None = None, abstained: bool = False,
                    note: str = "") -> int:
    cur = conn.execute(
        "INSERT INTO feedback (url, url_hash, kind, submitted_at, verdict_label,"
        " probability, threshold, abstained, note) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (url, url_hash, kind, submitted_at, verdict_label, probability, threshold,
         int(abstained), note),
    )
    return int(cur.lastrowid or 0)


def resolve_feedback(conn: sqlite3.Connection, ids: Iterable[int]) -> int:
    """Mark feedback rows operator-approved, admitting them to training.

    Nothing else in the pipeline sets `resolved`: submission through the web
    form never does, so a row only becomes training data once a human running
    the CLI has looked at it and said so.
    """
    wanted = [(int(i),) for i in ids]
    if not wanted:
        return 0
    cur = conn.executemany("UPDATE feedback SET resolved = 1 WHERE id = ?", wanted)
    conn.commit()
    return int(cur.rowcount or 0)


def feedback_labels(conn: sqlite3.Connection) -> dict[str, int]:
    """{url: label} from human corrections, newest submission winning.

    Only the two kinds that assert a label are returned. `bad_evidence` says a
    collector returned something wrong, which is a bug report about the
    pipeline rather than a statement about the page, and training on it would
    teach the model to reproduce the collector's mistake.

    Only rows an operator has approved (`resolved = 1`, set by
    `resolve_feedback`) are returned. POST /feedback is unauthenticated, so
    without that gate anyone able to reach the form could choose the labels the
    classifier is fitted on -- relabelling their own phishing pages benign, or
    mass-flagging real sites. Rows arrive with `resolved = 0`, so the queue
    fails closed and a human decides what trains the model.
    """
    out: dict[str, int] = {}
    for row in conn.execute(
        "SELECT url, kind FROM feedback WHERE kind IN ('false_positive','false_negative')"
        " AND resolved = 1 ORDER BY id ASC"
    ):
        out[row["url"]] = 0 if row["kind"] == "false_positive" else 1
    return out


def feedback_queue(conn: sqlite3.Connection, limit: int = 50) -> list[dict]:
    return [dict(r) for r in conn.execute(
        "SELECT id, url, kind, submitted_at, verdict_label, probability, abstained,"
        " note, resolved FROM feedback ORDER BY id DESC LIMIT ?", (limit,))]


def feedback_summary(conn: sqlite3.Connection) -> dict:
    out = {r["kind"]: r["n"] for r in conn.execute(
        "SELECT kind, COUNT(*) n FROM feedback GROUP BY kind")}
    row = conn.execute(
        "SELECT COUNT(*) n FROM feedback WHERE abstained = 1").fetchone()
    out["from_abstentions"] = row["n"] if row else 0
    return out


def corpus_summary(conn: sqlite3.Connection) -> dict:
    out: dict = {}
    for row in conn.execute("SELECT label, COUNT(*) n FROM feed_urls GROUP BY label"):
        out[row["label"]] = row["n"]
    span = conn.execute("SELECT MIN(first_seen) lo, MAX(first_seen) hi FROM feed_urls").fetchone()
    out["first_seen_range"] = (span["lo"], span["hi"]) if span and span["lo"] else None
    tr = conn.execute("SELECT COUNT(DISTINCT domain) n FROM tranco_ranks").fetchone()
    out["tranco_domains"] = tr["n"] if tr else 0
    return out


def benign_long_tail(conn: sqlite3.Connection, lo: int = 100_000, hi: int = 1_000_000,
                     limit: int = 5000, seed: int = 0) -> list[str]:
    """Benign domains from the long tail, not the head.

    Drawing negatives from the Tranco top 10k teaches a model to recognise
    famous websites. Ranks 100k-1M are ordinary sites, which is the comparison
    that actually matters.

    Sampling is seeded in Python rather than delegated to SQL `RANDOM()`.
    That is not a detail: with an unseeded sample the negative set changed on
    every run, and PR-AUC swung between 0.35 and 0.86 across consecutive
    evaluations of identical code. An evaluation you cannot reproduce is not
    an evaluation.
    """
    span = range(lo, hi + 1)
    picks = random.Random(seed).sample(span, min(limit, len(span)))
    placeholders = ",".join("?" * len(picks))
    rows = conn.execute(
        f"""
        SELECT domain FROM tranco_ranks
        WHERE rank IN ({placeholders})
          AND snapshot_date = (SELECT MAX(snapshot_date) FROM tranco_ranks)
        """,
        picks,
    ).fetchall()
    return [r["domain"] for r in rows]
