"""Vercel entrypoint.

Vercel's Python runtime looks for a top-level `app.py` that defines `app`; the
application itself lives under `src/`, which is not on the path there. This
file is the whole bridge. Nothing else imports it, and `npm run dev`, the
systemd unit and the tests all go straight to `phishing_detector.web.app`.

The platform sets `VERCEL=1`, which `config.stateless()` reads: the function's
filesystem is read-only, so the deployment keeps no bundle cache, no lookup
cache and no corrections queue, and the page says so.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from phishing_detector.web.app import app  # noqa: E402,F401
