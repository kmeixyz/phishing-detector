(() => {
  const WORDS = (() => {
    try { return JSON.parse(document.getElementById('page-words').textContent); }
    catch (_) { return {}; }
  })();
  const L = (en, vars) => Object.entries(vars || {}).reduce(
    (text, [k, v]) => text.split('{' + k + '}').join(v), WORDS[en] || en);
  const BASE = document.documentElement.dataset.base || '';
  const page = document.querySelector('.scan-page');
  const rows = [...document.querySelectorAll('.scan-step')];
  const completed = new Set();
  const params = new URLSearchParams({url:page.dataset.url});
  if (page.dataset.render === 'true') params.set('render', 'true');
  let finished = false;
  let lastEvent = Date.now();
  const source = new EventSource(BASE + '/api/scan?' + params);
  function stop() {
    finished = true; source.close(); clearInterval(watchdog);
  }
  function fail(message, detail) {
    if (finished) return;
    stop();
    document.title = L('Phishing Detector | Interrupted');
    document.getElementById('scan-live').hidden = true;
    document.getElementById('scan-recovery').hidden = false;
    document.getElementById('scan-title').textContent = L('The check was interrupted');
    document.getElementById('scan-lede').textContent = L('There is no completed result from this attempt.');
    document.querySelector('.scan-panel .status-label').textContent = L('Interrupted');
    document.getElementById('recovery-message').textContent = message;
    /* When the service says why it stopped, say that instead of a paraphrase.
       Run locally, the person reading it is the one who can act on
       "set PHISHING_DETECTOR_NO_STORE=1", and a generic failure message sends
       them looking for a fault that is not there. */
    const explain = document.getElementById('recovery-detail');
    if (detail) { explain.textContent = detail; explain.hidden = false; }
    /* What did and did not finish before it stopped is the useful part of an
       interrupted check, so it is opened rather than left behind a summary. */
    document.querySelector('.scan-sources').open = true;
    const failedParams = new URLSearchParams(params); failedParams.set('failed', 'true');
    history.replaceState(null, '', BASE + '/scan?' + failedParams);
    rows.filter(r => !completed.has(r.dataset.name)).forEach(r => { r.querySelector('.step-detail').textContent = L('Not completed'); });
  }
  const watchdog = setInterval(() => {
    if (Date.now() - lastEvent > 90000) fail(L('No progress update arrived for 90 seconds. Try again in a moment.'));
  }, 5000);
  source.onmessage = event => {
    lastEvent = Date.now();
    let message;
    try { message = JSON.parse(event.data); } catch (_) { fail(L('The service sent an unreadable progress update. Try again.')); return; }
    if (message.type === 'collector') {
      const row = rows.find(r => r.dataset.name === message.name);
      if (!row) return;
      completed.add(message.name);
      const label = L({ok:'Returned data', failed:'Failed', timeout:'Timed out', skipped:'Skipped'}[message.status] || 'Finished');
      row.querySelector('.step-detail').textContent = message.detail ? L('{label}: {detail}', {label, detail: message.detail}) : label;
      row.dataset.status = message.status;
      document.getElementById('bar').style.width = (completed.size / rows.length * 100) + '%';
      document.querySelector('[role="progressbar"]').setAttribute('aria-valuenow', completed.size);
      document.getElementById('headline').textContent = L('{done} of {total} checks finished', {done: completed.size, total: rows.length});
      document.getElementById('activity-count').textContent = L('{done} finished', {done: completed.size});
      document.getElementById('scan-current').textContent = L('{label}: {detail}', {label: row.firstElementChild.textContent, detail: label.toLowerCase()});
    } else if (message.type === 'done') {
      stop();
      document.getElementById('headline').textContent = L('Evidence gathered. Preparing your result...');
      const resultParams = new URLSearchParams(params);
      if (message.token) resultParams.set('t', message.token);
      /* replace, not assign: this page starts a scan the moment it loads, so
         leaving it in the history would make the back button run another. */
      location.replace(BASE + '/result?' + resultParams);
    } else if (message.type === 'error') {
      fail(L('The checker stopped before it could finish this address.'), message.detail);
    }
  };
  /* Leaving the page drops the stream, and the browser reports that as an
     error before `pagehide`: the Back button flashed "The check was
     interrupted" and rewrote this history entry to the failed state on the
     way out. An error is only reported if the page is still here a moment
     later. */
  let leaving = false;
  window.addEventListener('beforeunload', () => { leaving = true; });
  source.onerror = () => setTimeout(() => {
    if (!leaving) fail(L('The connection to the checker was lost. Try again in a moment.'));
  }, 300);
  window.addEventListener('pagehide', () => { leaving = true; source.close(); clearInterval(watchdog); });
  /* Restored from the back-forward cache, the stream closed above is gone and
     the progress shown is frozen where it was left. */
  window.addEventListener('pageshow', event => {
    if (!event.persisted || finished) return;
    leaving = false;
    fail(L('The check stopped when you left this page. Check the link again to see a result.'));
  });
})();
