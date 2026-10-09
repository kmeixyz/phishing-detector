/* Result controls only read the rendered record. Collected content stays text. */
(() => {
  const report = document.getElementById('report');
  /* The saved-result page has no report when the entry is gone. */
  if (!report) return;
  const status = document.getElementById('report-status');
  const announce = text => { status.textContent = text; };
  const tabs = [...report.querySelectorAll('.record-nav [role="tab"]')];
  function selectTab(tab, focus = false) {
    tabs.forEach(other => {
      const selected = other === tab;
      other.setAttribute('aria-selected', String(selected));
      other.tabIndex = selected ? 0 : -1;
      document.getElementById(other.getAttribute('aria-controls')).hidden = !selected;
    });
    if (focus) tab.focus({preventScroll: true});
  }
  tabs.forEach((tab, index) => {
    tab.addEventListener('click', () => selectTab(tab));
    tab.addEventListener('keydown', event => {
      let next;
      if (event.key === 'ArrowRight') next = (index + 1) % tabs.length;
      else if (event.key === 'ArrowLeft') next = (index + tabs.length - 1) % tabs.length;
      else if (event.key === 'Home') next = 0;
      else if (event.key === 'End') next = tabs.length - 1;
      else return;
      event.preventDefault();
      selectTab(tabs[next], true);
    });
  });
  async function copy(text, message) {
    try {
      await navigator.clipboard.writeText(text);
      announce(message);
    } catch (_) {
      announce('Copy was unavailable. Select the text you need and copy it manually.');
    }
  }
  document.querySelectorAll('[data-copy]').forEach(button => {
    button.addEventListener('click', () => copy(document.getElementById(button.dataset.copy).textContent.trim(), 'Copied.'));
  });
  const rows = [...document.querySelectorAll('.source-record')];
  const filter = document.getElementById('source-filter');
  function filterSources() {
    rows.forEach(row => {
      row.hidden = filter.value !== 'all' && !(filter.value === 'failed'
        ? ['failed', 'timeout'].includes(row.dataset.status) : row.dataset.status === filter.value);
    });
    document.getElementById('source-count').textContent = rows.filter(row => !row.hidden).length + ' of ' + rows.length + ' sources shown';
  }
  filter.addEventListener('change', filterSources);
  filterSources();
  document.getElementById('sources-expand').addEventListener('click', () => rows.filter(r => !r.hidden).forEach(r => { r.open = true; }));
  document.getElementById('sources-collapse').addEventListener('click', () => rows.forEach(r => { r.open = false; }));

  /* Match the FAQ accordion exactly: content is uncovered by an animated clip,
     interrupted motion resumes proportionally, and only one peer at a nested
     level stays open. Parents remain open when one of their children changes. */
  const folds = [...report.querySelectorAll('details')];
  const still = matchMedia('(prefers-reduced-motion: reduce)');
  const span = parseFloat(getComputedStyle(folds[0]).getPropertyValue('--qa-open')) || 200;
  const ease = getComputedStyle(document.documentElement).getPropertyValue('--ease').trim() || 'ease-out';
  // Like .qa__reveal around .qa__body, the clip has no padding or grid layout.
  // Its contents keep their natural size throughout both directions of motion.
  folds.forEach(fold => {
    const body = fold.querySelector(':scope > .fold-content, :scope > .value-fold__reveal');
    if (!body) return;
    const clip = document.createElement('div');
    clip.className = 'record-fold__reveal';
    body.before(clip);
    clip.append(body);
  });
  const revealFor = fold => fold.querySelector(':scope > .record-fold__reveal');
  const isOpen = fold => fold.open && !fold.classList.contains('record-fold--shutting');

  function slide(fold, open) {
    const box = revealFor(fold);
    if (!box) { fold.open = open; return; }
    const from = fold.open ? box.getBoundingClientRect().height : 0;
    if (fold._slide) { fold._slide.cancel(); fold._slide = null; }
    if (still.matches) {
      fold.classList.remove('record-fold--shutting');
      fold.open = open;
      return;
    }
    fold.open = true;
    fold.classList.toggle('record-fold--shutting', !open);
    const full = box.scrollHeight;
    const to = open ? full : 0;
    const ms = full ? span * Math.abs(to - from) / full : 0;
    const anim = box.animate(
      [{height: from + 'px'}, {height: to + 'px'}],
      {duration: ms, easing: ease, fill: 'forwards'}
    );
    fold._slide = anim;
    anim.onfinish = () => {
      fold.classList.remove('record-fold--shutting');
      fold.open = open;
      anim.cancel();
      fold._slide = null;
    };
  }

  folds.forEach(fold => {
    fold.querySelector(':scope > summary').addEventListener('click', event => {
      event.preventDefault();
      if (isOpen(fold)) { slide(fold, false); return; }
      [...fold.parentElement.children].forEach(peer => {
        if (peer !== fold && peer.tagName === 'DETAILS' && isOpen(peer)) slide(peer, false);
      });
      slide(fold, true);
    });
  });

  function revealHash(smooth = false) {
    let target;
    try { target = document.getElementById(decodeURIComponent(location.hash.slice(1))); } catch (_) { return; }
    if (!target) return;
    const panel = target.closest('.record-tab-panel');
    if (panel) selectTab(tabs.find(tab => tab.getAttribute('aria-controls') === panel.id));
    if (target.classList.contains('source-record')) { filter.value = 'all'; filterSources(); }
    let parent = target;
    while (parent && parent !== report) {
      if (parent.tagName === 'DETAILS') parent.open = true;
      parent = parent.parentElement;
    }
    if (target.id === 'feedback' || target.id === 'opened-link') target.querySelector('details').open = true;
    requestAnimationFrame(() => {
      target.scrollIntoView({
        behavior: smooth && !still.matches ? 'smooth' : 'auto',
        block: 'start'
      });
      const focus = target.tagName === 'DETAILS' ? target.querySelector('summary') : target;
      if (!focus.hasAttribute('tabindex')) focus.setAttribute('tabindex', '-1');
      focus.focus({preventScroll: true});
    });
  }
  window.addEventListener('hashchange', revealHash);
  document.querySelectorAll('a[href]').forEach(a => a.addEventListener('click', event => {
    if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey ||
        event.shiftKey || event.altKey || a.target === '_blank') return;
    const destination = new URL(a.href, location.href);
    if (!destination.hash || destination.origin !== location.origin ||
        destination.pathname !== location.pathname || destination.search !== location.search) return;
    event.preventDefault();
    if (destination.hash !== location.hash) history.pushState(null, '', destination.hash);
    revealHash(true);
  }));
  revealHash();
  /* Absent on an instance that collects no corrections. */
  const feedbackCancel = document.getElementById('feedback-cancel');
  if (feedbackCancel) feedbackCancel.addEventListener('click', () => {
    const details = document.querySelector('#feedback > details');
    details.open = false;
    details.querySelector('summary').focus();
  });

  document.getElementById('download-report').addEventListener('click', async event => {
    const button = event.currentTarget;
    button.disabled = true;
    announce('Preparing the complete report...');
    try {
      const styles = await Promise.all([...document.querySelectorAll('link[rel="stylesheet"]')].map(async link => {
        const response = await fetch(link.href);
        if (!response.ok) throw new Error('Styles unavailable');
        return response.text();
      }));
      const doc = document.implementation.createHTMLDocument('Link assessment');
      const charset = doc.createElement('meta'); charset.setAttribute('charset', 'utf-8'); doc.head.append(charset);
      const viewport = doc.createElement('meta'); viewport.name = 'viewport'; viewport.content = 'width=device-width, initial-scale=1'; doc.head.append(viewport);
      const style = doc.createElement('style'); style.textContent = styles.join('\n'); doc.head.append(style);
      const clone = report.cloneNode(true);
      clone.querySelectorAll('.no-export, script').forEach(el => el.remove());
      clone.querySelectorAll('[hidden]').forEach(el => { el.hidden = false; });
      clone.querySelectorAll('details').forEach(el => { el.open = true; });
      clone.querySelectorAll('.record-tab-panel').forEach(panel => {
        panel.removeAttribute('role');
        panel.removeAttribute('tabindex');
        panel.setAttribute('aria-labelledby', 'heading-' + panel.id);
      });
      // A saved report has no service endpoints or executable page content.
      // `a[href]`, not `a`: an anchor without one made getAttribute return null,
      // and the TypeError sent every download to "could not be prepared".
      clone.querySelectorAll('a[href]').forEach(a => { if (!a.getAttribute('href').startsWith('#')) a.removeAttribute('href'); });
      doc.body.append(clone);
      const note = doc.createElement('p'); note.className = 'wrap export-note';
      note.textContent = 'This report includes the full submitted link and collected evidence. Review it before sharing.';
      doc.body.prepend(note);
      const blob = new Blob(['<!doctype html>\n' + doc.documentElement.outerHTML], {type:'text/html;charset=utf-8'});
      const href = URL.createObjectURL(blob);
      const a = document.createElement('a'); a.href = href; a.download = 'link-assessment.html'; a.click();
      setTimeout(() => URL.revokeObjectURL(href), 30000);
      announce('Report downloaded. It includes the full link and evidence; review it before sharing.');
    } catch (_) { announce('The report could not be prepared. Try again.'); }
    finally { button.disabled = false; }
  });
  // Print all information without changing what the reader had open afterwards.
  let printState;
  window.addEventListener('beforeprint', () => {
    printState = [...report.querySelectorAll('details, [hidden]')].map(el => [el, el.open, el.hidden]);
    printState.forEach(([el]) => { if (el.tagName === 'DETAILS') el.open = true; el.hidden = false; });
  });
  window.addEventListener('afterprint', () => printState?.forEach(([el, open, hidden]) => { if (el.tagName === 'DETAILS') el.open = open; el.hidden = hidden; }));
})();
