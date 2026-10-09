(() => {
  /* The same reading of a paste as the server's `_one_address`: the address
     is the first token that looks like one; a following piece joins it only
     where a wrapped link's line could have broken; plain words around it are
     a sentence and are dropped; a second address is refused. Shared with the
     front page's address breakdown, which joined every space and so marked
     "secure-login.xyzsafe" as the site in "Is paypal.com.secure-login.xyz
     safe?". Returns {address, several}. */
  const lead = '(<["\'\u201c\u2018', tail = '.,;:!?>]"\'\u201d\u2019';
  const trim = t => {
    while (t && lead.includes(t[0])) t = t.slice(1);
    for (;;) {
      if (t && tail.includes(t.slice(-1))) t = t.slice(0, -1);
      else if (t.endsWith(')') && t.split(')').length > t.split('(').length) t = t.slice(0, -1);
      else return t;
    }
  };
  const isAddress = t => {
    t = trim(t);
    return /^https?:\/\//i.test(t) ||
      /^(?:(?:[^\s\/@:.]+\.)+(?:[\p{L}\p{M}]{2,}|xn--[a-z0-9-]+)\.?|\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?(?:[\/?#]\S*)?$/iu.test(t);
  };
  const isWord = t => /^[("'\u201c\u2018]*[\p{L}\p{M}]+(?:['\u2019-][\p{L}\p{M}]+)*[.,!?;:)"'\u201d\u2019]*$/u.test(t);
  function readPaste(value) {
    const tokens = value.split(/\s+/).filter(Boolean);
    const first = tokens.findIndex(isAddress);
    if (first < 0) return {address: tokens.join(''), several: false};
    let address = tokens[first];
    while (address && lead.includes(address[0])) address = address.slice(1);
    const rest = tokens.slice(first + 1);
    while (rest.length) {
      const next = rest[0];
      if (/^https?:\/{0,2}$/i.test(address) || /[?&=#%+\-_~]$/.test(address) ||
          /^[\/?&=#.%\-_]/.test(next) || !(isWord(next) || isAddress(next))) {
        address += rest.shift();
      } else break;
    }
    if (rest.some(isAddress)) return {address: tokens.join(''), several: true};
    return {address: (rest.length || first || lead.includes(tokens[first][0])) ? trim(address) : address,
            several: false};
  }
  window.readPaste = readPaste;

  document.querySelectorAll('form.check').forEach(form => {
    const input = form.querySelector('.check__input');
    const error = form.querySelector('.field-error');
    input.addEventListener('input', () => { error.hidden = true; input.removeAttribute('aria-invalid'); });
    const refuse = (event, message) => {
      event.preventDefault();
      error.textContent = message;
      error.hidden = false;
      input.setAttribute('aria-invalid', 'true'); input.focus();
    };
    form.addEventListener('submit', event => {
      const reading = readPaste(input.value);
      if (reading.several) {
        refuse(event, 'That looks like more than one address. Paste one at a time.');
        return;
      }
      const raw = reading.address;
      let valid = false;
      /* The server's list (urls.HOSTLESS_SCHEMES): without "://" these would
         be read as http://mailto:a@b.com -- user "mailto:a" on host b.com. */
      const hostless = /^(data|javascript|vbscript|mailto|tel|sms|about|blob):/i.test(raw);
      try {
        if (hostless) throw new Error('not a web address');
        const url = new URL(raw.includes('://') ? raw : 'http://' + raw);
        valid = ['http:', 'https:'].includes(url.protocol) &&
          (url.hostname.includes('.') || url.hostname.includes(':') || url.hostname === 'localhost') && url.port !== '0';
      } catch (_) { /* The field shows the reason below. */ }
      /* The server refuses anything longer (MAX_SUBMITTED_URL) rather than
         checking a truncated address; saying so here saves the round trip. */
      const tooLong = raw.length > 2000;
      if (tooLong) {
        refuse(event, 'That address is too long to check. Addresses of up to 2000 characters can be checked.');
        return;
      }
      if (!valid) {
        refuse(event, raw ? 'Enter a web address, such as example.com. Only HTTP and HTTPS links can be checked.'
          : 'Paste a link to check.');
        return;
      }
      /* The box is updated, so what is checked is what is shown. */
      if (input.value.trim() !== raw) input.value = raw;
    });
  });
})();
