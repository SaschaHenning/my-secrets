// Shared front-end helpers, loaded on every page via _head.html.
//
// Copy actions use event delegation on document, so any button with a
// data-copy-username or data-copy-password attribute works on any page
// (entries table, entry detail, start-page recent list) without
// per-page wiring. Nothing here is a security control — the reveal is
// gated server-side by the login session; these buttons only move an
// already-authorised value to the clipboard.

(function () {
  function flash(btn, symbol) {
    var orig = btn.dataset.label || btn.textContent;
    btn.dataset.label = orig;
    btn.textContent = symbol;
    btn.disabled = true;
    setTimeout(function () {
      btn.textContent = orig;
      btn.disabled = false;
    }, 1200);
  }

  function copyText(btn, text) {
    if (!text) return;
    navigator.clipboard.writeText(text).then(function () { flash(btn, '✅'); });
  }

  function copyPassword(btn, path) {
    // POSTs to the reveal endpoint with Accept: application/json. The
    // server re-checks policy and logs a `get` audit row, same as
    // `mys get --reveal`; the login session is the only gate.
    fetch('/entries/' + path, {
      method: 'POST',
      headers: { 'Accept': 'application/json' },
    }).then(function (res) {
      if (!res.ok) throw new Error('reveal failed');
      return res.json();
    }).then(function (data) {
      return navigator.clipboard.writeText(data.password);
    }).then(function () {
      flash(btn, '✅');
    }).catch(function () {
      flash(btn, '❌');
    });
  }

  document.addEventListener('click', function (e) {
    var pw = e.target.closest('[data-copy-password]');
    if (pw) {
      e.preventDefault();
      copyPassword(pw, pw.getAttribute('data-copy-password'));
      return;
    }
    var user = e.target.closest('[data-copy-username]');
    if (user) {
      e.preventDefault();
      copyText(user, user.getAttribute('data-copy-username'));
      return;
    }
  });
})();
