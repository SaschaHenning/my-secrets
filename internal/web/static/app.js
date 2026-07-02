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

// Keyboard-first navigation of the entries table: find a password with
// zero mouse. Active only on /entries (gated on #search), so the start
// page's form-wrapped search box keeps its plain Enter → /entries?q=
// submit. Reuses the existing copy buttons via .click(), so reveal stays
// exactly the session-only, audited path — no second auth route.
//
//   ↓ / ↑        move the highlighted row through the visible (filtered) rows
//   Enter        copy the active row's password (or the top match if none active)
//   Shift+Enter  open the active row's detail page
//   Alt+Enter    copy the active row's username instead of the password
(function () {
  if (!document.getElementById('search')) return; // entries page only

  var activeRow = null;

  function visibleRows() {
    return Array.prototype.filter.call(
      document.querySelectorAll('.entry-row'),
      function (r) {
        if (r.style.display === 'none') return false;
        var group = r.closest('.org-group');
        return !(group && group.style.display === 'none');
      }
    );
  }

  function setActive(row) {
    if (activeRow) activeRow.classList.remove('active');
    activeRow = row || null;
    if (activeRow) {
      activeRow.classList.add('active');
      activeRow.scrollIntoView({ block: 'nearest' });
    }
  }

  function move(delta) {
    var list = visibleRows();
    if (!list.length) { setActive(null); return; }
    var idx = activeRow ? list.indexOf(activeRow) : -1;
    if (idx < 0) {
      setActive(list[delta > 0 ? 0 : list.length - 1]);
      return;
    }
    setActive(list[Math.max(0, Math.min(list.length - 1, idx + delta))]);
  }

  // Target row for an action: the active one if still visible, else the
  // top match — so "type, Enter" copies the first result without arrowing.
  function target() {
    var list = visibleRows();
    if (!list.length) return null;
    if (activeRow && list.indexOf(activeRow) !== -1) return activeRow;
    return list[0];
  }

  function clickIn(row, selector) {
    if (!row) return;
    var btn = row.querySelector(selector);
    if (btn && !btn.disabled) btn.click();
  }

  function openRow(row) {
    if (!row) return;
    var link = row.querySelector('a[href^="/entries/"]');
    if (link) window.location.assign(link.getAttribute('href'));
  }

  document.addEventListener('keydown', function (e) {
    if (e.key === 'ArrowDown') { e.preventDefault(); move(1); return; }
    if (e.key === 'ArrowUp') { e.preventDefault(); move(-1); return; }
    if (e.key !== 'Enter') return;
    var row = target();
    if (!row) return;
    e.preventDefault();
    if (e.altKey) clickIn(row, '[data-copy-username]');
    else if (e.shiftKey) openRow(row);
    else clickIn(row, '[data-copy-password]');
  });

  // A changed filter can hide the active row — drop the highlight so the
  // next Enter targets the new top match.
  document.getElementById('search').addEventListener('input', function () {
    if (activeRow && visibleRows().indexOf(activeRow) === -1) setActive(null);
  });
})();
