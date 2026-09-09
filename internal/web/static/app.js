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

// Publish the header's real height as --header-h so the sticky search bar
// sits flush under it at any width. CSS cannot read it, and a fixed value
// drifts the moment the header wraps on a narrow screen.
(function () {
  var header = document.querySelector('header');
  if (!header) return;
  function publish() {
    document.documentElement.style.setProperty('--header-h', header.offsetHeight + 'px');
  }
  publish();
  if (window.ResizeObserver) new ResizeObserver(publish).observe(header);
  else window.addEventListener('resize', publish);
})();

// "/" focuses the page's search box from anywhere. Ignored while typing
// in a field, so a slash inside a query still reaches the input.
(function () {
  var box = document.getElementById('search') || document.getElementById('home-search');
  if (!box) return;
  document.addEventListener('keydown', function (e) {
    if (e.key !== '/' || e.metaKey || e.ctrlKey || e.altKey) return;
    var el = document.activeElement;
    if (el && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.isContentEditable)) return;
    e.preventDefault();
    box.focus();
    box.select();
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
  var searchEl = document.getElementById('search');
  if (!searchEl) return; // entries page only

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

  // Clear the filter, re-show every row, drop the highlight, and put the
  // cursor back in the search box for the next query.
  function resetSearch() {
    searchEl.value = '';
    searchEl.dispatchEvent(new Event('input', { bubbles: true }));
    setActive(null);
    searchEl.focus();
  }

  document.addEventListener('keydown', function (e) {
    // Escape resets the search and clears the selection — handled before
    // the focus guard below so it works even when a copy button is
    // focused (Esc has no native action on those anyway).
    if (e.key === 'Escape') {
      if (searchEl.value === '' && !activeRow) return; // nothing to reset
      e.preventDefault();
      resetSearch();
      return;
    }
    // Don't hijack keys aimed at a focused link or button (e.g. after
    // Tab): let them activate natively, so Enter opens the focused row's
    // link / triggers its own button instead of the active row's. The
    // search input isn't an a/button, so the type→↓→Enter flow is
    // unaffected (arrows keep focus in #search).
    if (e.target.closest('a, button')) return;
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
  searchEl.addEventListener('input', function () {
    if (activeRow && visibleRows().indexOf(activeRow) === -1) setActive(null);
  });
})();

// Escape on an entry detail page (/entries/<path>) backs out to the list.
// If you got here by clicking a row, the previous history entry is the
// (filtered) list, so history.back() restores it with your search intact.
// Otherwise — a bookmark/deep link, or a login round-trip that leaves
// /login as the previous history entry — go straight to /entries, so Esc
// never strands you on the login form. Gated on the referrer being inside
// the entries section rather than history.length, which a login redirect
// inflates. The list page (/entries, no trailing path) is handled by the
// keyboard IIFE above, so it's excluded here.
(function () {
  if (location.pathname.indexOf('/entries/') !== 0) return;
  var cameFromEntries =
    document.referrer.indexOf(window.location.origin + '/entries') === 0;
  document.addEventListener('keydown', function (e) {
    if (e.key !== 'Escape') return;
    e.preventDefault();
    if (cameFromEntries && window.history.length > 1) window.history.back();
    else window.location.assign('/entries');
  });
})();
