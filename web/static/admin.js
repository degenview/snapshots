'use strict';
(() => {
  const app = document.getElementById('app');
  let csrf = '';
  let view = 'overview';

  // --- tiny DOM helper: text is always set via textContent, never HTML -------
  function h(tag, attrs, ...kids) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === false || v == null) continue;
      if (k === 'class') el.className = v;
      else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
      else if (k === 'value') el.value = v;
      else if (k === 'checked') el.checked = !!v;
      else el.setAttribute(k, v === true ? '' : v);
    }
    for (const kid of kids.flat()) if (kid != null && kid !== false) el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
    return el;
  }

  async function api(method, path, body) {
    const opts = { method, credentials: 'same-origin', headers: {} };
    if (method !== 'GET') opts.headers['X-CSRF-Token'] = csrf;
    if (body !== undefined) { opts.headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(body); }
    const res = await fetch('/admin/api' + path, opts);
    if (res.status === 401 && path !== '/login') { renderLogin(); throw new Error('Signed out'); }
    if (res.status === 204) return null;
    let data = null;
    try { data = await res.json(); } catch (_) { /* empty */ }
    if (!res.ok) throw new Error((data && data.error && data.error.message) || `Request failed (${res.status})`);
    return data;
  }

  function toast(msg) {
    const t = h('div', { class: 'toast', role: 'status' }, msg);
    document.body.append(t); setTimeout(() => t.remove(), 2200);
  }
  const fail = (e) => { if (e.message !== 'Signed out') toast(e.message); };
  const fmtBytes = (n) => n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KiB` : n < 1073741824 ? `${(n / 1048576).toFixed(1)} MiB` : `${(n / 1073741824).toFixed(2)} GiB`;
  const fmtDate = (s) => s ? new Date(s).toLocaleString() : '—';
  const copy = async (text) => { await navigator.clipboard.writeText(text); toast('Copied'); };

  // --- login --------------------------------------------------------------------
  function renderLogin() {
    const err = h('p', { class: 'notice error', hidden: true, role: 'alert' });
    const pw = h('input', { type: 'password', autocomplete: 'current-password', autofocus: true });
    const submit = async (ev) => {
      ev.preventDefault();
      try {
        const r = await api('POST', '/login', { password: pw.value });
        csrf = r.csrf; pw.value = ''; render();
      } catch (e) { err.textContent = e.message; err.hidden = false; }
    };
    app.replaceChildren(h('main', { class: 'login center' },
      h('div', { class: 'logo', 'aria-hidden': 'true' }), h('h1', {}, 'Sign in'),
      h('form', { class: 'card', onsubmit: submit }, err, h('label', {}, 'Administrator password', pw),
        h('div', { class: 'actions' }, h('button', { class: 'btn primary', type: 'submit' }, 'Sign in')))));
    pw.focus();
  }

  // --- shell --------------------------------------------------------------------
  const views = { overview: () => renderOverview(), images: () => renderImages(0), tokens: () => renderTokens(), settings: () => renderSettings() };

  function shell(body) {
    const nav = h('nav', {}, ...Object.keys(views).map((k) =>
      h('button', { 'aria-current': k === view ? 'page' : false, onclick: () => { view = k; render(); } }, k[0].toUpperCase() + k.slice(1))));
    app.replaceChildren(
      h('div', { class: 'topbar' }, h('div', { class: 'brand' }, h('div', { class: 'logo', 'aria-hidden': 'true' }), 'Snapshots'), nav,
        h('button', { class: 'btn small', onclick: async () => { await api('POST', '/logout').catch(() => {}); csrf = ''; renderLogin(); } }, 'Sign out')),
      body);
  }

  async function render() {
    try { await views[view](); } catch (e) { fail(e); }
  }

  // --- overview -----------------------------------------------------------------
  async function renderOverview() {
    const o = await api('GET', '/overview');
    const stat = (v, l) => h('div', { class: 'stat' }, h('b', {}, v), h('span', {}, l));
    shell(h('div', {},
      h('div', { class: 'stats' },
        stat(o.images, 'images'), stat(fmtBytes(o.bytes), o.max_total_bytes ? `used of ${fmtBytes(o.max_total_bytes)}` : 'used'),
        stat(o.tokens, 'upload tokens'), stat(o.retention_days ? `${o.retention_days} days` : 'forever', 'kept')),
      h('div', { class: 'card' }, h('h2', {}, 'Connect DegenView'),
        h('p', { class: 'muted' }, 'Open Settings ▸ Snapshots and enter this host address', o.auth_required ? ' and one of your tokens:' : ':'),
        h('p', {}, h('code', {}, o.upload_url), ' ', h('button', { class: 'btn small', onclick: () => copy(o.upload_url) }, 'Copy')),
        o.auth_required ? h('p', { class: 'muted' }, 'Create a token under ', h('a', { href: '#', onclick: (e) => { e.preventDefault(); view = 'tokens'; render(); } }, 'Tokens'), '.')
          : h('p', { class: 'notice warn' }, 'Uploads are open to anyone: no token is required. Turn that on under Settings.')),
      h('p', { class: 'muted' }, `Version ${o.version} · storage: ${o.storage_kind}`)));
  }

  // --- images -------------------------------------------------------------------
  async function renderImages(page = 0) {
    const r = await api('GET', `/images?page=${page}`);
    const tiles = r.images.map((i) => h('div', { class: 'tile' },
      h('a', { class: 'thumb', href: `/i/${i.id}`, target: '_blank', rel: 'noopener' }, h('img', { src: `/i/${i.id}`, alt: '', loading: 'lazy' })),
      h('div', { class: 'meta' },
        h('span', {}, `${i.width}×${i.height} · ${fmtBytes(i.size)}`),
        h('span', {}, `Uploaded ${fmtDate(i.created_at)}`),
        h('span', {}, i.expires_at ? `Expires ${fmtDate(i.expires_at)}` : 'Never expires'),
        i.token ? h('span', {}, `Token: ${i.token}`) : null,
        h('div', { class: 'btns' },
          h('button', { class: 'btn small', onclick: () => copy(i.url) }, 'Copy link'),
          h('button', { class: 'btn small danger', onclick: async () => {
            if (!confirm('Delete this image? Its link stops working.')) return;
            try { await api('DELETE', `/images/${i.id}`); toast('Deleted'); renderImages(page); } catch (e) { fail(e); }
          } }, 'Delete')))));
    shell(h('div', {},
      r.images.length ? h('div', { class: 'grid' }, tiles) : h('p', { class: 'empty' }, 'No images yet.'),
      h('div', { class: 'actions' },
        page > 0 ? h('button', { class: 'btn', onclick: () => renderImages(page - 1) }, 'Newer') : null,
        r.has_more ? h('button', { class: 'btn', onclick: () => renderImages(page + 1) }, 'Older') : null)));
  }

  // --- tokens -------------------------------------------------------------------
  // `fresh` is a just-created token, shown once above the list.
  async function renderTokens(fresh) {
    const { tokens } = await api('GET', '/tokens');
    const name = h('input', { placeholder: 'e.g. Laptop', autocomplete: 'off', maxlength: 60 });
    const rows = tokens.map((t) => h('tr', {},
      h('td', {}, t.name), h('td', {}, fmtDate(t.created_at)), h('td', {}, t.last_used_at ? fmtDate(t.last_used_at) : 'never'),
      h('td', {}, h('button', { class: 'btn small danger', onclick: async () => {
        if (!confirm(`Revoke "${t.name}"? Anything using it stops working.`)) return;
        try { await api('DELETE', `/tokens/${t.id}`); renderTokens(); } catch (e) { fail(e); }
      } }, 'Revoke'))));
    shell(h('div', {},
      fresh ? h('div', { class: 'notice ok' }, h('p', {}, 'Token created. Copy it now: it is not shown again.'),
        h('p', {}, h('code', {}, fresh), ' ', h('button', { class: 'btn small', type: 'button', onclick: () => copy(fresh) }, 'Copy'))) : null,
      h('form', { class: 'card', onsubmit: async (ev) => {
        ev.preventDefault();
        try { const r = await api('POST', '/tokens', { name: name.value }); renderTokens(r.token); } catch (e) { fail(e); }
      } }, h('h2', {}, 'New upload token'), h('label', {}, 'Name', name),
        h('div', { class: 'actions' }, h('button', { class: 'btn primary', type: 'submit' }, 'Create token'))),
      rows.length ? h('table', {}, h('thead', {}, h('tr', {}, h('th', {}, 'Name'), h('th', {}, 'Created'), h('th', {}, 'Last used'), h('th', {}))), h('tbody', {}, rows))
        : h('p', { class: 'empty' }, 'No tokens yet.')));
  }

  // --- settings -----------------------------------------------------------------
  async function renderSettings() {
    const s = await api('GET', '/settings');
    const f = {};
    const field = (key, label, attrs = {}) => { f[key] = h('input', { autocomplete: 'off', spellcheck: 'false', ...attrs }); return h('label', {}, label, f[key]); };
    const retention = h('select', {}, ...[[1, '1 day'], [7, '7 days'], [30, '30 days'], [90, '90 days'], [365, '1 year'], [0, 'Never']]
      .map(([v, l]) => h('option', { value: v, selected: v === s.retention_days }, l)));
    const kind = h('select', {}, h('option', { value: 'local', selected: s.storage_kind === 'local' }, 'Local disk'), h('option', { value: 's3', selected: s.storage_kind === 's3' }, 'S3-compatible bucket'));
    const auth = h('input', { type: 'checkbox', checked: s.auth_required });
    const path = h('input', { type: 'checkbox', checked: s.s3.path_style });
    const out = h('p', { class: 'notice', hidden: true });
    const s3box = h('div', {},
      field('endpoint', 'Endpoint', { value: s.s3.endpoint, placeholder: 'https://nyc3.digitaloceanspaces.com' }),
      h('div', { class: 'row' }, field('region', 'Region', { value: s.s3.region }), field('bucket', 'Bucket', { value: s.s3.bucket })),
      h('div', { class: 'row' }, field('access', 'Access key ID', { value: s.s3.access_key }),
        field('secret', 'Secret access key', { type: 'password', placeholder: s.s3_secret_set ? '•••••••• (unchanged)' : '', autocomplete: 'new-password' })),
      field('prefix', 'Key prefix', { value: s.s3.prefix }), h('label', { class: 'check' }, path, 'Path-style addressing'),
      s.can_seal_secret ? null : h('p', { class: 'notice warn' }, 'Set SECRET_KEY to store a bucket secret.'));
    const syncKind = () => { s3box.hidden = kind.value !== 's3'; };
    kind.addEventListener('change', syncKind); syncKind();

    const body = () => ({
      public_url: f.url.value.trim(), auth_required: auth.checked, retention_days: Number(retention.value),
      max_image_bytes: Math.round(Number(f.maxImage.value) * 1048576), max_total_bytes: Math.round(Number(f.quota.value) * 1073741824),
      uploads_per_hour: Number(f.uploads.value), views_per_minute: Number(f.views.value), storage_kind: kind.value,
      s3: { endpoint: f.endpoint.value, region: f.region.value, bucket: f.bucket.value, access_key: f.access.value, secret_key: f.secret.value, path_style: path.checked, prefix: f.prefix.value },
    });
    const say = (cls, msg) => { out.className = `notice ${cls}`; out.textContent = msg; out.hidden = false; };

    shell(h('form', { onsubmit: async (ev) => {
      ev.preventDefault();
      try { await api('PUT', '/settings', body()); toast('Settings saved'); renderSettings(); } catch (e) { say('error', e.message); }
    } },
      h('div', { class: 'card' }, h('h2', {}, 'General'),
        field('url', 'Public address', { value: s.public_url }),
        h('label', {}, 'Delete images after', retention, h('small', {}, 'Applies to images uploaded from now on.')),
        h('label', { class: 'check' }, auth, 'Require an upload token'),
        h('div', { class: 'row' }, field('maxImage', 'Largest image (MiB)', { type: 'number', min: 1, max: 64, value: Math.round(s.max_image_bytes / 1048576) }),
          field('quota', 'Storage quota (GiB, 0 = none)', { type: 'number', min: 0, value: +(s.max_total_bytes / 1073741824).toFixed(2) })),
        h('div', { class: 'row' }, field('uploads', 'Uploads per hour, per IP', { type: 'number', min: 1, value: s.uploads_per_hour }),
          field('views', 'Image views per minute, per IP', { type: 'number', min: 1, value: s.views_per_minute }))),
      h('div', { class: 'card' }, h('h2', {}, 'Storage'),
        s.storage_images > 0 ? h('p', { class: 'muted' }, `${s.storage_images} image${s.storage_images === 1 ? ' is' : 's are'} stored here, so the location cannot change until ${s.storage_images === 1 ? 'it is' : 'they are'} gone.`) : null,
        h('label', {}, 'Store images on', kind), s3box,
        h('div', { class: 'actions' }, h('button', { class: 'btn', type: 'button', onclick: async () => {
          say('', 'Testing…');
          try { const r = await api('POST', '/settings/test-storage', body()); r.ok ? say('ok', 'Storage works.') : say('error', r.error); } catch (e) { say('error', e.message); }
        } }, 'Test storage'))),
      out, h('div', { class: 'actions' }, h('button', { class: 'btn primary', type: 'submit' }, 'Save settings')),
      passwordCard()));
  }

  function passwordCard() {
    const cur = h('input', { type: 'password', autocomplete: 'current-password' });
    const next = h('input', { type: 'password', autocomplete: 'new-password' });
    return h('div', { class: 'card' }, h('h2', {}, 'Change password'),
      h('label', {}, 'Current password', cur), h('label', {}, 'New password (12+ characters)', next),
      h('div', { class: 'actions' }, h('button', { class: 'btn', type: 'button', onclick: async () => {
        try { const r = await api('POST', '/password', { current: cur.value, new: next.value }); csrf = r.csrf; cur.value = next.value = ''; toast('Password changed; other sessions signed out'); } catch (e) { fail(e); }
      } }, 'Change password')));
  }

  // --- boot -----------------------------------------------------------------------
  (async () => {
    try {
      const r = await fetch('/admin/api/session', { credentials: 'same-origin' });
      if (r.ok) { csrf = (await r.json()).csrf; render(); } else renderLogin();
    } catch (_) { renderLogin(); }
  })();
})();
