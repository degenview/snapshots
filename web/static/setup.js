'use strict';
(() => {
  const root = document.getElementById('setup');
  const $ = (id) => document.getElementById(id);
  const canSeal = root.dataset.canSeal === 'true';
  const postgres = root.dataset.postgres === 'true';
  const state = { step: 1, token: '' };

  $('public-url').value = root.dataset.suggestedUrl || '';
  $('public-url').readOnly = root.dataset.urlFromEnv === 'true';
  if (postgres) { $('ephemeral-warning').hidden = false; }

  // --- helpers -----------------------------------------------------------
  const showError = (msg) => { const e = $('error'); e.textContent = msg || ''; e.hidden = !msg; if (msg) e.scrollIntoView({ block: 'nearest' }); };

  async function post(path, body) {
    const res = await fetch(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body), credentials: 'same-origin' });
    let data = null;
    try { data = await res.json(); } catch (_) { /* not JSON */ }
    if (!res.ok) throw new Error((data && data.error && data.error.message) || `Request failed (${res.status})`);
    return data;
  }

  function goto(step) {
    state.step = step;
    document.querySelectorAll('[data-panel]').forEach((p) => { p.hidden = Number(p.dataset.panel) !== step; });
    document.querySelectorAll('#steps li').forEach((li) => {
      const n = Number(li.dataset.step);
      li.classList.toggle('active', n === step);
      li.classList.toggle('done', n < step);
    });
    showError('');
    const first = document.querySelector(`[data-panel="${step}"] input:not([type=radio]):not([type=checkbox]):not([readonly])`);
    if (first) first.focus();
  }

  function busy(button, on) { button.disabled = on; }

  // --- storage form --------------------------------------------------------
  const kind = () => document.querySelector('input[name=storage]:checked').value;
  $('data-dir').textContent = (root.dataset.dataDir || 'data') + '/images';
  function syncStorage() {
    const s3 = kind() === 's3';
    $('s3-fields').hidden = !s3;
    $('no-key-warning').hidden = !(s3 && !canSeal);
    $('storage-result').hidden = true;
  }
  document.querySelectorAll('input[name=storage]').forEach((r) => r.addEventListener('change', syncStorage));
  if (postgres) { document.querySelector('input[name=storage][value=s3]').checked = true; }
  syncStorage();

  function settings() {
    return {
      public_url: $('public-url').value.trim(),
      auth_required: $('auth-required').checked,
      retention_days: Number($('retention').value),
      max_image_bytes: Math.round(Number($('max-image').value) * 1048576),
      max_total_bytes: Math.round(Number($('quota').value) * 1073741824),
      uploads_per_hour: Number($('uploads-hour').value),
      views_per_minute: Number($('views-minute').value),
      storage_kind: kind(),
      s3: {
        endpoint: $('s3-endpoint').value, region: $('s3-region').value, bucket: $('s3-bucket').value,
        access_key: $('s3-access').value, secret_key: $('s3-secret').value,
        path_style: $('s3-pathstyle').checked, prefix: $('s3-prefix').value,
      },
    };
  }

  async function testStorage() {
    const out = $('storage-result');
    out.hidden = false; out.className = 'notice'; out.textContent = 'Testing…';
    try {
      const r = await post('/setup/test-storage', { setup_token: state.token, ...settings() });
      out.className = r.ok ? 'notice ok' : 'notice error';
      out.textContent = r.ok ? 'Storage works: a test image was written, read back and deleted.' : r.error;
      return r.ok;
    } catch (e) { out.className = 'notice error'; out.textContent = e.message; return false; }
  }

  // --- steps ---------------------------------------------------------------
  $('unlock').addEventListener('click', async (ev) => {
    const token = $('setup-token').value.trim();
    if (!token) return showError('Enter the setup token.');
    busy(ev.target, true);
    try { await post('/setup/verify', { setup_token: token }); state.token = token; goto(2); }
    catch (e) { showError(e.message); } finally { busy(ev.target, false); }
  });
  $('setup-token').addEventListener('keydown', (e) => { if (e.key === 'Enter') $('unlock').click(); });

  $('to-storage').addEventListener('click', () => {
    const a = $('password').value, b = $('password2').value;
    if ([...a].length < 12) return showError('The password must be at least 12 characters.');
    if (a !== b) return showError('The two passwords do not match.');
    goto(3);
  });

  $('test-storage').addEventListener('click', async (ev) => { busy(ev.target, true); await testStorage(); busy(ev.target, false); });
  $('to-options').addEventListener('click', async (ev) => {
    if (kind() === 's3' && !canSeal) return showError('Set SECRET_KEY first (see the note above), or use local disk.');
    busy(ev.target, true);
    const ok = await testStorage();
    busy(ev.target, false);
    if (ok) goto(4);
  });

  $('auth-required').addEventListener('change', () => {
    const on = $('auth-required').checked;
    $('open-warning').hidden = on; $('token-name-wrap').hidden = !on;
  });

  $('finish').addEventListener('click', async (ev) => {
    busy(ev.target, true);
    try {
      const r = await post('/setup/complete', {
        setup_token: state.token, password: $('password').value, token_name: $('token-name').value, ...settings(),
      });
      $('done-url').textContent = r.upload_url;
      if (r.token) { $('done-token').textContent = r.token; $('done-token-wrap').hidden = false; }
      $('done-curl').textContent = `curl -X POST ${r.upload_url} \\\n` + (r.token ? `  -H "Authorization: Bearer ${r.token}" \\\n` : '') +
        '  -H "Content-Type: image/png" \\\n  --data-binary @chart.png';
      $('password').value = $('password2').value = $('s3-secret').value = '';
      goto(5);
    } catch (e) { showError(e.message); } finally { busy(ev.target, false); }
  });

  document.querySelectorAll('[data-back]').forEach((b) => b.addEventListener('click', () => goto(state.step - 1)));
  document.querySelectorAll('[data-copy]').forEach((b) => b.addEventListener('click', async () => {
    await navigator.clipboard.writeText($(b.dataset.copy).textContent);
    const t = b.textContent; b.textContent = 'Copied'; setTimeout(() => { b.textContent = t; }, 1200);
  }));

  goto(1);
})();
