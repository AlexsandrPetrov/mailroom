// Mailroom — панель администратора. Все данные с сервера выводятся через esc().
'use strict';

const $ = (s, root = document) => root.querySelector(s);
const $$ = (s, root = document) => Array.from(root.querySelectorAll(s));
const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
let csrf = '';
let me = {role: 'viewer'};
let domainsCache = [];
let mailboxesCache = [];
let currentDomain = null;

const TITLES = {
  overview: 'Обзор', recommendations: 'Рекомендации', domains: 'Домены и DNS', mailboxes: 'Почтовые ящики',
  aliases: 'Алиасы', queue: 'Очередь', trace: 'Трассировка', diagnostics: 'Проверки', logs: 'Логи',
  journal: 'Журнал действий', config: 'Конфигурация Postfix', settings: 'Настройки', users: 'Пользователи',
  activity: 'Активность', backups: 'Резервные копии',
  security: 'Безопасность',
};
const LEVEL = {ok: 'норма', warn: 'внимание', fail: 'ошибка', info: 'совет', skip: 'пропуск'};

// ---------- сеть ----------
async function api(path, options = {}) {
  const opts = {...options, headers: {...(options.headers || {})}};
  if (opts.body && typeof opts.body !== 'string') {
    opts.body = JSON.stringify(opts.body);
    opts.headers['Content-Type'] = 'application/json';
  }
  if (opts.method && opts.method !== 'GET') opts.headers['X-CSRF-Token'] = csrf;
  const response = await fetch(path, opts);
  if (response.status === 401) { location.href = '/login'; throw new Error('Требуется вход'); }
  let data = {};
  try { data = await response.json(); } catch (e) { /* не JSON */ }
  if (!response.ok) throw new Error(data.error || `Ошибка ${response.status}`);
  return data;
}
const post = (path, body) => api(path, {method: 'POST', body: body || {}});
const patch = (path, body) => api(path, {method: 'PATCH', body});
const del = (path, body) => api(path, {method: 'DELETE', body: body || {}});

// ---------- вывод ----------
function toast(text, level = 'ok') {
  const box = $('#toast');
  box.className = `notice ${level}`;
  box.textContent = text;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => box.classList.add('hidden'), level === 'fail' ? 8000 : 4000);
}
const fail = (e) => toast(e.message || String(e), 'fail');
const pill = (level, text) => `<span class="pill ${esc(level)}">${esc(text ?? LEVEL[level] ?? level)}</span>`;
function fmtDate(v) {
  if (!v) return '—';
  const d = new Date(typeof v === 'number' ? v * 1000 : v);
  return isNaN(d) ? esc(v) : d.toLocaleString('ru-RU', {dateStyle: 'short', timeStyle: 'short'});
}
function fmtBytes(b) {
  if (b == null) return '—';
  const u = ['Б', 'КБ', 'МБ', 'ГБ', 'ТБ'];
  let i = 0;
  while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
  return `${b.toFixed(i && b < 10 ? 1 : 0)} ${u[i]}`;
}
const mb = (n) => `${Number(n).toLocaleString('ru-RU')} МБ`;
function copyText(text) {
  navigator.clipboard?.writeText(text).then(() => toast('Скопировано'), () => toast('Не удалось скопировать', 'warn'));
}
function emptyRow(cols, text) { return `<tr><td colspan="${cols}" class="empty">${esc(text)}</td></tr>`; }

// ---------- модальные окна ----------
function openForm({title, eyebrow = '', fields, submit = 'Сохранить', onSubmit}) {
  const dialog = $('#form-modal');
  $('#modal-title').textContent = title;
  $('#modal-eyebrow').textContent = eyebrow;
  $('#modal-submit').textContent = submit;
  $('#modal-error').classList.add('hidden');
  $('#modal-fields').innerHTML = fields.map((f) => {
    const attrs = `name="${esc(f.name)}" ${f.required ? 'required' : ''} ${f.placeholder ? `placeholder="${esc(f.placeholder)}"` : ''} ${f.min != null ? `min="${f.min}"` : ''} ${f.maxlength ? `maxlength="${f.maxlength}"` : ''}`;
    let input;
    if (f.type === 'select') {
      input = `<select ${attrs}>${f.options.map((o) => `<option value="${esc(o.value)}" ${String(o.value) === String(f.value ?? '') ? 'selected' : ''}>${esc(o.label)}</option>`).join('')}</select>`;
    } else if (f.type === 'textarea') {
      input = `<textarea ${attrs} rows="${f.rows || 3}">${esc(f.value ?? '')}</textarea>`;
    } else if (f.type === 'checkbox') {
      return `<label class="check ${f.wide ? 'wide' : ''}"><input type="checkbox" name="${esc(f.name)}" ${f.value ? 'checked' : ''}> ${esc(f.label)}</label>`;
    } else if (f.type === 'note') {
      return `<p class="muted wide">${f.html}</p>`;
    } else {
      input = `<input type="${f.type || 'text'}" ${attrs} value="${esc(f.value ?? '')}" autocomplete="${f.type === 'password' ? 'new-password' : 'off'}">`;
    }
    return `<label class="field ${f.wide ? 'wide' : ''}"><span>${esc(f.label)}</span>${input}</label>`;
  }).join('');
  const form = $('#modal-form');
  form.onsubmit = async (event) => {
    if (event.submitter && event.submitter.value === 'cancel') return;
    event.preventDefault();
    const data = {};
    for (const el of form.elements) {
      if (!el.name) continue;
      data[el.name] = el.type === 'checkbox' ? el.checked : el.value;
    }
    const button = $('#modal-submit');
    button.disabled = true;
    try {
      await onSubmit(data);
      dialog.close();
    } catch (e) {
      $('#modal-error').textContent = e.message;
      $('#modal-error').classList.remove('hidden');
    } finally {
      button.disabled = false;
    }
  };
  dialog.showModal();
  form.querySelector('input,select,textarea')?.focus();
}

function showSecret(title, value, text) {
  $('#secret-title').textContent = title;
  $('#secret-value').textContent = value;
  $('#secret-text').textContent = text || 'Скопируйте пароль сейчас: повторно его показать нельзя. Передайте его пользователю защищённым способом.';
  $('#secret-modal').showModal();
}
$('#secret-copy').addEventListener('click', () => copyText($('#secret-value').textContent));
$('#secret-close').addEventListener('click', () => { $('#secret-value').textContent = ''; $('#secret-modal').close(); });

// ---------- навигация ----------
const loaders = {};
function show(name) {
  if (!TITLES[name]) name = 'overview';
  $$('[data-page]').forEach((s) => s.classList.toggle('hidden', s.dataset.page !== name));
  $$('.nav-item').forEach((b) => b.classList.toggle('active', b.dataset.section === name));
  $('#page-title').textContent = TITLES[name];
  $('#sidebar').classList.remove('open');
  if (location.hash !== `#${name}`) history.replaceState(null, '', `#${name}`);
  (loaders[name] || (() => {}))().catch(fail);
}
$$('.nav-item').forEach((b) => b.addEventListener('click', () => show(b.dataset.section)));
document.addEventListener('click', (e) => {
  const target = e.target.closest('[data-goto]');
  if (!target) return;
  const [page, id] = target.dataset.goto.split(':');
  if (page === 'domain') { show('domains'); openDomain(Number(id)); } else show(page);
});
$('#menu-toggle').addEventListener('click', () => $('#sidebar').classList.toggle('open'));
$('#refresh').addEventListener('click', () => show(location.hash.slice(1) || 'overview'));
$('#logout').addEventListener('click', async () => { await post('/api/auth/logout').catch(() => {}); location.href = '/login'; });

function applyRole() {
  const canWrite = me.role === 'admin' || me.role === 'operator';
  $$('[data-write]').forEach((el) => el.classList.toggle('hidden', !canWrite));
  $$('[data-admin]').forEach((el) => el.classList.toggle('hidden', me.role !== 'admin'));
  $('[data-section="users"]').classList.toggle('hidden', me.role !== 'admin');
}

// ---------- обзор ----------
loaders.overview = async () => {
  const d = await api('/api/overview');
  $('#host-name').textContent = d.host;
  const down = d.services.filter((s) => s.state !== 'active' && s.name !== 'fail2ban');
  $('#hero-title').textContent = down.length ? `Не работает: ${down.map((s) => s.name).join(', ')}` : 'Почтовые сервисы работают';
  $('#hero-text').textContent = `Доменов: ${d.counts.domains}, ящиков: ${d.counts.mailboxes}, алиасов: ${d.counts.aliases}. В веб-почте сейчас: ${d.counts.webmail_online}.`;
  const q = d.queue;
  $('#metrics').innerHTML = [
    ['Очередь', q.available ? q.total : '—', q.deferred ? `отложено ${q.deferred}` : 'писем'],
    ['Старейшее в очереди', q.oldest_minutes || 0, 'мин'],
    ['Хранилище', d.disk ? fmtBytes(d.disk.used) : '—', d.disk ? `из ${fmtBytes(d.disk.total)}` : ''],
    ['Проверено Rspamd', d.rspamd ? d.rspamd.scanned : '—', 'писем'],
  ].map(([l, v, s]) => `<div class="metric"><div class="metric-label">${esc(l)}</div><div class="metric-value">${esc(v)}<small>${esc(s)}</small></div></div>`).join('');
  $('#services').innerHTML = d.services.map((s) => `<div class="service-row"><span>${esc(s.name)}</span>${pill(s.state === 'active' ? 'ok' : (s.name === 'fail2ban' ? 'warn' : 'fail'), s.state)}</div>`).join('');
  const actions = d.rspamd ? Object.entries(d.rspamd.actions || {}).filter(([, n]) => n) : [];
  $('#rspamd').innerHTML = d.rspamd
    ? `<dl class="kv"><dt>Проверено</dt><dd>${esc(d.rspamd.scanned)}</dd>${actions.map(([a, n]) => `<dt>${esc(a)}</dt><dd>${esc(n)}</dd>`).join('')}<dt>Обучено</dt><dd>${esc(d.rspamd.learned)}</dd></dl>`
    : '<p class="muted">Статистика Rspamd недоступна (контроллер 127.0.0.1:11334).</p>';
  loadRecBadge();
};

// ---------- рекомендации ----------
async function loadRecBadge() {
  try {
    const d = await api('/api/recommendations');
    const badge = $('#rec-badge');
    const n = d.summary.fail || d.summary.warn;
    badge.textContent = n;
    badge.classList.toggle('warn', !d.summary.fail);
    badge.classList.toggle('hidden', !n);
    return d;
  } catch (e) { return null; }
}
loaders.recommendations = async () => {
  $('#rec-list').innerHTML = '<div class="empty">Проверяем DNS, TLS, сервисы и чёрные списки…</div>';
  const d = await loadRecBadge() || await api('/api/recommendations');
  $('#rec-summary').innerHTML = [['fail', 'Ошибки'], ['warn', 'Внимание'], ['info', 'Советы']].map(([k, l]) =>
    `<div class="metric"><div class="metric-label">${l}</div><div class="metric-value">${d.summary[k] || 0}</div></div>`).join('');
  $('#rec-list').innerHTML = d.items.length ? d.items.map((r) => `<div class="rec"><div>${pill(r.level)}</div><div>
      <div class="area">${esc(r.area)}</div><h4>${esc(r.title)}</h4>${r.detail ? `<p>${esc(r.detail)}</p>` : ''}
      ${r.fix ? `<div class="fix"><b>Как исправить:</b> ${esc(r.fix)}</div>` : ''}
      ${r.target ? `<button class="link-button" data-goto="${esc(r.target)}">Перейти →</button>` : ''}</div></div>`).join('')
    : '<div class="empty">Замечаний нет.</div>';
};
$('#rec-run').addEventListener('click', () => loaders.recommendations().catch(fail));

// ---------- домены ----------
loaders.domains = async () => {
  const d = await api('/api/domains');
  domainsCache = d.items;
  const dkim = {none: ['fail', 'нет ключа'], pending: ['warn', 'ждёт DNS'], active: ['ok', 'подпись']};
  $('#domains-table').innerHTML = d.items.length ? d.items.map((x) => `<tr class="${x.status !== 'active' ? 'dim' : ''}">
      <td><button class="link-button" data-open-domain="${x.id}"><b>${esc(x.name)}</b></button><div class="small muted">${esc(x.description)}</div></td>
      <td>${pill(x.status === 'active' ? 'ok' : 'off', x.status === 'active' ? 'активен' : 'отключён')}</td>
      <td>${pill(...(dkim[x.dkim_state] || dkim.none))}${x.dkim_selector ? ` <code>${esc(x.dkim_selector)}</code>` : ''}</td>
      <td class="num">${x.mailbox_count}</td><td class="num">${x.alias_count}</td>
      <td class="num">${mb(x.allocated_mb)} из ${mb(x.quota_mb)}</td>
      <td class="num"><button class="link-button" data-open-domain="${x.id}">DNS и DKIM</button></td></tr>`).join('')
    : emptyRow(7, 'Доменов пока нет. Добавьте первый домен.');
  $$('[data-open-domain]').forEach((b) => b.addEventListener('click', () => openDomain(Number(b.dataset.openDomain))));
  if (currentDomain) openDomain(currentDomain, false);
};

$('#new-domain').addEventListener('click', () => openForm({
  title: 'Новый домен', eyebrow: 'Домены', submit: 'Добавить',
  fields: [
    {name: 'name', label: 'Домен', placeholder: 'example.com', required: true, wide: true},
    {name: 'quota_mb', label: 'Квота домена, МБ', type: 'number', value: 10240, min: 1},
    {name: 'description', label: 'Описание', maxlength: 200},
    {name: 'service_target', label: 'Куда направить postmaster@, abuse@, dmarc@, tlsrpt@ (существующий ящик)', placeholder: 'admin@example.com', wide: true},
    {type: 'note', html: 'Служебные адреса обязательны: на postmaster@ и abuse@ пишут о проблемах с вашей почтой, на dmarc@ приходят отчёты DMARC. Можно указать ящик позже — тогда создайте алиасы вручную.'},
  ],
  onSubmit: async (data) => {
    const r = await post('/api/domains', data);
    toast('Домен добавлен. Создайте DKIM-ключ и опубликуйте записи DNS.');
    await loaders.domains();
    openDomain(r.id);
  },
}));

function domainTab(name) {
  $$('#dd-tabs .tab').forEach((t) => t.classList.toggle('active', t.dataset.tab === name));
  $$('[data-tabpage]').forEach((p) => p.classList.toggle('hidden', p.dataset.tabpage !== name));
}
$$('#dd-tabs .tab').forEach((t) => t.addEventListener('click', () => domainTab(t.dataset.tab)));
$('#dd-close').addEventListener('click', () => { currentDomain = null; $('#domain-detail').classList.add('hidden'); });
$('#dd-check').addEventListener('click', () => openDomain(currentDomain, true).catch(fail));

function recordHtml(r) {
  const c = r.check;
  return `<div class="dns-record"><header><span class="rtype">${esc(r.type)}</span><span class="rname">${esc(r.name)}</span>
      ${r.required ? '' : pill('info', 'по желанию')}${c ? pill(c.status) : ''}</header>
    <div class="copy-box"><code>${esc(r.value)}</code><button class="link-button" data-copy="${esc(r.value)}">копировать</button></div>
    <p>${esc(r.purpose)}</p>
    ${c && c.note ? `<p><b>${esc(c.note)}</b></p>` : ''}
    ${c && c.found && c.found.length ? `<div class="dns-found">Сейчас в DNS: ${c.found.map(esc).join(' | ')}</div>` : ''}</div>`;
}

async function openDomain(id, check = false) {
  currentDomain = id;
  const panel = $('#domain-detail');
  panel.classList.remove('hidden');
  const d = await api(`/api/domains/${id}/dns${check ? '?check=1' : ''}`);
  const row = domainsCache.find((x) => x.id === id) || {};
  $('#dd-name').textContent = d.domain;
  if (!d.public_ip) $('#dd-records').innerHTML = '<div class="notice warn">Укажите публичный IP в «Настройках» — без него записи A, PTR и SPF неполные.</div>';
  else $('#dd-records').innerHTML = '';
  $('#dd-records').insertAdjacentHTML('beforeend', d.records.map(recordHtml).join(''));
  // DKIM
  const k = d.dkim;
  const state = {none: 'Ключа нет', pending: 'Ключ создан, подпись не включена', active: 'Подпись включена'}[k.state];
  let html = `<dl class="kv"><dt>Состояние</dt><dd>${pill(k.state === 'active' ? 'ok' : k.state === 'pending' ? 'warn' : 'fail', state)}</dd>
    <dt>Селектор</dt><dd>${k.selector ? `<code>${esc(k.selector)}</code>` : '—'}</dd><dt>Создан</dt><dd>${fmtDate(k.created_at)}</dd></dl>`;
  const pendingSel = k.pending ? k.pending.selector : (k.state === 'pending' ? k.selector : null);
  if (pendingSel) {
    const rec = d.records.find((r) => r.name.startsWith(`${pendingSel}._domainkey`));
    html += `<h4>Опубликуйте запись${k.pending ? ' нового ключа' : ''}</h4>${rec ? recordHtml(rec) : ''}
      <div class="actions" data-write><button class="primary-button" id="dkim-activate">Проверить DNS и включить подпись</button>
      <button class="link-button danger" id="dkim-force">Включить без проверки</button></div>`;
  }
  if (k.state === 'active') html += `<div class="actions" data-write><button class="link-button danger" id="dkim-off">Выключить подпись</button></div>`;
  $('#dd-dkim').innerHTML = html;
  $('#dkim-activate')?.addEventListener('click', () => dkimActivate(false));
  $('#dkim-force')?.addEventListener('click', () => { if (confirm('Включить подпись, не убедившись, что ключ опубликован? Получатели увидят dkim=fail, пока запись не появится в DNS.')) dkimActivate(true); });
  $('#dkim-off')?.addEventListener('click', async () => {
    if (!confirm('Выключить DKIM-подпись домена?')) return;
    await post(`/api/domains/${id}/dkim/disable`).catch(fail);
    openDomain(id);
  });
  // SPF/DMARC
  const s = d.settings;
  const f = $('#policy-form');
  f.spf_mx.checked = s.spf.mx; f.spf_a.checked = s.spf.a; f.spf_ip4.value = s.spf.ip4.join(' ');
  f.spf_include.value = s.spf.include.join(' '); f.spf_all.value = s.spf.all;
  for (const key of ['p', 'sp', 'pct', 'fo', 'adkim', 'aspf']) f[`dmarc_${key}`].value = s.dmarc[key];
  f.dmarc_rua.checked = s.dmarc.rua; f.dmarc_ruf.checked = s.dmarc.ruf; f.tlsrpt.checked = s.tlsrpt; f.srv.checked = s.srv;
  const pf = $('#props-form');
  pf.quota_mb.value = row.quota_mb ?? ''; pf.description.value = row.description ?? ''; pf.status.value = row.status ?? 'active';
  applyRole();
  if (check) toast('Проверка DNS выполнена');
  panel.scrollIntoView({behavior: 'smooth', block: 'start'});
}

async function dkimActivate(force) {
  try {
    const r = await post(`/api/domains/${currentDomain}/dkim/activate`, {force});
    toast(r.dns_verified ? 'Ключ найден в DNS, подпись включена' : 'Подпись включена без проверки DNS', r.dns_verified ? 'ok' : 'warn');
    await loaders.domains();
  } catch (e) { fail(e); }
}

$('#dkim-generate').addEventListener('click', async () => {
  try {
    await post(`/api/domains/${currentDomain}/dkim`, {selector: $('#dkim-selector').value.trim(), bits: $('#dkim-bits').value});
    $('#dkim-selector').value = '';
    toast('Ключ создан. Опубликуйте TXT-запись и включите подпись.');
    await loaders.domains();
    domainTab('dkim');
  } catch (e) { fail(e); }
});

$('#policy-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const f = e.target;
  const split = (v) => v.split(/[\s,]+/).filter(Boolean);
  const body = {dns_settings: {
    spf: {mx: f.spf_mx.checked, a: f.spf_a.checked, ip4: split(f.spf_ip4.value), include: split(f.spf_include.value), all: f.spf_all.value},
    dmarc: {p: f.dmarc_p.value, sp: f.dmarc_sp.value, pct: Number(f.dmarc_pct.value), fo: f.dmarc_fo.value, adkim: f.dmarc_adkim.value,
      aspf: f.dmarc_aspf.value, rua: f.dmarc_rua.checked, ruf: f.dmarc_ruf.checked},
    tlsrpt: f.tlsrpt.checked, srv: f.srv.checked}};
  try {
    await patch(`/api/domains/${currentDomain}`, body);
    toast('Сохранено. Обновлённые записи — на вкладке «Записи DNS»');
    await openDomain(currentDomain);
    domainTab('records');
  } catch (err) { fail(err); }
});

$('#props-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const f = e.target;
  try {
    await patch(`/api/domains/${currentDomain}`, {quota_mb: Number(f.quota_mb.value), description: f.description.value, status: f.status.value});
    toast('Сохранено');
    await loaders.domains();
  } catch (err) { fail(err); }
});

$('#domain-delete').addEventListener('click', async () => {
  const row = domainsCache.find((x) => x.id === currentDomain);
  if (!row) return;
  const confirmName = prompt(`Удалить домен ${row.name} вместе с его ящиками и алиасами из базы? Письма на диске останутся.\nВведите имя домена для подтверждения:`);
  if (confirmName !== row.name) return;
  try {
    await del(`/api/domains/${currentDomain}`, {confirm: confirmName});
    currentDomain = null;
    $('#domain-detail').classList.add('hidden');
    toast('Домен удалён', 'warn');
    loaders.domains();
  } catch (e) { fail(e); }
});

document.addEventListener('click', (e) => {
  const b = e.target.closest('[data-copy]');
  if (b) copyText(b.dataset.copy);
});

// ---------- ящики ----------
async function ensureDomains() {
  if (!domainsCache.length) domainsCache = (await api('/api/domains')).items;
  return domainsCache;
}
loaders.mailboxes = async () => {
  const d = await api('/api/mailboxes?usage=1');
  mailboxesCache = d.items;
  renderMailboxes();
};
function renderMailboxes() {
  const q = $('#mailbox-filter').value.trim().toLowerCase();
  const items = mailboxesCache.filter((x) => !q || x.address.includes(q) || (x.display_name || '').toLowerCase().includes(q));
  $('#mailboxes-table').innerHTML = items.length ? items.map((x) => {
    const pct = x.used_bytes != null ? Math.round(x.used_bytes * 100 / (x.quota_mb * 1048576)) : null;
    return `<tr class="${x.status !== 'active' ? 'dim' : ''}">
      <td><b>${esc(x.address)}</b><div class="small muted">${esc(x.display_name)}</div></td>
      <td>${pill(x.status === 'active' ? 'ok' : 'off', x.status === 'active' ? 'активен' : 'отключён')}${x.domain_status !== 'active' ? ' ' + pill('warn', 'домен откл.') : ''}</td>
      <td class="num">${x.used_bytes != null ? `${fmtBytes(x.used_bytes)} ${pct >= 90 ? pill('warn', pct + '%') : `<span class="muted">${pct}%</span>`}` : '—'}${x.messages != null ? `<div class="small muted">${x.messages} писем</div>` : ''}</td>
      <td class="num">${mb(x.quota_mb)}</td><td>${fmtDate(x.last_login_at)}</td>
      <td class="num" data-write>
        <button class="link-button" data-mb-edit="${x.id}">Изменить</button>
        <button class="link-button" data-mb-pass="${x.id}">Пароль</button>
        <button class="link-button danger" data-mb-del="${x.id}">Удалить</button></td></tr>`;
  }).join('') : emptyRow(6, mailboxesCache.length ? 'Ничего не найдено' : 'Ящиков пока нет');
  applyRole();
  $$('[data-mb-edit]').forEach((b) => b.addEventListener('click', () => editMailbox(Number(b.dataset.mbEdit))));
  $$('[data-mb-pass]').forEach((b) => b.addEventListener('click', () => resetPassword(Number(b.dataset.mbPass))));
  $$('[data-mb-del]').forEach((b) => b.addEventListener('click', () => deleteMailbox(Number(b.dataset.mbDel))));
}
$('#mailbox-filter').addEventListener('input', renderMailboxes);

$('#new-mailbox').addEventListener('click', async () => {
  const domains = (await ensureDomains()).filter((x) => x.status === 'active');
  if (!domains.length) return toast('Сначала добавьте домен', 'warn');
  openForm({
    title: 'Новый ящик', eyebrow: 'Ящики', submit: 'Создать',
    fields: [
      {name: 'localpart', label: 'Имя (до @)', placeholder: 'ivanov', required: true},
      {name: 'domain_id', label: 'Домен', type: 'select', options: domains.map((x) => ({value: x.id, label: '@' + x.name}))},
      {name: 'display_name', label: 'Имя владельца', placeholder: 'Иван Иванов', maxlength: 100},
      {name: 'quota_mb', label: 'Квота, МБ', type: 'number', value: 2048, min: 1},
      {name: 'password', label: 'Пароль (пусто — сгенерировать)', type: 'password', wide: true},
    ],
    onSubmit: async (data) => {
      const r = await post('/api/mailboxes', {...data, domain_id: Number(data.domain_id), quota_mb: Number(data.quota_mb)});
      await loaders.mailboxes();
      if (r.generated_password) showSecret(`Ящик ${r.address}`, r.generated_password);
      else toast(`Ящик ${r.address} создан`);
    },
  });
});

function editMailbox(id) {
  const x = mailboxesCache.find((m) => m.id === id);
  openForm({
    title: x.address, eyebrow: 'Ящик',
    fields: [
      {name: 'display_name', label: 'Имя владельца', value: x.display_name, maxlength: 100},
      {name: 'quota_mb', label: 'Квота, МБ', type: 'number', value: x.quota_mb, min: 1},
      {name: 'status', label: 'Статус', type: 'select', value: x.status, options: [{value: 'active', label: 'активен'}, {value: 'disabled', label: 'отключён — вход и приём почты запрещены'}]},
    ],
    onSubmit: async (data) => {
      await patch(`/api/mailboxes/${id}`, {...data, quota_mb: Number(data.quota_mb)});
      toast('Сохранено');
      loaders.mailboxes();
    },
  });
}

function resetPassword(id) {
  const x = mailboxesCache.find((m) => m.id === id);
  openForm({
    title: `Пароль ${x.address}`, eyebrow: 'Ящик', submit: 'Сменить пароль',
    fields: [{name: 'password', label: 'Новый пароль (пусто — сгенерировать)', type: 'password', wide: true},
      {type: 'note', html: 'Сессии веб-почты этого ящика будут завершены. Почтовые программы запросят новый пароль.'}],
    onSubmit: async (data) => {
      const r = await post(`/api/mailboxes/${id}/password`, data);
      if (r.generated_password) showSecret(`Новый пароль ${r.address}`, r.generated_password);
      else toast('Пароль изменён');
    },
  });
}

function deleteMailbox(id) {
  const x = mailboxesCache.find((m) => m.id === id);
  openForm({
    title: `Удалить ${x.address}?`, eyebrow: 'Ящик', submit: 'Удалить',
    fields: [{type: 'note', html: 'Ящик исчезнет из базы: вход и приём почты прекратятся сразу.'},
      {name: 'purge', type: 'checkbox', label: 'Перенести письма в архив /var/vmail/.deleted (иначе останутся на месте)', wide: true}],
    onSubmit: async (data) => {
      const r = await del(`/api/mailboxes/${id}`, data);
      toast(`Ящик удалён: ${r.note}`, 'warn');
      loaders.mailboxes();
    },
  });
}

// ---------- алиасы ----------
let aliasesCache = [];
loaders.aliases = async () => {
  aliasesCache = (await api('/api/aliases')).items;
  $('#aliases-table').innerHTML = aliasesCache.length ? aliasesCache.map((x) => `<tr class="${x.status !== 'active' ? 'dim' : ''}">
      <td><b>${esc(x.address)}</b>${x.localpart === '*' ? ' ' + pill('warn', 'catch-all') : ''}</td>
      <td>${x.destinations.split(',').map((a) => `<div><code>${esc(a)}</code></div>`).join('')}</td>
      <td>${pill(x.status === 'active' ? 'ok' : 'off', x.status === 'active' ? 'активен' : 'отключён')}</td>
      <td class="muted">${esc(x.note)}</td>
      <td class="num" data-write><button class="link-button" data-al-edit="${x.id}">Изменить</button>
        <button class="link-button danger" data-al-del="${x.id}">Удалить</button></td></tr>`).join('')
    : emptyRow(5, 'Алиасов нет');
  applyRole();
  $$('[data-al-edit]').forEach((b) => b.addEventListener('click', () => editAlias(Number(b.dataset.alEdit))));
  $$('[data-al-del]').forEach((b) => b.addEventListener('click', async () => {
    const x = aliasesCache.find((a) => a.id === Number(b.dataset.alDel));
    if (!confirm(`Удалить алиас ${x.address}?`)) return;
    await del(`/api/aliases/${x.id}`).then(() => { toast('Алиас удалён', 'warn'); loaders.aliases(); }, fail);
  }));
};
$('#new-alias').addEventListener('click', async () => {
  const domains = await ensureDomains();
  if (!domains.length) return toast('Сначала добавьте домен', 'warn');
  openForm({
    title: 'Новый алиас', eyebrow: 'Алиасы', submit: 'Создать',
    fields: [
      {name: 'localpart', label: 'Имя (до @), * — все адреса домена', placeholder: 'sales', required: true},
      {name: 'domain_id', label: 'Домен', type: 'select', options: domains.map((x) => ({value: x.id, label: '@' + x.name}))},
      {name: 'destinations', label: 'Получатели (через запятую или с новой строки)', type: 'textarea', required: true, wide: true, placeholder: 'ivanov@example.com, petrov@gmail.com'},
      {name: 'note', label: 'Заметка', wide: true, maxlength: 200},
    ],
    onSubmit: async (data) => {
      await post('/api/aliases', {...data, domain_id: Number(data.domain_id)});
      toast('Алиас создан');
      loaders.aliases();
    },
  });
});
function editAlias(id) {
  const x = aliasesCache.find((a) => a.id === id);
  openForm({
    title: x.address, eyebrow: 'Алиас',
    fields: [
      {name: 'destinations', label: 'Получатели', type: 'textarea', value: x.destinations.split(',').join('\n'), wide: true, required: true},
      {name: 'status', label: 'Статус', type: 'select', value: x.status, options: [{value: 'active', label: 'активен'}, {value: 'disabled', label: 'отключён'}]},
      {name: 'note', label: 'Заметка', value: x.note, maxlength: 200},
    ],
    onSubmit: async (data) => { await patch(`/api/aliases/${id}`, data); toast('Сохранено'); loaders.aliases(); },
  });
}

// ---------- очередь ----------
loaders.queue = async () => {
  const d = await api('/api/queue');
  const s = d.summary;
  $('#queue-metrics').innerHTML = [['Всего', s.total], ['Отложено', s.deferred], ['Задержано', s.hold], ['Старейшее, мин', s.oldest_minutes]]
    .map(([l, v]) => `<div class="metric"><div class="metric-label">${l}</div><div class="metric-value">${esc(v ?? 0)}</div></div>`).join('');
  $('#queue-table').innerHTML = d.items.length ? d.items.map((x) => `<tr>
      <td><input type="checkbox" data-qid="${esc(x.id)}"></td><td><button class="link-button mono" data-trace="${esc(x.id)}">${esc(x.id)}</button></td>
      <td>${pill(x.queue === 'deferred' ? 'warn' : x.queue === 'hold' ? 'off' : 'info', x.queue)}</td>
      <td>${esc(x.sender || '<>')}</td><td>${x.recipients.map(esc).join('<br>')}</td>
      <td class="small">${esc(x.reason)}</td><td>${fmtDate(x.arrival)}</td></tr>`).join('')
    : emptyRow(7, 'Очередь пуста — все письма доставлены');
  $$('[data-trace]').forEach((b) => b.addEventListener('click', () => { show('trace'); $('#trace-form').q.value = b.dataset.trace; runTrace(); }));
};
$('#queue-all').addEventListener('change', (e) => $$('[data-qid]').forEach((c) => { c.checked = e.target.checked; }));
$('#queue-flush').addEventListener('click', async () => {
  await post('/api/queue/action', {action: 'flush'}).then(() => toast('Postfix повторит доставку'), fail);
  setTimeout(() => loaders.queue().catch(fail), 2000);
});
$$('[data-queue]').forEach((b) => b.addEventListener('click', async () => {
  const ids = $$('[data-qid]:checked').map((c) => c.dataset.qid);
  if (!ids.length) return toast('Выберите письма', 'warn');
  if (b.dataset.queue === 'delete' && !confirm(`Удалить ${ids.length} писем из очереди без доставки и без уведомления отправителя?`)) return;
  await post('/api/queue/action', {action: b.dataset.queue, ids}).then(() => toast('Готово'), fail);
  loaders.queue().catch(fail);
}));

// ---------- трассировка ----------
async function runTrace() {
  const f = $('#trace-form');
  $('#trace-output').textContent = 'Поиск…';
  try {
    const d = await api(`/api/trace?q=${encodeURIComponent(f.q.value.trim())}&hours=${f.hours.value}`);
    $('#trace-meta').textContent = d.queue_ids.length ? `ID очереди: ${d.queue_ids.join(', ')}` : '';
    $('#trace-output').textContent = d.lines.length ? d.lines.join('\n') : 'Ничего не найдено за выбранный период.';
  } catch (e) { $('#trace-output').textContent = e.message; }
}
$('#trace-form').addEventListener('submit', (e) => { e.preventDefault(); runTrace(); });
loaders.trace = async () => {};

// ---------- проверки ----------
loaders.diagnostics = async () => {
  const boxes = mailboxesCache.length ? mailboxesCache : (await api('/api/mailboxes')).items;
  $('#sendtest-from').innerHTML = boxes.filter((x) => x.status === 'active').map((x) => `<option>${esc(x.address)}</option>`).join('');
  const s = (await api('/api/settings')).items;
  const tls = $('#tls-form');
  if (!tls.host.value) tls.host.value = s.hostname;
};
function bindForm(id, handler) {
  $(id).addEventListener('submit', async (e) => {
    e.preventDefault();
    const button = e.target.querySelector('button');
    button.disabled = true;
    try { await handler(Object.fromEntries(new FormData(e.target))); } catch (err) { fail(err); } finally { button.disabled = false; }
  });
}
bindForm('#dns-form', async (f) => {
  const d = await api(`/api/diagnostics/dns?domain=${encodeURIComponent(f.domain.trim())}&selector=${encodeURIComponent(f.selector.trim())}`);
  $('#dns-results').innerHTML = `<table>${d.checks.map((c) => `<tr><td>${pill(c.ok ? 'ok' : (['MTA-STS', 'TLS-RPT'].includes(c.name) ? 'info' : 'fail'), c.name)}</td>
    <td class="small"><code>${esc(c.target)}</code><div>${c.values.map(esc).join('<br>') || '<span class="muted">нет записи</span>'}</div></td></tr>`).join('')}</table>`;
});
bindForm('#smtp-form', async (f) => {
  const d = await api(`/api/diagnostics/smtp?host=${encodeURIComponent(f.host.trim())}&port=${f.port}`);
  $('#smtp-results').innerHTML = `<p>${pill(d.ok ? 'ok' : 'fail', d.ok ? 'доступен' : 'ошибка')}</p><div class="terminal">${d.steps.map(esc).join('\n')}</div>`;
});
bindForm('#tls-form', async (f) => {
  const d = await api(`/api/diagnostics/tls?host=${encodeURIComponent(f.host.trim())}&port=${f.port}`);
  $('#tls-results').innerHTML = !d.ok ? `<p>${pill('fail', 'ошибка')} ${esc(d.error)}</p>` : `<dl class="kv">
    <dt>Доверие</dt><dd>${d.trusted ? pill('ok', 'доверенный') : pill('warn', 'не доверенный')} ${esc(d.trust_error)}</dd>
    <dt>Имена</dt><dd>${esc(d.san.join(', ') || d.subject)}</dd><dt>Издатель</dt><dd>${esc(d.issuer)}</dd>
    <dt>Действует до</dt><dd>${fmtDate(d.not_after)} ${pill(d.days_left > 14 ? 'ok' : 'warn', `${d.days_left} дн.`)}</dd><dt>Протокол</dt><dd>${esc(d.version)}</dd></dl>`;
});
bindForm('#dnsbl-form', async (f) => {
  const d = await api(`/api/diagnostics/dnsbl?ip=${encodeURIComponent(f.ip.trim())}`);
  $('#dnsbl-results').innerHTML = `<p class="muted">IP ${esc(d.ip)}</p><table>${d.lists.map((l) => `<tr><td>${pill(l.status)}</td><td>${esc(l.list)}</td><td class="small muted">${esc(l.detail)}</td></tr>`).join('')}</table>`;
});
bindForm('#sendtest-form', async (f) => {
  const d = await post('/api/diagnostics/send-test', f);
  $('#sendtest-results').innerHTML = `<p>${pill('ok', 'принято Postfix')} <code>${esc(d.message_id)}</code></p>
    <button class="link-button" id="sendtest-trace">Отследить доставку →</button>`;
  $('#sendtest-trace').addEventListener('click', () => { show('trace'); $('#trace-form').q.value = d.message_id.replace(/[<>]/g, ''); runTrace(); });
});
bindForm('#headers-form', async (f) => {
  const d = await post('/api/diagnostics/headers', f);
  const lvl = (r) => (['pass'].includes(r) ? 'ok' : ['none', 'neutral', 'softfail'].includes(r) ? 'warn' : 'fail');
  $('#headers-results').innerHTML = `<dl class="kv"><dt>От</dt><dd>${esc(d.from)}</dd><dt>Тема</dt><dd>${esc(d.subject)}</dd><dt>Return-Path</dt><dd>${esc(d.return_path)}</dd></dl>
    <h4>Проверки получателя</h4>${d.auth_results.length ? `<table>${d.auth_results.map((r) => `<tr><td>${pill(lvl(r.result), `${r.method} ${r.result}`)}</td><td class="small">${esc(r.detail)}<div class="muted">${esc(r.server)}</div></td></tr>`).join('')}</table>` : '<p class="muted">Нет заголовка Authentication-Results — вставьте заголовки из ящика получателя.</p>'}
    <h4>Подписи DKIM</h4>${d.dkim_signatures.map((s) => `<div><code>d=${esc(s.domain)} s=${esc(s.selector)} a=${esc(s.algorithm)}</code> ${s.domain === d.from_domain ? pill('ok', 'совпадает с From') : pill('warn', 'другой домен')}</div>`).join('') || '<p class="muted">Подписи нет.</p>'}
    ${Object.keys(d.spam).length ? `<h4>Антиспам</h4><dl class="kv">${Object.entries(d.spam).map(([k, v]) => `<dt>${esc(k)}</dt><dd class="small">${esc(v)}</dd>`).join('')}</dl>` : ''}
    <h4>Путь (${d.hops.length} серверов)</h4><div class="terminal">${d.hops.map((h, i) => `${i + 1}. ${h.delay_s != null ? `[+${h.delay_s} с] ` : ''}${h.text}`).map(esc).join('\n\n')}</div>`;
});

// ---------- логи, журнал, конфигурация ----------
loaders.logs = async () => {
  const d = await api(`/api/logs?service=${$('#log-service').value}`);
  $('#system-logs').textContent = d.lines.length ? d.lines.join('\n') : 'Журнал пуст или недоступен (пользователь mailroom должен входить в группу systemd-journal).';
};
$('#log-service').addEventListener('change', () => loaders.logs().catch(fail));
loaders.journal = async () => {
  const d = await api('/api/audit?limit=300');
  $('#journal-list').innerHTML = d.items.map((x) => `<div class="event-row">${pill(x.level === 'WARN' ? 'warn' : x.level === 'ERROR' ? 'fail' : 'ok', x.level)}
    <div><b>${esc(x.event)}</b><small>${esc(x.details)}${x.actor ? ` · ${esc(x.actor)}` : ''}</small></div><time>${fmtDate(x.created_at)}</time></div>`).join('') || '<div class="empty">Пусто</div>';
};
loaders.config = async () => {
  const d = await api('/api/config');
  $('#config-list').innerHTML = d.available ? d.values.map((x) => `<tr><td><code>${esc(x.key)}</code></td><td class="small"><code>${esc(x.value)}</code></td></tr>`).join('') : emptyRow(2, d.error);
};

// ---------- настройки ----------
loaders.settings = async () => {
  const s = (await api('/api/settings')).items;
  const f = $('#settings-form');
  for (const key of ['hostname', 'public_ip', 'message_size_mb', 'mynetworks', 'send_limit_hour', 'send_limit_message',
    'smtp_limit_hour', 'alert_email', 'telegram_token', 'telegram_chat']) f[key].value = s[key] ?? '';
  $$('input', f).forEach((i) => { i.disabled = me.role !== 'admin'; });
};
$('#settings-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  try {
    await api('/api/settings', {method: 'PUT', body: Object.fromEntries(new FormData(e.target))});
    toast('Сохранено. Нажмите «Применить к Postfix», чтобы изменить имя, сети и размер письма в Postfix.');
  } catch (err) { fail(err); }
});
$('#settings-apply').addEventListener('click', async () => {
  try {
    const r = await post('/api/settings/apply');
    toast(`Применено: ${r.output}`);
  } catch (e) { fail(e); }
});

$('#alerts-test').addEventListener('click', async () => {
  try {
    const r = await post('/api/alerts/test');
    toast(`Отправлено: ${r.results.join('; ')}`, r.results.some((x) => /ошибка/.test(x)) ? 'warn' : 'ok');
  } catch (e) { fail(e); }
});

// ---------- активность ----------
loaders.activity = async () => {
  const d = await api(`/api/activity?hours=${$('#activity-hours').value}`);
  const boxes = Object.entries(d.mailboxes).sort((a, b) => (b[1].sent - a[1].sent) || (b[1].logins - a[1].logins));
  const sent = boxes.reduce((s, [, v]) => s + v.sent, 0);
  const fails = d.failed_ips.reduce((s, x) => s + x.count, 0);
  $('#activity-metrics').innerHTML = [['Отправлено писем', sent], ['Входов в ящики', boxes.reduce((s, [, v]) => s + v.logins, 0)],
    ['Ошибок пароля', fails], ['Отклонено лимитом', d.ratelimited]]
    .map(([l, v]) => `<div class="metric"><div class="metric-label">${l}</div><div class="metric-value">${esc(v)}</div></div>`).join('');
  const ips = (list) => list.map((ip) => `<code>${esc(ip)}</code>`).join('<br>') || '—';
  $('#activity-table').innerHTML = boxes.length ? boxes.map(([user, v]) => `<tr><td><b>${esc(user)}</b></td>
      <td class="num">${v.sent}</td><td class="num">${v.sent_hour ? pill(v.sent_hour > 50 ? 'warn' : 'info', v.sent_hour) : '0'}</td>
      <td class="small">${ips(v.send_ips)}</td><td class="num">${v.logins}</td><td class="small">${ips(v.login_ips)}</td>
      <td>${fmtDate(v.last_login)}</td><td class="num">${v.failures ? pill('warn', v.failures) : '0'}</td></tr>`).join('')
    : emptyRow(8, 'За этот период почтовые программы не входили и не отправляли');
  $('#activity-fails').innerHTML = d.failed_ips.length ? d.failed_ips.map((x) => `<tr><td><code>${esc(x.ip)}</code></td><td class="num">${x.count}</td></tr>`).join('')
    : emptyRow(2, 'Неудачных входов нет');
  if (!d.journal_ok) toast('Журнал недоступен: пользователь mailroom должен быть в группе systemd-journal', 'warn');
};
$('#activity-hours').addEventListener('change', () => loaders.activity().catch(fail));

// ---------- резервные копии ----------
let backupPoll = null;
loaders.backups = async () => {
  const d = await api('/api/backups');
  const s = d.status;
  $('#backup-metrics').innerHTML = [
    ['Последняя копия', s ? fmtDate(s.finished_at) : 'не было', s ? (s.ok ? 'успешно' : 'ошибка') : ''],
    ['Размер', s && s.ok ? fmtBytes(s.size) : '—', s && s.seconds ? `${s.seconds} с` : ''],
    ['Удалённая копия', d.remote ? (s && /^отправлено/.test(s.remote || '') ? 'есть' : 'нет') : 'не настроена', ''],
    ['Сейчас', d.running ? 'копируется…' : 'ожидание', ''],
  ].map(([l, v, sm]) => `<div class="metric"><div class="metric-label">${l}</div><div class="metric-value">${esc(v)}<small>${esc(sm)}</small></div></div>`).join('');
  if (s && !s.ok) toast(`Последнее копирование: ${s.error}`, 'fail');
  if (s && s.remote && !/^отправлено/.test(s.remote)) toast(`Удалённая копия: ${s.remote}`, 'warn');
  $('#backup-table').innerHTML = d.items.length ? d.items.map((x) => `<tr><td><code>${esc(x.name)}</code></td><td class="num">${fmtBytes(x.size)}</td><td>${fmtDate(x.mtime)}</td></tr>`).join('')
    : emptyRow(3, d.error ? d.error : 'Копий пока нет');
  const f = $('#backup-form');
  f.backup_keep.value = d.keep; f.backup_remote.value = d.remote; f.backup_remote_port.value = d.remote_port;
  $('#backup-pubkey').textContent = d.pubkey || 'ключ ещё не создан — запустите deploy/install.sh';
  clearTimeout(backupPoll);
  if (d.running) backupPoll = setTimeout(() => { if (location.hash === '#backups') loaders.backups().catch(fail); }, 4000);
};
$('#backup-run').addEventListener('click', async () => {
  try { await post('/api/backups/run'); toast('Копирование запущено'); setTimeout(() => loaders.backups().catch(fail), 1500); } catch (e) { fail(e); }
});
$('#backup-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  try { await api('/api/settings', {method: 'PUT', body: Object.fromEntries(new FormData(e.target))}); toast('Сохранено'); } catch (err) { fail(err); }
});
$('#backup-pubkey-copy').addEventListener('click', () => copyText($('#backup-pubkey').textContent));

// ---------- пользователи ----------
loaders.users = async () => {
  const d = await api('/api/users');
  const roles = {admin: 'администратор', operator: 'оператор', viewer: 'наблюдатель'};
  $('#users-table').innerHTML = d.items.map((x) => `<tr><td><b>${esc(x.username)}</b></td><td>${esc(roles[x.role] || x.role)}</td>
    <td>${x.totp_enabled ? pill('ok', 'включена') : pill('warn', 'нет')}</td><td>${fmtDate(x.last_login_at)}</td>
    <td class="num">${x.username === me.username ? '' : `<button class="link-button danger" data-user-del="${x.id}">Удалить</button>`}</td></tr>`).join('');
  $$('[data-user-del]').forEach((b) => b.addEventListener('click', async () => {
    if (!confirm('Удалить пользователя панели?')) return;
    await del(`/api/users/${b.dataset.userDel}`).then(() => loaders.users(), fail);
  }));
};
$('#new-user').addEventListener('click', () => openForm({
  title: 'Новый пользователь панели', eyebrow: 'Доступ', submit: 'Создать',
  fields: [
    {name: 'username', label: 'Логин', required: true, placeholder: 'ivanov'},
    {name: 'role', label: 'Роль', type: 'select', value: 'operator', options: [{value: 'operator', label: 'оператор'}, {value: 'admin', label: 'администратор'}, {value: 'viewer', label: 'наблюдатель'}]},
    {name: 'password', label: 'Пароль (от 14 символов)', type: 'password', required: true, wide: true},
  ],
  onSubmit: async (data) => { await post('/api/users', data); toast('Пользователь создан'); loaders.users(); },
}));

// ---------- безопасность ----------
loaders.security = async () => {
  const d = await api('/api/auth/me');
  me = {...me, ...d};
  $('#security-status').textContent = d.totp_enabled ? '2FA включена' : '2FA не настроена';
  $('#setup-2fa').textContent = d.totp_enabled ? 'Перевыпустить секрет' : 'Настроить 2FA';
  $('#disable-2fa').classList.toggle('hidden', !d.totp_enabled);
};
$('#setup-2fa').addEventListener('click', async () => {
  try {
    const d = await post('/api/auth/totp/setup');
    $('#totp-secret').textContent = d.secret;
    $('#totp-uri').textContent = d.otpauth_uri;
    $('#totp-box').classList.remove('hidden');
  } catch (e) { fail(e); }
});
bindForm('#totp-form', async (f) => {
  await post('/api/auth/totp/enable', f);
  $('#totp-box').classList.add('hidden');
  toast('2FA включена');
  loaders.security();
});
$('#disable-2fa').addEventListener('click', () => openForm({
  title: 'Отключить 2FA', eyebrow: 'Безопасность', submit: 'Отключить',
  fields: [{name: 'password', label: 'Пароль', type: 'password', required: true, wide: true}],
  onSubmit: async (data) => { await post('/api/auth/totp/disable', data); toast('2FA отключена', 'warn'); loaders.security(); },
}));
bindForm('#password-form', async (f) => {
  await post('/api/auth/password', f);
  $('#password-form').reset();
  toast('Пароль изменён');
});

// ---------- старт ----------
(async () => {
  try {
    me = await api('/api/auth/me');
    csrf = me.csrf_token;
    $('#whoami').textContent = me.username;
    applyRole();
    show(location.hash.slice(1) || 'overview');
  } catch (e) { fail(e); }
})();
